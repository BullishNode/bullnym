//! On-chain BTC watcher for invoice settlement.
//!
//! Polls a mempool.space-shape API (Bull's own `mempool.bullbitcoin.com` by
//! default — see `BitcoinWatcherConfig`) for any unpaid/in_progress invoice
//! whose `accept_btc=TRUE` and `bitcoin_address IS NOT NULL`. On a confirmed
//! tx the row records an idempotent invoice payment event; on a
//! mempool-only sighting the row flips to `in_progress` via
//! `db::mark_invoice_in_progress`.
//!
//! Two-tier polling balances responsiveness with API budget:
//! - Active tier (default 30s): invoices created in the last
//!   `active_window_secs` (default 1h). Most pays land within this window.
//! - Idle tier (default 5min): older still-unpaid invoices, in case a payer
//!   broadcasts late or our polls get rate-limited mid-window.
//!
//! Token-bucket guards against runaway requests when many invoices are open
//! at once: at the configured rate (default 5 RPS) the watcher stops issuing
//! requests for the rest of the tick once the bucket is drained, picking up
//! again next tick.
//!
//! Cancellation: `tokio::select!` against `cancel.cancelled()` interleaves
//! between every blocking await so a `cancel()` from main.rs is honored
//! within one HTTP timeout (default 10s).

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::BitcoinWatcherConfig;
use crate::db;
use crate::rate_limit::TokenBucket;

/// Compact projection of an unpaid/in_progress BTC-accepting invoice — only
/// the fields the watcher needs to decide and act.
#[derive(sqlx::FromRow, Debug)]
struct InvoiceForBtcPoll {
    id: Uuid,
    bitcoin_address: String,
    amount_sat: i64,
}

/// Minimal subset of the mempool.space `/address/<addr>/txs` response
/// shape. Fields outside this subset are ignored.
#[derive(Deserialize, Debug)]
struct MempoolTx {
    txid: String,
    vout: Vec<MempoolVout>,
    status: MempoolTxStatus,
}

#[derive(Deserialize, Debug)]
struct MempoolVout {
    /// `scriptpubkey_address` is the human-readable address mempool decodes
    /// from the script. Absent for non-standard outputs.
    scriptpubkey_address: Option<String>,
    value: u64,
}

#[derive(Deserialize, Debug)]
struct MempoolTxStatus {
    confirmed: bool,
    block_height: Option<u32>,
}

pub struct BitcoinWatcher {
    cfg: BitcoinWatcherConfig,
    /// Ordered esplora endpoints (primary + hardcoded provider failovers).
    /// One endpoint is chosen per tick (whichever answers the tip fetch) and
    /// used for that tick's address queries, so confirmation math never mixes
    /// two nodes' views. See #47.
    endpoints: Vec<String>,
    tolerances: db::InvoiceAccountingTolerances,
    http: reqwest::Client,
    pool: PgPool,
    bucket: Arc<AsyncMutex<TokenBucket>>,
}

impl BitcoinWatcher {
    pub fn new(
        cfg: BitcoinWatcherConfig,
        tolerances: db::InvoiceAccountingTolerances,
        pool: PgPool,
    ) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.request_timeout_ms))
            .build()?;
        let bucket = Arc::new(AsyncMutex::new(TokenBucket::new(cfg.rate_per_sec)));
        let endpoints = cfg.effective_endpoints();
        Ok(Self {
            cfg,
            endpoints,
            tolerances,
            http,
            pool,
            bucket,
        })
    }

    /// Top-level loop. Returns when `cancel` fires.
    pub async fn run(self, cancel: CancellationToken) {
        tracing::info!(
            event = "bitcoin_watcher_started",
            endpoint = %self.cfg.endpoint,
            active_tick_secs = self.cfg.active_tick_secs,
            idle_tick_secs = self.cfg.idle_tick_secs,
            confirmations_required = self.cfg.confirmations_required,
            rate_per_sec = self.cfg.rate_per_sec,
            "bitcoin_watcher: starting poll loop"
        );

        let mut active = tokio::time::interval(Duration::from_secs(self.cfg.active_tick_secs));
        // Skip the immediate initial tick (interval fires at 0 by default).
        active.tick().await;
        let mut idle = tokio::time::interval(Duration::from_secs(self.cfg.idle_tick_secs));
        idle.tick().await;

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("bitcoin_watcher: shutdown requested");
                    return;
                }
                _ = active.tick() => {
                    self.poll_tier(true, &cancel).await;
                }
                _ = idle.tick() => {
                    self.poll_tier(false, &cancel).await;
                }
            }
        }
    }

    /// Run one tier's tick. `is_active` selects the active vs idle window
    /// predicate against `created_at`. The same SQL projects only the
    /// rows needed for the watcher's hot path.
    async fn poll_tier(&self, is_active: bool, cancel: &CancellationToken) {
        let invoices = match self.fetch_invoices(is_active).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    event = "bitcoin_watcher_db_error",
                    is_active = is_active,
                    "bitcoin_watcher: invoice list query failed: {e}"
                );
                return;
            }
        };
        if invoices.is_empty() {
            return;
        }

        // Tip is needed for confirmation-depth math. Treat a tip-fetch
        // failure as "skip this tick" — better than re-flipping rows
        // toward paid based on stale block_heights.
        let (tip, endpoint) = match self.fetch_tip_and_endpoint().await {
            Some(pair) => pair,
            None => {
                tracing::warn!("bitcoin_watcher: tip-height fetch failed on all endpoints; skipping tick");
                return;
            }
        };

        for inv in invoices {
            if cancel.is_cancelled() {
                return;
            }
            if !self.try_acquire_token().await {
                tracing::debug!(
                    event = "bitcoin_watcher_rate_limited_tick",
                    is_active = is_active,
                    "bitcoin_watcher: token bucket drained; deferring remaining invoices"
                );
                return;
            }
            self.check_invoice(&inv, tip, &endpoint).await;
        }
    }

    async fn fetch_invoices(&self, is_active: bool) -> Result<Vec<InvoiceForBtcPoll>, sqlx::Error> {
        // Active tier: created within last `active_window_secs`.
        // Idle tier:   created earlier than that (the rest of the still-
        //              unpaid corpus). Both predicates exclude expired
        //              rows so the watcher doesn't waste an RPS slot on
        //              a row about to be GC'd.
        let cmp = if is_active { ">" } else { "<=" };
        let sql = format!(
            "SELECT id, bitcoin_address, GREATEST(amount_sat - COALESCE(paid_amount_sat, 0), 0) AS amount_sat \
             FROM invoices \
             WHERE status IN ('unpaid', 'in_progress', 'partially_paid') \
               AND accept_btc = TRUE \
               AND bitcoin_address IS NOT NULL \
               AND created_at {cmp} NOW() - ($1 || ' seconds')::interval \
               AND expires_at > NOW() \
             ORDER BY random() \
             LIMIT 1000",
        );
        sqlx::query_as::<_, InvoiceForBtcPoll>(&sql)
            .bind(self.cfg.active_window_secs)
            .fetch_all(&self.pool)
            .await
    }

    /// Fetch the chain tip, failing over across endpoints. Returns the tip AND
    /// the endpoint that served it, so the tick's address queries use the same
    /// node (consistent confirmation math). `None` only if every endpoint fails.
    async fn fetch_tip_and_endpoint(&self) -> Option<(u32, String)> {
        for ep in &self.endpoints {
            // `/blocks/tip/height` returns a bare integer.
            let url = format!("{}/blocks/tip/height", ep.trim_end_matches('/'));
            let resp = match self.http.get(&url).send().await {
                Ok(r) if r.status().is_success() => r,
                Ok(r) => {
                    tracing::warn!(event = "btc_esplora_failover", op = "tip", endpoint = %ep, status = %r.status());
                    continue;
                }
                Err(e) => {
                    tracing::warn!(event = "btc_esplora_failover", op = "tip", endpoint = %ep, err = %e);
                    continue;
                }
            };
            let body = match resp.text().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(event = "btc_esplora_failover", op = "tip", endpoint = %ep, err = %e);
                    continue;
                }
            };
            match body.trim().parse::<u32>() {
                Ok(h) => return Some((h, ep.trim_end_matches('/').to_string())),
                Err(_) => {
                    tracing::warn!(
                        event = "btc_esplora_failover", op = "tip", endpoint = %ep,
                        "tip body did not parse as u32: '{}'",
                        body.chars().take(64).collect::<String>()
                    );
                    continue;
                }
            }
        }
        tracing::error!(
            event = "btc_esplora_all_endpoints_failed",
            op = "tip",
            endpoints = self.endpoints.len(),
            "all esplora endpoints failed the tip fetch"
        );
        None
    }

    /// Single-invoice check. On any HTTP error this is a no-op (logs and
    /// returns) — the next tick will retry. `mark_invoice_*` calls are
    /// idempotent so re-firing them on a re-poll is safe.
    async fn check_invoice(&self, inv: &InvoiceForBtcPoll, tip: u32, endpoint: &str) {
        let url = format!("{}/address/{}/txs", endpoint, inv.bitcoin_address);
        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    invoice_id = %inv.id,
                    "bitcoin_watcher: address-txs request failed: {e}"
                );
                return;
            }
        };

        let status = resp.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tracing::warn!(
                event = "bitcoin_watcher_upstream_429",
                invoice_id = %inv.id,
                "bitcoin_watcher: upstream rate-limited; backing off this tick"
            );
            return;
        }
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::BAD_REQUEST {
            // Bad address (rejected by validator at create-time should mean
            // this never fires, but defense-in-depth). Don't retry.
            tracing::error!(
                event = "bitcoin_watcher_bad_address",
                invoice_id = %inv.id,
                http_status = %status,
                "bitcoin_watcher: upstream rejected bitcoin_address"
            );
            return;
        }
        if !status.is_success() {
            tracing::warn!(
                invoice_id = %inv.id,
                http_status = %status,
                "bitcoin_watcher: address-txs non-2xx"
            );
            return;
        }

        let txs: Vec<MempoolTx> = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    invoice_id = %inv.id,
                    "bitcoin_watcher: address-txs JSON decode failed: {e}"
                );
                return;
            }
        };

        let mut saw_mempool = false;
        let mut seen_event_keys = Vec::new();
        for tx in &txs {
            for observation in bitcoin_direct_observations_for_tx(
                tx,
                &inv.bitcoin_address,
                tip,
                self.cfg.confirmations_required,
            ) {
                seen_event_keys.push(observation.event_key.clone());
                if observation.last_seen_state == "counted" {
                    if self
                        .record_confirmed_output(
                            inv,
                            tx,
                            observation.amount_sat,
                            observation.vout as usize,
                            observation.confirmations as u32,
                        )
                        .await
                    {
                        self.upsert_bitcoin_observation(inv, &observation).await;
                    }
                } else {
                    saw_mempool = true;
                    self.upsert_bitcoin_observation(inv, &observation).await;
                }
            }
        }

        if let Err(e) = db::mark_missing_bitcoin_payment_observations_not_seen(
            &self.pool,
            inv.id,
            &seen_event_keys,
        )
        .await
        {
            tracing::warn!(
                invoice_id = %inv.id,
                "bitcoin_watcher: stale observation update failed: {e}"
            );
        }

        if saw_mempool {
            match db::mark_invoice_in_progress(&self.pool, inv.id).await {
                Ok(rows) if rows > 0 => {
                    tracing::info!(
                        event = "invoice_in_progress_via_bitcoin",
                        invoice_id = %inv.id,
                        "bitcoin_watcher: invoice flipped to in_progress (mempool seen)"
                    );
                }
                Ok(_) => {
                    if let Err(e) =
                        db::mark_invoice_settlement_status(&self.pool, Some(inv.id), "pending")
                            .await
                    {
                        tracing::warn!(
                            invoice_id = %inv.id,
                            "bitcoin_watcher: mark settlement pending failed: {e}"
                        );
                    }
                    // Already in_progress / terminal — no-op.
                }
                Err(e) => {
                    tracing::error!(
                        invoice_id = %inv.id,
                        "bitcoin_watcher: mark_invoice_in_progress failed: {e}"
                    );
                }
            }
        }
    }

    async fn upsert_bitcoin_observation(
        &self,
        inv: &InvoiceForBtcPoll,
        observation: &BtcDirectObservation,
    ) {
        match db::upsert_invoice_payment_observation(
            &self.pool,
            inv.id,
            db::NewInvoicePaymentObservation {
                rail: "bitcoin",
                source: "bitcoin_direct",
                event_key: &observation.event_key,
                txid: &observation.txid,
                vout: observation.vout,
                address: &inv.bitcoin_address,
                amount_sat: observation.amount_sat as i64,
                confirmations: observation.confirmations as i32,
                block_height: observation.block_height.map(|h| h as i32),
                last_seen_state: observation.last_seen_state,
            },
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    invoice_id = %inv.id,
                    txid = %observation.txid,
                    vout = observation.vout,
                    state = observation.last_seen_state,
                    "bitcoin_watcher: payment observation upsert failed: {e}"
                );
            }
        }
    }

    async fn record_confirmed_output(
        &self,
        inv: &InvoiceForBtcPoll,
        tx: &MempoolTx,
        received_sat: u64,
        vout: usize,
        confs: u32,
    ) -> bool {
        let event_key = format!("bitcoin_direct:{}:{}", tx.txid, vout);
        let Ok(vout_i32) = i32::try_from(vout) else {
            tracing::error!(
                invoice_id = %inv.id,
                txid = %tx.txid,
                vout = vout,
                "bitcoin_watcher: vout index overflow"
            );
            return false;
        };

        match db::record_invoice_payment(
            &self.pool,
            inv.id,
            db::InvoicePaymentEvidence {
                rail: "bitcoin",
                source: "bitcoin_direct",
                event_key: &event_key,
                amount_sat: received_sat as i64,
                txid: Some(&tx.txid),
                vout: Some(vout_i32),
                boltz_swap_id: None,
                address: Some(&inv.bitcoin_address),
            },
            self.tolerances,
        )
        .await
        {
            Ok(rows) if rows > 0 => {
                tracing::info!(
                    event = "invoice_payment_event_bitcoin",
                    invoice_id = %inv.id,
                    txid = %tx.txid,
                    vout = vout,
                    received_sat = received_sat,
                    amount_sat = inv.amount_sat,
                    confirmations = confs,
                    "bitcoin_watcher: invoice BTC payment event recorded"
                );
                true
            }
            Ok(_) => match db::invoice_payment_event_exists(&self.pool, inv.id, &event_key).await {
                Ok(exists) => exists,
                Err(e) => {
                    tracing::warn!(
                        invoice_id = %inv.id,
                        txid = %tx.txid,
                        vout = vout,
                        "bitcoin_watcher: payment event existence check failed: {e}"
                    );
                    false
                }
            },
            Err(e) => {
                tracing::error!(
                    invoice_id = %inv.id,
                    txid = %tx.txid,
                    vout = vout,
                    "bitcoin_watcher: record_invoice_payment failed: {e}"
                );
                false
            }
        }
    }

    async fn try_acquire_token(&self) -> bool {
        let mut bucket = self.bucket.lock().await;
        bucket.try_consume()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BtcDirectObservation {
    event_key: String,
    txid: String,
    vout: i32,
    amount_sat: u64,
    confirmations: u32,
    block_height: Option<u32>,
    last_seen_state: &'static str,
}

fn bitcoin_direct_observations_for_tx(
    tx: &MempoolTx,
    address: &str,
    tip: u32,
    confirmations_required: u32,
) -> Vec<BtcDirectObservation> {
    let (confirmations, block_height, last_seen_state) = if tx.status.confirmed {
        let Some(height) = tx.status.block_height else {
            return Vec::new();
        };
        let confs = tip.saturating_sub(height).saturating_add(1);
        let state = if confs >= confirmations_required {
            "counted"
        } else {
            "awaiting_confirmations"
        };
        (confs, Some(height), state)
    } else {
        (0, None, "seen_unconfirmed")
    };

    tx.vout
        .iter()
        .enumerate()
        .filter_map(|(vout, output)| {
            if output.scriptpubkey_address.as_deref() != Some(address) || output.value == 0 {
                return None;
            }
            let Ok(vout_i32) = i32::try_from(vout) else {
                tracing::error!(
                    txid = %tx.txid,
                    vout = vout,
                    "bitcoin_watcher: vout index overflow"
                );
                return None;
            };
            Some(BtcDirectObservation {
                event_key: format!("bitcoin_direct:{}:{vout}", tx.txid),
                txid: tx.txid.clone(),
                vout: vout_i32,
                amount_sat: output.value,
                confirmations,
                block_height,
                last_seen_state,
            })
        })
        .collect()
}

/// Convenience entry-point used by main.rs. Constructs the watcher and
/// drives `run` until cancellation.
pub async fn run(
    cfg: BitcoinWatcherConfig,
    tolerances: db::InvoiceAccountingTolerances,
    pool: PgPool,
    cancel: CancellationToken,
) {
    if !cfg.enabled {
        tracing::warn!("bitcoin_watcher: disabled by config; not starting");
        return;
    }
    let watcher = match BitcoinWatcher::new(cfg, tolerances, pool) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("bitcoin_watcher: client init failed: {e}");
            return;
        }
    };
    watcher.run(cancel).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(txid: &str, confirmed: bool, block_height: Option<u32>) -> MempoolTx {
        MempoolTx {
            txid: txid.to_string(),
            vout: vec![
                MempoolVout {
                    scriptpubkey_address: Some("bc1qother".to_string()),
                    value: 2_000,
                },
                MempoolVout {
                    scriptpubkey_address: Some("bc1qtarget".to_string()),
                    value: 6_000,
                },
            ],
            status: MempoolTxStatus {
                confirmed,
                block_height,
            },
        }
    }

    #[test]
    fn observation_helper_marks_mempool_output_unconfirmed() {
        let observations = bitcoin_direct_observations_for_tx(
            &tx(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                false,
                None,
            ),
            "bc1qtarget",
            800_000,
            2,
        );

        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].event_key,
            "bitcoin_direct:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1"
        );
        assert_eq!(observations[0].amount_sat, 6_000);
        assert_eq!(observations[0].confirmations, 0);
        assert_eq!(observations[0].block_height, None);
        assert_eq!(observations[0].last_seen_state, "seen_unconfirmed");
    }

    #[test]
    fn observation_helper_marks_below_threshold_confirmed_output_awaiting_confirmations() {
        let observations = bitcoin_direct_observations_for_tx(
            &tx(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                true,
                Some(799_999),
            ),
            "bc1qtarget",
            800_000,
            3,
        );

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].confirmations, 2);
        assert_eq!(observations[0].block_height, Some(799_999));
        assert_eq!(observations[0].last_seen_state, "awaiting_confirmations");
    }

    #[test]
    fn observation_helper_marks_threshold_confirmed_output_counted() {
        let observations = bitcoin_direct_observations_for_tx(
            &tx(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                true,
                Some(799_998),
            ),
            "bc1qtarget",
            800_000,
            3,
        );

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].confirmations, 3);
        assert_eq!(observations[0].block_height, Some(799_998));
        assert_eq!(observations[0].last_seen_state, "counted");
    }
}

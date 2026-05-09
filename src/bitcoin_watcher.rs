//! On-chain BTC watcher for invoice settlement.
//!
//! Polls a mempool.space-shape API (Bull's own `mempool.bullbitcoin.com` by
//! default — see `BitcoinWatcherConfig`) for any unpaid/in_progress invoice
//! whose `accept_btc=TRUE` and `bitcoin_address IS NOT NULL`. On a confirmed
//! tx the row flips via `db::mark_invoice_paid(.., "bitcoin")`; on a
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
    #[allow(dead_code)]
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

/// `/blocks/tip/height` returns a bare integer (text body, integer literal).
/// We use `text()` + `parse::<u32>()` to avoid a JSON wrapper.

pub struct BitcoinWatcher {
    cfg: BitcoinWatcherConfig,
    http: reqwest::Client,
    pool: PgPool,
    bucket: Arc<AsyncMutex<TokenBucket>>,
}

impl BitcoinWatcher {
    pub fn new(
        cfg: BitcoinWatcherConfig,
        pool: PgPool,
    ) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.request_timeout_ms))
            .build()?;
        let bucket = Arc::new(AsyncMutex::new(TokenBucket::new(cfg.rate_per_sec)));
        Ok(Self { cfg, http, pool, bucket })
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
        let tip = match self.fetch_tip_height().await {
            Some(h) => h,
            None => {
                tracing::warn!("bitcoin_watcher: tip-height fetch failed; skipping tick");
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
            self.check_invoice(&inv, tip).await;
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
            "SELECT id, bitcoin_address, amount_sat \
             FROM invoices \
             WHERE status IN ('unpaid', 'in_progress') \
               AND accept_btc = TRUE \
               AND bitcoin_address IS NOT NULL \
               AND created_at {cmp} NOW() - ($1 || ' seconds')::interval \
               AND expires_at > NOW() \
             ORDER BY created_at DESC \
             LIMIT 1000",
        );
        sqlx::query_as::<_, InvoiceForBtcPoll>(&sql)
            .bind(self.cfg.active_window_secs)
            .fetch_all(&self.pool)
            .await
    }

    async fn fetch_tip_height(&self) -> Option<u32> {
        let url = format!("{}/blocks/tip/height", self.cfg.endpoint);
        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("bitcoin_watcher: tip request failed: {e}");
                return None;
            }
        };
        if !resp.status().is_success() {
            tracing::warn!(
                "bitcoin_watcher: tip request non-2xx: {}",
                resp.status()
            );
            return None;
        }
        let body = match resp.text().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("bitcoin_watcher: tip body read failed: {e}");
                return None;
            }
        };
        match body.trim().parse::<u32>() {
            Ok(h) => Some(h),
            Err(_) => {
                tracing::warn!(
                    "bitcoin_watcher: tip body did not parse as u32: '{}'",
                    body.chars().take(64).collect::<String>()
                );
                None
            }
        }
    }

    /// Single-invoice check. On any HTTP error this is a no-op (logs and
    /// returns) — the next tick will retry. `mark_invoice_*` calls are
    /// idempotent so re-firing them on a re-poll is safe.
    async fn check_invoice(&self, inv: &InvoiceForBtcPoll, tip: u32) {
        let url = format!("{}/address/{}/txs", self.cfg.endpoint, inv.bitcoin_address);
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
        if status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::BAD_REQUEST
        {
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

        // Walk newest-to-oldest looking for either a confirmed tx (priority)
        // or a mempool-only tx (fallback). The first confirmed tx with a
        // sufficient confirmation count wins; ordering via `mempool.space`
        // is by descending block height with mempool-only at the front.
        let mut saw_mempool = false;
        for tx in &txs {
            let received_sat: i64 = tx
                .vout
                .iter()
                .filter(|v| v.scriptpubkey_address.as_deref() == Some(inv.bitcoin_address.as_str()))
                .map(|v| v.value as i64)
                .sum();
            if received_sat == 0 {
                continue;
            }

            if tx.status.confirmed {
                let height = match tx.status.block_height {
                    Some(h) => h,
                    None => continue, // confirmed-without-height is unreachable but defensive.
                };
                let confs = tip.saturating_sub(height).saturating_add(1);
                if confs >= self.cfg.confirmations_required {
                    match db::mark_invoice_paid(&self.pool, inv.id, received_sat, "bitcoin").await {
                        Ok(rows) if rows > 0 => {
                            tracing::info!(
                                event = "invoice_paid_via_bitcoin",
                                invoice_id = %inv.id,
                                received_sat = received_sat,
                                amount_sat = inv.amount_sat,
                                confirmations = confs,
                                "bitcoin_watcher: invoice flipped to paid"
                            );
                        }
                        Ok(_) => {
                            // Already terminal — no-op.
                        }
                        Err(e) => {
                            tracing::error!(
                                invoice_id = %inv.id,
                                "bitcoin_watcher: mark_invoice_paid failed: {e}"
                            );
                        }
                    }
                    return;
                }
                // Confirmed but not yet at threshold — treat as mempool for
                // the in_progress flip; subsequent ticks will re-check.
                saw_mempool = true;
            } else {
                saw_mempool = true;
            }
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

    async fn try_acquire_token(&self) -> bool {
        let mut bucket = self.bucket.lock().await;
        bucket.try_consume()
    }
}

/// Convenience entry-point used by main.rs. Constructs the watcher and
/// drives `run` until cancellation.
pub async fn run(
    cfg: BitcoinWatcherConfig,
    pool: PgPool,
    cancel: CancellationToken,
) {
    if !cfg.enabled {
        tracing::warn!("bitcoin_watcher: disabled by config; not starting");
        return;
    }
    let watcher = match BitcoinWatcher::new(cfg, pool) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("bitcoin_watcher: client init failed: {e}");
            return;
        }
    };
    watcher.run(cancel).await;
}

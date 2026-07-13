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

use crate::admission::WorkerReporter;
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
    created_at_cursor: String,
}

impl InvoiceForBtcPoll {
    fn scan_cursor(&self) -> db::WatcherScanCursor {
        db::WatcherScanCursor {
            created_at: self.created_at_cursor.clone(),
            id: self.id,
        }
    }
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

struct ConfirmedOutputOutcome {
    recorded: bool,
    healthy: bool,
}

const WATCHER_BATCH_SIZE: usize = 1_000;

const BITCOIN_WATCHER_PAGE_SQL: &str = "SELECT id, bitcoin_address, \
            GREATEST(amount_sat - COALESCE(paid_amount_sat, 0), 0) AS amount_sat, \
            created_at::TEXT AS created_at_cursor \
     FROM invoices \
     WHERE status IN ('unpaid', 'in_progress', 'partially_paid') \
       AND accept_btc = TRUE \
       AND bitcoin_address IS NOT NULL \
       AND created_at {cmp} $3::timestamptz - ($1 || ' seconds')::interval \
       AND expires_at + ($2 || ' seconds')::interval > $3::timestamptz \
       AND created_at <= $3::timestamptz \
       AND ( \
             $4::timestamptz IS NULL \
             OR (created_at, id) > ($4::timestamptz, $5::uuid) \
           ) \
     ORDER BY created_at ASC, id ASC \
     LIMIT $6";

struct InvoicePollBatch {
    invoices: Vec<InvoiceForBtcPoll>,
    has_more: bool,
}

fn truncate_to_watcher_batch<T>(rows: &mut Vec<T>, limit: usize) -> bool {
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    has_more
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CycleOutcome {
    Healthy,
    Incomplete,
    Failed,
}

impl CycleOutcome {
    fn after_token_exhaustion(useful_progress: usize) -> Self {
        if useful_progress == 0 {
            Self::Failed
        } else {
            Self::Incomplete
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchTier {
    Active,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportAction {
    Success,
    Failure,
    ProgressOnly,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum TierState {
    #[default]
    Unknown,
    Healthy,
    Failed,
}

#[derive(Debug, Default)]
struct TierHealth {
    active: TierState,
    idle: TierState,
}

impl TierHealth {
    fn observe(&mut self, tier: WatchTier, outcome: CycleOutcome) -> ReportAction {
        let (current, other) = match tier {
            WatchTier::Active => (&mut self.active, self.idle),
            WatchTier::Idle => (&mut self.idle, self.active),
        };
        match outcome {
            CycleOutcome::Incomplete => ReportAction::ProgressOnly,
            CycleOutcome::Failed => {
                *current = TierState::Failed;
                ReportAction::Failure
            }
            CycleOutcome::Healthy => {
                *current = TierState::Healthy;
                if other == TierState::Healthy {
                    ReportAction::Success
                } else {
                    ReportAction::ProgressOnly
                }
            }
        }
    }
}

fn report_outcome(
    reporter: &WorkerReporter,
    tier_health: &mut TierHealth,
    tier: WatchTier,
    outcome: CycleOutcome,
) {
    match tier_health.observe(tier, outcome) {
        ReportAction::Success => reporter.cycle_succeeded(),
        ReportAction::Failure => reporter.cycle_failed(),
        ReportAction::ProgressOnly => reporter.progress(),
    }
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
    pub async fn run(self, cancel: CancellationToken, mut reporter: WorkerReporter) {
        let mut tier_health = TierHealth::default();
        let mut active_epoch = db::WatcherScanEpoch::default();
        let mut idle_epoch = db::WatcherScanEpoch::default();
        tracing::info!(
            event = "bitcoin_watcher_started",
            endpoint = %self.cfg.endpoint,
            effective_endpoints = ?self.endpoints,
            active_tick_secs = self.cfg.active_tick_secs,
            idle_tick_secs = self.cfg.idle_tick_secs,
            confirmations_required = self.cfg.confirmations_required,
            rate_per_sec = self.cfg.rate_per_sec,
            "bitcoin_watcher: starting poll loop"
        );

        if cancel.is_cancelled() {
            reporter.intentional_shutdown();
            return;
        }

        for (tier, is_active, epoch) in [
            (WatchTier::Active, true, &mut active_epoch),
            (WatchTier::Idle, false, &mut idle_epoch),
        ] {
            let startup_outcome = self.poll_tier(is_active, &cancel, &reporter, epoch).await;
            if cancel.is_cancelled() {
                reporter.intentional_shutdown();
                return;
            }
            report_outcome(&reporter, &mut tier_health, tier, startup_outcome);
        }

        let mut active = tokio::time::interval(Duration::from_secs(self.cfg.active_tick_secs));
        // The current process completed its startup scan above; consume each
        // interval's immediate tick so subsequent scans follow their cadence.
        active.tick().await;
        let mut idle = tokio::time::interval(Duration::from_secs(self.cfg.idle_tick_secs));
        idle.tick().await;

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("bitcoin_watcher: shutdown requested");
                    reporter.intentional_shutdown();
                    return;
                }
                _ = active.tick() => {
                    let healthy = self
                        .poll_tier(true, &cancel, &reporter, &mut active_epoch)
                        .await;
                    if cancel.is_cancelled() {
                        reporter.intentional_shutdown();
                        return;
                    }
                    report_outcome(
                        &reporter,
                        &mut tier_health,
                        WatchTier::Active,
                        healthy,
                    );
                }
                _ = idle.tick() => {
                    let healthy = self
                        .poll_tier(false, &cancel, &reporter, &mut idle_epoch)
                        .await;
                    if cancel.is_cancelled() {
                        reporter.intentional_shutdown();
                        return;
                    }
                    report_outcome(
                        &reporter,
                        &mut tier_health,
                        WatchTier::Idle,
                        healthy,
                    );
                }
            }
        }
    }

    /// Run one tier's tick. `is_active` selects the active vs idle window
    /// predicate against `created_at`. The same SQL projects only the
    /// rows needed for the watcher's hot path.
    async fn poll_tier(
        &self,
        is_active: bool,
        cancel: &CancellationToken,
        reporter: &WorkerReporter,
        epoch: &mut db::WatcherScanEpoch,
    ) -> CycleOutcome {
        reporter.progress();
        if cancel.is_cancelled() {
            return CycleOutcome::Incomplete;
        }

        // Probe the evidence backend even when the database page is empty. An
        // enabled URL list is configuration, not proof that this process can
        // currently observe a direct-Bitcoin payment.
        let (tip, endpoint) = match self.fetch_tip_and_endpoint().await {
            Some(pair) => pair,
            None => {
                tracing::warn!(
                    "bitcoin_watcher: tip-height fetch failed on all endpoints; skipping tick"
                );
                return CycleOutcome::Failed;
            }
        };

        if epoch.snapshot().is_none() {
            match db::watcher_scan_snapshot(&self.pool).await {
                Ok(snapshot) => epoch.begin(snapshot),
                Err(e) => {
                    tracing::warn!(
                        event = "bitcoin_watcher_db_error",
                        is_active = is_active,
                        "bitcoin_watcher: scan snapshot query failed: {e}"
                    );
                    return CycleOutcome::Failed;
                }
            }
        }

        let batch = match self.fetch_invoices(is_active, epoch).await {
            Ok(batch) => batch,
            Err(e) => {
                tracing::warn!(
                    event = "bitcoin_watcher_db_error",
                    is_active = is_active,
                    "bitcoin_watcher: invoice list query failed: {e}"
                );
                return CycleOutcome::Failed;
            }
        };
        if batch.invoices.is_empty() {
            epoch.finish();
            return CycleOutcome::Healthy;
        }

        let mut useful_progress = 0usize;
        for inv in batch.invoices {
            reporter.progress();
            if cancel.is_cancelled() {
                return CycleOutcome::Incomplete;
            }
            if !self.try_acquire_token().await {
                tracing::debug!(
                    event = "bitcoin_watcher_rate_limited_tick",
                    is_active = is_active,
                    "bitcoin_watcher: token bucket drained; deferring remaining invoices"
                );
                return CycleOutcome::after_token_exhaustion(useful_progress);
            }
            if !self.check_invoice(&inv, tip, &endpoint, reporter).await {
                // Keep the cursor on the last proven row. The failed invoice is
                // retried on the next page instead of being skipped.
                return CycleOutcome::Failed;
            }
            epoch.advance(inv.scan_cursor());
            useful_progress = useful_progress.saturating_add(1);
        }

        if batch.has_more {
            CycleOutcome::Incomplete
        } else {
            epoch.finish();
            CycleOutcome::Healthy
        }
    }

    async fn fetch_invoices(
        &self,
        is_active: bool,
        epoch: &db::WatcherScanEpoch,
    ) -> Result<InvoicePollBatch, sqlx::Error> {
        // Active tier: created within last `active_window_secs`.
        // Idle tier:   created earlier than that (the rest of the still-
        //              unpaid corpus). Both predicates exclude expired
        //              rows so the watcher doesn't waste an RPS slot on
        //              a row about to be GC'd.
        let cmp = if is_active { ">" } else { "<=" };
        let snapshot = epoch
            .snapshot()
            .expect("watcher epoch snapshot initialized before page query");
        let cursor = epoch.cursor();
        let sql = BITCOIN_WATCHER_PAGE_SQL.replace("{cmp}", cmp);
        let mut invoices = sqlx::query_as::<_, InvoiceForBtcPoll>(&sql)
            .bind(self.cfg.active_window_secs)
            .bind(self.tolerances.payment_grace_secs as i64)
            .bind(snapshot)
            .bind(cursor.map(|cursor| cursor.created_at.as_str()))
            .bind(cursor.map(|cursor| cursor.id))
            .bind((WATCHER_BATCH_SIZE + 1) as i64)
            .fetch_all(&self.pool)
            .await?;
        let has_more = truncate_to_watcher_batch(&mut invoices, WATCHER_BATCH_SIZE);
        Ok(InvoicePollBatch { invoices, has_more })
    }

    /// Fetch the chain tip from a single endpoint. `None` on connection error,
    /// non-2xx, or an unparseable body. `/blocks/tip/height` returns a bare int.
    async fn fetch_tip_from(&self, endpoint: &str) -> Option<u32> {
        let ep = endpoint.trim_end_matches('/');
        let url = format!("{ep}/blocks/tip/height");
        let resp = match self.http.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::warn!(event = "btc_esplora_failover", op = "tip", endpoint = %ep, status = %r.status());
                return None;
            }
            Err(e) => {
                tracing::warn!(event = "btc_esplora_failover", op = "tip", endpoint = %ep, err = %e);
                return None;
            }
        };
        let body = match resp.text().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(event = "btc_esplora_failover", op = "tip", endpoint = %ep, err = %e);
                return None;
            }
        };
        match body.trim().parse::<u32>() {
            Ok(h) => Some(h),
            Err(_) => {
                tracing::warn!(
                    event = "btc_esplora_failover", op = "tip", endpoint = %ep,
                    "tip body did not parse as u32: '{}'",
                    body.chars().take(64).collect::<String>()
                );
                None
            }
        }
    }

    /// Fetch the chain tip, failing over across endpoints. Returns the tip AND
    /// the endpoint that served it, so the tick's address queries can start on
    /// the same node (consistent confirmation math). `None` only if every
    /// endpoint fails.
    async fn fetch_tip_and_endpoint(&self) -> Option<(u32, String)> {
        for ep in &self.endpoints {
            let ep = ep.trim_end_matches('/');
            if let Some(h) = self.fetch_tip_from(ep).await {
                return Some((h, ep.to_string()));
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

    /// Single-invoice check with endpoint failover (#47). Queries the address
    /// txs starting on the tick's chosen endpoint (whose tip we already have,
    /// paired for consistent confirmation math), then rotates to the other
    /// endpoints on a connection error or an endpoint-specific non-2xx. For a
    /// fallback endpoint the tip is re-fetched FROM THAT SAME NODE, so tip and
    /// the accepted address response never mix two nodes' chain views. On any
    /// terminal HTTP condition this is a no-op (logs and returns) — the next
    /// tick will retry. `mark_invoice_*` calls are idempotent so re-firing them
    /// on a re-poll is safe.
    ///
    /// Failover taxonomy:
    ///   - 429: a per-tick backoff signal, NOT an endpoint fault — return
    ///     (rotating would just hammer the next provider).
    ///   - 400: a permanent bad-address (create-time validation should prevent
    ///     it) — return; every node rejects the same malformed address.
    ///   - 404 / 5xx / other non-2xx / connection error / decode error: an
    ///     endpoint-specific fault (e.g. a node without an address index answers
    ///     404, an overloaded one 5xx) — rotate to the next endpoint.
    async fn check_invoice(
        &self,
        inv: &InvoiceForBtcPoll,
        tip: u32,
        endpoint: &str,
        reporter: &WorkerReporter,
    ) -> bool {
        // Failover order: the tick's chosen endpoint first (tip already known),
        // then the remaining endpoints (tip re-fetched per node).
        let chosen = endpoint.trim_end_matches('/');
        let mut order: Vec<(&str, Option<u32>)> = vec![(chosen, Some(tip))];
        for ep in &self.endpoints {
            let ep = ep.trim_end_matches('/');
            if ep != chosen {
                order.push((ep, None));
            }
        }

        let mut endpoint_errors: Vec<String> = Vec::new();
        for (idx, (ep, known_tip)) in order.iter().enumerate() {
            reporter.progress();
            // Resolve the tip for THIS endpoint: the chosen endpoint reuses the
            // tick's tip; a fallback fetches its own. If a fallback's tip fetch
            // fails, skip it (we must not pair its address response with another
            // node's tip).
            let ep_tip = match known_tip {
                Some(t) => *t,
                None => match self.fetch_tip_from(ep).await {
                    Some(t) => t,
                    None => {
                        endpoint_errors.push(format!("{ep}: tip fetch failed"));
                        continue;
                    }
                },
            };

            let url = format!("{}/address/{}/txs", ep, inv.bitcoin_address);
            let resp = match self.http.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        event = "btc_esplora_failover",
                        op = "address_txs",
                        invoice_id = %inv.id,
                        endpoint = %ep,
                        "bitcoin_watcher: address-txs request failed: {e}"
                    );
                    endpoint_errors.push(format!("{ep}: {e}"));
                    continue;
                }
            };

            let status = resp.status();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                tracing::warn!(
                    event = "bitcoin_watcher_upstream_429",
                    invoice_id = %inv.id,
                    endpoint = %ep,
                    "bitcoin_watcher: upstream rate-limited; backing off this tick"
                );
                return false;
            }
            if status == reqwest::StatusCode::BAD_REQUEST {
                tracing::error!(
                    event = "bitcoin_watcher_bad_address",
                    invoice_id = %inv.id,
                    http_status = %status,
                    endpoint = %ep,
                    "bitcoin_watcher: upstream rejected bitcoin_address (400)"
                );
                return true;
            }
            if !status.is_success() {
                // 404 / 5xx / other — endpoint-specific fault, rotate.
                tracing::warn!(
                    event = "btc_esplora_failover",
                    op = "address_txs",
                    invoice_id = %inv.id,
                    endpoint = %ep,
                    http_status = %status,
                    "bitcoin_watcher: address-txs non-2xx; trying next endpoint"
                );
                endpoint_errors.push(format!("{ep}: {status}"));
                continue;
            }

            let txs: Vec<MempoolTx> = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        event = "btc_esplora_failover",
                        op = "address_txs",
                        invoice_id = %inv.id,
                        endpoint = %ep,
                        "bitcoin_watcher: address-txs JSON decode failed: {e}"
                    );
                    endpoint_errors.push(format!("{ep}: decode {e}"));
                    continue;
                }
            };

            if idx > 0 {
                tracing::warn!(
                    event = "btc_esplora_failover",
                    op = "address_txs",
                    invoice_id = %inv.id,
                    endpoint = %ep,
                    "bitcoin_watcher: address query served by failover endpoint"
                );
            }

            return self.process_address_txs(inv, &txs, ep_tip, reporter).await;
        }

        tracing::warn!(
            event = "btc_esplora_all_endpoints_failed",
            op = "address_txs",
            invoice_id = %inv.id,
            "bitcoin_watcher: all esplora endpoints failed the address-txs fetch this tick: {}",
            endpoint_errors.join(" | ")
        );
        false
    }

    /// Process an address-txs response: upsert observations, record confirmed
    /// outputs, and flip the invoice to `in_progress` on a mempool sighting.
    /// `tip` MUST come from the same node that served `txs` (consistent
    /// confirmation math — see `check_invoice`).
    async fn process_address_txs(
        &self,
        inv: &InvoiceForBtcPoll,
        txs: &[MempoolTx],
        tip: u32,
        reporter: &WorkerReporter,
    ) -> bool {
        let mut saw_mempool = false;
        let mut seen_event_keys = Vec::new();
        let mut healthy = true;
        for tx in txs {
            reporter.progress();
            for observation in bitcoin_direct_observations_for_tx(
                tx,
                &inv.bitcoin_address,
                tip,
                self.cfg.confirmations_required,
            ) {
                reporter.progress();
                seen_event_keys.push(observation.event_key.clone());
                if observation.last_seen_state == "counted" {
                    let outcome = self
                        .record_confirmed_output(
                            inv,
                            tx,
                            observation.amount_sat,
                            observation.vout as usize,
                            observation.confirmations,
                        )
                        .await;
                    healthy &= outcome.healthy;
                    if outcome.recorded {
                        healthy &= self.upsert_bitcoin_observation(inv, &observation).await;
                    }
                } else {
                    saw_mempool = true;
                    healthy &= self.upsert_bitcoin_observation(inv, &observation).await;
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
            healthy = false;
            tracing::warn!(
                invoice_id = %inv.id,
                "bitcoin_watcher: stale observation update failed: {e}"
            );
        }

        if saw_mempool {
            match db::mark_invoice_in_progress_for_component(
                &self.pool,
                inv.id,
                db::InvoiceInProgressComponent::Direct,
            )
            .await
            {
                Ok(true) => {
                    tracing::info!(
                        event = "invoice_in_progress_via_bitcoin",
                        invoice_id = %inv.id,
                        "bitcoin_watcher: invoice flipped to in_progress (mempool seen)"
                    );
                }
                Ok(false) => {}
                Err(e) => {
                    healthy = false;
                    tracing::error!(
                        invoice_id = %inv.id,
                        "bitcoin_watcher: mark_invoice_in_progress failed: {e}"
                    );
                }
            }
        }
        healthy
    }

    async fn upsert_bitcoin_observation(
        &self,
        inv: &InvoiceForBtcPoll,
        observation: &BtcDirectObservation,
    ) -> bool {
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
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(
                    invoice_id = %inv.id,
                    txid = %observation.txid,
                    vout = observation.vout,
                    state = observation.last_seen_state,
                    "bitcoin_watcher: payment observation upsert failed: {e}"
                );
                false
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
    ) -> ConfirmedOutputOutcome {
        let event_key = format!("bitcoin_direct:{}:{}", tx.txid, vout);
        let Ok(vout_i32) = i32::try_from(vout) else {
            tracing::error!(
                invoice_id = %inv.id,
                txid = %tx.txid,
                vout = vout,
                "bitcoin_watcher: vout index overflow"
            );
            return ConfirmedOutputOutcome {
                recorded: false,
                healthy: true,
            };
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
                ConfirmedOutputOutcome {
                    recorded: true,
                    healthy: true,
                }
            }
            Ok(_) => match db::invoice_payment_event_exists(&self.pool, inv.id, &event_key).await {
                Ok(exists) => ConfirmedOutputOutcome {
                    recorded: exists,
                    healthy: true,
                },
                Err(e) => {
                    tracing::warn!(
                        invoice_id = %inv.id,
                        txid = %tx.txid,
                        vout = vout,
                        "bitcoin_watcher: payment event existence check failed: {e}"
                    );
                    ConfirmedOutputOutcome {
                        recorded: false,
                        healthy: false,
                    }
                }
            },
            Err(e) => {
                tracing::error!(
                    invoice_id = %inv.id,
                    txid = %tx.txid,
                    vout = vout,
                    "bitcoin_watcher: record_invoice_payment failed: {e}"
                );
                ConfirmedOutputOutcome {
                    recorded: false,
                    healthy: false,
                }
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
    reporter: WorkerReporter,
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
    watcher.run(cancel, reporter).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{MoneyAdmission, Rail, Worker};
    use sqlx::postgres::PgPoolOptions;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn admission_fixture() -> (MoneyAdmission, WorkerReporter, TierHealth) {
        let admission = MoneyAdmission::healthy_test_fixture();
        let reporter = admission.reporter(Worker::BitcoinWatcher);
        (admission, reporter, TierHealth::default())
    }

    #[test]
    fn bitcoin_watcher_expiry_membership_is_frozen_at_the_scan_epoch() {
        assert!(BITCOIN_WATCHER_PAGE_SQL
            .contains("expires_at + ($2 || ' seconds')::interval > $3::timestamptz"));
        assert!(!BITCOIN_WATCHER_PAGE_SQL.contains("NOW()"));
    }

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

    #[test]
    fn bitcoin_watcher_batch_detects_only_the_sentinel_boundary() {
        for (fetched, expected_more) in [
            (WATCHER_BATCH_SIZE - 1, false),
            (WATCHER_BATCH_SIZE, false),
            (WATCHER_BATCH_SIZE + 1, true),
        ] {
            let mut rows = vec![(); fetched];
            assert_eq!(
                truncate_to_watcher_batch(&mut rows, WATCHER_BATCH_SIZE),
                expected_more,
                "unexpected has_more for {fetched} fetched rows"
            );
            assert_eq!(rows.len(), fetched.min(WATCHER_BATCH_SIZE));
        }
    }

    #[test]
    fn incomplete_startup_cycle_stays_closed() {
        let (admission, reporter, mut tier_health) = admission_fixture();

        assert_eq!(
            TierHealth::default().observe(WatchTier::Active, CycleOutcome::Incomplete),
            ReportAction::ProgressOnly
        );

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Incomplete,
        );

        assert!(!admission.decision(Rail::DirectBitcoin).allowed());
    }

    #[test]
    fn healthy_tier_cannot_open_startup_while_other_tier_is_unknown() {
        let (admission, reporter, mut tier_health) = admission_fixture();

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Healthy,
        );
        assert_eq!(tier_health.active, TierState::Healthy);
        assert_eq!(tier_health.idle, TierState::Unknown);
        assert!(!admission.decision(Rail::DirectBitcoin).allowed());

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Idle,
            CycleOutcome::Healthy,
        );
        assert!(admission.decision(Rail::DirectBitcoin).allowed());
    }

    #[test]
    fn incomplete_page_does_not_mutate_tier_failure_or_recovery_latch() {
        let mut tier_health = TierHealth::default();
        assert_eq!(
            tier_health.observe(WatchTier::Idle, CycleOutcome::Failed),
            ReportAction::Failure
        );
        assert_eq!(tier_health.idle, TierState::Failed);

        assert_eq!(
            tier_health.observe(WatchTier::Idle, CycleOutcome::Incomplete),
            ReportAction::ProgressOnly
        );
        assert_eq!(tier_health.idle, TierState::Failed);
        assert_eq!(tier_health.active, TierState::Unknown);
    }

    #[test]
    fn token_exhaustion_requires_useful_progress_for_incomplete() {
        assert_eq!(
            CycleOutcome::after_token_exhaustion(0),
            CycleOutcome::Failed
        );
        assert_eq!(
            CycleOutcome::after_token_exhaustion(1),
            CycleOutcome::Incomplete
        );
    }

    #[tokio::test]
    async fn failing_tip_probe_prevents_empty_startup_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind counting tip server");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("tip server address")
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let server_calls = calls.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept tip request");
            let mut request = [0u8; 1_024];
            let _ = socket.read(&mut request).await;
            server_calls.fetch_add(1, Ordering::SeqCst);
            socket
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await
                .expect("write failing tip response");
        });

        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .expect("lazy test pool");
        let cfg = BitcoinWatcherConfig {
            endpoint: endpoint.clone(),
            endpoints: Vec::new(),
            request_timeout_ms: 1_000,
            ..BitcoinWatcherConfig::default()
        };
        let mut watcher =
            BitcoinWatcher::new(cfg, db::InvoiceAccountingTolerances::default(), pool)
                .expect("bitcoin watcher");
        // Keep the unit test hermetic: production construction appends public
        // failovers, while this test needs exactly one counting endpoint.
        watcher.endpoints = vec![endpoint];
        let cancel = CancellationToken::new();
        let (admission, reporter, mut tier_health) = admission_fixture();
        let mut epoch = db::WatcherScanEpoch::default();

        // The lazy pool has no server behind it. The tip probe must run before
        // any empty/page lookup can short-circuit the tier as healthy.
        let outcome = watcher
            .poll_tier(true, &cancel, &reporter, &mut epoch)
            .await;
        server.await.expect("counting tip server");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(outcome, CycleOutcome::Failed);
        report_outcome(&reporter, &mut tier_health, WatchTier::Active, outcome);
        assert_eq!(tier_health.active, TierState::Failed);
        assert!(!admission.decision(Rail::DirectBitcoin).allowed());
    }

    #[test]
    fn active_success_does_not_reset_interleaved_idle_failures() {
        let (admission, reporter, mut tier_health) = admission_fixture();
        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Healthy,
        );

        for attempt in 1..=3 {
            report_outcome(
                &reporter,
                &mut tier_health,
                WatchTier::Idle,
                CycleOutcome::Failed,
            );
            if attempt < 3 {
                report_outcome(
                    &reporter,
                    &mut tier_health,
                    WatchTier::Active,
                    CycleOutcome::Healthy,
                );
            }
        }

        assert!(!admission.decision(Rail::DirectBitcoin).allowed());
    }

    #[test]
    fn two_successes_reopen_after_both_tiers_are_healthy() {
        let (admission, reporter, mut tier_health) = admission_fixture();
        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Healthy,
        );
        for _ in 0..3 {
            report_outcome(
                &reporter,
                &mut tier_health,
                WatchTier::Idle,
                CycleOutcome::Failed,
            );
            report_outcome(
                &reporter,
                &mut tier_health,
                WatchTier::Active,
                CycleOutcome::Healthy,
            );
        }
        assert!(!admission.decision(Rail::DirectBitcoin).allowed());

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Idle,
            CycleOutcome::Healthy,
        );
        assert!(!admission.decision(Rail::DirectBitcoin).allowed());
        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Healthy,
        );

        assert!(admission.decision(Rail::DirectBitcoin).allowed());
    }
}

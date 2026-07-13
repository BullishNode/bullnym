//! On-chain BTC watcher for invoice settlement.
//!
//! Polls a mempool.space-shape API (Bull's own `mempool.bullbitcoin.com` by
//! default — see `BitcoinWatcherConfig`) for open direct-Bitcoin invoices and
//! for invoices with durable Bitcoin evidence that still requires tx-specific
//! follow-up. Every positive or explicit-regression view is applied through the
//! direct-payment generation/reducer transaction.
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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize};
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
    block_hash: Option<String>,
}

#[derive(Deserialize, Debug)]
struct MempoolBlockStatus {
    in_best_chain: bool,
}

/// Optional mempool.space extension (`/api/v1/tx/:txid/rbf`). Plain Esplora
/// servers do not expose this route; an unsupported response is cached as a
/// capability miss and is never interpreted as replacement evidence.
#[derive(Deserialize, Debug)]
struct MempoolRbfHistory {
    replacements: Option<MempoolRbfNode>,
}

#[derive(Deserialize, Debug)]
struct MempoolRbfNode {
    tx: MempoolRbfTx,
    #[serde(default)]
    replaces: Vec<MempoolRbfNode>,
}

#[derive(Deserialize, Debug)]
struct MempoolRbfTx {
    txid: String,
}

#[derive(Debug)]
enum EndpointFetch<T> {
    Found(T),
    NotFound,
    Retry,
    Backoff,
    BudgetExhausted,
}

#[derive(Debug)]
enum EndpointEvidence {
    Ready(Vec<BtcDirectObservation>),
    Incomplete,
    HardBound,
    Retry,
    Backoff,
}

#[derive(Debug)]
enum AddressHistoryFetch {
    Complete(Vec<MempoolTx>),
    Incomplete,
    HardBound,
    Retry,
    Backoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvoiceCheckOutcome {
    Complete,
    Incomplete,
    HardBound,
    Failed,
}

#[derive(Clone, Copy)]
struct RequestPermit<'a> {
    cancel: &'a CancellationToken,
    reporter: &'a WorkerReporter,
}

const WATCHER_BATCH_SIZE: usize = 1_000;
const ESPLORA_CONFIRMED_PAGE_SIZE: usize = 25;
/// Bull's Esplora-compatible address route and the public failover currently
/// return up to fifty confirmed transactions on the initial route. Cursor
/// continuation pages retain the canonical Esplora size of twenty-five.
const EXTENDED_FIRST_CONFIRMED_PAGE_SIZE: usize = 50;
/// One bounded initial address response plus at most fifteen canonical older
/// confirmed pages. A full final page is deliberately incomplete: the watcher
/// retains the invoice and never applies a truncated generation.
const MAX_CONFIRMED_HISTORY_PAGES: usize = 16;
const MAX_RBF_TREE_NODES: usize = 256;
const MAX_FIRST_ADDRESS_TRANSACTIONS: usize = 64;
const MAX_ADDRESS_HISTORY_TRANSACTIONS: usize = MAX_FIRST_ADDRESS_TRANSACTIONS
    + (MAX_CONFIRMED_HISTORY_PAGES - 1) * ESPLORA_CONFIRMED_PAGE_SIZE;
const MAX_KNOWN_DIRECT_OBSERVATIONS: usize = 128;
const MAX_KNOWN_DIRECT_TXIDS: usize = 64;
const MAX_REDUCER_OBSERVATIONS: usize = 128;

const BITCOIN_WATCHER_PAGE_SQL: &str = "SELECT id, bitcoin_address, amount_sat, \
            created_at::TEXT AS created_at_cursor \
     FROM invoices \
     WHERE bitcoin_address IS NOT NULL \
       AND status NOT IN ('cancelled', 'expired') \
       AND ( \
             ( \
               status IN ('unpaid', 'in_progress', 'partially_paid') \
               AND accept_btc = TRUE \
               AND expires_at + ($2 || ' seconds')::interval > $3::timestamptz \
             ) \
             OR EXISTS ( \
               SELECT 1 FROM invoice_payment_observations o \
               WHERE o.invoice_id = invoices.id \
                 AND o.source = 'bitcoin_direct' \
                 AND o.last_seen_state <> 'superseded' \
             ) \
             OR EXISTS ( \
               SELECT 1 FROM invoice_payment_events e \
               WHERE e.invoice_id = invoices.id \
                 AND e.source = 'bitcoin_direct' \
                 AND e.accounting_state <> 'superseded' \
             ) \
           ) \
       AND created_at {cmp} $3::timestamptz - ($1 || ' seconds')::interval \
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

fn bitcoin_known_evidence_is_hard_bound(known: &[db::BitcoinDirectWatchEvidence]) -> bool {
    known.len() > MAX_KNOWN_DIRECT_OBSERVATIONS
        || known
            .iter()
            .map(|evidence| evidence.txid.to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
            .len()
            > MAX_KNOWN_DIRECT_TXIDS
}

fn should_start_next_invoice(processed_any: bool, token_available: bool) -> bool {
    !processed_any || token_available
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CycleOutcome {
    Healthy,
    Incomplete,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchTier {
    Active,
    Idle,
}

#[derive(Debug, Default)]
struct BitcoinTierScanEpoch {
    scan: db::WatcherScanEpoch,
    hard_bound_failure: bool,
}

impl BitcoinTierScanEpoch {
    fn note_hard_bound(&mut self, cursor: db::WatcherScanCursor) {
        self.hard_bound_failure = true;
        self.scan.advance(cursor);
    }

    fn finish_outcome(&mut self) -> CycleOutcome {
        self.scan.finish();
        if std::mem::take(&mut self.hard_bound_failure) {
            CycleOutcome::Failed
        } else {
            CycleOutcome::Healthy
        }
    }
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
    rbf_capabilities: Arc<AsyncMutex<BTreeMap<String, bool>>>,
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
            rbf_capabilities: Arc::new(AsyncMutex::new(BTreeMap::new())),
        })
    }

    /// Top-level loop. Returns when `cancel` fires.
    pub async fn run(self, cancel: CancellationToken, mut reporter: WorkerReporter) {
        let mut tier_health = TierHealth::default();
        let mut active_epoch = BitcoinTierScanEpoch::default();
        let mut idle_epoch = BitcoinTierScanEpoch::default();
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
        epoch: &mut BitcoinTierScanEpoch,
    ) -> CycleOutcome {
        reporter.progress();
        if cancel.is_cancelled() {
            return CycleOutcome::Incomplete;
        }
        let request = RequestPermit { cancel, reporter };

        // Probe the evidence backend even when the database page is empty. An
        // enabled URL list is configuration, not proof that this process can
        // currently observe a direct-Bitcoin payment.
        let (probe_tip, endpoint) = match self.fetch_tip_and_endpoint(request).await {
            EndpointFetch::Found(pair) => pair,
            EndpointFetch::BudgetExhausted => return CycleOutcome::Incomplete,
            EndpointFetch::NotFound | EndpointFetch::Retry | EndpointFetch::Backoff => {
                tracing::warn!(
                    "bitcoin_watcher: tip-height fetch failed on all endpoints; skipping tick"
                );
                return CycleOutcome::Failed;
            }
        };

        if epoch.scan.snapshot().is_none() {
            match db::watcher_scan_snapshot(&self.pool).await {
                Ok(snapshot) => epoch.scan.begin(snapshot),
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
            return epoch.finish_outcome();
        }

        let mut processed_any = false;
        for inv in batch.invoices {
            if !should_start_next_invoice(processed_any, self.token_available().await) {
                // Waiting is reserved for an already-started atomic invoice.
                // Yield between rows so a large active page cannot monopolize
                // the single watcher loop and delay the idle tier indefinitely.
                return CycleOutcome::Incomplete;
            }
            reporter.progress();
            if cancel.is_cancelled() {
                return CycleOutcome::Incomplete;
            }
            match self
                .check_invoice(&inv, &endpoint, probe_tip, request)
                .await
            {
                InvoiceCheckOutcome::Complete => {
                    processed_any = true;
                }
                InvoiceCheckOutcome::Incomplete => {
                    // Keep the cursor on the last fully applied invoice. Any
                    // pages/follow-ups fetched for this row are discarded and
                    // its reserved generation remains unapplied.
                    return CycleOutcome::Incomplete;
                }
                InvoiceCheckOutcome::HardBound => {
                    // This row cannot fit the process-local evidence bound in
                    // this epoch. Retire only its keyset position so later
                    // obligations remain observable, but remember the epoch
                    // failure and never apply its truncated generation.
                    epoch.note_hard_bound(inv.scan_cursor());
                    processed_any = true;
                    continue;
                }
                InvoiceCheckOutcome::Failed => {
                    // Keep the cursor on the last proven row. The failed invoice
                    // is retried on the next page instead of being skipped.
                    return CycleOutcome::Failed;
                }
            }
            epoch.scan.advance(inv.scan_cursor());
        }

        if batch.has_more {
            CycleOutcome::Incomplete
        } else {
            epoch.finish_outcome()
        }
    }

    async fn fetch_invoices(
        &self,
        is_active: bool,
        epoch: &BitcoinTierScanEpoch,
    ) -> Result<InvoicePollBatch, sqlx::Error> {
        // Active tier: created within last `active_window_secs`.
        // Idle tier:   created earlier than that (the rest of the still-
        //              unpaid corpus). Both predicates exclude expired
        //              rows so the watcher doesn't waste an RPS slot on
        //              a row about to be GC'd.
        let cmp = if is_active { ">" } else { "<=" };
        let snapshot = epoch
            .scan
            .snapshot()
            .expect("watcher epoch snapshot initialized before page query");
        let cursor = epoch.scan.cursor();
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

    /// Fetch the chain tip from a single endpoint. Transport/non-2xx/parse
    /// failures are retryable; local request-budget exhaustion is distinct.
    /// `/blocks/tip/height` returns a bare int.
    async fn fetch_tip_from(
        &self,
        endpoint: &str,
        request: RequestPermit<'_>,
    ) -> EndpointFetch<u32> {
        if !self.acquire_token(request).await {
            return EndpointFetch::BudgetExhausted;
        }
        let ep = endpoint.trim_end_matches('/');
        let url = format!("{ep}/blocks/tip/height");
        let resp = match self.http.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::warn!(event = "btc_esplora_failover", op = "tip", endpoint = %ep, status = %r.status());
                return EndpointFetch::Retry;
            }
            Err(e) => {
                tracing::warn!(event = "btc_esplora_failover", op = "tip", endpoint = %ep, err = %e);
                return EndpointFetch::Retry;
            }
        };
        let body = match resp.text().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(event = "btc_esplora_failover", op = "tip", endpoint = %ep, err = %e);
                return EndpointFetch::Retry;
            }
        };
        match body.trim().parse::<u32>() {
            Ok(h) => EndpointFetch::Found(h),
            Err(_) => {
                tracing::warn!(
                    event = "btc_esplora_failover", op = "tip", endpoint = %ep,
                    "tip body did not parse as u32: '{}'",
                    body.chars().take(64).collect::<String>()
                );
                EndpointFetch::Retry
            }
        }
    }

    /// Fetch the chain tip, failing over across endpoints. Returns the tip AND
    /// the endpoint that served it, so the tick's address queries can start on
    /// the same node (consistent confirmation math). `Retry` means every
    /// endpoint failed.
    async fn fetch_tip_and_endpoint(
        &self,
        request: RequestPermit<'_>,
    ) -> EndpointFetch<(u32, String)> {
        for ep in &self.endpoints {
            let ep = ep.trim_end_matches('/');
            match self.fetch_tip_from(ep, request).await {
                EndpointFetch::Found(h) => {
                    return EndpointFetch::Found((h, ep.to_string()));
                }
                EndpointFetch::BudgetExhausted => return EndpointFetch::BudgetExhausted,
                EndpointFetch::NotFound | EndpointFetch::Retry | EndpointFetch::Backoff => {}
            }
        }
        tracing::error!(
            event = "btc_esplora_all_endpoints_failed",
            op = "tip",
            endpoints = self.endpoints.len(),
            "all esplora endpoints failed the tip fetch"
        );
        EndpointFetch::Retry
    }

    /// Reserve the invoice/source generation before any chain evidence used by
    /// this scan is fetched. One endpoint supplies the tip, discovery response,
    /// known-tx follow-ups, and block-regression proof; partial endpoint views
    /// are discarded rather than mixed across authorities.
    async fn check_invoice(
        &self,
        inv: &InvoiceForBtcPoll,
        endpoint: &str,
        endpoint_tip: u32,
        request: RequestPermit<'_>,
    ) -> InvoiceCheckOutcome {
        let reporter = request.reporter;
        let generation = match db::reserve_direct_observation_generation(
            &self.pool,
            inv.id,
            db::DirectPaymentSource::Bitcoin,
        )
        .await
        {
            Ok(generation) => generation,
            Err(e) => {
                tracing::warn!(
                    event = "bitcoin_watcher_generation_reserve_failed",
                    invoice_id = %inv.id,
                    "bitcoin_watcher: direct observation generation reserve failed: {e}"
                );
                return InvoiceCheckOutcome::Failed;
            }
        };
        let known = match db::list_bitcoin_direct_watch_evidence(
            &self.pool,
            inv.id,
            (MAX_KNOWN_DIRECT_OBSERVATIONS + 1) as i64,
        )
        .await
        {
            Ok(known) => known,
            Err(e) => {
                tracing::warn!(
                    event = "bitcoin_watcher_known_evidence_failed",
                    invoice_id = %inv.id,
                    "bitcoin_watcher: durable Bitcoin evidence query failed: {e}"
                );
                return InvoiceCheckOutcome::Failed;
            }
        };
        if bitcoin_known_evidence_is_hard_bound(&known) {
            tracing::warn!(
                event = "bitcoin_watcher_known_evidence_bound_reached",
                invoice_id = %inv.id,
                observations = known.len(),
                observation_limit = MAX_KNOWN_DIRECT_OBSERVATIONS,
                txid_limit = MAX_KNOWN_DIRECT_TXIDS,
                "bitcoin_watcher: durable evidence exceeds the bounded atomic invoice budget"
            );
            return InvoiceCheckOutcome::HardBound;
        }

        // Failover order: the successful health-probe endpoint first, then the
        // remaining configured endpoints. Each attempt fetches its own tip.
        let chosen = endpoint.trim_end_matches('/');
        let mut order = vec![(chosen, Some(endpoint_tip))];
        for ep in &self.endpoints {
            let ep = ep.trim_end_matches('/');
            if ep != chosen {
                order.push((ep, None));
            }
        }

        let mut endpoint_errors: Vec<String> = Vec::new();
        for (idx, (ep, known_tip)) in order.into_iter().enumerate() {
            reporter.progress();
            let ep_tip = match known_tip {
                Some(tip) => tip,
                None => match self.fetch_tip_from(ep, request).await {
                    EndpointFetch::Found(tip) => tip,
                    EndpointFetch::BudgetExhausted => {
                        return InvoiceCheckOutcome::Incomplete;
                    }
                    EndpointFetch::NotFound | EndpointFetch::Retry | EndpointFetch::Backoff => {
                        endpoint_errors.push(format!("{ep}: tip fetch failed"));
                        continue;
                    }
                },
            };

            let observations = match self
                .collect_endpoint_evidence(inv, &known, ep_tip, ep, request)
                .await
            {
                EndpointEvidence::Ready(observations) => observations,
                EndpointEvidence::Incomplete => return InvoiceCheckOutcome::Incomplete,
                EndpointEvidence::HardBound => return InvoiceCheckOutcome::HardBound,
                EndpointEvidence::Retry => {
                    endpoint_errors.push(format!("{ep}: incomplete evidence view"));
                    continue;
                }
                EndpointEvidence::Backoff => return InvoiceCheckOutcome::Incomplete,
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

            let reducer_observations: Vec<_> = observations
                .iter()
                .map(BtcDirectObservation::as_reducer_observation)
                .collect();
            let applied = db::apply_direct_observation_batch(
                &self.pool,
                db::DirectObservationBatch {
                    invoice_id: inv.id,
                    source: db::DirectPaymentSource::Bitcoin,
                    authority: ep,
                    generation,
                    observations: &reducer_observations,
                },
                self.tolerances,
            )
            .await;
            return match applied {
                Ok(db::ApplyDirectObservationOutcome::Applied { changed }) => {
                    tracing::info!(
                        event = "bitcoin_direct_observation_batch_applied",
                        invoice_id = %inv.id,
                        generation,
                        changed,
                        observations = reducer_observations.len(),
                        amount_sat = inv.amount_sat,
                        authority = %ep,
                        "bitcoin_watcher: direct observation batch applied"
                    );
                    InvoiceCheckOutcome::Complete
                }
                Ok(
                    db::ApplyDirectObservationOutcome::AlreadyApplied
                    | db::ApplyDirectObservationOutcome::Stale { .. }
                    | db::ApplyDirectObservationOutcome::Closed,
                ) => InvoiceCheckOutcome::Complete,
                Err(e) => {
                    tracing::error!(
                        event = "bitcoin_direct_observation_batch_failed",
                        invoice_id = %inv.id,
                        generation,
                        authority = %ep,
                        "bitcoin_watcher: direct observation batch failed: {e}"
                    );
                    InvoiceCheckOutcome::Failed
                }
            };
        }

        tracing::warn!(
            event = "btc_esplora_all_endpoints_failed",
            op = "address_txs",
            invoice_id = %inv.id,
            "bitcoin_watcher: all esplora endpoints failed the address-txs fetch this tick: {}",
            endpoint_errors.join(" | ")
        );
        InvoiceCheckOutcome::Failed
    }

    /// Fetch one complete, bounded address-history snapshot from a single
    /// Esplora authority. The first route contains mempool transactions plus
    /// either the canonical newest 25 confirmed transactions or the observed
    /// extended first response of 50. Older confirmed pages always use the
    /// documented 25-item last-seen cursor contract. No caller may apply the
    /// returned prefix until the terminal short page has proved completeness.
    async fn fetch_complete_address_history(
        &self,
        inv: &InvoiceForBtcPoll,
        endpoint: &str,
        request: RequestPermit<'_>,
    ) -> AddressHistoryFetch {
        let reporter = request.reporter;
        let address_url = format!("{endpoint}/address/{}/txs", inv.bitcoin_address);
        let first: Vec<MempoolTx> = match self
            .fetch_json(&address_url, "address_txs", inv.id, endpoint, request)
            .await
        {
            EndpointFetch::Found(txs) => txs,
            EndpointFetch::BudgetExhausted => return AddressHistoryFetch::Incomplete,
            EndpointFetch::Backoff => return AddressHistoryFetch::Backoff,
            EndpointFetch::NotFound | EndpointFetch::Retry => {
                return AddressHistoryFetch::Retry;
            }
        };
        if first.len() > MAX_FIRST_ADDRESS_TRANSACTIONS {
            tracing::warn!(
                event = "bitcoin_watcher_address_history_bound_reached",
                invoice_id = %inv.id,
                endpoint = %endpoint,
                observed = first.len(),
                limit = MAX_FIRST_ADDRESS_TRANSACTIONS,
                "bitcoin_watcher: first address page exceeded the bounded transaction budget"
            );
            return AddressHistoryFetch::HardBound;
        }

        let mut seen = BTreeSet::new();
        for tx in &first {
            if !remember_canonical_bitcoin_txid(&mut seen, &tx.txid) {
                tracing::warn!(
                    event = "bitcoin_watcher_invalid_address_history",
                    invoice_id = %inv.id,
                    endpoint = %endpoint,
                    "bitcoin_watcher: first address page had an invalid or duplicate txid"
                );
                return AddressHistoryFetch::Retry;
            }
        }

        let first_confirmed = first.iter().filter(|tx| tx.status.confirmed).count();
        if first_confirmed > ESPLORA_CONFIRMED_PAGE_SIZE
            && first_confirmed != EXTENDED_FIRST_CONFIRMED_PAGE_SIZE
        {
            tracing::warn!(
                event = "bitcoin_watcher_invalid_address_history",
                invoice_id = %inv.id,
                endpoint = %endpoint,
                first_confirmed,
                canonical_limit = ESPLORA_CONFIRMED_PAGE_SIZE,
                extended_first_limit = EXTENDED_FIRST_CONFIRMED_PAGE_SIZE,
                "bitcoin_watcher: first address page had an unsupported confirmed transaction count"
            );
            return AddressHistoryFetch::Retry;
        }

        let mut history = first;
        let mut confirmed_in_page = first_confirmed;
        let mut last_seen_txid = history
            .iter()
            .rev()
            .find(|tx| tx.status.confirmed)
            .map(|tx| tx.txid.clone());
        let mut pages = 1usize;

        while matches!(
            confirmed_in_page,
            ESPLORA_CONFIRMED_PAGE_SIZE | EXTENDED_FIRST_CONFIRMED_PAGE_SIZE
        ) {
            let Some(cursor) = last_seen_txid.as_deref() else {
                return AddressHistoryFetch::Retry;
            };
            reporter.progress();
            let page_url = format!(
                "{endpoint}/address/{}/txs/chain/{cursor}",
                inv.bitcoin_address
            );
            let page: Vec<MempoolTx> = match self
                .fetch_json(&page_url, "address_txs_chain", inv.id, endpoint, request)
                .await
            {
                EndpointFetch::Found(txs) => txs,
                EndpointFetch::BudgetExhausted => return AddressHistoryFetch::Incomplete,
                EndpointFetch::Backoff => return AddressHistoryFetch::Backoff,
                EndpointFetch::NotFound | EndpointFetch::Retry => {
                    return AddressHistoryFetch::Retry;
                }
            };
            if page.len() > ESPLORA_CONFIRMED_PAGE_SIZE
                || page.iter().any(|tx| !tx.status.confirmed)
            {
                tracing::warn!(
                    event = "bitcoin_watcher_invalid_address_history",
                    invoice_id = %inv.id,
                    endpoint = %endpoint,
                    "bitcoin_watcher: confirmed-history page had an invalid shape"
                );
                return AddressHistoryFetch::Retry;
            }
            for tx in &page {
                if !remember_canonical_bitcoin_txid(&mut seen, &tx.txid) {
                    tracing::warn!(
                        event = "bitcoin_watcher_invalid_address_history",
                        invoice_id = %inv.id,
                        endpoint = %endpoint,
                        "bitcoin_watcher: confirmed-history cursor repeated or returned an invalid txid"
                    );
                    return AddressHistoryFetch::Retry;
                }
            }
            if pages >= MAX_CONFIRMED_HISTORY_PAGES {
                if page.is_empty() {
                    break;
                }
                tracing::warn!(
                    event = "bitcoin_watcher_address_history_bound_reached",
                    invoice_id = %inv.id,
                    endpoint = %endpoint,
                    pages,
                    "bitcoin_watcher: bounded address history remained full; skipping this row for the epoch without applying a partial generation"
                );
                return AddressHistoryFetch::HardBound;
            }
            if history.len().saturating_add(page.len()) > MAX_ADDRESS_HISTORY_TRANSACTIONS {
                return AddressHistoryFetch::HardBound;
            }
            confirmed_in_page = page.len();
            last_seen_txid = page.last().map(|tx| tx.txid.clone());
            history.extend(page);
            pages += 1;
        }

        AddressHistoryFetch::Complete(history)
    }

    async fn collect_endpoint_evidence(
        &self,
        inv: &InvoiceForBtcPoll,
        known: &[db::BitcoinDirectWatchEvidence],
        tip: u32,
        endpoint: &str,
        request: RequestPermit<'_>,
    ) -> EndpointEvidence {
        let reporter = request.reporter;
        if bitcoin_known_evidence_is_hard_bound(known) {
            return EndpointEvidence::HardBound;
        }
        let discovered = match self
            .fetch_complete_address_history(inv, endpoint, request)
            .await
        {
            AddressHistoryFetch::Complete(txs) => txs,
            AddressHistoryFetch::Incomplete => return EndpointEvidence::Incomplete,
            AddressHistoryFetch::HardBound => return EndpointEvidence::HardBound,
            AddressHistoryFetch::Retry => return EndpointEvidence::Retry,
            AddressHistoryFetch::Backoff => return EndpointEvidence::Backoff,
        };

        let mut observations = BTreeMap::new();
        for tx in &discovered {
            reporter.progress();
            let discovered_outputs = match bitcoin_direct_observations_for_tx(
                tx,
                &inv.bitcoin_address,
                tip,
                self.cfg.confirmations_required,
            ) {
                Ok(outputs) => outputs,
                Err(e) => {
                    tracing::warn!(
                        event = "bitcoin_watcher_invalid_positive_evidence",
                        invoice_id = %inv.id,
                        txid = %tx.txid,
                        endpoint = %endpoint,
                        "bitcoin_watcher: rejected address discovery response: {e}"
                    );
                    return EndpointEvidence::Retry;
                }
            };
            for observation in discovered_outputs {
                observations.insert(observation.event_key.clone(), observation);
                if observations.len() > MAX_REDUCER_OBSERVATIONS {
                    return EndpointEvidence::HardBound;
                }
            }
        }

        // A successful address history is discovery evidence only. Every
        // durable transaction gets one tx-specific check; grouping by txid also
        // lets one positively proven replacement map multiple merchant outputs
        // one-to-one without issuing duplicate RBF capability requests.
        let mut known_by_txid: BTreeMap<&str, Vec<&db::BitcoinDirectWatchEvidence>> =
            BTreeMap::new();
        for evidence in known {
            known_by_txid
                .entry(evidence.txid.as_str())
                .or_default()
                .push(evidence);
        }
        for (known_txid, evidence_group) in known_by_txid {
            reporter.progress();
            for evidence in &evidence_group {
                // A known identity is never updated from address discovery.
                observations.remove(&evidence.event_key);
            }
            let tx_url = format!("{endpoint}/tx/{known_txid}");
            match self
                .fetch_json::<MempoolTx>(&tx_url, "known_tx", inv.id, endpoint, request)
                .await
            {
                EndpointFetch::Found(tx) => {
                    for evidence in &evidence_group {
                        let current = match bitcoin_direct_observation_for_known(
                            &tx,
                            evidence,
                            tip,
                            self.cfg.confirmations_required,
                        ) {
                            Ok(current) => current,
                            Err(e) => {
                                tracing::warn!(
                                    event = "bitcoin_watcher_invalid_known_evidence",
                                    invoice_id = %inv.id,
                                    txid = %evidence.txid,
                                    endpoint = %endpoint,
                                    "bitcoin_watcher: rejected tx-specific response: {e}"
                                );
                                return EndpointEvidence::Retry;
                            }
                        };
                        match self
                            .reconcile_known_block_view(
                                evidence, current, inv.id, endpoint, request,
                            )
                            .await
                        {
                            EndpointFetch::Found(Some(observation)) => {
                                observations.insert(observation.event_key.clone(), observation);
                            }
                            EndpointFetch::Found(None) | EndpointFetch::NotFound => {}
                            EndpointFetch::BudgetExhausted => {
                                return EndpointEvidence::Incomplete;
                            }
                            EndpointFetch::Retry => return EndpointEvidence::Retry,
                            EndpointFetch::Backoff => return EndpointEvidence::Backoff,
                        }
                    }
                }
                EndpointFetch::NotFound => {
                    match self
                        .replacement_for_missing(&evidence_group, inv, tip, endpoint, request)
                        .await
                    {
                        EndpointFetch::Found(Some(replacement_observations)) => {
                            for observation in replacement_observations {
                                if observations
                                    .get(&observation.event_key)
                                    .is_some_and(|prior| {
                                        prior.supersedes_event_key.is_some()
                                            && observation.supersedes_event_key.is_some()
                                            && prior.supersedes_event_key
                                                != observation.supersedes_event_key
                                    })
                                {
                                    tracing::warn!(
                                        event = "bitcoin_watcher_competing_replacement_mapping",
                                        invoice_id = %inv.id,
                                        replacement_event_key = %observation.event_key,
                                        endpoint = %endpoint,
                                        "bitcoin_watcher: one replacement output cannot supersede multiple durable outputs"
                                    );
                                    return EndpointEvidence::Retry;
                                }
                                observations.insert(observation.event_key.clone(), observation);
                                if observations.len() > MAX_REDUCER_OBSERVATIONS {
                                    return EndpointEvidence::HardBound;
                                }
                            }
                        }
                        EndpointFetch::Found(None) | EndpointFetch::NotFound => {
                            for evidence in &evidence_group {
                                match self
                                    .explicit_reorg_for_missing(evidence, inv.id, endpoint, request)
                                    .await
                                {
                                    EndpointFetch::Found(Some(regression)) => {
                                        observations
                                            .insert(regression.event_key.clone(), regression);
                                    }
                                    EndpointFetch::Found(None) | EndpointFetch::NotFound => {}
                                    EndpointFetch::BudgetExhausted => {
                                        return EndpointEvidence::Incomplete;
                                    }
                                    EndpointFetch::Retry => return EndpointEvidence::Retry,
                                    EndpointFetch::Backoff => return EndpointEvidence::Backoff,
                                }
                            }
                        }
                        EndpointFetch::BudgetExhausted => return EndpointEvidence::Incomplete,
                        EndpointFetch::Retry => return EndpointEvidence::Retry,
                        EndpointFetch::Backoff => return EndpointEvidence::Backoff,
                    }
                }
                EndpointFetch::BudgetExhausted => return EndpointEvidence::Incomplete,
                EndpointFetch::Retry => return EndpointEvidence::Retry,
                EndpointFetch::Backoff => return EndpointEvidence::Backoff,
            }
        }

        if observations.len() > MAX_REDUCER_OBSERVATIONS {
            EndpointEvidence::HardBound
        } else {
            EndpointEvidence::Ready(observations.into_values().collect())
        }
    }

    async fn replacement_for_missing(
        &self,
        evidence: &[&db::BitcoinDirectWatchEvidence],
        inv: &InvoiceForBtcPoll,
        tip: u32,
        endpoint: &str,
        request: RequestPermit<'_>,
    ) -> EndpointFetch<Option<Vec<BtcDirectObservation>>> {
        let reporter = request.reporter;
        let Some(first) = evidence.first() else {
            return EndpointFetch::Found(None);
        };
        let history = match self
            .fetch_optional_rbf_history(&first.txid, inv.id, endpoint, request)
            .await
        {
            EndpointFetch::Found(history) => history,
            EndpointFetch::NotFound => return EndpointFetch::Found(None),
            EndpointFetch::BudgetExhausted => return EndpointFetch::BudgetExhausted,
            EndpointFetch::Retry => return EndpointFetch::Retry,
            EndpointFetch::Backoff => return EndpointFetch::Backoff,
        };
        let replacement_txid = match latest_replacement_txid(&history, &first.txid) {
            Ok(Some(txid)) => txid,
            Ok(None) => return EndpointFetch::Found(None),
            Err(error) => {
                tracing::warn!(
                    event = "bitcoin_watcher_invalid_rbf_history",
                    invoice_id = %inv.id,
                    txid = %first.txid,
                    endpoint = %endpoint,
                    "bitcoin_watcher: rejected provider RBF relation: {error}"
                );
                return EndpointFetch::Retry;
            }
        };

        // A canonical prior block contradicts replacement evidence. Require
        // positive orphan proof before replacing any previously confirmed
        // identity; a timeout/404 remains conservative.
        if let Some(confirmed) = evidence
            .iter()
            .copied()
            .find(|item| evidence_had_confirmed_block(item))
        {
            let Some(block_hash) = confirmed.block_hash.as_deref() else {
                return EndpointFetch::Retry;
            };
            match self
                .fetch_block_status(block_hash, inv.id, endpoint, request)
                .await
            {
                EndpointFetch::Found(status) if !status.in_best_chain => {}
                EndpointFetch::Found(_) | EndpointFetch::NotFound | EndpointFetch::Retry => {
                    return EndpointFetch::Retry;
                }
                EndpointFetch::BudgetExhausted => return EndpointFetch::BudgetExhausted,
                EndpointFetch::Backoff => return EndpointFetch::Backoff,
            }
        }

        reporter.progress();
        let replacement_url = format!("{endpoint}/tx/{replacement_txid}");
        let replacement = match self
            .fetch_json::<MempoolTx>(
                &replacement_url,
                "replacement_tx",
                inv.id,
                endpoint,
                request,
            )
            .await
        {
            EndpointFetch::Found(tx) => tx,
            EndpointFetch::BudgetExhausted => return EndpointFetch::BudgetExhausted,
            EndpointFetch::NotFound | EndpointFetch::Retry => return EndpointFetch::Retry,
            EndpointFetch::Backoff => return EndpointFetch::Backoff,
        };
        match replacement_observations_for_known(
            &replacement,
            &replacement_txid,
            evidence,
            &inv.bitcoin_address,
            tip,
            self.cfg.confirmations_required,
        ) {
            Ok(observations) => EndpointFetch::Found(Some(observations)),
            Err(error) => {
                tracing::warn!(
                    event = "bitcoin_watcher_invalid_replacement_evidence",
                    invoice_id = %inv.id,
                    old_txid = %first.txid,
                    replacement_txid = %replacement_txid,
                    endpoint = %endpoint,
                    "bitcoin_watcher: rejected replacement transaction: {error}"
                );
                EndpointFetch::Retry
            }
        }
    }

    async fn reconcile_known_block_view(
        &self,
        evidence: &db::BitcoinDirectWatchEvidence,
        current: BtcDirectObservation,
        invoice_id: Uuid,
        endpoint: &str,
        request: RequestPermit<'_>,
    ) -> EndpointFetch<Option<BtcDirectObservation>> {
        if !evidence_had_confirmed_block(evidence) {
            return EndpointFetch::Found(Some(current));
        }

        let current_block_changed = current.block_height != evidence.block_height
            || current.block_hash.as_deref() != evidence.block_hash.as_deref();
        if !current_block_changed {
            return EndpointFetch::Found(Some(current));
        }

        let block_hash = evidence
            .block_hash
            .as_deref()
            .expect("confirmed evidence has a block hash");
        match self
            .fetch_block_status(block_hash, invoice_id, endpoint, request)
            .await
        {
            EndpointFetch::Found(status) if !status.in_best_chain => {
                match current.with_block_regression(evidence) {
                    Ok(current) => EndpointFetch::Found(Some(current)),
                    Err(e) => {
                        tracing::warn!(
                            event = "bitcoin_watcher_invalid_block_regression",
                            invoice_id = %invoice_id,
                            txid = %evidence.txid,
                            endpoint = %endpoint,
                            "bitcoin_watcher: could not build atomic reorg evidence: {e}"
                        );
                        EndpointFetch::Retry
                    }
                }
            }
            EndpointFetch::Found(_) => EndpointFetch::Retry,
            EndpointFetch::NotFound | EndpointFetch::Retry => EndpointFetch::Retry,
            EndpointFetch::Backoff => EndpointFetch::Backoff,
            EndpointFetch::BudgetExhausted => EndpointFetch::BudgetExhausted,
        }
    }

    async fn explicit_reorg_for_missing(
        &self,
        evidence: &db::BitcoinDirectWatchEvidence,
        invoice_id: Uuid,
        endpoint: &str,
        request: RequestPermit<'_>,
    ) -> EndpointFetch<Option<BtcDirectObservation>> {
        if !evidence_had_confirmed_block(evidence) {
            return EndpointFetch::Found(None);
        }
        let block_hash = evidence
            .block_hash
            .as_deref()
            .expect("confirmed evidence has a block hash");
        match self
            .fetch_block_status(block_hash, invoice_id, endpoint, request)
            .await
        {
            EndpointFetch::Found(status) if !status.in_best_chain => {
                EndpointFetch::Found(explicit_reorg_observation(evidence))
            }
            // A tx 404 is never disappearance evidence by itself. A canonical
            // prior block is contradictory but still conservative: no write.
            EndpointFetch::Found(_) => EndpointFetch::Found(None),
            EndpointFetch::NotFound | EndpointFetch::Retry => EndpointFetch::Retry,
            EndpointFetch::Backoff => EndpointFetch::Backoff,
            EndpointFetch::BudgetExhausted => EndpointFetch::BudgetExhausted,
        }
    }

    async fn fetch_optional_rbf_history(
        &self,
        txid: &str,
        invoice_id: Uuid,
        endpoint: &str,
        request: RequestPermit<'_>,
    ) -> EndpointFetch<MempoolRbfHistory> {
        if self
            .rbf_capabilities
            .lock()
            .await
            .get(endpoint)
            .is_some_and(|supported| !*supported)
        {
            return EndpointFetch::NotFound;
        }
        if !self.acquire_token(request).await {
            return EndpointFetch::BudgetExhausted;
        }

        let url = format!("{endpoint}/v1/tx/{txid}/rbf");
        let response = match self.http.get(&url).send().await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    event = "btc_esplora_failover",
                    op = "rbf_history",
                    invoice_id = %invoice_id,
                    endpoint = %endpoint,
                    "bitcoin_watcher: optional RBF capability request failed: {error}"
                );
                return EndpointFetch::Retry;
            }
        };
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return EndpointFetch::Backoff;
        }
        if matches!(
            status,
            reqwest::StatusCode::BAD_REQUEST
                | reqwest::StatusCode::NOT_FOUND
                | reqwest::StatusCode::METHOD_NOT_ALLOWED
                | reqwest::StatusCode::NOT_IMPLEMENTED
        ) {
            self.rbf_capabilities
                .lock()
                .await
                .insert(endpoint.to_owned(), false);
            return EndpointFetch::NotFound;
        }
        if !status.is_success() {
            return EndpointFetch::Retry;
        }
        match response.json::<MempoolRbfHistory>().await {
            Ok(history) => {
                self.rbf_capabilities
                    .lock()
                    .await
                    .insert(endpoint.to_owned(), true);
                EndpointFetch::Found(history)
            }
            Err(error) => {
                tracing::warn!(
                    event = "bitcoin_watcher_invalid_rbf_history",
                    invoice_id = %invoice_id,
                    txid = %txid,
                    endpoint = %endpoint,
                    "bitcoin_watcher: RBF capability returned invalid JSON: {error}"
                );
                EndpointFetch::Retry
            }
        }
    }

    async fn fetch_block_status(
        &self,
        block_hash: &str,
        invoice_id: Uuid,
        endpoint: &str,
        request: RequestPermit<'_>,
    ) -> EndpointFetch<MempoolBlockStatus> {
        let url = format!("{endpoint}/block/{block_hash}/status");
        self.fetch_json(&url, "block_status", invoice_id, endpoint, request)
            .await
    }

    async fn fetch_json<T: DeserializeOwned>(
        &self,
        url: &str,
        op: &'static str,
        invoice_id: Uuid,
        endpoint: &str,
        request: RequestPermit<'_>,
    ) -> EndpointFetch<T> {
        if !self.acquire_token(request).await {
            tracing::debug!(
                event = "bitcoin_watcher_request_budget_exhausted",
                op,
                invoice_id = %invoice_id,
                endpoint = %endpoint,
                "bitcoin_watcher: retaining the current invoice before HTTP request"
            );
            return EndpointFetch::BudgetExhausted;
        }
        let response = match self.http.get(url).send().await {
            Ok(response) => response,
            Err(e) => {
                tracing::warn!(
                    event = "btc_esplora_failover",
                    op,
                    invoice_id = %invoice_id,
                    endpoint = %endpoint,
                    "bitcoin_watcher: evidence request failed: {e}"
                );
                return EndpointFetch::Retry;
            }
        };
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tracing::warn!(
                event = "bitcoin_watcher_upstream_429",
                op,
                invoice_id = %invoice_id,
                endpoint = %endpoint,
                "bitcoin_watcher: upstream rate-limited; backing off this tick"
            );
            return EndpointFetch::Backoff;
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return EndpointFetch::NotFound;
        }
        if !status.is_success() {
            tracing::warn!(
                event = "btc_esplora_failover",
                op,
                invoice_id = %invoice_id,
                endpoint = %endpoint,
                http_status = %status,
                "bitcoin_watcher: evidence request returned non-success"
            );
            return EndpointFetch::Retry;
        }
        match response.json().await {
            Ok(value) => EndpointFetch::Found(value),
            Err(e) => {
                tracing::warn!(
                    event = "btc_esplora_failover",
                    op,
                    invoice_id = %invoice_id,
                    endpoint = %endpoint,
                    "bitcoin_watcher: evidence JSON decode failed: {e}"
                );
                EndpointFetch::Retry
            }
        }
    }

    async fn acquire_token(&self, request: RequestPermit<'_>) -> bool {
        loop {
            if request.cancel.is_cancelled() {
                return false;
            }
            let retry_after = {
                let mut bucket = self.bucket.lock().await;
                if request.cancel.is_cancelled() {
                    return false;
                }
                if bucket.try_consume() {
                    return true;
                }
                bucket.retry_after()
            };
            request.reporter.progress();
            tokio::select! {
                _ = request.cancel.cancelled() => return false,
                _ = tokio::time::sleep(retry_after) => {}
            }
        }
    }

    async fn token_available(&self) -> bool {
        self.bucket.lock().await.has_available()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BtcDirectObservation {
    event_key: String,
    txid: String,
    vout: i32,
    address: String,
    amount_sat: i64,
    confirmations: i32,
    block_height: Option<i32>,
    block_hash: Option<String>,
    phase: db::DirectObservationPhase,
    supersedes_event_key: Option<String>,
}

impl BtcDirectObservation {
    fn as_reducer_observation(&self) -> db::DirectOutputObservation<'_> {
        db::DirectOutputObservation {
            event_key: &self.event_key,
            txid: &self.txid,
            vout: self.vout,
            address: &self.address,
            amount_sat: self.amount_sat,
            asset_id: None,
            confirmations: self.confirmations,
            block_height: self.block_height,
            block_hash: self.block_hash.as_deref(),
            verification: db::DirectEvidenceVerification::Verified,
            phase: self.phase,
            supersedes_event_key: self.supersedes_event_key.as_deref(),
        }
    }

    fn with_block_regression(
        mut self,
        evidence: &db::BitcoinDirectWatchEvidence,
    ) -> Result<Self, String> {
        let positive_phase = match self.phase {
            db::DirectObservationPhase::Provisional => db::DirectPositivePhase::Provisional,
            db::DirectObservationPhase::Confirmed => db::DirectPositivePhase::Confirmed,
            db::DirectObservationPhase::Finalized => db::DirectPositivePhase::Finalized,
            db::DirectObservationPhase::ReobservedAfterBlockRegression { .. }
            | db::DirectObservationPhase::ResolutionPending(_) => {
                return Err("current Bitcoin evidence is not a plain positive phase".to_string());
            }
        };
        let prior_height = evidence
            .block_height
            .ok_or_else(|| "durable Bitcoin evidence omitted prior block height".to_string())?;
        let prior_hash = evidence
            .block_hash
            .as_deref()
            .ok_or_else(|| "durable Bitcoin evidence omitted prior block hash".to_string())?;
        self.phase = db::DirectObservationPhase::reobserved_after_block_regression(
            positive_phase,
            prior_height,
            prior_hash,
            db::DirectRegressionReason::Reorged,
        )?;
        Ok(self)
    }
}

fn valid_bitcoin_txid(txid: &str) -> bool {
    txid.len() == 64
        && txid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn remember_canonical_bitcoin_txid(seen: &mut BTreeSet<String>, txid: &str) -> bool {
    valid_bitcoin_txid(txid) && seen.insert(txid.to_owned())
}

/// Return the current root transaction only when the provider tree contains a
/// unique, bounded path back to the requested old txid. A null tree means the
/// optional provider has no replacement relation; malformed/cross-transaction
/// trees are never accepted as conflict evidence.
fn latest_replacement_txid(
    history: &MempoolRbfHistory,
    old_txid: &str,
) -> Result<Option<String>, String> {
    let Some(root) = history.replacements.as_ref() else {
        return Ok(None);
    };
    if !valid_bitcoin_txid(old_txid) || !valid_bitcoin_txid(&root.tx.txid) {
        return Err("RBF history contains an invalid transaction id".to_string());
    }
    let mut stack = vec![root];
    let mut seen = BTreeSet::new();
    let mut found_old = false;
    while let Some(node) = stack.pop() {
        if seen.len() >= MAX_RBF_TREE_NODES {
            return Err("RBF history exceeds the bounded tree size".to_string());
        }
        if !valid_bitcoin_txid(&node.tx.txid) || !seen.insert(node.tx.txid.to_ascii_lowercase()) {
            return Err("RBF history contains an invalid or duplicate txid".to_string());
        }
        found_old |= node.tx.txid.eq_ignore_ascii_case(old_txid);
        stack.extend(node.replaces.iter());
    }
    if !found_old {
        return Err("RBF history does not contain the requested old transaction".to_string());
    }
    if root.tx.txid.eq_ignore_ascii_case(old_txid) {
        Ok(None)
    } else {
        Ok(Some(root.tx.txid.clone()))
    }
}

fn invalid_replacement_observation(
    evidence: &db::BitcoinDirectWatchEvidence,
) -> BtcDirectObservation {
    BtcDirectObservation {
        event_key: evidence.event_key.clone(),
        txid: evidence.txid.clone(),
        vout: evidence.vout,
        address: evidence.address.clone(),
        amount_sat: evidence.amount_sat,
        confirmations: evidence.confirmations,
        block_height: evidence.block_height,
        block_hash: evidence.block_hash.clone(),
        phase: db::DirectObservationPhase::ResolutionPending(
            db::DirectRegressionReason::InvalidReplacement,
        ),
        supersedes_event_key: None,
    }
}

/// Map a provider-proven replacement to the old merchant outputs. Validity is
/// deliberately exact and one-to-one: same invoice address and same actual
/// output value. Address/amount similarity never establishes the transaction
/// relation; that relation is supplied separately by the RBF capability.
fn replacement_observations_for_known(
    replacement: &MempoolTx,
    expected_replacement_txid: &str,
    evidence: &[&db::BitcoinDirectWatchEvidence],
    invoice_address: &str,
    tip: u32,
    confirmations_required: u32,
) -> Result<Vec<BtcDirectObservation>, String> {
    if evidence.is_empty() {
        return Err("replacement mapping requires durable prior evidence".to_string());
    }
    if !valid_bitcoin_txid(expected_replacement_txid)
        || replacement.txid != expected_replacement_txid
    {
        return Err(
            "replacement response txid does not match the provider-proven txid".to_string(),
        );
    }
    if evidence
        .iter()
        .any(|item| item.txid == replacement.txid || item.address.as_str() != invoice_address)
    {
        return Err("replacement transaction is not distinct or invoice-bound".to_string());
    }
    let mut outputs = bitcoin_direct_observations_for_tx(
        replacement,
        invoice_address,
        tip,
        confirmations_required,
    )?;
    let mut claimed = BTreeSet::new();
    let mut regressions = Vec::new();
    for old in evidence {
        let replacement_index = outputs.iter().enumerate().find_map(|(index, output)| {
            (!claimed.contains(&index) && output.amount_sat == old.amount_sat).then_some(index)
        });
        if let Some(index) = replacement_index {
            claimed.insert(index);
            outputs[index].supersedes_event_key = Some(old.event_key.clone());
        } else {
            regressions.push(invalid_replacement_observation(old));
        }
    }
    outputs.extend(regressions);
    Ok(outputs)
}

fn bitcoin_direct_observations_for_tx(
    tx: &MempoolTx,
    address: &str,
    tip: u32,
    confirmations_required: u32,
) -> Result<Vec<BtcDirectObservation>, String> {
    if !valid_bitcoin_txid(&tx.txid) {
        return Err("Bitcoin transaction id is not canonical lowercase hex".to_string());
    }
    let (confirmations, block_height, block_hash, phase) =
        bitcoin_observation_phase(&tx.status, tip, confirmations_required)?;
    let mut observations = Vec::new();
    for (vout, output) in tx.vout.iter().enumerate() {
        if output.scriptpubkey_address.as_deref() != Some(address) || output.value == 0 {
            continue;
        }
        let vout_i32 =
            i32::try_from(vout).map_err(|_| format!("Bitcoin vout index {vout} exceeds i32"))?;
        let amount_sat = i64::try_from(output.value)
            .map_err(|_| format!("Bitcoin output value {} exceeds i64", output.value))?;
        observations.push(BtcDirectObservation {
            event_key: format!("bitcoin_direct:{}:{vout}", tx.txid),
            txid: tx.txid.clone(),
            vout: vout_i32,
            address: address.to_owned(),
            amount_sat,
            confirmations,
            block_height,
            block_hash: block_hash.clone(),
            phase,
            supersedes_event_key: None,
        });
    }
    Ok(observations)
}

fn bitcoin_direct_observation_for_known(
    tx: &MempoolTx,
    evidence: &db::BitcoinDirectWatchEvidence,
    tip: u32,
    confirmations_required: u32,
) -> Result<BtcDirectObservation, String> {
    if !valid_bitcoin_txid(&tx.txid) {
        return Err("tx-specific response returned a non-canonical txid".to_string());
    }
    if tx.txid != evidence.txid {
        return Err("tx-specific response returned a different txid".to_string());
    }
    let vout = usize::try_from(evidence.vout)
        .map_err(|_| "durable Bitcoin vout is negative".to_string())?;
    let output = tx
        .vout
        .get(vout)
        .ok_or_else(|| "tx-specific response omitted the durable merchant output".to_string())?;
    if output.scriptpubkey_address.as_deref() != Some(evidence.address.as_str()) {
        return Err("tx-specific response changed the durable merchant destination".to_string());
    }
    let amount_sat = i64::try_from(output.value)
        .map_err(|_| "tx-specific output value exceeds i64".to_string())?;
    if amount_sat != evidence.amount_sat {
        return Err("tx-specific response changed the durable merchant value".to_string());
    }
    let (confirmations, block_height, block_hash, phase) =
        bitcoin_observation_phase(&tx.status, tip, confirmations_required)?;
    Ok(BtcDirectObservation {
        event_key: evidence.event_key.clone(),
        txid: evidence.txid.clone(),
        vout: evidence.vout,
        address: evidence.address.clone(),
        amount_sat,
        confirmations,
        block_height,
        block_hash,
        phase,
        supersedes_event_key: None,
    })
}

fn bitcoin_observation_phase(
    status: &MempoolTxStatus,
    tip: u32,
    confirmations_required: u32,
) -> Result<(i32, Option<i32>, Option<String>, db::DirectObservationPhase), String> {
    if confirmations_required == 0 {
        return Err("Bitcoin finality confirmations must be nonzero".to_string());
    }
    if !status.confirmed {
        if status.block_height.is_some() || status.block_hash.is_some() {
            return Err("unconfirmed Bitcoin evidence carried block identity".to_string());
        }
        return Ok((0, None, None, db::DirectObservationPhase::Provisional));
    }

    let height = status
        .block_height
        .ok_or_else(|| "confirmed Bitcoin evidence omitted block height".to_string())?;
    let block_hash = status
        .block_hash
        .as_ref()
        .ok_or_else(|| "confirmed Bitcoin evidence omitted block hash".to_string())?;
    if height == 0 || height > tip {
        return Err(format!(
            "confirmed Bitcoin block height {height} is outside tip {tip}"
        ));
    }
    let confirmations_u32 = tip - height + 1;
    let confirmations = i32::try_from(confirmations_u32)
        .map_err(|_| "Bitcoin confirmation depth exceeds i32".to_string())?;
    let block_height =
        i32::try_from(height).map_err(|_| "Bitcoin block height exceeds i32".to_string())?;
    let phase = if confirmations_u32 >= confirmations_required {
        db::DirectObservationPhase::Finalized
    } else {
        // Accounting activates at one confirmation, independently of N.
        db::DirectObservationPhase::Confirmed
    };
    Ok((
        confirmations,
        Some(block_height),
        Some(block_hash.clone()),
        phase,
    ))
}

fn evidence_had_confirmed_block(evidence: &db::BitcoinDirectWatchEvidence) -> bool {
    matches!(
        evidence.last_seen_state.as_deref(),
        Some("awaiting_confirmations" | "counted")
    ) && evidence.block_height.is_some()
        && evidence.block_hash.is_some()
}

fn explicit_reorg_observation(
    evidence: &db::BitcoinDirectWatchEvidence,
) -> Option<BtcDirectObservation> {
    if !evidence_had_confirmed_block(evidence) {
        return None;
    }
    Some(BtcDirectObservation {
        event_key: evidence.event_key.clone(),
        txid: evidence.txid.clone(),
        vout: evidence.vout,
        address: evidence.address.clone(),
        amount_sat: evidence.amount_sat,
        confirmations: evidence.confirmations,
        block_height: evidence.block_height,
        block_hash: evidence.block_hash.clone(),
        phase: db::DirectObservationPhase::ResolutionPending(db::DirectRegressionReason::Reorged),
        supersedes_event_key: None,
    })
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
        assert!(BITCOIN_WATCHER_PAGE_SQL.contains("invoice_payment_observations"));
        assert!(BITCOIN_WATCHER_PAGE_SQL.contains("invoice_payment_events"));
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
                block_hash: confirmed.then(|| {
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string()
                }),
            },
        }
    }

    fn watch_evidence(txid: &str, vout: i32, amount_sat: i64) -> db::BitcoinDirectWatchEvidence {
        db::BitcoinDirectWatchEvidence {
            event_key: format!("bitcoin_direct:{txid}:{vout}"),
            txid: txid.to_string(),
            vout,
            address: "bc1qtarget".to_string(),
            amount_sat,
            confirmations: 0,
            block_height: None,
            block_hash: None,
            last_seen_state: Some("seen_unconfirmed".to_string()),
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
        )
        .unwrap();

        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].event_key,
            "bitcoin_direct:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1"
        );
        assert_eq!(observations[0].amount_sat, 6_000);
        assert_eq!(observations[0].confirmations, 0);
        assert_eq!(observations[0].block_height, None);
        assert_eq!(observations[0].block_hash, None);
        assert_eq!(
            observations[0].phase,
            db::DirectObservationPhase::Provisional
        );
    }

    #[test]
    fn provider_rbf_tree_proves_only_a_bounded_relation_containing_the_old_tx() {
        let old_txid = "1".repeat(64);
        let middle_txid = "2".repeat(64);
        let latest_txid = "3".repeat(64);
        let history: MempoolRbfHistory = serde_json::from_value(serde_json::json!({
            "replacements": {
                "tx": { "txid": latest_txid },
                "replaces": [{
                    "tx": { "txid": middle_txid },
                    "replaces": [{
                        "tx": { "txid": old_txid },
                        "replaces": []
                    }]
                }]
            }
        }))
        .unwrap();

        assert_eq!(
            latest_replacement_txid(&history, &"1".repeat(64)).unwrap(),
            Some("3".repeat(64))
        );
        assert!(latest_replacement_txid(&history, &"4".repeat(64)).is_err());
    }

    #[test]
    fn provider_proven_exact_replacement_supersedes_one_old_output() {
        let old_txid = "4".repeat(64);
        let replacement_txid = "5".repeat(64);
        let old = watch_evidence(&old_txid, 0, 6_000);
        let replacement = tx(&replacement_txid, false, None);

        let observations = replacement_observations_for_known(
            &replacement,
            &replacement_txid,
            &[&old],
            "bc1qtarget",
            800_000,
            3,
        )
        .unwrap();

        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].event_key,
            format!("bitcoin_direct:{replacement_txid}:1")
        );
        assert_eq!(
            observations[0].supersedes_event_key.as_deref(),
            Some(old.event_key.as_str())
        );
    }

    #[test]
    fn provider_proven_replacement_without_exact_merchant_output_is_incident() {
        let old_txid = "6".repeat(64);
        let replacement_txid = "7".repeat(64);
        let old = watch_evidence(&old_txid, 0, 5_999);
        let replacement = tx(&replacement_txid, false, None);

        let observations = replacement_observations_for_known(
            &replacement,
            &replacement_txid,
            &[&old],
            "bc1qtarget",
            800_000,
            3,
        )
        .unwrap();

        assert_eq!(observations.len(), 2);
        assert!(observations.iter().any(|observation| {
            observation.event_key == old.event_key
                && observation.phase
                    == db::DirectObservationPhase::ResolutionPending(
                        db::DirectRegressionReason::InvalidReplacement,
                    )
        }));
        assert!(observations.iter().any(|observation| {
            observation.txid == replacement_txid
                && observation.amount_sat == 6_000
                && observation.supersedes_event_key.is_none()
        }));
    }

    #[test]
    fn replacement_body_must_match_the_provider_proven_txid() {
        let old = watch_evidence(&"8".repeat(64), 0, 6_000);
        let proven_txid = "9".repeat(64);
        let wrong_body = tx(&"a".repeat(64), false, None);

        let error = replacement_observations_for_known(
            &wrong_body,
            &proven_txid,
            &[&old],
            "bc1qtarget",
            800_000,
            3,
        )
        .unwrap_err();

        assert!(error.contains("does not match"));
    }

    #[test]
    fn case_variant_txid_cannot_bypass_history_dedup() {
        let txid = "abcdef0123456789".repeat(4);
        let mut seen = BTreeSet::new();

        assert!(remember_canonical_bitcoin_txid(&mut seen, &txid));
        assert!(!remember_canonical_bitcoin_txid(
            &mut seen,
            &txid.to_uppercase()
        ));
        assert!(!remember_canonical_bitcoin_txid(&mut seen, &txid));

        let upper_body = tx(&txid.to_uppercase(), false, None);
        assert!(bitcoin_direct_observations_for_tx(&upper_body, "bc1qtarget", 800_000, 3).is_err());
    }

    #[tokio::test]
    async fn extended_fifty_confirmed_first_page_revalidates_all_known_transactions() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind extended first-page Esplora fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let address = "bc1qtarget";
        let first_page = (0..EXTENDED_FIRST_CONFIRMED_PAGE_SIZE)
            .map(|index| {
                serde_json::json!({
                    "txid": format!("{index:064x}"),
                    "vout": [{"scriptpubkey_address": address, "value": 1_000}],
                    "status": {
                        "confirmed": true,
                        "block_height": 799_900 + index,
                        "block_hash": format!("{:064x}", 30_000 + index)
                    }
                })
            })
            .collect::<Vec<_>>();
        let mut bodies = vec![
            serde_json::to_string(&first_page).unwrap(),
            "[]".to_string(),
        ];
        bodies.extend(
            first_page
                .iter()
                .map(|transaction| serde_json::to_string(transaction).unwrap()),
        );
        let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server_paths = paths.clone();
        let server = tokio::spawn(async move {
            for body in bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2_048];
                let read = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                server_paths
                    .lock()
                    .unwrap()
                    .push(request.lines().next().unwrap_or_default().to_string());
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .unwrap();
        let watcher = BitcoinWatcher::new(
            BitcoinWatcherConfig {
                endpoint: endpoint.clone(),
                endpoints: Vec::new(),
                rate_per_sec: 1_000,
                ..BitcoinWatcherConfig::default()
            },
            db::InvoiceAccountingTolerances::default(),
            pool,
        )
        .unwrap();
        let known = (0..EXTENDED_FIRST_CONFIRMED_PAGE_SIZE)
            .map(|index| watch_evidence(&format!("{index:064x}"), 0, 1_000))
            .collect::<Vec<_>>();
        let (_, reporter, _) = admission_fixture();
        let cancel = CancellationToken::new();
        let inv = InvoiceForBtcPoll {
            id: Uuid::new_v4(),
            bitcoin_address: address.to_string(),
            amount_sat: 50_000,
            created_at_cursor: "2026-07-12 12:00:00+00".to_string(),
        };

        let evidence = watcher
            .collect_endpoint_evidence(
                &inv,
                &known,
                800_000,
                &endpoint,
                RequestPermit {
                    cancel: &cancel,
                    reporter: &reporter,
                },
            )
            .await;
        server.await.unwrap();

        let EndpointEvidence::Ready(observations) = evidence else {
            panic!("extended first-page evidence was not complete");
        };
        assert_eq!(observations.len(), EXTENDED_FIRST_CONFIRMED_PAGE_SIZE);
        assert!(observations.iter().all(|observation| {
            observation.phase == db::DirectObservationPhase::Finalized
                && observation.block_hash.is_some()
        }));
        let paths = paths.lock().unwrap();
        assert_eq!(paths.len(), EXTENDED_FIRST_CONFIRMED_PAGE_SIZE + 2);
        assert_eq!(paths[0], "GET /address/bc1qtarget/txs HTTP/1.1");
        assert!(paths[1].starts_with(&format!(
            "GET /address/bc1qtarget/txs/chain/{:064x} ",
            EXTENDED_FIRST_CONFIRMED_PAGE_SIZE - 1
        )));
        assert_eq!(paths[2], format!("GET /tx/{:064x} HTTP/1.1", 0));
        assert_eq!(
            paths.last().unwrap(),
            &format!(
                "GET /tx/{:064x} HTTP/1.1",
                EXTENDED_FIRST_CONFIRMED_PAGE_SIZE - 1
            )
        );
    }

    #[tokio::test]
    async fn canonical_twenty_five_item_pagination_discovers_the_twenty_sixth_payment() {
        assert_eq!(ESPLORA_CONFIRMED_PAGE_SIZE, 25);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind paginated Esplora fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let address = "bc1qtarget";
        let first_page = (0..ESPLORA_CONFIRMED_PAGE_SIZE)
            .map(|index| {
                serde_json::json!({
                    "txid": format!("{index:064x}"),
                    "vout": [{"scriptpubkey_address": "bc1qother", "value": 1_000}],
                    "status": {
                        "confirmed": true,
                        "block_height": 799_900 + index,
                        "block_hash": format!("{:064x}", 10_000 + index)
                    }
                })
            })
            .collect::<Vec<_>>();
        let payment_txid = "f".repeat(64);
        let second_page = vec![serde_json::json!({
            "txid": payment_txid,
            "vout": [{"scriptpubkey_address": address, "value": 6_000}],
            "status": {
                "confirmed": true,
                "block_height": 799_800,
                "block_hash": "e".repeat(64)
            }
        })];
        let bodies = vec![
            serde_json::to_string(&first_page).unwrap(),
            serde_json::to_string(&second_page).unwrap(),
        ];
        let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server_paths = paths.clone();
        let server = tokio::spawn(async move {
            for body in bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2_048];
                let read = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                server_paths
                    .lock()
                    .unwrap()
                    .push(request.lines().next().unwrap_or_default().to_string());
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .unwrap();
        let cfg = BitcoinWatcherConfig {
            endpoint: endpoint.clone(),
            endpoints: Vec::new(),
            rate_per_sec: 10,
            ..BitcoinWatcherConfig::default()
        };
        let mut watcher =
            BitcoinWatcher::new(cfg, db::InvoiceAccountingTolerances::default(), pool).unwrap();
        watcher.endpoints = vec![endpoint.clone()];
        let (_, reporter, _) = admission_fixture();
        let cancel = CancellationToken::new();
        let inv = InvoiceForBtcPoll {
            id: Uuid::new_v4(),
            bitcoin_address: address.to_string(),
            amount_sat: 6_000,
            created_at_cursor: "2026-07-12 12:00:00+00".to_string(),
        };

        let evidence = watcher
            .collect_endpoint_evidence(
                &inv,
                &[],
                800_000,
                &endpoint,
                RequestPermit {
                    cancel: &cancel,
                    reporter: &reporter,
                },
            )
            .await;
        server.await.unwrap();

        let EndpointEvidence::Ready(observations) = evidence else {
            panic!("paginated evidence was not complete");
        };
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].txid, "f".repeat(64));
        let paths = paths.lock().unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], "GET /address/bc1qtarget/txs HTTP/1.1");
        assert!(paths[1].starts_with(&format!(
            "GET /address/bc1qtarget/txs/chain/{:064x} ",
            ESPLORA_CONFIRMED_PAGE_SIZE - 1
        )));
    }

    #[tokio::test]
    async fn unsupported_first_confirmed_page_shapes_fail_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind invalid first-page Esplora fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let unsupported_counts = [26usize, 49, 51, MAX_FIRST_ADDRESS_TRANSACTIONS];
        let bodies = unsupported_counts.map(|count| {
            serde_json::to_string(
                &(0..count)
                    .map(|index| {
                        serde_json::json!({
                            "txid": format!("{index:064x}"),
                            "vout": [{"scriptpubkey_address": "bc1qother", "value": 1_000}],
                            "status": {
                                "confirmed": true,
                                "block_height": 799_900 + index,
                                "block_hash": format!("{:064x}", 40_000 + index)
                            }
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        });
        let server = tokio::spawn(async move {
            for body in bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2_048];
                let _ = socket.read(&mut request).await.unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .unwrap();
        let watcher = BitcoinWatcher::new(
            BitcoinWatcherConfig {
                endpoint: endpoint.clone(),
                endpoints: Vec::new(),
                rate_per_sec: 1_000,
                ..BitcoinWatcherConfig::default()
            },
            db::InvoiceAccountingTolerances::default(),
            pool,
        )
        .unwrap();
        let (_, reporter, _) = admission_fixture();
        let cancel = CancellationToken::new();
        let inv = InvoiceForBtcPoll {
            id: Uuid::new_v4(),
            bitcoin_address: "bc1qtarget".to_string(),
            amount_sat: 6_000,
            created_at_cursor: "2026-07-12 12:00:00+00".to_string(),
        };

        for count in unsupported_counts {
            let evidence = watcher
                .collect_endpoint_evidence(
                    &inv,
                    &[],
                    800_000,
                    &endpoint,
                    RequestPermit {
                        cancel: &cancel,
                        reporter: &reporter,
                    },
                )
                .await;
            assert!(
                matches!(evidence, EndpointEvidence::Retry),
                "unsupported first confirmed count {count} must fail closed"
            );
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pagination_waits_for_refill_and_completes_the_atomic_invoice() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind budgeted Esplora fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let first_page = (0..ESPLORA_CONFIRMED_PAGE_SIZE)
            .map(|index| {
                serde_json::json!({
                    "txid": format!("{index:064x}"),
                    "vout": [{"scriptpubkey_address": "bc1qother", "value": 1_000}],
                    "status": {
                        "confirmed": true,
                        "block_height": 799_900 + index,
                        "block_hash": format!("{:064x}", 20_000 + index)
                    }
                })
            })
            .collect::<Vec<_>>();
        let body = serde_json::to_string(&first_page).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let server_calls = calls.clone();
        let server = tokio::spawn(async move {
            for body in [body, "[]".to_string()] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2_048];
                let _ = socket.read(&mut request).await.unwrap();
                server_calls.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .unwrap();
        let cfg = BitcoinWatcherConfig {
            endpoint: endpoint.clone(),
            endpoints: Vec::new(),
            rate_per_sec: 1,
            ..BitcoinWatcherConfig::default()
        };
        let watcher =
            BitcoinWatcher::new(cfg, db::InvoiceAccountingTolerances::default(), pool).unwrap();
        let (_, reporter, _) = admission_fixture();
        let cancel = CancellationToken::new();
        let inv = InvoiceForBtcPoll {
            id: Uuid::new_v4(),
            bitcoin_address: "bc1qtarget".to_string(),
            amount_sat: 6_000,
            created_at_cursor: "2026-07-12 12:00:00+00".to_string(),
        };

        let evidence = watcher
            .collect_endpoint_evidence(
                &inv,
                &[],
                800_000,
                &endpoint,
                RequestPermit {
                    cancel: &cancel,
                    reporter: &reporter,
                },
            )
            .await;
        server.await.unwrap();

        assert!(matches!(evidence, EndpointEvidence::Ready(ref rows) if rows.is_empty()));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn oversized_first_mempool_page_is_a_hard_bound() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind oversized Esplora fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let body = serde_json::to_string(
            &(0..=MAX_FIRST_ADDRESS_TRANSACTIONS)
                .map(|index| {
                    serde_json::json!({
                        "txid": format!("{index:064x}"),
                        "vout": [{"scriptpubkey_address": "bc1qother", "value": 1_000}],
                        "status": {"confirmed": false}
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2_048];
            let _ = socket.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .unwrap();
        let watcher = BitcoinWatcher::new(
            BitcoinWatcherConfig {
                endpoint: endpoint.clone(),
                endpoints: Vec::new(),
                ..BitcoinWatcherConfig::default()
            },
            db::InvoiceAccountingTolerances::default(),
            pool,
        )
        .unwrap();
        let (_, reporter, _) = admission_fixture();
        let cancel = CancellationToken::new();
        let inv = InvoiceForBtcPoll {
            id: Uuid::new_v4(),
            bitcoin_address: "bc1qtarget".to_string(),
            amount_sat: 6_000,
            created_at_cursor: "2026-07-12 12:00:00+00".to_string(),
        };

        let evidence = watcher
            .collect_endpoint_evidence(
                &inv,
                &[],
                800_000,
                &endpoint,
                RequestPermit {
                    cancel: &cancel,
                    reporter: &reporter,
                },
            )
            .await;
        server.await.unwrap();

        assert!(matches!(evidence, EndpointEvidence::HardBound));
    }

    #[tokio::test]
    async fn four_known_transactions_complete_beyond_one_bucketful() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind known-evidence Esplora fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let txids = (1..=4)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>();
        let mut bodies = vec!["[]".to_string()];
        bodies.extend(txids.iter().map(|txid| {
            serde_json::json!({
                "txid": txid,
                "vout": [{"scriptpubkey_address": "bc1qtarget", "value": 1_000}],
                "status": {"confirmed": false}
            })
            .to_string()
        }));
        let server = tokio::spawn(async move {
            for body in bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2_048];
                let _ = socket.read(&mut request).await.unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .unwrap();
        let watcher = BitcoinWatcher::new(
            BitcoinWatcherConfig {
                endpoint: endpoint.clone(),
                endpoints: Vec::new(),
                rate_per_sec: 4,
                ..BitcoinWatcherConfig::default()
            },
            db::InvoiceAccountingTolerances::default(),
            pool,
        )
        .unwrap();
        let known = txids
            .iter()
            .map(|txid| watch_evidence(txid, 0, 1_000))
            .collect::<Vec<_>>();
        let (_, reporter, _) = admission_fixture();
        let cancel = CancellationToken::new();
        let inv = InvoiceForBtcPoll {
            id: Uuid::new_v4(),
            bitcoin_address: "bc1qtarget".to_string(),
            amount_sat: 4_000,
            created_at_cursor: "2026-07-12 12:00:00+00".to_string(),
        };

        let evidence = watcher
            .collect_endpoint_evidence(
                &inv,
                &known,
                800_000,
                &endpoint,
                RequestPermit {
                    cancel: &cancel,
                    reporter: &reporter,
                },
            )
            .await;
        server.await.unwrap();

        let EndpointEvidence::Ready(observations) = evidence else {
            panic!("known evidence did not complete after token refill");
        };
        assert_eq!(observations.len(), 4);
    }

    #[tokio::test]
    async fn known_evidence_caps_precede_network_work_and_token_wait_is_cancellable() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .unwrap();
        let watcher = BitcoinWatcher::new(
            BitcoinWatcherConfig {
                rate_per_sec: 1,
                ..BitcoinWatcherConfig::default()
            },
            db::InvoiceAccountingTolerances::default(),
            pool,
        )
        .unwrap();
        let (_, reporter, _) = admission_fixture();
        let cancel = CancellationToken::new();
        let request = RequestPermit {
            cancel: &cancel,
            reporter: &reporter,
        };
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            !watcher
                .acquire_token(RequestPermit {
                    cancel: &cancelled,
                    reporter: &reporter,
                })
                .await,
            "an already-cancelled obligation must not consume available capacity"
        );
        let inv = InvoiceForBtcPoll {
            id: Uuid::new_v4(),
            bitcoin_address: "bc1qtarget".to_string(),
            amount_sat: 6_000,
            created_at_cursor: "2026-07-12 12:00:00+00".to_string(),
        };
        assert_eq!(MAX_KNOWN_DIRECT_TXIDS, 64);
        for accepted_txid_count in [50, MAX_KNOWN_DIRECT_TXIDS] {
            let accepted = (0..accepted_txid_count)
                .map(|index| watch_evidence(&format!("{index:064x}"), 0, 1_000))
                .collect::<Vec<_>>();
            assert!(!bitcoin_known_evidence_is_hard_bound(&accepted));
        }
        let known = (0..=MAX_KNOWN_DIRECT_TXIDS)
            .map(|index| watch_evidence(&format!("{index:064x}"), 0, 1_000))
            .collect::<Vec<_>>();
        assert!(bitcoin_known_evidence_is_hard_bound(&known));

        assert!(matches!(
            watcher
                .collect_endpoint_evidence(&inv, &known, 800_000, "http://unused", request)
                .await,
            EndpointEvidence::HardBound
        ));
        let too_many_outputs = (0..=MAX_KNOWN_DIRECT_OBSERVATIONS)
            .map(|vout| watch_evidence(&"f".repeat(64), vout as i32, 1_000))
            .collect::<Vec<_>>();
        assert!(matches!(
            watcher
                .collect_endpoint_evidence(
                    &inv,
                    &too_many_outputs,
                    800_000,
                    "http://unused",
                    request,
                )
                .await,
            EndpointEvidence::HardBound
        ));
        assert!(watcher.acquire_token(request).await);
        cancel.cancel();
        let acquired =
            tokio::time::timeout(Duration::from_millis(100), watcher.acquire_token(request))
                .await
                .expect("cancelled token wait must return promptly");
        assert!(!acquired);
    }

    #[tokio::test]
    async fn hard_history_bound_returns_no_partial_observations_for_apply() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hard-bound Esplora fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let bodies = (0..=MAX_CONFIRMED_HISTORY_PAGES)
            .map(|page_index| {
                let page = (0..ESPLORA_CONFIRMED_PAGE_SIZE)
                    .map(|row_index| {
                        let identity = page_index * ESPLORA_CONFIRMED_PAGE_SIZE + row_index;
                        serde_json::json!({
                            "txid": format!("{identity:064x}"),
                            "vout": [{"scriptpubkey_address": "bc1qtarget", "value": 1_000}],
                            "status": {
                                "confirmed": true,
                                "block_height": 700_000 + identity,
                                "block_hash": format!("{:064x}", 100_000 + identity)
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                serde_json::to_string(&page).unwrap()
            })
            .collect::<Vec<_>>();
        let calls = Arc::new(AtomicUsize::new(0));
        let server_calls = calls.clone();
        let server = tokio::spawn(async move {
            for body in bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2_048];
                let _ = socket.read(&mut request).await.unwrap();
                server_calls.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .unwrap();
        let cfg = BitcoinWatcherConfig {
            endpoint: endpoint.clone(),
            endpoints: Vec::new(),
            rate_per_sec: 1_000,
            ..BitcoinWatcherConfig::default()
        };
        let watcher =
            BitcoinWatcher::new(cfg, db::InvoiceAccountingTolerances::default(), pool).unwrap();
        let (_, reporter, _) = admission_fixture();
        let cancel = CancellationToken::new();
        let inv = InvoiceForBtcPoll {
            id: Uuid::new_v4(),
            bitcoin_address: "bc1qtarget".to_string(),
            amount_sat: 6_000,
            created_at_cursor: "2026-07-12 12:00:00+00".to_string(),
        };

        let evidence = watcher
            .collect_endpoint_evidence(
                &inv,
                &[],
                800_000,
                &endpoint,
                RequestPermit {
                    cancel: &cancel,
                    reporter: &reporter,
                },
            )
            .await;
        server.await.unwrap();

        assert!(matches!(evidence, EndpointEvidence::HardBound));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            MAX_CONFIRMED_HISTORY_PAGES + 1
        );
    }

    #[tokio::test]
    async fn live_rbf_capability_maps_a_proven_exact_replacement_atomically() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind RBF Esplora fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let old_txid = "8".repeat(64);
        let replacement_txid = "9".repeat(64);
        let responses = vec![
            (200, "[]".to_string()),
            (404, String::new()),
            (
                200,
                serde_json::json!({
                    "replacements": {
                        "tx": { "txid": replacement_txid },
                        "replaces": [{
                            "tx": { "txid": old_txid },
                            "replaces": []
                        }]
                    }
                })
                .to_string(),
            ),
            (
                200,
                serde_json::json!({
                    "txid": replacement_txid,
                    "vout": [
                        {"scriptpubkey_address": "bc1qother", "value": 2_000},
                        {"scriptpubkey_address": "bc1qtarget", "value": 6_000}
                    ],
                    "status": {
                        "confirmed": false,
                        "block_height": null,
                        "block_hash": null
                    }
                })
                .to_string(),
            ),
        ];
        let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server_paths = paths.clone();
        let server = tokio::spawn(async move {
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2_048];
                let read = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                server_paths
                    .lock()
                    .unwrap()
                    .push(request.lines().next().unwrap_or_default().to_string());
                let reason = if status == 200 { "OK" } else { "Not Found" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .unwrap();
        let cfg = BitcoinWatcherConfig {
            endpoint: endpoint.clone(),
            endpoints: Vec::new(),
            rate_per_sec: 10,
            ..BitcoinWatcherConfig::default()
        };
        let watcher =
            BitcoinWatcher::new(cfg, db::InvoiceAccountingTolerances::default(), pool).unwrap();
        let (_, reporter, _) = admission_fixture();
        let cancel = CancellationToken::new();
        let inv = InvoiceForBtcPoll {
            id: Uuid::new_v4(),
            bitcoin_address: "bc1qtarget".to_string(),
            amount_sat: 6_000,
            created_at_cursor: "2026-07-12 12:00:00+00".to_string(),
        };
        let old = watch_evidence(&old_txid, 0, 6_000);

        let evidence = watcher
            .collect_endpoint_evidence(
                &inv,
                std::slice::from_ref(&old),
                800_000,
                &endpoint,
                RequestPermit {
                    cancel: &cancel,
                    reporter: &reporter,
                },
            )
            .await;
        server.await.unwrap();

        let EndpointEvidence::Ready(observations) = evidence else {
            panic!("RBF evidence was not complete");
        };
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].txid, replacement_txid);
        assert_eq!(
            observations[0].supersedes_event_key.as_deref(),
            Some(old.event_key.as_str())
        );
        let paths = paths.lock().unwrap();
        assert_eq!(paths.len(), 4);
        assert_eq!(paths[0], "GET /address/bc1qtarget/txs HTTP/1.1");
        assert_eq!(paths[1], format!("GET /tx/{old_txid} HTTP/1.1"));
        assert_eq!(paths[2], format!("GET /v1/tx/{old_txid}/rbf HTTP/1.1"));
        assert_eq!(paths[3], format!("GET /tx/{replacement_txid} HTTP/1.1"));
    }

    #[test]
    fn observation_helper_activates_accounting_at_one_confirmation() {
        let observations = bitcoin_direct_observations_for_tx(
            &tx(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                true,
                Some(800_000),
            ),
            "bc1qtarget",
            800_000,
            3,
        )
        .unwrap();

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].confirmations, 1);
        assert_eq!(observations[0].block_height, Some(800_000));
        assert_eq!(observations[0].phase, db::DirectObservationPhase::Confirmed);
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
        )
        .unwrap();

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].confirmations, 3);
        assert_eq!(observations[0].block_height, Some(799_998));
        assert_eq!(observations[0].phase, db::DirectObservationPhase::Finalized);
    }

    #[test]
    fn observation_helper_keeps_n_minus_one_pending() {
        let observations = bitcoin_direct_observations_for_tx(
            &tx(
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                true,
                Some(799_999),
            ),
            "bc1qtarget",
            800_000,
            3,
        )
        .unwrap();

        assert_eq!(observations[0].confirmations, 2);
        assert_eq!(observations[0].phase, db::DirectObservationPhase::Confirmed);
    }

    #[test]
    fn malformed_or_impossible_confirmation_evidence_is_rejected() {
        let mut missing_hash = tx(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            true,
            Some(800_000),
        );
        missing_hash.status.block_hash = None;
        assert!(
            bitcoin_direct_observations_for_tx(&missing_hash, "bc1qtarget", 800_000, 3,).is_err()
        );

        let above_tip = tx(
            "abababababababababababababababababababababababababababababababab",
            true,
            Some(800_001),
        );
        assert!(bitcoin_direct_observations_for_tx(&above_tip, "bc1qtarget", 800_000, 3,).is_err());
        assert!(bitcoin_direct_observations_for_tx(
            &tx(
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                false,
                None,
            ),
            "bc1qtarget",
            800_000,
            0,
        )
        .is_err());
    }

    #[test]
    fn explicit_reorg_requires_prior_confirmed_block_identity() {
        let evidence = db::BitcoinDirectWatchEvidence {
            event_key:
                "bitcoin_direct:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1"
                    .to_string(),
            txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            vout: 1,
            address: "bc1qtarget".to_string(),
            amount_sat: 6_000,
            confirmations: 2,
            block_height: Some(799_999),
            block_hash: Some(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            ),
            last_seen_state: Some("awaiting_confirmations".to_string()),
        };
        let regression = explicit_reorg_observation(&evidence).unwrap();
        assert_eq!(
            regression.phase,
            db::DirectObservationPhase::ResolutionPending(db::DirectRegressionReason::Reorged)
        );

        let provisional = db::BitcoinDirectWatchEvidence {
            block_height: None,
            block_hash: None,
            last_seen_state: Some("seen_unconfirmed".to_string()),
            ..evidence
        };
        assert!(explicit_reorg_observation(&provisional).is_none());
    }

    #[test]
    fn same_snapshot_remining_keeps_current_positive_evidence() {
        let evidence = db::BitcoinDirectWatchEvidence {
            event_key:
                "bitcoin_direct:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1"
                    .to_string(),
            txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            vout: 1,
            address: "bc1qtarget".to_string(),
            amount_sat: 6_000,
            confirmations: 2,
            block_height: Some(799_999),
            block_hash: Some(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            ),
            last_seen_state: Some("awaiting_confirmations".to_string()),
        };
        let mut remined = tx(&evidence.txid, true, Some(800_000));
        remined.status.block_hash =
            Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string());
        let current = bitcoin_direct_observation_for_known(&remined, &evidence, 800_001, 3)
            .unwrap()
            .with_block_regression(&evidence)
            .unwrap();

        assert_eq!(current.confirmations, 2);
        assert_eq!(current.block_height, Some(800_000));
        assert_eq!(
            current.block_hash.as_deref(),
            Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
        );
        match current.phase {
            db::DirectObservationPhase::ReobservedAfterBlockRegression {
                phase,
                prior_block_height,
                prior_block_hash,
                reason,
            } => {
                assert_eq!(phase, db::DirectPositivePhase::Confirmed);
                assert_eq!(prior_block_height, 799_999);
                assert_eq!(hex::encode(prior_block_hash), evidence.block_hash.unwrap());
                assert_eq!(reason, db::DirectRegressionReason::Reorged);
            }
            other => panic!("unexpected re-mining phase: {other:?}"),
        }
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
    fn invoice_boundary_waits_only_inside_the_first_atomic_obligation() {
        assert!(should_start_next_invoice(false, false));
        assert!(should_start_next_invoice(false, true));
        assert!(!should_start_next_invoice(true, false));
        assert!(should_start_next_invoice(true, true));
    }

    #[test]
    fn hard_bound_epoch_visits_later_rows_fails_health_and_retries_next_epoch() {
        let hard_bound = db::WatcherScanCursor {
            created_at: "2026-07-12 11:00:00+00".to_string(),
            id: Uuid::from_u128(1),
        };
        let later = db::WatcherScanCursor {
            created_at: "2026-07-12 11:01:00+00".to_string(),
            id: Uuid::from_u128(2),
        };
        let mut epoch = BitcoinTierScanEpoch::default();
        epoch.scan.begin("2026-07-12 12:00:00+00".to_string());

        epoch.note_hard_bound(hard_bound.clone());
        assert_eq!(epoch.scan.cursor(), Some(&hard_bound));
        epoch.scan.advance(later.clone());
        assert_eq!(epoch.scan.cursor(), Some(&later));

        let outcome = epoch.finish_outcome();
        assert_eq!(outcome, CycleOutcome::Failed);
        assert!(epoch.scan.snapshot().is_none());
        assert!(epoch.scan.cursor().is_none());
        assert!(!epoch.hard_bound_failure);

        let (admission, reporter, mut tier_health) = admission_fixture();
        report_outcome(&reporter, &mut tier_health, WatchTier::Active, outcome);
        assert!(!admission.decision(Rail::DirectBitcoin).allowed());

        epoch.scan.begin("2026-07-12 12:05:00+00".to_string());
        assert!(epoch.scan.cursor().is_none(), "hard row retries next epoch");
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
        let mut epoch = BitcoinTierScanEpoch::default();

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

    #[tokio::test]
    async fn tx_404_is_ambiguous_evidence_not_a_regression() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tx 404 server");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("tx 404 server address")
        );
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept tx request");
            let mut request = [0u8; 1_024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await
                .expect("write tx 404 response");
        });
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_bitcoin_watcher_unit_test")
            .expect("lazy test pool");
        let mut watcher = BitcoinWatcher::new(
            BitcoinWatcherConfig {
                endpoint: endpoint.clone(),
                endpoints: Vec::new(),
                request_timeout_ms: 1_000,
                ..BitcoinWatcherConfig::default()
            },
            db::InvoiceAccountingTolerances::default(),
            pool,
        )
        .expect("bitcoin watcher");
        watcher.endpoints = vec![endpoint.clone()];
        let cancel = CancellationToken::new();
        let (_, reporter, _) = admission_fixture();

        let result = watcher
            .fetch_json::<MempoolTx>(
                &format!("{endpoint}/tx/{}", "a".repeat(64)),
                "known_tx",
                Uuid::new_v4(),
                &endpoint,
                RequestPermit {
                    cancel: &cancel,
                    reporter: &reporter,
                },
            )
            .await;
        server.await.expect("tx 404 server");

        assert!(matches!(result, EndpointFetch::NotFound));
        assert!(explicit_reorg_observation(&db::BitcoinDirectWatchEvidence {
            event_key: format!("bitcoin_direct:{}:0", "a".repeat(64)),
            txid: "a".repeat(64),
            vout: 0,
            address: "bc1qtarget".to_string(),
            amount_sat: 6_000,
            confirmations: 0,
            block_height: None,
            block_hash: None,
            last_seen_state: Some("seen_unconfirmed".to_string()),
        })
        .is_none());
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

//! Chain watcher background task.
//!
//! Periodically polls the Liquid Electrum backend for activity at each active
//! nym's "next address" (and a small lookahead window). When a payment is
//! observed at an address with index `>= next_addr_idx`, we advance
//! `users.next_addr_idx` past it so future LNURL callbacks return a fresh
//! unused address.
//!
//! Polling-based by design: simple, no subscription state to manage. ~30s
//! cadence is fine for our LUD-22 "last unused address" semantics.

use std::sync::Arc;
use std::time::Duration;

use std::str::FromStr;

use elements::encode::deserialize;
use lwk_wollet::elements;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use crate::admission::WorkerReporter;
use crate::db;
use crate::error::AppError;
use crate::rate_limit::RateLimiter;
use crate::utxo::{
    LiquidHistoryEntry, LiquidHistorySnapshot, LiquidHistorySnapshotLimit,
    LiquidHistorySnapshotLimits, LiquidHistorySnapshotOutcome, UtxoBackend,
};

/// One invoice scan is an atomic evidence unit. The one-authority history/tip
/// snapshot is charged as one high-level watcher operation, while every raw-tx
/// fetch consumes its own token. These caps stop a dusted address from causing
/// unbounded header or raw-transaction fanout in one obligation.
const LIQUID_SNAPSHOT_LIMITS: LiquidHistorySnapshotLimits = LiquidHistorySnapshotLimits {
    max_history_entries: db::MAX_DIRECT_OBSERVATIONS_PER_BATCH,
    max_block_heights: db::MAX_DIRECT_OBSERVATIONS_PER_BATCH,
};
const MAX_LIQUID_KNOWN_OBSERVATIONS: usize = db::MAX_DIRECT_OBSERVATIONS_PER_BATCH;
const MAX_LIQUID_EMITTED_OUTPUTS: usize = db::MAX_DIRECT_OBSERVATIONS_PER_BATCH;

fn complete_liquid_snapshot(
    outcome: LiquidHistorySnapshotOutcome,
) -> Result<LiquidHistorySnapshot, LiquidHistorySnapshotLimit> {
    match outcome {
        LiquidHistorySnapshotOutcome::Complete(snapshot) => Ok(snapshot),
        LiquidHistorySnapshotOutcome::Incomplete(limit) => Err(limit),
    }
}

fn prior_liquid_tx_count_is_hard_bound(count: usize) -> bool {
    count > LIQUID_SNAPSHOT_LIMITS.max_history_entries
}

fn liquid_known_observation_count_is_hard_bound(count: usize) -> bool {
    count > MAX_LIQUID_KNOWN_OBSERVATIONS
}

fn liquid_emitted_output_count_is_hard_bound(count: usize) -> bool {
    count > MAX_LIQUID_EMITTED_OUTPUTS
}

fn liquid_emitted_output_count_would_be_hard_bound(current: usize, additional: usize) -> bool {
    current
        .checked_add(additional)
        .is_none_or(liquid_emitted_output_count_is_hard_bound)
}

pub struct ChainWatcherConfig {
    /// How often to scan the "active" set (users with a recent callback).
    pub active_tick_secs: u64,
    /// How often to scan the "idle" set (everyone else). Idle ticks also
    /// re-scan the active set, so the active loop never stalls during an
    /// idle pass.
    pub idle_tick_secs: u64,
    /// A user is "active" if `last_callback_at` is within this many
    /// seconds. NULL last_callback_at always falls in the idle set.
    pub active_window_secs: u32,
    pub lookahead: u32,
    /// Confirmations at which verified direct Liquid evidence becomes final.
    /// Accounting activates at one confirmation independently of this value.
    pub liquid_finality_confirmations: u32,
}

impl Default for ChainWatcherConfig {
    fn default() -> Self {
        Self {
            active_tick_secs: 30,
            idle_tick_secs: 600,
            active_window_secs: 86_400,
            lookahead: 10,
            liquid_finality_confirmations: 2,
        }
    }
}

impl ChainWatcherConfig {
    /// Build from `RateLimitConfig` so the watcher cadences come from one
    /// place (the deployed config) without each call site recomputing.
    pub fn from_rate_limit_config(
        rl: &crate::config::RateLimitConfig,
        liquid_finality_confirmations: u32,
    ) -> Self {
        Self {
            active_tick_secs: rl.chain_watcher_active_user_tick_secs as u64,
            idle_tick_secs: rl.chain_watcher_idle_user_tick_secs as u64,
            active_window_secs: rl.chain_watcher_active_window_secs,
            lookahead: 10,
            liquid_finality_confirmations,
        }
    }
}

#[derive(Clone, Copy)]
struct ChainWatcherPollCtx<'a> {
    pool: &'a PgPool,
    backend: &'a (dyn UtxoBackend + Send + Sync),
    rate_limiter: &'a RateLimiter,
    cancel: &'a CancellationToken,
}

enum LiquidRecordOutcome {
    Applied { recorded: usize },
    Deferred,
    HardBound,
}

#[derive(Clone, Copy)]
struct LiquidInvoiceObservationTarget<'a> {
    invoice_id: uuid::Uuid,
    address: &'a str,
    script: &'a elements::Script,
    blinding_key_hex: &'a str,
    finality_confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiquidObservedOutput {
    event_key: String,
    txid: String,
    vout: i32,
    amount_sat: i64,
    asset_id: String,
    confirmations: i32,
    block_height: Option<i32>,
    block_hash: Option<String>,
    phase: db::DirectObservationPhase,
    supersedes_event_key: Option<String>,
}

/// The pegin domain bit is part of an Elements spent-outpoint identity; a
/// mainchain pegin outpoint must never collide with a Liquid outpoint carrying
/// the same display txid/vout.
type LiquidInputOutpoint = (bool, String, u32);
type LiquidTransactionInputs = std::collections::HashSet<LiquidInputOutpoint>;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct LiquidKnownObservation {
    event_key: String,
    txid: String,
    vout: i32,
    address: String,
    amount_sat: i64,
    asset_id: Option<String>,
    confirmations: i32,
    block_height: Option<i32>,
    block_hash: Option<String>,
    last_seen_state: String,
}

impl LiquidKnownObservation {
    fn had_positive_block(&self) -> bool {
        matches!(
            self.last_seen_state.as_str(),
            "awaiting_confirmations" | "counted"
        ) && self.block_height.is_some()
            && self.block_hash.is_some()
    }

    fn explicit_invalidation_observation(
        &self,
        reason: db::DirectRegressionReason,
    ) -> Result<LiquidObservedOutput, AppError> {
        let asset_id = self.asset_id.clone().ok_or_else(|| {
            AppError::DbError("stored Liquid observation is missing its asset identity".into())
        })?;
        Ok(LiquidObservedOutput {
            event_key: self.event_key.clone(),
            txid: self.txid.clone(),
            vout: self.vout,
            amount_sat: self.amount_sat,
            asset_id,
            confirmations: self.confirmations,
            // Preserve the positively observed prior inclusion identity. The
            // phase/reason says that identity is no longer canonical; retaining
            // it keeps the immutable evidence available to the transition log.
            block_height: self.block_height,
            block_hash: self.block_hash.clone(),
            phase: db::DirectObservationPhase::ResolutionPending(reason),
            supersedes_event_key: None,
        })
    }
}

impl LiquidObservedOutput {
    fn as_direct_observation<'a>(&'a self, address: &'a str) -> db::DirectOutputObservation<'a> {
        db::DirectOutputObservation {
            event_key: &self.event_key,
            txid: &self.txid,
            vout: self.vout,
            address,
            amount_sat: self.amount_sat,
            asset_id: Some(&self.asset_id),
            confirmations: self.confirmations,
            block_height: self.block_height,
            block_hash: self.block_hash.as_deref(),
            verification: db::DirectEvidenceVerification::Verified,
            phase: self.phase,
            supersedes_event_key: self.supersedes_event_key.as_deref(),
        }
    }

    fn mark_reobserved_after_block_regression(
        &mut self,
        prior_block_height: i32,
        prior_block_hash: &str,
    ) -> Result<(), AppError> {
        let phase = match self.phase {
            db::DirectObservationPhase::Provisional => db::DirectPositivePhase::Provisional,
            db::DirectObservationPhase::Confirmed => db::DirectPositivePhase::Confirmed,
            db::DirectObservationPhase::Finalized => db::DirectPositivePhase::Finalized,
            db::DirectObservationPhase::ReobservedAfterBlockRegression { .. }
            | db::DirectObservationPhase::ResolutionPending(_) => {
                return Err(AppError::DbError(
                    "Liquid output already carries regression state before DB comparison".into(),
                ));
            }
        };
        self.phase = db::DirectObservationPhase::reobserved_after_block_regression(
            phase,
            prior_block_height,
            prior_block_hash,
            db::DirectRegressionReason::Reorged,
        )
        .map_err(|error| AppError::DbError(format!("stored Liquid block identity: {error}")))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CycleOutcome {
    Healthy,
    Incomplete,
    HardBoundFailed,
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

#[derive(Debug, Default)]
struct LiquidTierScanEpoch {
    nyms: db::WatcherNymScanEpoch,
    invoices: db::WatcherScanEpoch,
    nyms_complete: bool,
    invoice_hard_bound_failure: bool,
}

impl LiquidTierScanEpoch {
    fn note_invoice_hard_bound(&mut self, cursor: db::WatcherScanCursor) {
        self.invoice_hard_bound_failure = true;
        self.invoices.advance(cursor);
    }

    fn finish(&mut self) {
        self.nyms.finish();
        self.invoices.finish();
        self.nyms_complete = false;
        self.invoice_hard_bound_failure = false;
    }
}

fn liquid_invoice_epoch_outcome(epoch: &LiquidTierScanEpoch, has_more: bool) -> CycleOutcome {
    if has_more {
        CycleOutcome::Incomplete
    } else if epoch.invoice_hard_bound_failure {
        CycleOutcome::HardBoundFailed
    } else {
        CycleOutcome::Healthy
    }
}

impl TierHealth {
    fn observe(&mut self, tier: WatchTier, outcome: CycleOutcome) -> ReportAction {
        let (current, other) = match tier {
            WatchTier::Active => (&mut self.active, self.idle),
            WatchTier::Idle => (&mut self.idle, self.active),
        };
        match outcome {
            CycleOutcome::Incomplete => ReportAction::ProgressOnly,
            CycleOutcome::Failed | CycleOutcome::HardBoundFailed => {
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

/// Run the chain watcher loop. Spawned for the lifetime of the server.
/// Two cadences:
///   - `active_tick_secs`: scans only users with a recent callback.
///     Bounded by real traffic, not by the size of the `users` table.
///   - `idle_tick_secs`: scans every active user (active + idle). Catches
///     payments to users who haven't had a recent callback.
///
/// `rate_limiter` exposes a dedicated watcher-only Electrum bucket
/// (`check_electrum_watcher`) so a callback storm cannot starve the
/// watcher and vice-versa.
pub async fn run(
    pool: PgPool,
    backend: Arc<dyn UtxoBackend + Send + Sync>,
    rate_limiter: Arc<RateLimiter>,
    cancel: CancellationToken,
    cfg: ChainWatcherConfig,
    tolerances: db::InvoiceAccountingTolerances,
    mut reporter: WorkerReporter,
) {
    let mut tier_health = TierHealth::default();
    let mut active_epoch = LiquidTierScanEpoch::default();
    let mut idle_epoch = LiquidTierScanEpoch::default();
    if cancel.is_cancelled() {
        reporter.intentional_shutdown();
        return;
    }

    for (tier, active, epoch) in [
        (WatchTier::Active, true, &mut active_epoch),
        (WatchTier::Idle, false, &mut idle_epoch),
    ] {
        let startup_outcome = poll_cycle(
            ChainWatcherPollCtx {
                pool: &pool,
                backend: backend.as_ref(),
                rate_limiter: rate_limiter.as_ref(),
                cancel: &cancel,
            },
            &cfg,
            tolerances,
            active,
            &reporter,
            epoch,
        )
        .await;
        if cancel.is_cancelled() {
            reporter.intentional_shutdown();
            return;
        }
        report_outcome(&reporter, &mut tier_health, tier, startup_outcome);
    }

    let mut active_tick = tokio::time::interval(Duration::from_secs(cfg.active_tick_secs));
    let mut idle_tick = tokio::time::interval(Duration::from_secs(cfg.idle_tick_secs));
    active_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // The current process completed its startup scan above; consume each
    // interval's immediate tick so the next scans follow the configured cadence.
    active_tick.tick().await;
    idle_tick.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("chain_watcher: shutdown signal received, exiting");
                reporter.intentional_shutdown();
                return;
            }
            _ = active_tick.tick() => {
                let healthy = poll_cycle(
                    ChainWatcherPollCtx {
                        pool: &pool,
                        backend: backend.as_ref(),
                        rate_limiter: rate_limiter.as_ref(),
                        cancel: &cancel,
                    },
                    &cfg, tolerances, true, &reporter, &mut active_epoch,
                ).await;
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
            _ = idle_tick.tick() => {
                let healthy = poll_cycle(
                    ChainWatcherPollCtx {
                        pool: &pool,
                        backend: backend.as_ref(),
                        rate_limiter: rate_limiter.as_ref(),
                        cancel: &cancel,
                    },
                    &cfg, tolerances, false, &reporter, &mut idle_epoch,
                ).await;
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

async fn poll_cycle(
    ctx: ChainWatcherPollCtx<'_>,
    cfg: &ChainWatcherConfig,
    tolerances: db::InvoiceAccountingTolerances,
    active: bool,
    reporter: &WorkerReporter,
    epoch: &mut LiquidTierScanEpoch,
) -> CycleOutcome {
    reporter.progress();
    if ctx.cancel.is_cancelled() {
        return CycleOutcome::Incomplete;
    }
    if let Err(error) = ctx.backend.health_check().await {
        tracing::warn!(
            tier = if active { "active" } else { "idle" },
            "chain_watcher: Liquid backend health check failed: {error}"
        );
        return CycleOutcome::Failed;
    }
    let tier = if active { "active" } else { "idle" };
    if !epoch.nyms_complete {
        if epoch.nyms.snapshot().is_none() {
            match db::watcher_scan_snapshot(ctx.pool).await {
                Ok(snapshot) => epoch.nyms.begin(snapshot),
                Err(e) => {
                    tracing::warn!("chain_watcher: nym scan snapshot failed: {e}");
                    return CycleOutcome::Failed;
                }
            }
        }
        let snapshot = epoch
            .nyms
            .snapshot()
            .expect("watcher nym epoch snapshot initialized before page query");
        let page = if active {
            db::list_recently_active_nyms_for_watcher_page(
                ctx.pool,
                cfg.active_window_secs,
                snapshot,
                epoch.nyms.query_cursor(),
            )
            .await
        } else {
            // Idle ticks scan all active users (active + idle subsets).
            db::list_active_nyms_for_watcher_page(ctx.pool, snapshot, epoch.nyms.query_cursor())
                .await
        };
        let page = match page {
            Ok(page) => page,
            Err(e) => {
                tracing::warn!("chain_watcher: list {tier} nym page failed: {e}");
                return CycleOutcome::Failed;
            }
        };
        let has_more = page.has_more;
        let nym_outcome = match poll_nyms(
            ctx,
            cfg.lookahead,
            page.rows,
            tier,
            reporter,
            &mut epoch.nyms,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::warn!("chain_watcher {tier} poll failed: {e:?}");
                CycleOutcome::Failed
            }
        };
        if ctx.cancel.is_cancelled() || nym_outcome != CycleOutcome::Healthy {
            return nym_outcome;
        }
        if has_more {
            return CycleOutcome::Incomplete;
        }
        // Keep the completed nym epoch latched while invoice pages drain.
        // Reset both phases together only after the invoice epoch is healthy.
        epoch.nyms_complete = true;
    }

    let outcome = poll_invoice_addresses(
        ctx,
        tolerances,
        cfg.liquid_finality_confirmations,
        tier,
        reporter,
        epoch,
    )
    .await;
    match outcome {
        CycleOutcome::Healthy => {
            epoch.finish();
            CycleOutcome::Healthy
        }
        CycleOutcome::HardBoundFailed => {
            // The whole frozen epoch was visited, including rows after every
            // hard-bound obligation. Reset process-local cursors so affected
            // invoices are retried next epoch, while reporting this epoch as
            // unhealthy to close new direct-Liquid admission.
            epoch.finish();
            CycleOutcome::Failed
        }
        CycleOutcome::Incomplete | CycleOutcome::Failed => outcome,
    }
}

/// Address-keyed scan for invoice Liquid destinations. This catches both
/// linked and unlinked invoices and runs alongside the per-nym lookahead in
/// `poll_nyms`. Payment events are idempotent by outpoint.
///
/// Direct Liquid accounting: inspect raw tx outputs, unblind outputs that
/// match the invoice script, and record exact LBTC amounts idempotently.
async fn poll_invoice_addresses(
    ctx: ChainWatcherPollCtx<'_>,
    tolerances: db::InvoiceAccountingTolerances,
    liquid_finality_confirmations: u32,
    tier: &'static str,
    reporter: &WorkerReporter,
    epoch: &mut LiquidTierScanEpoch,
) -> CycleOutcome {
    reporter.progress();
    if epoch.invoices.snapshot().is_none() {
        match db::watcher_scan_snapshot(ctx.pool).await {
            Ok(snapshot) => epoch.invoices.begin(snapshot),
            Err(e) => {
                tracing::warn!("chain_watcher: invoice scan snapshot failed: {e}");
                return CycleOutcome::Failed;
            }
        }
    }
    let snapshot = epoch
        .invoices
        .snapshot()
        .expect("watcher epoch snapshot initialized before page query");
    let batch = match db::list_unpaid_invoices_with_liquid_address_page(
        ctx.pool,
        tolerances.payment_grace_secs,
        snapshot,
        epoch.invoices.cursor(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("chain_watcher: list invoice addresses failed: {e}");
            return CycleOutcome::Failed;
        }
    };
    let invoices = batch.rows;
    let n_total = invoices.len();
    if n_total == 0 {
        return liquid_invoice_epoch_outcome(epoch, false);
    }
    let started = std::time::Instant::now();
    let mut hits = 0usize;
    let mut useful_progress = 0usize;
    for invoice in invoices {
        reporter.progress();
        if ctx.cancel.is_cancelled() {
            return CycleOutcome::Incomplete;
        }
        if ctx.rate_limiter.check_electrum_watcher().await.is_err() {
            tracing::debug!(
                "chain_watcher: invoice scan watcher Electrum bucket exhausted, deferring"
            );
            return CycleOutcome::after_token_exhaustion(useful_progress);
        }

        // Parse the wallet-supplied or descriptor-derived address into a
        // Liquid script. Bad/foreign-network addresses are rejected at
        // create time by the validators, so this should never fail in
        // practice; defensively log+skip if it does.
        let parsed = match elements::Address::from_str(&invoice.liquid_address) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    invoice_id = %invoice.id,
                    "chain_watcher: invoice liquid_address parse failed: {e}"
                );
                epoch.invoices.advance(invoice.scan_cursor());
                useful_progress = useful_progress.saturating_add(1);
                continue;
            }
        };
        let script = parsed.script_pubkey();

        match record_liquid_events_for_script(
            ctx,
            LiquidInvoiceObservationTarget {
                invoice_id: invoice.id,
                address: &invoice.liquid_address,
                script: &script,
                blinding_key_hex: &invoice.liquid_blinding_key_hex,
                finality_confirmations: liquid_finality_confirmations,
            },
            tolerances,
            reporter,
        )
        .await
        {
            Ok(LiquidRecordOutcome::Applied { recorded }) => {
                hits += recorded;
                epoch.invoices.advance(invoice.scan_cursor());
                useful_progress = useful_progress.saturating_add(1);
            }
            Ok(LiquidRecordOutcome::Deferred) => {
                // Incomplete replacement/reorg proof is a safe deferral, not a
                // successful scan. Keep this invoice at the keyset cursor and
                // never apply its incomplete generation.
                return CycleOutcome::Incomplete;
            }
            Ok(LiquidRecordOutcome::HardBound) => {
                // The generation was deliberately left unapplied. Retire only
                // this row for the frozen epoch so later obligations are still
                // scanned, then fail the completed epoch and retry this row in
                // the next process-local epoch.
                epoch.note_invoice_hard_bound(invoice.scan_cursor());
                useful_progress = useful_progress.saturating_add(1);
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    invoice_id = %invoice.id,
                    "chain_watcher: invoice Liquid output scan failed: {e}"
                );
                if matches!(
                    e,
                    AppError::InvalidAmount(_) | AppError::InvalidDescriptor(_)
                ) {
                    // Malformed persisted row: isolate it, but count the row as
                    // visited so it cannot pin every later invoice forever.
                    epoch.invoices.advance(invoice.scan_cursor());
                    useful_progress = useful_progress.saturating_add(1);
                    continue;
                }
                return CycleOutcome::Failed;
            }
        }
    }
    let elapsed_ms = started.elapsed().as_millis();
    // Quiet ticks (no invoices in scope) stay at debug; non-empty ticks
    // log at info so the operator can see the address scan is alive
    // without sifting through verbose-mode logs.
    if n_total > 0 {
        tracing::info!(
            event = "chain_watcher_invoice_scan_tick",
            tier = tier,
            scanned = n_total,
            deferred = batch.has_more,
            hits = hits,
            elapsed_ms = elapsed_ms,
            "chain_watcher: invoice address scan tick"
        );
    } else {
        tracing::debug!(
            "chain_watcher: {} invoice address scan {} addrs, {} hits, {}ms",
            tier,
            n_total,
            hits,
            elapsed_ms
        );
    }
    liquid_invoice_epoch_outcome(epoch, batch.has_more)
}

async fn record_liquid_events_for_script(
    ctx: ChainWatcherPollCtx<'_>,
    target: LiquidInvoiceObservationTarget<'_>,
    tolerances: db::InvoiceAccountingTolerances,
    reporter: &WorkerReporter,
) -> Result<LiquidRecordOutcome, AppError> {
    let LiquidInvoiceObservationTarget {
        invoice_id,
        address,
        script,
        blinding_key_hex,
        finality_confirmations: liquid_finality_confirmations,
    } = target;
    if liquid_finality_confirmations == 0 {
        return Err(AppError::ServiceUnavailable(
            "Liquid finality confirmations must be non-zero".into(),
        ));
    }
    let blinding_key = elements::secp256k1_zkp::SecretKey::from_str(blinding_key_hex)
        .map_err(|e| AppError::InvalidAmount(format!("stored Liquid blinding key invalid: {e}")))?;

    // The generation fence is issued before the first chain request. If the
    // snapshot, raw-tx verification, cancellation check, or later DB work
    // fails, this generation remains unapplied and cannot erase prior proof.
    let generation = db::reserve_direct_observation_generation(
        ctx.pool,
        invoice_id,
        db::DirectPaymentSource::Liquid,
    )
    .await?;
    if ctx.cancel.is_cancelled() {
        return Err(AppError::ElectrumError(
            "Liquid observation cancelled before chain snapshot".into(),
        ));
    }

    let known = list_liquid_direct_watch_evidence(ctx.pool, invoice_id).await?;
    if liquid_known_observation_count_is_hard_bound(known.len()) {
        tracing::warn!(
            event = "liquid_watcher_known_observation_bound_reached",
            invoice_id = %invoice_id,
            observed = known.len(),
            limit = MAX_LIQUID_KNOWN_OBSERVATIONS,
            "chain_watcher: stored Liquid evidence exceeds the atomic invoice budget"
        );
        return Ok(LiquidRecordOutcome::HardBound);
    }
    let boltz_settlement_txids = db::invoice_boltz_settlement_txids(ctx.pool, invoice_id)
        .await?
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    if known
        .iter()
        .any(|observation| observation.address != address)
    {
        return Err(AppError::DbError(
            "stored Liquid observation does not match the invoice address".into(),
        ));
    }
    let prior_block_heights = known
        .iter()
        .filter(|observation| observation.had_positive_block())
        .filter_map(|observation| observation.block_height)
        .collect::<Vec<_>>();
    let snapshot_outcome = ctx
        .backend
        .liquid_history_snapshot(script, &prior_block_heights, LIQUID_SNAPSHOT_LIMITS)
        .await?;
    let snapshot = match complete_liquid_snapshot(snapshot_outcome) {
        Ok(snapshot) => snapshot,
        Err(limit) => {
            tracing::warn!(
                event = "liquid_watcher_snapshot_budget_exhausted",
                invoice_id = %invoice_id,
                ?limit,
                "chain_watcher: bounded Liquid snapshot deferred without applying its generation"
            );
            return Ok(LiquidRecordOutcome::HardBound);
        }
    };
    let mut outputs = Vec::new();
    let mut current_inputs = std::collections::HashMap::new();
    for entry in &snapshot.entries {
        if boltz_settlement_txids.contains(&entry.txid.to_ascii_lowercase()) {
            tracing::debug!(
                event = "liquid_watcher_boltz_settlement_excluded",
                invoice_id = %invoice_id,
                txid = %entry.txid,
                "chain_watcher: excluding invoice-linked Boltz settlement from direct evidence"
            );
            continue;
        }
        if ctx.cancel.is_cancelled() {
            return Err(AppError::ElectrumError(
                "Liquid observation cancelled during transaction verification".into(),
            ));
        }
        reporter.progress();
        if !ctx.rate_limiter.acquire_electrum_watcher(ctx.cancel).await {
            return Err(AppError::ElectrumError(
                "Liquid observation cancelled while waiting for current raw-tx budget".into(),
            ));
        }
        let raw = ctx.backend.get_raw_tx(&entry.txid).await?;
        let tx: elements::Transaction = deserialize(&raw)
            .map_err(|e| AppError::ElectrumError(format!("liquid tx decode: {e}")))?;
        let actual_txid = tx.txid().to_string();
        if !actual_txid.eq_ignore_ascii_case(&entry.txid) {
            return Err(AppError::ElectrumError(format!(
                "Liquid watcher txid mismatch: requested {}, backend returned {actual_txid}",
                entry.txid
            )));
        }
        current_inputs.insert(entry.txid.clone(), liquid_transaction_inputs(&tx));
        let extracted = extract_liquid_outputs(
            entry,
            snapshot.tip_height,
            liquid_finality_confirmations,
            &tx,
            script,
            blinding_key,
            invoice_id,
        )?;
        if liquid_emitted_output_count_would_be_hard_bound(outputs.len(), extracted.len()) {
            tracing::warn!(
                event = "liquid_watcher_emitted_output_bound_reached",
                invoice_id = %invoice_id,
                observed = outputs.len().saturating_add(extracted.len()),
                limit = MAX_LIQUID_EMITTED_OUTPUTS,
                "chain_watcher: verified Liquid outputs exceed the atomic invoice budget"
            );
            return Ok(LiquidRecordOutcome::HardBound);
        }
        outputs.extend(extracted);
    }

    let current_txids = snapshot
        .entries
        .iter()
        .map(|entry| entry.txid.as_str())
        .collect::<std::collections::HashSet<_>>();
    let prior_txids = known
        .iter()
        .filter(|observation| !current_txids.contains(observation.txid.as_str()))
        .map(|observation| observation.txid.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if prior_liquid_tx_count_is_hard_bound(prior_txids.len()) {
        tracing::warn!(
            event = "liquid_watcher_prior_tx_budget_exhausted",
            invoice_id = %invoice_id,
            observed = prior_txids.len(),
            limit = LIQUID_SNAPSHOT_LIMITS.max_history_entries,
            "chain_watcher: prior transaction evidence exceeds the atomic invoice budget"
        );
        return Ok(LiquidRecordOutcome::HardBound);
    }
    let mut prior_inputs = std::collections::HashMap::new();
    for txid in prior_txids {
        if ctx.cancel.is_cancelled() {
            return Err(AppError::ElectrumError(
                "Liquid observation cancelled during replacement verification".into(),
            ));
        }
        reporter.progress();
        if !ctx.rate_limiter.acquire_electrum_watcher(ctx.cancel).await {
            return Err(AppError::ElectrumError(
                "Liquid observation cancelled while waiting for prior raw-tx budget".into(),
            ));
        }
        let raw = match ctx.backend.get_raw_tx(&txid).await {
            Ok(raw) => raw,
            // An evicted/orphaned transaction may no longer be retrievable.
            // Without its committed inputs there is no replacement proof.
            Err(AppError::UtxoNotFound) => continue,
            Err(error) => return Err(error),
        };
        let tx: elements::Transaction = deserialize(&raw)
            .map_err(|error| AppError::ElectrumError(format!("prior liquid tx decode: {error}")))?;
        let actual_txid = tx.txid().to_string();
        if !actual_txid.eq_ignore_ascii_case(&txid) {
            return Err(AppError::ElectrumError(format!(
                "Liquid prior txid mismatch: requested {txid}, backend returned {actual_txid}"
            )));
        }
        prior_inputs.insert(txid, liquid_transaction_inputs(&tx));
    }

    if !reconcile_liquid_replacements(
        &known,
        &snapshot,
        &current_inputs,
        &prior_inputs,
        &mut outputs,
    )? {
        tracing::warn!(
            event = "liquid_watcher_incomplete_replacement_proof",
            invoice_id = %invoice_id,
            "chain_watcher: replacement evidence conflicts with the anchored prior block; deferring"
        );
        return Ok(LiquidRecordOutcome::Deferred);
    }
    if liquid_emitted_output_count_is_hard_bound(outputs.len()) {
        tracing::warn!(
            event = "liquid_watcher_emitted_output_bound_reached",
            invoice_id = %invoice_id,
            observed = outputs.len(),
            limit = MAX_LIQUID_EMITTED_OUTPUTS,
            "chain_watcher: replacement reconciliation exceeds the atomic invoice budget"
        );
        return Ok(LiquidRecordOutcome::HardBound);
    }

    if !reconcile_liquid_block_regressions(&known, &snapshot, &mut outputs)? {
        tracing::warn!(
            event = "liquid_watcher_incomplete_reorg_proof",
            invoice_id = %invoice_id,
            "chain_watcher: current Liquid evidence conflicts with stored inclusion but prior block proof is unavailable; deferring"
        );
        return Ok(LiquidRecordOutcome::Deferred);
    }
    if liquid_emitted_output_count_is_hard_bound(outputs.len()) {
        tracing::warn!(
            event = "liquid_watcher_emitted_output_bound_reached",
            invoice_id = %invoice_id,
            observed = outputs.len(),
            limit = MAX_LIQUID_EMITTED_OUTPUTS,
            "chain_watcher: block-regression reconciliation exceeds the atomic invoice budget"
        );
        return Ok(LiquidRecordOutcome::HardBound);
    }
    if ctx.cancel.is_cancelled() {
        return Err(AppError::ElectrumError(
            "Liquid observation cancelled before batch apply".into(),
        ));
    }

    let observations = outputs
        .iter()
        .map(|output| output.as_direct_observation(address))
        .collect::<Vec<_>>();
    let observation_count = observations.len();
    let apply_outcome = db::apply_direct_observation_batch(
        ctx.pool,
        db::DirectObservationBatch {
            invoice_id,
            source: db::DirectPaymentSource::Liquid,
            authority: &snapshot.authority,
            generation,
            observations: &observations,
        },
        tolerances,
    )
    .await?;

    let recorded = match apply_outcome {
        db::ApplyDirectObservationOutcome::Applied { changed: true } => observation_count,
        db::ApplyDirectObservationOutcome::Applied { changed: false }
        | db::ApplyDirectObservationOutcome::AlreadyApplied
        | db::ApplyDirectObservationOutcome::Stale { .. } => 0,
    };
    if recorded > 0 {
        tracing::info!(
            event = "invoice_payment_observation_liquid",
            invoice_id = %invoice_id,
            generation,
            observations = observation_count,
            authority = %snapshot.authority,
            "chain_watcher: applied verified Liquid observation batch"
        );
    }
    Ok(LiquidRecordOutcome::Applied { recorded })
}

#[allow(clippy::too_many_arguments)]
fn extract_liquid_outputs(
    entry: &LiquidHistoryEntry,
    tip_height: i32,
    finality_confirmations: u32,
    tx: &elements::Transaction,
    script: &elements::Script,
    blinding_key: elements::secp256k1_zkp::SecretKey,
    invoice_id: uuid::Uuid,
) -> Result<Vec<LiquidObservedOutput>, AppError> {
    let (confirmations, block_height, block_hash, phase) =
        liquid_lifecycle_evidence(entry, tip_height, finality_confirmations)?;
    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let mut outputs = Vec::new();
    for (vout, txout) in tx.output.iter().enumerate() {
        if &txout.script_pubkey != script {
            continue;
        }
        let secrets = match txout.unblind(&secp, blinding_key) {
            Ok(secrets) => secrets,
            Err(error) => {
                tracing::debug!(
                    invoice_id = %invoice_id,
                    txid = %entry.txid,
                    vout,
                    "chain_watcher: matching Liquid output did not unblind: {error}"
                );
                continue;
            }
        };
        if secrets.asset != elements::AssetId::LIQUID_BTC {
            tracing::debug!(
                invoice_id = %invoice_id,
                txid = %entry.txid,
                vout,
                asset = %secrets.asset,
                "chain_watcher: ignoring non-LBTC Liquid invoice output"
            );
            continue;
        }
        let amount_sat = i64::try_from(secrets.value)
            .map_err(|_| AppError::InvalidAmount("Liquid output amount overflow".into()))?;
        if amount_sat <= 0 {
            continue;
        }
        let vout = i32::try_from(vout)
            .map_err(|_| AppError::InvalidAmount("Liquid output vout overflow".into()))?;
        outputs.push(LiquidObservedOutput {
            event_key: format!("liquid_direct:{}:{vout}", entry.txid),
            txid: entry.txid.clone(),
            vout,
            amount_sat,
            asset_id: secrets.asset.to_string(),
            confirmations,
            block_height,
            block_hash: block_hash.clone(),
            phase,
            supersedes_event_key: None,
        });
    }
    Ok(outputs)
}

fn liquid_lifecycle_evidence(
    entry: &LiquidHistoryEntry,
    tip_height: i32,
    finality_confirmations: u32,
) -> Result<(i32, Option<i32>, Option<String>, db::DirectObservationPhase), AppError> {
    if finality_confirmations == 0 {
        return Err(AppError::ServiceUnavailable(
            "Liquid finality confirmations must be non-zero".into(),
        ));
    }
    if entry.height <= 0 {
        if entry.block_hash.is_some() {
            return Err(AppError::ElectrumError(
                "mempool Liquid history unexpectedly carried a block hash".into(),
            ));
        }
        return Ok((0, None, None, db::DirectObservationPhase::Provisional));
    }
    if tip_height < entry.height {
        return Err(AppError::ElectrumError(format!(
            "Liquid history height {} exceeds tip {tip_height}",
            entry.height
        )));
    }
    let block_hash = entry.block_hash.clone().ok_or_else(|| {
        AppError::ElectrumError("confirmed Liquid history is missing block identity".into())
    })?;
    let confirmations = tip_height
        .checked_sub(entry.height)
        .and_then(|distance| distance.checked_add(1))
        .ok_or_else(|| AppError::ElectrumError("Liquid confirmation overflow".into()))?;
    let phase = if u32::try_from(confirmations)
        .is_ok_and(|confirmations| confirmations >= finality_confirmations)
    {
        db::DirectObservationPhase::Finalized
    } else {
        db::DirectObservationPhase::Confirmed
    };
    Ok((confirmations, Some(entry.height), Some(block_hash), phase))
}

fn liquid_transaction_inputs(tx: &elements::Transaction) -> LiquidTransactionInputs {
    tx.input
        .iter()
        .filter(|input| !input.previous_output.is_null())
        .map(|input| {
            (
                input.is_pegin,
                input.previous_output.txid.to_string(),
                input.previous_output.vout,
            )
        })
        .collect()
}

/// Classify positively evidenced Liquid replacements from exact transaction
/// input overlap. A replacement is atomic only when one old observation maps
/// to one new exact invoice output and that new output maps back to one old
/// observation. Mismatches and multi-candidate relations become explicit
/// incidents; missing old raw evidence or no overlap is never inferred.
fn reconcile_liquid_replacements(
    known: &[LiquidKnownObservation],
    snapshot: &LiquidHistorySnapshot,
    current_inputs: &std::collections::HashMap<String, LiquidTransactionInputs>,
    prior_inputs: &std::collections::HashMap<String, LiquidTransactionInputs>,
    outputs: &mut Vec<LiquidObservedOutput>,
) -> Result<bool, AppError> {
    #[derive(Debug)]
    enum Decision {
        Replacement {
            old_event_key: String,
            output_index: usize,
        },
        Incident {
            old_event_key: String,
            reason: db::DirectRegressionReason,
        },
    }

    let current_txids = snapshot
        .entries
        .iter()
        .map(|entry| entry.txid.as_str())
        .collect::<std::collections::HashSet<_>>();
    let known_by_key = known
        .iter()
        .map(|observation| (observation.event_key.as_str(), observation))
        .collect::<std::collections::HashMap<_, _>>();
    let mut decisions = Vec::new();

    for old in known
        .iter()
        .filter(|old| !current_txids.contains(old.txid.as_str()))
    {
        let Some(old_inputs) = prior_inputs.get(&old.txid) else {
            continue;
        };
        if old_inputs.is_empty() {
            continue;
        }
        let overlapping_txids = current_inputs
            .iter()
            .filter(|(_, inputs)| !inputs.is_disjoint(old_inputs))
            .map(|(txid, _)| txid.as_str())
            .collect::<Vec<_>>();
        if overlapping_txids.is_empty() {
            continue;
        }

        if old.had_positive_block() {
            let (Some(height), Some(prior_hash)) = (old.block_height, old.block_hash.as_deref())
            else {
                return Err(AppError::DbError(
                    "stored confirmed Liquid replacement candidate is missing block identity"
                        .into(),
                ));
            };
            let Some(current_hash) = snapshot.anchored_block_hashes.get(&height) else {
                return Ok(false);
            };
            if current_hash.eq_ignore_ascii_case(prior_hash) {
                // The old transaction is still committed by a canonical block;
                // a conflicting history entry is provider disagreement, not a
                // replacement proof.
                return Ok(false);
            }
        }

        if overlapping_txids.len() != 1 {
            decisions.push(Decision::Incident {
                old_event_key: old.event_key.clone(),
                reason: db::DirectRegressionReason::Conflict,
            });
            continue;
        }
        let replacement_txid = overlapping_txids[0];
        let old_asset = old.asset_id.as_deref().ok_or_else(|| {
            AppError::DbError("stored Liquid observation is missing its asset identity".into())
        })?;
        let matching_outputs = outputs
            .iter()
            .enumerate()
            .filter(|(_, output)| {
                output.txid == replacement_txid
                    && output.amount_sat == old.amount_sat
                    && output.asset_id.eq_ignore_ascii_case(old_asset)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        match matching_outputs.as_slice() {
            [output_index] => decisions.push(Decision::Replacement {
                old_event_key: old.event_key.clone(),
                output_index: *output_index,
            }),
            [] => decisions.push(Decision::Incident {
                old_event_key: old.event_key.clone(),
                reason: db::DirectRegressionReason::InvalidReplacement,
            }),
            _ => decisions.push(Decision::Incident {
                old_event_key: old.event_key.clone(),
                reason: db::DirectRegressionReason::Conflict,
            }),
        }
    }

    let mut claims_per_output = std::collections::HashMap::<usize, usize>::new();
    for decision in &decisions {
        if let Decision::Replacement { output_index, .. } = decision {
            *claims_per_output.entry(*output_index).or_default() += 1;
        }
    }

    let mut incidents = Vec::new();
    for decision in decisions {
        match decision {
            Decision::Replacement {
                old_event_key,
                output_index,
            } if claims_per_output.get(&output_index) == Some(&1) => {
                outputs[output_index].supersedes_event_key = Some(old_event_key);
            }
            Decision::Replacement { old_event_key, .. } => {
                incidents.push((old_event_key, db::DirectRegressionReason::Conflict));
            }
            Decision::Incident {
                old_event_key,
                reason,
            } => incidents.push((old_event_key, reason)),
        }
    }
    for (old_event_key, reason) in incidents {
        let old = known_by_key.get(old_event_key.as_str()).ok_or_else(|| {
            AppError::DbError("Liquid replacement decision lost its prior observation".into())
        })?;
        outputs.push(old.explicit_invalidation_observation(reason)?);
    }
    Ok(true)
}

async fn list_liquid_direct_watch_evidence(
    pool: &PgPool,
    invoice_id: uuid::Uuid,
) -> Result<Vec<LiquidKnownObservation>, AppError> {
    sqlx::query_as(
        "SELECT event_key, txid, vout, address, amount_sat, asset_id, \
                confirmations, block_height, inclusion_block_hash AS block_hash, \
                last_seen_state::TEXT AS last_seen_state \
         FROM invoice_payment_observations \
         WHERE invoice_id = $1 \
           AND source = 'liquid_direct' \
           AND last_seen_state <> 'superseded' \
         ORDER BY event_key \
         LIMIT $2",
    )
    .bind(invoice_id)
    .bind((MAX_LIQUID_KNOWN_OBSERVATIONS + 1) as i64)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// Reconcile stored positive block identities against the same-authority
/// canonical headers anchored by `snapshot`.
///
/// Returns `false` only for a contradictory positive view whose prior block
/// could not be proven regressed. Callers must defer the whole generation in
/// that case. Missing observations are conservative no-ops unless their prior
/// canonical header hash positively changed.
fn reconcile_liquid_block_regressions(
    known: &[LiquidKnownObservation],
    snapshot: &LiquidHistorySnapshot,
    outputs: &mut Vec<LiquidObservedOutput>,
) -> Result<bool, AppError> {
    let known = known
        .iter()
        .map(|observation| (observation.event_key.as_str(), observation))
        .collect::<std::collections::HashMap<_, _>>();
    let present_keys = outputs
        .iter()
        .flat_map(|output| {
            std::iter::once(output.event_key.clone())
                .chain(output.supersedes_event_key.iter().cloned())
        })
        .collect::<std::collections::HashSet<_>>();

    for output in outputs.iter_mut() {
        let Some(stored) = known.get(output.event_key.as_str()) else {
            continue;
        };
        if !stored.had_positive_block() {
            continue;
        }
        let (Some(prior_height), Some(prior_hash)) =
            (stored.block_height, stored.block_hash.as_deref())
        else {
            return Err(AppError::DbError(
                "stored confirmed Liquid observation is missing block identity".into(),
            ));
        };
        if !reobserved_after_block_regression(
            prior_height,
            prior_hash,
            output.block_height,
            output.block_hash.as_deref(),
        ) {
            continue;
        }
        let Some(current_prior_hash) = snapshot.anchored_block_hashes.get(&prior_height) else {
            return Ok(false);
        };
        if current_prior_hash.eq_ignore_ascii_case(prior_hash) {
            // A stable canonical prior block contradicts the changed positive
            // assignment. Never turn that disagreement into a demotion.
            return Ok(false);
        }
        output.mark_reobserved_after_block_regression(prior_height, prior_hash)?;
    }

    // Append explicit incidents only for prior positive identities absent from
    // the complete current history whose old inclusion block is now proven
    // non-canonical. Ordinary omission and unavailable anchors are no-ops.
    let missing_regressions = known
        .values()
        .filter(|stored| stored.had_positive_block())
        .filter(|stored| !present_keys.contains(&stored.event_key))
        .filter(|stored| {
            let (Some(height), Some(prior_hash)) =
                (stored.block_height, stored.block_hash.as_deref())
            else {
                return false;
            };
            snapshot
                .anchored_block_hashes
                .get(&height)
                .is_some_and(|current_hash| !current_hash.eq_ignore_ascii_case(prior_hash))
        })
        .map(|stored| stored.explicit_invalidation_observation(db::DirectRegressionReason::Reorged))
        .collect::<Result<Vec<_>, _>>()?;

    outputs.extend(missing_regressions);
    Ok(true)
}

fn reobserved_after_block_regression(
    prior_height: i32,
    prior_hash: &str,
    observed_height: Option<i32>,
    observed_hash: Option<&str>,
) -> bool {
    match (observed_height, observed_hash) {
        (None, None) => true,
        (Some(height), Some(hash)) => {
            prior_height != height || !prior_hash.eq_ignore_ascii_case(hash)
        }
        // Lifecycle construction rejects partial current identities before
        // this point; reducer validation also fails closed if one is injected.
        _ => true,
    }
}

async fn poll_nyms(
    ctx: ChainWatcherPollCtx<'_>,
    lookahead: u32,
    nyms: Vec<db::ActiveNymForWatcher>,
    tier: &'static str,
    reporter: &WorkerReporter,
    epoch: &mut db::WatcherNymScanEpoch,
) -> Result<CycleOutcome, AppError> {
    let n_total = nyms.len();
    let started = std::time::Instant::now();
    let mut useful_progress = 0usize;

    let mut rows = nyms.into_iter();
    loop {
        if epoch.current().is_none() {
            let Some(nym) = rows.next() else {
                break;
            };

            // Skip rows with negative indices defensively — DB schema uses i32,
            // but next_addr_idx is conceptually u32. This is obligation-local.
            let base_index = match u32::try_from(nym.next_addr_idx) {
                Ok(index) => index,
                Err(_) => {
                    tracing::warn!(
                        nym = %nym.nym,
                        next_addr_idx = nym.next_addr_idx,
                        "chain_watcher: nym has invalid next_addr_idx; skipping frozen scan"
                    );
                    epoch.advance(nym.nym);
                    useful_progress = useful_progress.saturating_add(1);
                    continue;
                }
            };
            let nym_name = nym.nym;
            if !epoch.begin_nym(nym_name.clone(), nym.ct_descriptor, base_index, lookahead) {
                tracing::warn!(
                    nym = %nym_name,
                    base_index,
                    lookahead,
                    "chain_watcher: frozen nym range exceeds address-index storage; isolating nym"
                );
                epoch.advance(nym_name);
                useful_progress = useful_progress.saturating_add(1);
                continue;
            }
        }

        let current = epoch
            .current()
            .expect("current nym initialized before address scan")
            .clone();
        reporter.progress();
        if ctx.cancel.is_cancelled() {
            return Ok(CycleOutcome::Incomplete);
        }

        let script = match derive_script_pubkey(&current.ct_descriptor, current.next_index) {
            Ok(script) => script,
            Err(error) => {
                tracing::warn!(
                    nym = %current.nym,
                    idx = current.next_index,
                    "chain_watcher: derive failed for frozen nym address: {error}"
                );
                // Malformed persisted descriptor: isolate this whole nym and
                // clear its address subcursor so later keyset rows can proceed.
                epoch.finish_current_nym();
                useful_progress = useful_progress.saturating_add(1);
                continue;
            }
        };

        // Use the watcher-dedicated Electrum bucket so a user-callback storm
        // cannot starve the watcher. The exact current address remains retained
        // when the bucket is empty; useful address progress in this page keeps
        // the cycle incomplete rather than falsely failed.
        if ctx.rate_limiter.check_electrum_watcher().await.is_err() {
            tracing::debug!(
                nym = %current.nym,
                idx = current.next_index,
                "chain_watcher: watcher Electrum bucket exhausted; retaining frozen address"
            );
            return Ok(CycleOutcome::after_token_exhaustion(useful_progress));
        }

        match ctx.backend.has_history(&script).await {
            Ok(true) => {
                // Preserve reservation-before-user-cursor ordering. The address
                // subcursor advances only after both idempotent writes succeed;
                // either failure retries this exact index on the next tick.
                let fulfilled = db::mark_reservations_fulfilled_at_idx(
                    ctx.pool,
                    &current.nym,
                    current.next_index,
                )
                .await?;
                db::advance_next_addr_idx(ctx.pool, &current.nym, current.next_index).await?;
                tracing::info!(
                    nym = %current.nym,
                    idx = current.next_index,
                    fulfilled,
                    "chain_watcher: observed payment in frozen nym range"
                );
            }
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(
                    nym = %current.nym,
                    idx = current.next_index,
                    "chain_watcher: has_history failed for frozen nym address: {error}"
                );
                return Ok(CycleOutcome::Failed);
            }
        }

        epoch.visit_current_address();
        useful_progress = useful_progress.saturating_add(1);
    }
    let elapsed_ms = started.elapsed().as_millis();
    tracing::debug!(
        "chain_watcher: {} tick scanned {} nyms in {}ms",
        tier,
        n_total,
        elapsed_ms
    );
    Ok(CycleOutcome::Healthy)
}

/// Derive the scriptpubkey for `(ct_descriptor, idx)`. Mirrors
/// `descriptor::derive_address` but returns a `Script` so we can hand it to
/// the Electrum backend without a string round-trip.
fn derive_script_pubkey(ct_descriptor: &str, index: u32) -> Result<elements::Script, AppError> {
    let desc: lwk_wollet::WolletDescriptor = ct_descriptor
        .parse()
        .map_err(|e| AppError::InvalidDescriptor(format!("{e}")))?;
    let addr = desc
        .address(index, &elements::AddressParams::LIQUID)
        .map_err(|e| AppError::InvalidDescriptor(format!("address derivation failed: {e}")))?;
    Ok(addr.script_pubkey())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{MoneyAdmission, Rail, Worker};
    use crate::config::RateLimitConfig;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_DESCRIPTOR: &str = "ct(slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023),elwpkh([73c5da0a/84h/1776h/0h]xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*))#y8jljyxl";

    enum FakeHistory {
        Empty,
        BackendFailure,
    }

    struct FakeNymBackend {
        history: FakeHistory,
        health_calls: Arc<AtomicUsize>,
        fail_health: bool,
    }

    #[async_trait::async_trait]
    impl UtxoBackend for FakeNymBackend {
        async fn health_check(&self) -> Result<(), AppError> {
            self.health_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_health {
                Err(AppError::ElectrumError(
                    "test health check failure".to_string(),
                ))
            } else {
                Ok(())
            }
        }

        async fn get_raw_tx(&self, _txid_hex: &str) -> Result<Vec<u8>, AppError> {
            Err(AppError::UtxoNotFound)
        }

        async fn is_unspent(
            &self,
            _script_pubkey: &elements::Script,
            _txid_hex: &str,
            _vout: u32,
        ) -> Result<bool, AppError> {
            Ok(false)
        }

        async fn has_history(&self, _script_pubkey: &elements::Script) -> Result<bool, AppError> {
            match self.history {
                FakeHistory::Empty => Ok(false),
                FakeHistory::BackendFailure => {
                    Err(AppError::ElectrumError("test backend failure".to_string()))
                }
            }
        }

        async fn history_txids(
            &self,
            _script_pubkey: &elements::Script,
        ) -> Result<Vec<String>, AppError> {
            Ok(Vec::new())
        }

        async fn find_spending_txid(
            &self,
            _script_pubkey: &elements::Script,
            _txid_hex: &str,
            _vout: u32,
        ) -> Result<Option<String>, AppError> {
            Ok(None)
        }
    }

    fn test_nym(nym: &str) -> db::ActiveNymForWatcher {
        db::ActiveNymForWatcher {
            nym: nym.to_string(),
            ct_descriptor: TEST_DESCRIPTOR.to_string(),
            next_addr_idx: 0,
        }
    }

    fn lazy_test_pool() -> PgPool {
        PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_watcher_unit_test")
            .expect("lazy test pool")
    }

    fn fixture() -> (MoneyAdmission, WorkerReporter, TierHealth) {
        let admission = MoneyAdmission::healthy_test_fixture();
        let reporter = admission.reporter(Worker::LiquidWatcher);
        (admission, reporter, TierHealth::default())
    }

    fn history_entry(height: i32, block_hash: Option<&str>) -> LiquidHistoryEntry {
        LiquidHistoryEntry {
            txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            height,
            block_hash: block_hash.map(str::to_string),
        }
    }

    fn known_liquid_observation(
        event_key: &str,
        txid: &str,
        block_height: i32,
        block_hash: &str,
    ) -> LiquidKnownObservation {
        LiquidKnownObservation {
            event_key: event_key.to_string(),
            txid: txid.to_string(),
            vout: 0,
            address: "lq1known".to_string(),
            amount_sat: 1_000,
            asset_id: Some(elements::AssetId::LIQUID_BTC.to_string()),
            confirmations: 2,
            block_height: Some(block_height),
            block_hash: Some(block_hash.to_string()),
            last_seen_state: "counted".to_string(),
        }
    }

    fn liquid_snapshot(
        entries: Vec<LiquidHistoryEntry>,
        anchors: &[(i32, &str)],
    ) -> LiquidHistorySnapshot {
        LiquidHistorySnapshot {
            authority: "liquid-electrum:test".to_string(),
            tip_height: 200,
            entries,
            anchored_block_hashes: anchors
                .iter()
                .map(|(height, hash)| (*height, (*hash).to_string()))
                .collect(),
        }
    }

    fn provisional_liquid_output(txid: &str, vout: i32, amount_sat: i64) -> LiquidObservedOutput {
        LiquidObservedOutput {
            event_key: format!("liquid_direct:{txid}:{vout}"),
            txid: txid.to_string(),
            vout,
            amount_sat,
            asset_id: elements::AssetId::LIQUID_BTC.to_string(),
            confirmations: 0,
            block_height: None,
            block_hash: None,
            phase: db::DirectObservationPhase::Provisional,
            supersedes_event_key: None,
        }
    }

    fn tx_inputs(txid: &str, vout: u32) -> LiquidTransactionInputs {
        [(false, txid.to_string(), vout)].into_iter().collect()
    }

    #[test]
    fn liquid_lifecycle_boundaries_keep_accounting_and_finality_distinct() {
        let block_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let provisional = liquid_lifecycle_evidence(&history_entry(0, None), 100, 2).unwrap();
        assert_eq!(provisional.0, 0);
        assert_eq!(provisional.3, db::DirectObservationPhase::Provisional);

        let one_confirmation =
            liquid_lifecycle_evidence(&history_entry(100, Some(block_hash)), 100, 2).unwrap();
        assert_eq!(one_confirmation.0, 1);
        assert_eq!(one_confirmation.3, db::DirectObservationPhase::Confirmed);

        let configured_finality =
            liquid_lifecycle_evidence(&history_entry(100, Some(block_hash)), 101, 2).unwrap();
        assert_eq!(configured_finality.0, 2);
        assert_eq!(configured_finality.3, db::DirectObservationPhase::Finalized);

        let one_block_finality =
            liquid_lifecycle_evidence(&history_entry(100, Some(block_hash)), 100, 1).unwrap();
        assert_eq!(one_block_finality.3, db::DirectObservationPhase::Finalized);
    }

    #[test]
    fn liquid_lifecycle_rejects_incomplete_or_invalid_confirmation_evidence() {
        assert!(liquid_lifecycle_evidence(&history_entry(1, None), 1, 2).is_err());
        assert!(liquid_lifecycle_evidence(&history_entry(2, Some(&"b".repeat(64))), 1, 2).is_err());
        assert!(liquid_lifecycle_evidence(&history_entry(0, None), 1, 0).is_err());
        assert!(
            liquid_lifecycle_evidence(&history_entry(0, Some(&"b".repeat(64))), 1, 2,).is_err()
        );
    }

    #[test]
    fn block_regression_context_preserves_current_positive_evidence_atomically() {
        let old_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let new_hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        assert!(!reobserved_after_block_regression(
            100,
            old_hash,
            Some(100),
            Some(old_hash),
        ));
        assert!(reobserved_after_block_regression(
            100,
            old_hash,
            Some(100),
            Some(new_hash),
        ));
        assert!(reobserved_after_block_regression(100, old_hash, None, None));

        let mut output = LiquidObservedOutput {
            event_key:
                "liquid_direct:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0"
                    .into(),
            txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            vout: 0,
            amount_sat: 1_000,
            asset_id: elements::AssetId::LIQUID_BTC.to_string(),
            confirmations: 1,
            block_height: Some(101),
            block_hash: Some(new_hash.into()),
            phase: db::DirectObservationPhase::Confirmed,
            supersedes_event_key: None,
        };
        output
            .mark_reobserved_after_block_regression(100, old_hash)
            .unwrap();
        assert_eq!(output.confirmations, 1);
        assert_eq!(output.block_height, Some(101));
        assert_eq!(output.block_hash.as_deref(), Some(new_hash));
        assert!(matches!(
            output.phase,
            db::DirectObservationPhase::ReobservedAfterBlockRegression {
                phase: db::DirectPositivePhase::Confirmed,
                prior_block_height: 100,
                reason: db::DirectRegressionReason::Reorged,
                ..
            }
        ));
    }

    #[test]
    fn missing_liquid_tx_demotes_only_when_prior_block_hash_regressed() {
        let txid = "a".repeat(64);
        let event_key = format!("liquid_direct:{txid}:0");
        let old_hash = "b".repeat(64);
        let new_hash = "c".repeat(64);
        let known = vec![known_liquid_observation(&event_key, &txid, 100, &old_hash)];

        let mut outputs = Vec::new();
        let regressed = liquid_snapshot(vec![], &[(100, &new_hash)]);
        assert!(reconcile_liquid_block_regressions(&known, &regressed, &mut outputs).unwrap());
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].event_key, event_key);
        assert_eq!(outputs[0].block_height, Some(100));
        assert_eq!(outputs[0].block_hash.as_deref(), Some(old_hash.as_str()));
        assert!(matches!(
            outputs[0].phase,
            db::DirectObservationPhase::ResolutionPending(db::DirectRegressionReason::Reorged)
        ));

        let mut unchanged_outputs = Vec::new();
        let unchanged = liquid_snapshot(vec![], &[(100, &old_hash)]);
        assert!(
            reconcile_liquid_block_regressions(&known, &unchanged, &mut unchanged_outputs).unwrap()
        );
        assert!(unchanged_outputs.is_empty());

        let mut unavailable_outputs = Vec::new();
        let unavailable = liquid_snapshot(vec![], &[]);
        assert!(
            reconcile_liquid_block_regressions(&known, &unavailable, &mut unavailable_outputs)
                .unwrap()
        );
        assert!(unavailable_outputs.is_empty());
    }

    #[test]
    fn reobserved_liquid_tx_carries_atomic_prior_block_context() {
        let txid = "a".repeat(64);
        let event_key = format!("liquid_direct:{txid}:0");
        let old_hash = "b".repeat(64);
        let new_hash = "c".repeat(64);
        let known = vec![known_liquid_observation(&event_key, &txid, 100, &old_hash)];
        let mut outputs = vec![LiquidObservedOutput {
            event_key,
            txid,
            vout: 0,
            amount_sat: 1_000,
            asset_id: elements::AssetId::LIQUID_BTC.to_string(),
            confirmations: 0,
            block_height: None,
            block_hash: None,
            phase: db::DirectObservationPhase::Provisional,
            supersedes_event_key: None,
        }];
        let snapshot = liquid_snapshot(vec![], &[(100, &new_hash)]);

        assert!(reconcile_liquid_block_regressions(&known, &snapshot, &mut outputs).unwrap());
        assert!(matches!(
            outputs[0].phase,
            db::DirectObservationPhase::ReobservedAfterBlockRegression {
                phase: db::DirectPositivePhase::Provisional,
                prior_block_height: 100,
                reason: db::DirectRegressionReason::Reorged,
                ..
            }
        ));
    }

    #[test]
    fn contradictory_present_liquid_tx_defers_without_mutation() {
        let txid = "a".repeat(64);
        let event_key = format!("liquid_direct:{txid}:0");
        let old_hash = "b".repeat(64);
        let known = vec![known_liquid_observation(&event_key, &txid, 100, &old_hash)];
        let mut outputs = vec![LiquidObservedOutput {
            event_key,
            txid,
            vout: 0,
            amount_sat: 1_000,
            asset_id: elements::AssetId::LIQUID_BTC.to_string(),
            confirmations: 0,
            block_height: None,
            block_hash: None,
            phase: db::DirectObservationPhase::Provisional,
            supersedes_event_key: None,
        }];
        let snapshot = liquid_snapshot(vec![], &[(100, &old_hash)]);

        assert!(!reconcile_liquid_block_regressions(&known, &snapshot, &mut outputs).unwrap());
        assert_eq!(outputs[0].phase, db::DirectObservationPhase::Provisional);
    }

    #[test]
    fn unique_exact_liquid_input_overlap_is_an_atomic_replacement() {
        let old_txid = "a".repeat(64);
        let new_txid = "b".repeat(64);
        let funding_txid = "f".repeat(64);
        let old_event_key = format!("liquid_direct:{old_txid}:0");
        let old_hash = "c".repeat(64);
        let current_hash = "d".repeat(64);
        let known = vec![known_liquid_observation(
            &old_event_key,
            &old_txid,
            100,
            &old_hash,
        )];
        let snapshot = liquid_snapshot(
            vec![LiquidHistoryEntry {
                txid: new_txid.clone(),
                height: 0,
                block_hash: None,
            }],
            &[(100, &current_hash)],
        );
        let current_inputs = [(new_txid.clone(), tx_inputs(&funding_txid, 1))]
            .into_iter()
            .collect();
        let prior_inputs = [(old_txid, tx_inputs(&funding_txid, 1))]
            .into_iter()
            .collect();
        let mut outputs = vec![provisional_liquid_output(&new_txid, 2, 1_000)];

        assert!(reconcile_liquid_replacements(
            &known,
            &snapshot,
            &current_inputs,
            &prior_inputs,
            &mut outputs,
        )
        .unwrap());
        assert_eq!(outputs.len(), 1);
        assert_eq!(
            outputs[0].supersedes_event_key.as_deref(),
            Some(old_event_key.as_str())
        );
        assert!(reconcile_liquid_block_regressions(&known, &snapshot, &mut outputs).unwrap());
        assert_eq!(
            outputs.len(),
            1,
            "an atomic replacement must not also expose a reorg incident"
        );
    }

    #[test]
    fn decoded_liquid_transactions_drive_exact_live_replacement_evidence() {
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let blinding_key = secp256k1::SecretKey::new(&mut rng);
        let blinding_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &blinding_key);
        let script = elements::Script::from(vec![0x51]);
        let funding =
            elements::OutPoint::new(elements::Txid::from_str(&"f".repeat(64)).unwrap(), 7);
        let mut confidential_output = || {
            let input_secrets = elements::TxOutSecrets::new(
                elements::AssetId::LIQUID_BTC,
                elements::confidential::AssetBlindingFactor::new(&mut rng),
                1_000,
                elements::confidential::ValueBlindingFactor::new(&mut rng),
            );
            elements::TxOut::new_last_confidential(
                &mut rng,
                &secp,
                1_000,
                elements::AssetId::LIQUID_BTC,
                script.clone(),
                blinding_pubkey,
                &[input_secrets],
                &[],
            )
            .unwrap()
            .0
        };
        let old = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: funding,
                sequence: elements::Sequence::ZERO,
                ..Default::default()
            }],
            output: vec![confidential_output()],
        };
        let replacement = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: funding,
                sequence: elements::Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            }],
            output: vec![confidential_output()],
        };
        let old: elements::Transaction = deserialize(&elements::encode::serialize(&old)).unwrap();
        let replacement: elements::Transaction =
            deserialize(&elements::encode::serialize(&replacement)).unwrap();
        let old_txid = old.txid().to_string();
        let replacement_txid = replacement.txid().to_string();
        assert_ne!(old_txid, replacement_txid);

        let old_event_key = format!("liquid_direct:{old_txid}:0");
        let mut old_observation =
            known_liquid_observation(&old_event_key, &old_txid, 100, &"c".repeat(64));
        old_observation.confirmations = 0;
        old_observation.block_height = None;
        old_observation.block_hash = None;
        old_observation.last_seen_state = "seen_unconfirmed".to_string();
        let known = vec![old_observation];
        let entry = LiquidHistoryEntry {
            txid: replacement_txid.clone(),
            height: 0,
            block_hash: None,
        };
        let snapshot = liquid_snapshot(vec![entry.clone()], &[]);
        let current_inputs = [(
            replacement_txid.clone(),
            liquid_transaction_inputs(&replacement),
        )]
        .into_iter()
        .collect();
        let prior_inputs = [(old_txid, liquid_transaction_inputs(&old))]
            .into_iter()
            .collect();
        let mut outputs = extract_liquid_outputs(
            &entry,
            200,
            2,
            &replacement,
            &script,
            blinding_key,
            uuid::Uuid::nil(),
        )
        .unwrap();

        assert!(reconcile_liquid_replacements(
            &known,
            &snapshot,
            &current_inputs,
            &prior_inputs,
            &mut outputs,
        )
        .unwrap());
        assert_eq!(outputs.len(), 1);
        let reducer_observation = outputs[0].as_direct_observation("lq1known");
        assert_eq!(
            reducer_observation.supersedes_event_key,
            Some(old_event_key.as_str())
        );
    }

    #[test]
    fn overlapping_liquid_tx_with_mismatched_output_is_invalid_replacement() {
        let old_txid = "a".repeat(64);
        let new_txid = "b".repeat(64);
        let funding_txid = "f".repeat(64);
        let old_event_key = format!("liquid_direct:{old_txid}:0");
        let old_hash = "c".repeat(64);
        let current_hash = "d".repeat(64);
        let known = vec![known_liquid_observation(
            &old_event_key,
            &old_txid,
            100,
            &old_hash,
        )];
        let snapshot = liquid_snapshot(
            vec![LiquidHistoryEntry {
                txid: new_txid.clone(),
                height: 0,
                block_hash: None,
            }],
            &[(100, &current_hash)],
        );
        let current_inputs = [(new_txid.clone(), tx_inputs(&funding_txid, 1))]
            .into_iter()
            .collect();
        let prior_inputs = [(old_txid, tx_inputs(&funding_txid, 1))]
            .into_iter()
            .collect();
        let mut outputs = vec![provisional_liquid_output(&new_txid, 2, 999)];

        assert!(reconcile_liquid_replacements(
            &known,
            &snapshot,
            &current_inputs,
            &prior_inputs,
            &mut outputs,
        )
        .unwrap());
        assert_eq!(outputs.len(), 2);
        assert!(outputs[0].supersedes_event_key.is_none());
        assert_eq!(outputs[1].event_key, old_event_key);
        assert!(matches!(
            outputs[1].phase,
            db::DirectObservationPhase::ResolutionPending(
                db::DirectRegressionReason::InvalidReplacement
            )
        ));
    }

    #[test]
    fn multiple_exact_liquid_replacement_outputs_are_conflict() {
        let old_txid = "a".repeat(64);
        let new_txid = "b".repeat(64);
        let funding_txid = "f".repeat(64);
        let old_event_key = format!("liquid_direct:{old_txid}:0");
        let old_hash = "c".repeat(64);
        let current_hash = "d".repeat(64);
        let known = vec![known_liquid_observation(
            &old_event_key,
            &old_txid,
            100,
            &old_hash,
        )];
        let snapshot = liquid_snapshot(
            vec![LiquidHistoryEntry {
                txid: new_txid.clone(),
                height: 0,
                block_hash: None,
            }],
            &[(100, &current_hash)],
        );
        let current_inputs = [(new_txid.clone(), tx_inputs(&funding_txid, 1))]
            .into_iter()
            .collect();
        let prior_inputs = [(old_txid, tx_inputs(&funding_txid, 1))]
            .into_iter()
            .collect();
        let mut outputs = vec![
            provisional_liquid_output(&new_txid, 2, 1_000),
            provisional_liquid_output(&new_txid, 3, 1_000),
        ];

        assert!(reconcile_liquid_replacements(
            &known,
            &snapshot,
            &current_inputs,
            &prior_inputs,
            &mut outputs,
        )
        .unwrap());
        assert_eq!(outputs.len(), 3);
        assert!(outputs[..2]
            .iter()
            .all(|output| output.supersedes_event_key.is_none()));
        assert_eq!(outputs[2].event_key, old_event_key);
        assert!(matches!(
            outputs[2].phase,
            db::DirectObservationPhase::ResolutionPending(db::DirectRegressionReason::Conflict)
        ));
    }

    #[test]
    fn missing_or_nonoverlapping_liquid_inputs_never_infer_replacement() {
        let old_txid = "a".repeat(64);
        let new_txid = "b".repeat(64);
        let old_event_key = format!("liquid_direct:{old_txid}:0");
        let old_hash = "c".repeat(64);
        let known = vec![known_liquid_observation(
            &old_event_key,
            &old_txid,
            100,
            &old_hash,
        )];
        let snapshot = liquid_snapshot(
            vec![LiquidHistoryEntry {
                txid: new_txid.clone(),
                height: 0,
                block_hash: None,
            }],
            &[],
        );
        let current_inputs = [(new_txid.clone(), tx_inputs(&"e".repeat(64), 1))]
            .into_iter()
            .collect();
        let mut outputs = vec![provisional_liquid_output(&new_txid, 2, 1_000)];

        assert!(reconcile_liquid_replacements(
            &known,
            &snapshot,
            &current_inputs,
            &std::collections::HashMap::new(),
            &mut outputs,
        )
        .unwrap());
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].supersedes_event_key.is_none());

        let prior_inputs = [(old_txid, tx_inputs(&"f".repeat(64), 1))]
            .into_iter()
            .collect();
        assert!(reconcile_liquid_replacements(
            &known,
            &snapshot,
            &current_inputs,
            &prior_inputs,
            &mut outputs,
        )
        .unwrap());
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].supersedes_event_key.is_none());
    }

    #[test]
    fn exact_lbtc_outputs_are_retained_as_separate_observations() {
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let blinding_key = secp256k1::SecretKey::new(&mut rng);
        let blinding_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &blinding_key);
        let script = elements::Script::from(vec![0x51]);
        let other_script = elements::Script::from(vec![0x52]);

        let mut confidential_output = |value, script_pubkey| {
            let input_secrets = elements::TxOutSecrets::new(
                elements::AssetId::LIQUID_BTC,
                elements::confidential::AssetBlindingFactor::new(&mut rng),
                value,
                elements::confidential::ValueBlindingFactor::new(&mut rng),
            );
            elements::TxOut::new_last_confidential(
                &mut rng,
                &secp,
                value,
                elements::AssetId::LIQUID_BTC,
                script_pubkey,
                blinding_pubkey,
                &[input_secrets],
                &[],
            )
            .expect("confidential output")
            .0
        };
        let tx = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![
                confidential_output(999, other_script),
                confidential_output(125, script.clone()),
                confidential_output(875, script.clone()),
            ],
        };
        let entry = LiquidHistoryEntry {
            txid: tx.txid().to_string(),
            height: 100,
            block_hash: Some(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            ),
        };
        let outputs = extract_liquid_outputs(
            &entry,
            100,
            2,
            &tx,
            &script,
            blinding_key,
            uuid::Uuid::nil(),
        )
        .unwrap();

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].vout, 1);
        assert_eq!(outputs[0].amount_sat, 125);
        assert_eq!(outputs[1].vout, 2);
        assert_eq!(outputs[1].amount_sat, 875);
        assert!(outputs
            .iter()
            .all(|output| output.asset_id == elements::AssetId::LIQUID_BTC.to_string()));
        assert!(outputs
            .iter()
            .all(|output| output.phase == db::DirectObservationPhase::Confirmed));
    }

    #[test]
    fn incomplete_startup_cycle_stays_closed() {
        let (admission, reporter, mut tier_health) = fixture();

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

        assert!(!admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn healthy_tier_cannot_open_startup_while_other_tier_is_unknown() {
        let (admission, reporter, mut tier_health) = fixture();

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Healthy,
        );
        assert_eq!(tier_health.active, TierState::Healthy);
        assert_eq!(tier_health.idle, TierState::Unknown);
        assert!(!admission.decision(Rail::DirectLiquid).allowed());

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Idle,
            CycleOutcome::Healthy,
        );
        assert!(admission.decision(Rail::DirectLiquid).allowed());
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

    #[test]
    fn completed_nym_phase_stays_latched_until_invoice_epoch_finishes() {
        let mut epoch = LiquidTierScanEpoch::default();
        epoch.nyms.begin("2026-07-12 12:00:00+00".to_string());
        epoch.nyms.advance("last-nym".to_string());
        epoch.nyms_complete = true;
        epoch.invoices.begin("2026-07-12 12:01:00+00".to_string());
        epoch.invoices.advance(db::WatcherScanCursor {
            created_at: "2026-07-12 11:00:00+00".to_string(),
            id: uuid::Uuid::from_u128(1),
        });

        // An incomplete invoice page leaves the completed nym phase intact,
        // so the next tick resumes invoices instead of restarting at nym one.
        assert!(epoch.nyms_complete);
        assert_eq!(epoch.nyms.cursor(), Some("last-nym"));
        assert!(epoch.invoices.cursor().is_some());

        epoch.finish();
        assert!(!epoch.nyms_complete);
        assert!(epoch.nyms.snapshot().is_none());
        assert!(epoch.nyms.cursor().is_none());
        assert!(epoch.invoices.snapshot().is_none());
        assert!(epoch.invoices.cursor().is_none());
    }

    #[test]
    fn liquid_history_anchor_and_prior_tx_caps_are_hard_bounds() {
        assert_eq!(LIQUID_SNAPSHOT_LIMITS.max_history_entries, 256);
        assert_eq!(LIQUID_SNAPSHOT_LIMITS.max_block_heights, 256);
        assert_eq!(MAX_LIQUID_KNOWN_OBSERVATIONS, 256);
        assert_eq!(MAX_LIQUID_EMITTED_OUTPUTS, 256);

        for limit in [
            LiquidHistorySnapshotLimit::HistoryEntries {
                observed: 257,
                limit: LIQUID_SNAPSHOT_LIMITS.max_history_entries,
            },
            LiquidHistorySnapshotLimit::BlockHeights {
                observed: 257,
                limit: LIQUID_SNAPSHOT_LIMITS.max_block_heights,
            },
        ] {
            let result = complete_liquid_snapshot(LiquidHistorySnapshotOutcome::Incomplete(limit));
            assert_eq!(result.unwrap_err(), limit);
        }

        assert!(!prior_liquid_tx_count_is_hard_bound(204));
        assert!(!prior_liquid_tx_count_is_hard_bound(256));
        assert!(prior_liquid_tx_count_is_hard_bound(257));
        assert!(!liquid_known_observation_count_is_hard_bound(199));
        assert!(!liquid_known_observation_count_is_hard_bound(256));
        assert!(liquid_known_observation_count_is_hard_bound(257));
        assert!(!liquid_emitted_output_count_is_hard_bound(199));
        assert!(!liquid_emitted_output_count_is_hard_bound(256));
        assert!(liquid_emitted_output_count_is_hard_bound(257));
        assert!(!liquid_emitted_output_count_would_be_hard_bound(255, 1));
        assert!(liquid_emitted_output_count_would_be_hard_bound(256, 1));
        assert!(liquid_emitted_output_count_would_be_hard_bound(
            usize::MAX,
            1
        ));
    }

    #[tokio::test]
    async fn liquid_mid_obligation_budget_waits_beyond_initial_capacity() {
        let pool = lazy_test_pool();
        let cfg = RateLimitConfig {
            chain_watcher_electrum_rate_per_sec: 2,
            ..RateLimitConfig::default()
        };
        let rate_limiter = RateLimiter::new(pool, cfg);
        let cancel = CancellationToken::new();

        for _ in 0..2 {
            assert!(rate_limiter.acquire_electrum_watcher(&cancel).await);
        }
        let acquired = tokio::time::timeout(
            Duration::from_millis(1_500),
            rate_limiter.acquire_electrum_watcher(&cancel),
        )
        .await
        .expect("watcher budget should refill instead of restarting the obligation");

        assert!(acquired);
    }

    #[tokio::test]
    async fn liquid_mid_obligation_budget_wait_is_cancellable() {
        let pool = lazy_test_pool();
        let cfg = RateLimitConfig {
            chain_watcher_electrum_rate_per_sec: 1,
            ..RateLimitConfig::default()
        };
        let rate_limiter = RateLimiter::new(pool, cfg);
        let already_cancelled = CancellationToken::new();
        already_cancelled.cancel();
        assert!(
            !rate_limiter
                .acquire_electrum_watcher(&already_cancelled)
                .await,
            "an already-cancelled obligation must not consume available capacity"
        );

        let cancel = CancellationToken::new();
        assert!(rate_limiter.acquire_electrum_watcher(&cancel).await);
        cancel.cancel();
        let acquired = tokio::time::timeout(
            Duration::from_millis(100),
            rate_limiter.acquire_electrum_watcher(&cancel),
        )
        .await
        .expect("cancelled watcher budget wait should return promptly");

        assert!(!acquired);
    }

    #[test]
    fn liquid_hard_bound_epoch_visits_later_rows_fails_health_and_retries() {
        let hard_bound = db::WatcherScanCursor {
            created_at: "2026-07-12 11:00:00+00".to_string(),
            id: uuid::Uuid::from_u128(1),
        };
        let later = db::WatcherScanCursor {
            created_at: "2026-07-12 11:01:00+00".to_string(),
            id: uuid::Uuid::from_u128(2),
        };
        let mut epoch = LiquidTierScanEpoch {
            nyms_complete: true,
            ..LiquidTierScanEpoch::default()
        };
        epoch.invoices.begin("2026-07-12 12:00:00+00".to_string());

        epoch.note_invoice_hard_bound(hard_bound.clone());
        assert_eq!(epoch.invoices.cursor(), Some(&hard_bound));
        epoch.invoices.advance(later.clone());
        assert_eq!(epoch.invoices.cursor(), Some(&later));
        assert_eq!(
            liquid_invoice_epoch_outcome(&epoch, false),
            CycleOutcome::HardBoundFailed
        );

        let (admission, reporter, mut tier_health) = fixture();
        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::HardBoundFailed,
        );
        assert!(!admission.decision(Rail::DirectLiquid).allowed());

        epoch.finish();
        assert!(epoch.invoices.snapshot().is_none());
        assert!(epoch.invoices.cursor().is_none());
        assert!(!epoch.invoice_hard_bound_failure);
        epoch.invoices.begin("2026-07-12 12:05:00+00".to_string());
        assert!(
            epoch.invoices.cursor().is_none(),
            "hard row retries next epoch"
        );
    }

    #[tokio::test]
    async fn nym_token_exhaustion_resumes_after_last_complete_nym() {
        let pool = lazy_test_pool();
        let cfg = RateLimitConfig {
            chain_watcher_electrum_rate_per_sec: 1,
            ..RateLimitConfig::default()
        };
        let rate_limiter = RateLimiter::new(pool.clone(), cfg);
        let backend = FakeNymBackend {
            history: FakeHistory::Empty,
            health_calls: Arc::new(AtomicUsize::new(0)),
            fail_health: false,
        };
        let cancel = CancellationToken::new();
        let (_admission, reporter, _) = fixture();
        let ctx = ChainWatcherPollCtx {
            pool: &pool,
            backend: &backend,
            rate_limiter: &rate_limiter,
            cancel: &cancel,
        };
        let mut epoch = db::WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());

        let outcome = poll_nyms(
            ctx,
            0,
            vec![test_nym("alice"), test_nym("bob")],
            "active",
            &reporter,
            &mut epoch,
        )
        .await
        .expect("nym page outcome");
        assert_eq!(outcome, CycleOutcome::Incomplete);
        assert_eq!(epoch.cursor(), Some("alice"));
        let current = epoch
            .current()
            .expect("bob retained after token exhaustion");
        assert_eq!(current.nym, "bob");
        assert_eq!(current.next_index, 0);

        // The next keyset page begins after bob; bob itself resumes from the
        // frozen subcursor. With no newly-refilled token it makes zero address
        // progress, fails, and still does not skip bob.
        let outcome = poll_nyms(ctx, 0, vec![], "active", &reporter, &mut epoch)
            .await
            .expect("resumed nym page outcome");
        assert_eq!(outcome, CycleOutcome::Failed);
        assert_eq!(epoch.cursor(), Some("alice"));
        assert_eq!(epoch.current().expect("bob still retained").next_index, 0);
    }

    #[tokio::test]
    async fn mid_nym_token_exhaustion_resumes_at_exact_next_address() {
        let pool = lazy_test_pool();
        let cfg = RateLimitConfig {
            chain_watcher_electrum_rate_per_sec: 1,
            ..RateLimitConfig::default()
        };
        let rate_limiter = RateLimiter::new(pool.clone(), cfg);
        let backend = FakeNymBackend {
            history: FakeHistory::Empty,
            health_calls: Arc::new(AtomicUsize::new(0)),
            fail_health: false,
        };
        let cancel = CancellationToken::new();
        let (_admission, reporter, _) = fixture();
        let ctx = ChainWatcherPollCtx {
            pool: &pool,
            backend: &backend,
            rate_limiter: &rate_limiter,
            cancel: &cancel,
        };
        let mut epoch = db::WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());

        let outcome = poll_nyms(
            ctx,
            2,
            vec![test_nym("alice")],
            "active",
            &reporter,
            &mut epoch,
        )
        .await
        .expect("partial nym outcome");
        assert_eq!(outcome, CycleOutcome::Incomplete);
        let current = epoch.current().expect("mid-nym subcursor retained");
        assert_eq!(current.nym, "alice");
        assert_eq!(current.next_index, 1);
        assert_eq!(current.end_index, 2);
        assert_eq!(epoch.cursor(), None);
        assert_eq!(epoch.query_cursor(), Some("alice"));

        // Production fetches later rows strictly after query_cursor, so the
        // retained nym is absent from this page and resumes from memory.
        let outcome = poll_nyms(ctx, 2, vec![], "active", &reporter, &mut epoch)
            .await
            .expect("retained nym outcome");
        assert_eq!(outcome, CycleOutcome::Failed);
        assert_eq!(
            epoch.current().expect("exact address retained").next_index,
            1
        );
    }

    #[tokio::test]
    async fn systemic_nym_backend_failure_retains_current_nym() {
        let pool = lazy_test_pool();
        let rate_limiter = RateLimiter::new(pool.clone(), RateLimitConfig::default());
        let backend = FakeNymBackend {
            history: FakeHistory::BackendFailure,
            health_calls: Arc::new(AtomicUsize::new(0)),
            fail_health: false,
        };
        let cancel = CancellationToken::new();
        let (_admission, reporter, _) = fixture();
        let ctx = ChainWatcherPollCtx {
            pool: &pool,
            backend: &backend,
            rate_limiter: &rate_limiter,
            cancel: &cancel,
        };
        let mut epoch = db::WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        epoch.advance("alice".to_string());

        let outcome = poll_nyms(ctx, 0, vec![test_nym("bob")], "idle", &reporter, &mut epoch)
            .await
            .expect("backend failure outcome");
        assert_eq!(outcome, CycleOutcome::Failed);
        assert_eq!(epoch.cursor(), Some("alice"));
        let current = epoch.current().expect("systemic failure retains bob");
        assert_eq!(current.nym, "bob");
        assert_eq!(current.next_index, 0);
        assert_eq!(current.end_index, 0);
    }

    #[tokio::test]
    async fn disappeared_current_nym_finishes_frozen_work_before_later_page_rows() {
        let pool = lazy_test_pool();
        let rate_limiter = RateLimiter::new(pool.clone(), RateLimitConfig::default());
        let backend = FakeNymBackend {
            history: FakeHistory::Empty,
            health_calls: Arc::new(AtomicUsize::new(0)),
            fail_health: false,
        };
        let cancel = CancellationToken::new();
        let (_admission, reporter, _) = fixture();
        let ctx = ChainWatcherPollCtx {
            pool: &pool,
            backend: &backend,
            rate_limiter: &rate_limiter,
            cancel: &cancel,
        };
        let mut epoch = db::WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        assert!(epoch.begin_nym("gone".to_string(), TEST_DESCRIPTOR.to_string(), 0, 0));
        assert_eq!(epoch.query_cursor(), Some("gone"));

        // The DB page is keyed after `gone`, so a deactivated/deleted current
        // nym is not present. Its frozen address still drains safely, then the
        // later row proceeds without a pin or skip.
        let outcome = poll_nyms(
            ctx,
            0,
            vec![test_nym("later")],
            "idle",
            &reporter,
            &mut epoch,
        )
        .await
        .expect("disappeared nym convergence");
        assert_eq!(outcome, CycleOutcome::Healthy);
        assert!(epoch.current().is_none());
        assert_eq!(epoch.cursor(), Some("later"));
    }

    #[tokio::test]
    async fn failing_liquid_probe_prevents_empty_startup_success() {
        let pool = lazy_test_pool();
        let rate_limiter = RateLimiter::new(pool.clone(), RateLimitConfig::default());
        let health_calls = Arc::new(AtomicUsize::new(0));
        let backend = FakeNymBackend {
            history: FakeHistory::Empty,
            health_calls: health_calls.clone(),
            fail_health: true,
        };
        let cancel = CancellationToken::new();
        let (admission, reporter, mut tier_health) = fixture();
        let mut epoch = LiquidTierScanEpoch::default();

        // The lazy pool has no server behind it. The backend probe must run
        // before an empty/page lookup can short-circuit the tier as healthy.
        let outcome = poll_cycle(
            ChainWatcherPollCtx {
                pool: &pool,
                backend: &backend,
                rate_limiter: &rate_limiter,
                cancel: &cancel,
            },
            &ChainWatcherConfig::default(),
            db::InvoiceAccountingTolerances::default(),
            true,
            &reporter,
            &mut epoch,
        )
        .await;

        assert_eq!(health_calls.load(Ordering::SeqCst), 1);
        assert_eq!(outcome, CycleOutcome::Failed);
        report_outcome(&reporter, &mut tier_health, WatchTier::Active, outcome);
        assert_eq!(tier_health.active, TierState::Failed);
        assert!(!admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn active_success_does_not_reset_interleaved_idle_failures() {
        let (admission, reporter, mut tier_health) = fixture();
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

        assert!(!admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn two_successes_reopen_after_both_tiers_are_healthy() {
        let (admission, reporter, mut tier_health) = fixture();
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
        assert!(!admission.decision(Rail::DirectLiquid).allowed());

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Idle,
            CycleOutcome::Healthy,
        );
        assert!(!admission.decision(Rail::DirectLiquid).allowed());
        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Healthy,
        );

        assert!(admission.decision(Rail::DirectLiquid).allowed());
    }
}

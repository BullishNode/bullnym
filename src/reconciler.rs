//! Boltz state reconciler.
//!
//! Boltz's webhook delivery is best-effort: 5 retries × 60s constant
//! interval, 15s timeout per delivery, ~5 minutes total before
//! `Abandoned` (verified at boltz-backend `boltzr/src/webhook/caller.rs`).
//! If a webhook is dropped — Boltz incident, our deploy mid-flight,
//! transient 5xx — the row stays in `pending` / `lockup_*` while the
//! on-chain HTLC progresses, and the 30s background sweep can't
//! advance it because the sweep doesn't query Boltz for state, it just
//! retries claims.
//!
//! The reconciler closes that gap. It runs on a separate `tokio::spawn`
//! task, ticks every 90s by default, scans every non-terminal swap
//! older than 60s (capped at 200 per tick), and calls
//! `BoltzApiClientV2::get_swap` to fetch Boltz's current view. If the
//! views disagree, it patches our DB to match Boltz — Boltz's state is
//! the source of truth for the swap state machine.
//!
//! The reconciler **does not claim** — that's the sweep's job. The
//! reconciler only updates row state and schedules immediate retries
//! by setting `next_claim_attempt_at = NOW()`. This split keeps the
//! reconciler simple and idempotent.

use std::sync::Arc;
use std::time::Duration;

use boltz_client::error::Error as BoltzClientError;
use boltz_client::swaps::boltz::BoltzApiClientV2;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use crate::admission::WorkerReporter;
use crate::config::ReconcilerConfig;
use crate::db::{self, ReconcilerSwap, SwapStatus};
use crate::error::AppError;
use crate::invoice;
use crate::AppState;

/// Health accumulated across one worker cycle. Provider failures only close a
/// cycle when every attempted provider call failed, which isolates a missing or
/// malformed individual swap. Database and other typed infrastructure failures
/// are systemic immediately.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CycleHealth {
    provider_attempts: u32,
    provider_successes: u32,
    systemic_failure: bool,
}

impl CycleHealth {
    fn provider_succeeded(&mut self) {
        self.provider_attempts = self.provider_attempts.saturating_add(1);
        self.provider_successes = self.provider_successes.saturating_add(1);
    }

    fn provider_failed(&mut self) {
        self.provider_attempts = self.provider_attempts.saturating_add(1);
    }

    fn provider_error(&mut self, error: &BoltzClientError) {
        if matches!(
            error,
            BoltzClientError::HTTPStatusNotSuccess(status, _)
                if matches!(
                    *status,
                    reqwest::StatusCode::BAD_REQUEST
                        | reqwest::StatusCode::NOT_FOUND
                        | reqwest::StatusCode::CONFLICT
                        | reqwest::StatusCode::UNPROCESSABLE_ENTITY
                )
        ) {
            // A typed request-specific response proves the provider is alive;
            // isolate the malformed/stale obligation instead of degrading the
            // whole worker.
            self.provider_succeeded();
        } else {
            self.provider_failed();
        }
    }

    fn observe_app_error(&mut self, error: &AppError) {
        if matches!(
            error,
            AppError::DbError(_) | AppError::ElectrumError(_) | AppError::BoltzError(_)
        ) {
            self.systemic_failure = true;
        }
    }

    fn settlement_write(&mut self, succeeded: bool) {
        if !succeeded {
            self.systemic_failure = true;
        }
    }

    fn is_healthy(self) -> bool {
        !self.systemic_failure && (self.provider_attempts == 0 || self.provider_successes > 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanOutcome {
    Progress,
    Succeeded,
    Failed,
    Cancelled,
}

impl ScanOutcome {
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Cancelled, _) | (_, Self::Cancelled) => Self::Cancelled,
            (Self::Failed, _) | (_, Self::Failed) => Self::Failed,
            (Self::Progress, _) | (_, Self::Progress) => Self::Progress,
            (Self::Succeeded, Self::Succeeded) => Self::Succeeded,
        }
    }
}

fn scan_outcome(limit: u32, fetched: usize, healthy: bool) -> ScanOutcome {
    if limit == 0 || !healthy {
        ScanOutcome::Failed
    } else if fetched > limit as usize {
        ScanOutcome::Progress
    } else {
        ScanOutcome::Succeeded
    }
}

fn sentinel_limit(limit: u32) -> u32 {
    limit.saturating_add(1)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ScanCursor {
    after_id: Option<uuid::Uuid>,
    drained: bool,
}

impl ScanCursor {
    fn visit(&mut self, id: uuid::Uuid) {
        debug_assert!(self.after_id.is_none_or(|after_id| id > after_id));
        self.after_id = Some(id);
    }

    fn finish_page(&mut self, limit: u32, fetched: usize, healthy: bool) -> ScanOutcome {
        let outcome = scan_outcome(limit, fetched, healthy);
        if outcome == ScanOutcome::Succeeded {
            self.drained = true;
        }
        outcome
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EpochScan<const N: usize> {
    epoch_micros: Option<i64>,
    cursors: [ScanCursor; N],
}

impl<const N: usize> Default for EpochScan<N> {
    fn default() -> Self {
        Self {
            epoch_micros: None,
            cursors: [ScanCursor::default(); N],
        }
    }
}

impl<const N: usize> EpochScan<N> {
    fn begin(&mut self, epoch_micros: i64) {
        self.epoch_micros = Some(epoch_micros);
        self.cursors = [ScanCursor::default(); N];
    }

    fn reset(&mut self) {
        self.epoch_micros = None;
        self.cursors = [ScanCursor::default(); N];
    }

    fn apply_outcome(&mut self, outcome: ScanOutcome) {
        if outcome != ScanOutcome::Progress {
            self.reset();
        }
    }
}

async fn current_scan_epoch<const N: usize>(
    pool: &PgPool,
    scan: &mut EpochScan<N>,
) -> Result<i64, sqlx::Error> {
    if let Some(epoch) = scan.epoch_micros {
        return Ok(epoch);
    }
    let next = db::reconciler_scan_epoch_micros(pool).await?;
    scan.begin(next);
    Ok(next)
}

fn report_epoch_outcome<const N: usize>(
    outcome: ScanOutcome,
    scan: &mut EpochScan<N>,
    reporter: &WorkerReporter,
) {
    match outcome {
        ScanOutcome::Progress => reporter.progress(),
        ScanOutcome::Succeeded => reporter.cycle_succeeded(),
        ScanOutcome::Failed => reporter.cycle_failed(),
        ScanOutcome::Cancelled => {}
    }
    scan.apply_outcome(outcome);
}

/// Spawn the reconciler background task. One task per process.
pub fn spawn(
    pool: PgPool,
    boltz_api_url: String,
    config: Arc<ReconcilerConfig>,
    cancel: CancellationToken,
    mut reporter: WorkerReporter,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Bounded timeout: a hung get_swap must not freeze the reconciler loop
        // (the only recovery for dropped webhooks / the only chain-swap poll
        // driver). Without it, one black-holed Boltz call permanently disables
        // recovery and in-flight swaps stay stuck.
        let client = BoltzApiClientV2::new(boltz_api_url, Some(Duration::from_secs(10)));
        let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs));
        let mut scan = EpochScan::<1>::default();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    reporter.intentional_shutdown();
                    tracing::info!("reconciler: shutting down");
                    return;
                }
                _ = tick.tick() => {
                    let scan_epoch = match current_scan_epoch(&pool, &mut scan).await {
                        Ok(epoch) => epoch,
                        Err(e) => {
                            scan.reset();
                            reporter.cycle_failed();
                            tracing::error!("reconciler epoch acquisition failed: {e}");
                            continue;
                        }
                    };
                    match run_one_tick(
                        &pool,
                        &client,
                        &config,
                        &cancel,
                        &reporter,
                        scan_epoch,
                        &mut scan.cursors[0],
                    ).await {
                        Ok(ScanOutcome::Cancelled) => {
                            scan.reset();
                            reporter.intentional_shutdown();
                            tracing::info!("reconciler: cancellation requested mid-page; shutting down");
                            return;
                        }
                        Ok(outcome) => {
                            if outcome == ScanOutcome::Failed {
                                tracing::warn!("reconciler page completed with systemic failures");
                            }
                            report_epoch_outcome(outcome, &mut scan, &reporter);
                        }
                        Err(e) => {
                            scan.reset();
                            reporter.cycle_failed();
                            tracing::error!("reconciler tick failed: {e}");
                        }
                    }
                }
            }
        }
    })
}

/// Chain-swap reconciler. The reverse `spawn` above only touches `swap_records`;
/// chain swaps have no other polling recovery, so a dropped Boltz webhook during
/// `pending`/`user_lock_*`/`server_lock_*` would strand the swap forever. This
/// polls Boltz `get_swap` for every non-terminal chain swap and re-drives it
/// through the same handler a webhook would (`claimer::handle_chain_swap_webhook`),
/// which is idempotent. Needs `AppState` because claiming a chain swap requires
/// electrum/boltz endpoints, the utxo backend, and accounting tolerances.
pub fn spawn_chain(
    state: AppState,
    config: Arc<ReconcilerConfig>,
    cancel: CancellationToken,
    mut reporter: WorkerReporter,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Bounded timeout (see spawn() above): a hung chain get_swap must not
        // freeze the chain reconciler loop.
        let client = BoltzApiClientV2::new(
            state.config.boltz.api_url.clone(),
            Some(Duration::from_secs(10)),
        );
        let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs));
        let mut scan = EpochScan::<2>::default();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    reporter.intentional_shutdown();
                    tracing::info!("chain reconciler: shutting down");
                    return;
                }
                _ = tick.tick() => {
                    let scan_epoch = match current_scan_epoch(&state.db, &mut scan).await {
                        Ok(epoch) => epoch,
                        Err(e) => {
                            scan.reset();
                            reporter.cycle_failed();
                            tracing::error!("chain reconciler epoch acquisition failed: {e}");
                            continue;
                        }
                    };
                    match run_one_chain_tick(
                        &state,
                        &client,
                        &config,
                        &cancel,
                        &reporter,
                        scan_epoch,
                        &mut scan.cursors,
                    ).await {
                        Ok(ScanOutcome::Cancelled) => {
                            scan.reset();
                            reporter.intentional_shutdown();
                            tracing::info!("chain reconciler: cancellation requested mid-page; shutting down");
                            return;
                        }
                        Ok(outcome) => {
                            if outcome == ScanOutcome::Failed {
                                tracing::warn!("chain reconciler page completed with systemic failures");
                            }
                            report_epoch_outcome(outcome, &mut scan, &reporter);
                        }
                        Err(e) => {
                            scan.reset();
                            reporter.cycle_failed();
                            tracing::error!("chain reconciler tick failed: {e}");
                        }
                    }
                }
            }
        }
    })
}

/// Settlement-repair task. Re-records invoice payment events for reverse
/// (Lightning) swaps that reached `claimed` — merchant funds are on chain —
/// but whose invoice flip never completed: the process died, or
/// `record_invoice_payment` transiently failed, between committing the
/// `claimed` status (`claimer.rs`) and running
/// `flip_invoice_on_lightning_settlement` (whose error is logged and reflected
/// in this worker's cycle health). Without this the merchant is paid while the
/// invoice shows unpaid, and the reconciler never revisits terminal `claimed`
/// rows. The flip is idempotent (dedup by event_key), so re-running is a safe
/// no-op once the event exists.
pub fn spawn_settlement_repair(
    state: AppState,
    config: Arc<ReconcilerConfig>,
    cancel: CancellationToken,
    mut reporter: WorkerReporter,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs));
        let mut scan = EpochScan::<2>::default();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    reporter.intentional_shutdown();
                    tracing::info!("settlement repair: shutting down");
                    return;
                }
                _ = tick.tick() => {
                    let scan_epoch = match current_scan_epoch(&state.db, &mut scan).await {
                        Ok(epoch) => epoch,
                        Err(e) => {
                            scan.reset();
                            reporter.cycle_failed();
                            tracing::error!("settlement repair epoch acquisition failed: {e}");
                            continue;
                        }
                    };
                    match run_settlement_repair_tick(
                        &state,
                        &config,
                        &cancel,
                        &reporter,
                        scan_epoch,
                        &mut scan.cursors,
                    ).await {
                        Ok(ScanOutcome::Cancelled) => {
                            scan.reset();
                            reporter.intentional_shutdown();
                            tracing::info!("settlement repair: cancellation requested mid-page; shutting down");
                            return;
                        }
                        Ok(outcome) => {
                            if outcome == ScanOutcome::Failed {
                                tracing::warn!("settlement repair page completed with write failures");
                            }
                            report_epoch_outcome(outcome, &mut scan, &reporter);
                        }
                        Err(e) => {
                            scan.reset();
                            reporter.cycle_failed();
                            tracing::error!("settlement repair tick failed: {e}");
                        }
                    }
                }
            }
        }
    })
}

/// Slow-recovery task (issue #63). Funded swaps that exhaust the fast claim
/// retry budget land in `claim_stuck`, which every claim-sweep query excludes —
/// so a claimable output stranded by a transient outage (backend down, fee
/// mismatch, cooperative claim unavailable, deploy bug) would be abandoned even
/// after health returns. This revives such rows back into the normal claim
/// sweep on a long, persisted, capped backoff. It does NOT claim or probe the
/// chain itself — it hands the row to the battle-tested claim path (which does
/// the cooperative→script fallback and outspend-probe recovery on an
/// already-spent lockup). Runs at a much slower cadence than the main
/// reconciler and is bounded per tick, so it can never starve normal claiming
/// or hot-loop.
pub fn spawn_slow_recovery(
    state: AppState,
    config: Arc<ReconcilerConfig>,
    cancel: CancellationToken,
    mut reporter: WorkerReporter,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(Duration::from_secs(config.slow_recovery_interval_secs));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    reporter.intentional_shutdown();
                    tracing::info!("slow recovery: shutting down");
                    return;
                }
                _ = tick.tick() => {
                    match run_slow_recovery_tick(&state, &config, &cancel, &reporter).await {
                        Ok(ScanOutcome::Progress) => reporter.progress(),
                        Ok(ScanOutcome::Succeeded) => reporter.cycle_succeeded(),
                        Ok(ScanOutcome::Failed) => {
                            reporter.cycle_failed();
                            tracing::warn!("slow recovery page cannot run with a zero row cap");
                        }
                        Ok(ScanOutcome::Cancelled) => {
                            reporter.intentional_shutdown();
                            tracing::info!("slow recovery: cancellation requested mid-page; shutting down");
                            return;
                        }
                        Err(e) => {
                            reporter.cycle_failed();
                            tracing::error!("slow recovery tick failed: {e}");
                        }
                    }
                }
            }
        }
    })
}

/// Next slow-recovery backoff: `base * 2^slow_attempts`, capped, saturating.
/// Pure so it is unit-tested without a DB.
fn slow_recovery_backoff_secs(slow_attempts: i32, base_secs: u64, cap_secs: u64) -> u64 {
    let exp = slow_attempts.clamp(0, 16) as u32;
    base_secs
        .saturating_mul(2u64.saturating_pow(exp))
        .min(cap_secs)
}

async fn run_slow_recovery_tick(
    state: &AppState,
    config: &ReconcilerConfig,
    cancel: &CancellationToken,
    reporter: &WorkerReporter,
) -> Result<ScanOutcome, sqlx::Error> {
    let limit = config.slow_recovery_max_per_tick;
    if limit == 0 {
        return Ok(ScanOutcome::Failed);
    }
    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    let max_attempts = state.config.claim.max_claim_attempts;
    let base = config.slow_recovery_backoff_base_secs;
    let cap = config.slow_recovery_backoff_cap_secs;
    let fetch_limit = sentinel_limit(limit);

    // Reverse rail.
    let reverse = db::list_claim_stuck_swaps_for_slow_retry(&state.db, fetch_limit).await?;
    let reverse_fetched = reverse.len();
    for (id, boltz_swap_id, slow_attempts) in reverse.into_iter().take(limit as usize) {
        if cancel.is_cancelled() {
            return Ok(ScanOutcome::Cancelled);
        }
        reporter.progress();
        let backoff = slow_recovery_backoff_secs(slow_attempts, base, cap);
        let revived =
            db::revive_claim_stuck_swap_for_slow_retry(&state.db, id, max_attempts, backoff)
                .await?;
        if revived == 1 {
            tracing::warn!(
                event = "slow_recovery_revived",
                rail = "lightning_boltz_reverse",
                swap_id = %boltz_swap_id,
                slow_attempt = slow_attempts + 1,
                "reviving funded claim_stuck reverse swap into the claim sweep"
            );
        }
    }
    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }

    // Chain rail.
    let chain = db::list_claim_stuck_chain_swaps_for_slow_retry(&state.db, fetch_limit).await?;
    let chain_fetched = chain.len();
    for (id, boltz_swap_id, slow_attempts) in chain.into_iter().take(limit as usize) {
        if cancel.is_cancelled() {
            return Ok(ScanOutcome::Cancelled);
        }
        reporter.progress();
        let backoff = slow_recovery_backoff_secs(slow_attempts, base, cap);
        let revived =
            db::revive_claim_stuck_chain_swap_for_slow_retry(&state.db, id, max_attempts, backoff)
                .await?;
        if revived == 1 {
            tracing::warn!(
                event = "slow_recovery_revived",
                rail = "bitcoin_boltz_chain",
                swap_id = %boltz_swap_id,
                slow_attempt = slow_attempts + 1,
                "reviving funded claim_stuck chain swap into the claim sweep"
            );
        }
    }
    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    Ok(scan_outcome(limit, reverse_fetched, true).merge(scan_outcome(limit, chain_fetched, true)))
}

async fn run_settlement_repair_tick(
    state: &AppState,
    config: &ReconcilerConfig,
    cancel: &CancellationToken,
    reporter: &WorkerReporter,
    epoch_micros: i64,
    cursors: &mut [ScanCursor; 2],
) -> Result<ScanOutcome, sqlx::Error> {
    // Only recently-claimed rows: a stuck flip is repaired within a tick or
    // two, after which the event exists and the row drops out of the query.
    // The window covers the maximum invoice lifetime.
    const REPAIR_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;
    let tolerances = db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting);
    let mut health = CycleHealth::default();
    let limit = config.max_per_tick;
    if limit == 0 {
        return Ok(ScanOutcome::Failed);
    }
    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    let fetch_limit = sentinel_limit(limit);

    // --- Lightning (reverse) rail ---
    let reverse_outcome = if cursors[0].drained {
        ScanOutcome::Succeeded
    } else {
        let mut stuck = db::list_claimed_swaps_missing_lightning_event(
            &state.db,
            REPAIR_MAX_AGE_SECS,
            epoch_micros,
            cursors[0].after_id,
            fetch_limit,
        )
        .await?;
        if cancel.is_cancelled() {
            return Ok(ScanOutcome::Cancelled);
        }
        let fetched = stuck.len();
        stuck.truncate(limit as usize);
        for swap in &stuck {
            if cancel.is_cancelled() {
                return Ok(ScanOutcome::Cancelled);
            }
            reporter.progress();
            let (Some(invoice_id), Some(claim_txid)) =
                (swap.invoice_id, swap.claim_txid.as_deref())
            else {
                cursors[0].visit(swap.id);
                continue;
            };
            tracing::warn!(
                event = "settlement_repair",
                rail = "lightning_boltz_reverse",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %invoice_id,
                "re-recording missing invoice payment event for a claimed Lightning swap"
            );
            let write_succeeded = crate::invoice::flip_invoice_on_lightning_settlement(
                &state.db,
                Some(invoice_id),
                swap.amount_sat,
                &swap.boltz_swap_id,
                claim_txid,
                tolerances,
            )
            .await;
            health.settlement_write(write_succeeded);
            cursors[0].visit(swap.id);
        }
        if cancel.is_cancelled() {
            return Ok(ScanOutcome::Cancelled);
        }
        cursors[0].finish_page(limit, fetched, true)
    };

    // --- Bitcoin (chain) rail (issue #61) ---
    // Same crash-consistency gap: a chain swap can reach terminal `claimed`
    // (merchant L-BTC on chain) without its `bitcoin_boltz_chain` payment event.
    // Reuse the same idempotent event key and the same settlement flip, so a
    // repaired invoice lands in the identical state as an uninterrupted claim,
    // and a replay is a no-op (ON CONFLICT on the UNIQUE event_key).
    let chain_outcome = if cursors[1].drained {
        ScanOutcome::Succeeded
    } else {
        let mut chain_stuck = db::list_claimed_chain_swaps_missing_payment_event(
            &state.db,
            REPAIR_MAX_AGE_SECS,
            epoch_micros,
            cursors[1].after_id,
            fetch_limit,
        )
        .await?;
        if cancel.is_cancelled() {
            return Ok(ScanOutcome::Cancelled);
        }
        let fetched = chain_stuck.len();
        chain_stuck.truncate(limit as usize);
        for swap in &chain_stuck {
            if cancel.is_cancelled() {
                return Ok(ScanOutcome::Cancelled);
            }
            reporter.progress();
            // The query requires a persisted claim txid; a terminal status alone is
            // never fabricated into a payment. Guard defensively and alert instead.
            let Some(claim_txid) = swap.claim_txid.as_deref() else {
                tracing::error!(
                    event = "settlement_repair_irreconcilable",
                    swap_id = %swap.boltz_swap_id,
                    invoice_id = %swap.invoice_id,
                    "claimed chain swap missing claim_txid; not fabricating a payment"
                );
                cursors[1].visit(swap.id);
                continue;
            };
            tracing::warn!(
                event = "settlement_repair",
                rail = "bitcoin_boltz_chain",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                "re-recording missing invoice payment event for a claimed chain swap"
            );
            let write_succeeded = crate::invoice::flip_invoice_on_bitcoin_boltz_settlement(
                &state.db,
                Some(swap.invoice_id),
                swap.effective_server_lock_amount_sat(),
                &swap.boltz_swap_id,
                claim_txid,
                tolerances,
            )
            .await;
            health.settlement_write(write_succeeded);
            cursors[1].visit(swap.id);
        }
        if cancel.is_cancelled() {
            return Ok(ScanOutcome::Cancelled);
        }
        cursors[1].finish_page(limit, fetched, true)
    };
    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    if !health.is_healthy() {
        return Ok(ScanOutcome::Failed);
    }
    Ok(reverse_outcome.merge(chain_outcome))
}

async fn run_one_chain_tick(
    state: &AppState,
    client: &BoltzApiClientV2,
    config: &ReconcilerConfig,
    cancel: &CancellationToken,
    reporter: &WorkerReporter,
    epoch_micros: i64,
    cursors: &mut [ScanCursor; 2],
) -> Result<ScanOutcome, sqlx::Error> {
    let limit = config.max_per_tick;
    if limit == 0 {
        return Ok(ScanOutcome::Failed);
    }
    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    let fetch_limit = sentinel_limit(limit);
    let mut health = CycleHealth::default();
    // Write-ahead recovery backstop: a dropped request or process restart can
    // leave a committed attempt in `refunding`.  Never reset it to
    // `refund_due` (that used to authorize reconstruction after an ambiguous
    // broadcast). Re-enter the journal executor, which probes chain evidence
    // and replays only the exact committed bytes. The age floor keeps an active
    // request from racing this worker.
    let refunding_stale_secs = (config.min_age_secs as i64).saturating_mul(10).max(600);
    let mut recovery_scan_error = None;
    let recovery_outcome = if cursors[0].drained {
        ScanOutcome::Succeeded
    } else {
        match db::list_stale_refunding_chain_swaps(
            &state.db,
            refunding_stale_secs,
            epoch_micros,
            cursors[0].after_id,
            fetch_limit,
        )
        .await
        {
            Ok(mut recoveries) => {
                if cancel.is_cancelled() {
                    return Ok(ScanOutcome::Cancelled);
                }
                let fetched = recoveries.len();
                recoveries.truncate(limit as usize);
                for swap in recoveries {
                    if cancel.is_cancelled() {
                        return Ok(ScanOutcome::Cancelled);
                    }
                    reporter.progress();
                    match crate::claimer::execute_chain_swap_refund(state, &swap).await {
                        Ok(txid) => tracing::warn!(
                            event = "chain_swap_recovery_resumed",
                            swap_id = %swap.boltz_swap_id,
                            recovery_txid = %txid,
                            "stale journaled Bitcoin recovery reconciled"
                        ),
                        Err(error) => {
                            health.observe_app_error(&error);
                            tracing::warn!(
                                event = "chain_swap_recovery_resume_deferred",
                                swap_id = %swap.boltz_swap_id,
                                error = %error,
                                "stale journaled Bitcoin recovery remains pending"
                            );
                        }
                    }
                    cursors[0].visit(swap.id);
                }
                if cancel.is_cancelled() {
                    return Ok(ScanOutcome::Cancelled);
                }
                cursors[0].finish_page(limit, fetched, true)
            }
            Err(e) => {
                tracing::warn!("chain reconciler: list stale refunding failed: {e}");
                // Keep running the ordinary reconciliation scan, but fail the
                // worker cycle: a skipped recovery scan must not open admission.
                recovery_scan_error = Some(e);
                ScanOutcome::Failed
            }
        }
    };

    // `refunding` rows are deliberately excluded from this ordinary subset:
    // the stale-recovery cursor above owns them independently under the same
    // frozen process-local epoch.
    let ordinary_outcome = if cursors[1].drained {
        ScanOutcome::Succeeded
    } else {
        let mut stale = db::list_non_terminal_chain_swaps_oldest_first(
            &state.db,
            config.min_age_secs,
            epoch_micros,
            cursors[1].after_id,
            fetch_limit,
        )
        .await?;
        if cancel.is_cancelled() {
            return Ok(ScanOutcome::Cancelled);
        }
        let fetched = stale.len();
        stale.truncate(limit as usize);

        if stale.is_empty() {
            tracing::debug!("chain reconciler: no stale ordinary chain swaps");
        } else {
            tracing::info!(
                "chain reconciler: scanning {} stale chain swap(s)",
                stale.len()
            );
        }

        for swap in &stale {
            if cancel.is_cancelled() {
                return Ok(ScanOutcome::Cancelled);
            }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(ScanOutcome::Cancelled),
                _ = tokio::time::sleep(Duration::from_millis(config.inter_call_delay_ms)) => {}
            }
            reporter.progress();

            let remote = match client.get_swap(&swap.boltz_swap_id).await {
                Ok(r) => {
                    health.provider_succeeded();
                    r
                }
                Err(e) => {
                    health.provider_error(&e);
                    tracing::warn!(
                        "chain reconciler: get_swap({}) failed: {e}",
                        swap.boltz_swap_id
                    );
                    cursors[1].visit(swap.id);
                    continue;
                }
            };

            // Re-drive through the idempotent webhook handler with Boltz's current
            // view — exactly what a delivered webhook would have done.
            if let Err(e) =
                crate::claimer::handle_chain_swap_webhook(state, swap, &remote.status).await
            {
                health.observe_app_error(&e);
                tracing::error!(
                    "chain reconciler: handle failed for {}: {e}",
                    swap.boltz_swap_id
                );
            }
            cursors[1].visit(swap.id);
        }
        if cancel.is_cancelled() {
            return Ok(ScanOutcome::Cancelled);
        }
        cursors[1].finish_page(limit, fetched, true)
    };

    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    if let Some(error) = recovery_scan_error {
        return Err(error);
    }
    if !health.is_healthy() {
        return Ok(ScanOutcome::Failed);
    }
    Ok(recovery_outcome.merge(ordinary_outcome))
}

async fn run_one_tick(
    pool: &PgPool,
    client: &BoltzApiClientV2,
    config: &ReconcilerConfig,
    cancel: &CancellationToken,
    reporter: &WorkerReporter,
    epoch_micros: i64,
    cursor: &mut ScanCursor,
) -> Result<ScanOutcome, sqlx::Error> {
    let limit = config.max_per_tick;
    if limit == 0 {
        return Ok(ScanOutcome::Failed);
    }
    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    let mut health = CycleHealth::default();
    let mut stale = db::list_non_terminal_swaps_oldest_first(
        pool,
        config.min_age_secs,
        epoch_micros,
        cursor.after_id,
        sentinel_limit(limit),
    )
    .await?;
    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    let fetched = stale.len();
    stale.truncate(limit as usize);

    if stale.is_empty() {
        tracing::debug!("reconciler: no stale swaps");
        return Ok(cursor.finish_page(limit, fetched, true));
    }

    tracing::info!("reconciler: scanning {} stale swap(s)", stale.len());

    for swap in &stale {
        // Cooperative cancellation: at default config a single tick can
        // take ~50s (200 swaps × 250ms each); without this, SIGTERM has
        // to wait for the tick to complete. Never advance past the unvisited
        // row when cancellation wins.
        if cancel.is_cancelled() {
            return Ok(ScanOutcome::Cancelled);
        }
        // Defensive throttle. With max_per_tick=200 and 50ms delay,
        // peak Boltz API RPM is ~133 — well below any reasonable rate
        // limit. Yields between calls to keep the runtime responsive.
        tokio::select! {
            _ = cancel.cancelled() => return Ok(ScanOutcome::Cancelled),
            _ = tokio::time::sleep(Duration::from_millis(config.inter_call_delay_ms)) => {}
        }
        reporter.progress();

        let remote = match client.get_swap(&swap.boltz_swap_id).await {
            Ok(r) => {
                health.provider_succeeded();
                r
            }
            Err(e) => {
                health.provider_error(&e);
                tracing::warn!("reconciler: get_swap({}) failed: {e}", swap.boltz_swap_id);
                cursor.visit(swap.id);
                continue;
            }
        };

        let action = decide_action(swap, &remote.status);
        if let Err(e) = apply_action(pool, swap, action).await {
            health.systemic_failure = true;
            tracing::error!(
                "reconciler: apply failed for swap {}: {e}",
                swap.boltz_swap_id
            );
        }
        cursor.visit(swap.id);
    }

    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    if !health.is_healthy() {
        Ok(ScanOutcome::Failed)
    } else {
        Ok(cursor.finish_page(limit, fetched, true))
    }
}

/// Decision matrix: (Boltz status × our status) → ReconcilerAction.
///
/// Centralized + pure so it's unit-testable without a DB or HTTP
/// client. The caller (`apply_action`) does the actual writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcilerAction {
    /// Views agree; nothing to do.
    Noop,
    /// Boltz says lockup is in mempool; advance our row.
    AdvanceToLockupMempool,
    /// Boltz says lockup is confirmed; advance our row.
    AdvanceToLockupConfirmed,
    /// Boltz says the lockup is on-chain and our row is in some
    /// claimable state; nudge `next_claim_attempt_at` so the sweep
    /// picks it up immediately. Status not changed.
    ScheduleImmediateClaim,
    /// Boltz emitted `swap.expired`. Flip `cooperative_refused` and
    /// schedule an immediate retry so the sweep takes the script path.
    /// Status NOT changed — the on-chain HTLC is still claimable until
    /// `timeoutBlockHeight`.
    ScheduleScriptPathRetry,
    /// Boltz says the LN side is dead (`invoice.expired` /
    /// `transaction.failed`). Terminal `expired`. User is safe — they
    /// never paid the LN invoice or Boltz never funded the lockup.
    MarkExpired,
    /// Boltz says the lockup was refunded. Terminal `lockup_refunded`.
    /// FUND LOSS. P0 alert.
    MarkLockupRefunded,
    /// Boltz says invoice settled but our row is not Claimed. Either
    /// our broadcast landed but we lost the response, or someone else
    /// claimed. The reconciler logs loudly and leaves manual rescue to
    /// disambiguate.
    NeedsManualAttention(&'static str),
}

pub(crate) fn decide_action(swap: &ReconcilerSwap, boltz_status: &str) -> ReconcilerAction {
    use ReconcilerAction::*;

    let our_terminal = matches!(
        swap.status.as_str(),
        "claimed" | "expired" | "claim_stuck" | "lockup_refunded"
    );
    if our_terminal {
        // Reconciler scan filters terminal rows out, but be defensive:
        // a row that became terminal between SELECT and this dispatch
        // should never be touched again.
        return Noop;
    }

    match (boltz_status, swap.status.as_str()) {
        // Boltz still in pre-funding. Wait.
        ("swap.created", _) => Noop,

        // Boltz says the lockup is on-chain.
        ("transaction.mempool", "pending") => AdvanceToLockupMempool,
        ("transaction.confirmed", "pending") => AdvanceToLockupConfirmed,
        ("transaction.confirmed", "lockup_mempool") => AdvanceToLockupConfirmed,
        ("transaction.mempool" | "transaction.confirmed", _) => ScheduleImmediateClaim,

        // Wall-clock invoice timer expired but the on-chain HTLC is
        // still claimable until `timeoutBlockHeight`. Cooperative is
        // now refused — script-path is the only recovery.
        ("swap.expired", _) => ScheduleScriptPathRetry,

        // LN side died without us doing anything wrong.
        ("invoice.expired" | "transaction.failed", _) => MarkExpired,

        // Boltz refunded the lockup. We're past the on-chain claim
        // window; the user paid LN and got nothing back.
        ("transaction.refunded", _) => MarkLockupRefunded,

        // Boltz says invoice settled. That means the claim API received
        // our preimage, but Boltz does not track whether our claim tx was
        // broadcast. If our row is not Claimed yet, nudge the claimer; it
        // owns the advisory lock and the lockup-outspend recovery probe.
        ("invoice.settled", "claimed") => Noop,
        ("invoice.settled", _) => ScheduleImmediateClaim,

        // `minerfee.paid` and any future Boltz-side states are
        // informational; debug-log and move on.
        _ => Noop,
    }
}

async fn apply_action(
    pool: &PgPool,
    swap: &ReconcilerSwap,
    action: ReconcilerAction,
) -> Result<(), sqlx::Error> {
    use ReconcilerAction::*;
    match action {
        Noop => Ok(()),
        AdvanceToLockupMempool => {
            tracing::info!(
                event = "reconciler_advance",
                swap_id = %swap.boltz_swap_id,
                from = %swap.status,
                to = "lockup_mempool",
                "reconciler advancing status (webhook missed)"
            );
            db::update_swap_status(pool, swap.id, SwapStatus::LockupMempool, None).await?;
            db::schedule_immediate_claim(pool, swap.id).await?;
            // Mempool sighting advances the checkout invoice to
            // `in_progress`. The matching webhook arm uses the same helper.
            invoice::flip_invoice_on_lightning_in_progress(
                pool,
                swap.invoice_id,
                &swap.boltz_swap_id,
            )
            .await;
            Ok(())
        }
        AdvanceToLockupConfirmed => {
            tracing::info!(
                event = "reconciler_advance",
                swap_id = %swap.boltz_swap_id,
                from = %swap.status,
                to = "lockup_confirmed",
                "reconciler advancing status (webhook missed)"
            );
            db::update_swap_status(pool, swap.id, SwapStatus::LockupConfirmed, None).await?;
            db::schedule_immediate_claim(pool, swap.id).await?;
            // Confirmed lockup is still settlement-pending. The claimer
            // records accounting only after our claim succeeds.
            invoice::flip_invoice_on_lightning_in_progress(
                pool,
                swap.invoice_id,
                &swap.boltz_swap_id,
            )
            .await;
            Ok(())
        }
        ScheduleImmediateClaim => {
            // If we never saw a lockup webhook the row is still `pending`, but
            // `get_ready_to_claim_swaps` only sweeps `lockup_mempool`/
            // `lockup_confirmed`/`claiming`/`claim_failed` — scheduling a claim
            // on a `pending` row is a silent no-op that recurs every tick while
            // the (still-claimable) HTLC is abandoned. Advance to
            // `lockup_confirmed` first so the sweep actually picks it up, the
            // same way the mempool/confirmed arms do.
            if swap.status == "pending" {
                db::update_swap_status(pool, swap.id, SwapStatus::LockupConfirmed, None).await?;
            }
            tracing::debug!(
                event = "reconciler_schedule_claim",
                swap_id = %swap.boltz_swap_id,
                "reconciler scheduling immediate claim retry"
            );
            db::schedule_immediate_claim(pool, swap.id).await?;
            Ok(())
        }
        ScheduleScriptPathRetry => {
            // Same `pending` no-op guard as ScheduleImmediateClaim: a swap that
            // reached `swap.expired` while still locally `pending` is excluded
            // by the sweep, so the script-path retry would never run.
            if swap.status == "pending" {
                db::update_swap_status(pool, swap.id, SwapStatus::LockupConfirmed, None).await?;
            }
            tracing::warn!(
                event = "reconciler_swap_expired",
                swap_id = %swap.boltz_swap_id,
                "boltz reports swap.expired; flipping cooperative_refused for script-path retry"
            );
            db::schedule_script_path_retry(pool, swap.id).await?;
            Ok(())
        }
        MarkExpired => {
            tracing::info!(
                event = "reconciler_expired",
                swap_id = %swap.boltz_swap_id,
                "boltz reports LN side dead; marking expired"
            );
            db::update_swap_status(pool, swap.id, SwapStatus::Expired, None).await?;
            Ok(())
        }
        MarkLockupRefunded => {
            tracing::error!(
                event = "swap_lockup_refunded",
                swap_id = %swap.boltz_swap_id,
                nym = %swap.nym.as_deref().unwrap_or("<invoice-only>"),
                amount_sat = swap.amount_sat,
                "FUND LOSS: boltz refunded lockup; user paid LN side, no on-chain claim"
            );
            db::update_swap_status(pool, swap.id, SwapStatus::LockupRefunded, None).await?;
            db::mark_invoice_settlement_status(pool, swap.invoice_id, "refunded").await?;
            // Do not record an invoice payment event. A refunded lockup
            // is an incident, not merchant-side settlement.
            Ok(())
        }
        NeedsManualAttention(reason) => {
            tracing::error!(
                event = "reconciler_needs_attention",
                swap_id = %swap.boltz_swap_id,
                nym = %swap.nym.as_deref().unwrap_or("<invoice-only>"),
                our_status = %swap.status,
                reason,
                "reconciler cannot progress this swap; manual intervention required"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;

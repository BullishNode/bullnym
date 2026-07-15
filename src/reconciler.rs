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
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use crate::{
    admission::WorkerReporter,
    chain_swap_action::{
        recheck_recovery_under_lock, reduce_chain_swap_evidence, ChainSwapAction,
        ChainSwapEvidence, MerchantTransactionEvidence, RecoveryExecutionGate,
    },
    config::ReconcilerConfig,
    db::{self, ChainSwapRecord, ChainSwapStatus, ReconcilerSwap, SwapStatus},
    error::AppError,
    invoice,
    merchant_output_verifier::{
        observe_bitcoin_merchant_output_journal, observe_liquid_merchant_output,
        BitcoinMerchantObservationError, LinkedReplacementJournalEvidence,
        LiquidMerchantObservationError, MerchantOutputCommitment, MerchantSourcePrevout,
        MerchantTransactionJournalEvidence, PreviousBitcoinMerchantConfirmation,
        PreviousLiquidMerchantConfirmation,
    },
    merchant_settlement_adoption::{MerchantSettlementContext, MerchantSettlementPath},
    merchant_settlement_lifecycle::{
        MerchantSettlementLifecycle, SettlementAccountingState, SettlementChain,
        SettlementFinalityPolicy,
    },
    merchant_settlement_service::{
        MerchantSettlementPersistenceCommand, MerchantSettlementProcessingError,
        MerchantSettlementProcessingOutcome,
    },
    AppState,
};

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
    boltz: Arc<crate::boltz::BoltzService>,
    config: Arc<ReconcilerConfig>,
    cancel: CancellationToken,
    mut reporter: WorkerReporter,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
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
                        boltz.as_ref(),
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

/// Runtime action exposed to the future lifecycle repository worker. Only
/// chain observation/finality and the already-established under-lock recovery
/// gate can produce an executable action; every other reducer result is
/// retained explicitly as blocked work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapSettlementRuntimeAction {
    WatchTransaction,
    Finalize,
    RecoverBitcoin,
    Blocked(ChainSwapAction),
}

/// One coherent runtime boundary: current source/lock/action evidence plus the
/// exact verified merchant-output amount retained by the settlement repository.
/// Requested, quoted, and provider amounts do not belong here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoredSettlementRuntimeInput {
    pub chain_evidence: ChainSwapEvidence,
    pub verified_actual_amount_sat: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSwapSettlementRuntimeDecision {
    pub action: ChainSwapSettlementRuntimeAction,
    /// Present from the first independently verified confirmation onward, but
    /// only when the coherent reducer result still authorizes watching or
    /// finalization. This is intentionally independent of finality.
    pub accounting_eligible_actual_amount_sat: Option<u64>,
}

/// Compose a policy-validated restored settlement lifecycle with a fresh
/// per-swap source/lock evidence boundary. The lifecycle is authoritative for
/// its merchant transaction slot; conflicting persisted transaction evidence
/// fails closed. Bitcoin recovery is returned only through the shared
/// under-lock execution gate. A recovery executor must call this at its
/// per-swap execution-lock boundary; a pre-lock call is planning evidence only
/// and never authorizes broadcast.
pub fn decide_restored_chain_swap_settlement(
    chain_swap: &ChainSwapRecord,
    lifecycle: &MerchantSettlementLifecycle,
    input: RestoredSettlementRuntimeInput,
) -> ChainSwapSettlementRuntimeDecision {
    let status = match chain_swap.parsed_status() {
        Ok(status) => status,
        Err(_) => return blocked_settlement_decision(ChainSwapAction::IntegrityHold),
    };
    if chain_swap.from_chain != "BTC"
        || chain_swap.to_chain != "L-BTC"
        || chain_swap.user_lock_amount_sat <= 0
        || chain_swap.effective_server_lock_amount_sat() <= 0
        || !record_matches_settlement_path(chain_swap, status, lifecycle)
    {
        return blocked_settlement_decision(ChainSwapAction::IntegrityHold);
    }

    let mapped = MerchantTransactionEvidence::from_settlement_lifecycle(lifecycle);
    let mut evidence = input.chain_evidence;
    let transaction_slot = match lifecycle.chain() {
        SettlementChain::Liquid => &mut evidence.liquid_claim_transaction,
        SettlementChain::Bitcoin => &mut evidence.bitcoin_recovery_transaction,
    };
    if !matches!(*transaction_slot, MerchantTransactionEvidence::None)
        && *transaction_slot != mapped
    {
        return blocked_settlement_decision(ChainSwapAction::IntegrityHold);
    }
    *transaction_slot = mapped;

    let reduced = reduce_chain_swap_evidence(&evidence);
    let recovery_gate = recheck_recovery_under_lock(&evidence);
    let action = match reduced {
        ChainSwapAction::WatchTransaction => ChainSwapSettlementRuntimeAction::WatchTransaction,
        ChainSwapAction::Finalize => ChainSwapSettlementRuntimeAction::Finalize,
        ChainSwapAction::RecoverBitcoin => match recovery_gate {
            RecoveryExecutionGate::Authorized => ChainSwapSettlementRuntimeAction::RecoverBitcoin,
            RecoveryExecutionGate::Blocked(action) => {
                ChainSwapSettlementRuntimeAction::Blocked(action)
            }
        },
        _ => match recovery_gate {
            RecoveryExecutionGate::Blocked(action) => {
                ChainSwapSettlementRuntimeAction::Blocked(action)
            }
            RecoveryExecutionGate::Authorized => {
                ChainSwapSettlementRuntimeAction::Blocked(ChainSwapAction::IntegrityHold)
            }
        },
    };
    if matches!(action, ChainSwapSettlementRuntimeAction::RecoverBitcoin)
        && status != ChainSwapStatus::Refunding
    {
        return blocked_settlement_decision(ChainSwapAction::IntegrityHold);
    }

    let accounting_eligible = matches!(
        lifecycle.accounting_state(),
        SettlementAccountingState::Confirmed | SettlementAccountingState::Finalized
    );
    let executable_settlement = matches!(
        action,
        ChainSwapSettlementRuntimeAction::WatchTransaction
            | ChainSwapSettlementRuntimeAction::Finalize
    );
    let accounting_eligible_actual_amount_sat = if accounting_eligible && executable_settlement {
        match input
            .verified_actual_amount_sat
            .and_then(|amount| u64::try_from(amount).ok())
            .filter(|amount| *amount > 0)
        {
            Some(amount) => Some(amount),
            None => return blocked_settlement_decision(ChainSwapAction::IntegrityHold),
        }
    } else {
        None
    };

    ChainSwapSettlementRuntimeDecision {
        action,
        accounting_eligible_actual_amount_sat,
    }
}

fn record_matches_settlement_path(
    chain_swap: &ChainSwapRecord,
    status: ChainSwapStatus,
    lifecycle: &MerchantSettlementLifecycle,
) -> bool {
    let txid_matches =
        |candidate: &str| candidate.eq_ignore_ascii_case(lifecycle.active_txid().as_str());
    match lifecycle.chain() {
        SettlementChain::Liquid => {
            matches!(
                status,
                ChainSwapStatus::ServerLockMempool
                    | ChainSwapStatus::ServerLockConfirmed
                    | ChainSwapStatus::Claiming
                    | ChainSwapStatus::Claimed
                    | ChainSwapStatus::ClaimFailed
                    | ChainSwapStatus::ClaimStuck
            ) && chain_swap.claim_txid.as_deref().is_some_and(txid_matches)
        }
        SettlementChain::Bitcoin => match status {
            ChainSwapStatus::Refunding => {
                chain_swap.refund_txid.as_deref().is_none_or(txid_matches)
            }
            ChainSwapStatus::Refunded => {
                chain_swap.refund_txid.as_deref().is_some_and(txid_matches)
            }
            _ => false,
        },
    }
}

fn blocked_settlement_decision(action: ChainSwapAction) -> ChainSwapSettlementRuntimeDecision {
    ChainSwapSettlementRuntimeDecision {
        action: ChainSwapSettlementRuntimeAction::Blocked(action),
        accounting_eligible_actual_amount_sat: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppliedMerchantSettlementAction {
    Watching,
    Demoted,
    Finalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournaledMerchantSettlementTick {
    NoJournal,
    CandidateNotObserved,
    Applied {
        action: AppliedMerchantSettlementAction,
        checkpoint_version: i64,
        projection_changed: bool,
        journal_rebroadcast_required: bool,
    },
}

/// Require the repository to durably publish the service's exact-byte replay
/// request as well as every accounting demotion. An eviction before first
/// confirmation remains `Watching` for accounting, but still has to mark and
/// redrive the immutable journal. Finalized accounting can never request
/// another broadcast.
const fn compose_merchant_settlement_rebroadcast(
    action: AppliedMerchantSettlementAction,
    service_requested: bool,
    repository_required: bool,
) -> Option<bool> {
    if service_requested && matches!(action, AppliedMerchantSettlementAction::Finalized) {
        return None;
    }
    let expected = service_requested || matches!(action, AppliedMerchantSettlementAction::Demoted);
    if repository_required == expected {
        Some(expected)
    } else {
        None
    }
}

/// Execute one exact-output settlement observation from a single validated
/// repository work packet. The packet's checkpoint version is the CAS token;
/// no database read is reopened between chain observation and persistence.
/// Parent terminal/demotion state is deliberately not written here: the CAS
/// repository transaction is its sole authority.
async fn process_journaled_merchant_settlement(
    state: &AppState,
    chain_swap: &ChainSwapRecord,
) -> Result<JournaledMerchantSettlementTick, AppError> {
    let Some(context) = merchant_settlement_context_for_record(chain_swap)? else {
        return Ok(JournaledMerchantSettlementTick::NoJournal);
    };
    let policy = merchant_settlement_finality_policy(state)?;
    let Some(mut work) = db::load_merchant_settlement_work_item(&state.db, &context, policy)
        .await
        .map_err(map_merchant_settlement_repository_error)?
    else {
        return Ok(JournaledMerchantSettlementTick::NoJournal);
    };

    let processing = match context.path() {
        MerchantSettlementPath::LiquidClaim => {
            let backend = state.utxo_backend.as_deref().ok_or_else(|| {
                AppError::ElectrumError(
                    "Liquid merchant settlement observation backend is unavailable".into(),
                )
            })?;
            let original_sources = journal_source_prevouts(&work.original_journal);
            let original = journal_evidence(&work.original_journal, &original_sources);
            let replacement_sources = work
                .linked_replacement
                .as_ref()
                .map(journal_source_prevouts);
            let replacement_evidence = work
                .linked_replacement
                .as_ref()
                .zip(replacement_sources.as_ref())
                .map(|(row, sources)| journal_evidence(row, sources));
            let linked_replacement = work
                .linked_replacement
                .as_ref()
                .zip(replacement_evidence.as_ref())
                .map(|(row, replacement)| LinkedReplacementJournalEvidence {
                    replaces_txid: row.replaces_txid.as_deref().unwrap_or_default(),
                    replacement: *replacement,
                });
            let blinding_key = work.liquid_blinding_key_hex.as_deref().ok_or_else(|| {
                AppError::ClaimError(
                    "Liquid merchant settlement journal lacks its blinding key".into(),
                )
            })?;
            let previous = previous_liquid_confirmation(&work.previous_confirmation);
            let observation = match observe_liquid_merchant_output(
                backend,
                &original,
                linked_replacement.as_ref(),
                blinding_key,
                previous,
            )
            .await
            {
                Ok(observation) => observation,
                Err(LiquidMerchantObservationError::CandidateNotObserved) => {
                    match work.service.resume_missing_candidate_redrive() {
                        Some(processing) => {
                            return persist_merchant_settlement_processing(
                                state, chain_swap, context, policy, work, processing,
                            )
                            .await
                        }
                        None => {
                            return Ok(JournaledMerchantSettlementTick::CandidateNotObserved);
                        }
                    }
                }
                Err(error) => return Err(map_liquid_observation_error(error)),
            };
            work.service
                .apply_liquid_observation(&observation, &work.approved_destination)
                .map_err(map_settlement_processing_error)?
        }
        MerchantSettlementPath::BitcoinRecovery => {
            let backend = state.bitcoin_recovery_backend.as_deref().ok_or_else(|| {
                AppError::ElectrumError(
                    "Bitcoin merchant settlement observation backend is unavailable".into(),
                )
            })?;
            let original_sources = journal_source_prevouts(&work.original_journal);
            let original = journal_evidence(&work.original_journal, &original_sources);
            let previous = previous_bitcoin_confirmation(&work.previous_confirmation);
            let observation =
                match observe_bitcoin_merchant_output_journal(backend, &original, None, previous)
                    .await
                {
                    Ok(observation) => observation,
                    Err(BitcoinMerchantObservationError::CandidateNotObserved) => {
                        match work.service.resume_missing_candidate_redrive() {
                            Some(processing) => {
                                return persist_merchant_settlement_processing(
                                    state, chain_swap, context, policy, work, processing,
                                )
                                .await
                            }
                            None => {
                                return Ok(JournaledMerchantSettlementTick::CandidateNotObserved);
                            }
                        }
                    }
                    Err(error) => return Err(map_bitcoin_observation_error(error)),
                };
            work.service
                .apply_bitcoin_recovery_observation(&observation, &work.approved_destination)
                .map_err(map_settlement_processing_error)?
        }
    };

    persist_merchant_settlement_processing(state, chain_swap, context, policy, work, processing)
        .await
}

async fn persist_merchant_settlement_processing(
    state: &AppState,
    chain_swap: &ChainSwapRecord,
    context: MerchantSettlementContext,
    policy: SettlementFinalityPolicy,
    work: db::MerchantSettlementWorkItem,
    processing: MerchantSettlementProcessingOutcome,
) -> Result<JournaledMerchantSettlementTick, AppError> {
    let action = match work.service.lifecycle().accounting_state() {
        SettlementAccountingState::Finalized => AppliedMerchantSettlementAction::Finalized,
        SettlementAccountingState::Demoted => AppliedMerchantSettlementAction::Demoted,
        SettlementAccountingState::Unrecorded | SettlementAccountingState::Confirmed => {
            AppliedMerchantSettlementAction::Watching
        }
    };
    let snapshot = work.service.snapshot();
    let service_rebroadcast_requested = processing.rebroadcast_journaled;
    let persisted = db::persist_merchant_settlement_outcome(
        &state.db,
        work.checkpoint_version,
        &snapshot,
        &processing,
        policy,
        db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
    )
    .await
    .map_err(map_merchant_settlement_repository_error)?;

    let expected_parent_status = match (context.path(), action) {
        (MerchantSettlementPath::LiquidClaim, AppliedMerchantSettlementAction::Finalized) => {
            "claimed"
        }
        (MerchantSettlementPath::BitcoinRecovery, AppliedMerchantSettlementAction::Finalized) => {
            "refunded"
        }
        (MerchantSettlementPath::LiquidClaim, _) => "claiming",
        (MerchantSettlementPath::BitcoinRecovery, _) => "refunding",
    };
    let journal_rebroadcast_required = compose_merchant_settlement_rebroadcast(
        action,
        service_rebroadcast_requested,
        persisted.journal_rebroadcast_required,
    );
    if persisted.parent_transition.current_status != expected_parent_status
        || journal_rebroadcast_required.is_none()
    {
        return Err(AppError::ClaimError(format!(
            "merchant settlement persistence returned incoherent parent/journal transition for {}",
            chain_swap.id
        )));
    }

    Ok(JournaledMerchantSettlementTick::Applied {
        action,
        checkpoint_version: persisted.checkpoint_version,
        projection_changed: persisted.projection_changed,
        journal_rebroadcast_required: journal_rebroadcast_required
            .expect("coherence checked immediately above"),
    })
}

fn merchant_settlement_finality_policy(
    state: &AppState,
) -> Result<SettlementFinalityPolicy, AppError> {
    SettlementFinalityPolicy::new(
        state.config.liquid_watcher.finality_confirmations,
        state.config.bitcoin_watcher.confirmations_required,
    )
    .map_err(|error| {
        AppError::ClaimError(format!(
            "merchant settlement finality configuration is invalid: {error}"
        ))
    })
}

fn merchant_settlement_context_for_record(
    chain_swap: &ChainSwapRecord,
) -> Result<Option<MerchantSettlementContext>, AppError> {
    let status = chain_swap.parsed_status().map_err(|error| {
        AppError::ClaimError(format!(
            "invalid chain-swap status at merchant settlement boundary: {error}"
        ))
    })?;
    let path = match status {
        ChainSwapStatus::Claiming
        | ChainSwapStatus::Claimed
        | ChainSwapStatus::ClaimFailed
        | ChainSwapStatus::ClaimStuck => MerchantSettlementPath::LiquidClaim,
        ChainSwapStatus::Refunding | ChainSwapStatus::Refunded => {
            MerchantSettlementPath::BitcoinRecovery
        }
        _ => return Ok(None),
    };
    MerchantSettlementContext::new(
        chain_swap.invoice_id,
        chain_swap.id,
        chain_swap.boltz_swap_id.clone(),
        path,
    )
    .map(Some)
    .map_err(|error| {
        AppError::ClaimError(format!(
            "invalid merchant settlement context for chain swap {}: {error}",
            chain_swap.id
        ))
    })
}

fn journal_source_prevouts(
    row: &db::MerchantSettlementJournalRow,
) -> Vec<MerchantSourcePrevout<'_>> {
    row.source_prevouts
        .iter()
        .map(|source| MerchantSourcePrevout {
            txid: &source.txid,
            vout: source.vout,
            amount_sat: source.amount_sat,
            script_pubkey_hex: &source.script_pubkey_hex,
        })
        .collect()
}

fn journal_evidence<'a>(
    row: &'a db::MerchantSettlementJournalRow,
    source_prevouts: &'a [MerchantSourcePrevout<'a>],
) -> MerchantTransactionJournalEvidence<'a> {
    MerchantTransactionJournalEvidence {
        raw_transaction: &row.raw_transaction,
        txid: &row.txid,
        source_prevouts,
        merchant: MerchantOutputCommitment {
            destination_address: &row.destination_address,
            destination_script_hex: &row.destination_script_hex,
            asset: &row.asset,
            amount_sat: row.destination_amount_sat,
            vout: row.destination_vout,
        },
    }
}

fn previous_liquid_confirmation(
    previous: &db::MerchantSettlementPreviousConfirmation,
) -> PreviousLiquidMerchantConfirmation<'_> {
    match previous {
        db::MerchantSettlementPreviousConfirmation::NeverObserved => {
            PreviousLiquidMerchantConfirmation::NeverObserved
        }
        db::MerchantSettlementPreviousConfirmation::Mempool => {
            PreviousLiquidMerchantConfirmation::Mempool
        }
        db::MerchantSettlementPreviousConfirmation::Confirmed {
            block_height,
            block_hash,
        } => PreviousLiquidMerchantConfirmation::Confirmed {
            block_height: *block_height,
            block_hash,
        },
        db::MerchantSettlementPreviousConfirmation::Reorged {
            previous_block_height,
            previous_block_hash,
        } => PreviousLiquidMerchantConfirmation::Reorged {
            previous_block_height: *previous_block_height,
            previous_block_hash,
        },
    }
}

fn previous_bitcoin_confirmation(
    previous: &db::MerchantSettlementPreviousConfirmation,
) -> PreviousBitcoinMerchantConfirmation<'_> {
    match previous {
        db::MerchantSettlementPreviousConfirmation::NeverObserved => {
            PreviousBitcoinMerchantConfirmation::NeverObserved
        }
        db::MerchantSettlementPreviousConfirmation::Mempool => {
            PreviousBitcoinMerchantConfirmation::Mempool
        }
        db::MerchantSettlementPreviousConfirmation::Confirmed {
            block_height,
            block_hash,
        } => PreviousBitcoinMerchantConfirmation::Confirmed {
            block_height: *block_height,
            block_hash,
        },
        db::MerchantSettlementPreviousConfirmation::Reorged {
            previous_block_height,
            previous_block_hash,
        } => PreviousBitcoinMerchantConfirmation::Reorged {
            previous_block_height: *previous_block_height,
            previous_block_hash,
        },
    }
}

fn map_merchant_settlement_repository_error(
    error: db::MerchantSettlementRepositoryError,
) -> AppError {
    match error {
        db::MerchantSettlementRepositoryError::Database(error) => {
            AppError::DbError(error.to_string())
        }
        error => AppError::ClaimError(error.to_string()),
    }
}

fn map_settlement_processing_error(error: MerchantSettlementProcessingError) -> AppError {
    AppError::ClaimError(error.to_string())
}

fn map_liquid_observation_error(error: LiquidMerchantObservationError) -> AppError {
    match error {
        LiquidMerchantObservationError::Backend(error) => error,
        error => AppError::ClaimError(error.to_string()),
    }
}

fn map_bitcoin_observation_error(error: BitcoinMerchantObservationError) -> AppError {
    match error {
        BitcoinMerchantObservationError::Backend(error) => error,
        error => AppError::ClaimError(error.to_string()),
    }
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

enum ChainSwapProviderPollError {
    Provider(BoltzClientError),
    Handler(AppError),
}

async fn poll_chain_swap_provider_once(
    state: &AppState,
    swap: &ChainSwapRecord,
) -> Result<(), ChainSwapProviderPollError> {
    let remote = state
        .boltz
        .get_swap(&swap.boltz_swap_id)
        .await
        .map_err(ChainSwapProviderPollError::Provider)?;
    crate::claimer::handle_chain_swap_webhook(state, swap, &remote.status)
        .await
        .map_err(ChainSwapProviderPollError::Handler)
}

/// Execute one real chain-reconciler provider read and idempotent reducer
/// handoff without spawning the periodic worker.
#[doc(hidden)]
pub async fn exercise_chain_swap_provider_poll_once(
    state: &AppState,
    swap: &ChainSwapRecord,
) -> Result<(), AppError> {
    poll_chain_swap_provider_once(state, swap)
        .await
        .map_err(|error| match error {
            ChainSwapProviderPollError::Provider(error) => {
                AppError::BoltzError(format!("chain provider poll failed: {error}"))
            }
            ChainSwapProviderPollError::Handler(error) => error,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlowRecoveryRail {
    Reverse,
    Chain,
}

/// Build one fair, combined page across both recovery rails. Alternation keeps
/// a continuously full rail from starving the other; if one is empty, the
/// other consumes the remaining budget.
fn slow_recovery_rail_schedule(
    reverse_count: usize,
    chain_count: usize,
    limit: u32,
) -> Vec<SlowRecoveryRail> {
    let maximum = limit as usize;
    let capacity = maximum.min(reverse_count.saturating_add(chain_count));
    let mut schedule = Vec::with_capacity(capacity);
    let mut reverse_remaining = reverse_count;
    let mut chain_remaining = chain_count;
    let mut prefer_reverse = true;

    while schedule.len() < maximum && (reverse_remaining > 0 || chain_remaining > 0) {
        let rail = if prefer_reverse {
            if reverse_remaining > 0 {
                SlowRecoveryRail::Reverse
            } else {
                SlowRecoveryRail::Chain
            }
        } else if chain_remaining > 0 {
            SlowRecoveryRail::Chain
        } else {
            SlowRecoveryRail::Reverse
        };
        match rail {
            SlowRecoveryRail::Reverse => reverse_remaining -= 1,
            SlowRecoveryRail::Chain => chain_remaining -= 1,
        }
        schedule.push(rail);
        prefer_reverse = !prefer_reverse;
    }
    schedule
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

    let reverse = db::list_claim_stuck_swaps_for_slow_retry(&state.db, fetch_limit).await?;
    let reverse_fetched = reverse.len();
    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    let chain = db::list_claim_stuck_chain_swaps_for_slow_retry(&state.db, fetch_limit).await?;
    let chain_fetched = chain.len();
    let schedule = slow_recovery_rail_schedule(reverse_fetched, chain_fetched, limit);
    let mut reverse = reverse.into_iter();
    let mut chain = chain.into_iter();

    for rail in schedule {
        if cancel.is_cancelled() {
            return Ok(ScanOutcome::Cancelled);
        }
        let candidate = match rail {
            SlowRecoveryRail::Reverse => reverse.next(),
            SlowRecoveryRail::Chain => chain.next(),
        };
        let Some((id, boltz_swap_id, slow_attempts)) = candidate else {
            tracing::error!(
                event = "slow_recovery_schedule_invariant_failed",
                ?rail,
                "slow-recovery schedule exceeded its fetched rows"
            );
            return Ok(ScanOutcome::Failed);
        };
        reporter.progress();
        let backoff = slow_recovery_backoff_secs(slow_attempts, base, cap);
        let revived = match rail {
            SlowRecoveryRail::Reverse => {
                db::revive_claim_stuck_swap_for_slow_retry(&state.db, id, max_attempts, backoff)
                    .await?
            }
            SlowRecoveryRail::Chain => {
                db::revive_claim_stuck_chain_swap_for_slow_retry(
                    &state.db,
                    id,
                    max_attempts,
                    backoff,
                )
                .await?
            }
        };
        if revived == 1 {
            let rail_name = match rail {
                SlowRecoveryRail::Reverse => "lightning_boltz_reverse",
                SlowRecoveryRail::Chain => "bitcoin_boltz_chain",
            };
            tracing::warn!(
                event = "slow_recovery_revived",
                rail = rail_name,
                swap_id = %boltz_swap_id,
                slow_attempt = slow_attempts + 1,
                "reviving funded claim_stuck swap into the claim sweep"
            );
        }
    }
    if cancel.is_cancelled() {
        return Ok(ScanOutcome::Cancelled);
    }
    Ok(scan_outcome(
        limit,
        reverse_fetched.saturating_add(chain_fetched),
        true,
    ))
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
    const REPAIR_MAX_AGE_SECS: u64 = invoice::INVOICE_LIFETIME_SECS as u64;
    let tolerances = db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting);
    let merchant_policy = match merchant_settlement_finality_policy(state) {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(
                event = "merchant_settlement_repair_configuration_invalid",
                error = %error,
                "legacy settlement repair is disabled because exact-output finality is invalid"
            );
            return Ok(ScanOutcome::Failed);
        }
    };
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

    // --- Bitcoin chain-swap rail ---
    // Exact-output checkpoints are the only authority for a missing payment
    // event. Legacy requested/provider amounts must never repair these rows.
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
            let repository_context = match MerchantSettlementContext::new(
                swap.invoice_id,
                swap.id,
                swap.boltz_swap_id.clone(),
                MerchantSettlementPath::LiquidClaim,
            ) {
                Ok(context) => context,
                Err(error) => {
                    health.settlement_write(false);
                    tracing::error!(
                        event = "settlement_repair_irreconcilable",
                        swap_id = %swap.boltz_swap_id,
                        invoice_id = %swap.invoice_id,
                        error = %error,
                        "claimed chain swap has invalid exact-output settlement identity"
                    );
                    cursors[1].visit(swap.id);
                    continue;
                }
            };
            let work = match db::load_merchant_settlement_work_item(
                &state.db,
                &repository_context,
                merchant_policy,
            )
            .await
            {
                Ok(Some(work)) => work,
                Ok(None) => {
                    health.settlement_write(false);
                    tracing::error!(
                        event = "settlement_repair_exact_evidence_missing",
                        swap_id = %swap.boltz_swap_id,
                        invoice_id = %swap.invoice_id,
                        "claimed chain swap has no validated exact-output checkpoint; proxy amount repair refused"
                    );
                    cursors[1].visit(swap.id);
                    continue;
                }
                Err(db::MerchantSettlementRepositoryError::Database(error)) => return Err(error),
                Err(error) => {
                    health.settlement_write(false);
                    tracing::error!(
                        event = "settlement_repair_repository_invalid",
                        swap_id = %swap.boltz_swap_id,
                        invoice_id = %swap.invoice_id,
                        error = %error,
                        "exact-output repository ownership could not be validated; legacy amount repair skipped"
                    );
                    cursors[1].visit(swap.id);
                    continue;
                }
            };
            let Some(intent) = work.service.repair_accounting_intent().cloned() else {
                health.settlement_write(false);
                tracing::error!(
                    event = "settlement_repair_exact_evidence_unconfirmed",
                    swap_id = %swap.boltz_swap_id,
                    invoice_id = %swap.invoice_id,
                    "claimed chain swap checkpoint has no confirmed exact-output repair intent"
                );
                cursors[1].visit(swap.id);
                continue;
            };
            let mut commands = vec![
                MerchantSettlementPersistenceCommand::Record(intent.clone()),
                MerchantSettlementPersistenceCommand::Activate(intent.identity.clone()),
            ];
            if work.service.lifecycle().accounting_state() == SettlementAccountingState::Finalized {
                commands.push(MerchantSettlementPersistenceCommand::Finalize(
                    intent.identity.clone(),
                ));
            }
            let outcome = MerchantSettlementProcessingOutcome {
                commands,
                redrive_observation: false,
                rebroadcast_journaled: false,
            };
            let snapshot = work.service.snapshot();
            tracing::warn!(
                event = "settlement_repair_exact_output",
                rail = "bitcoin_boltz_chain",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                txid = %intent.txid,
                vout = intent.vout,
                actual_amount_sat = intent.actual_amount_sat,
                "CAS-replaying confirmed exact-output accounting for a claimed chain swap"
            );
            match db::persist_merchant_settlement_outcome(
                &state.db,
                work.checkpoint_version,
                &snapshot,
                &outcome,
                merchant_policy,
                tolerances,
            )
            .await
            {
                Ok(result) => tracing::info!(
                    event = "settlement_repair_exact_output_applied",
                    swap_id = %swap.boltz_swap_id,
                    checkpoint_version = result.checkpoint_version,
                    projection_changed = result.projection_changed,
                    "repaired chain-swap accounting from retained exact output"
                ),
                Err(db::MerchantSettlementRepositoryError::Database(error)) => return Err(error),
                Err(error) => {
                    health.settlement_write(false);
                    tracing::error!(
                        event = "settlement_repair_exact_output_failed",
                        swap_id = %swap.boltz_swap_id,
                        error = %error,
                        "exact-output settlement repair CAS failed"
                    );
                }
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
    if !health.is_healthy() {
        return Ok(ScanOutcome::Failed);
    }
    Ok(reverse_outcome.merge(chain_outcome))
}

async fn run_one_chain_tick(
    state: &AppState,
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
                    match process_journaled_merchant_settlement(state, &swap).await {
                        Ok(JournaledMerchantSettlementTick::Applied {
                            action:
                                action @ (AppliedMerchantSettlementAction::Watching
                                | AppliedMerchantSettlementAction::Finalized),
                            checkpoint_version,
                            projection_changed,
                            journal_rebroadcast_required,
                        }) => {
                            tracing::info!(
                                event = "chain_swap_merchant_settlement_applied",
                                swap_id = %swap.boltz_swap_id,
                                path = "bitcoin_recovery",
                                ?action,
                                checkpoint_version,
                                projection_changed,
                                "persisted exact Bitcoin recovery merchant-output observation"
                            );
                            if !journal_rebroadcast_required {
                                cursors[0].visit(swap.id);
                                continue;
                            }
                            tracing::warn!(
                                event = "chain_swap_merchant_settlement_unconfirmed_eviction",
                                swap_id = %swap.boltz_swap_id,
                                path = "bitcoin_recovery",
                                checkpoint_version,
                                projection_changed,
                                "persisted unconfirmed Bitcoin recovery eviction; redriving exact journal bytes"
                            );
                        }
                        Ok(JournaledMerchantSettlementTick::Applied {
                            action: AppliedMerchantSettlementAction::Demoted,
                            checkpoint_version,
                            projection_changed,
                            journal_rebroadcast_required,
                        }) => {
                            tracing::warn!(
                                event = "chain_swap_merchant_settlement_demoted",
                                swap_id = %swap.boltz_swap_id,
                                path = "bitcoin_recovery",
                                checkpoint_version,
                                projection_changed,
                                journal_rebroadcast_required,
                                "persisted Bitcoin recovery demotion; redriving exact journal bytes"
                            );
                        }
                        Ok(JournaledMerchantSettlementTick::CandidateNotObserved)
                        | Ok(JournaledMerchantSettlementTick::NoJournal) => {}
                        Err(error) => {
                            health.observe_app_error(&error);
                            tracing::warn!(
                                event = "chain_swap_merchant_settlement_deferred",
                                swap_id = %swap.boltz_swap_id,
                                path = "bitcoin_recovery",
                                error = %error,
                                "exact Bitcoin recovery settlement observation failed closed"
                            );
                            cursors[0].visit(swap.id);
                            continue;
                        }
                    }
                    match crate::chain_recovery::execute_journaled_recovery_automatically(
                        state, swap.id,
                    )
                    .await
                    {
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
            match process_journaled_merchant_settlement(state, swap).await {
                Ok(JournaledMerchantSettlementTick::Applied {
                    action:
                        action @ (AppliedMerchantSettlementAction::Watching
                        | AppliedMerchantSettlementAction::Finalized),
                    checkpoint_version,
                    projection_changed,
                    journal_rebroadcast_required,
                }) => {
                    tracing::info!(
                        event = "chain_swap_merchant_settlement_applied",
                        swap_id = %swap.boltz_swap_id,
                        path = "liquid_claim",
                        ?action,
                        checkpoint_version,
                        projection_changed,
                        "persisted exact Liquid claim merchant-output observation"
                    );
                    if journal_rebroadcast_required {
                        tracing::warn!(
                            event = "chain_swap_merchant_settlement_unconfirmed_eviction",
                            swap_id = %swap.boltz_swap_id,
                            path = "liquid_claim",
                            checkpoint_version,
                            projection_changed,
                            "persisted unconfirmed Liquid claim eviction; redriving exact journal bytes"
                        );
                        if let Err(error) =
                            crate::claimer::redrive_journaled_chain_claim(state, swap.id).await
                        {
                            health.observe_app_error(&error);
                            tracing::warn!(
                                event = "chain_swap_merchant_settlement_rebroadcast_deferred",
                                swap_id = %swap.boltz_swap_id,
                                path = "liquid_claim",
                                error = %error,
                                "unconfirmed Liquid claim exact-byte rebroadcast deferred"
                            );
                        }
                    }
                    cursors[1].visit(swap.id);
                    continue;
                }
                Ok(JournaledMerchantSettlementTick::Applied {
                    action: AppliedMerchantSettlementAction::Demoted,
                    checkpoint_version,
                    projection_changed,
                    journal_rebroadcast_required,
                }) => {
                    tracing::warn!(
                        event = "chain_swap_merchant_settlement_demoted",
                        swap_id = %swap.boltz_swap_id,
                        path = "liquid_claim",
                        checkpoint_version,
                        projection_changed,
                        journal_rebroadcast_required,
                        "persisted Liquid claim demotion; redriving exact journal bytes"
                    );
                    if let Err(error) =
                        crate::claimer::redrive_journaled_chain_claim(state, swap.id).await
                    {
                        health.observe_app_error(&error);
                        tracing::warn!(
                            event = "chain_swap_merchant_settlement_rebroadcast_deferred",
                            swap_id = %swap.boltz_swap_id,
                            path = "liquid_claim",
                            error = %error,
                            "demoted Liquid claim exact-byte rebroadcast deferred"
                        );
                    }
                    cursors[1].visit(swap.id);
                    continue;
                }
                Ok(JournaledMerchantSettlementTick::CandidateNotObserved)
                | Ok(JournaledMerchantSettlementTick::NoJournal) => {}
                Err(error) => {
                    health.observe_app_error(&error);
                    tracing::warn!(
                        event = "chain_swap_merchant_settlement_deferred",
                        swap_id = %swap.boltz_swap_id,
                        path = "liquid_claim",
                        error = %error,
                        "exact Liquid claim settlement observation failed closed"
                    );
                    cursors[1].visit(swap.id);
                    continue;
                }
            }
            match crate::chain_fallback::schedule_automatic_fallback(state, swap.id).await {
                Ok(
                    crate::chain_fallback::AutomaticFallbackScheduleOutcome::Scheduled
                    | crate::chain_fallback::AutomaticFallbackScheduleOutcome::AlreadyDue,
                ) => {
                    tracing::warn!(
                        event = "automatic_fallback_due",
                        chain_swap_id = %swap.id,
                        "independent under-lock evidence scheduled automatic Bitcoin fallback"
                    );
                    cursors[1].visit(swap.id);
                    continue;
                }
                Ok(crate::chain_fallback::AutomaticFallbackScheduleOutcome::AlreadyExecuting) => {
                    cursors[1].visit(swap.id);
                    continue;
                }
                Ok(crate::chain_fallback::AutomaticFallbackScheduleOutcome::Deferred(action)) => {
                    tracing::debug!(
                        event = "automatic_fallback_observed",
                        chain_swap_id = %swap.id,
                        ?action,
                        "automatic Bitcoin fallback remains ineligible"
                    );
                }
                Ok(
                    crate::chain_fallback::AutomaticFallbackScheduleOutcome::EvidenceUnavailable(
                        action,
                    ),
                ) => {
                    health.systemic_failure = true;
                    tracing::warn!(
                        event = "automatic_fallback_evidence_unavailable",
                        chain_swap_id = %swap.id,
                        ?action,
                        "automatic Bitcoin fallback authority is unavailable; new chain admission remains closed"
                    );
                }
                Ok(crate::chain_fallback::AutomaticFallbackScheduleOutcome::IntegrityHold) => {
                    health.systemic_failure = true;
                    tracing::error!(
                        event = "automatic_fallback_integrity_hold",
                        chain_swap_id = %swap.id,
                        "automatic Bitcoin fallback evidence requires operator integrity review; new chain admission remains closed"
                    );
                }
                Ok(
                    crate::chain_fallback::AutomaticFallbackScheduleOutcome::Busy
                    | crate::chain_fallback::AutomaticFallbackScheduleOutcome::Missing
                    | crate::chain_fallback::AutomaticFallbackScheduleOutcome::IneligibleStatus(_),
                ) => {}
                Err(error) => {
                    health.observe_app_error(&error);
                    tracing::warn!(
                        event = "automatic_fallback_evidence_deferred",
                        chain_swap_id = %swap.id,
                        error = %error,
                        "automatic Bitcoin fallback evidence failed closed"
                    );
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(ScanOutcome::Cancelled),
                _ = tokio::time::sleep(Duration::from_millis(config.inter_call_delay_ms)) => {}
            }
            reporter.progress();

            match poll_chain_swap_provider_once(state, swap).await {
                Ok(()) => {
                    health.provider_succeeded();
                }
                Err(ChainSwapProviderPollError::Provider(error)) => {
                    health.provider_error(&error);
                    tracing::warn!(
                        "chain reconciler: get_swap({}) failed: {error}",
                        swap.boltz_swap_id
                    );
                }
                Err(ChainSwapProviderPollError::Handler(error)) => {
                    health.provider_succeeded();
                    health.observe_app_error(&error);
                    tracing::error!(
                        "chain reconciler: handle failed for {}: {error}",
                        swap.boltz_swap_id
                    );
                }
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
    boltz: &crate::boltz::BoltzService,
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

        let remote = match boltz.get_swap(&swap.boltz_swap_id).await {
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
    /// Boltz says the Lightning invoice settled but our row is not Claimed.
    /// Preserve a structured operator alert while automatically re-driving
    /// the claim path, which owns the lockup-outspend recovery probe.
    RecoverSettledWithoutLocalClaim,
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
        // owns the advisory lock and the lockup-outspend recovery probe. Keep
        // this distinct from an ordinary retry: the provider/local mismatch
        // is operationally alertable until the claim path resolves it.
        ("invoice.settled", "claimed") => Noop,
        ("invoice.settled", _) => RecoverSettledWithoutLocalClaim,

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
        RecoverSettledWithoutLocalClaim => {
            // A missed lockup webhook can leave the local row `pending`, which
            // the claim sweep does not select. Promote only that live state;
            // every other live status is already claimable and terminal rows
            // were rejected by `decide_action` above.
            if swap.status == "pending" {
                db::update_swap_status(pool, swap.id, SwapStatus::LockupConfirmed, None).await?;
            }
            let scheduled = db::schedule_immediate_claim(pool, swap.id).await?;
            if scheduled == 1 {
                tracing::error!(
                    event = "reverse_swap_settled_without_local_claim",
                    source = "reconciler",
                    swap_id = %swap.boltz_swap_id,
                    nym = %swap.nym.as_deref().unwrap_or("<invoice-only>"),
                    our_status = %swap.status,
                    claim_txid = ?swap.claim_txid,
                    amount_sat = swap.amount_sat,
                    "provider reports a settled Lightning invoice without a local claimed state; scheduling automatic claim recovery"
                );
            } else {
                tracing::debug!(
                    swap_id = %swap.boltz_swap_id,
                    "settled reverse swap reached a terminal state before reconciler recovery scheduling"
                );
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;

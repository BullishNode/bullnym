//! Bounded automatic Bitcoin fallback scheduling and execution (#85).
//!
//! Provider polling never authorizes this worker. The ordinary chain
//! reconciler may ask the scheduler to evaluate one obligation, but both the
//! scheduling write and the executor rebuild the complete independent #82
//! packet while holding `chain-claim:<id>`. `refund_due` is therefore only a
//! queue marker after positive path eligibility, never evidence by itself; a
//! cooperative path becomes spend authority only after its returned signature
//! is validated and its exact bytes are journaled.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::admission::WorkerReporter;
use crate::chain_swap_action::{reduce_chain_swap_evidence, ChainSwapAction};
use crate::chain_swap_runtime_evidence::collect_automatic_fallback_evidence_under_lock;
use crate::config::ReconcilerConfig;
use crate::db::{self, ChainSwapStatus};
use crate::error::AppError;
use crate::utxo::{LiquidHistorySnapshotLimits, LiquidHistorySnapshotOutcome};
use crate::AppState;

const READINESS_LIQUID_HISTORY_LIMIT: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomaticFallbackScheduleOutcome {
    Scheduled,
    AlreadyDue,
    AlreadyExecuting,
    Deferred(ChainSwapAction),
    EvidenceUnavailable(ChainSwapAction),
    IntegrityHold,
    Busy,
    Missing,
    IneligibleStatus(ChainSwapStatus),
}

/// Rebuild #82 evidence and publish a queue marker only after an exact path is
/// eligible for construction. No provider status or retry counter enters the
/// decision, and no transaction construction happens in this function.
pub async fn schedule_automatic_fallback(
    state: &AppState,
    chain_swap_id: Uuid,
) -> Result<AutomaticFallbackScheduleOutcome, AppError> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    let lock_key = format!("chain-claim:{chain_swap_id}");
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
    if !got_lock {
        tx.commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        return Ok(AutomaticFallbackScheduleOutcome::Busy);
    }

    let Some(swap) = db::get_chain_swap_by_id_for_update(&mut *tx, chain_swap_id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?
    else {
        tx.commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        return Ok(AutomaticFallbackScheduleOutcome::Missing);
    };
    let status = swap.parsed_status().map_err(AppError::DbError)?;
    if status == ChainSwapStatus::Refunding {
        tx.commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        return Ok(AutomaticFallbackScheduleOutcome::AlreadyExecuting);
    }
    if !schedule_candidate_status(status) {
        tx.commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        return Ok(AutomaticFallbackScheduleOutcome::IneligibleStatus(status));
    }

    let (recovery_address_commitment_id, merchant_emergency_btc_address) = swap
        .creation_terms
        .as_ref()
        .map(|terms| {
            (
                terms.recovery_address_commitment_id,
                terms.merchant_emergency_btc_address.as_deref(),
            )
        })
        .unwrap_or((None, None));
    if !has_automatic_fallback_recovery_contract(
        recovery_address_commitment_id,
        merchant_emergency_btc_address,
    ) {
        tx.commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        return Ok(AutomaticFallbackScheduleOutcome::IntegrityHold);
    }

    let recovery_attempt = db::get_bitcoin_recovery_attempt_for_update(&mut tx, chain_swap_id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    let collected = collect_automatic_fallback_evidence_under_lock(
        state,
        &mut tx,
        &swap,
        recovery_attempt.as_ref(),
    )
    .await?;
    if collected.committed_destination().is_none() {
        tx.commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        return Ok(AutomaticFallbackScheduleOutcome::IntegrityHold);
    }
    let action = reduce_chain_swap_evidence(&collected.evidence);
    if !collected.dependencies_available() {
        tx.commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        return Ok(AutomaticFallbackScheduleOutcome::EvidenceUnavailable(
            action,
        ));
    }
    if action == ChainSwapAction::IntegrityHold {
        tx.commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        return Ok(AutomaticFallbackScheduleOutcome::IntegrityHold);
    }
    if collected.automatic_construction_path().is_none() {
        tx.commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        return Ok(AutomaticFallbackScheduleOutcome::Deferred(action));
    }
    let destination = collected.committed_destination().ok_or_else(|| {
        AppError::ClaimError("automatic fallback lacks its immutable destination".into())
    })?;

    if status == ChainSwapStatus::RefundDue && swap.refund_address.as_deref() == Some(destination) {
        tx.commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        return Ok(AutomaticFallbackScheduleOutcome::AlreadyDue);
    }
    let updated = sqlx::query(
        "UPDATE chain_swap_records \
            SET status = 'refund_due', refund_address = $2, updated_at = NOW() \
          WHERE id = $1 \
            AND status IN ('pending', 'user_lock_mempool', 'user_lock_confirmed', \
                           'server_lock_mempool', 'server_lock_confirmed', 'refund_due') \
            AND claim_txid IS NULL AND claim_tx_hex IS NULL \
            AND (refund_address IS NULL OR refund_address = $2)",
    )
    .bind(chain_swap_id)
    .bind(destination)
    .execute(&mut *tx)
    .await
    .map_err(|error| AppError::DbError(error.to_string()))?;
    if updated.rows_affected() != 1 {
        return Err(AppError::ClaimError(
            "automatic fallback lost its locked scheduling transition".into(),
        ));
    }
    tx.commit()
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    Ok(AutomaticFallbackScheduleOutcome::Scheduled)
}

const fn schedule_candidate_status(status: ChainSwapStatus) -> bool {
    matches!(
        status,
        ChainSwapStatus::Pending
            | ChainSwapStatus::UserLockMempool
            | ChainSwapStatus::UserLockConfirmed
            | ChainSwapStatus::ServerLockMempool
            | ChainSwapStatus::ServerLockConfirmed
            | ChainSwapStatus::RefundDue
    )
}

fn has_automatic_fallback_recovery_contract(
    recovery_address_commitment_id: Option<Uuid>,
    merchant_emergency_btc_address: Option<&str>,
) -> bool {
    recovery_address_commitment_id.is_some() && merchant_emergency_btc_address.is_some()
}

/// Exercise the global authorities needed by every automatic fallback even
/// when there is no due row whose payment script could otherwise drive them.
/// This is admission health only: execution remains per-swap, under-lock, and
/// continues independently when this probe closes new-money admission.
async fn probe_automatic_fallback_dependencies(state: &AppState) -> Result<(), AppError> {
    let bitcoin = state
        .bitcoin_lockup_witness_adapter
        .as_deref()
        .ok_or_else(|| {
            AppError::ElectrumError(
                "automatic fallback primary Bitcoin witness is unavailable".into(),
            )
        })?;
    bitcoin
        .primary_authority_health_check()
        .await
        .map_err(|_| {
            AppError::ElectrumError(
                "automatic fallback primary Bitcoin witness is unhealthy".into(),
            )
        })?;

    let liquid = state.utxo_backend.as_deref().ok_or_else(|| {
        AppError::ElectrumError("automatic fallback Liquid evidence is unavailable".into())
    })?;
    let outcome = liquid
        .automatic_fallback_liquid_history_snapshot(
            &automatic_fallback_readiness_script(),
            &[],
            LiquidHistorySnapshotLimits {
                max_history_entries: READINESS_LIQUID_HISTORY_LIMIT,
                max_block_heights: READINESS_LIQUID_HISTORY_LIMIT,
            },
        )
        .await?;
    match outcome {
        LiquidHistorySnapshotOutcome::Complete(_) => Ok(()),
        LiquidHistorySnapshotOutcome::Incomplete(_) => Err(AppError::ElectrumError(
            "automatic fallback Liquid authority readiness snapshot is incomplete".into(),
        )),
    }
}

/// An ephemeral, unspendable script used only to prove that two distinct
/// Liquid authorities can agree on a stable history/tip boundary. It carries no
/// payment identity and cannot authorize a per-swap decision. Fresh randomness
/// prevents the readiness probe itself from becoming a public history-flooding
/// target that can remotely close new-money admission.
fn automatic_fallback_readiness_script() -> lwk_wollet::elements::Script {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0x6a, 0x20]); // OP_RETURN PUSH32
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    lwk_wollet::elements::Script::from(bytes)
}

fn automatic_fallback_failure_is_systemic(error: &AppError) -> bool {
    match error {
        AppError::DbError(_) | AppError::ElectrumError(_) => true,
        // Automatic execution owns immutable journal/evidence invariants. A
        // ClaimError here is therefore admission-significant except for normal
        // contention with another executor holding the same advisory lock.
        AppError::ClaimError(reason) => !reason.starts_with("chain swap is busy"),
        _ => false,
    }
}

/// Existing-obligation executor. It is intentionally not conditioned on the
/// new-money admission state and performs no provider polling. Each due row is
/// re-authorized under the shared lock inside the journal executor.
pub fn spawn_automatic_fallback_executor(
    state: AppState,
    config: Arc<ReconcilerConfig>,
    cancel: CancellationToken,
    mut reporter: WorkerReporter,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs));
        let mut after_id = None;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    reporter.intentional_shutdown();
                    tracing::info!(event = "automatic_fallback_shutdown", "automatic Bitcoin fallback executor shutting down");
                    return;
                }
                _ = tick.tick() => {}
            }
            // Probe admission dependencies independently of queue occupancy,
            // but never let a failed readiness probe disable draining existing
            // obligations below.
            let mut systemic_failure = match probe_automatic_fallback_dependencies(&state).await {
                Ok(()) => false,
                Err(error) => {
                    tracing::warn!(
                        event = "automatic_fallback_readiness_failed",
                        error = %error,
                        "automatic fallback dependencies are unhealthy; new Bitcoin-chain admission remains closed while existing work continues"
                    );
                    true
                }
            };
            let due = match db::list_automatic_fallback_due_chain_swaps(
                &state.db,
                config.max_per_tick,
                after_id,
            )
            .await
            {
                Ok(due) => due,
                Err(error) => {
                    reporter.cycle_failed();
                    tracing::error!(
                        event = "automatic_fallback_scan_failed",
                        error = %error,
                        "automatic Bitcoin fallback worklist scan failed"
                    );
                    continue;
                }
            };
            for swap in due {
                // Advance even when this row defers, is busy, or is corrupt.
                // The next bounded page starts after it and wraps oldest-first,
                // preventing a permanently blocked prefix from starving newer
                // obligations.
                after_id = Some(swap.id);
                if cancel.is_cancelled() {
                    reporter.intentional_shutdown();
                    return;
                }
                reporter.progress();
                match crate::chain_recovery::execute_journaled_recovery_automatically(
                    &state, swap.id,
                )
                .await
                {
                    Ok(txid) => tracing::warn!(
                        event = "automatic_fallback_recovery_redriven",
                        chain_swap_id = %swap.id,
                        recovery_txid = %txid,
                        "automatic Bitcoin fallback committed/reconciled exact journal bytes"
                    ),
                    Err(error) => {
                        systemic_failure |= automatic_fallback_failure_is_systemic(&error);
                        tracing::warn!(
                            event = "automatic_fallback_deferred",
                            chain_swap_id = %swap.id,
                            error = %error,
                            "automatic Bitcoin fallback remains queued for fresh evidence"
                        );
                    }
                }
                tokio::select! {
                    _ = cancel.cancelled() => {
                        reporter.intentional_shutdown();
                        return;
                    },
                    _ = tokio::time::sleep(Duration::from_millis(config.inter_call_delay_ms)) => {}
                }
            }
            if systemic_failure {
                reporter.cycle_failed();
            } else {
                reporter.cycle_succeeded();
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_preexecution_branches_are_scheduler_candidates() {
        for status in [
            ChainSwapStatus::Pending,
            ChainSwapStatus::UserLockMempool,
            ChainSwapStatus::UserLockConfirmed,
            ChainSwapStatus::ServerLockMempool,
            ChainSwapStatus::ServerLockConfirmed,
            ChainSwapStatus::RefundDue,
        ] {
            assert!(schedule_candidate_status(status));
        }
        for status in [
            ChainSwapStatus::Claiming,
            ChainSwapStatus::Claimed,
            ChainSwapStatus::ClaimFailed,
            ChainSwapStatus::ClaimStuck,
            ChainSwapStatus::Expired,
            ChainSwapStatus::LockupFailed,
            ChainSwapStatus::Refunded,
            ChainSwapStatus::Refunding,
        ] {
            assert!(!schedule_candidate_status(status));
        }
    }

    #[test]
    fn only_rows_with_the_current_recovery_contract_are_fallback_candidates() {
        let commitment_id = Uuid::from_u128(1);
        assert!(!has_automatic_fallback_recovery_contract(None, None));
        assert!(!has_automatic_fallback_recovery_contract(
            Some(commitment_id),
            None,
        ));
        assert!(!has_automatic_fallback_recovery_contract(
            None,
            Some("bc1qaddressonly")
        ));
        assert!(has_automatic_fallback_recovery_contract(
            Some(commitment_id),
            Some("bc1qcommitted")
        ));
    }

    #[test]
    fn readiness_probe_uses_an_ephemeral_unspendable_non_payment_script() {
        let first = automatic_fallback_readiness_script();
        let second = automatic_fallback_readiness_script();
        assert_eq!(first.as_bytes().len(), 34);
        assert_eq!(&first.as_bytes()[..2], &[0x6a, 0x20]);
        assert_ne!(first, second);
    }

    #[test]
    fn invariant_failures_close_admission_but_lock_contention_does_not() {
        assert!(automatic_fallback_failure_is_systemic(&AppError::DbError(
            "database unavailable".into()
        )));
        assert!(automatic_fallback_failure_is_systemic(
            &AppError::ElectrumError("authority unavailable".into())
        ));
        assert!(automatic_fallback_failure_is_systemic(
            &AppError::ClaimError("immutable recovery packet mismatch".into())
        ));
        assert!(!automatic_fallback_failure_is_systemic(
            &AppError::ClaimError(
                "chain swap is busy (claim/recovery in progress); retry shortly".into()
            )
        ));
        assert!(!automatic_fallback_failure_is_systemic(
            &AppError::RecoveryNotAvailable("fresh evidence changed".into())
        ));
    }
}

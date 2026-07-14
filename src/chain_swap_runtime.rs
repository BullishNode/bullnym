//! Narrow runtime interpretation of the pure chain-swap evidence reducer.
//!
//! Evidence collection stays outside this module. In particular, provider
//! status is installed only as a hint and provider transaction ids may only
//! have selected a transaction already present in the independently audited
//! [`PrimaryBitcoinSourceProjectionV1`]. A missing primary projection forces
//! the decision back to incomplete/unknown regardless of caller-supplied
//! Bitcoin fields.

use sqlx::PgPool;
use uuid::Uuid;

use crate::chain_swap_action::{
    recheck_chain_swap_execution_under_lock, reduce_chain_swap_evidence, BitcoinSourceEvidence,
    ChainSwapAction, ChainSwapEvidence, ChainSwapExecutionAction, ChainSwapExecutionGate,
    CooperativeRecoveryEvidence, EvidenceQuality, LiquidLockEvidence, LiquidPathEvidence,
    MerchantTransactionEvidence, ProviderStatusEvidence, RecoveryDestinationEvidence,
    RenegotiationEvidence,
};
use crate::chain_swap_primary_source::PrimaryBitcoinSourceProjectionV1;
use crate::chain_swap_runtime_evidence::collect_pending_expiry_evidence_under_lock;
use crate::db::{self, ChainSwapStatus};
use crate::error::AppError;
use crate::AppState;

/// One caller-assembled evidence snapshot plus the independently projected
/// primary Bitcoin transaction.
///
/// `evidence.bitcoin_source` is never trusted directly. It is overwritten by
/// `primary_bitcoin`, or by `Unknown` when that projection is unavailable.
#[derive(Debug, Clone, Copy)]
pub struct ChainSwapProviderEvidence<'a> {
    pub evidence: ChainSwapEvidence,
    pub primary_bitcoin: Option<&'a PrimaryBitcoinSourceProjectionV1>,
}

impl<'a> ChainSwapProviderEvidence<'a> {
    /// Fail-closed input for a provider delivery that has no independently
    /// assembled chain snapshot yet.
    pub const fn incomplete() -> Self {
        Self {
            evidence: ChainSwapEvidence {
                quality: EvidenceQuality::Incomplete,
                provider_status: ProviderStatusEvidence::Unknown,
                bitcoin_source: BitcoinSourceEvidence::Unknown,
                liquid_lock: LiquidLockEvidence::Unknown,
                liquid_path: LiquidPathEvidence::Unknown,
                renegotiation: RenegotiationEvidence::Ambiguous,
                recovery_destination: RecoveryDestinationEvidence::Missing,
                cooperative_recovery: CooperativeRecoveryEvidence::Unknown,
                bitcoin_timeout: crate::chain_swap_action::BitcoinTimeoutEvidence::Unknown,
                liquid_claim_transaction: MerchantTransactionEvidence::None,
                bitcoin_recovery_transaction: MerchantTransactionEvidence::None,
            },
            primary_bitcoin: None,
        }
    }
}

/// Runtime effect allowed by one reducer result at the provider-observation
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapProviderEffect {
    /// Evidence is incomplete or disagreeing; keep reconciling without writes.
    Observe,
    /// A safe reducer action exists but its executor is outside this narrow
    /// provider-expiry integration.
    Reconcile(ChainSwapAction),
    /// Retire a never-funded pending offer. This is deliberately narrower than
    /// the reducer's generic `Finalize`, which also covers merchant settlement.
    FinalizeUnfunded,
    /// Positive conflicting evidence stops automated action.
    IntegrityHold,
}

/// Result of applying a provider-observation effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapProviderApplyOutcome {
    Observed,
    Reconcile(ChainSwapAction),
    Finalized,
    AlreadyFinalized,
    IntegrityHold,
    Busy,
    Missing,
    StateChanged(ChainSwapStatus),
}

/// Interpret one provider observation through the shared evidence reducer.
///
/// Provider status is only a hint. The primary Bitcoin projection must already
/// have validated any provider txid selector against independent history.
pub fn decide_chain_swap_provider_effect(
    provider_status: &str,
    input: ChainSwapProviderEvidence<'_>,
) -> ChainSwapProviderEffect {
    let evidence = normalized_evidence(provider_status, input);
    provider_effect_for_evidence(provider_status, &evidence)
}

fn provider_effect_for_evidence(
    provider_status: &str,
    evidence: &ChainSwapEvidence,
) -> ChainSwapProviderEffect {
    match reduce_chain_swap_evidence(evidence) {
        ChainSwapAction::Observe => ChainSwapProviderEffect::Observe,
        ChainSwapAction::IntegrityHold => ChainSwapProviderEffect::IntegrityHold,
        ChainSwapAction::Finalize
            if provider_status == "swap.expired" && is_unfunded_expiry(evidence) =>
        {
            ChainSwapProviderEffect::FinalizeUnfunded
        }
        action => ChainSwapProviderEffect::Reconcile(action),
    }
}

/// Apply a pending provider-expiry trigger from fresh evidence collected inside
/// the existing per-swap execution boundary.
///
/// The incoming status only triggers the read. It is never reduction authority:
/// the collector must return a fresh provider status together with complete
/// chain evidence after the advisory lock and row reload.
pub async fn apply_chain_swap_provider_effect(
    state: &AppState,
    chain_swap_id: Uuid,
    _incoming_status: &str,
) -> Result<ChainSwapProviderApplyOutcome, AppError> {
    apply_chain_swap_provider_effect_inner(
        &state.db,
        chain_swap_id,
        LockedEvidenceSource::Runtime(state),
    )
    .await
}

/// Deterministic integration seam. Supplied evidence is normalized and gated
/// only after the same advisory lock and `FOR UPDATE` reload as production.
#[doc(hidden)]
pub async fn apply_chain_swap_provider_effect_with_evidence(
    pool: &PgPool,
    chain_swap_id: Uuid,
    provider_status: &str,
    input: ChainSwapProviderEvidence<'_>,
) -> Result<ChainSwapProviderApplyOutcome, AppError> {
    apply_chain_swap_provider_effect_inner(
        pool,
        chain_swap_id,
        LockedEvidenceSource::Supplied {
            provider_status,
            input,
        },
    )
    .await
}

enum LockedEvidenceSource<'a> {
    Runtime(&'a AppState),
    Supplied {
        provider_status: &'a str,
        input: ChainSwapProviderEvidence<'a>,
    },
}

async fn apply_chain_swap_provider_effect_inner(
    pool: &PgPool,
    chain_swap_id: Uuid,
    source: LockedEvidenceSource<'_>,
) -> Result<ChainSwapProviderApplyOutcome, AppError> {
    let mut tx = pool.begin().await?;
    let lock_key = format!("chain-claim:{chain_swap_id}");
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await?;
    if !got_lock {
        tx.commit().await?;
        return Ok(ChainSwapProviderApplyOutcome::Busy);
    }

    let Some(current) = db::get_chain_swap_by_id_for_update(&mut *tx, chain_swap_id).await? else {
        tx.commit().await?;
        return Ok(ChainSwapProviderApplyOutcome::Missing);
    };
    let current_status = current.parsed_status().map_err(AppError::DbError)?;

    match current_status {
        ChainSwapStatus::Expired => {
            tx.commit().await?;
            Ok(ChainSwapProviderApplyOutcome::AlreadyFinalized)
        }
        ChainSwapStatus::Pending => {
            let (provider_status, evidence) = match source {
                LockedEvidenceSource::Runtime(state) => {
                    let collected =
                        collect_pending_expiry_evidence_under_lock(state, &mut tx, &current)
                            .await?;
                    let provider_status = collected.provider_status.unwrap_or_default();
                    let evidence = normalized_evidence(
                        &provider_status,
                        ChainSwapProviderEvidence {
                            evidence: collected.evidence,
                            primary_bitcoin: collected.primary_bitcoin.as_ref(),
                        },
                    );
                    (provider_status, evidence)
                }
                LockedEvidenceSource::Supplied {
                    provider_status,
                    input,
                } => (
                    provider_status.to_owned(),
                    normalized_evidence(provider_status, input),
                ),
            };

            let effect = provider_effect_for_evidence(&provider_status, &evidence);
            if effect != ChainSwapProviderEffect::FinalizeUnfunded {
                tx.commit().await?;
                return Ok(non_mutating_outcome(effect));
            }

            match recheck_finalize_unfunded_under_lock(&evidence) {
                ChainSwapProviderEffect::FinalizeUnfunded => {}
                blocked => {
                    tx.commit().await?;
                    return Ok(non_mutating_outcome(blocked));
                }
            }

            let updated = sqlx::query(
                "UPDATE chain_swap_records \
                 SET status = 'expired', updated_at = NOW() \
                 WHERE id = $1 AND status = 'pending'",
            )
            .bind(chain_swap_id)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(AppError::DbError(format!(
                    "locked pending chain swap changed before unfunded finalization: {chain_swap_id}"
                )));
            }
            tx.commit().await?;
            Ok(ChainSwapProviderApplyOutcome::Finalized)
        }
        status => {
            tx.commit().await?;
            Ok(ChainSwapProviderApplyOutcome::StateChanged(status))
        }
    }
}

fn recheck_finalize_unfunded_under_lock(evidence: &ChainSwapEvidence) -> ChainSwapProviderEffect {
    match recheck_chain_swap_execution_under_lock(ChainSwapExecutionAction::Finalize, evidence) {
        ChainSwapExecutionGate::Authorized if is_unfunded_expiry(evidence) => {
            ChainSwapProviderEffect::FinalizeUnfunded
        }
        ChainSwapExecutionGate::Authorized => {
            ChainSwapProviderEffect::Reconcile(ChainSwapAction::Finalize)
        }
        ChainSwapExecutionGate::Blocked(ChainSwapAction::Observe) => {
            ChainSwapProviderEffect::Observe
        }
        ChainSwapExecutionGate::Blocked(ChainSwapAction::IntegrityHold) => {
            ChainSwapProviderEffect::IntegrityHold
        }
        ChainSwapExecutionGate::Blocked(action) => ChainSwapProviderEffect::Reconcile(action),
    }
}

fn non_mutating_outcome(effect: ChainSwapProviderEffect) -> ChainSwapProviderApplyOutcome {
    match effect {
        ChainSwapProviderEffect::Observe => ChainSwapProviderApplyOutcome::Observed,
        ChainSwapProviderEffect::Reconcile(action) => {
            ChainSwapProviderApplyOutcome::Reconcile(action)
        }
        ChainSwapProviderEffect::IntegrityHold => ChainSwapProviderApplyOutcome::IntegrityHold,
        ChainSwapProviderEffect::FinalizeUnfunded => {
            unreachable!("finalization cannot be converted to a non-mutating outcome")
        }
    }
}

fn normalized_evidence(
    provider_status: &str,
    input: ChainSwapProviderEvidence<'_>,
) -> ChainSwapEvidence {
    let mut evidence = input.evidence;
    evidence.provider_status = provider_status_evidence(provider_status);
    if evidence.provider_status == ProviderStatusEvidence::Unknown {
        evidence.quality = EvidenceQuality::Incomplete;
    }
    match input.primary_bitcoin {
        Some(primary) => primary.apply_to_reducer_evidence(&mut evidence),
        None => {
            evidence.quality = EvidenceQuality::Incomplete;
            evidence.bitcoin_source = BitcoinSourceEvidence::Unknown;
        }
    }
    evidence
}

fn provider_status_evidence(status: &str) -> ProviderStatusEvidence {
    match status {
        "swap.expired"
        | "transaction.lockupFailed"
        | "transaction.failed"
        | "transaction.refunded" => ProviderStatusEvidence::Expired,
        "transaction.claimed" => ProviderStatusEvidence::SettlementHint,
        "swap.created"
        | "transaction.mempool"
        | "transaction.confirmed"
        | "transaction.server.mempool"
        | "transaction.server.confirmed"
        | "transaction.zeroconf.rejected" => ProviderStatusEvidence::Active,
        _ => ProviderStatusEvidence::Unknown,
    }
}

fn is_unfunded_expiry(evidence: &ChainSwapEvidence) -> bool {
    evidence.quality == EvidenceQuality::CompleteAndAgreed
        && evidence.provider_status == ProviderStatusEvidence::Expired
        && evidence.bitcoin_source == BitcoinSourceEvidence::Unfunded
        && matches!(
            evidence.liquid_lock,
            LiquidLockEvidence::NotObserved | LiquidLockEvidence::SpentByProviderRefund
        )
        && evidence.liquid_claim_transaction == MerchantTransactionEvidence::None
        && evidence.bitcoin_recovery_transaction == MerchantTransactionEvidence::None
}

#[cfg(test)]
mod tests {
    use crate::chain_lockup_witness_audit::{
        ChainLockupInclusionV1, ChainLockupManifestClassificationV1,
        ChainLockupManifestWitnessAuditV1, ChainLockupSpendV1, ChainLockupWitnessFindingV1,
    };
    use crate::chain_swap_action::BitcoinTimeoutEvidence;
    use crate::chain_swap_primary_source::{
        project_primary_bitcoin_source_v1, PrimaryBitcoinSourceAuthorityV1,
    };

    use super::*;

    const EXPECTED_SAT: u64 = 42_000;

    fn hash(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn audit(findings: Vec<ChainLockupWitnessFindingV1>) -> ChainLockupManifestWitnessAuditV1 {
        ChainLockupManifestWitnessAuditV1 {
            manifest_sequence: 1,
            manifest_id: Uuid::from_u128(1),
            chain_swap_id: Uuid::from_u128(2),
            expected_amount_sat: EXPECTED_SAT,
            classification: if findings.is_empty() {
                ChainLockupManifestClassificationV1::Missing
            } else {
                ChainLockupManifestClassificationV1::Spent
            },
            findings,
        }
    }

    fn base_evidence() -> ChainSwapEvidence {
        ChainSwapEvidence {
            quality: EvidenceQuality::CompleteAndAgreed,
            provider_status: ProviderStatusEvidence::Unknown,
            bitcoin_source: BitcoinSourceEvidence::Unknown,
            liquid_lock: LiquidLockEvidence::NotObserved,
            liquid_path: LiquidPathEvidence::Unavailable,
            renegotiation: RenegotiationEvidence::ExplicitlyUnavailable,
            recovery_destination: RecoveryDestinationEvidence::Committed,
            cooperative_recovery: CooperativeRecoveryEvidence::Unavailable,
            bitcoin_timeout: BitcoinTimeoutEvidence::BeforeTimeout,
            liquid_claim_transaction: MerchantTransactionEvidence::None,
            bitcoin_recovery_transaction: MerchantTransactionEvidence::None,
        }
    }

    fn unfunded_projection() -> PrimaryBitcoinSourceProjectionV1 {
        project_primary_bitcoin_source_v1(
            &audit(vec![]),
            None,
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
        )
        .unwrap()
    }

    #[test]
    fn complete_independent_unfunded_expiry_is_the_only_terminal_effect() {
        let primary = unfunded_projection();
        let input = ChainSwapProviderEvidence {
            evidence: base_evidence(),
            primary_bitcoin: Some(&primary),
        };
        assert_eq!(
            decide_chain_swap_provider_effect("swap.expired", input),
            ChainSwapProviderEffect::FinalizeUnfunded
        );
        assert_eq!(
            decide_chain_swap_provider_effect("swap.created", input),
            ChainSwapProviderEffect::Observe
        );
        assert_eq!(
            decide_chain_swap_provider_effect("transaction.failed", input),
            ChainSwapProviderEffect::Reconcile(ChainSwapAction::Finalize),
            "only the exact fresh swap.expired status may retire a pending offer"
        );
    }

    #[test]
    fn under_lock_gate_blocks_stale_finalization_after_a_liquid_lock_appears() {
        let primary = unfunded_projection();
        let planned = ChainSwapProviderEvidence {
            evidence: base_evidence(),
            primary_bitcoin: Some(&primary),
        };
        assert_eq!(
            decide_chain_swap_provider_effect("swap.expired", planned),
            ChainSwapProviderEffect::FinalizeUnfunded
        );

        let mut reread = base_evidence();
        reread.liquid_lock = LiquidLockEvidence::ConfirmedUnspent;
        let reread = normalized_evidence(
            "swap.expired",
            ChainSwapProviderEvidence {
                evidence: reread,
                primary_bitcoin: Some(&primary),
            },
        );
        assert_eq!(
            recheck_finalize_unfunded_under_lock(&reread),
            ChainSwapProviderEffect::Reconcile(ChainSwapAction::ClaimLiquid)
        );
    }

    #[test]
    fn missing_projection_overwrites_caller_bitcoin_claims_and_observes() {
        let mut evidence = base_evidence();
        evidence.bitcoin_source = BitcoinSourceEvidence::Unfunded;
        assert_eq!(
            decide_chain_swap_provider_effect(
                "swap.expired",
                ChainSwapProviderEvidence {
                    evidence,
                    primary_bitcoin: None,
                },
            ),
            ChainSwapProviderEffect::Observe
        );
    }

    #[test]
    fn provider_or_backend_disagreement_observes() {
        let provider_disagreement = project_primary_bitcoin_source_v1(
            &audit(vec![]),
            Some(&hash('a')),
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
        )
        .unwrap();
        let backend_disagreement = project_primary_bitcoin_source_v1(
            &audit(vec![]),
            None,
            PrimaryBitcoinSourceAuthorityV1::BackendDisagreement,
        )
        .unwrap();

        for primary in [&provider_disagreement, &backend_disagreement] {
            assert_eq!(
                decide_chain_swap_provider_effect(
                    "swap.expired",
                    ChainSwapProviderEvidence {
                        evidence: base_evidence(),
                        primary_bitcoin: Some(primary),
                    },
                ),
                ChainSwapProviderEffect::Observe
            );
        }
    }

    #[test]
    fn independent_unknown_outspend_is_an_integrity_hold() {
        let finding = ChainLockupWitnessFindingV1 {
            txid: hash('a'),
            vout: 0,
            observed_amount_sat: EXPECTED_SAT,
            inclusion: ChainLockupInclusionV1::Confirmed {
                confirmations: 3,
                block_height: 900_000,
                block_hash: hash('b'),
            },
            spend: ChainLockupSpendV1::Spent {
                spending_txid: hash('c'),
                inclusion: ChainLockupInclusionV1::Confirmed {
                    confirmations: 2,
                    block_height: 900_001,
                    block_hash: hash('d'),
                },
            },
            classification:
                crate::chain_lockup_witness_audit::ChainLockupFindingClassificationV1::Spent,
        };
        let primary = project_primary_bitcoin_source_v1(
            &audit(vec![finding]),
            Some(&hash('a')),
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
        )
        .unwrap();
        assert_eq!(
            decide_chain_swap_provider_effect(
                "swap.expired",
                ChainSwapProviderEvidence {
                    evidence: base_evidence(),
                    primary_bitcoin: Some(&primary),
                },
            ),
            ChainSwapProviderEffect::IntegrityHold
        );
    }

    #[test]
    fn merchant_settlement_finalize_never_reuses_unfunded_expiry_effect() {
        let primary = unfunded_projection();
        let mut evidence = base_evidence();
        evidence.liquid_lock = LiquidLockEvidence::SpentByMerchantClaim;
        evidence.liquid_claim_transaction = MerchantTransactionEvidence::Finalized;
        assert_eq!(
            decide_chain_swap_provider_effect(
                "swap.expired",
                ChainSwapProviderEvidence {
                    evidence,
                    primary_bitcoin: Some(&primary),
                },
            ),
            ChainSwapProviderEffect::Reconcile(ChainSwapAction::Finalize)
        );
    }
}

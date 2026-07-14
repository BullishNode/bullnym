//! Executable startup boundary for the accepted three-source recovery audit.
//!
//! The global chain-swap creation permit makes the authenticated witness,
//! PostgreSQL snapshot, and provider restore fetch one quiescent observation.
//! The result is a process-startup admission fact only. The accepted creation
//! permit may resume or repair already-persisted canonical obligations before
//! yielding a clean guard; this module adds no reconstruction policy, worker,
//! public endpoint, or recovery-evidence exposure of its own.

use std::fmt;
use std::future::Future;

use boltz_client::util::secrets::SwapMasterKey;
use sqlx::PgPool;

use crate::boltz_restore_fetch::BoltzRestoreFetcher;
use crate::chain_lockup_witness_adapter::BitcoinLockupWitnessAdapterV1;
use crate::chain_lockup_witness_audit::audit_manifest_set_against_chain_lockup_witness_v1;
use crate::chain_swap_creation_permit::{ChainSwapCreationPermit, ChainSwapCreationPermitError};
use crate::recovery_shadow_audit::{
    RecoveryShadowAuditCoordinatorV1, RecoveryShadowBoltzFetcherV1, RecoveryShadowClassificationV1,
    RecoveryShadowReportV1,
};
use crate::swap_manifest_runtime::RecoveryManifestRuntimeV1;
use crate::swap_manifest_witness::{
    RecoveryManifestWitnessLoaderV1, MAX_RECOVERY_WITNESS_RECORDS_V1,
};

/// One startup cannot repair more obligations than the accepted recovery
/// witness can subsequently authenticate. The loop counts complete permit
/// acquisitions, so it can never perform an unbounded extra repair merely to
/// discover that this cap was reached.
const MAX_STARTUP_CREATION_PERMIT_ACQUISITIONS_V1: usize = MAX_RECOVERY_WITNESS_RECORDS_V1;

/// Sanitized result retained only long enough to initialize money admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupProviderReconciliationFactV1 {
    report: RecoveryShadowReportV1,
    chain_witness: StartupChainLockupWitnessReportV1,
    repaired_obligation_count: usize,
}

/// Identity-free summary of the complete Bitcoin-mainnet witness audit used
/// to initialize the provider-recovery admission fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupChainLockupWitnessReportV1 {
    pub manifest_count: usize,
    pub observation_count: usize,
    pub missing_manifest_count: usize,
    pub unconfirmed_manifest_count: usize,
    pub confirmed_manifest_count: usize,
    pub spent_manifest_count: usize,
    pub conflicting_manifest_count: usize,
}

impl StartupChainLockupWitnessReportV1 {
    fn exact_agreement(self) -> bool {
        self.conflicting_manifest_count == 0
    }
}

impl StartupProviderReconciliationFactV1 {
    /// Only complete, exact agreement opens the new Bitcoin chain-swap rail.
    pub fn exact_agreement(&self) -> bool {
        startup_sources_exact(self.report.classification, self.chain_witness)
    }

    /// Bounded, identity-free evidence for structured startup diagnostics.
    pub fn report(&self) -> RecoveryShadowReportV1 {
        self.report
    }

    pub fn chain_witness(&self) -> StartupChainLockupWitnessReportV1 {
        self.chain_witness
    }

    /// Number of interrupted obligations drained before the clean audit.
    pub fn repaired_obligation_count(&self) -> usize {
        self.repaired_obligation_count
    }
}

fn startup_sources_exact(
    recovery: RecoveryShadowClassificationV1,
    chain: StartupChainLockupWitnessReportV1,
) -> bool {
    recovery == RecoveryShadowClassificationV1::Consistent && chain.exact_agreement()
}

/// Fixed startup failures. Lower-layer SQL, object-store, provider, URL,
/// credential, manifest, key, and identity details are deliberately discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupProviderReconciliationErrorV1 {
    CreationBoundaryUnavailable,
    RepairLimitExceeded,
    ThreeSourceAuditFailed,
    ChainWitnessAuditFailed,
    CreationBoundaryReleaseFailed,
}

impl fmt::Display for StartupProviderReconciliationErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CreationBoundaryUnavailable => {
                "startup recovery creation boundary is unavailable"
            }
            Self::RepairLimitExceeded => "startup recovery repair limit was reached",
            Self::ThreeSourceAuditFailed => "startup recovery three-source audit failed",
            Self::ChainWitnessAuditFailed => "startup recovery chain witness audit failed",
            Self::CreationBoundaryReleaseFailed => {
                "startup recovery creation boundary release failed"
            }
        })
    }
}

impl std::error::Error for StartupProviderReconciliationErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Run the accepted witness/local/provider audit under the same process-wide
/// permit used by every chain-swap creation route.
///
/// Holding the permit resumes any interrupted manifest delivery first and then
/// prevents a new provider mutation from appearing between the three reads.
/// Classified differences are returned as a closed admission fact, while
/// unavailable or invalid sources return a fixed source-free error.
pub async fn reconcile_startup_provider_state_v1(
    pool: &PgPool,
    runtime: &RecoveryManifestRuntimeV1,
    fetcher: &BoltzRestoreFetcher,
    swap_master_key: &SwapMasterKey,
    chain_witness_adapter: &BitcoinLockupWitnessAdapterV1,
) -> Result<StartupProviderReconciliationFactV1, StartupProviderReconciliationErrorV1> {
    let witness_open_secrets = runtime
        .witness_open_secrets_v1()
        .map_err(|_| StartupProviderReconciliationErrorV1::ThreeSourceAuditFailed)?;
    let (permit, repaired_obligation_count) =
        acquire_after_bounded_repairs(MAX_STARTUP_CREATION_PERMIT_ACQUISITIONS_V1, || {
            ChainSwapCreationPermit::acquire(pool, runtime)
        })
        .await?;

    let witness =
        RecoveryManifestWitnessLoaderV1::new(runtime.store().clone(), witness_open_secrets);
    let provider = RecoveryShadowBoltzFetcherV1::new(fetcher, swap_master_key);
    let audit = async {
        let (report, manifests) =
            RecoveryShadowAuditCoordinatorV1::new(witness, pool.clone(), provider)
                .run_once_with_manifests()
                .await
                .map_err(|_| StartupProviderReconciliationErrorV1::ThreeSourceAuditFailed)?;
        let snapshot = chain_witness_adapter
            .load_snapshot(&manifests)
            .await
            .map_err(|_| StartupProviderReconciliationErrorV1::ChainWitnessAuditFailed)?;
        let chain =
            audit_manifest_set_against_chain_lockup_witness_v1(&manifests, &snapshot.observations)
                .map_err(|_| StartupProviderReconciliationErrorV1::ChainWitnessAuditFailed)?;
        Ok::<_, StartupProviderReconciliationErrorV1>((
            report,
            StartupChainLockupWitnessReportV1 {
                manifest_count: chain.manifests.len(),
                observation_count: chain.observation_count,
                missing_manifest_count: chain.missing_manifest_count,
                unconfirmed_manifest_count: chain.unconfirmed_manifest_count,
                confirmed_manifest_count: chain.confirmed_manifest_count,
                spent_manifest_count: chain.spent_manifest_count,
                conflicting_manifest_count: chain.conflicting_manifest_count,
            },
        ))
    }
    .await;

    permit
        .release()
        .await
        .map_err(|_| StartupProviderReconciliationErrorV1::CreationBoundaryReleaseFailed)?;

    let (report, chain_witness) = audit?;
    Ok(StartupProviderReconciliationFactV1 {
        report,
        chain_witness,
        repaired_obligation_count,
    })
}

async fn acquire_after_bounded_repairs<P, F, Fut>(
    max_acquisitions: usize,
    mut acquire: F,
) -> Result<(P, usize), StartupProviderReconciliationErrorV1>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<P, ChainSwapCreationPermitError>>,
{
    let mut repaired_obligation_count = 0_usize;
    for _ in 0..max_acquisitions {
        match acquire().await {
            Ok(permit) => return Ok((permit, repaired_obligation_count)),
            Err(ChainSwapCreationPermitError::ManifestRepairCompleted) => {
                repaired_obligation_count += 1;
            }
            Err(_) => {
                return Err(StartupProviderReconciliationErrorV1::CreationBoundaryUnavailable);
            }
        }
    }
    Err(StartupProviderReconciliationErrorV1::RepairLimitExceeded)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use crate::admission::{
        Dependency, MoneyAdmission, ProviderRecoveryConsistencyTransitionV1, Rail, ReasonCode,
    };
    use crate::recovery_shadow_audit::{
        RecoveryShadowBoltzReportV1, RecoveryShadowCoverageV1,
        RecoveryShadowLineageClassificationsV1, RecoveryShadowLocalReportV1,
        RecoveryShadowProviderLocalHighWaterRelationV1,
    };

    use super::*;

    fn exact_empty_fact() -> StartupProviderReconciliationFactV1 {
        StartupProviderReconciliationFactV1 {
            report: RecoveryShadowReportV1 {
                manifest_count: 0,
                manifest_lineage_count: 0,
                manifest_max_child_index: None,
                provider_local_high_water_relation:
                    RecoveryShadowProviderLocalHighWaterRelationV1::BothEmpty,
                boltz: RecoveryShadowBoltzReportV1 {
                    validated_record_count: 0,
                    chain_record_count: 0,
                    reverse_record_count: 0,
                    provider_only_chain_record_count: 0,
                    provider_max_child_index: None,
                    coverage: RecoveryShadowCoverageV1::Exact,
                },
                local: RecoveryShadowLocalReportV1 {
                    local_record_count: 0,
                    exact_match_count: 0,
                    manifest_only_record_count: 0,
                    local_only_record_count: 0,
                    local_lineage_count: 0,
                    local_max_child_index: None,
                    lineage_classifications: RecoveryShadowLineageClassificationsV1::default(),
                    coverage: RecoveryShadowCoverageV1::Exact,
                },
                classification: RecoveryShadowClassificationV1::Consistent,
            },
            chain_witness: StartupChainLockupWitnessReportV1 {
                manifest_count: 0,
                observation_count: 0,
                missing_manifest_count: 0,
                unconfirmed_manifest_count: 0,
                confirmed_manifest_count: 0,
                spent_manifest_count: 0,
                conflicting_manifest_count: 0,
            },
            repaired_obligation_count: 0,
        }
    }

    #[test]
    fn public_errors_are_fixed_bounded_and_source_free() {
        for error in [
            StartupProviderReconciliationErrorV1::CreationBoundaryUnavailable,
            StartupProviderReconciliationErrorV1::RepairLimitExceeded,
            StartupProviderReconciliationErrorV1::ThreeSourceAuditFailed,
            StartupProviderReconciliationErrorV1::ChainWitnessAuditFailed,
            StartupProviderReconciliationErrorV1::CreationBoundaryReleaseFailed,
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(rendered.len() <= 112);
            for forbidden in [
                "postgres://",
                "https://",
                "xpub",
                "mnemonic",
                "ciphertext",
                "provider_swap_id",
            ] {
                assert!(!rendered.contains(forbidden));
            }
            assert!(error.source().is_none());
        }
    }

    #[tokio::test]
    async fn bounded_reacquisition_drains_repairs_but_never_exceeds_the_cap() {
        use std::collections::VecDeque;

        let mut repaired_then_clean = VecDeque::from([
            Err(ChainSwapCreationPermitError::ManifestRepairCompleted),
            Err(ChainSwapCreationPermitError::ManifestRepairCompleted),
            Ok(()),
        ]);
        let (_, repaired) = acquire_after_bounded_repairs(3, || {
            let result = repaired_then_clean.pop_front().unwrap();
            async move { result }
        })
        .await
        .unwrap();
        assert_eq!(repaired, 2);
        assert!(repaired_then_clean.is_empty());

        let mut never_clean = VecDeque::from([
            Err::<(), _>(ChainSwapCreationPermitError::ManifestRepairCompleted),
            Err::<(), _>(ChainSwapCreationPermitError::ManifestRepairCompleted),
            Err::<(), _>(ChainSwapCreationPermitError::ManifestRepairCompleted),
        ]);
        assert_eq!(
            acquire_after_bounded_repairs(2, || {
                let result = never_clean.pop_front().unwrap();
                async move { result }
            })
            .await
            .unwrap_err(),
            StartupProviderReconciliationErrorV1::RepairLimitExceeded
        );
        assert_eq!(never_clean.len(), 1, "the cap performed no extra repair");
    }

    #[test]
    fn startup_chain_witness_success_opens_and_conflict_fails_closed() {
        let complete_non_conflicting = StartupChainLockupWitnessReportV1 {
            manifest_count: 3,
            observation_count: 2,
            missing_manifest_count: 1,
            unconfirmed_manifest_count: 0,
            confirmed_manifest_count: 1,
            spent_manifest_count: 1,
            conflicting_manifest_count: 0,
        };
        assert!(startup_sources_exact(
            RecoveryShadowClassificationV1::Consistent,
            complete_non_conflicting,
        ));

        let conflicting = StartupChainLockupWitnessReportV1 {
            conflicting_manifest_count: 1,
            ..complete_non_conflicting
        };
        assert!(!startup_sources_exact(
            RecoveryShadowClassificationV1::Consistent,
            conflicting,
        ));
        assert!(!startup_sources_exact(
            RecoveryShadowClassificationV1::DifferencesClassified,
            complete_non_conflicting,
        ));
    }

    #[test]
    fn authenticated_reconciliation_is_the_only_transition_that_opens_provider_recovery() {
        let admission = MoneyAdmission::healthy_test_fixture();

        let failed = admission.apply_provider_recovery_reconciliation_v1(Err(
            StartupProviderReconciliationErrorV1::ThreeSourceAuditFailed,
        ));
        assert_eq!(failed, ProviderRecoveryConsistencyTransitionV1::Unsafe);
        let closed = admission.decision(Rail::BitcoinChain);
        assert!(!closed.allowed());
        assert!(closed.reasons.iter().any(|reason| {
            reason.dependency == Dependency::ProviderRecoveryConsistency
                && reason.code == ReasonCode::Unsafe
        }));

        let exact = admission.apply_provider_recovery_reconciliation_v1(Ok(exact_empty_fact()));
        assert_eq!(exact, ProviderRecoveryConsistencyTransitionV1::Safe);
        assert!(admission.decision(Rail::BitcoinChain).allowed());
    }

    #[test]
    fn classified_or_chain_disagreement_can_only_transition_to_unsafe() {
        let admission = MoneyAdmission::healthy_test_fixture();

        let mut classified = exact_empty_fact();
        classified.report.classification = RecoveryShadowClassificationV1::DifferencesClassified;
        assert_eq!(
            admission.apply_provider_recovery_reconciliation_v1(Ok(classified)),
            ProviderRecoveryConsistencyTransitionV1::Unsafe
        );
        assert!(!admission.decision(Rail::BitcoinChain).allowed());

        let mut chain_conflict = exact_empty_fact();
        chain_conflict.chain_witness.conflicting_manifest_count = 1;
        assert_eq!(
            admission.apply_provider_recovery_reconciliation_v1(Ok(chain_conflict)),
            ProviderRecoveryConsistencyTransitionV1::Unsafe
        );
        assert!(!admission.decision(Rail::BitcoinChain).allowed());
    }
}

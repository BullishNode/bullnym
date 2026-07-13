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
    repaired_obligation_count: usize,
}

impl StartupProviderReconciliationFactV1 {
    /// Only complete, exact agreement opens the new Bitcoin chain-swap rail.
    pub fn exact_agreement(&self) -> bool {
        self.report.classification == RecoveryShadowClassificationV1::Consistent
    }

    /// Bounded, identity-free evidence for structured startup diagnostics.
    pub fn report(&self) -> RecoveryShadowReportV1 {
        self.report
    }

    /// Number of interrupted obligations drained before the clean audit.
    pub fn repaired_obligation_count(&self) -> usize {
        self.repaired_obligation_count
    }
}

/// Fixed startup failures. Lower-layer SQL, object-store, provider, URL,
/// credential, manifest, key, and identity details are deliberately discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupProviderReconciliationErrorV1 {
    CreationBoundaryUnavailable,
    RepairLimitExceeded,
    ThreeSourceAuditFailed,
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
    let audit = RecoveryShadowAuditCoordinatorV1::new(witness, pool.clone(), provider)
        .run_once()
        .await
        .map_err(|_| StartupProviderReconciliationErrorV1::ThreeSourceAuditFailed);

    permit
        .release()
        .await
        .map_err(|_| StartupProviderReconciliationErrorV1::CreationBoundaryReleaseFailed)?;

    Ok(StartupProviderReconciliationFactV1 {
        report: audit?,
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

    use super::*;

    #[test]
    fn public_errors_are_fixed_bounded_and_source_free() {
        for error in [
            StartupProviderReconciliationErrorV1::CreationBoundaryUnavailable,
            StartupProviderReconciliationErrorV1::RepairLimitExceeded,
            StartupProviderReconciliationErrorV1::ThreeSourceAuditFailed,
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
}

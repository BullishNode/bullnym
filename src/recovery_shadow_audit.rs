//! One-shot, three-source recovery shadow audit.
//!
//! This module composes the existing authenticated manifest-witness loader,
//! read-only PostgreSQL snapshot adapter, and bounded validated Boltz xpub
//! restore fetcher. It produces only counts, high-waters, and classifications.
//! It deliberately performs no reconstruction, persistence, admission change,
//! worker scheduling, chain lookup, or runtime/configuration wiring.

use std::fmt;

use async_trait::async_trait;
use boltz_client::util::secrets::SwapMasterKey;
use sqlx::PgPool;

use crate::boltz_restore::{BoltzRestoreKind, ValidatedBoltzRestoreSet};
use crate::boltz_restore_fetch::{BoltzRestoreFetchError, BoltzRestoreFetcher};
use crate::db::{load_local_chain_swap_recovery_snapshot_v1, LocalRecoverySnapshotReadErrorV1};
use crate::local_chain_swap_recovery_audit::{
    audit_manifest_set_against_local_recovery_snapshot_v1, LocalChainSwapRecoveryAuditError,
    LocalChainSwapRecoveryAuditV1, LocalChainSwapRecoverySnapshotV1,
    LocalRecoveryHighWaterRelationV1, MAX_RECOVERY_AUDIT_LOCAL_LINEAGES_V1,
    MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1, MAX_RECOVERY_AUDIT_MANIFEST_RECORDS_V1,
};
use crate::swap_manifest::{
    audit_manifest_set_against_boltz_restore_v1, SwapManifestBoltzAuditError,
    SwapManifestBoltzAuditV1, SwapManifestV1,
};
use crate::swap_manifest_witness::{
    RecoveryManifestWitnessLoaderV1, RecoveryWitnessLoadError, MAX_RECOVERY_WITNESS_RECORDS_V1,
};

/// Maximum validated provider records accepted by one shadow comparison.
pub const MAX_RECOVERY_SHADOW_PROVIDER_RECORDS_V1: usize = 10_000;
/// A validated Bullnym restore record has at most claim and refund keys.
pub const MAX_RECOVERY_SHADOW_PROVIDER_KEYS_V1: usize = MAX_RECOVERY_SHADOW_PROVIDER_RECORDS_V1 * 2;

const MAX_RECOVERY_SHADOW_MANIFEST_RECORDS_V1: usize =
    if MAX_RECOVERY_WITNESS_RECORDS_V1 < MAX_RECOVERY_AUDIT_MANIFEST_RECORDS_V1 {
        MAX_RECOVERY_WITNESS_RECORDS_V1
    } else {
        MAX_RECOVERY_AUDIT_MANIFEST_RECORDS_V1
    };

/// Injectable boundary for one authenticated, quiescent witness load.
#[async_trait]
pub trait RecoveryShadowWitnessSourceV1: Send + Sync {
    async fn load_validated_witness(&self)
        -> Result<Vec<SwapManifestV1>, RecoveryWitnessLoadError>;
}

#[async_trait]
impl RecoveryShadowWitnessSourceV1 for RecoveryManifestWitnessLoaderV1 {
    async fn load_validated_witness(
        &self,
    ) -> Result<Vec<SwapManifestV1>, RecoveryWitnessLoadError> {
        Ok(self.load_quiescent().await?.into_parts().0)
    }
}

/// Injectable boundary for one coherent, read-only PostgreSQL snapshot.
#[async_trait]
pub trait RecoveryShadowLocalSnapshotSourceV1: Send + Sync {
    async fn load_validated_local_snapshot(
        &self,
    ) -> Result<LocalChainSwapRecoverySnapshotV1, LocalRecoverySnapshotReadErrorV1>;
}

#[async_trait]
impl RecoveryShadowLocalSnapshotSourceV1 for PgPool {
    async fn load_validated_local_snapshot(
        &self,
    ) -> Result<LocalChainSwapRecoverySnapshotV1, LocalRecoverySnapshotReadErrorV1> {
        load_local_chain_swap_recovery_snapshot_v1(self).await
    }
}

/// Injectable boundary for one bounded, validated provider restore fetch.
#[async_trait]
pub trait RecoveryShadowBoltzSourceV1: Send + Sync {
    async fn fetch_validated_boltz_restore(
        &self,
    ) -> Result<ValidatedBoltzRestoreSet, BoltzRestoreFetchError>;
}

/// Unwired adapter joining the existing fetcher with its secret validation key.
/// Neither field is exposed through `Debug`.
pub struct RecoveryShadowBoltzFetcherV1<'a> {
    fetcher: &'a BoltzRestoreFetcher,
    swap_master_key: &'a SwapMasterKey,
}

impl<'a> RecoveryShadowBoltzFetcherV1<'a> {
    pub fn new(fetcher: &'a BoltzRestoreFetcher, swap_master_key: &'a SwapMasterKey) -> Self {
        Self {
            fetcher,
            swap_master_key,
        }
    }
}

impl fmt::Debug for RecoveryShadowBoltzFetcherV1<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryShadowBoltzFetcherV1")
            .field("fetcher", &"<redacted>")
            .field("swap_master_key", &"<redacted>")
            .finish()
    }
}

#[async_trait]
impl RecoveryShadowBoltzSourceV1 for RecoveryShadowBoltzFetcherV1<'_> {
    async fn fetch_validated_boltz_restore(
        &self,
    ) -> Result<ValidatedBoltzRestoreSet, BoltzRestoreFetchError> {
        self.fetcher.fetch_and_validate(self.swap_master_key).await
    }
}

/// Whether one cross-source comparison found only exact witnessed coverage or
/// retained bounded candidates for a later policy boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryShadowCoverageV1 {
    Exact,
    CandidatesPresent,
}

/// Overall shadow-only result. This is a classification, never an admission
/// decision and never permission to reconstruct or mutate records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryShadowClassificationV1 {
    Consistent,
    DifferencesClassified,
}

/// Counts for all signed-versus-local allocator relations. Lineage identities
/// and root fingerprints are intentionally discarded.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryShadowLineageClassificationsV1 {
    pub equal: usize,
    pub local_ahead: usize,
    pub local_behind: usize,
    pub local_missing: usize,
    pub manifest_missing: usize,
}

impl RecoveryShadowLineageClassificationsV1 {
    fn has_differences(self) -> bool {
        self.local_ahead != 0
            || self.local_behind != 0
            || self.local_missing != 0
            || self.manifest_missing != 0
    }
}

/// Relation between Boltz's validated global xpub restore high-water and the
/// complete PostgreSQL allocation-registry high-water.
///
/// PostgreSQL may be ahead because allocations are durably reserved before a
/// provider call and gaps are permanent. Boltz being ahead proves that the
/// restored database omitted at least one provider-visible allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryShadowProviderLocalHighWaterRelationV1 {
    BothEmpty,
    Equal,
    LocalAhead,
    ProviderAhead,
}

impl RecoveryShadowProviderLocalHighWaterRelationV1 {
    fn provider_is_ahead(self) -> bool {
        self == Self::ProviderAhead
    }
}

/// Sanitized manifest-versus-provider portion of one shadow report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryShadowBoltzReportV1 {
    pub validated_record_count: usize,
    pub chain_record_count: usize,
    pub reverse_record_count: usize,
    pub provider_only_chain_record_count: usize,
    pub provider_max_child_index: Option<u32>,
    pub coverage: RecoveryShadowCoverageV1,
}

/// Sanitized manifest-versus-local portion of one shadow report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryShadowLocalReportV1 {
    pub local_record_count: usize,
    pub exact_match_count: usize,
    pub manifest_only_record_count: usize,
    pub local_only_record_count: usize,
    pub local_lineage_count: usize,
    pub local_max_child_index: Option<i64>,
    pub lineage_classifications: RecoveryShadowLineageClassificationsV1,
    pub coverage: RecoveryShadowCoverageV1,
}

/// One bounded public report. It contains no provider ids, swap/database ids,
/// root fingerprints, endpoints, envelopes, provider bodies, or key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryShadowReportV1 {
    pub manifest_count: usize,
    pub manifest_lineage_count: usize,
    pub manifest_max_child_index: Option<i64>,
    pub provider_local_high_water_relation: RecoveryShadowProviderLocalHighWaterRelationV1,
    pub boltz: RecoveryShadowBoltzReportV1,
    pub local: RecoveryShadowLocalReportV1,
    pub classification: RecoveryShadowClassificationV1,
}

/// Fixed one-shot failures. Underlying transport, SQL, object-store,
/// cryptographic, and cross-audit errors are intentionally discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryShadowAuditErrorV1 {
    WitnessLoadFailed,
    WitnessRecordLimitExceeded,
    LocalSnapshotLoadFailed,
    LocalRecordLimitExceeded,
    LocalLineageLimitExceeded,
    BoltzRestoreFetchFailed,
    BoltzRecordLimitExceeded,
    BoltzKeyLimitExceeded,
    ManifestBoltzAuditFailed,
    ManifestLocalAuditFailed,
}

impl fmt::Display for RecoveryShadowAuditErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WitnessLoadFailed => "recovery shadow witness load failed",
            Self::WitnessRecordLimitExceeded => "recovery shadow witness exceeds the record limit",
            Self::LocalSnapshotLoadFailed => "recovery shadow local snapshot load failed",
            Self::LocalRecordLimitExceeded => {
                "recovery shadow local snapshot exceeds the record limit"
            }
            Self::LocalLineageLimitExceeded => {
                "recovery shadow local snapshot exceeds the lineage limit"
            }
            Self::BoltzRestoreFetchFailed => "recovery shadow provider restore fetch failed",
            Self::BoltzRecordLimitExceeded => {
                "recovery shadow provider restore exceeds the record limit"
            }
            Self::BoltzKeyLimitExceeded => "recovery shadow provider restore exceeds the key limit",
            Self::ManifestBoltzAuditFailed => "recovery shadow manifest/provider comparison failed",
            Self::ManifestLocalAuditFailed => "recovery shadow manifest/local comparison failed",
        })
    }
}

impl std::error::Error for RecoveryShadowAuditErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[derive(Clone, Copy)]
struct RecoveryShadowLimitsV1 {
    manifest_records: usize,
    local_records: usize,
    local_lineages: usize,
    boltz_records: usize,
    boltz_keys: usize,
}

impl RecoveryShadowLimitsV1 {
    const PRODUCTION: Self = Self {
        manifest_records: MAX_RECOVERY_SHADOW_MANIFEST_RECORDS_V1,
        local_records: MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1,
        local_lineages: MAX_RECOVERY_AUDIT_LOCAL_LINEAGES_V1,
        boltz_records: MAX_RECOVERY_SHADOW_PROVIDER_RECORDS_V1,
        boltz_keys: MAX_RECOVERY_SHADOW_PROVIDER_KEYS_V1,
    };
}

/// Unwired coordinator. `run_once` consumes the instance so one coordinator
/// cannot accidentally reuse a witness or snapshot across multiple reports.
pub struct RecoveryShadowAuditCoordinatorV1<W, L, B> {
    witness: W,
    local: L,
    boltz: B,
    limits: RecoveryShadowLimitsV1,
}

impl<W, L, B> RecoveryShadowAuditCoordinatorV1<W, L, B> {
    pub fn new(witness: W, local: L, boltz: B) -> Self {
        Self {
            witness,
            local,
            boltz,
            limits: RecoveryShadowLimitsV1::PRODUCTION,
        }
    }

    #[cfg(test)]
    fn with_test_limits(witness: W, local: L, boltz: B, limits: RecoveryShadowLimitsV1) -> Self {
        Self {
            witness,
            local,
            boltz,
            limits,
        }
    }
}

impl<W, L, B> fmt::Debug for RecoveryShadowAuditCoordinatorV1<W, L, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryShadowAuditCoordinatorV1")
            .field("witness", &"<redacted source>")
            .field("local", &"<redacted source>")
            .field("boltz", &"<redacted source>")
            .field("limits", &"<bounded>")
            .finish()
    }
}

impl<W, L, B> RecoveryShadowAuditCoordinatorV1<W, L, B>
where
    W: RecoveryShadowWitnessSourceV1,
    L: RecoveryShadowLocalSnapshotSourceV1,
    B: RecoveryShadowBoltzSourceV1,
{
    pub async fn run_once(self) -> Result<RecoveryShadowReportV1, RecoveryShadowAuditErrorV1> {
        self.run_once_with_manifests()
            .await
            .map(|(report, _)| report)
    }

    /// Startup-only handoff of the exact authenticated manifest vector used by
    /// both existing cross-source comparisons. Keeping this crate-local avoids
    /// a second witness read before the public-chain audit.
    pub(crate) async fn run_once_with_manifests(
        self,
    ) -> Result<(RecoveryShadowReportV1, Vec<SwapManifestV1>), RecoveryShadowAuditErrorV1> {
        let manifests = self
            .witness
            .load_validated_witness()
            .await
            .map_err(|_| RecoveryShadowAuditErrorV1::WitnessLoadFailed)?;
        if manifests.len() > self.limits.manifest_records {
            return Err(RecoveryShadowAuditErrorV1::WitnessRecordLimitExceeded);
        }

        let local_snapshot = self
            .local
            .load_validated_local_snapshot()
            .await
            .map_err(|_| RecoveryShadowAuditErrorV1::LocalSnapshotLoadFailed)?;
        if local_snapshot.records.len() > self.limits.local_records {
            return Err(RecoveryShadowAuditErrorV1::LocalRecordLimitExceeded);
        }
        if local_snapshot.summary.lineage_high_waters.len() > self.limits.local_lineages {
            return Err(RecoveryShadowAuditErrorV1::LocalLineageLimitExceeded);
        }

        let boltz_restore = self
            .boltz
            .fetch_validated_boltz_restore()
            .await
            .map_err(|_| RecoveryShadowAuditErrorV1::BoltzRestoreFetchFailed)?;
        if boltz_restore.records.len() > self.limits.boltz_records {
            return Err(RecoveryShadowAuditErrorV1::BoltzRecordLimitExceeded);
        }
        let boltz_key_count = boltz_restore
            .records
            .iter()
            .try_fold(0_usize, |count, record| {
                count.checked_add(record.keys.len())
            });
        if boltz_key_count.is_none_or(|count| count > self.limits.boltz_keys) {
            return Err(RecoveryShadowAuditErrorV1::BoltzKeyLimitExceeded);
        }

        let boltz_audit = audit_manifest_set_against_boltz_restore_v1(&manifests, &boltz_restore)
            .map_err(collapse_manifest_boltz_error)?;
        let local_audit =
            audit_manifest_set_against_local_recovery_snapshot_v1(&manifests, &local_snapshot)
                .map_err(collapse_manifest_local_error)?;

        let report = build_report(&boltz_restore, &boltz_audit, &local_audit);
        Ok((report, manifests))
    }
}

fn collapse_manifest_boltz_error(_: SwapManifestBoltzAuditError) -> RecoveryShadowAuditErrorV1 {
    RecoveryShadowAuditErrorV1::ManifestBoltzAuditFailed
}

fn collapse_manifest_local_error(
    _: LocalChainSwapRecoveryAuditError,
) -> RecoveryShadowAuditErrorV1 {
    RecoveryShadowAuditErrorV1::ManifestLocalAuditFailed
}

fn build_report(
    boltz_restore: &ValidatedBoltzRestoreSet,
    boltz_audit: &SwapManifestBoltzAuditV1,
    local_audit: &LocalChainSwapRecoveryAuditV1,
) -> RecoveryShadowReportV1 {
    let chain_record_count = boltz_restore
        .records
        .iter()
        .filter(|record| record.kind == BoltzRestoreKind::Chain)
        .count();
    let reverse_record_count = boltz_restore.records.len() - chain_record_count;
    let boltz_coverage = if boltz_audit.provider_only_chain_record_count == 0 {
        RecoveryShadowCoverageV1::Exact
    } else {
        RecoveryShadowCoverageV1::CandidatesPresent
    };

    let mut lineage_classifications = RecoveryShadowLineageClassificationsV1::default();
    for comparison in &local_audit.lineage_high_waters {
        match comparison.relation {
            LocalRecoveryHighWaterRelationV1::Equal => lineage_classifications.equal += 1,
            LocalRecoveryHighWaterRelationV1::LocalAhead => {
                lineage_classifications.local_ahead += 1;
            }
            LocalRecoveryHighWaterRelationV1::LocalBehind => {
                lineage_classifications.local_behind += 1;
            }
            LocalRecoveryHighWaterRelationV1::LocalMissing => {
                lineage_classifications.local_missing += 1;
            }
            LocalRecoveryHighWaterRelationV1::ManifestMissing => {
                lineage_classifications.manifest_missing += 1;
            }
        }
    }

    let local_coverage = if local_audit.manifest_only_chain_swap_ids.is_empty()
        && local_audit.local_only_chain_swap_ids.is_empty()
        && local_audit.exact_match_count == local_audit.manifest_set.manifest_count
        && local_audit.exact_match_count == local_audit.local_record_count
    {
        RecoveryShadowCoverageV1::Exact
    } else {
        RecoveryShadowCoverageV1::CandidatesPresent
    };

    let manifest_max_child_index = boltz_audit
        .manifest_set
        .lineage_high_waters
        .iter()
        .map(|high_water| high_water.child_index)
        .max();
    let local_max_child_index = local_audit
        .lineage_high_waters
        .iter()
        .filter_map(|comparison| comparison.local_child_index)
        .max();
    let local_lineage_count = local_audit
        .lineage_high_waters
        .iter()
        .filter(|comparison| comparison.local_child_index.is_some())
        .count();
    let provider_local_high_water_relation =
        compare_provider_local_high_water(boltz_restore.max_child_index, local_max_child_index);

    let classification = if boltz_coverage == RecoveryShadowCoverageV1::Exact
        && local_coverage == RecoveryShadowCoverageV1::Exact
        && !lineage_classifications.has_differences()
        && !provider_local_high_water_relation.provider_is_ahead()
    {
        RecoveryShadowClassificationV1::Consistent
    } else {
        RecoveryShadowClassificationV1::DifferencesClassified
    };

    RecoveryShadowReportV1 {
        manifest_count: boltz_audit.manifest_set.manifest_count,
        manifest_lineage_count: boltz_audit.manifest_set.lineage_high_waters.len(),
        manifest_max_child_index,
        provider_local_high_water_relation,
        boltz: RecoveryShadowBoltzReportV1 {
            validated_record_count: boltz_restore.records.len(),
            chain_record_count,
            reverse_record_count,
            provider_only_chain_record_count: boltz_audit.provider_only_chain_record_count,
            provider_max_child_index: boltz_audit.provider_max_child_index,
            coverage: boltz_coverage,
        },
        local: RecoveryShadowLocalReportV1 {
            local_record_count: local_audit.local_record_count,
            exact_match_count: local_audit.exact_match_count,
            manifest_only_record_count: local_audit.manifest_only_chain_swap_ids.len(),
            local_only_record_count: local_audit.local_only_chain_swap_ids.len(),
            local_lineage_count,
            local_max_child_index,
            lineage_classifications,
            coverage: local_coverage,
        },
        classification,
    }
}

fn compare_provider_local_high_water(
    provider: Option<u32>,
    local: Option<i64>,
) -> RecoveryShadowProviderLocalHighWaterRelationV1 {
    match (provider.map(i64::from), local) {
        (None, None) => RecoveryShadowProviderLocalHighWaterRelationV1::BothEmpty,
        (Some(provider), Some(local)) if provider == local => {
            RecoveryShadowProviderLocalHighWaterRelationV1::Equal
        }
        (Some(provider), Some(local)) if provider < local => {
            RecoveryShadowProviderLocalHighWaterRelationV1::LocalAhead
        }
        (None, Some(_)) => RecoveryShadowProviderLocalHighWaterRelationV1::LocalAhead,
        (Some(_), None) | (Some(_), Some(_)) => {
            RecoveryShadowProviderLocalHighWaterRelationV1::ProviderAhead
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::sync::{Arc, Mutex};

    use boltz_client::network::Network;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::boltz_restore::{
        BoltzRestoreKeyPurpose, ValidatedBoltzRestoreKey, ValidatedBoltzRestoreRecord,
    };
    use crate::db::LocalRecoverySnapshotReadStageV1;
    use crate::local_chain_swap_recovery_audit::{
        LocalChainSwapRecoveryAllocationV1, LocalChainSwapRecoveryEvidenceV1,
        LocalChainSwapRecoverySnapshotSummaryV1, LocalRecoveryLineageComparisonV1,
        LocalRecoveryLineageHighWaterV1,
    };
    use crate::swap_manifest::{
        ManifestLineageHighWaterV1, SwapManifestSetAuditV1, SWAP_MANIFEST_FORMAT,
        SWAP_MANIFEST_VERSION,
    };

    const PROVIDER_SENTINEL: &str = "ProviderIdentityMustNotEscape";
    const ROOT_SENTINEL: &str = "0011223344556677";
    const ENDPOINT_SENTINEL: &str = "shadow-endpoint-must-not-escape.example";
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    type Trace = Arc<Mutex<Vec<&'static str>>>;

    struct FakeWitness {
        result: Result<Vec<SwapManifestV1>, RecoveryWitnessLoadError>,
        trace: Trace,
    }

    #[async_trait]
    impl RecoveryShadowWitnessSourceV1 for FakeWitness {
        async fn load_validated_witness(
            &self,
        ) -> Result<Vec<SwapManifestV1>, RecoveryWitnessLoadError> {
            self.trace.lock().unwrap().push("witness");
            self.result.clone()
        }
    }

    struct FakeLocal {
        result: Result<LocalChainSwapRecoverySnapshotV1, LocalRecoverySnapshotReadErrorV1>,
        trace: Trace,
    }

    #[async_trait]
    impl RecoveryShadowLocalSnapshotSourceV1 for FakeLocal {
        async fn load_validated_local_snapshot(
            &self,
        ) -> Result<LocalChainSwapRecoverySnapshotV1, LocalRecoverySnapshotReadErrorV1> {
            self.trace.lock().unwrap().push("local");
            self.result.clone()
        }
    }

    struct FakeBoltz {
        result: Result<ValidatedBoltzRestoreSet, BoltzRestoreFetchError>,
        trace: Trace,
    }

    #[async_trait]
    impl RecoveryShadowBoltzSourceV1 for FakeBoltz {
        async fn fetch_validated_boltz_restore(
            &self,
        ) -> Result<ValidatedBoltzRestoreSet, BoltzRestoreFetchError> {
            self.trace.lock().unwrap().push("boltz");
            self.result.clone()
        }
    }

    fn trace() -> Trace {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn fake_witness(
        trace: &Trace,
        result: Result<Vec<SwapManifestV1>, RecoveryWitnessLoadError>,
    ) -> FakeWitness {
        FakeWitness {
            result,
            trace: Arc::clone(trace),
        }
    }

    fn fake_local(
        trace: &Trace,
        result: Result<LocalChainSwapRecoverySnapshotV1, LocalRecoverySnapshotReadErrorV1>,
    ) -> FakeLocal {
        FakeLocal {
            result,
            trace: Arc::clone(trace),
        }
    }

    fn fake_boltz(
        trace: &Trace,
        result: Result<ValidatedBoltzRestoreSet, BoltzRestoreFetchError>,
    ) -> FakeBoltz {
        FakeBoltz {
            result,
            trace: Arc::clone(trace),
        }
    }

    fn empty_local_snapshot() -> LocalChainSwapRecoverySnapshotV1 {
        LocalChainSwapRecoverySnapshotV1 {
            records: Vec::new(),
            summary: LocalChainSwapRecoverySnapshotSummaryV1 {
                record_count: 0,
                lineage_high_waters: Vec::new(),
            },
        }
    }

    fn empty_boltz_restore() -> ValidatedBoltzRestoreSet {
        ValidatedBoltzRestoreSet {
            records: Vec::new(),
            max_child_index: None,
        }
    }

    fn compressed_public_key(scalar: u8) -> String {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&Secp256k1::new(), &secret).to_string()
    }

    fn local_only_record() -> LocalChainSwapRecoveryEvidenceV1 {
        LocalChainSwapRecoveryEvidenceV1 {
            chain_swap_id: Uuid::from_u128(0x101),
            boltz_swap_id: "LocalOnlyProviderRecord".into(),
            root_fingerprint: ROOT_SENTINEL.into(),
            key_epoch: 1,
            derivation_scheme_version: 1,
            claim: LocalChainSwapRecoveryAllocationV1 {
                allocation_id: Uuid::from_u128(0x102),
                child_index: 10,
                compressed_public_key_hex: compressed_public_key(1),
            },
            refund: LocalChainSwapRecoveryAllocationV1 {
                allocation_id: Uuid::from_u128(0x103),
                child_index: 11,
                compressed_public_key_hex: compressed_public_key(2),
            },
            claim_preimage_sha256: "11".repeat(32),
            canonical_creation_response_sha256: "22".repeat(32),
        }
    }

    fn provider_record(
        provider_swap_id: &str,
        kind: BoltzRestoreKind,
    ) -> ValidatedBoltzRestoreRecord {
        let (purposes, first_index) = match kind {
            BoltzRestoreKind::Chain => (
                vec![
                    BoltzRestoreKeyPurpose::ChainClaim,
                    BoltzRestoreKeyPurpose::ChainRefund,
                ],
                20,
            ),
            BoltzRestoreKind::Reverse => (vec![BoltzRestoreKeyPurpose::ReverseClaim], 30),
        };
        let keys = purposes
            .into_iter()
            .enumerate()
            .map(|(offset, purpose)| ValidatedBoltzRestoreKey {
                purpose,
                child_index: first_index + u32::try_from(offset).unwrap(),
                public_key_hex: compressed_public_key(10 + u8::try_from(offset).unwrap()),
                preimage_sha256_hex: (purpose != BoltzRestoreKeyPurpose::ChainRefund)
                    .then(|| "33".repeat(32)),
            })
            .collect();
        ValidatedBoltzRestoreRecord {
            provider_swap_id: provider_swap_id.into(),
            kind,
            status: "transaction.mempool".into(),
            created_at: 1_784_000_000,
            keys,
        }
    }

    fn provider_set(records: Vec<ValidatedBoltzRestoreRecord>) -> ValidatedBoltzRestoreSet {
        let max_child_index = records
            .iter()
            .flat_map(|record| record.keys.iter())
            .map(|key| key.child_index)
            .max();
        ValidatedBoltzRestoreSet {
            records,
            max_child_index,
        }
    }

    fn invalid_manifest(provider_sentinel: &str) -> SwapManifestV1 {
        serde_json::from_value(json!({
            "format": SWAP_MANIFEST_FORMAT,
            "version": SWAP_MANIFEST_VERSION,
            "restore_identity": {
                "manifest_id": Uuid::from_u128(1),
                "manifest_sequence": 1,
                "previous_manifest_id": null,
                "chain_swap_id": Uuid::from_u128(2),
                "boltz_swap_id": provider_sentinel,
                "created_at_unix": 1
            },
            "derivation_lineage": {
                "root_fingerprint": "invalid",
                "key_epoch": 1,
                "derivation_scheme_version": 1,
                "allocation_high_water_child_index": 1,
                "claim": {
                    "allocation_id": Uuid::from_u128(3),
                    "child_index": 0,
                    "purpose": "chain_claim",
                    "public_key_hex": provider_sentinel,
                    "preimage_hash_hex": null
                },
                "refund": {
                    "allocation_id": Uuid::from_u128(4),
                    "child_index": 1,
                    "purpose": "chain_refund",
                    "public_key_hex": provider_sentinel,
                    "preimage_hash_hex": null
                }
            },
            "creation": {
                "lockup_address": "invalid",
                "lockup_bip21": "invalid",
                "user_lock_amount_sat": 1,
                "server_lock_amount_sat": 1,
                "canonical_provider_response_json": "{}",
                "pinned_pair_hash": "00",
                "canonical_pair_quote_json": "{}",
                "creation_response_sha256": "00",
                "btc_claim_script_sha256": "00",
                "btc_refund_script_sha256": "00",
                "liquid_claim_script_sha256": "00",
                "liquid_refund_script_sha256": "00",
                "btc_timeout_height": 1,
                "liquid_timeout_height": 1,
                "btc_network": "bitcoin",
                "liquid_network": "liquid",
                "liquid_asset_id": "invalid",
                "merchant_liquid_destination": "invalid",
                "merchant_emergency_btc_address": null
            },
            "merchant_policy": {
                "invoice_id": Uuid::from_u128(5),
                "merchant_nym": provider_sentinel,
                "merchant_liquid_destination": "invalid",
                "emergency_bitcoin_commitment_id": null,
                "merchant_emergency_btc_address": null
            }
        }))
        .unwrap()
    }

    fn tight_limits() -> RecoveryShadowLimitsV1 {
        RecoveryShadowLimitsV1 {
            manifest_records: 1,
            local_records: 1,
            local_lineages: 1,
            boltz_records: 1,
            boltz_keys: 2,
        }
    }

    fn assert_trace(actual: &Trace, expected: &[&'static str]) {
        assert_eq!(&*actual.lock().unwrap(), expected);
    }

    #[tokio::test]
    async fn empty_sources_produce_one_consistent_report_in_fixed_order() {
        let calls = trace();
        let coordinator = RecoveryShadowAuditCoordinatorV1::new(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(&calls, Ok(empty_local_snapshot())),
            fake_boltz(&calls, Ok(empty_boltz_restore())),
        );

        let report = coordinator.run_once().await.unwrap();

        assert_eq!(
            report,
            RecoveryShadowReportV1 {
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
            }
        );
        assert_trace(&calls, &["witness", "local", "boltz"]);
    }

    #[tokio::test]
    async fn provider_and_local_only_records_are_sanitized_shadow_candidates() {
        let calls = trace();
        let local_record = local_only_record();
        let local_id = local_record.chain_swap_id;
        let local_key = local_record.claim.compressed_public_key_hex.clone();
        let local = LocalChainSwapRecoverySnapshotV1 {
            records: vec![local_record],
            summary: LocalChainSwapRecoverySnapshotSummaryV1 {
                record_count: 1,
                lineage_high_waters: vec![LocalRecoveryLineageHighWaterV1 {
                    root_fingerprint: ROOT_SENTINEL.into(),
                    key_epoch: 1,
                    derivation_scheme_version: 1,
                    child_index: 11,
                }],
            },
        };
        let provider = provider_set(vec![provider_record(
            PROVIDER_SENTINEL,
            BoltzRestoreKind::Chain,
        )]);
        let coordinator = RecoveryShadowAuditCoordinatorV1::new(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(&calls, Ok(local)),
            fake_boltz(&calls, Ok(provider)),
        );

        let report = coordinator.run_once().await.unwrap();

        assert_eq!(
            report.classification,
            RecoveryShadowClassificationV1::DifferencesClassified
        );
        assert_eq!(report.boltz.provider_only_chain_record_count, 1);
        assert_eq!(
            report.boltz.coverage,
            RecoveryShadowCoverageV1::CandidatesPresent
        );
        assert_eq!(report.local.local_only_record_count, 1);
        assert_eq!(report.local.manifest_only_record_count, 0);
        assert_eq!(report.local.lineage_classifications.manifest_missing, 1);
        assert_eq!(report.local.local_max_child_index, Some(11));
        assert_eq!(
            report.local.coverage,
            RecoveryShadowCoverageV1::CandidatesPresent
        );

        let debug = format!("{report:?}");
        for forbidden in [
            PROVIDER_SENTINEL,
            ROOT_SENTINEL,
            &local_id.to_string(),
            &local_key,
            &"11".repeat(32),
            &"22".repeat(32),
        ] {
            assert!(!debug.contains(forbidden), "report leaked {forbidden:?}");
        }
        assert_trace(&calls, &["witness", "local", "boltz"]);
    }

    #[test]
    fn every_lineage_relation_is_counted_without_retaining_identities() {
        let manifest_set = SwapManifestSetAuditV1 {
            manifest_count: 2,
            last_manifest_sequence: Some(2),
            last_manifest_id: Some(Uuid::from_u128(0x999)),
            lineage_high_waters: vec![ManifestLineageHighWaterV1 {
                root_fingerprint: ROOT_SENTINEL.into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                child_index: 12,
            }],
        };
        let boltz_restore = provider_set(vec![
            provider_record(PROVIDER_SENTINEL, BoltzRestoreKind::Chain),
            provider_record("ReverseIdentityMustNotEscape", BoltzRestoreKind::Reverse),
        ]);
        let boltz_audit = SwapManifestBoltzAuditV1 {
            manifest_set: manifest_set.clone(),
            provider_only_chain_swap_ids: vec![PROVIDER_SENTINEL.into()],
            provider_only_chain_record_count: 1,
            provider_max_child_index: Some(30),
        };
        let relations = [
            LocalRecoveryHighWaterRelationV1::Equal,
            LocalRecoveryHighWaterRelationV1::LocalAhead,
            LocalRecoveryHighWaterRelationV1::LocalBehind,
            LocalRecoveryHighWaterRelationV1::LocalMissing,
            LocalRecoveryHighWaterRelationV1::ManifestMissing,
        ];
        let lineage_high_waters = relations
            .into_iter()
            .enumerate()
            .map(|(index, relation)| LocalRecoveryLineageComparisonV1 {
                root_fingerprint: format!("{index:016x}"),
                key_epoch: 1,
                derivation_scheme_version: 1,
                signed_manifest_child_index: (relation
                    != LocalRecoveryHighWaterRelationV1::ManifestMissing)
                    .then_some(12),
                local_child_index: (relation != LocalRecoveryHighWaterRelationV1::LocalMissing)
                    .then_some(10 + i64::try_from(index).unwrap()),
                relation,
            })
            .collect();
        let manifest_only_id = Uuid::from_u128(0x888);
        let local_only_id = Uuid::from_u128(0x777);
        let local_audit = LocalChainSwapRecoveryAuditV1 {
            manifest_set,
            local_record_count: 2,
            exact_match_count: 1,
            manifest_only_chain_swap_ids: vec![manifest_only_id],
            local_only_chain_swap_ids: vec![local_only_id],
            lineage_high_waters,
        };

        let report = build_report(&boltz_restore, &boltz_audit, &local_audit);

        assert_eq!(report.manifest_count, 2);
        assert_eq!(report.manifest_lineage_count, 1);
        assert_eq!(report.manifest_max_child_index, Some(12));
        assert_eq!(report.boltz.chain_record_count, 1);
        assert_eq!(report.boltz.reverse_record_count, 1);
        assert_eq!(report.local.manifest_only_record_count, 1);
        assert_eq!(report.local.local_only_record_count, 1);
        assert_eq!(
            report.local.lineage_classifications,
            RecoveryShadowLineageClassificationsV1 {
                equal: 1,
                local_ahead: 1,
                local_behind: 1,
                local_missing: 1,
                manifest_missing: 1,
            }
        );
        assert_eq!(report.local.local_lineage_count, 4);
        assert_eq!(report.local.local_max_child_index, Some(14));
        assert_eq!(
            report.classification,
            RecoveryShadowClassificationV1::DifferencesClassified
        );

        let debug = format!("{report:?}");
        for forbidden in [
            PROVIDER_SENTINEL,
            ROOT_SENTINEL,
            &manifest_only_id.to_string(),
            &local_only_id.to_string(),
        ] {
            assert!(!debug.contains(forbidden));
        }
    }

    #[test]
    fn provider_local_high_water_relation_preserves_permanent_local_gaps() {
        use RecoveryShadowProviderLocalHighWaterRelationV1 as Relation;

        for (provider, local, expected) in [
            (None, None, Relation::BothEmpty),
            (Some(30), Some(30), Relation::Equal),
            (Some(30), Some(31), Relation::LocalAhead),
            (None, Some(31), Relation::LocalAhead),
            (Some(30), Some(29), Relation::ProviderAhead),
            (Some(30), None, Relation::ProviderAhead),
        ] {
            assert_eq!(compare_provider_local_high_water(provider, local), expected);
        }
    }

    #[test]
    fn local_ahead_and_manifest_missing_lineages_remain_differences() {
        for classifications in [
            RecoveryShadowLineageClassificationsV1 {
                local_ahead: 1,
                ..RecoveryShadowLineageClassificationsV1::default()
            },
            RecoveryShadowLineageClassificationsV1 {
                manifest_missing: 1,
                ..RecoveryShadowLineageClassificationsV1::default()
            },
        ] {
            assert!(classifications.has_differences());
        }
    }

    #[test]
    fn provider_ahead_high_water_closes_otherwise_exact_startup_evidence() {
        let manifest_set = SwapManifestSetAuditV1 {
            manifest_count: 1,
            last_manifest_sequence: Some(1),
            last_manifest_id: Some(Uuid::from_u128(0x901)),
            lineage_high_waters: vec![ManifestLineageHighWaterV1 {
                root_fingerprint: ROOT_SENTINEL.into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                child_index: 29,
            }],
        };
        let provider = provider_set(vec![
            provider_record("ExistingChainRecord", BoltzRestoreKind::Chain),
            provider_record("MissingReverseRecord", BoltzRestoreKind::Reverse),
        ]);
        let boltz_audit = SwapManifestBoltzAuditV1 {
            manifest_set: manifest_set.clone(),
            provider_only_chain_swap_ids: Vec::new(),
            provider_only_chain_record_count: 0,
            provider_max_child_index: Some(30),
        };
        let local_audit = LocalChainSwapRecoveryAuditV1 {
            manifest_set,
            local_record_count: 1,
            exact_match_count: 1,
            manifest_only_chain_swap_ids: Vec::new(),
            local_only_chain_swap_ids: Vec::new(),
            lineage_high_waters: vec![LocalRecoveryLineageComparisonV1 {
                root_fingerprint: ROOT_SENTINEL.into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                signed_manifest_child_index: Some(29),
                local_child_index: Some(29),
                relation: LocalRecoveryHighWaterRelationV1::Equal,
            }],
        };

        let report = build_report(&provider, &boltz_audit, &local_audit);

        assert_eq!(report.boltz.coverage, RecoveryShadowCoverageV1::Exact);
        assert_eq!(report.local.coverage, RecoveryShadowCoverageV1::Exact);
        assert_eq!(report.local.lineage_classifications.equal, 1);
        assert_eq!(
            report.provider_local_high_water_relation,
            RecoveryShadowProviderLocalHighWaterRelationV1::ProviderAhead
        );
        assert_eq!(
            report.classification,
            RecoveryShadowClassificationV1::DifferencesClassified
        );
        let debug = format!("{report:?}");
        assert!(!debug.contains("MissingReverseRecord"));
        assert!(!debug.contains(ROOT_SENTINEL));
    }

    #[tokio::test]
    async fn source_failures_collapse_and_stop_in_deterministic_order() {
        let calls = trace();
        let error = RecoveryShadowAuditCoordinatorV1::new(
            fake_witness(&calls, Err(RecoveryWitnessLoadError::StoreReadFailed)),
            fake_local(&calls, Ok(empty_local_snapshot())),
            fake_boltz(&calls, Ok(empty_boltz_restore())),
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::WitnessLoadFailed);
        assert_trace(&calls, &["witness"]);

        let calls = trace();
        let error = RecoveryShadowAuditCoordinatorV1::new(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(
                &calls,
                Err(LocalRecoverySnapshotReadErrorV1::Database(
                    LocalRecoverySnapshotReadStageV1::ReadRecords,
                )),
            ),
            fake_boltz(&calls, Ok(empty_boltz_restore())),
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::LocalSnapshotLoadFailed);
        assert_trace(&calls, &["witness", "local"]);

        let calls = trace();
        let error = RecoveryShadowAuditCoordinatorV1::new(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(&calls, Ok(empty_local_snapshot())),
            fake_boltz(&calls, Err(BoltzRestoreFetchError::InvalidRecords)),
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::BoltzRestoreFetchFailed);
        assert_trace(&calls, &["witness", "local", "boltz"]);
    }

    #[tokio::test]
    async fn every_coordinator_limit_precedes_audit_or_later_source_work() {
        let limits = tight_limits();
        let calls = trace();
        let poison = invalid_manifest(PROVIDER_SENTINEL);
        let error = RecoveryShadowAuditCoordinatorV1::with_test_limits(
            fake_witness(&calls, Ok(vec![poison.clone(), poison])),
            fake_local(&calls, Ok(empty_local_snapshot())),
            fake_boltz(&calls, Ok(empty_boltz_restore())),
            limits,
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(
            error,
            RecoveryShadowAuditErrorV1::WitnessRecordLimitExceeded
        );
        assert_trace(&calls, &["witness"]);

        let calls = trace();
        let record = local_only_record();
        let oversized_local = LocalChainSwapRecoverySnapshotV1 {
            records: vec![record.clone(), record],
            summary: LocalChainSwapRecoverySnapshotSummaryV1 {
                record_count: 2,
                lineage_high_waters: Vec::new(),
            },
        };
        let error = RecoveryShadowAuditCoordinatorV1::with_test_limits(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(&calls, Ok(oversized_local)),
            fake_boltz(&calls, Ok(empty_boltz_restore())),
            limits,
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::LocalRecordLimitExceeded);
        assert_trace(&calls, &["witness", "local"]);

        let calls = trace();
        let high_water = LocalRecoveryLineageHighWaterV1 {
            root_fingerprint: ROOT_SENTINEL.into(),
            key_epoch: 1,
            derivation_scheme_version: 1,
            child_index: 1,
        };
        let oversized_lineages = LocalChainSwapRecoverySnapshotV1 {
            records: Vec::new(),
            summary: LocalChainSwapRecoverySnapshotSummaryV1 {
                record_count: 0,
                lineage_high_waters: vec![high_water.clone(), high_water],
            },
        };
        let error = RecoveryShadowAuditCoordinatorV1::with_test_limits(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(&calls, Ok(oversized_lineages)),
            fake_boltz(&calls, Ok(empty_boltz_restore())),
            limits,
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::LocalLineageLimitExceeded);
        assert_trace(&calls, &["witness", "local"]);

        let calls = trace();
        let record = provider_record(PROVIDER_SENTINEL, BoltzRestoreKind::Chain);
        let error = RecoveryShadowAuditCoordinatorV1::with_test_limits(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(&calls, Ok(empty_local_snapshot())),
            fake_boltz(&calls, Ok(provider_set(vec![record.clone(), record]))),
            limits,
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::BoltzRecordLimitExceeded);
        assert_trace(&calls, &["witness", "local", "boltz"]);

        let calls = trace();
        let mut record = provider_record(PROVIDER_SENTINEL, BoltzRestoreKind::Chain);
        record.keys.push(ValidatedBoltzRestoreKey {
            purpose: BoltzRestoreKeyPurpose::ReverseClaim,
            child_index: 99,
            public_key_hex: compressed_public_key(99),
            preimage_sha256_hex: Some("44".repeat(32)),
        });
        let error = RecoveryShadowAuditCoordinatorV1::with_test_limits(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(&calls, Ok(empty_local_snapshot())),
            fake_boltz(&calls, Ok(provider_set(vec![record]))),
            limits,
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::BoltzKeyLimitExceeded);
        assert_trace(&calls, &["witness", "local", "boltz"]);
    }

    #[tokio::test]
    async fn cross_audit_failures_are_collapsed_without_raw_evidence() {
        let calls = trace();
        let error = RecoveryShadowAuditCoordinatorV1::new(
            fake_witness(&calls, Ok(vec![invalid_manifest(PROVIDER_SENTINEL)])),
            fake_local(&calls, Ok(empty_local_snapshot())),
            fake_boltz(&calls, Ok(empty_boltz_restore())),
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::ManifestBoltzAuditFailed);
        assert!(!format!("{error:?} {error}").contains(PROVIDER_SENTINEL));

        let calls = trace();
        let duplicate = provider_record(PROVIDER_SENTINEL, BoltzRestoreKind::Chain);
        let error = RecoveryShadowAuditCoordinatorV1::new(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(&calls, Ok(empty_local_snapshot())),
            fake_boltz(&calls, Ok(provider_set(vec![duplicate.clone(), duplicate]))),
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::ManifestBoltzAuditFailed);
        assert!(!format!("{error:?} {error}").contains(PROVIDER_SENTINEL));

        let calls = trace();
        let inconsistent_local = LocalChainSwapRecoverySnapshotV1 {
            records: Vec::new(),
            summary: LocalChainSwapRecoverySnapshotSummaryV1 {
                record_count: 1,
                lineage_high_waters: Vec::new(),
            },
        };
        let error = RecoveryShadowAuditCoordinatorV1::new(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(&calls, Ok(inconsistent_local)),
            fake_boltz(&calls, Ok(empty_boltz_restore())),
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::ManifestLocalAuditFailed);
    }

    #[test]
    fn every_error_is_fixed_bounded_redacted_and_source_free() {
        let errors = [
            RecoveryShadowAuditErrorV1::WitnessLoadFailed,
            RecoveryShadowAuditErrorV1::WitnessRecordLimitExceeded,
            RecoveryShadowAuditErrorV1::LocalSnapshotLoadFailed,
            RecoveryShadowAuditErrorV1::LocalRecordLimitExceeded,
            RecoveryShadowAuditErrorV1::LocalLineageLimitExceeded,
            RecoveryShadowAuditErrorV1::BoltzRestoreFetchFailed,
            RecoveryShadowAuditErrorV1::BoltzRecordLimitExceeded,
            RecoveryShadowAuditErrorV1::BoltzKeyLimitExceeded,
            RecoveryShadowAuditErrorV1::ManifestBoltzAuditFailed,
            RecoveryShadowAuditErrorV1::ManifestLocalAuditFailed,
        ];

        for error in errors {
            let rendered = format!("{error:?} {error}");
            assert!(rendered.len() <= 96, "unbounded error: {rendered}");
            for forbidden in [
                PROVIDER_SENTINEL,
                ROOT_SENTINEL,
                ENDPOINT_SENTINEL,
                TEST_MNEMONIC,
                "postgres://",
                "ciphertext",
                "private",
            ] {
                assert!(!rendered.contains(forbidden));
            }
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn coordinator_and_real_boltz_adapter_debug_are_fully_redacted() {
        let calls = trace();
        let coordinator = RecoveryShadowAuditCoordinatorV1::new(
            fake_witness(&calls, Ok(vec![invalid_manifest(PROVIDER_SENTINEL)])),
            fake_local(&calls, Ok(empty_local_snapshot())),
            fake_boltz(
                &calls,
                Ok(provider_set(vec![provider_record(
                    PROVIDER_SENTINEL,
                    BoltzRestoreKind::Chain,
                )])),
            ),
        );
        let debug = format!("{coordinator:?}");
        assert!(debug.contains("<redacted source>"));
        assert!(!debug.contains(PROVIDER_SENTINEL));
        assert!(!debug.contains(ROOT_SENTINEL));

        let fetcher = BoltzRestoreFetcher::new(&format!("https://{ENDPOINT_SENTINEL}/v2")).unwrap();
        let master_key =
            SwapMasterKey::from_mnemonic(TEST_MNEMONIC, None, Network::Mainnet).unwrap();
        let adapter = RecoveryShadowBoltzFetcherV1::new(&fetcher, &master_key);
        let debug = format!("{adapter:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(ENDPOINT_SENTINEL));
        assert!(!debug.contains(TEST_MNEMONIC));
        assert!(!debug.contains(&master_key.get_master_xpub().to_string()));
    }
}

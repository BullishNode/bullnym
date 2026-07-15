//! One-shot, three-source recovery shadow audit.
//!
//! This module composes the existing authenticated manifest-witness loader,
//! read-only PostgreSQL snapshot adapter, and bounded validated Boltz xpub
//! restore fetcher. It produces only counts, high-waters, and classifications.
//! It deliberately performs no reconstruction, persistence, admission change,
//! worker scheduling, chain lookup, or runtime/configuration wiring.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use async_trait::async_trait;
use boltz_client::util::secrets::SwapMasterKey;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::boltz_restore::{
    BoltzRestoreKeyPurpose, BoltzRestoreKind, ValidatedBoltzRestoreRecord, ValidatedBoltzRestoreSet,
};
use crate::boltz_restore_fetch::{BoltzRestoreFetchError, BoltzRestoreFetcher};
use crate::db::{load_local_chain_swap_recovery_snapshot_v1, LocalRecoverySnapshotReadErrorV1};
use crate::local_chain_swap_recovery_audit::{
    audit_manifest_set_against_local_recovery_snapshot_v1, LocalChainSwapRecoveryAuditError,
    LocalChainSwapRecoveryAuditV1, LocalChainSwapRecoverySnapshotV1,
    LocalChainSwapRecoveryStructuralClassV1, LocalRecoveryHighWaterRelationV1,
    MAX_RECOVERY_AUDIT_CHAIN_INVENTORY_RECORDS_V1, MAX_RECOVERY_AUDIT_LOCAL_LINEAGES_V1,
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
        active_root_fingerprint: &str,
    ) -> Result<LocalChainSwapRecoverySnapshotV1, LocalRecoverySnapshotReadErrorV1>;
}

#[async_trait]
impl RecoveryShadowLocalSnapshotSourceV1 for PgPool {
    async fn load_validated_local_snapshot(
        &self,
        active_root_fingerprint: &str,
    ) -> Result<LocalChainSwapRecoverySnapshotV1, LocalRecoverySnapshotReadErrorV1> {
        load_local_chain_swap_recovery_snapshot_v1(self, active_root_fingerprint).await
    }
}

/// Injectable boundary for one bounded, validated provider restore fetch.
#[async_trait]
pub trait RecoveryShadowBoltzSourceV1: Send + Sync {
    /// Stable non-secret identifier for the configured xpub restore root.
    fn active_root_fingerprint(&self) -> Option<String>;

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
    fn active_root_fingerprint(&self) -> Option<String> {
        let keypair = self.swap_master_key.derive_swapkey(0).ok()?;
        let digest = Sha256::digest(keypair.public_key().serialize());
        Some(hex::encode(&digest[..8]))
    }

    async fn fetch_validated_boltz_restore(
        &self,
    ) -> Result<ValidatedBoltzRestoreSet, BoltzRestoreFetchError> {
        self.fetcher.fetch_and_validate(self.swap_master_key).await
    }
}

/// Whether one cross-source comparison found exact accepted coverage (signed
/// current-v1 or strictly fenced complete legacy) or retained candidates.
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
    fn has_unsafe_differences(self) -> bool {
        // Reverse swaps and committed-before-provider orphan reservations can
        // legitimately create an allocator lineage with no chain manifest at
        // all. Exact manifest/local record coverage proves such a
        // `manifest_missing` lineage is allocator-only. The active-root
        // provider/local high-water comparison below remains the authoritative
        // safety check: provider-ahead still fails closed.
        self.local_behind != 0 || self.local_missing != 0
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
    /// Allocation high-water for the active provider root only. Allocations
    /// retained under an older root cannot mask provider-ahead evidence.
    pub local_max_child_index: Option<i64>,
    pub lineage_classifications: RecoveryShadowLineageClassificationsV1,
    pub coverage: RecoveryShadowCoverageV1,
}

/// Sanitized exact-set accounting across provider and every local chain-swap
/// generation. It intentionally contains counts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryShadowChainInventoryReportV1 {
    pub local_chain_record_count: usize,
    pub current_v1_record_count: usize,
    pub complete_legacy_record_count: usize,
    pub exact_provider_local_id_count: usize,
    pub legacy_provider_key_count: usize,
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
    pub chain_inventory: RecoveryShadowChainInventoryReportV1,
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
    ChainInventoryAuditFailed,
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
            Self::ChainInventoryAuditFailed => {
                "recovery shadow all-chain inventory comparison failed"
            }
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

        let active_root_fingerprint = self
            .boltz
            .active_root_fingerprint()
            .ok_or(RecoveryShadowAuditErrorV1::BoltzRestoreFetchFailed)?;
        let local_snapshot = self
            .local
            .load_validated_local_snapshot(&active_root_fingerprint)
            .await
            .map_err(|_| RecoveryShadowAuditErrorV1::LocalSnapshotLoadFailed)?;
        if local_snapshot.summary.active_root_fingerprint != active_root_fingerprint {
            return Err(RecoveryShadowAuditErrorV1::ChainInventoryAuditFailed);
        }
        if local_snapshot.records.len() > self.limits.local_records {
            return Err(RecoveryShadowAuditErrorV1::LocalRecordLimitExceeded);
        }
        if local_snapshot.summary.chain_inventory.len()
            > MAX_RECOVERY_AUDIT_CHAIN_INVENTORY_RECORDS_V1.min(self.limits.local_records)
        {
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
        let chain_inventory = audit_complete_chain_inventory_v1(
            &manifests,
            &local_snapshot,
            &boltz_restore,
            &local_audit,
            &active_root_fingerprint,
        )
        .map_err(|_| RecoveryShadowAuditErrorV1::ChainInventoryAuditFailed)?;

        let active_root_local_max_child_index =
            active_root_local_high_water(&local_snapshot, &active_root_fingerprint);
        let report = build_report(
            &boltz_restore,
            &boltz_audit,
            &local_audit,
            chain_inventory,
            active_root_local_max_child_index,
        );
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompleteChainInventoryAuditErrorV1 {
    DuplicateProviderChainId,
    DuplicateLocalChainId,
    ProviderLocalSetMismatch,
    CurrentEvidenceSetMismatch,
    CurrentManifestSetMismatch,
    CurrentManifestAuditMismatch,
    CurrentActiveRootMismatch,
    MissingActiveRootLegacyHighWater,
    LegacyMigration044RootMismatch,
    LegacyMigration044RoleMismatch,
    LegacyProviderKeyShapeInvalid,
    LegacyProviderKeyAboveHighWater,
    CountOverflow,
}

fn audit_complete_chain_inventory_v1(
    manifests: &[SwapManifestV1],
    local: &LocalChainSwapRecoverySnapshotV1,
    boltz_restore: &ValidatedBoltzRestoreSet,
    local_audit: &LocalChainSwapRecoveryAuditV1,
    active_root_fingerprint: &str,
) -> Result<RecoveryShadowChainInventoryReportV1, CompleteChainInventoryAuditErrorV1> {
    let mut provider_chain = BTreeMap::<&str, &ValidatedBoltzRestoreRecord>::new();
    for record in boltz_restore
        .records
        .iter()
        .filter(|record| record.kind == BoltzRestoreKind::Chain)
    {
        if provider_chain
            .insert(record.provider_swap_id.as_str(), record)
            .is_some()
        {
            return Err(CompleteChainInventoryAuditErrorV1::DuplicateProviderChainId);
        }
    }

    let mut local_inventory = BTreeMap::new();
    let mut current_ids = BTreeSet::new();
    let mut complete_legacy_ids = BTreeSet::new();
    for record in &local.summary.chain_inventory {
        if local_inventory
            .insert(record.boltz_swap_id.as_str(), record)
            .is_some()
        {
            return Err(CompleteChainInventoryAuditErrorV1::DuplicateLocalChainId);
        }
        match record.structural_class {
            LocalChainSwapRecoveryStructuralClassV1::CurrentV1 => {
                current_ids.insert(record.boltz_swap_id.as_str());
            }
            LocalChainSwapRecoveryStructuralClassV1::CompleteLegacy => {
                complete_legacy_ids.insert(record.boltz_swap_id.as_str());
            }
        }
    }

    let provider_ids = provider_chain.keys().copied().collect::<BTreeSet<_>>();
    let local_ids = local_inventory.keys().copied().collect::<BTreeSet<_>>();
    if provider_ids != local_ids {
        return Err(CompleteChainInventoryAuditErrorV1::ProviderLocalSetMismatch);
    }
    let current_evidence_ids = local
        .records
        .iter()
        .map(|record| record.boltz_swap_id.as_str())
        .collect::<BTreeSet<_>>();
    if current_ids != current_evidence_ids {
        return Err(CompleteChainInventoryAuditErrorV1::CurrentEvidenceSetMismatch);
    }
    let manifested_ids = manifests
        .iter()
        .map(|manifest| manifest.restore_identity.boltz_swap_id.as_str())
        .collect::<BTreeSet<_>>();
    if current_ids != manifested_ids {
        return Err(CompleteChainInventoryAuditErrorV1::CurrentManifestSetMismatch);
    }
    if manifests
        .iter()
        .any(|manifest| manifest.derivation_lineage.root_fingerprint != active_root_fingerprint)
        || local
            .records
            .iter()
            .any(|record| record.root_fingerprint != active_root_fingerprint)
    {
        return Err(CompleteChainInventoryAuditErrorV1::CurrentActiveRootMismatch);
    }
    if local_audit.exact_match_count != current_ids.len()
        || !local_audit.manifest_only_chain_swap_ids.is_empty()
        || !local_audit.local_only_chain_swap_ids.is_empty()
    {
        return Err(CompleteChainInventoryAuditErrorV1::CurrentManifestAuditMismatch);
    }

    let mut legacy_provider_key_count = 0_usize;
    if !complete_legacy_ids.is_empty() {
        let legacy_high_water = local
            .summary
            .active_root_legacy_high_water
            .ok_or(CompleteChainInventoryAuditErrorV1::MissingActiveRootLegacyHighWater)?;
        for provider_id in &complete_legacy_ids {
            let local_record = local_inventory
                .get(provider_id)
                .ok_or(CompleteChainInventoryAuditErrorV1::ProviderLocalSetMismatch)?;
            let provider_record = provider_chain
                .get(provider_id)
                .ok_or(CompleteChainInventoryAuditErrorV1::ProviderLocalSetMismatch)?;
            if provider_record.keys.len() != 2 {
                return Err(CompleteChainInventoryAuditErrorV1::LegacyProviderKeyShapeInvalid);
            }
            let mut claims = provider_record
                .keys
                .iter()
                .filter(|key| key.purpose == BoltzRestoreKeyPurpose::ChainClaim);
            let mut refunds = provider_record
                .keys
                .iter()
                .filter(|key| key.purpose == BoltzRestoreKeyPurpose::ChainRefund);
            let Some(claim) = claims.next() else {
                return Err(CompleteChainInventoryAuditErrorV1::LegacyProviderKeyShapeInvalid);
            };
            let Some(refund) = refunds.next() else {
                return Err(CompleteChainInventoryAuditErrorV1::LegacyProviderKeyShapeInvalid);
            };
            if claims.next().is_some() || refunds.next().is_some() {
                return Err(CompleteChainInventoryAuditErrorV1::LegacyProviderKeyShapeInvalid);
            }
            legacy_provider_key_count = legacy_provider_key_count
                .checked_add(provider_record.keys.len())
                .ok_or(CompleteChainInventoryAuditErrorV1::CountOverflow)?;
            if provider_record
                .keys
                .iter()
                .any(|key| i64::from(key.child_index) > legacy_high_water)
            {
                return Err(CompleteChainInventoryAuditErrorV1::LegacyProviderKeyAboveHighWater);
            }
            if let Some(legacy) = &local_record.legacy_derivation {
                if legacy.root_fingerprint != active_root_fingerprint {
                    return Err(CompleteChainInventoryAuditErrorV1::LegacyMigration044RootMismatch);
                }
                if i64::from(claim.child_index) != legacy.claim_child_index
                    || i64::from(refund.child_index) != legacy.refund_child_index
                {
                    return Err(CompleteChainInventoryAuditErrorV1::LegacyMigration044RoleMismatch);
                }
            }
        }
    }

    Ok(RecoveryShadowChainInventoryReportV1 {
        local_chain_record_count: local_ids.len(),
        current_v1_record_count: current_ids.len(),
        complete_legacy_record_count: complete_legacy_ids.len(),
        exact_provider_local_id_count: provider_ids.len(),
        legacy_provider_key_count,
    })
}

fn build_report(
    boltz_restore: &ValidatedBoltzRestoreSet,
    boltz_audit: &SwapManifestBoltzAuditV1,
    local_audit: &LocalChainSwapRecoveryAuditV1,
    chain_inventory: RecoveryShadowChainInventoryReportV1,
    active_root_local_max_child_index: Option<i64>,
) -> RecoveryShadowReportV1 {
    let chain_record_count = boltz_restore
        .records
        .iter()
        .filter(|record| record.kind == BoltzRestoreKind::Chain)
        .count();
    let reverse_record_count = boltz_restore.records.len() - chain_record_count;
    // The strict inventory audit above proves every provider-only chain record
    // is an exact local complete-legacy identity under the active-root fence.
    let boltz_coverage = RecoveryShadowCoverageV1::Exact;

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
    let local_lineage_count = local_audit
        .lineage_high_waters
        .iter()
        .filter(|comparison| comparison.local_child_index.is_some())
        .count();
    let provider_local_high_water_relation = compare_provider_local_high_water(
        boltz_restore.max_child_index,
        active_root_local_max_child_index,
    );

    let classification = if boltz_coverage == RecoveryShadowCoverageV1::Exact
        && local_coverage == RecoveryShadowCoverageV1::Exact
        && !lineage_classifications.has_unsafe_differences()
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
            local_max_child_index: active_root_local_max_child_index,
            lineage_classifications,
            coverage: local_coverage,
        },
        chain_inventory,
        classification,
    }
}

fn active_root_local_high_water(
    local: &LocalChainSwapRecoverySnapshotV1,
    active_root_fingerprint: &str,
) -> Option<i64> {
    local
        .summary
        .lineage_high_waters
        .iter()
        .filter(|lineage| lineage.root_fingerprint == active_root_fingerprint)
        .map(|lineage| lineage.child_index)
        .max()
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
        LocalChainSwapRecoveryInventoryRecordV1, LocalChainSwapRecoveryLegacyDerivationV1,
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
            _: &str,
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
        fn active_root_fingerprint(&self) -> Option<String> {
            Some(ROOT_SENTINEL.into())
        }

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
                chain_inventory_record_count: 0,
                chain_inventory: Vec::new(),
                active_root_fingerprint: ROOT_SENTINEL.into(),
                active_root_legacy_high_water: None,
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

    fn empty_local_audit() -> LocalChainSwapRecoveryAuditV1 {
        LocalChainSwapRecoveryAuditV1 {
            manifest_set: SwapManifestSetAuditV1 {
                manifest_count: 0,
                last_manifest_sequence: None,
                last_manifest_id: None,
                lineage_high_waters: Vec::new(),
            },
            local_record_count: 0,
            exact_match_count: 0,
            manifest_only_chain_swap_ids: Vec::new(),
            local_only_chain_swap_ids: Vec::new(),
            lineage_high_waters: Vec::new(),
        }
    }

    fn legacy_inventory(
        boltz_swap_id: &str,
        legacy_derivation: Option<LocalChainSwapRecoveryLegacyDerivationV1>,
    ) -> LocalChainSwapRecoveryInventoryRecordV1 {
        LocalChainSwapRecoveryInventoryRecordV1 {
            boltz_swap_id: boltz_swap_id.into(),
            structural_class: LocalChainSwapRecoveryStructuralClassV1::CompleteLegacy,
            legacy_derivation,
        }
    }

    fn legacy_snapshot(
        chain_inventory: Vec<LocalChainSwapRecoveryInventoryRecordV1>,
        active_root_legacy_high_water: Option<i64>,
    ) -> LocalChainSwapRecoverySnapshotV1 {
        LocalChainSwapRecoverySnapshotV1 {
            records: Vec::new(),
            summary: LocalChainSwapRecoverySnapshotSummaryV1 {
                record_count: 0,
                chain_inventory_record_count: chain_inventory.len(),
                chain_inventory,
                active_root_fingerprint: ROOT_SENTINEL.into(),
                active_root_legacy_high_water,
                lineage_high_waters: Vec::new(),
            },
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

    fn provider_chain_record_at(
        provider_swap_id: &str,
        claim_child_index: u32,
        refund_child_index: u32,
    ) -> ValidatedBoltzRestoreRecord {
        let mut record = provider_record(provider_swap_id, BoltzRestoreKind::Chain);
        record.keys[0].child_index = claim_child_index;
        record.keys[1].child_index = refund_child_index;
        record
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

    fn empty_chain_inventory_report() -> RecoveryShadowChainInventoryReportV1 {
        RecoveryShadowChainInventoryReportV1 {
            local_chain_record_count: 0,
            current_v1_record_count: 0,
            complete_legacy_record_count: 0,
            exact_provider_local_id_count: 0,
            legacy_provider_key_count: 0,
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
                chain_inventory: RecoveryShadowChainInventoryReportV1 {
                    local_chain_record_count: 0,
                    current_v1_record_count: 0,
                    complete_legacy_record_count: 0,
                    exact_provider_local_id_count: 0,
                    legacy_provider_key_count: 0,
                },
                classification: RecoveryShadowClassificationV1::Consistent,
            }
        );
        assert_trace(&calls, &["witness", "local", "boltz"]);
    }

    #[tokio::test]
    async fn empty_chain_sources_use_the_active_root_allocator_high_water_fail_safely() {
        let mut reverse = provider_record(
            "ReverseAllocatorHistoryMustNotEscape",
            BoltzRestoreKind::Reverse,
        );
        reverse.keys[0].child_index = 101;
        let provider = provider_set(vec![reverse]);

        for (local_child_index, expected_relation, expected_classification) in [
            (
                101,
                RecoveryShadowProviderLocalHighWaterRelationV1::Equal,
                RecoveryShadowClassificationV1::Consistent,
            ),
            (
                100,
                RecoveryShadowProviderLocalHighWaterRelationV1::ProviderAhead,
                RecoveryShadowClassificationV1::DifferencesClassified,
            ),
        ] {
            let calls = trace();
            let local = LocalChainSwapRecoverySnapshotV1 {
                records: Vec::new(),
                summary: LocalChainSwapRecoverySnapshotSummaryV1 {
                    record_count: 0,
                    chain_inventory_record_count: 0,
                    chain_inventory: Vec::new(),
                    active_root_fingerprint: ROOT_SENTINEL.into(),
                    active_root_legacy_high_water: None,
                    lineage_high_waters: vec![LocalRecoveryLineageHighWaterV1 {
                        root_fingerprint: ROOT_SENTINEL.into(),
                        key_epoch: 1,
                        derivation_scheme_version: 1,
                        child_index: local_child_index,
                    }],
                },
            };
            let report = RecoveryShadowAuditCoordinatorV1::new(
                fake_witness(&calls, Ok(Vec::new())),
                fake_local(&calls, Ok(local)),
                fake_boltz(&calls, Ok(provider.clone())),
            )
            .run_once()
            .await
            .unwrap();

            assert_eq!(report.manifest_count, 0);
            assert_eq!(report.boltz.chain_record_count, 0);
            assert_eq!(report.boltz.reverse_record_count, 1);
            assert_eq!(report.local.local_record_count, 0);
            assert_eq!(report.chain_inventory.local_chain_record_count, 0);
            assert_eq!(report.local.lineage_classifications.manifest_missing, 1);
            assert_eq!(report.provider_local_high_water_relation, expected_relation);
            assert_eq!(report.classification, expected_classification);
            assert_trace(&calls, &["witness", "local", "boltz"]);
        }
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
                chain_inventory_record_count: 1,
                chain_inventory: vec![LocalChainSwapRecoveryInventoryRecordV1 {
                    boltz_swap_id: "LocalOnlyProviderRecord".into(),
                    structural_class: LocalChainSwapRecoveryStructuralClassV1::CurrentV1,
                    legacy_derivation: None,
                }],
                active_root_fingerprint: ROOT_SENTINEL.into(),
                active_root_legacy_high_water: None,
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

        let error = coordinator.run_once().await.unwrap_err();

        assert_eq!(error, RecoveryShadowAuditErrorV1::ChainInventoryAuditFailed);
        let debug = format!("{error:?}");
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
    fn complete_legacy_inventory_requires_exact_ids_roles_and_active_root_fence() {
        let migration_044 = LocalChainSwapRecoveryLegacyDerivationV1 {
            root_fingerprint: ROOT_SENTINEL.into(),
            claim_child_index: 22,
            refund_child_index: 23,
        };
        let local = legacy_snapshot(
            vec![
                legacy_inventory("LegacyPre044", None),
                legacy_inventory("LegacyMigration044", Some(migration_044.clone())),
            ],
            Some(23),
        );
        let provider = provider_set(vec![
            provider_chain_record_at("LegacyPre044", 20, 21),
            provider_chain_record_at("LegacyMigration044", 22, 23),
        ]);
        let report = audit_complete_chain_inventory_v1(
            &[],
            &local,
            &provider,
            &empty_local_audit(),
            ROOT_SENTINEL,
        )
        .unwrap();
        assert_eq!(
            report,
            RecoveryShadowChainInventoryReportV1 {
                local_chain_record_count: 2,
                current_v1_record_count: 0,
                complete_legacy_record_count: 2,
                exact_provider_local_id_count: 2,
                legacy_provider_key_count: 4,
            }
        );

        let missing = legacy_snapshot(
            vec![
                legacy_inventory("LegacyPre044", None),
                legacy_inventory("MissingLocal", None),
            ],
            Some(23),
        );
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[],
                &missing,
                &provider,
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::ProviderLocalSetMismatch)
        );

        let substituted = legacy_snapshot(
            vec![
                legacy_inventory("LegacyPre044", None),
                legacy_inventory("SubstitutedLocal", None),
            ],
            Some(23),
        );
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[],
                &substituted,
                &provider,
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::ProviderLocalSetMismatch)
        );

        let above_high_water =
            legacy_snapshot(vec![legacy_inventory("LegacyPre044", None)], Some(20));
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[],
                &above_high_water,
                &provider_set(vec![provider_chain_record_at("LegacyPre044", 20, 21,)]),
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::LegacyProviderKeyAboveHighWater)
        );

        let wrong_root = legacy_snapshot(
            vec![legacy_inventory(
                "LegacyMigration044",
                Some(LocalChainSwapRecoveryLegacyDerivationV1 {
                    root_fingerprint: "ffeeddccbbaa9988".into(),
                    ..migration_044.clone()
                }),
            )],
            Some(23),
        );
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[],
                &wrong_root,
                &provider_set(vec![
                    provider_chain_record_at("LegacyMigration044", 22, 23,)
                ]),
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::LegacyMigration044RootMismatch)
        );

        let wrong_role = legacy_snapshot(
            vec![legacy_inventory(
                "LegacyMigration044",
                Some(LocalChainSwapRecoveryLegacyDerivationV1 {
                    claim_child_index: 23,
                    refund_child_index: 22,
                    ..migration_044
                }),
            )],
            Some(23),
        );
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[],
                &wrong_role,
                &provider_set(vec![
                    provider_chain_record_at("LegacyMigration044", 22, 23,)
                ]),
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::LegacyMigration044RoleMismatch)
        );
    }

    #[test]
    fn legacy_inventory_rejects_duplicates_partial_roles_and_current_without_witness() {
        let provider_record = provider_chain_record_at("LegacyRecord", 20, 21);
        let duplicate_provider =
            provider_set(vec![provider_record.clone(), provider_record.clone()]);
        let local = legacy_snapshot(vec![legacy_inventory("LegacyRecord", None)], Some(21));
        let no_legacy_fence = legacy_snapshot(vec![legacy_inventory("LegacyRecord", None)], None);
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[],
                &no_legacy_fence,
                &provider_set(vec![provider_record.clone()]),
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::MissingActiveRootLegacyHighWater)
        );
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[],
                &local,
                &duplicate_provider,
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::DuplicateProviderChainId)
        );

        let duplicate_local = legacy_snapshot(
            vec![
                legacy_inventory("LegacyRecord", None),
                legacy_inventory("LegacyRecord", None),
            ],
            Some(21),
        );
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[],
                &duplicate_local,
                &provider_set(vec![provider_record.clone()]),
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::DuplicateLocalChainId)
        );

        let mut duplicate_role = provider_record.clone();
        duplicate_role.keys[1].purpose = BoltzRestoreKeyPurpose::ChainClaim;
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[],
                &local,
                &provider_set(vec![duplicate_role]),
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::LegacyProviderKeyShapeInvalid)
        );

        let mut current = local_only_record();
        current.boltz_swap_id = "CurrentWithoutWitness".into();
        let current_local = LocalChainSwapRecoverySnapshotV1 {
            records: vec![current],
            summary: LocalChainSwapRecoverySnapshotSummaryV1 {
                record_count: 1,
                chain_inventory_record_count: 1,
                chain_inventory: vec![LocalChainSwapRecoveryInventoryRecordV1 {
                    boltz_swap_id: "CurrentWithoutWitness".into(),
                    structural_class: LocalChainSwapRecoveryStructuralClassV1::CurrentV1,
                    legacy_derivation: None,
                }],
                active_root_fingerprint: ROOT_SENTINEL.into(),
                active_root_legacy_high_water: None,
                lineage_high_waters: Vec::new(),
            },
        };
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[],
                &current_local,
                &provider_set(vec![provider_chain_record_at(
                    "CurrentWithoutWitness",
                    20,
                    21,
                )]),
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::CurrentManifestSetMismatch)
        );

        for error in [
            CompleteChainInventoryAuditErrorV1::DuplicateProviderChainId,
            CompleteChainInventoryAuditErrorV1::DuplicateLocalChainId,
            CompleteChainInventoryAuditErrorV1::ProviderLocalSetMismatch,
            CompleteChainInventoryAuditErrorV1::LegacyProviderKeyAboveHighWater,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains("LegacyRecord"));
            assert!(!debug.contains(ROOT_SENTINEL));
        }
    }

    #[test]
    fn current_inventory_root_must_equal_the_authoritative_provider_root() {
        const ALTERNATE_ROOT: &str = "ffeeddccbbaa9988";
        let mut manifest = invalid_manifest("CurrentAlternateRoot");
        manifest.derivation_lineage.root_fingerprint = ALTERNATE_ROOT.into();
        let mut current = local_only_record();
        current.boltz_swap_id = "CurrentAlternateRoot".into();
        current.root_fingerprint = ALTERNATE_ROOT.into();
        let local = LocalChainSwapRecoverySnapshotV1 {
            records: vec![current],
            summary: LocalChainSwapRecoverySnapshotSummaryV1 {
                record_count: 1,
                chain_inventory_record_count: 1,
                chain_inventory: vec![LocalChainSwapRecoveryInventoryRecordV1 {
                    boltz_swap_id: "CurrentAlternateRoot".into(),
                    structural_class: LocalChainSwapRecoveryStructuralClassV1::CurrentV1,
                    legacy_derivation: None,
                }],
                active_root_fingerprint: ALTERNATE_ROOT.into(),
                active_root_legacy_high_water: None,
                lineage_high_waters: Vec::new(),
            },
        };
        assert_eq!(
            audit_complete_chain_inventory_v1(
                &[manifest],
                &local,
                &provider_set(vec![provider_chain_record_at(
                    "CurrentAlternateRoot",
                    20,
                    21,
                )]),
                &empty_local_audit(),
                ROOT_SENTINEL,
            ),
            Err(CompleteChainInventoryAuditErrorV1::CurrentActiveRootMismatch)
        );
    }

    #[tokio::test]
    async fn coordinator_rejects_a_canonical_but_non_authoritative_snapshot_root() {
        const ALTERNATE_ROOT: &str = "ffeeddccbbaa9988";
        let calls = trace();
        let mut local = legacy_snapshot(
            vec![legacy_inventory(
                "LegacyAlternateRoot",
                Some(LocalChainSwapRecoveryLegacyDerivationV1 {
                    root_fingerprint: ALTERNATE_ROOT.into(),
                    claim_child_index: 20,
                    refund_child_index: 21,
                }),
            )],
            Some(21),
        );
        local.summary.active_root_fingerprint = ALTERNATE_ROOT.into();
        let error = RecoveryShadowAuditCoordinatorV1::new(
            fake_witness(&calls, Ok(Vec::new())),
            fake_local(&calls, Ok(local)),
            fake_boltz(
                &calls,
                Ok(provider_set(vec![provider_chain_record_at(
                    "LegacyAlternateRoot",
                    20,
                    21,
                )])),
            ),
        )
        .run_once()
        .await
        .unwrap_err();
        assert_eq!(error, RecoveryShadowAuditErrorV1::ChainInventoryAuditFailed);
        assert_trace(&calls, &["witness", "local"]);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(ALTERNATE_ROOT));
        assert!(!rendered.contains("LegacyAlternateRoot"));
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

        let report = build_report(
            &boltz_restore,
            &boltz_audit,
            &local_audit,
            empty_chain_inventory_report(),
            Some(14),
        );

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
    fn allocator_only_and_local_ahead_lineages_defer_to_the_global_high_water_gate() {
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
            assert!(!classifications.has_unsafe_differences());
        }

        for classifications in [
            RecoveryShadowLineageClassificationsV1 {
                local_behind: 1,
                ..RecoveryShadowLineageClassificationsV1::default()
            },
            RecoveryShadowLineageClassificationsV1 {
                local_missing: 1,
                ..RecoveryShadowLineageClassificationsV1::default()
            },
        ] {
            assert!(classifications.has_unsafe_differences());
        }
    }

    #[test]
    fn empty_chain_authorities_accept_allocator_only_reverse_history_when_not_provider_ahead() {
        let provider = provider_set(vec![provider_record(
            "ReverseHistoryMustNotEscape",
            BoltzRestoreKind::Reverse,
        )]);
        let manifest_set = SwapManifestSetAuditV1 {
            manifest_count: 0,
            last_manifest_sequence: None,
            last_manifest_id: None,
            lineage_high_waters: Vec::new(),
        };
        let boltz_audit = SwapManifestBoltzAuditV1 {
            manifest_set: manifest_set.clone(),
            provider_only_chain_swap_ids: Vec::new(),
            provider_only_chain_record_count: 0,
            provider_max_child_index: Some(30),
        };

        for (local_child_index, expected_relation) in [
            (30, RecoveryShadowProviderLocalHighWaterRelationV1::Equal),
            (
                31,
                RecoveryShadowProviderLocalHighWaterRelationV1::LocalAhead,
            ),
        ] {
            let local_audit = LocalChainSwapRecoveryAuditV1 {
                manifest_set: manifest_set.clone(),
                local_record_count: 0,
                exact_match_count: 0,
                manifest_only_chain_swap_ids: Vec::new(),
                local_only_chain_swap_ids: Vec::new(),
                lineage_high_waters: vec![LocalRecoveryLineageComparisonV1 {
                    root_fingerprint: ROOT_SENTINEL.into(),
                    key_epoch: 1,
                    derivation_scheme_version: 1,
                    signed_manifest_child_index: None,
                    local_child_index: Some(local_child_index),
                    relation: LocalRecoveryHighWaterRelationV1::ManifestMissing,
                }],
            };
            let report = build_report(
                &provider,
                &boltz_audit,
                &local_audit,
                empty_chain_inventory_report(),
                Some(local_child_index),
            );

            assert_eq!(report.manifest_count, 0);
            assert_eq!(report.boltz.chain_record_count, 0);
            assert_eq!(report.local.local_record_count, 0);
            assert_eq!(report.chain_inventory.local_chain_record_count, 0);
            assert_eq!(report.local.lineage_classifications.manifest_missing, 1);
            assert_eq!(report.provider_local_high_water_relation, expected_relation);
            assert_eq!(
                report.classification,
                RecoveryShadowClassificationV1::Consistent
            );
        }
    }

    #[test]
    fn a_different_root_high_water_cannot_mask_active_root_provider_ahead() {
        const RETIRED_ROOT: &str = "ffeeddccbbaa9988";
        let mut local = empty_local_snapshot();
        local.summary.lineage_high_waters = vec![
            LocalRecoveryLineageHighWaterV1 {
                root_fingerprint: ROOT_SENTINEL.into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                child_index: 29,
            },
            LocalRecoveryLineageHighWaterV1 {
                root_fingerprint: RETIRED_ROOT.into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                child_index: 1_000,
            },
        ];
        let active_high_water = active_root_local_high_water(&local, ROOT_SENTINEL);
        assert_eq!(active_high_water, Some(29));

        let provider = provider_set(vec![provider_record(
            "ProviderAheadMustNotEscape",
            BoltzRestoreKind::Reverse,
        )]);
        let mut local_audit = empty_local_audit();
        local_audit.lineage_high_waters = vec![
            LocalRecoveryLineageComparisonV1 {
                root_fingerprint: ROOT_SENTINEL.into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                signed_manifest_child_index: None,
                local_child_index: Some(29),
                relation: LocalRecoveryHighWaterRelationV1::ManifestMissing,
            },
            LocalRecoveryLineageComparisonV1 {
                root_fingerprint: RETIRED_ROOT.into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                signed_manifest_child_index: None,
                local_child_index: Some(1_000),
                relation: LocalRecoveryHighWaterRelationV1::ManifestMissing,
            },
        ];
        let boltz_audit = SwapManifestBoltzAuditV1 {
            manifest_set: local_audit.manifest_set.clone(),
            provider_only_chain_swap_ids: Vec::new(),
            provider_only_chain_record_count: 0,
            provider_max_child_index: Some(30),
        };
        let report = build_report(
            &provider,
            &boltz_audit,
            &local_audit,
            empty_chain_inventory_report(),
            active_high_water,
        );

        assert_eq!(
            report.provider_local_high_water_relation,
            RecoveryShadowProviderLocalHighWaterRelationV1::ProviderAhead
        );
        assert_eq!(
            report.classification,
            RecoveryShadowClassificationV1::DifferencesClassified
        );
        let debug = format!("{report:?}");
        assert!(!debug.contains(RETIRED_ROOT));
        assert!(!debug.contains("ProviderAheadMustNotEscape"));
    }

    #[test]
    fn nonempty_matching_sources_are_consistent_when_provider_is_not_ahead() {
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
            provider_chain_record_at("ExistingChainRecord", 28, 29),
            provider_record("LaterReverseRecord", BoltzRestoreKind::Reverse),
        ]);
        let boltz_audit = SwapManifestBoltzAuditV1 {
            manifest_set: manifest_set.clone(),
            provider_only_chain_swap_ids: Vec::new(),
            provider_only_chain_record_count: 0,
            provider_max_child_index: Some(30),
        };

        for (local_child_index, expected_relation) in [
            (30, RecoveryShadowProviderLocalHighWaterRelationV1::Equal),
            (
                31,
                RecoveryShadowProviderLocalHighWaterRelationV1::LocalAhead,
            ),
        ] {
            let local_audit = LocalChainSwapRecoveryAuditV1 {
                manifest_set: manifest_set.clone(),
                local_record_count: 1,
                exact_match_count: 1,
                manifest_only_chain_swap_ids: Vec::new(),
                local_only_chain_swap_ids: Vec::new(),
                lineage_high_waters: vec![LocalRecoveryLineageComparisonV1 {
                    root_fingerprint: ROOT_SENTINEL.into(),
                    key_epoch: 1,
                    derivation_scheme_version: 1,
                    signed_manifest_child_index: Some(29),
                    local_child_index: Some(local_child_index),
                    relation: LocalRecoveryHighWaterRelationV1::LocalAhead,
                }],
            };

            let report = build_report(
                &provider,
                &boltz_audit,
                &local_audit,
                RecoveryShadowChainInventoryReportV1 {
                    local_chain_record_count: 1,
                    current_v1_record_count: 1,
                    complete_legacy_record_count: 0,
                    exact_provider_local_id_count: 1,
                    legacy_provider_key_count: 0,
                },
                Some(local_child_index),
            );

            assert_eq!(report.local.lineage_classifications.local_ahead, 1);
            assert_eq!(report.provider_local_high_water_relation, expected_relation);
            assert_eq!(
                report.classification,
                RecoveryShadowClassificationV1::Consistent
            );
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

        let report = build_report(
            &provider,
            &boltz_audit,
            &local_audit,
            empty_chain_inventory_report(),
            Some(29),
        );

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
                chain_inventory_record_count: 0,
                chain_inventory: Vec::new(),
                active_root_fingerprint: ROOT_SENTINEL.into(),
                active_root_legacy_high_water: None,
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
                chain_inventory_record_count: 0,
                chain_inventory: Vec::new(),
                active_root_fingerprint: ROOT_SENTINEL.into(),
                active_root_legacy_high_water: None,
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
                chain_inventory_record_count: 0,
                chain_inventory: Vec::new(),
                active_root_fingerprint: ROOT_SENTINEL.into(),
                active_root_legacy_high_water: None,
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
            RecoveryShadowAuditErrorV1::ChainInventoryAuditFailed,
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
        let active_root_fingerprint = adapter.active_root_fingerprint().unwrap();
        assert_eq!(active_root_fingerprint.len(), 16);
        assert!(active_root_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        let debug = format!("{adapter:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(ENDPOINT_SENTINEL));
        assert!(!debug.contains(TEST_MNEMONIC));
        assert!(!debug.contains(&master_key.get_master_xpub().to_string()));
        assert!(!debug.contains(&active_root_fingerprint));
    }
}

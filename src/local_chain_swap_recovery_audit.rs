//! Pure comparison of signed swap manifests with a PostgreSQL snapshot.
//!
//! The types in this module are deliberately storage-neutral. A later database
//! adapter may populate the snapshot, but this audit performs no SQL, I/O,
//! reconstruction, admission decision, or mutation. Missing records are only
//! classified for later policy.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use secp256k1::PublicKey;
use uuid::Uuid;

use crate::swap_manifest::{
    audit_append_only_manifest_set_v1, SwapManifestSetAuditV1, SwapManifestV1,
    MAX_UNHARDENED_SWAP_CHILD_INDEX,
};

/// Maximum signed manifest records accepted by one in-memory comparison.
pub const MAX_RECOVERY_AUDIT_MANIFEST_RECORDS_V1: usize = 10_000;
/// Maximum local chain-swap evidence records accepted by one snapshot.
pub const MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1: usize = 10_000;
/// Maximum all-generation chain-swap identities accepted by one snapshot.
pub const MAX_RECOVERY_AUDIT_CHAIN_INVENTORY_RECORDS_V1: usize =
    MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1;
/// Maximum derivation namespaces accepted in one local snapshot summary.
pub const MAX_RECOVERY_AUDIT_LOCAL_LINEAGES_V1: usize = 4_096;

const REDACTED: &str = "<redacted>";

/// One stable, non-secret key-allocation identity from the local database.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalChainSwapRecoveryAllocationV1 {
    pub allocation_id: Uuid,
    pub child_index: i64,
    pub compressed_public_key_hex: String,
}

impl fmt::Debug for LocalChainSwapRecoveryAllocationV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalChainSwapRecoveryAllocationV1")
            .field("allocation_id", &self.allocation_id)
            .field("child_index", &self.child_index)
            .field("compressed_public_key_hex", &REDACTED)
            .finish()
    }
}

/// Bounded public recovery evidence for one locally persisted chain swap.
///
/// This intentionally excludes merchant nyms, destinations, amounts, status,
/// secrets, and provider response bytes. Hashes authenticate the stable #65 / #80
/// evidence without placing those larger objects in the comparison boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalChainSwapRecoveryEvidenceV1 {
    pub chain_swap_id: Uuid,
    pub boltz_swap_id: String,
    pub root_fingerprint: String,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    pub claim: LocalChainSwapRecoveryAllocationV1,
    pub refund: LocalChainSwapRecoveryAllocationV1,
    pub claim_preimage_sha256: String,
    pub canonical_creation_response_sha256: String,
}

impl fmt::Debug for LocalChainSwapRecoveryEvidenceV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalChainSwapRecoveryEvidenceV1")
            .field("chain_swap_id", &self.chain_swap_id)
            .field("boltz_swap_id", &REDACTED)
            .field("root_fingerprint", &REDACTED)
            .field("key_epoch", &self.key_epoch)
            .field("derivation_scheme_version", &self.derivation_scheme_version)
            .field("claim", &self.claim)
            .field("refund", &self.refund)
            .field("claim_preimage_sha256", &REDACTED)
            .field("canonical_creation_response_sha256", &REDACTED)
            .finish()
    }
}

/// Local allocator high-water for one derivation namespace.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalRecoveryLineageHighWaterV1 {
    pub root_fingerprint: String,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    pub child_index: i64,
}

/// Structurally complete local generation represented by one chain-swap row.
///
/// Current-v1 rows carry complete #65 allocation lineage and #80 creation
/// evidence. Complete legacy rows carry neither, and their migration-044
/// root/index tuple is either wholly present or wholly absent. No partial
/// generation is representable at this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalChainSwapRecoveryStructuralClassV1 {
    CurrentV1,
    CompleteLegacy,
}

/// Optional complete migration-044 identity retained for an otherwise legacy
/// row. Pre-044 rows have no such tuple. Values remain internal and redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalChainSwapRecoveryLegacyDerivationV1 {
    pub root_fingerprint: String,
    pub claim_child_index: i64,
    pub refund_child_index: i64,
}

impl fmt::Debug for LocalChainSwapRecoveryLegacyDerivationV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalChainSwapRecoveryLegacyDerivationV1")
            .field("root_fingerprint", &REDACTED)
            .field("claim_child_index", &REDACTED)
            .field("refund_child_index", &REDACTED)
            .finish()
    }
}

/// One bounded all-generation identity used only for exact provider/local set
/// accounting. The provider id is necessary internally but always redacted by
/// `Debug` and is never copied into the public recovery report.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalChainSwapRecoveryInventoryRecordV1 {
    pub boltz_swap_id: String,
    pub structural_class: LocalChainSwapRecoveryStructuralClassV1,
    pub legacy_derivation: Option<LocalChainSwapRecoveryLegacyDerivationV1>,
}

impl fmt::Debug for LocalChainSwapRecoveryInventoryRecordV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalChainSwapRecoveryInventoryRecordV1")
            .field("boltz_swap_id", &REDACTED)
            .field("structural_class", &self.structural_class)
            .field(
                "legacy_derivation_present",
                &self.legacy_derivation.is_some(),
            )
            .finish()
    }
}

impl fmt::Debug for LocalRecoveryLineageHighWaterV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalRecoveryLineageHighWaterV1")
            .field("root_fingerprint", &REDACTED)
            .field("key_epoch", &self.key_epoch)
            .field("derivation_scheme_version", &self.derivation_scheme_version)
            .field("child_index", &self.child_index)
            .finish()
    }
}

/// Independently computed local snapshot summary.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalChainSwapRecoverySnapshotSummaryV1 {
    pub record_count: usize,
    pub chain_inventory_record_count: usize,
    pub chain_inventory: Vec<LocalChainSwapRecoveryInventoryRecordV1>,
    pub active_root_fingerprint: String,
    /// Immutable migration-050 exclusion for the configured active root.
    pub active_root_legacy_high_water: Option<i64>,
    pub lineage_high_waters: Vec<LocalRecoveryLineageHighWaterV1>,
}

impl fmt::Debug for LocalChainSwapRecoverySnapshotSummaryV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalChainSwapRecoverySnapshotSummaryV1")
            .field("record_count", &self.record_count)
            .field(
                "chain_inventory_record_count",
                &self.chain_inventory_record_count,
            )
            .field("chain_inventory", &self.chain_inventory.len())
            .field("active_root_fingerprint", &REDACTED)
            .field(
                "active_root_legacy_high_water_present",
                &self.active_root_legacy_high_water.is_some(),
            )
            .field("lineage_high_waters", &self.lineage_high_waters)
            .finish()
    }
}

/// One complete, already-read PostgreSQL snapshot supplied to the pure audit.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalChainSwapRecoverySnapshotV1 {
    pub records: Vec<LocalChainSwapRecoveryEvidenceV1>,
    pub summary: LocalChainSwapRecoverySnapshotSummaryV1,
}

impl fmt::Debug for LocalChainSwapRecoverySnapshotV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalChainSwapRecoverySnapshotV1")
            .field("records", &self.records.len())
            .field("summary", &self.summary)
            .finish()
    }
}

/// Direction of the local allocator relative to the signed witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRecoveryHighWaterRelationV1 {
    Equal,
    /// Expected when later reverse-swap or orphan allocations are local only.
    LocalAhead,
    /// Explicit shadow/admission signal; this pure audit does not enact policy.
    LocalBehind,
    /// The signed lineage has no local allocator summary.
    LocalMissing,
    /// The local lineage has no signed chain-swap manifest yet.
    ManifestMissing,
}

/// Signed-versus-local allocator comparison for one derivation namespace.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalRecoveryLineageComparisonV1 {
    pub root_fingerprint: String,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    pub signed_manifest_child_index: Option<i64>,
    pub local_child_index: Option<i64>,
    pub relation: LocalRecoveryHighWaterRelationV1,
}

impl fmt::Debug for LocalRecoveryLineageComparisonV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalRecoveryLineageComparisonV1")
            .field("root_fingerprint", &REDACTED)
            .field("key_epoch", &self.key_epoch)
            .field("derivation_scheme_version", &self.derivation_scheme_version)
            .field(
                "signed_manifest_child_index",
                &self.signed_manifest_child_index,
            )
            .field("local_child_index", &self.local_child_index)
            .field("relation", &self.relation)
            .finish()
    }
}

/// Compact classifications produced after exact cross-source comparison.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalChainSwapRecoveryAuditV1 {
    pub manifest_set: SwapManifestSetAuditV1,
    pub local_record_count: usize,
    pub exact_match_count: usize,
    /// Signed obligations absent locally. These are stale-restore reconstruction
    /// candidates only; this audit neither invents nor applies a repair.
    pub manifest_only_chain_swap_ids: Vec<Uuid>,
    /// Local records absent from the witness, retained as legacy/cutover
    /// candidates for a later policy boundary.
    pub local_only_chain_swap_ids: Vec<Uuid>,
    pub lineage_high_waters: Vec<LocalRecoveryLineageComparisonV1>,
}

impl fmt::Debug for LocalChainSwapRecoveryAuditV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalChainSwapRecoveryAuditV1")
            .field("manifest_count", &self.manifest_set.manifest_count)
            .field("local_record_count", &self.local_record_count)
            .field("exact_match_count", &self.exact_match_count)
            .field(
                "manifest_only_chain_swap_ids",
                &self.manifest_only_chain_swap_ids,
            )
            .field("local_only_chain_swap_ids", &self.local_only_chain_swap_ids)
            .field("lineage_high_waters", &self.lineage_high_waters)
            .finish()
    }
}

/// Stable field labels for exact-record conflicts. Values are never retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalChainSwapRecoveryFieldV1 {
    RootFingerprint,
    KeyEpoch,
    DerivationSchemeVersion,
    ClaimAllocationId,
    ClaimChildIndex,
    ClaimPublicKey,
    RefundAllocationId,
    RefundChildIndex,
    RefundPublicKey,
    ClaimPreimageSha256,
    CanonicalCreationResponseSha256,
}

impl LocalChainSwapRecoveryFieldV1 {
    fn label(self) -> &'static str {
        match self {
            Self::RootFingerprint => "root fingerprint",
            Self::KeyEpoch => "key epoch",
            Self::DerivationSchemeVersion => "derivation scheme version",
            Self::ClaimAllocationId => "claim allocation id",
            Self::ClaimChildIndex => "claim child index",
            Self::ClaimPublicKey => "claim public key",
            Self::RefundAllocationId => "refund allocation id",
            Self::RefundChildIndex => "refund child index",
            Self::RefundPublicKey => "refund public key",
            Self::ClaimPreimageSha256 => "claim preimage hash",
            Self::CanonicalCreationResponseSha256 => "creation response hash",
        }
    }
}

/// Fail-closed snapshot/manifest integrity errors. Variants intentionally carry
/// no provider id, nym, key, fingerprint, or hash value.
#[derive(Clone, PartialEq, Eq)]
pub enum LocalChainSwapRecoveryAuditError {
    InvalidManifestSet,
    TooManyManifestRecords,
    TooManyLocalRecords,
    TooManyChainInventoryRecords,
    TooManyLocalLineages,
    SnapshotRecordCountMismatch,
    SnapshotChainInventoryRecordCountMismatch,
    InvalidLocalEvidence,
    InvalidChainInventoryEvidence,
    InvalidActiveRootLegacyHighWater,
    InvalidLocalLineageHighWater,
    DuplicateLocalChainSwapId,
    DuplicateLocalBoltzSwapId,
    DuplicateLocalAllocationId,
    DuplicateLocalDerivationIdentity,
    DuplicateLocalPublicKey,
    DuplicateLocalClaimPreimageHash,
    DuplicateLocalCreationResponseHash,
    DuplicateChainInventoryBoltzSwapId,
    CurrentChainInventoryMismatch,
    DuplicateLocalLineage,
    MissingLocalLineageHighWater,
    LocalLineageHighWaterTrailsEvidence,
    PartialCrossIdentity,
    FieldConflict(LocalChainSwapRecoveryFieldV1),
}

impl fmt::Debug for LocalChainSwapRecoveryAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifestSet => f.write_str("InvalidManifestSet"),
            Self::FieldConflict(field) => f.debug_tuple("FieldConflict").field(field).finish(),
            Self::TooManyManifestRecords => f.write_str("TooManyManifestRecords"),
            Self::TooManyLocalRecords => f.write_str("TooManyLocalRecords"),
            Self::TooManyChainInventoryRecords => f.write_str("TooManyChainInventoryRecords"),
            Self::TooManyLocalLineages => f.write_str("TooManyLocalLineages"),
            Self::SnapshotRecordCountMismatch => f.write_str("SnapshotRecordCountMismatch"),
            Self::SnapshotChainInventoryRecordCountMismatch => {
                f.write_str("SnapshotChainInventoryRecordCountMismatch")
            }
            Self::InvalidLocalEvidence => f.write_str("InvalidLocalEvidence"),
            Self::InvalidChainInventoryEvidence => f.write_str("InvalidChainInventoryEvidence"),
            Self::InvalidActiveRootLegacyHighWater => {
                f.write_str("InvalidActiveRootLegacyHighWater")
            }
            Self::InvalidLocalLineageHighWater => f.write_str("InvalidLocalLineageHighWater"),
            Self::DuplicateLocalChainSwapId => f.write_str("DuplicateLocalChainSwapId"),
            Self::DuplicateLocalBoltzSwapId => f.write_str("DuplicateLocalBoltzSwapId"),
            Self::DuplicateLocalAllocationId => f.write_str("DuplicateLocalAllocationId"),
            Self::DuplicateLocalDerivationIdentity => {
                f.write_str("DuplicateLocalDerivationIdentity")
            }
            Self::DuplicateLocalPublicKey => f.write_str("DuplicateLocalPublicKey"),
            Self::DuplicateLocalClaimPreimageHash => f.write_str("DuplicateLocalClaimPreimageHash"),
            Self::DuplicateLocalCreationResponseHash => {
                f.write_str("DuplicateLocalCreationResponseHash")
            }
            Self::DuplicateChainInventoryBoltzSwapId => {
                f.write_str("DuplicateChainInventoryBoltzSwapId")
            }
            Self::CurrentChainInventoryMismatch => f.write_str("CurrentChainInventoryMismatch"),
            Self::DuplicateLocalLineage => f.write_str("DuplicateLocalLineage"),
            Self::MissingLocalLineageHighWater => f.write_str("MissingLocalLineageHighWater"),
            Self::LocalLineageHighWaterTrailsEvidence => {
                f.write_str("LocalLineageHighWaterTrailsEvidence")
            }
            Self::PartialCrossIdentity => f.write_str("PartialCrossIdentity"),
        }
    }
}

impl fmt::Display for LocalChainSwapRecoveryAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifestSet => {
                f.write_str("local recovery audit rejected the signed manifest set")
            }
            Self::TooManyManifestRecords => {
                f.write_str("local recovery audit exceeds the manifest record limit")
            }
            Self::TooManyLocalRecords => {
                f.write_str("local recovery audit exceeds the snapshot record limit")
            }
            Self::TooManyChainInventoryRecords => {
                f.write_str("local recovery audit exceeds the chain inventory limit")
            }
            Self::TooManyLocalLineages => {
                f.write_str("local recovery audit exceeds the snapshot lineage limit")
            }
            Self::SnapshotRecordCountMismatch => {
                f.write_str("local recovery snapshot summary count is inconsistent")
            }
            Self::SnapshotChainInventoryRecordCountMismatch => {
                f.write_str("local recovery chain inventory count is inconsistent")
            }
            Self::InvalidLocalEvidence => {
                f.write_str("local recovery snapshot contains invalid public evidence")
            }
            Self::InvalidChainInventoryEvidence => {
                f.write_str("local recovery chain inventory contains invalid public evidence")
            }
            Self::InvalidActiveRootLegacyHighWater => {
                f.write_str("local recovery snapshot contains an invalid legacy high-water")
            }
            Self::InvalidLocalLineageHighWater => {
                f.write_str("local recovery snapshot contains an invalid allocator high-water")
            }
            Self::DuplicateLocalChainSwapId => {
                f.write_str("local recovery snapshot reuses a chain-swap id")
            }
            Self::DuplicateLocalBoltzSwapId => {
                f.write_str("local recovery snapshot reuses a provider swap id")
            }
            Self::DuplicateLocalAllocationId => {
                f.write_str("local recovery snapshot reuses an allocation id")
            }
            Self::DuplicateLocalDerivationIdentity => {
                f.write_str("local recovery snapshot reuses a derivation identity")
            }
            Self::DuplicateLocalPublicKey => {
                f.write_str("local recovery snapshot reuses a derived public key")
            }
            Self::DuplicateLocalClaimPreimageHash => {
                f.write_str("local recovery snapshot reuses a claim preimage hash")
            }
            Self::DuplicateLocalCreationResponseHash => {
                f.write_str("local recovery snapshot reuses a creation response hash")
            }
            Self::DuplicateChainInventoryBoltzSwapId => {
                f.write_str("local recovery chain inventory reuses a provider swap id")
            }
            Self::CurrentChainInventoryMismatch => {
                f.write_str("local recovery current inventory disagrees with current evidence")
            }
            Self::DuplicateLocalLineage => {
                f.write_str("local recovery snapshot repeats an allocator lineage")
            }
            Self::MissingLocalLineageHighWater => {
                f.write_str("local recovery evidence has no allocator high-water")
            }
            Self::LocalLineageHighWaterTrailsEvidence => {
                f.write_str("local allocator high-water trails local recovery evidence")
            }
            Self::PartialCrossIdentity => {
                f.write_str("local and signed recovery identities only partially agree")
            }
            Self::FieldConflict(field) => write!(
                f,
                "local and signed recovery evidence conflict on {}",
                field.label()
            ),
        }
    }
}

impl std::error::Error for LocalChainSwapRecoveryAuditError {}

type LineageKey = (String, i32, i32);
type DerivationIdentity = (String, i32, i32, i64);

/// Audit one complete local snapshot against one complete signed witness.
///
/// Constant-time input bounds are checked before allocating or validating the
/// supplied slices. The append-only manifest-set audit then runs before any
/// substantive local evidence validation or cross-source comparison. Exact
/// identity matches must agree on every stable field. Manifest-only and
/// local-only records are returned as sorted compact candidates; no
/// reconstruction or repair is performed. A local-ahead high-water is reported,
/// not rejected, because reverse-swap and orphan allocations can legitimately
/// advance the allocator.
pub fn audit_manifest_set_against_local_recovery_snapshot_v1(
    manifests: &[SwapManifestV1],
    local: &LocalChainSwapRecoverySnapshotV1,
) -> Result<LocalChainSwapRecoveryAuditV1, LocalChainSwapRecoveryAuditError> {
    if manifests.len() > MAX_RECOVERY_AUDIT_MANIFEST_RECORDS_V1 {
        return Err(LocalChainSwapRecoveryAuditError::TooManyManifestRecords);
    }
    if local.records.len() > MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1 {
        return Err(LocalChainSwapRecoveryAuditError::TooManyLocalRecords);
    }
    if local.summary.chain_inventory.len() > MAX_RECOVERY_AUDIT_CHAIN_INVENTORY_RECORDS_V1 {
        return Err(LocalChainSwapRecoveryAuditError::TooManyChainInventoryRecords);
    }
    if local.summary.lineage_high_waters.len() > MAX_RECOVERY_AUDIT_LOCAL_LINEAGES_V1 {
        return Err(LocalChainSwapRecoveryAuditError::TooManyLocalLineages);
    }
    if local.summary.record_count != local.records.len() {
        return Err(LocalChainSwapRecoveryAuditError::SnapshotRecordCountMismatch);
    }
    if local.summary.chain_inventory_record_count != local.summary.chain_inventory.len() {
        return Err(LocalChainSwapRecoveryAuditError::SnapshotChainInventoryRecordCountMismatch);
    }

    let manifest_set = audit_append_only_manifest_set_v1(manifests)
        .map_err(|_| LocalChainSwapRecoveryAuditError::InvalidManifestSet)?;

    let local_lineage_high_waters = validate_local_snapshot(local)?;

    let mut local_by_chain_swap_id = BTreeMap::new();
    let mut local_by_boltz_swap_id = BTreeMap::new();
    for record in &local.records {
        local_by_chain_swap_id.insert(record.chain_swap_id, record);
        local_by_boltz_swap_id.insert(record.boltz_swap_id.as_str(), record);
    }

    let mut exact_match_count = 0_usize;
    let mut matched_local_chain_swap_ids = BTreeSet::new();
    let mut manifest_only_chain_swap_ids = Vec::new();

    for manifest in manifests {
        let identity = &manifest.restore_identity;
        let by_chain = local_by_chain_swap_id.get(&identity.chain_swap_id).copied();
        let by_boltz = local_by_boltz_swap_id
            .get(identity.boltz_swap_id.as_str())
            .copied();

        let local_record = match (by_chain, by_boltz) {
            (None, None) => {
                manifest_only_chain_swap_ids.push(identity.chain_swap_id);
                continue;
            }
            (Some(by_chain), Some(by_boltz)) if std::ptr::eq(by_chain, by_boltz) => by_chain,
            _ => return Err(LocalChainSwapRecoveryAuditError::PartialCrossIdentity),
        };

        require_exact_record_match(manifest, local_record)?;
        exact_match_count += 1;
        matched_local_chain_swap_ids.insert(local_record.chain_swap_id);
    }

    let mut local_only_chain_swap_ids = local
        .records
        .iter()
        .filter(|record| !matched_local_chain_swap_ids.contains(&record.chain_swap_id))
        .map(|record| record.chain_swap_id)
        .collect::<Vec<_>>();
    manifest_only_chain_swap_ids.sort_unstable();
    local_only_chain_swap_ids.sort_unstable();

    let lineage_high_waters =
        compare_lineage_high_waters(&manifest_set, &local_lineage_high_waters);

    Ok(LocalChainSwapRecoveryAuditV1 {
        manifest_set,
        local_record_count: local.records.len(),
        exact_match_count,
        manifest_only_chain_swap_ids,
        local_only_chain_swap_ids,
        lineage_high_waters,
    })
}

fn validate_local_snapshot(
    local: &LocalChainSwapRecoverySnapshotV1,
) -> Result<BTreeMap<LineageKey, i64>, LocalChainSwapRecoveryAuditError> {
    let mut chain_swap_ids = BTreeSet::new();
    let mut boltz_swap_ids = BTreeSet::new();
    let mut allocation_ids = BTreeSet::new();
    let mut derivation_identities = BTreeSet::new();
    let mut x_only_public_keys = BTreeSet::new();
    let mut claim_preimage_hashes = BTreeSet::new();
    let mut creation_response_hashes = BTreeSet::new();

    for record in &local.records {
        let (claim_x_only, refund_x_only) = validate_local_evidence(record)?;

        if !chain_swap_ids.insert(record.chain_swap_id) {
            return Err(LocalChainSwapRecoveryAuditError::DuplicateLocalChainSwapId);
        }
        if !boltz_swap_ids.insert(record.boltz_swap_id.as_str()) {
            return Err(LocalChainSwapRecoveryAuditError::DuplicateLocalBoltzSwapId);
        }
        for allocation in [&record.claim, &record.refund] {
            if !allocation_ids.insert(allocation.allocation_id) {
                return Err(LocalChainSwapRecoveryAuditError::DuplicateLocalAllocationId);
            }
            let identity: DerivationIdentity = (
                record.root_fingerprint.clone(),
                record.key_epoch,
                record.derivation_scheme_version,
                allocation.child_index,
            );
            if !derivation_identities.insert(identity) {
                return Err(LocalChainSwapRecoveryAuditError::DuplicateLocalDerivationIdentity);
            }
        }
        for x_only_public_key in [claim_x_only, refund_x_only] {
            if !x_only_public_keys.insert(x_only_public_key) {
                return Err(LocalChainSwapRecoveryAuditError::DuplicateLocalPublicKey);
            }
        }
        if !claim_preimage_hashes.insert(record.claim_preimage_sha256.as_str()) {
            return Err(LocalChainSwapRecoveryAuditError::DuplicateLocalClaimPreimageHash);
        }
        // The canonical #80 response embeds the provider swap id. Reuse across
        // distinct local records is an identity conflict, not a content dedupe.
        if !creation_response_hashes.insert(record.canonical_creation_response_sha256.as_str()) {
            return Err(LocalChainSwapRecoveryAuditError::DuplicateLocalCreationResponseHash);
        }
    }

    let mut inventory_ids = BTreeSet::new();
    let mut current_inventory_ids = BTreeSet::new();
    if !is_valid_root_fingerprint(&local.summary.active_root_fingerprint) {
        return Err(LocalChainSwapRecoveryAuditError::InvalidChainInventoryEvidence);
    }
    for record in &local.summary.chain_inventory {
        if record.boltz_swap_id.is_empty()
            || record.boltz_swap_id.len() > 128
            || !record
                .boltz_swap_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(LocalChainSwapRecoveryAuditError::InvalidChainInventoryEvidence);
        }
        if !inventory_ids.insert(record.boltz_swap_id.as_str()) {
            return Err(LocalChainSwapRecoveryAuditError::DuplicateChainInventoryBoltzSwapId);
        }
        match record.structural_class {
            LocalChainSwapRecoveryStructuralClassV1::CurrentV1 => {
                if record.legacy_derivation.is_some() {
                    return Err(LocalChainSwapRecoveryAuditError::InvalidChainInventoryEvidence);
                }
                current_inventory_ids.insert(record.boltz_swap_id.as_str());
            }
            LocalChainSwapRecoveryStructuralClassV1::CompleteLegacy => {
                if record.legacy_derivation.as_ref().is_some_and(|derivation| {
                    !is_valid_root_fingerprint(&derivation.root_fingerprint)
                        || !(0..=MAX_UNHARDENED_SWAP_CHILD_INDEX)
                            .contains(&derivation.claim_child_index)
                        || !(0..=MAX_UNHARDENED_SWAP_CHILD_INDEX)
                            .contains(&derivation.refund_child_index)
                        || derivation.claim_child_index == derivation.refund_child_index
                }) {
                    return Err(LocalChainSwapRecoveryAuditError::InvalidChainInventoryEvidence);
                }
            }
        }
    }
    if current_inventory_ids != boltz_swap_ids {
        return Err(LocalChainSwapRecoveryAuditError::CurrentChainInventoryMismatch);
    }
    if local
        .summary
        .active_root_legacy_high_water
        .is_some_and(|high_water| !(0..=MAX_UNHARDENED_SWAP_CHILD_INDEX).contains(&high_water))
    {
        return Err(LocalChainSwapRecoveryAuditError::InvalidActiveRootLegacyHighWater);
    }

    let mut lineage_high_waters = BTreeMap::new();
    for high_water in &local.summary.lineage_high_waters {
        if !is_valid_root_fingerprint(&high_water.root_fingerprint)
            || high_water.key_epoch <= 0
            || high_water.derivation_scheme_version <= 0
            || !(0..=MAX_UNHARDENED_SWAP_CHILD_INDEX).contains(&high_water.child_index)
        {
            return Err(LocalChainSwapRecoveryAuditError::InvalidLocalLineageHighWater);
        }
        let key = (
            high_water.root_fingerprint.clone(),
            high_water.key_epoch,
            high_water.derivation_scheme_version,
        );
        if lineage_high_waters
            .insert(key, high_water.child_index)
            .is_some()
        {
            return Err(LocalChainSwapRecoveryAuditError::DuplicateLocalLineage);
        }
    }

    for record in &local.records {
        let key = (
            record.root_fingerprint.clone(),
            record.key_epoch,
            record.derivation_scheme_version,
        );
        let high_water = lineage_high_waters
            .get(&key)
            .ok_or(LocalChainSwapRecoveryAuditError::MissingLocalLineageHighWater)?;
        if *high_water < record.claim.child_index.max(record.refund.child_index) {
            return Err(LocalChainSwapRecoveryAuditError::LocalLineageHighWaterTrailsEvidence);
        }
    }

    Ok(lineage_high_waters)
}

fn validate_local_evidence(
    record: &LocalChainSwapRecoveryEvidenceV1,
) -> Result<([u8; 32], [u8; 32]), LocalChainSwapRecoveryAuditError> {
    if record.chain_swap_id.is_nil()
        || record.boltz_swap_id.is_empty()
        || record.boltz_swap_id.len() > 128
        || !record
            .boltz_swap_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
        || !is_valid_root_fingerprint(&record.root_fingerprint)
        || record.key_epoch <= 0
        || record.derivation_scheme_version <= 0
        || !is_valid_sha256(&record.claim_preimage_sha256)
        || !is_valid_sha256(&record.canonical_creation_response_sha256)
    {
        return Err(LocalChainSwapRecoveryAuditError::InvalidLocalEvidence);
    }

    let claim_public_key = validate_local_allocation(&record.claim)?;
    let refund_public_key = validate_local_allocation(&record.refund)?;
    let claim_x_only = claim_public_key.x_only_public_key().0.serialize();
    let refund_x_only = refund_public_key.x_only_public_key().0.serialize();
    if record.claim.allocation_id == record.refund.allocation_id
        || record.claim.child_index == record.refund.child_index
        || claim_x_only == refund_x_only
    {
        return Err(LocalChainSwapRecoveryAuditError::InvalidLocalEvidence);
    }
    Ok((claim_x_only, refund_x_only))
}

fn validate_local_allocation(
    allocation: &LocalChainSwapRecoveryAllocationV1,
) -> Result<PublicKey, LocalChainSwapRecoveryAuditError> {
    if allocation.allocation_id.is_nil()
        || !(0..=MAX_UNHARDENED_SWAP_CHILD_INDEX).contains(&allocation.child_index)
        || allocation.compressed_public_key_hex.len() != 66
        || !matches!(
            allocation.compressed_public_key_hex.get(..2),
            Some("02" | "03")
        )
        || !is_lower_hex(&allocation.compressed_public_key_hex)
    {
        return Err(LocalChainSwapRecoveryAuditError::InvalidLocalEvidence);
    }
    let public_key = PublicKey::from_str(&allocation.compressed_public_key_hex)
        .map_err(|_| LocalChainSwapRecoveryAuditError::InvalidLocalEvidence)?;
    if public_key.to_string() != allocation.compressed_public_key_hex {
        return Err(LocalChainSwapRecoveryAuditError::InvalidLocalEvidence);
    }
    Ok(public_key)
}

fn is_valid_root_fingerprint(value: &str) -> bool {
    value.len() == 16 && is_lower_hex(value)
}

fn is_valid_sha256(value: &str) -> bool {
    value.len() == 64 && is_lower_hex(value)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_exact_record_match(
    manifest: &SwapManifestV1,
    local: &LocalChainSwapRecoveryEvidenceV1,
) -> Result<(), LocalChainSwapRecoveryAuditError> {
    let lineage = &manifest.derivation_lineage;
    let checks = [
        (
            lineage.root_fingerprint == local.root_fingerprint,
            LocalChainSwapRecoveryFieldV1::RootFingerprint,
        ),
        (
            lineage.key_epoch == local.key_epoch,
            LocalChainSwapRecoveryFieldV1::KeyEpoch,
        ),
        (
            lineage.derivation_scheme_version == local.derivation_scheme_version,
            LocalChainSwapRecoveryFieldV1::DerivationSchemeVersion,
        ),
        (
            lineage.claim.allocation_id == local.claim.allocation_id,
            LocalChainSwapRecoveryFieldV1::ClaimAllocationId,
        ),
        (
            lineage.claim.child_index == local.claim.child_index,
            LocalChainSwapRecoveryFieldV1::ClaimChildIndex,
        ),
        (
            lineage.claim.public_key_hex == local.claim.compressed_public_key_hex,
            LocalChainSwapRecoveryFieldV1::ClaimPublicKey,
        ),
        (
            lineage.refund.allocation_id == local.refund.allocation_id,
            LocalChainSwapRecoveryFieldV1::RefundAllocationId,
        ),
        (
            lineage.refund.child_index == local.refund.child_index,
            LocalChainSwapRecoveryFieldV1::RefundChildIndex,
        ),
        (
            lineage.refund.public_key_hex == local.refund.compressed_public_key_hex,
            LocalChainSwapRecoveryFieldV1::RefundPublicKey,
        ),
        (
            lineage.claim.preimage_hash_hex.as_deref()
                == Some(local.claim_preimage_sha256.as_str()),
            LocalChainSwapRecoveryFieldV1::ClaimPreimageSha256,
        ),
        (
            manifest.creation.creation_response_sha256 == local.canonical_creation_response_sha256,
            LocalChainSwapRecoveryFieldV1::CanonicalCreationResponseSha256,
        ),
    ];

    for (matches, field) in checks {
        if !matches {
            return Err(LocalChainSwapRecoveryAuditError::FieldConflict(field));
        }
    }
    Ok(())
}

fn compare_lineage_high_waters(
    manifest_set: &SwapManifestSetAuditV1,
    local: &BTreeMap<LineageKey, i64>,
) -> Vec<LocalRecoveryLineageComparisonV1> {
    let mut combined: BTreeMap<LineageKey, (Option<i64>, Option<i64>)> = BTreeMap::new();
    for high_water in &manifest_set.lineage_high_waters {
        combined
            .entry((
                high_water.root_fingerprint.clone(),
                high_water.key_epoch,
                high_water.derivation_scheme_version,
            ))
            .or_default()
            .0 = Some(high_water.child_index);
    }
    for (key, child_index) in local {
        combined.entry(key.clone()).or_default().1 = Some(*child_index);
    }

    combined
        .into_iter()
        .map(
            |(
                (root_fingerprint, key_epoch, derivation_scheme_version),
                (signed_manifest_child_index, local_child_index),
            )| {
                let relation = match (signed_manifest_child_index, local_child_index) {
                    (Some(signed), Some(local)) if local == signed => {
                        LocalRecoveryHighWaterRelationV1::Equal
                    }
                    (Some(signed), Some(local)) if local > signed => {
                        LocalRecoveryHighWaterRelationV1::LocalAhead
                    }
                    (Some(_), Some(_)) => LocalRecoveryHighWaterRelationV1::LocalBehind,
                    (Some(_), None) => LocalRecoveryHighWaterRelationV1::LocalMissing,
                    (None, Some(_)) => LocalRecoveryHighWaterRelationV1::ManifestMissing,
                    (None, None) => unreachable!("lineage union cannot contain an empty entry"),
                };
                LocalRecoveryLineageComparisonV1 {
                    root_fingerprint,
                    key_epoch,
                    derivation_scheme_version,
                    signed_manifest_child_index,
                    local_child_index,
                    relation,
                }
            },
        )
        .collect()
}

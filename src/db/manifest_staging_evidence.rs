//! Narrow PostgreSQL projection for staging one recovery manifest.
//!
//! The projection deliberately excludes the mnemonic, preimage, private
//! claim/refund keys, raw provider response, destinations, amounts, and every
//! other secret-bearing chain-swap column. One SQL statement reads the
//! persisted migration-050 lineage, both exact append-only allocation rows,
//! and the allocator high-water from the same PostgreSQL statement snapshot.

use std::fmt;

use sqlx::PgExecutor;
use uuid::Uuid;

use crate::swap_manifest_staging::{
    PersistedChainSwapKeyReference, PersistedChainSwapLineageEvidence,
    PublicSwapKeyAllocationEvidence, PublicSwapKeyAllocationHighWaterEvidence,
};

use super::SwapKeyPurpose;

const MANIFEST_STAGING_EVIDENCE_SQL: &str = "SELECT \
         chain.id AS chain_swap_id, \
         chain.root_fingerprint, \
         chain.key_epoch, \
         chain.derivation_scheme_version, \
         chain.claim_key_allocation_id, \
         chain.refund_key_allocation_id, \
         chain.claim_key_index AS claim_child_index, \
         chain.refund_key_index AS refund_child_index, \
         chain.claim_public_key_hex, \
         chain.refund_public_key_hex, \
         chain.preimage_hash_hex AS chain_preimage_hash_hex, \
         claim.id AS claim_allocation_id, \
         claim.root_fingerprint AS claim_root_fingerprint, \
         claim.key_epoch AS claim_key_epoch, \
         claim.derivation_scheme_version AS claim_derivation_scheme_version, \
         claim.child_index AS claim_allocation_child_index, \
         claim.purpose AS claim_purpose, \
         claim.public_key_hex AS claim_allocation_public_key_hex, \
         claim.preimage_hash_hex AS claim_allocation_preimage_hash_hex, \
         refund.id AS refund_allocation_id, \
         refund.root_fingerprint AS refund_root_fingerprint, \
         refund.key_epoch AS refund_key_epoch, \
         refund.derivation_scheme_version AS refund_derivation_scheme_version, \
         refund.child_index AS refund_allocation_child_index, \
         refund.purpose AS refund_purpose, \
         refund.public_key_hex AS refund_allocation_public_key_hex, \
         refund.preimage_hash_hex AS refund_allocation_preimage_hash_hex, \
         (SELECT MAX(allocation.child_index) \
            FROM swap_key_allocations AS allocation \
           WHERE allocation.root_fingerprint = chain.root_fingerprint \
             AND allocation.key_epoch = chain.key_epoch \
             AND allocation.derivation_scheme_version = chain.derivation_scheme_version \
         ) AS allocation_high_water_child_index \
    FROM chain_swap_records AS chain \
    LEFT JOIN swap_key_allocations AS claim \
      ON claim.id = chain.claim_key_allocation_id \
    LEFT JOIN swap_key_allocations AS refund \
      ON refund.id = chain.refund_key_allocation_id \
   WHERE chain.id = $1";

/// Public evidence required by the pure manifest-staging boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestStagingEvidence {
    pub persisted_lineage: PersistedChainSwapLineageEvidence,
    pub claim_allocation: PublicSwapKeyAllocationEvidence,
    pub refund_allocation: PublicSwapKeyAllocationEvidence,
    pub allocation_high_water: PublicSwapKeyAllocationHighWaterEvidence,
}

/// Sanitized failures from the non-secret projection.
///
/// SQLx sources are intentionally discarded because database errors can carry
/// connection details or stored operational values. Field names are fixed
/// compile-time labels and never contain row data.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ManifestStagingEvidenceReadError {
    Database,
    IncompleteStoredEvidence { field: &'static str },
    InvalidAllocationPurpose { field: &'static str },
}

impl fmt::Debug for ManifestStagingEvidenceReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database => f.write_str("Database"),
            Self::IncompleteStoredEvidence { field } => f
                .debug_struct("IncompleteStoredEvidence")
                .field("field", field)
                .finish(),
            Self::InvalidAllocationPurpose { field } => f
                .debug_struct("InvalidAllocationPurpose")
                .field("field", field)
                .finish(),
        }
    }
}

impl fmt::Display for ManifestStagingEvidenceReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database => f.write_str("manifest-staging database read failed"),
            Self::IncompleteStoredEvidence { field } => {
                write!(f, "manifest-staging evidence lacks required field {field}")
            }
            Self::InvalidAllocationPurpose { field } => {
                write!(
                    f,
                    "manifest-staging evidence has invalid purpose field {field}"
                )
            }
        }
    }
}

impl std::error::Error for ManifestStagingEvidenceReadError {}

#[derive(sqlx::FromRow)]
struct ManifestStagingEvidenceRow {
    chain_swap_id: Uuid,
    root_fingerprint: Option<String>,
    key_epoch: Option<i32>,
    derivation_scheme_version: Option<i32>,
    claim_key_allocation_id: Option<Uuid>,
    refund_key_allocation_id: Option<Uuid>,
    claim_child_index: Option<i64>,
    refund_child_index: Option<i64>,
    claim_public_key_hex: Option<String>,
    refund_public_key_hex: Option<String>,
    chain_preimage_hash_hex: Option<String>,
    claim_allocation_id: Option<Uuid>,
    claim_root_fingerprint: Option<String>,
    claim_key_epoch: Option<i32>,
    claim_derivation_scheme_version: Option<i32>,
    claim_allocation_child_index: Option<i64>,
    claim_purpose: Option<String>,
    claim_allocation_public_key_hex: Option<String>,
    claim_allocation_preimage_hash_hex: Option<String>,
    refund_allocation_id: Option<Uuid>,
    refund_root_fingerprint: Option<String>,
    refund_key_epoch: Option<i32>,
    refund_derivation_scheme_version: Option<i32>,
    refund_allocation_child_index: Option<i64>,
    refund_purpose: Option<String>,
    refund_allocation_public_key_hex: Option<String>,
    refund_allocation_preimage_hash_hex: Option<String>,
    allocation_high_water_child_index: Option<i64>,
}

/// Load the exact non-secret evidence for one already-persisted chain swap.
///
/// `executor` may be the same transaction that inserted the chain-swap row and
/// owns the manifest-ledger advisory lock. A missing chain-swap identity is
/// distinct from a present row with incomplete or dangling lineage evidence.
pub async fn load_manifest_staging_evidence<'e, E>(
    executor: E,
    chain_swap_id: Uuid,
) -> Result<Option<ManifestStagingEvidence>, ManifestStagingEvidenceReadError>
where
    E: PgExecutor<'e>,
{
    let row = sqlx::query_as::<_, ManifestStagingEvidenceRow>(MANIFEST_STAGING_EVIDENCE_SQL)
        .bind(chain_swap_id)
        .fetch_optional(executor)
        .await
        .map_err(|_| ManifestStagingEvidenceReadError::Database)?;
    row.map(TryInto::try_into).transpose()
}

impl TryFrom<ManifestStagingEvidenceRow> for ManifestStagingEvidence {
    type Error = ManifestStagingEvidenceReadError;

    fn try_from(row: ManifestStagingEvidenceRow) -> Result<Self, Self::Error> {
        let root_fingerprint = required(row.root_fingerprint, "root_fingerprint")?;
        let key_epoch = required(row.key_epoch, "key_epoch")?;
        let derivation_scheme_version =
            required(row.derivation_scheme_version, "derivation_scheme_version")?;
        let claim_key_allocation_id =
            required(row.claim_key_allocation_id, "claim_key_allocation_id")?;
        let refund_key_allocation_id =
            required(row.refund_key_allocation_id, "refund_key_allocation_id")?;
        let claim_child_index = required(row.claim_child_index, "claim_key_index")?;
        let refund_child_index = required(row.refund_child_index, "refund_key_index")?;
        let claim_public_key_hex = required(row.claim_public_key_hex, "claim_public_key_hex")?;
        let refund_public_key_hex = required(row.refund_public_key_hex, "refund_public_key_hex")?;
        let chain_preimage_hash_hex = required(row.chain_preimage_hash_hex, "preimage_hash_hex")?;

        let claim_allocation_id = required(row.claim_allocation_id, "claim_allocation.id")?;
        let claim_root_fingerprint = required(
            row.claim_root_fingerprint,
            "claim_allocation.root_fingerprint",
        )?;
        let claim_key_epoch = required(row.claim_key_epoch, "claim_allocation.key_epoch")?;
        let claim_derivation_scheme_version = required(
            row.claim_derivation_scheme_version,
            "claim_allocation.derivation_scheme_version",
        )?;
        let claim_allocation_child_index = required(
            row.claim_allocation_child_index,
            "claim_allocation.child_index",
        )?;
        let claim_purpose = allocation_purpose(
            required(row.claim_purpose, "claim_allocation.purpose")?.as_str(),
            "claim_allocation.purpose",
        )?;
        let claim_allocation_public_key_hex = required(
            row.claim_allocation_public_key_hex,
            "claim_allocation.public_key_hex",
        )?;

        let refund_allocation_id = required(row.refund_allocation_id, "refund_allocation.id")?;
        let refund_root_fingerprint = required(
            row.refund_root_fingerprint,
            "refund_allocation.root_fingerprint",
        )?;
        let refund_key_epoch = required(row.refund_key_epoch, "refund_allocation.key_epoch")?;
        let refund_derivation_scheme_version = required(
            row.refund_derivation_scheme_version,
            "refund_allocation.derivation_scheme_version",
        )?;
        let refund_allocation_child_index = required(
            row.refund_allocation_child_index,
            "refund_allocation.child_index",
        )?;
        let refund_purpose = allocation_purpose(
            required(row.refund_purpose, "refund_allocation.purpose")?.as_str(),
            "refund_allocation.purpose",
        )?;
        let refund_allocation_public_key_hex = required(
            row.refund_allocation_public_key_hex,
            "refund_allocation.public_key_hex",
        )?;
        let high_water = required(
            row.allocation_high_water_child_index,
            "allocation_high_water_child_index",
        )?;

        Ok(Self {
            persisted_lineage: PersistedChainSwapLineageEvidence {
                chain_swap_id: row.chain_swap_id,
                root_fingerprint: root_fingerprint.clone(),
                key_epoch,
                derivation_scheme_version,
                claim: PersistedChainSwapKeyReference {
                    allocation_id: claim_key_allocation_id,
                    child_index: claim_child_index,
                    public_key_hex: claim_public_key_hex,
                    preimage_hash_hex: Some(chain_preimage_hash_hex),
                },
                refund: PersistedChainSwapKeyReference {
                    allocation_id: refund_key_allocation_id,
                    child_index: refund_child_index,
                    public_key_hex: refund_public_key_hex,
                    preimage_hash_hex: None,
                },
            },
            claim_allocation: PublicSwapKeyAllocationEvidence {
                allocation_id: claim_allocation_id,
                root_fingerprint: claim_root_fingerprint,
                key_epoch: claim_key_epoch,
                derivation_scheme_version: claim_derivation_scheme_version,
                child_index: claim_allocation_child_index,
                purpose: claim_purpose,
                public_key_hex: claim_allocation_public_key_hex,
                preimage_hash_hex: row.claim_allocation_preimage_hash_hex,
            },
            refund_allocation: PublicSwapKeyAllocationEvidence {
                allocation_id: refund_allocation_id,
                root_fingerprint: refund_root_fingerprint,
                key_epoch: refund_key_epoch,
                derivation_scheme_version: refund_derivation_scheme_version,
                child_index: refund_allocation_child_index,
                purpose: refund_purpose,
                public_key_hex: refund_allocation_public_key_hex,
                preimage_hash_hex: row.refund_allocation_preimage_hash_hex,
            },
            allocation_high_water: PublicSwapKeyAllocationHighWaterEvidence {
                root_fingerprint,
                key_epoch,
                derivation_scheme_version,
                child_index: high_water,
            },
        })
    }
}

fn required<T>(
    value: Option<T>,
    field: &'static str,
) -> Result<T, ManifestStagingEvidenceReadError> {
    value.ok_or(ManifestStagingEvidenceReadError::IncompleteStoredEvidence { field })
}

fn allocation_purpose(
    value: &str,
    field: &'static str,
) -> Result<SwapKeyPurpose, ManifestStagingEvidenceReadError> {
    match value {
        "reverse_claim" => Ok(SwapKeyPurpose::ReverseClaim),
        "chain_claim" => Ok(SwapKeyPurpose::ChainClaim),
        "chain_refund" => Ok(SwapKeyPurpose::ChainRefund),
        _ => Err(ManifestStagingEvidenceReadError::InvalidAllocationPurpose { field }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_row() -> ManifestStagingEvidenceRow {
        ManifestStagingEvidenceRow {
            chain_swap_id: Uuid::from_u128(1),
            root_fingerprint: Some("0011223344556677".into()),
            key_epoch: Some(2),
            derivation_scheme_version: Some(1),
            claim_key_allocation_id: Some(Uuid::from_u128(2)),
            refund_key_allocation_id: Some(Uuid::from_u128(3)),
            claim_child_index: Some(430),
            refund_child_index: Some(431),
            claim_public_key_hex: Some(format!("02{}", "11".repeat(32))),
            refund_public_key_hex: Some(format!("03{}", "22".repeat(32))),
            chain_preimage_hash_hex: Some("33".repeat(32)),
            claim_allocation_id: Some(Uuid::from_u128(2)),
            claim_root_fingerprint: Some("0011223344556677".into()),
            claim_key_epoch: Some(2),
            claim_derivation_scheme_version: Some(1),
            claim_allocation_child_index: Some(430),
            claim_purpose: Some("chain_claim".into()),
            claim_allocation_public_key_hex: Some(format!("02{}", "11".repeat(32))),
            claim_allocation_preimage_hash_hex: Some("33".repeat(32)),
            refund_allocation_id: Some(Uuid::from_u128(3)),
            refund_root_fingerprint: Some("0011223344556677".into()),
            refund_key_epoch: Some(2),
            refund_derivation_scheme_version: Some(1),
            refund_allocation_child_index: Some(431),
            refund_purpose: Some("chain_refund".into()),
            refund_allocation_public_key_hex: Some(format!("03{}", "22".repeat(32))),
            refund_allocation_preimage_hash_hex: None,
            allocation_high_water_child_index: Some(435),
        }
    }

    #[test]
    fn maps_only_exact_public_staging_evidence() {
        let evidence = ManifestStagingEvidence::try_from(complete_row()).unwrap();

        assert_eq!(evidence.persisted_lineage.chain_swap_id, Uuid::from_u128(1));
        assert_eq!(evidence.persisted_lineage.claim.child_index, 430);
        assert_eq!(evidence.persisted_lineage.refund.child_index, 431);
        assert_eq!(
            evidence.claim_allocation.purpose,
            SwapKeyPurpose::ChainClaim
        );
        assert_eq!(
            evidence.refund_allocation.purpose,
            SwapKeyPurpose::ChainRefund
        );
        assert_eq!(evidence.allocation_high_water.child_index, 435);
    }

    #[test]
    fn sql_projection_cannot_materialize_secret_or_money_bearing_columns() {
        for forbidden in [
            "chain.preimage_hex",
            "chain.claim_key_hex",
            "chain.refund_key_hex",
            "chain.boltz_response_json",
            "chain.lockup_address",
            "chain.lockup_bip21",
            "chain.user_lock_amount_sat",
            "chain.server_lock_amount_sat",
            "chain.merchant_liquid_destination",
            "chain.merchant_emergency_btc_address",
        ] {
            assert!(
                !MANIFEST_STAGING_EVIDENCE_SQL.contains(forbidden),
                "secret-bearing projection added: {forbidden}"
            );
        }
    }

    #[test]
    fn incomplete_or_unknown_stored_evidence_fails_closed_without_a_source() {
        let mut incomplete = complete_row();
        incomplete.claim_allocation_id = None;
        assert_eq!(
            ManifestStagingEvidence::try_from(incomplete).unwrap_err(),
            ManifestStagingEvidenceReadError::IncompleteStoredEvidence {
                field: "claim_allocation.id"
            }
        );

        let mut invalid_purpose = complete_row();
        invalid_purpose.refund_purpose = Some("private-purpose-canary".into());
        let error = ManifestStagingEvidence::try_from(invalid_purpose).unwrap_err();
        assert_eq!(
            error,
            ManifestStagingEvidenceReadError::InvalidAllocationPurpose {
                field: "refund_allocation.purpose"
            }
        );
        assert!(std::error::Error::source(&error).is_none());
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("private-purpose-canary"));
    }
}

//! Read-only PostgreSQL projection for chain-swap recovery reconciliation.
//!
//! This adapter deliberately returns only the stable, non-secret #65 lineage
//! and #80 creation digest consumed by the pure local recovery audit. It does
//! not read raw provider responses, private keys, preimages, destinations,
//! amounts, merchant identities, lifecycle state, or transaction evidence.

use std::fmt;

use sqlx::{PgPool, Postgres, Transaction};

use crate::local_chain_swap_recovery_audit::{
    audit_manifest_set_against_local_recovery_snapshot_v1, LocalChainSwapRecoveryAllocationV1,
    LocalChainSwapRecoveryEvidenceV1, LocalChainSwapRecoverySnapshotSummaryV1,
    LocalChainSwapRecoverySnapshotV1, LocalRecoveryLineageHighWaterV1,
    MAX_RECOVERY_AUDIT_LOCAL_LINEAGES_V1, MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1,
};
use crate::swap_manifest::MAX_UNHARDENED_SWAP_CHILD_INDEX;

const RECORD_COUNT_SQL: &str = "SELECT \
         COUNT(*) FILTER ( \
             WHERE claim_key_allocation_id IS NOT NULL \
               AND creation_response_sha256 IS NOT NULL \
         )::BIGINT AS eligible_count, \
         COUNT(*) FILTER ( \
             WHERE NOT ( \
                 ( \
                     num_nonnulls( \
                         claim_key_allocation_id, refund_key_allocation_id, \
                         key_epoch, derivation_scheme_version, \
                         claim_public_key_hex, refund_public_key_hex, preimage_hash_hex \
                     ) = 0 \
                     AND num_nonnulls( \
                         root_fingerprint, claim_key_index, refund_key_index \
                     ) IN (0, 3) \
                 ) \
                 OR num_nonnulls( \
                     claim_key_allocation_id, refund_key_allocation_id, \
                     root_fingerprint, key_epoch, derivation_scheme_version, \
                     claim_key_index, refund_key_index, claim_public_key_hex, \
                     refund_public_key_hex, preimage_hash_hex \
                 ) = 10 \
             ) \
                OR ( \
                    creation_response_sha256 IS NOT NULL \
                    AND claim_key_allocation_id IS NULL \
                ) \
                OR ( \
                    claim_key_allocation_id IS NOT NULL \
                    AND creation_response_sha256 IS NOT NULL \
                    AND ( \
                        octet_length(boltz_swap_id) NOT BETWEEN 1 AND 128 \
                        OR boltz_swap_id !~ '^[A-Za-z0-9]+$' \
                    ) \
                ) \
         )::BIGINT AS invalid_shape_count \
       FROM chain_swap_records";

const INVALID_ALLOCATION_COUNT_SQL: &str = "SELECT COUNT(*)::BIGINT \
       FROM swap_key_allocations \
      WHERE root_fingerprint !~ '^[0-9a-f]{16}$' \
         OR key_epoch <= 0 \
         OR derivation_scheme_version <= 0 \
         OR child_index NOT BETWEEN 0 AND $1 \
         OR purpose NOT IN ('reverse_claim', 'chain_claim', 'chain_refund') \
         OR public_key_hex !~ '^(02|03)[0-9a-f]{64}$' \
         OR (preimage_hash_hex IS NOT NULL AND preimage_hash_hex !~ '^[0-9a-f]{64}$') \
         OR (purpose IN ('reverse_claim', 'chain_claim') AND preimage_hash_hex IS NULL) \
         OR (purpose = 'chain_refund' AND preimage_hash_hex IS NOT NULL)";

const LINEAGE_COUNT_SQL: &str = "SELECT COUNT(*)::BIGINT FROM ( \
         SELECT 1 FROM swap_key_allocations \
         GROUP BY root_fingerprint, key_epoch, derivation_scheme_version \
     ) AS recovery_lineages";

const RECORDS_SQL: &str = "SELECT \
         chain.id AS chain_swap_id, \
         chain.boltz_swap_id, \
         chain.root_fingerprint AS chain_root_fingerprint, \
         chain.key_epoch AS chain_key_epoch, \
         chain.derivation_scheme_version AS chain_derivation_scheme_version, \
         chain.claim_key_allocation_id AS chain_claim_allocation_id, \
         chain.refund_key_allocation_id AS chain_refund_allocation_id, \
         chain.claim_key_index AS chain_claim_child_index, \
         chain.refund_key_index AS chain_refund_child_index, \
         chain.claim_public_key_hex AS chain_claim_public_key_hex, \
         chain.refund_public_key_hex AS chain_refund_public_key_hex, \
         chain.preimage_hash_hex AS chain_preimage_hash_hex, \
         chain.creation_response_sha256, \
         claim.id AS claim_allocation_id, \
         claim.root_fingerprint AS claim_root_fingerprint, \
         claim.key_epoch AS claim_key_epoch, \
         claim.derivation_scheme_version AS claim_derivation_scheme_version, \
         claim.child_index AS claim_child_index, \
         claim.purpose AS claim_purpose, \
         claim.public_key_hex AS claim_public_key_hex, \
         claim.preimage_hash_hex AS claim_preimage_hash_hex, \
         refund.id AS refund_allocation_id, \
         refund.root_fingerprint AS refund_root_fingerprint, \
         refund.key_epoch AS refund_key_epoch, \
         refund.derivation_scheme_version AS refund_derivation_scheme_version, \
         refund.child_index AS refund_child_index, \
         refund.purpose AS refund_purpose, \
         refund.public_key_hex AS refund_public_key_hex, \
         refund.preimage_hash_hex AS refund_preimage_hash_hex \
     FROM chain_swap_records AS chain \
     JOIN swap_key_allocations AS claim \
       ON claim.id = chain.claim_key_allocation_id \
     JOIN swap_key_allocations AS refund \
       ON refund.id = chain.refund_key_allocation_id \
     WHERE chain.claim_key_allocation_id IS NOT NULL \
       AND chain.creation_response_sha256 IS NOT NULL \
     ORDER BY chain.id ASC \
     LIMIT $1";

const LINEAGE_HIGH_WATERS_SQL: &str =
    "SELECT root_fingerprint, key_epoch, derivation_scheme_version, \
            MAX(child_index)::BIGINT AS child_index \
       FROM swap_key_allocations \
      GROUP BY root_fingerprint, key_epoch, derivation_scheme_version \
      ORDER BY root_fingerprint ASC, key_epoch ASC, derivation_scheme_version ASC \
      LIMIT $1";

/// Bounded stages exposed by a sanitized database-read failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRecoverySnapshotReadStageV1 {
    Begin,
    SetIsolation,
    CountRecords,
    ValidateAllocations,
    CountLineages,
    ReadRecords,
    ReadLineages,
    Rollback,
    Commit,
}

/// Fail-closed snapshot load errors. No SQLx source is retained because server
/// errors can contain operational values or database connection details.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalRecoverySnapshotReadErrorV1 {
    Database(LocalRecoverySnapshotReadStageV1),
    TooManyRecords,
    TooManyLineages,
    InvalidStoredEvidence,
}

impl fmt::Debug for LocalRecoverySnapshotReadErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(stage) => f.debug_tuple("Database").field(stage).finish(),
            Self::TooManyRecords => f.write_str("TooManyRecords"),
            Self::TooManyLineages => f.write_str("TooManyLineages"),
            Self::InvalidStoredEvidence => f.write_str("InvalidStoredEvidence"),
        }
    }
}

impl fmt::Display for LocalRecoverySnapshotReadErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(stage) => {
                write!(
                    f,
                    "local recovery snapshot database read failed at {stage:?}"
                )
            }
            Self::TooManyRecords => f.write_str("local recovery snapshot exceeds the record limit"),
            Self::TooManyLineages => {
                f.write_str("local recovery snapshot exceeds the lineage limit")
            }
            Self::InvalidStoredEvidence => {
                f.write_str("local recovery snapshot contains inconsistent stored evidence")
            }
        }
    }
}

impl std::error::Error for LocalRecoverySnapshotReadErrorV1 {}

#[derive(sqlx::FromRow)]
struct RecoveryRecordRow {
    chain_swap_id: uuid::Uuid,
    boltz_swap_id: String,
    chain_root_fingerprint: String,
    chain_key_epoch: i32,
    chain_derivation_scheme_version: i32,
    chain_claim_allocation_id: uuid::Uuid,
    chain_refund_allocation_id: uuid::Uuid,
    chain_claim_child_index: i64,
    chain_refund_child_index: i64,
    chain_claim_public_key_hex: String,
    chain_refund_public_key_hex: String,
    chain_preimage_hash_hex: String,
    creation_response_sha256: String,
    claim_allocation_id: uuid::Uuid,
    claim_root_fingerprint: String,
    claim_key_epoch: i32,
    claim_derivation_scheme_version: i32,
    claim_child_index: i64,
    claim_purpose: String,
    claim_public_key_hex: String,
    claim_preimage_hash_hex: Option<String>,
    refund_allocation_id: uuid::Uuid,
    refund_root_fingerprint: String,
    refund_key_epoch: i32,
    refund_derivation_scheme_version: i32,
    refund_child_index: i64,
    refund_purpose: String,
    refund_public_key_hex: String,
    refund_preimage_hash_hex: Option<String>,
}

#[derive(sqlx::FromRow)]
struct RecoveryLineageRow {
    root_fingerprint: String,
    key_epoch: i32,
    derivation_scheme_version: i32,
    child_index: i64,
}

/// Load one transactionally coherent local recovery snapshot.
///
/// A PostgreSQL `REPEATABLE READ, READ ONLY` transaction fixes one database
/// view before any count or row read. Counts are checked before either
/// `fetch_all`, and both row queries retain a defensive `limit + 1` cap. The
/// returned count and per-lineage high-waters are derived inside this adapter;
/// no caller summary is accepted. Legacy rows without complete #65 and #80
/// evidence are intentionally outside this v1 projection.
pub async fn load_local_chain_swap_recovery_snapshot_v1(
    pool: &PgPool,
) -> Result<LocalChainSwapRecoverySnapshotV1, LocalRecoverySnapshotReadErrorV1> {
    let mut tx = pool.begin().await.map_err(|_| {
        LocalRecoverySnapshotReadErrorV1::Database(LocalRecoverySnapshotReadStageV1::Begin)
    })?;

    if sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return rollback_with(
            tx,
            LocalRecoverySnapshotReadErrorV1::Database(
                LocalRecoverySnapshotReadStageV1::SetIsolation,
            ),
        )
        .await;
    }

    let snapshot = read_snapshot(&mut tx).await;
    match snapshot {
        Ok(snapshot) => {
            tx.commit().await.map_err(|_| {
                LocalRecoverySnapshotReadErrorV1::Database(LocalRecoverySnapshotReadStageV1::Commit)
            })?;
            Ok(snapshot)
        }
        Err(error) => rollback_with(tx, error).await,
    }
}

async fn rollback_with(
    tx: Transaction<'_, Postgres>,
    error: LocalRecoverySnapshotReadErrorV1,
) -> Result<LocalChainSwapRecoverySnapshotV1, LocalRecoverySnapshotReadErrorV1> {
    match tx.rollback().await {
        Ok(()) => Err(error),
        Err(_) => Err(LocalRecoverySnapshotReadErrorV1::Database(
            LocalRecoverySnapshotReadStageV1::Rollback,
        )),
    }
}

async fn read_snapshot(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<LocalChainSwapRecoverySnapshotV1, LocalRecoverySnapshotReadErrorV1> {
    let (record_count, invalid_shape_count): (i64, i64) = sqlx::query_as(RECORD_COUNT_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| {
            LocalRecoverySnapshotReadErrorV1::Database(
                LocalRecoverySnapshotReadStageV1::CountRecords,
            )
        })?;
    let record_count = usize::try_from(record_count)
        .map_err(|_| LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence)?;
    if record_count > MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1 {
        return Err(LocalRecoverySnapshotReadErrorV1::TooManyRecords);
    }
    if invalid_shape_count != 0 {
        return Err(LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence);
    }

    let lineage_count: i64 = sqlx::query_scalar(LINEAGE_COUNT_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| {
            LocalRecoverySnapshotReadErrorV1::Database(
                LocalRecoverySnapshotReadStageV1::CountLineages,
            )
        })?;
    let lineage_count = usize::try_from(lineage_count)
        .map_err(|_| LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence)?;
    if lineage_count > MAX_RECOVERY_AUDIT_LOCAL_LINEAGES_V1 {
        return Err(LocalRecoverySnapshotReadErrorV1::TooManyLineages);
    }

    let invalid_allocation_count: i64 = sqlx::query_scalar(INVALID_ALLOCATION_COUNT_SQL)
        .bind(MAX_UNHARDENED_SWAP_CHILD_INDEX)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| {
            LocalRecoverySnapshotReadErrorV1::Database(
                LocalRecoverySnapshotReadStageV1::ValidateAllocations,
            )
        })?;
    if invalid_allocation_count != 0 {
        return Err(LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence);
    }

    let record_limit = i64::try_from(MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1 + 1)
        .map_err(|_| LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence)?;
    let rows = sqlx::query_as::<_, RecoveryRecordRow>(RECORDS_SQL)
        .bind(record_limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(|_| {
            LocalRecoverySnapshotReadErrorV1::Database(
                LocalRecoverySnapshotReadStageV1::ReadRecords,
            )
        })?;
    if rows.len() != record_count {
        return Err(LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence);
    }
    let records = rows
        .into_iter()
        .map(recovery_evidence_from_row)
        .collect::<Result<Vec<_>, _>>()?;

    let lineage_limit = i64::try_from(MAX_RECOVERY_AUDIT_LOCAL_LINEAGES_V1 + 1)
        .map_err(|_| LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence)?;
    let lineage_rows = sqlx::query_as::<_, RecoveryLineageRow>(LINEAGE_HIGH_WATERS_SQL)
        .bind(lineage_limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(|_| {
            LocalRecoverySnapshotReadErrorV1::Database(
                LocalRecoverySnapshotReadStageV1::ReadLineages,
            )
        })?;
    if lineage_rows.len() != lineage_count {
        return Err(LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence);
    }
    let lineage_high_waters = lineage_rows
        .into_iter()
        .map(|row| LocalRecoveryLineageHighWaterV1 {
            root_fingerprint: row.root_fingerprint,
            key_epoch: row.key_epoch,
            derivation_scheme_version: row.derivation_scheme_version,
            child_index: row.child_index,
        })
        .collect();

    let snapshot = LocalChainSwapRecoverySnapshotV1 {
        records,
        summary: LocalChainSwapRecoverySnapshotSummaryV1 {
            record_count,
            lineage_high_waters,
        },
    };

    // Reuse the accepted pure audit's complete local validation boundary. An
    // empty manifest set performs no cross-source classification but still
    // validates identities, duplicates, bounds, and allocator coverage.
    audit_manifest_set_against_local_recovery_snapshot_v1(&[], &snapshot)
        .map_err(|_| LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence)?;

    Ok(snapshot)
}

fn recovery_evidence_from_row(
    row: RecoveryRecordRow,
) -> Result<LocalChainSwapRecoveryEvidenceV1, LocalRecoverySnapshotReadErrorV1> {
    let claim_matches_chain = row.claim_allocation_id == row.chain_claim_allocation_id
        && row.claim_root_fingerprint == row.chain_root_fingerprint
        && row.claim_key_epoch == row.chain_key_epoch
        && row.claim_derivation_scheme_version == row.chain_derivation_scheme_version
        && row.claim_child_index == row.chain_claim_child_index
        && row.claim_public_key_hex == row.chain_claim_public_key_hex
        && row.claim_preimage_hash_hex.as_deref() == Some(&row.chain_preimage_hash_hex)
        && row.claim_purpose == "chain_claim";
    let refund_matches_chain = row.refund_allocation_id == row.chain_refund_allocation_id
        && row.refund_root_fingerprint == row.chain_root_fingerprint
        && row.refund_key_epoch == row.chain_key_epoch
        && row.refund_derivation_scheme_version == row.chain_derivation_scheme_version
        && row.refund_child_index == row.chain_refund_child_index
        && row.refund_public_key_hex == row.chain_refund_public_key_hex
        && row.refund_preimage_hash_hex.is_none()
        && row.refund_purpose == "chain_refund";
    if !claim_matches_chain || !refund_matches_chain {
        return Err(LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence);
    }

    Ok(LocalChainSwapRecoveryEvidenceV1 {
        chain_swap_id: row.chain_swap_id,
        boltz_swap_id: row.boltz_swap_id,
        root_fingerprint: row.chain_root_fingerprint,
        key_epoch: row.chain_key_epoch,
        derivation_scheme_version: row.chain_derivation_scheme_version,
        claim: LocalChainSwapRecoveryAllocationV1 {
            allocation_id: row.claim_allocation_id,
            child_index: row.claim_child_index,
            compressed_public_key_hex: row.claim_public_key_hex,
        },
        refund: LocalChainSwapRecoveryAllocationV1 {
            allocation_id: row.refund_allocation_id,
            child_index: row.refund_child_index,
            compressed_public_key_hex: row.refund_public_key_hex,
        },
        claim_preimage_sha256: row.chain_preimage_hash_hex,
        canonical_creation_response_sha256: row.creation_response_sha256,
    })
}

#[cfg(test)]
mod tests {
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use uuid::Uuid;

    use super::*;

    fn public_key(scalar: u8) -> String {
        PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[scalar; 32]).unwrap(),
        )
        .to_string()
    }

    fn valid_row() -> RecoveryRecordRow {
        RecoveryRecordRow {
            chain_swap_id: Uuid::from_u128(1),
            boltz_swap_id: "providerid".into(),
            chain_root_fingerprint: "0011223344556677".into(),
            chain_key_epoch: 1,
            chain_derivation_scheme_version: 1,
            chain_claim_allocation_id: Uuid::from_u128(2),
            chain_refund_allocation_id: Uuid::from_u128(3),
            chain_claim_child_index: 10,
            chain_refund_child_index: 11,
            chain_claim_public_key_hex: public_key(1),
            chain_refund_public_key_hex: public_key(2),
            chain_preimage_hash_hex: "aa".repeat(32),
            creation_response_sha256: "bb".repeat(32),
            claim_allocation_id: Uuid::from_u128(2),
            claim_root_fingerprint: "0011223344556677".into(),
            claim_key_epoch: 1,
            claim_derivation_scheme_version: 1,
            claim_child_index: 10,
            claim_purpose: "chain_claim".into(),
            claim_public_key_hex: public_key(1),
            claim_preimage_hash_hex: Some("aa".repeat(32)),
            refund_allocation_id: Uuid::from_u128(3),
            refund_root_fingerprint: "0011223344556677".into(),
            refund_key_epoch: 1,
            refund_derivation_scheme_version: 1,
            refund_child_index: 11,
            refund_purpose: "chain_refund".into(),
            refund_public_key_hex: public_key(2),
            refund_preimage_hash_hex: None,
        }
    }

    #[test]
    fn recovery_projection_selects_only_approved_public_evidence() {
        for predicate in [
            "claim_key_allocation_id IS NOT NULL",
            "creation_response_sha256 IS NOT NULL",
        ] {
            assert!(RECORD_COUNT_SQL.contains(predicate));
            assert!(RECORDS_SQL.contains(predicate));
        }
        assert!(RECORD_COUNT_SQL.contains("invalid_shape_count"));
        assert!(RECORD_COUNT_SQL.contains("octet_length(boltz_swap_id)"));
        assert!(INVALID_ALLOCATION_COUNT_SQL.contains("child_index NOT BETWEEN 0 AND $1"));
        for forbidden in [
            "boltz_response_json",
            "preimage_hex",
            "claim_key_hex",
            "refund_key_hex",
            "merchant_liquid_destination",
            "merchant_emergency_btc_address",
            "user_lock_amount_sat",
            "server_lock_amount_sat",
            "canonical_pair_quote_json",
        ] {
            assert!(!RECORDS_SQL.contains(forbidden), "selected {forbidden}");
        }
        assert!(RECORDS_SQL.contains("ORDER BY chain.id ASC"));
        assert!(LINEAGE_HIGH_WATERS_SQL.contains(
            "ORDER BY root_fingerprint ASC, key_epoch ASC, derivation_scheme_version ASC"
        ));
        assert!(RECORDS_SQL.contains("LIMIT $1"));
        assert!(LINEAGE_HIGH_WATERS_SQL.contains("LIMIT $1"));
    }

    #[test]
    fn recovery_projection_uses_registry_values_and_rejects_denormalized_conflicts() {
        let evidence = recovery_evidence_from_row(valid_row()).unwrap();
        assert_eq!(evidence.claim.allocation_id, Uuid::from_u128(2));
        assert_eq!(evidence.refund.allocation_id, Uuid::from_u128(3));
        assert_eq!(evidence.claim_preimage_sha256, "aa".repeat(32));

        let mut wrong_purpose = valid_row();
        wrong_purpose.claim_purpose = "reverse_claim".into();
        assert_eq!(
            recovery_evidence_from_row(wrong_purpose).unwrap_err(),
            LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence
        );

        let mut wrong_copy = valid_row();
        wrong_copy.chain_refund_child_index += 1;
        assert_eq!(
            recovery_evidence_from_row(wrong_copy).unwrap_err(),
            LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence
        );

        let mut refund_with_preimage = valid_row();
        refund_with_preimage.refund_preimage_hash_hex = Some("cc".repeat(32));
        assert_eq!(
            recovery_evidence_from_row(refund_with_preimage).unwrap_err(),
            LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence
        );
    }

    #[test]
    fn recovery_projection_errors_are_bounded_redacted_and_source_free() {
        const SENTINEL: &str = "OperationalSecretOrDatabaseUrlMustNotEscape";
        let errors = [
            LocalRecoverySnapshotReadErrorV1::Database(
                LocalRecoverySnapshotReadStageV1::ReadRecords,
            ),
            LocalRecoverySnapshotReadErrorV1::TooManyRecords,
            LocalRecoverySnapshotReadErrorV1::TooManyLineages,
            LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence,
        ];
        for error in errors {
            let display = error.to_string();
            let debug = format!("{error:?}");
            assert!(display.len() <= 96);
            assert!(!display.contains(SENTINEL));
            assert!(!debug.contains(SENTINEL));
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}

use std::fmt;
use std::str::FromStr;

use secp256k1::schnorr::Signature;
use secp256k1::XOnlyPublicKey;
use sqlx::{Executor, PgPool, Postgres};
use uuid::Uuid;

use crate::recovery_address_registration::{
    VerifiedRecoveryAddressRegistration, RECOVERY_ADDRESS_REGISTRATION_VERSION,
};
use crate::validators;

/// PostgreSQL advisory-lock class shared with migration 053 (ASCII "RCMT").
const RECOVERY_COMMITMENT_LOCK_CLASS: i32 = 1_380_142_420;

const COMMITMENT_COLUMNS: &str = "commitment_id, npub, contract_format_version, \
    commitment_version, canonical_btc_address, original_signature, signed_at_unix, \
    EXTRACT(EPOCH FROM registered_at)::BIGINT AS registered_at_unix";

/// One immutable, merchant-wide recovery-address commitment.
///
/// Address and signature access is explicit so ordinary debug logging cannot
/// disclose private recovery policy or replayable authorization evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryAddressCommitment {
    pub commitment_id: Uuid,
    pub npub: String,
    pub contract_format_version: u16,
    pub commitment_version: u64,
    canonical_btc_address: String,
    original_signature: String,
    pub signed_at_unix: u64,
    pub registered_at_unix: i64,
}

impl RecoveryAddressCommitment {
    pub fn canonical_btc_address(&self) -> &str {
        &self.canonical_btc_address
    }

    pub fn original_signature(&self) -> &str {
        &self.original_signature
    }
}

impl fmt::Debug for RecoveryAddressCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryAddressCommitment")
            .field("commitment_id", &self.commitment_id)
            .field("npub", &"<redacted>")
            .field("contract_format_version", &self.contract_format_version)
            .field("commitment_version", &self.commitment_version)
            .field("canonical_btc_address", &"<redacted>")
            .field("original_signature", &"<redacted>")
            .field("signed_at_unix", &self.signed_at_unix)
            .field("registered_at_unix", &self.registered_at_unix)
            .finish()
    }
}

pub enum RecoveryAddressCommitmentError {
    Database(sqlx::Error),
    InvalidEvidence { field: &'static str },
    SourceIdentityNotActive,
    TimestampOutsideDatabaseRange { timestamp: u64 },
    VersionExhausted,
    CorruptCommitmentId { commitment_id: Uuid },
    CorruptContractFormatVersion { version: i16 },
    CorruptCommitmentVersion { version: i64 },
    CorruptSignedTimestamp { timestamp: i64 },
    CorruptRegistrationTimestamp { timestamp: i64 },
}

impl fmt::Debug for RecoveryAddressCommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_variant = match self {
            Self::Database(_) => "Database(<redacted>)",
            Self::InvalidEvidence { .. } => "InvalidEvidence(<redacted>)",
            Self::SourceIdentityNotActive => "SourceIdentityNotActive",
            Self::TimestampOutsideDatabaseRange { .. } => {
                "TimestampOutsideDatabaseRange(<redacted>)"
            }
            Self::VersionExhausted => "VersionExhausted",
            Self::CorruptCommitmentId { .. } => "CorruptCommitmentId(<redacted>)",
            Self::CorruptContractFormatVersion { .. } => "CorruptContractFormatVersion(<redacted>)",
            Self::CorruptCommitmentVersion { .. } => "CorruptCommitmentVersion(<redacted>)",
            Self::CorruptSignedTimestamp { .. } => "CorruptSignedTimestamp(<redacted>)",
            Self::CorruptRegistrationTimestamp { .. } => "CorruptRegistrationTimestamp(<redacted>)",
        };
        f.write_str(redacted_variant)
    }
}

impl fmt::Display for RecoveryAddressCommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => {
                f.write_str("recovery-address commitment database operation failed")
            }
            Self::InvalidEvidence { field } => {
                write!(f, "recovery-address commitment has invalid {field}")
            }
            Self::SourceIdentityNotActive => {
                f.write_str("recovery-address commitment source identity is not active")
            }
            Self::TimestampOutsideDatabaseRange { .. } => {
                f.write_str("recovery-address signed timestamp is outside PostgreSQL BIGINT")
            }
            Self::VersionExhausted => {
                f.write_str("recovery-address commitment version exhausted PostgreSQL BIGINT")
            }
            Self::CorruptCommitmentId { .. } => {
                f.write_str("recovery-address commitment has a nil stored identity")
            }
            Self::CorruptContractFormatVersion { .. } => {
                f.write_str("recovery-address commitment has an invalid stored contract version")
            }
            Self::CorruptCommitmentVersion { .. } => {
                f.write_str("recovery-address commitment has an invalid stored sequence")
            }
            Self::CorruptSignedTimestamp { .. } => {
                f.write_str("recovery-address commitment has an invalid stored signed timestamp")
            }
            Self::CorruptRegistrationTimestamp { .. } => f.write_str(
                "recovery-address commitment has an invalid stored registration timestamp",
            ),
        }
    }
}

impl std::error::Error for RecoveryAddressCommitmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // PostgreSQL constraint detail can contain the auth npub, recovery
        // address, and signature. Chained reporters must not bypass the
        // redacted Display/Debug boundary by rendering the raw sqlx source.
        None
    }
}

impl From<sqlx::Error> for RecoveryAddressCommitmentError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(sqlx::FromRow)]
struct RecoveryAddressCommitmentDbRow {
    commitment_id: Uuid,
    npub: String,
    contract_format_version: i16,
    commitment_version: i64,
    canonical_btc_address: String,
    original_signature: String,
    signed_at_unix: i64,
    registered_at_unix: i64,
}

impl TryFrom<RecoveryAddressCommitmentDbRow> for RecoveryAddressCommitment {
    type Error = RecoveryAddressCommitmentError;

    fn try_from(row: RecoveryAddressCommitmentDbRow) -> Result<Self, Self::Error> {
        if row.commitment_id.is_nil() {
            return Err(RecoveryAddressCommitmentError::CorruptCommitmentId {
                commitment_id: row.commitment_id,
            });
        }
        let contract_format_version = u16::try_from(row.contract_format_version).map_err(|_| {
            RecoveryAddressCommitmentError::CorruptContractFormatVersion {
                version: row.contract_format_version,
            }
        })?;
        if contract_format_version != RECOVERY_ADDRESS_REGISTRATION_VERSION {
            return Err(
                RecoveryAddressCommitmentError::CorruptContractFormatVersion {
                    version: row.contract_format_version,
                },
            );
        }
        let commitment_version = u64::try_from(row.commitment_version).map_err(|_| {
            RecoveryAddressCommitmentError::CorruptCommitmentVersion {
                version: row.commitment_version,
            }
        })?;
        if commitment_version == 0 {
            return Err(RecoveryAddressCommitmentError::CorruptCommitmentVersion {
                version: row.commitment_version,
            });
        }
        let signed_at_unix = u64::try_from(row.signed_at_unix).map_err(|_| {
            RecoveryAddressCommitmentError::CorruptSignedTimestamp {
                timestamp: row.signed_at_unix,
            }
        })?;
        if signed_at_unix == 0 {
            return Err(RecoveryAddressCommitmentError::CorruptSignedTimestamp {
                timestamp: row.signed_at_unix,
            });
        }
        if row.registered_at_unix <= 0 {
            return Err(
                RecoveryAddressCommitmentError::CorruptRegistrationTimestamp {
                    timestamp: row.registered_at_unix,
                },
            );
        }
        validate_npub(&row.npub)?;
        validate_canonical_address(&row.canonical_btc_address)?;
        validate_canonical_signature(&row.original_signature)?;

        Ok(Self {
            commitment_id: row.commitment_id,
            npub: row.npub,
            contract_format_version,
            commitment_version,
            canonical_btc_address: row.canonical_btc_address,
            original_signature: row.original_signature,
            signed_at_unix,
            registered_at_unix: row.registered_at_unix,
        })
    }
}

/// Persist a verified commitment, returning the original row on an exact
/// request retry. Distinct rotations for the same npub serialize under one
/// transaction-scoped advisory lock and receive contiguous versions.
pub async fn persist_recovery_address_commitment(
    pool: &PgPool,
    registration: &VerifiedRecoveryAddressRegistration,
) -> Result<RecoveryAddressCommitment, RecoveryAddressCommitmentError> {
    validate_registration(registration)?;
    let contract_format_version = i16::try_from(registration.version()).map_err(|_| {
        RecoveryAddressCommitmentError::InvalidEvidence {
            field: "contract_format_version",
        }
    })?;
    let signed_at_unix = i64::try_from(registration.timestamp()).map_err(|_| {
        RecoveryAddressCommitmentError::TimestampOutsideDatabaseRange {
            timestamp: registration.timestamp(),
        }
    })?;

    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
        .bind(RECOVERY_COMMITMENT_LOCK_CLASS)
        .bind(registration.npub())
        .execute(&mut *tx)
        .await?;

    // Admission is re-checked under the same transaction lock even for exact
    // retries. FOR UPDATE conflicts with lifecycle deactivation so the two
    // operations have one database-defined order. Route checks are only an
    // optimization; persistence owns the invariant.
    let source_exists: Option<i32> = sqlx::query_scalar(
        "SELECT 1 \
           FROM users \
          WHERE npub = $1 \
            AND is_active = TRUE \
          FOR UPDATE",
    )
    .bind(registration.npub())
    .fetch_optional(&mut *tx)
    .await?;
    if source_exists.is_none() {
        return Err(RecoveryAddressCommitmentError::SourceIdentityNotActive);
    }

    let exact = sqlx::query_as::<_, RecoveryAddressCommitmentDbRow>(&format!(
        "SELECT {COMMITMENT_COLUMNS} \
           FROM recovery_address_commitments \
          WHERE npub = $1 \
            AND contract_format_version = $2 \
            AND canonical_btc_address = $3 \
            AND original_signature = $4 \
            AND signed_at_unix = $5"
    ))
    .bind(registration.npub())
    .bind(contract_format_version)
    .bind(registration.canonical_btc_address())
    .bind(registration.original_signature())
    .bind(signed_at_unix)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(exact) = exact {
        let exact = exact.try_into()?;
        tx.commit().await?;
        return Ok(exact);
    }

    let tail: Option<i64> = sqlx::query_scalar(
        "SELECT commitment_version \
           FROM recovery_address_commitments \
          WHERE npub = $1 \
          ORDER BY commitment_version DESC \
          LIMIT 1",
    )
    .bind(registration.npub())
    .fetch_optional(&mut *tx)
    .await?;
    let commitment_version = match tail {
        None => 1,
        Some(i64::MAX) => return Err(RecoveryAddressCommitmentError::VersionExhausted),
        Some(version) if version > 0 => version + 1,
        Some(version) => {
            return Err(RecoveryAddressCommitmentError::CorruptCommitmentVersion { version })
        }
    };

    let row = sqlx::query_as::<_, RecoveryAddressCommitmentDbRow>(&format!(
        "INSERT INTO recovery_address_commitments (\
             commitment_id, npub, contract_format_version, commitment_version, \
             canonical_btc_address, original_signature, signed_at_unix\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING {COMMITMENT_COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(registration.npub())
    .bind(contract_format_version)
    .bind(commitment_version)
    .bind(registration.canonical_btc_address())
    .bind(registration.original_signature())
    .bind(signed_at_unix)
    .fetch_one(&mut *tx)
    .await?;
    let commitment = row.try_into()?;
    tx.commit().await?;
    Ok(commitment)
}

/// Select the latest immutable commitment for a merchant identity. The generic
/// executor lets future swap creation use the same transaction that inserts
/// its eventual commitment reference.
pub async fn select_current_recovery_address_commitment<'e, E>(
    executor: E,
    npub: &str,
) -> Result<Option<RecoveryAddressCommitment>, RecoveryAddressCommitmentError>
where
    E: Executor<'e, Database = Postgres>,
{
    validate_npub(npub)?;
    let row = sqlx::query_as::<_, RecoveryAddressCommitmentDbRow>(&format!(
        "SELECT {COMMITMENT_COLUMNS} \
           FROM recovery_address_commitments \
          WHERE npub = $1 \
          ORDER BY commitment_version DESC \
          LIMIT 1"
    ))
    .bind(npub)
    .fetch_optional(executor)
    .await?;
    row.map(TryInto::try_into).transpose()
}

/// Select one immutable commitment by the identity copied into a chain swap.
///
/// Automatic recovery must use the exact historical commitment retained by
/// the swap, not the merchant's current (possibly rotated) default address.
/// The generic executor lets the recovery gate perform this read inside the
/// same transaction and row/advisory-lock boundary as its final decision.
pub async fn select_recovery_address_commitment_by_id<'e, E>(
    executor: E,
    commitment_id: Uuid,
) -> Result<Option<RecoveryAddressCommitment>, RecoveryAddressCommitmentError>
where
    E: Executor<'e, Database = Postgres>,
{
    if commitment_id.is_nil() {
        return Err(RecoveryAddressCommitmentError::CorruptCommitmentId { commitment_id });
    }
    let row = sqlx::query_as::<_, RecoveryAddressCommitmentDbRow>(&format!(
        "SELECT {COMMITMENT_COLUMNS} \
           FROM recovery_address_commitments \
          WHERE commitment_id = $1"
    ))
    .bind(commitment_id)
    .fetch_optional(executor)
    .await?;
    row.map(TryInto::try_into).transpose()
}

fn validate_registration(
    registration: &VerifiedRecoveryAddressRegistration,
) -> Result<(), RecoveryAddressCommitmentError> {
    if registration.version() != RECOVERY_ADDRESS_REGISTRATION_VERSION {
        return Err(RecoveryAddressCommitmentError::InvalidEvidence {
            field: "contract_format_version",
        });
    }
    validate_npub(registration.npub())?;
    validate_canonical_address(registration.canonical_btc_address())?;
    validate_canonical_signature(registration.original_signature())?;
    if registration.timestamp() == 0 {
        return Err(RecoveryAddressCommitmentError::InvalidEvidence {
            field: "signed_at_unix",
        });
    }
    Ok(())
}

fn validate_npub(npub: &str) -> Result<(), RecoveryAddressCommitmentError> {
    let parsed = XOnlyPublicKey::from_str(npub)
        .map_err(|_| RecoveryAddressCommitmentError::InvalidEvidence { field: "npub" })?;
    if parsed.to_string() != npub {
        return Err(RecoveryAddressCommitmentError::InvalidEvidence { field: "npub" });
    }
    Ok(())
}

fn validate_canonical_address(address: &str) -> Result<(), RecoveryAddressCommitmentError> {
    let canonical = validators::canonical_btc_mainnet_address(address).map_err(|_| {
        RecoveryAddressCommitmentError::InvalidEvidence {
            field: "canonical_btc_address",
        }
    })?;
    if canonical != address {
        return Err(RecoveryAddressCommitmentError::InvalidEvidence {
            field: "canonical_btc_address",
        });
    }
    Ok(())
}

fn validate_canonical_signature(signature: &str) -> Result<(), RecoveryAddressCommitmentError> {
    let parsed = Signature::from_str(signature).map_err(|_| {
        RecoveryAddressCommitmentError::InvalidEvidence {
            field: "original_signature",
        }
    })?;
    if parsed.to_string() != signature {
        return Err(RecoveryAddressCommitmentError::InvalidEvidence {
            field: "original_signature",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_db_row() -> RecoveryAddressCommitmentDbRow {
        RecoveryAddressCommitmentDbRow {
            commitment_id: Uuid::new_v4(),
            npub: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            contract_format_version: 1,
            commitment_version: 1,
            canonical_btc_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            original_signature: "11".repeat(64),
            signed_at_unix: 1_700_000_000,
            registered_at_unix: 1_700_000_001,
        }
    }

    #[test]
    fn stored_nil_commitment_id_is_rejected() {
        let mut row = valid_db_row();
        row.commitment_id = Uuid::nil();
        assert!(matches!(
            RecoveryAddressCommitment::try_from(row),
            Err(RecoveryAddressCommitmentError::CorruptCommitmentId { commitment_id })
                if commitment_id.is_nil()
        ));
    }

    #[test]
    fn stored_non_positive_registration_timestamp_is_rejected() {
        let mut row = valid_db_row();
        row.registered_at_unix = 0;
        assert!(matches!(
            RecoveryAddressCommitment::try_from(row),
            Err(RecoveryAddressCommitmentError::CorruptRegistrationTimestamp { timestamp: 0 })
        ));
    }
}

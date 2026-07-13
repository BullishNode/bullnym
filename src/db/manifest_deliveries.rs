use std::fmt;

use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// PostgreSQL advisory-lock namespace shared with migration 052.
const MANIFEST_LEDGER_LOCK_CLASS: i32 = 1_112_886_348;
const MANIFEST_LEDGER_LOCK_OBJECT: i32 = 87;
pub const MAX_MANIFEST_ENVELOPE_BYTES: usize = 1_048_576;
pub const MAX_MANIFEST_AUDIT_PAGE: usize = 1_000;

const DELIVERY_COLUMNS: &str = "manifest_id, chain_swap_id, manifest_sequence, \
    previous_manifest_id, encrypted_envelope, envelope_sha256, delivery_state, \
    EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at_unix, \
    EXTRACT(EPOCH FROM delivered_at)::BIGINT AS delivered_at_unix";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestDeliveryIdentity {
    pub manifest_id: Uuid,
    pub chain_swap_id: Uuid,
    /// Checked projection of PostgreSQL's positive `BIGINT` sequence.
    pub manifest_sequence: u64,
    pub previous_manifest_id: Option<Uuid>,
}

/// Tail identity allocated while the caller's transaction owns the dedicated
/// manifest-ledger advisory lock. Fields are private so ordinary callers
/// cannot manufacture a gap or branch without bypassing this API; migration
/// 052 independently enforces the same topology for direct SQL writers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestSequenceReservation {
    manifest_sequence: u64,
    previous_manifest_id: Option<Uuid>,
}

impl ManifestSequenceReservation {
    pub fn manifest_sequence(self) -> u64 {
        self.manifest_sequence
    }

    pub fn previous_manifest_id(self) -> Option<Uuid> {
        self.previous_manifest_id
    }

    pub fn identity(
        self,
        manifest_id: Uuid,
        chain_swap_id: Uuid,
    ) -> Result<ManifestDeliveryIdentity, ManifestDeliveryError> {
        if manifest_id.is_nil() {
            return Err(ManifestDeliveryError::InvalidIdentity {
                field: "manifest_id",
            });
        }
        if chain_swap_id.is_nil() {
            return Err(ManifestDeliveryError::InvalidIdentity {
                field: "chain_swap_id",
            });
        }
        Ok(ManifestDeliveryIdentity {
            manifest_id,
            chain_swap_id,
            manifest_sequence: self.manifest_sequence,
            previous_manifest_id: self.previous_manifest_id,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ChainSwapManifestDelivery {
    pub manifest_id: Uuid,
    pub chain_swap_id: Uuid,
    pub manifest_sequence: u64,
    pub previous_manifest_id: Option<Uuid>,
    encrypted_envelope: String,
    pub envelope_sha256: String,
    pub delivery_state: String,
    pub created_at_unix: i64,
    pub delivered_at_unix: Option<i64>,
}

impl ChainSwapManifestDelivery {
    pub fn identity(&self) -> ManifestDeliveryIdentity {
        ManifestDeliveryIdentity {
            manifest_id: self.manifest_id,
            chain_swap_id: self.chain_swap_id,
            manifest_sequence: self.manifest_sequence,
            previous_manifest_id: self.previous_manifest_id,
        }
    }

    pub fn encrypted_envelope(&self) -> &str {
        &self.encrypted_envelope
    }

    pub fn into_encrypted_envelope(self) -> String {
        self.encrypted_envelope
    }
}

impl fmt::Debug for ChainSwapManifestDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainSwapManifestDelivery")
            .field("manifest_id", &self.manifest_id)
            .field("chain_swap_id", &self.chain_swap_id)
            .field("manifest_sequence", &self.manifest_sequence)
            .field("previous_manifest_id", &self.previous_manifest_id)
            .field("encrypted_envelope_bytes", &self.encrypted_envelope.len())
            .field("encrypted_envelope", &"<redacted>")
            .field("envelope_sha256", &self.envelope_sha256)
            .field("delivery_state", &self.delivery_state)
            .field("created_at_unix", &self.created_at_unix)
            .field("delivered_at_unix", &self.delivered_at_unix)
            .finish()
    }
}

#[derive(Debug)]
pub enum ManifestDeliveryError {
    Database(sqlx::Error),
    PendingDelivery {
        manifest_id: Uuid,
        chain_swap_id: Uuid,
        manifest_sequence: u64,
    },
    InvalidEnvelopeSize {
        actual: usize,
        max: usize,
    },
    InvalidAuditLimit {
        requested: usize,
        max: usize,
    },
    InvalidIdentity {
        field: &'static str,
    },
    SequenceExhausted,
    SequenceOutsideDatabaseRange {
        sequence: u64,
    },
    CorruptDatabaseSequence {
        sequence: i64,
    },
}

impl fmt::Display for ManifestDeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => f.write_str("manifest delivery database operation failed"),
            Self::PendingDelivery { .. } => {
                f.write_str("a prior recovery-manifest delivery is still pending")
            }
            Self::InvalidEnvelopeSize { actual, max } => write!(
                f,
                "encrypted recovery manifest has {actual} bytes; allowed range is 1..={max}"
            ),
            Self::InvalidAuditLimit { requested, max } => write!(
                f,
                "manifest delivery audit limit {requested} is outside 1..={max}"
            ),
            Self::InvalidIdentity { field } => {
                write!(f, "manifest delivery {field} must not be nil")
            }
            Self::SequenceExhausted => {
                f.write_str("manifest delivery sequence exhausted PostgreSQL BIGINT")
            }
            Self::SequenceOutsideDatabaseRange { .. } => {
                f.write_str("manifest delivery sequence is outside PostgreSQL BIGINT")
            }
            Self::CorruptDatabaseSequence { .. } => {
                f.write_str("manifest delivery database contains a non-positive sequence")
            }
        }
    }
}

impl std::error::Error for ManifestDeliveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for ManifestDeliveryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(sqlx::FromRow)]
struct ManifestDeliveryDbRow {
    manifest_id: Uuid,
    chain_swap_id: Uuid,
    manifest_sequence: i64,
    previous_manifest_id: Option<Uuid>,
    encrypted_envelope: String,
    envelope_sha256: String,
    delivery_state: String,
    created_at_unix: i64,
    delivered_at_unix: Option<i64>,
}

impl TryFrom<ManifestDeliveryDbRow> for ChainSwapManifestDelivery {
    type Error = ManifestDeliveryError;

    fn try_from(row: ManifestDeliveryDbRow) -> Result<Self, Self::Error> {
        let manifest_sequence = u64::try_from(row.manifest_sequence).map_err(|_| {
            ManifestDeliveryError::CorruptDatabaseSequence {
                sequence: row.manifest_sequence,
            }
        })?;
        if manifest_sequence == 0 {
            return Err(ManifestDeliveryError::CorruptDatabaseSequence {
                sequence: row.manifest_sequence,
            });
        }
        Ok(Self {
            manifest_id: row.manifest_id,
            chain_swap_id: row.chain_swap_id,
            manifest_sequence,
            previous_manifest_id: row.previous_manifest_id,
            encrypted_envelope: row.encrypted_envelope,
            envelope_sha256: row.envelope_sha256,
            delivery_state: row.delivery_state,
            created_at_unix: row.created_at_unix,
            delivered_at_unix: row.delivered_at_unix,
        })
    }
}

/// Serialize global sequence/predecessor allocation inside the caller's
/// transaction. A pending row is returned as a typed refusal: the caller must
/// resume and deliver it before signing any later manifest.
pub async fn lock_manifest_delivery_tail(
    conn: &mut PgConnection,
) -> Result<ManifestSequenceReservation, ManifestDeliveryError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(MANIFEST_LEDGER_LOCK_CLASS)
        .bind(MANIFEST_LEDGER_LOCK_OBJECT)
        .execute(&mut *conn)
        .await?;

    let pending: Option<(Uuid, Uuid, i64)> = sqlx::query_as(
        "SELECT manifest_id, chain_swap_id, manifest_sequence \
           FROM chain_swap_manifest_deliveries \
          WHERE delivery_state = 'pending' \
          ORDER BY manifest_sequence \
          LIMIT 1",
    )
    .fetch_optional(&mut *conn)
    .await?;
    if let Some((manifest_id, chain_swap_id, manifest_sequence)) = pending {
        let stored_sequence = manifest_sequence;
        let manifest_sequence = u64::try_from(stored_sequence).map_err(|_| {
            ManifestDeliveryError::CorruptDatabaseSequence {
                sequence: stored_sequence,
            }
        })?;
        if manifest_sequence == 0 {
            return Err(ManifestDeliveryError::CorruptDatabaseSequence {
                sequence: stored_sequence,
            });
        }
        return Err(ManifestDeliveryError::PendingDelivery {
            manifest_id,
            chain_swap_id,
            manifest_sequence,
        });
    }

    let tail: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT manifest_id, manifest_sequence \
           FROM chain_swap_manifest_deliveries \
          ORDER BY manifest_sequence DESC \
          LIMIT 1",
    )
    .fetch_optional(&mut *conn)
    .await?;

    match tail {
        None => Ok(ManifestSequenceReservation {
            manifest_sequence: 1,
            previous_manifest_id: None,
        }),
        Some((_, i64::MAX)) => Err(ManifestDeliveryError::SequenceExhausted),
        Some((manifest_id, sequence)) if sequence > 0 => Ok(ManifestSequenceReservation {
            manifest_sequence: u64::try_from(sequence + 1)
                .expect("positive BIGINT tail plus one fits u64"),
            previous_manifest_id: Some(manifest_id),
        }),
        Some((_, sequence)) => Err(ManifestDeliveryError::CorruptDatabaseSequence { sequence }),
    }
}

/// Insert the exact caller-signed encrypted envelope while the caller's
/// transaction still owns the tail reservation lock. The database recomputes
/// and checks this SHA-256 independently. This layer cannot decrypt the
/// envelope and therefore does not claim its ciphertext binds these metadata.
pub async fn insert_manifest_delivery(
    conn: &mut PgConnection,
    identity: &ManifestDeliveryIdentity,
    encrypted_envelope: &str,
) -> Result<ChainSwapManifestDelivery, ManifestDeliveryError> {
    let actual = encrypted_envelope.len();
    if actual == 0 || actual > MAX_MANIFEST_ENVELOPE_BYTES {
        return Err(ManifestDeliveryError::InvalidEnvelopeSize {
            actual,
            max: MAX_MANIFEST_ENVELOPE_BYTES,
        });
    }
    if identity.manifest_id.is_nil() {
        return Err(ManifestDeliveryError::InvalidIdentity {
            field: "manifest_id",
        });
    }
    if identity.chain_swap_id.is_nil() {
        return Err(ManifestDeliveryError::InvalidIdentity {
            field: "chain_swap_id",
        });
    }
    let manifest_sequence = i64::try_from(identity.manifest_sequence).map_err(|_| {
        ManifestDeliveryError::SequenceOutsideDatabaseRange {
            sequence: identity.manifest_sequence,
        }
    })?;
    let envelope_sha256 = hex::encode(Sha256::digest(encrypted_envelope.as_bytes()));

    let row = sqlx::query_as::<_, ManifestDeliveryDbRow>(&format!(
        "INSERT INTO chain_swap_manifest_deliveries (\
             manifest_id, chain_swap_id, manifest_sequence, previous_manifest_id, \
             encrypted_envelope, envelope_sha256\
         ) VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING {DELIVERY_COLUMNS}"
    ))
    .bind(identity.manifest_id)
    .bind(identity.chain_swap_id)
    .bind(manifest_sequence)
    .bind(identity.previous_manifest_id)
    .bind(encrypted_envelope)
    .bind(envelope_sha256)
    .fetch_one(conn)
    .await?;
    row.try_into()
}

/// Resume every pending delivery in global sequence order. Migration 052
/// constrains this set to at most one row, but returning a list keeps recovery
/// callers fail-visible if a future version deliberately changes that policy.
pub async fn list_pending_manifest_deliveries(
    pool: &PgPool,
) -> Result<Vec<ChainSwapManifestDelivery>, ManifestDeliveryError> {
    let rows = sqlx::query_as::<_, ManifestDeliveryDbRow>(&format!(
        "SELECT {DELIVERY_COLUMNS} \
           FROM chain_swap_manifest_deliveries \
          WHERE delivery_state = 'pending' \
          ORDER BY manifest_sequence"
    ))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(TryInto::try_into).collect()
}

/// Mark delivery once, or return the already-delivered row on an exact retry.
/// Any mismatch in manifest, swap, sequence, predecessor, or envelope digest
/// returns `None` and changes nothing.
pub async fn mark_manifest_delivered(
    pool: &PgPool,
    identity: &ManifestDeliveryIdentity,
    envelope_sha256: &str,
) -> Result<Option<ChainSwapManifestDelivery>, ManifestDeliveryError> {
    let manifest_sequence = i64::try_from(identity.manifest_sequence).map_err(|_| {
        ManifestDeliveryError::SequenceOutsideDatabaseRange {
            sequence: identity.manifest_sequence,
        }
    })?;
    let row = sqlx::query_as::<_, ManifestDeliveryDbRow>(&format!(
        "UPDATE chain_swap_manifest_deliveries \
            SET delivery_state = 'delivered', \
                delivered_at = COALESCE(delivered_at, NOW()) \
          WHERE manifest_id = $1 \
            AND chain_swap_id = $2 \
            AND manifest_sequence = $3 \
            AND previous_manifest_id IS NOT DISTINCT FROM $4 \
            AND envelope_sha256 = $5 \
         RETURNING {DELIVERY_COLUMNS}"
    ))
    .bind(identity.manifest_id)
    .bind(identity.chain_swap_id)
    .bind(manifest_sequence)
    .bind(identity.previous_manifest_id)
    .bind(envelope_sha256)
    .fetch_optional(pool)
    .await?;
    row.map(TryInto::try_into).transpose()
}

pub async fn get_manifest_delivery(
    pool: &PgPool,
    manifest_id: Uuid,
) -> Result<Option<ChainSwapManifestDelivery>, ManifestDeliveryError> {
    let row = sqlx::query_as::<_, ManifestDeliveryDbRow>(&format!(
        "SELECT {DELIVERY_COLUMNS} \
           FROM chain_swap_manifest_deliveries \
          WHERE manifest_id = $1"
    ))
    .bind(manifest_id)
    .fetch_optional(pool)
    .await?;
    row.map(TryInto::try_into).transpose()
}

/// Read one bounded append-only audit page strictly after `after_sequence`.
pub async fn list_manifest_delivery_audit(
    pool: &PgPool,
    after_sequence: u64,
    limit: usize,
) -> Result<Vec<ChainSwapManifestDelivery>, ManifestDeliveryError> {
    if !(1..=MAX_MANIFEST_AUDIT_PAGE).contains(&limit) {
        return Err(ManifestDeliveryError::InvalidAuditLimit {
            requested: limit,
            max: MAX_MANIFEST_AUDIT_PAGE,
        });
    }
    let after_sequence = i64::try_from(after_sequence).map_err(|_| {
        ManifestDeliveryError::SequenceOutsideDatabaseRange {
            sequence: after_sequence,
        }
    })?;
    let rows = sqlx::query_as::<_, ManifestDeliveryDbRow>(&format!(
        "SELECT {DELIVERY_COLUMNS} \
           FROM chain_swap_manifest_deliveries \
          WHERE manifest_sequence > $1 \
          ORDER BY manifest_sequence \
          LIMIT $2"
    ))
    .bind(after_sequence)
    .bind(i64::try_from(limit).expect("bounded audit limit fits BIGINT"))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(TryInto::try_into).collect()
}

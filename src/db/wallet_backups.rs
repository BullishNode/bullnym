use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::error::AppError;

const WALLET_BACKUP_GLOBAL_LOCK_KEY: i64 = 0x5742_4143_4b55_5053;

#[derive(Clone, PartialEq, Eq)]
pub struct WalletBackupHead {
    pub generation: i64,
    etag: Vec<u8>,
    ciphertext: Option<Vec<u8>>,
    ciphertext_sha256: Option<Vec<u8>>,
    pub ciphertext_bytes: Option<i32>,
    pub updated_at_unix: i64,
    pub deleted_at_unix: Option<i64>,
}

impl WalletBackupHead {
    pub fn etag(&self) -> &[u8] {
        &self.etag
    }

    pub fn ciphertext(&self) -> Option<&[u8]> {
        self.ciphertext.as_deref()
    }

    pub fn ciphertext_sha256(&self) -> Option<&[u8]> {
        self.ciphertext_sha256.as_deref()
    }

    pub fn is_tombstone(&self) -> bool {
        self.deleted_at_unix.is_some()
    }
}

impl std::fmt::Debug for WalletBackupHead {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WalletBackupHead")
            .field("generation", &self.generation)
            .field("etag", &"<redacted>")
            .field("ciphertext", &"<redacted>")
            .field("ciphertext_sha256", &"<redacted>")
            .field("ciphertext_bytes", &self.ciphertext_bytes)
            .field("updated_at_unix", &self.updated_at_unix)
            .field("deleted_at_unix", &self.deleted_at_unix)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletBackupMutationOutcome {
    Applied,
    ExactRetry,
    HeadConflict,
    GlobalCapacityExceeded,
}

fn row_to_head(row: sqlx::postgres::PgRow) -> WalletBackupHead {
    WalletBackupHead {
        generation: row.get("generation"),
        etag: row.get("etag"),
        ciphertext: row.get("ciphertext"),
        ciphertext_sha256: row.get("ciphertext_sha256"),
        ciphertext_bytes: row.get("ciphertext_bytes"),
        updated_at_unix: row.get("updated_at_unix"),
        deleted_at_unix: row.get("deleted_at_unix"),
    }
}

async fn lock_head(
    transaction: &mut Transaction<'_, Postgres>,
    stream: &str,
    author_pubkey: &[u8],
) -> Result<(), AppError> {
    let lock_name = format!("wallet-backup:{stream}:{}", hex::encode(author_pubkey));
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_name)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn fetch_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    stream: &str,
    author_pubkey: &[u8],
) -> Result<Option<WalletBackupHead>, AppError> {
    let row = sqlx::query(
        "SELECT generation, etag, ciphertext, ciphertext_sha256, ciphertext_bytes, \
                EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at_unix, \
                EXTRACT(EPOCH FROM deleted_at)::BIGINT AS deleted_at_unix \
         FROM wallet_backup_blobs \
         WHERE stream = $1 AND author_pubkey = $2 \
         FOR UPDATE",
    )
    .bind(stream)
    .bind(author_pubkey)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(row_to_head))
}

pub async fn fetch_wallet_backup_head(
    pool: &PgPool,
    stream: &str,
    author_pubkey: &[u8],
) -> Result<Option<WalletBackupHead>, AppError> {
    let row = sqlx::query(
        "SELECT generation, etag, ciphertext, ciphertext_sha256, ciphertext_bytes, \
                EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at_unix, \
                EXTRACT(EPOCH FROM deleted_at)::BIGINT AS deleted_at_unix \
         FROM wallet_backup_blobs \
         WHERE stream = $1 AND author_pubkey = $2",
    )
    .bind(stream)
    .bind(author_pubkey)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(row_to_head))
}

#[allow(clippy::too_many_arguments)]
pub async fn store_wallet_backup(
    pool: &PgPool,
    stream: &str,
    author_pubkey: &[u8],
    generation: i64,
    expected_etag: Option<&[u8]>,
    etag: &[u8],
    ciphertext: &[u8],
    ciphertext_sha256: &[u8],
    global_stored_bytes_limit: u64,
) -> Result<WalletBackupMutationOutcome, AppError> {
    let mut transaction = pool.begin().await?;
    lock_head(&mut transaction, stream, author_pubkey).await?;
    let current = fetch_in_transaction(&mut transaction, stream, author_pubkey).await?;

    if let Some(current) = current.as_ref() {
        if !current.is_tombstone()
            && current.generation == generation
            && current.etag() == etag
            && current.ciphertext() == Some(ciphertext)
            && current.ciphertext_sha256() == Some(ciphertext_sha256)
        {
            transaction.commit().await?;
            return Ok(WalletBackupMutationOutcome::ExactRetry);
        }
    }

    let expected_generation = match current.as_ref() {
        None => Some(1),
        Some(head) => head.generation.checked_add(1),
    };
    let expected_matches = match (&current, expected_etag) {
        (None, None) => true,
        (Some(head), Some(expected)) => head.etag() == expected,
        _ => false,
    };
    if Some(generation) != expected_generation || !expected_matches {
        transaction.rollback().await?;
        return Ok(WalletBackupMutationOutcome::HeadConflict);
    }

    if global_stored_bytes_limit > 0 {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(WALLET_BACKUP_GLOBAL_LOCK_KEY)
            .execute(&mut *transaction)
            .await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(ciphertext_bytes), 0)::BIGINT FROM wallet_backup_blobs",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let previous = current
            .as_ref()
            .and_then(|head| head.ciphertext_bytes)
            .unwrap_or(0) as i64;
        let projected = total - previous + i64::try_from(ciphertext.len()).unwrap_or(i64::MAX);
        if projected < 0 || projected as u64 > global_stored_bytes_limit {
            transaction.rollback().await?;
            return Ok(WalletBackupMutationOutcome::GlobalCapacityExceeded);
        }
    }

    sqlx::query(
        "INSERT INTO wallet_backup_blobs (\
             stream, author_pubkey, generation, etag, ciphertext, ciphertext_sha256, ciphertext_bytes\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (stream, author_pubkey) DO UPDATE SET \
             generation = EXCLUDED.generation, \
             etag = EXCLUDED.etag, \
             ciphertext = EXCLUDED.ciphertext, \
             ciphertext_sha256 = EXCLUDED.ciphertext_sha256, \
             ciphertext_bytes = EXCLUDED.ciphertext_bytes, \
             updated_at = now(), \
             deleted_at = NULL",
    )
    .bind(stream)
    .bind(author_pubkey)
    .bind(generation)
    .bind(etag)
    .bind(ciphertext)
    .bind(ciphertext_sha256)
    .bind(i32::try_from(ciphertext.len()).map_err(|_| {
        AppError::DbError("wallet backup ciphertext length exceeds PostgreSQL integer".into())
    })?)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(WalletBackupMutationOutcome::Applied)
}

pub async fn delete_wallet_backup(
    pool: &PgPool,
    stream: &str,
    author_pubkey: &[u8],
    generation: i64,
    expected_etag: &[u8],
    tombstone_etag: &[u8],
) -> Result<WalletBackupMutationOutcome, AppError> {
    let mut transaction = pool.begin().await?;
    lock_head(&mut transaction, stream, author_pubkey).await?;
    let Some(current) = fetch_in_transaction(&mut transaction, stream, author_pubkey).await? else {
        transaction.rollback().await?;
        return Ok(WalletBackupMutationOutcome::HeadConflict);
    };

    if current.is_tombstone()
        && current.generation == generation
        && current.etag() == tombstone_etag
    {
        transaction.commit().await?;
        return Ok(WalletBackupMutationOutcome::ExactRetry);
    }

    if current.is_tombstone() {
        transaction.rollback().await?;
        return Ok(WalletBackupMutationOutcome::HeadConflict);
    }

    if current.generation.checked_add(1) != Some(generation) || current.etag() != expected_etag {
        transaction.rollback().await?;
        return Ok(WalletBackupMutationOutcome::HeadConflict);
    }

    sqlx::query(
        "UPDATE wallet_backup_blobs SET \
             generation = $3, etag = $4, ciphertext = NULL, ciphertext_sha256 = NULL, \
             ciphertext_bytes = NULL, updated_at = now(), deleted_at = now() \
         WHERE stream = $1 AND author_pubkey = $2",
    )
    .bind(stream)
    .bind(author_pubkey)
    .bind(generation)
    .bind(tombstone_etag)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(WalletBackupMutationOutcome::Applied)
}

pub async fn cleanup_expired_wallet_backup_tombstones(
    pool: &PgPool,
    retention_secs: i32,
    limit: i64,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "DELETE FROM wallet_backup_blobs \
         WHERE ctid IN (\
             SELECT ctid FROM wallet_backup_blobs \
             WHERE deleted_at IS NOT NULL \
               AND deleted_at < now() - make_interval(secs => $1) \
             ORDER BY deleted_at \
             LIMIT $2 \
             FOR UPDATE SKIP LOCKED\
         )",
    )
    .bind(retention_secs)
    .bind(limit)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

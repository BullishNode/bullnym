use sqlx::PgPool;

use super::mark_user_used;

// --- Outpoint → address index reservations ---

#[derive(Debug, sqlx::FromRow)]
pub struct OutpointAddress {
    pub nym: String,
    pub outpoint: String,
    pub addr_index: i32,
    pub pubkey: Option<String>,
    pub fulfilled: bool,
}

pub async fn get_outpoint_address(
    pool: &PgPool,
    nym: &str,
    outpoint: &str,
) -> Result<Option<OutpointAddress>, sqlx::Error> {
    sqlx::query_as::<_, OutpointAddress>(
        "SELECT nym, outpoint, addr_index, pubkey, fulfilled \
         FROM outpoint_addresses WHERE nym = $1 AND outpoint = $2",
    )
    .bind(nym)
    .bind(outpoint)
    .fetch_optional(pool)
    .await
}

pub async fn list_reservations_for_nym(
    pool: &PgPool,
    nym: &str,
) -> Result<Vec<OutpointAddress>, sqlx::Error> {
    sqlx::query_as::<_, OutpointAddress>(
        "SELECT nym, outpoint, addr_index, pubkey, fulfilled \
         FROM outpoint_addresses WHERE nym = $1 ORDER BY addr_index ASC",
    )
    .bind(nym)
    .fetch_all(pool)
    .await
}

pub async fn count_unfulfilled_reservations(pool: &PgPool, nym: &str) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM outpoint_addresses \
         WHERE nym = $1 AND fulfilled = FALSE",
    )
    .bind(nym)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Idempotent allocation: returns the cached addr_index if `(nym, outpoint)`
/// was seen before even after product deactivation; otherwise reads the active
/// user's CURRENT `next_addr_idx`,
/// inserts a new `outpoint_addresses` row using that value (informational),
/// and returns it. Does NOT advance `users.next_addr_idx` — that's done
/// asynchronously by the chain watcher when an address is observed paid.
/// Runs inside a single transaction so concurrent callers see consistent state.
pub async fn allocate_outpoint_address(
    pool: &PgPool,
    nym: &str,
    outpoint: &str,
    pubkey_hex: &str,
) -> Result<i32, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Cache hit?
    let cached: Option<(i32,)> = sqlx::query_as(
        "SELECT addr_index FROM outpoint_addresses \
         WHERE nym = $1 AND outpoint = $2",
    )
    .bind(nym)
    .bind(outpoint)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some((idx,)) = cached {
        tx.commit().await?;
        return Ok(idx);
    }

    // A cache miss is a new public instruction and remains active-only. Read
    // current next_addr_idx (no increment — chain watcher advances it).
    let (current_idx,): (i32,) = sqlx::query_as(
        "SELECT next_addr_idx FROM users \
         WHERE nym = $1 AND is_active = TRUE",
    )
    .bind(nym)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO outpoint_addresses (nym, outpoint, addr_index, pubkey) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(nym)
    .bind(outpoint)
    .bind(current_idx)
    .bind(pubkey_hex)
    .execute(&mut *tx)
    .await?;

    mark_user_used(&mut *tx, nym).await?;

    tx.commit().await?;
    Ok(current_idx)
}

pub async fn mark_reservation_fulfilled(
    pool: &PgPool,
    nym: &str,
    outpoint: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE outpoint_addresses SET fulfilled = TRUE, fulfilled_at = NOW() \
         WHERE nym = $1 AND outpoint = $2 AND fulfilled = FALSE",
    )
    .bind(nym)
    .bind(outpoint)
    .execute(pool)
    .await?;
    Ok(())
}

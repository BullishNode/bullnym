use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub nym: String,
    pub npub: String,
    pub ct_descriptor: String,
    pub next_addr_idx: i32,
    pub dns_record_id: Option<String>,
    pub is_active: bool,
}

pub async fn get_user_by_nym(pool: &PgPool, nym: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, dns_record_id, is_active \
         FROM users WHERE nym = $1",
    )
    .bind(nym)
    .fetch_optional(pool)
    .await
}

pub async fn get_user_by_npub(pool: &PgPool, npub: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, dns_record_id, is_active \
         FROM users WHERE npub = $1",
    )
    .bind(npub)
    .fetch_optional(pool)
    .await
}

pub async fn create_user(
    pool: &PgPool,
    nym: &str,
    npub: &str,
    ct_descriptor: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "INSERT INTO users (nym, npub, ct_descriptor) VALUES ($1, $2, $3) \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, dns_record_id, is_active",
    )
    .bind(nym)
    .bind(npub)
    .bind(ct_descriptor)
    .fetch_one(pool)
    .await
}

pub async fn update_user_descriptor(
    pool: &PgPool,
    npub: &str,
    ct_descriptor: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "UPDATE users SET ct_descriptor = $2, next_addr_idx = 0 \
         WHERE npub = $1 AND is_active = TRUE \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, dns_record_id, is_active",
    )
    .bind(npub)
    .bind(ct_descriptor)
    .fetch_optional(pool)
    .await
}

pub async fn update_dns_record_id(
    pool: &PgPool,
    nym: &str,
    dns_record_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET dns_record_id = $2 WHERE nym = $1")
        .bind(nym)
        .bind(dns_record_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Atomically allocates the next swap key index from a PostgreSQL sequence.
/// Each call returns a unique, never-repeated value that survives restarts.
pub async fn next_swap_key_index(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT nextval('swap_key_seq')")
        .fetch_one(pool)
        .await?;
    Ok(row.0 as u64)
}

/// Atomically increments next_addr_idx and returns the index to use.
/// Returns None if the nym does not exist or is inactive.
pub async fn allocate_address_index(pool: &PgPool, nym: &str) -> Result<Option<i32>, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as(
        "UPDATE users SET next_addr_idx = next_addr_idx + 1 \
         WHERE nym = $1 AND is_active = TRUE \
         RETURNING next_addr_idx - 1",
    )
    .bind(nym)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(idx,)| idx))
}

pub async fn record_swap(
    pool: &PgPool,
    nym: &str,
    boltz_swap_id: &str,
    address: &str,
    address_index: i32,
    amount_sat: u64,
    invoice: &str,
    preimage_hex: &str,
    claim_key_hex: &str,
    boltz_response_json: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO swap_records \
         (nym, boltz_swap_id, address, address_index, amount_sat, invoice, \
          preimage_hex, claim_key_hex, boltz_response_json, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')",
    )
    .bind(nym)
    .bind(boltz_swap_id)
    .bind(address)
    .bind(address_index)
    .bind(amount_sat as i64)
    .bind(invoice)
    .bind(preimage_hex)
    .bind(claim_key_hex)
    .bind(boltz_response_json)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct SwapRecord {
    pub id: Uuid,
    pub nym: String,
    pub boltz_swap_id: String,
    pub address: String,
    pub address_index: i32,
    pub amount_sat: i64,
    pub invoice: String,
    pub preimage_hex: Option<String>,
    pub claim_key_hex: Option<String>,
    pub boltz_response_json: Option<String>,
    pub status: String,
    pub claim_txid: Option<String>,
}

pub async fn get_swap_by_boltz_id(
    pool: &PgPool,
    boltz_swap_id: &str,
) -> Result<Option<SwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, SwapRecord>(
        "SELECT id, nym, boltz_swap_id, address, address_index, amount_sat, invoice, \
         preimage_hex, claim_key_hex, boltz_response_json, status, claim_txid \
         FROM swap_records WHERE boltz_swap_id = $1",
    )
    .bind(boltz_swap_id)
    .fetch_optional(pool)
    .await
}

pub async fn update_swap_status(
    pool: &PgPool,
    id: Uuid,
    status: &str,
    claim_txid: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE swap_records SET status = $2, claim_txid = COALESCE($3, claim_txid), \
         updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(status)
    .bind(claim_txid)
    .execute(pool)
    .await?;
    Ok(())
}

/// Find swaps stuck in claimable states (for crash recovery on startup).
pub async fn get_unclaimed_swaps(pool: &PgPool) -> Result<Vec<SwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, SwapRecord>(
        "SELECT id, nym, boltz_swap_id, address, address_index, amount_sat, invoice, \
         preimage_hex, claim_key_hex, boltz_response_json, status, claim_txid \
         FROM swap_records \
         WHERE status IN ('lockup_mempool', 'lockup_confirmed', 'claiming', 'claim_failed') \
         AND claim_txid IS NULL",
    )
    .fetch_all(pool)
    .await
}

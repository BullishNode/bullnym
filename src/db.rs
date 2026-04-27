use std::fmt;
use std::str::FromStr;

use sqlx::PgPool;
use uuid::Uuid;

// --- Swap status enum ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapStatus {
    Pending,
    LockupMempool,
    LockupConfirmed,
    Claiming,
    Claimed,
    ClaimFailed,
    Expired,
}

impl SwapStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Claimed | Self::Expired)
    }

    pub fn is_claimable(self) -> bool {
        matches!(
            self,
            Self::LockupMempool | Self::LockupConfirmed | Self::Claiming | Self::ClaimFailed
        )
    }
}

impl fmt::Display for SwapStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::LockupMempool => "lockup_mempool",
            Self::LockupConfirmed => "lockup_confirmed",
            Self::Claiming => "claiming",
            Self::Claimed => "claimed",
            Self::ClaimFailed => "claim_failed",
            Self::Expired => "expired",
        })
    }
}

impl FromStr for SwapStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "lockup_mempool" => Ok(Self::LockupMempool),
            "lockup_confirmed" => Ok(Self::LockupConfirmed),
            "claiming" => Ok(Self::Claiming),
            "claimed" => Ok(Self::Claimed),
            "claim_failed" => Ok(Self::ClaimFailed),
            "expired" => Ok(Self::Expired),
            other => Err(format!("unknown swap status: {other}")),
        }
    }
}

// --- User ---

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub nym: String,
    pub npub: String,
    pub ct_descriptor: String,
    pub next_addr_idx: i32,
    pub is_active: bool,
}

pub async fn get_user_by_nym(pool: &PgPool, nym: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE nym = $1",
    )
    .bind(nym)
    .fetch_optional(pool)
    .await
}

pub async fn get_user_by_npub(pool: &PgPool, npub: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = TRUE",
    )
    .bind(npub)
    .fetch_optional(pool)
    .await
}

pub async fn get_inactive_user_by_npub(pool: &PgPool, npub: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = FALSE \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(npub)
    .fetch_optional(pool)
    .await
}

pub async fn reactivate_user(
    pool: &PgPool,
    npub: &str,
    nym: &str,
    ct_descriptor: &str,
) -> Result<User, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET nym = $2, ct_descriptor = $3, is_active = TRUE, next_addr_idx = 0 \
         WHERE id = (SELECT id FROM users WHERE npub = $1 AND is_active = FALSE ORDER BY created_at DESC LIMIT 1) \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
    )
    .bind(npub)
    .bind(nym)
    .bind(ct_descriptor)
    .fetch_one(&mut *tx)
    .await?;
    // Descriptor reset means any cached outpoint→addr_index mappings now
    // point into the wrong keyspace. Drop them.
    sqlx::query("DELETE FROM outpoint_addresses WHERE nym = $1")
        .bind(&user.nym)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(user)
}

pub async fn create_user(
    pool: &PgPool,
    nym: &str,
    npub: &str,
    ct_descriptor: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "INSERT INTO users (nym, npub, ct_descriptor) VALUES ($1, $2, $3) \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
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
    let mut tx = pool.begin().await?;
    let user_opt = sqlx::query_as::<_, User>(
        "UPDATE users SET ct_descriptor = $2, next_addr_idx = 0 \
         WHERE npub = $1 AND is_active = TRUE \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
    )
    .bind(npub)
    .bind(ct_descriptor)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(user) = &user_opt {
        sqlx::query("DELETE FROM outpoint_addresses WHERE nym = $1")
            .bind(&user.nym)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(user_opt)
}

pub async fn deactivate_user(pool: &PgPool, npub: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "UPDATE users SET is_active = FALSE \
         WHERE npub = $1 AND is_active = TRUE \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
    )
    .bind(npub)
    .fetch_optional(pool)
    .await
}

/// Outcome of a purge attempt.
pub enum PurgeOutcome {
    /// Purge applied. Returns the (now-deactivated) user row.
    Purged(User),
    /// No active user exists for this npub.
    NotFound,
    /// Refused because in-flight swaps still hold live claim secrets.
    InFlightSwaps(usize),
}

/// Hard-delete every swap_record and outpoint_address tied to this npub's
/// active nym, then deactivate the user row while keeping `nym` and `npub`
/// so the address stays reserved and the original owner can re-register.
///
/// Refuses if any swap is non-terminal: those rows hold the only copy of
/// `claim_key_hex` / `preimage_hex` needed to redeem a Boltz lockup.
pub async fn purge_user(pool: &PgPool, npub: &str) -> Result<PurgeOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let user_opt = sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = TRUE FOR UPDATE",
    )
    .bind(npub)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(user) = user_opt else {
        tx.rollback().await?;
        return Ok(PurgeOutcome::NotFound);
    };

    let in_flight: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM swap_records \
         WHERE nym = $1 AND status NOT IN ('claimed', 'expired')",
    )
    .bind(&user.nym)
    .fetch_one(&mut *tx)
    .await?;
    if in_flight > 0 {
        tx.rollback().await?;
        return Ok(PurgeOutcome::InFlightSwaps(in_flight as usize));
    }

    sqlx::query("DELETE FROM swap_records WHERE nym = $1")
        .bind(&user.nym)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM outpoint_addresses WHERE nym = $1")
        .bind(&user.nym)
        .execute(&mut *tx)
        .await?;

    let purged = sqlx::query_as::<_, User>(
        "UPDATE users SET is_active = FALSE, ct_descriptor = '', next_addr_idx = 0 \
         WHERE id = $1 \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
    )
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(PurgeOutcome::Purged(purged))
}

// --- Address & swap key allocation ---

pub async fn next_swap_key_index(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT nextval('swap_key_seq')")
        .fetch_one(pool)
        .await?;
    Ok(row.0 as u64)
}

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

// --- Swap records ---

pub struct NewSwapRecord<'a> {
    pub nym: &'a str,
    pub boltz_swap_id: &'a str,
    pub address: &'a str,
    pub address_index: i32,
    pub amount_sat: u64,
    pub invoice: &'a str,
    pub preimage_hex: &'a str,
    pub claim_key_hex: &'a str,
    pub boltz_response_json: &'a str,
}

pub async fn record_swap(pool: &PgPool, swap: &NewSwapRecord<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO swap_records \
         (nym, boltz_swap_id, address, address_index, amount_sat, invoice, \
          preimage_hex, claim_key_hex, boltz_response_json, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')",
    )
    .bind(swap.nym)
    .bind(swap.boltz_swap_id)
    .bind(swap.address)
    .bind(swap.address_index)
    .bind(swap.amount_sat as i64)
    .bind(swap.invoice)
    .bind(swap.preimage_hex)
    .bind(swap.claim_key_hex)
    .bind(swap.boltz_response_json)
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

impl SwapRecord {
    pub fn parsed_status(&self) -> Result<SwapStatus, String> {
        self.status.parse()
    }
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
    status: SwapStatus,
    claim_txid: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE swap_records SET status = $2, claim_txid = COALESCE($3, claim_txid), \
         updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(status.to_string())
    .bind(claim_txid)
    .execute(pool)
    .await?;
    Ok(())
}

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

pub async fn count_unfulfilled_reservations(
    pool: &PgPool,
    nym: &str,
) -> Result<i64, sqlx::Error> {
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
/// was seen before; otherwise bumps `users.next_addr_idx` and inserts a new
/// row. Runs inside a single transaction so concurrent callers can't race on
/// the same nym.
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

    // Allocate next index on the nym's users row (SELECT FOR UPDATE via
    // UPDATE ... RETURNING implicitly row-locks).
    let (allocated_idx,): (i32,) = sqlx::query_as(
        "UPDATE users SET next_addr_idx = next_addr_idx + 1 \
         WHERE nym = $1 AND is_active = TRUE \
         RETURNING next_addr_idx - 1",
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
    .bind(allocated_idx)
    .bind(pubkey_hex)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(allocated_idx)
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

// --- Rate limit events ---

pub async fn record_rate_limit_event(
    pool: &PgPool,
    bucket: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO rate_limit_events (bucket) VALUES ($1)")
        .bind(bucket)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn count_rate_limit_events(
    pool: &PgPool,
    bucket: &str,
    window_secs: u32,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM rate_limit_events \
         WHERE bucket = $1 AND created_at > NOW() - ($2 || ' seconds')::interval",
    )
    .bind(bucket)
    .bind(window_secs as i32)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_status_round_trip() {
        for status in [
            SwapStatus::Pending,
            SwapStatus::LockupMempool,
            SwapStatus::LockupConfirmed,
            SwapStatus::Claiming,
            SwapStatus::Claimed,
            SwapStatus::ClaimFailed,
            SwapStatus::Expired,
        ] {
            let s = status.to_string();
            let parsed: SwapStatus = s.parse().unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn swap_status_terminal() {
        assert!(SwapStatus::Claimed.is_terminal());
        assert!(SwapStatus::Expired.is_terminal());
        assert!(!SwapStatus::Pending.is_terminal());
        assert!(!SwapStatus::ClaimFailed.is_terminal());
    }

    #[test]
    fn swap_status_claimable() {
        assert!(SwapStatus::LockupMempool.is_claimable());
        assert!(SwapStatus::LockupConfirmed.is_claimable());
        assert!(SwapStatus::Claiming.is_claimable());
        assert!(SwapStatus::ClaimFailed.is_claimable());
        assert!(!SwapStatus::Pending.is_claimable());
        assert!(!SwapStatus::Claimed.is_claimable());
        assert!(!SwapStatus::Expired.is_claimable());
    }

    #[test]
    fn swap_status_unknown_rejected() {
        assert!("garbage".parse::<SwapStatus>().is_err());
    }
}

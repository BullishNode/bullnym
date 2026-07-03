use std::fmt;
use std::str::FromStr;

use sqlx::PgPool;
use uuid::Uuid;

use super::ClaimFailureOutcome;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapStatus {
    Pending,
    UserLockMempool,
    UserLockConfirmed,
    ServerLockMempool,
    ServerLockConfirmed,
    Claiming,
    Claimed,
    ClaimFailed,
    ClaimStuck,
    Expired,
    LockupFailed,
    Refunded,
}

impl ChainSwapStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Claimed | Self::ClaimStuck | Self::Expired | Self::LockupFailed | Self::Refunded
        )
    }
}

impl fmt::Display for ChainSwapStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::UserLockMempool => "user_lock_mempool",
            Self::UserLockConfirmed => "user_lock_confirmed",
            Self::ServerLockMempool => "server_lock_mempool",
            Self::ServerLockConfirmed => "server_lock_confirmed",
            Self::Claiming => "claiming",
            Self::Claimed => "claimed",
            Self::ClaimFailed => "claim_failed",
            Self::ClaimStuck => "claim_stuck",
            Self::Expired => "expired",
            Self::LockupFailed => "lockup_failed",
            Self::Refunded => "refunded",
        })
    }
}

impl FromStr for ChainSwapStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "user_lock_mempool" => Ok(Self::UserLockMempool),
            "user_lock_confirmed" => Ok(Self::UserLockConfirmed),
            "server_lock_mempool" => Ok(Self::ServerLockMempool),
            "server_lock_confirmed" => Ok(Self::ServerLockConfirmed),
            "claiming" => Ok(Self::Claiming),
            "claimed" => Ok(Self::Claimed),
            "claim_failed" => Ok(Self::ClaimFailed),
            "claim_stuck" => Ok(Self::ClaimStuck),
            "expired" => Ok(Self::Expired),
            "lockup_failed" => Ok(Self::LockupFailed),
            "refunded" => Ok(Self::Refunded),
            other => Err(format!("unknown chain swap status: {other}")),
        }
    }
}

pub struct NewChainSwapRecord<'a> {
    pub invoice_id: Uuid,
    pub nym: Option<&'a str>,
    pub boltz_swap_id: &'a str,
    pub lockup_address: &'a str,
    pub lockup_bip21: Option<&'a str>,
    pub user_lock_amount_sat: i64,
    pub server_lock_amount_sat: i64,
    pub preimage_hex: &'a str,
    pub claim_key_hex: &'a str,
    pub refund_key_hex: &'a str,
    pub boltz_response_json: &'a str,
}

#[derive(Debug, sqlx::FromRow)]
pub struct ChainSwapRecord {
    pub id: Uuid,
    pub invoice_id: Uuid,
    pub nym: Option<String>,
    pub boltz_swap_id: String,
    pub from_chain: String,
    pub to_chain: String,
    pub lockup_address: String,
    pub lockup_bip21: Option<String>,
    pub user_lock_amount_sat: i64,
    pub server_lock_amount_sat: i64,
    pub preimage_hex: String,
    pub claim_key_hex: String,
    pub refund_key_hex: String,
    pub boltz_response_json: String,
    pub status: String,
    pub claim_txid: Option<String>,
    pub claim_tx_hex: Option<String>,
    pub claim_attempts: i32,
    pub last_claim_error: Option<String>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

impl ChainSwapRecord {
    pub fn parsed_status(&self) -> Result<ChainSwapStatus, String> {
        self.status.parse()
    }
}

const CHAIN_SWAP_RECORD_COLUMNS: &str =
    "id, invoice_id, nym, boltz_swap_id, from_chain, to_chain, \
     lockup_address, lockup_bip21, user_lock_amount_sat, server_lock_amount_sat, \
     preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json, status, claim_txid, \
     claim_tx_hex, claim_attempts, last_claim_error, \
     EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at_unix, \
     EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at_unix";

pub async fn record_chain_swap(
    pool: &PgPool,
    swap: &NewChainSwapRecord<'_>,
) -> Result<ChainSwapRecord, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "INSERT INTO chain_swap_records \
             (invoice_id, nym, boltz_swap_id, from_chain, to_chain, lockup_address, lockup_bip21, \
              user_lock_amount_sat, server_lock_amount_sat, preimage_hex, claim_key_hex, \
              refund_key_hex, boltz_response_json) \
         VALUES ($1, $2, $3, 'BTC', 'L-BTC', $4, $5, $6, $7, $8, $9, $10, $11) \
         RETURNING {CHAIN_SWAP_RECORD_COLUMNS}"
    ))
    .bind(swap.invoice_id)
    .bind(swap.nym)
    .bind(swap.boltz_swap_id)
    .bind(swap.lockup_address)
    .bind(swap.lockup_bip21)
    .bind(swap.user_lock_amount_sat)
    .bind(swap.server_lock_amount_sat)
    .bind(swap.preimage_hex)
    .bind(swap.claim_key_hex)
    .bind(swap.refund_key_hex)
    .bind(swap.boltz_response_json)
    .fetch_one(pool)
    .await
}

pub async fn get_chain_swap_by_boltz_id(
    pool: &PgPool,
    boltz_swap_id: &str,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} FROM chain_swap_records WHERE boltz_swap_id = $1"
    ))
    .bind(boltz_swap_id)
    .fetch_optional(pool)
    .await
}

pub async fn get_chain_swap_by_id<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} FROM chain_swap_records WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await
}

pub async fn latest_payable_chain_swap_for_invoice(
    pool: &PgPool,
    invoice_id: Uuid,
    amount_sat: i64,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} FROM chain_swap_records \
         WHERE invoice_id = $1 \
           AND status = 'pending' \
           AND user_lock_amount_sat = $2 \
         ORDER BY created_at DESC \
         LIMIT 1"
    ))
    .bind(invoice_id)
    .bind(amount_sat)
    .fetch_optional(pool)
    .await
}

pub async fn update_chain_swap_status(
    pool: &PgPool,
    id: Uuid,
    status: ChainSwapStatus,
    claim_txid: Option<&str>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET status = $2, claim_txid = COALESCE($3, claim_txid), updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck')",
    )
    .bind(id)
    .bind(status.to_string())
    .bind(claim_txid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn get_ready_to_claim_chain_swaps(
    pool: &PgPool,
) -> Result<Vec<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE status IN ('server_lock_mempool', 'server_lock_confirmed', 'claiming', 'claim_failed') \
           AND (next_claim_attempt_at IS NULL OR next_claim_attempt_at <= NOW()) \
         ORDER BY next_claim_attempt_at NULLS FIRST"
    ))
    .fetch_all(pool)
    .await
}

pub async fn record_chain_swap_claim_failure(
    pool: &PgPool,
    id: Uuid,
    error_msg: &str,
    max_attempts: i32,
) -> Result<ClaimFailureOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let bumped: Option<(i32,)> = sqlx::query_as(
        "UPDATE chain_swap_records \
         SET claim_attempts = claim_attempts + 1, \
             last_claim_error = $2, \
             last_claim_error_at = NOW(), \
             updated_at = NOW(), \
             next_claim_attempt_at = NOW() + ( \
                 CASE \
                     WHEN claim_attempts + 1 <= 1 THEN INTERVAL '10 seconds' \
                     WHEN claim_attempts + 1 = 2 THEN INTERVAL '20 seconds' \
                     WHEN claim_attempts + 1 = 3 THEN INTERVAL '60 seconds' \
                     WHEN claim_attempts + 1 = 4 THEN INTERVAL '300 seconds' \
                     WHEN claim_attempts + 1 = 5 THEN INTERVAL '600 seconds' \
                     WHEN claim_attempts + 1 = 6 THEN INTERVAL '1800 seconds' \
                     ELSE INTERVAL '3600 seconds' \
                 END \
             ) * (0.8 + 0.4 * random()) \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck') \
         RETURNING claim_attempts",
    )
    .bind(id)
    .bind(error_msg)
    .fetch_optional(&mut *tx)
    .await?;

    let outcome = match bumped {
        None => ClaimFailureOutcome::NoOp,
        Some((attempts,)) if attempts >= max_attempts => {
            sqlx::query(
                "UPDATE chain_swap_records \
                 SET status = 'claim_stuck', updated_at = NOW() \
                 WHERE id = $1 \
                   AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck')",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            ClaimFailureOutcome::Stuck
        }
        Some(_) => ClaimFailureOutcome::Scheduled,
    };

    tx.commit().await?;
    Ok(outcome)
}

pub async fn clear_chain_swap_claim_failure_state(
    pool: &PgPool,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE chain_swap_records \
         SET last_claim_error = NULL, \
             last_claim_error_at = NULL, \
             next_claim_attempt_at = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

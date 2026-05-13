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
    /// Auto-retry budget exhausted. Excluded from the background sweep;
    /// requires manual intervention via the runbook (rescue: reset
    /// claim_attempts, clear claim_tx_hex, flip cooperative_refused,
    /// status back to lockup_confirmed).
    ClaimStuck,
    /// Boltz auto-refunded its lockup before we claimed. The user paid
    /// the LN invoice and got nothing back — fund-loss terminal state.
    /// Reconciler is the only path that writes this; emits a P0 alert.
    LockupRefunded,
}

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

impl SwapStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Claimed | Self::Expired | Self::ClaimStuck | Self::LockupRefunded
        )
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
            Self::ClaimStuck => "claim_stuck",
            Self::LockupRefunded => "lockup_refunded",
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
            "claim_stuck" => Ok(Self::ClaimStuck),
            "lockup_refunded" => Ok(Self::LockupRefunded),
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

pub async fn get_inactive_user_by_npub(
    pool: &PgPool,
    npub: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = FALSE \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(npub)
    .fetch_optional(pool)
    .await
}

/// Mark a user row as having seen real activity (a Lightning swap or a
/// Liquid LUD-22 reservation). Idempotent: the `WHERE has_been_used = FALSE`
/// guard makes re-marking a no-op. Caller passes the executor (a tx
/// borrow when this update belongs to a larger atomic flow, or the pool
/// directly otherwise).
pub async fn mark_user_used<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    nym: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET has_been_used = TRUE WHERE nym = $1 AND has_been_used = FALSE")
        .bind(nym)
        .execute(executor)
        .await?;
    Ok(())
}

/// Total nyms ever registered under this npub (active + inactive). Used
/// to enforce `max_lifetime_nyms_per_npub` so one key can't squat the
/// namespace via dereg/rereg cycles.
pub async fn count_lifetime_nyms_by_npub(pool: &PgPool, npub: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE npub = $1")
        .bind(npub)
        .fetch_one(pool)
        .await
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreviousNym {
    pub nym: String,
    pub created_at: String,
}

/// One round trip: `(active_nym, previous_nyms_most_recent_first, used_count)`.
pub async fn lookup_status_by_npub(
    pool: &PgPool,
    npub: &str,
) -> Result<(Option<String>, Vec<PreviousNym>, i64), sqlx::Error> {
    let row: (
        Option<String>,
        Option<sqlx::types::Json<Vec<PreviousNym>>>,
        Option<i64>,
    ) = sqlx::query_as(
        "SELECT \
                (SELECT nym FROM users WHERE npub = $1 AND is_active = TRUE LIMIT 1) \
                    AS active_nym, \
                (SELECT json_agg(json_build_object('nym', nym, 'created_at', created_at) \
                                 ORDER BY created_at DESC) \
                   FROM users WHERE npub = $1 AND is_active = FALSE) \
                    AS previous_nyms, \
                (SELECT COUNT(*) FROM users WHERE npub = $1) AS used",
    )
    .bind(npub)
    .fetch_one(pool)
    .await?;
    Ok((
        row.0,
        row.1.map(|j| j.0).unwrap_or_default(),
        row.2.unwrap_or(0),
    ))
}

/// Outcome of `register_user_atomic`. Mirrors the three branches of the
/// register handler so the caller can map each to the right `AppError`.
pub enum RegisterOutcome {
    /// New user row inserted.
    Created(User),
    /// Existing inactive row reactivated (caller asked for the same nym they
    /// previously held).
    Reactivated(User),
    /// This npub already has an active row under `nym`. Caller maps to
    /// `AppError::KeyAlreadyRegistered`.
    KeyAlreadyRegistered { nym: String },
    /// Inserting would push past the lifetime cap. Caller maps to
    /// `AppError::NymQuotaExceeded`. Carries `used` so the error envelope
    /// can ship the same `quota` object the mobile sees on lookup.
    QuotaExceeded { used: i64, cap: i64 },
}

/// Atomic register flow. Serializes concurrent registers from the same npub
/// via `pg_advisory_xact_lock(hashtext(npub))` so the cap check, the
/// active-row check, and the INSERT/UPDATE all observe a consistent view.
///
/// Advisory-lock keyspace audit (Kumulynja PLAN-3): the rate-limit code in
/// `record_and_count_rate_limit_atomic` and `record_and_count_distinct_nyms_atomic`
/// also uses `pg_advisory_xact_lock`, but keys on `hashtext(<bucket-string>)`
/// where the bucket is `register:ip:...`, `meta:ip:...`, etc. — never `npub`
/// raw. Bucket strings and raw npub hex live in disjoint string spaces, so
/// hashtext collisions are vanishingly improbable, and no single tx ever
/// holds both a registration lock and a rate-limit lock (the rate-limit gates
/// run before this function is called).
pub async fn register_user_atomic(
    pool: &PgPool,
    npub: &str,
    nym: &str,
    ct_descriptor: &str,
    cap: i64,
) -> Result<RegisterOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(npub)
        .execute(&mut *tx)
        .await?;

    // Re-check inside the lock — another tx may have inserted the active row
    // while we were waiting.
    let active = sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = TRUE",
    )
    .bind(npub)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(active) = active {
        tx.rollback().await?;
        return Ok(RegisterOutcome::KeyAlreadyRegistered { nym: active.nym });
    }

    let prior_inactive = sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = FALSE \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(npub)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(prior) = prior_inactive.as_ref().filter(|u| u.nym == nym) {
        // Reactivate same nym — no rename, FK from swap_records still aligned.
        let user = sqlx::query_as::<_, User>(
            "UPDATE users SET ct_descriptor = $3, is_active = TRUE, next_addr_idx = 0 \
             WHERE npub = $1 AND nym = $2 AND is_active = FALSE \
             RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
        )
        .bind(npub)
        .bind(&prior.nym)
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
        return Ok(RegisterOutcome::Reactivated(user));
    }

    // Cap check inside the lock.
    let used: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE npub = $1")
        .bind(npub)
        .fetch_one(&mut *tx)
        .await?;
    if used >= cap {
        tx.rollback().await?;
        return Ok(RegisterOutcome::QuotaExceeded { used, cap });
    }

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (nym, npub, ct_descriptor) VALUES ($1, $2, $3) \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
    )
    .bind(nym)
    .bind(npub)
    .bind(ct_descriptor)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(RegisterOutcome::Created(user))
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

    // Auto-archive any donation page tied to this nym so the public URL
    // stops accepting donations after the user purges. The page row stays
    // (so old social-media links resolve cleanly to a "this donation
    // page has been deleted" template) — same shape as user-initiated
    // archive via DELETE /donation-page.
    sqlx::query(
        "UPDATE donation_pages SET archived_at = now(), updated_at = now() \
         WHERE nym = $1 AND archived_at IS NULL",
    )
    .bind(&user.nym)
    .execute(&mut *tx)
    .await?;

    // Phase B: cookie-pinned donation_allocations is gone (migration 019).
    // Invoice rows survive purge with `liquid_address` set, but they
    // cascade-delete via `users(nym) ON DELETE CASCADE` — except purge
    // doesn't DELETE the user row, just deactivates it. Invoices remain
    // queryable by id, but their addresses are no longer derivable
    // (descriptor wiped below). Acceptable: any in-flight invoice for a
    // purged user becomes a graveyard row that the GC will eventually
    // expire to 'expired' status.

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
    pub nym: Option<&'a str>,
    pub boltz_swap_id: &'a str,
    pub address: Option<&'a str>,
    pub address_index: Option<i32>,
    pub amount_sat: u64,
    pub invoice: &'a str,
    pub preimage_hex: &'a str,
    pub claim_key_hex: &'a str,
    pub boltz_response_json: &'a str,
    /// Set when this swap is the Lightning offer for a specific invoice.
    /// The claimer records an invoice payment event through this id only
    /// after merchant-side claim success.
    pub invoice_id: Option<Uuid>,
}

pub async fn record_swap(pool: &PgPool, swap: &NewSwapRecord<'_>) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO swap_records \
         (nym, boltz_swap_id, address, address_index, amount_sat, invoice, \
          preimage_hex, claim_key_hex, boltz_response_json, status, invoice_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10)",
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
    .bind(swap.invoice_id)
    .execute(&mut *tx)
    .await?;
    if let Some(nym) = swap.nym {
        mark_user_used(&mut *tx, nym).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Fill in the claim destination on a swap_records row whose `address` was
/// not pre-allocated at swap creation (the post-MRH-deprecation flow). The
/// `WHERE address IS NULL` guard makes this idempotent: a retry that races
/// a successful first call no-ops.
pub async fn set_swap_address(
    pool: &PgPool,
    swap_id: Uuid,
    address: &str,
    address_index: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE swap_records SET address = $2, address_index = $3 \
         WHERE id = $1 AND address IS NULL",
    )
    .bind(swap_id)
    .bind(address)
    .bind(address_index)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct SwapRecord {
    pub id: Uuid,
    pub nym: Option<String>,
    pub boltz_swap_id: String,
    pub address: Option<String>,
    pub address_index: Option<i32>,
    pub amount_sat: i64,
    pub invoice: String,
    pub preimage_hex: Option<String>,
    pub claim_key_hex: Option<String>,
    pub boltz_response_json: Option<String>,
    pub status: String,
    pub claim_txid: Option<String>,
    /// Hex-encoded fully-signed claim transaction. Populated immediately
    /// before the first broadcast attempt so subsequent retries
    /// re-broadcast the SAME tx instead of constructing a new one
    /// (`construct_claim` is non-deterministic on Liquid: random MuSig2
    /// nonces + asset/value blinding factors). Cleared by the bump-fee
    /// retry path.
    pub claim_tx_hex: Option<String>,
    /// 'cooperative' (MuSig2 keypath, requires Boltz cosign) or 'script'
    /// (preimage-revealing script-path). The script path is the only
    /// recovery once Boltz status reaches `swap.expired`.
    pub claim_path: Option<String>,
    /// Total claim attempts (across construct+broadcast). The background
    /// sweep gives up at `config.max_claim_attempts` and transitions the
    /// row to `ClaimStuck`.
    pub claim_attempts: i32,
    /// Currently-budgeted fee rate in sat/vByte. Set on first attempt;
    /// bumped on relay-fee rejection up to `claim_fee_sat_per_vb_cap`.
    pub current_fee_rate: Option<f64>,
    /// Last claim error message — operator-facing surface for stuck swaps.
    pub last_claim_error: Option<String>,
    /// Set when Boltz refused the cooperative MuSig2 endpoint (HTTP 4xx
    /// or known refusal substrings). Future attempts skip cooperative and
    /// take the script path.
    pub cooperative_refused: bool,
    /// When this swap is the Lightning offer for an invoice, the claimer
    /// records a payment event against this invoice only after the
    /// merchant-side claim succeeds. NULL for LNURL Lightning Address
    /// swaps and for legacy donation-page rows.
    pub invoice_id: Option<Uuid>,
    // NOTE: `next_claim_attempt_at` and `last_claim_error_at` are real
    // columns in the schema but intentionally NOT read into this struct.
    // Reading TIMESTAMPTZ requires the `time` or `chrono` sqlx feature
    // flag, which the workspace deliberately avoids (see DonationPage
    // comment at db.rs around line 935). All timestamp comparisons
    // happen server-side in SQL (e.g. `WHERE next_claim_attempt_at IS
    // NULL OR next_claim_attempt_at <= NOW()`), and the values are only
    // surfaced to operators via direct DB queries (the runbook).
}

impl SwapRecord {
    pub fn parsed_status(&self) -> Result<SwapStatus, String> {
        self.status.parse()
    }
}

/// SQL projection of every `SwapRecord` field above. Centralized so each
/// new column added to the struct is reflected in exactly one place; the
/// FromRow derive matches by name so column order is cosmetic. The two
/// timestamp columns (`next_claim_attempt_at`, `last_claim_error_at`)
/// are intentionally excluded — see the struct comment.
const SWAP_RECORD_COLUMNS: &str =
    "id, nym, boltz_swap_id, address, address_index, amount_sat, invoice, \
     preimage_hex, claim_key_hex, boltz_response_json, status, claim_txid, \
     claim_tx_hex, claim_path, claim_attempts, current_fee_rate, \
     last_claim_error, cooperative_refused, invoice_id";

pub async fn get_swap_by_boltz_id(
    pool: &PgPool,
    boltz_swap_id: &str,
) -> Result<Option<SwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, SwapRecord>(&format!(
        "SELECT {SWAP_RECORD_COLUMNS} FROM swap_records WHERE boltz_swap_id = $1"
    ))
    .bind(boltz_swap_id)
    .fetch_optional(pool)
    .await
}

/// Load a swap row by primary key. Generic over any sqlx executor so the
/// claimer can call this inside its locked transaction (passing
/// `&mut *tx`) instead of going back to the pool for a fresh connection.
pub async fn get_swap_by_id<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<Option<SwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, SwapRecord>(&format!(
        "SELECT {SWAP_RECORD_COLUMNS} FROM swap_records WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await
}

/// Forward-only status update. Refuses to write through a row whose
/// status is already in a terminal state (claimed, expired, claim_stuck,
/// lockup_refunded). Closes the race where, e.g., a `transaction.failed`
/// webhook arrives during a successful claim and would otherwise
/// overwrite `Claimed → Expired`.
///
/// Returns the number of rows updated. A 0 return is normal when the
/// row had already reached a terminal state — the caller should not
/// treat it as an error.
///
/// NOTE: this guard does not enforce ordinal monotonicity between
/// non-terminal states (e.g. lockup_confirmed → lockup_mempool, which a
/// late webhook could provoke). Both are claimable and the consequence
/// is purely observability noise. PR #4 keeps the simpler invariant.
pub async fn update_swap_status(
    pool: &PgPool,
    id: Uuid,
    status: SwapStatus,
    claim_txid: Option<&str>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE swap_records SET status = $2, claim_txid = COALESCE($3, claim_txid), \
         updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
    )
    .bind(id)
    .bind(status.to_string())
    .bind(claim_txid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Set `cooperative_refused = TRUE` so the next claim attempt takes the
/// script path (PR #6 reads this flag in `construct_claim_tx`). Used by
/// the webhook handler when Boltz emits `swap.expired` — the cooperative
/// endpoint refuses post-expiry per `MusigSigner.ts`, but the on-chain
/// HTLC is still claimable until `timeoutBlockHeight` via the script
/// path.
///
/// Idempotent. Status is not touched here — the row stays claimable.
pub async fn mark_cooperative_refused(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE swap_records \
         SET cooperative_refused = TRUE, updated_at = NOW() \
         WHERE id = $1 AND cooperative_refused = FALSE \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Outcome of `record_claim_failure`. Drives the caller's logging and
/// (eventually, via PR #11) metrics counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimFailureOutcome {
    /// Attempt counter incremented, next_claim_attempt_at set per the
    /// backoff schedule. The background sweep will retry later.
    Scheduled,
    /// Attempts ≥ `max_attempts`. Status transitioned to `claim_stuck`;
    /// row no longer picked up by the sweep. Operator action required.
    Stuck,
    /// The row was already in a terminal state (or didn't exist). The
    /// failure record was a no-op.
    NoOp,
}

/// Record a failed claim attempt and schedule the next retry.
///
/// Called from `claim_swap` when the broadcast fails (or, in PR #6,
/// when `construct_claim_tx` exhausts its options). Increments
/// `claim_attempts`, stamps `last_claim_error`, and computes
/// `next_claim_attempt_at` from the documented backoff schedule:
///
/// ```text
/// claim_attempts (post-increment): 1, 2, 3,  4,   5,    6,    7+
/// delay (seconds):                30, 60, 120, 300, 600, 1800, 3600 (cap)
/// ```
///
/// ±20% jitter is applied via Postgres `random()` so a backlog draining
/// at the same tick doesn't synchronise into a thundering herd. Jitter
/// is server-side so we don't pull a `rand` dependency.
///
/// When `claim_attempts` reaches `max_attempts`, the row transitions to
/// `claim_stuck` (terminal). Subsequent calls become `NoOp` because the
/// terminal-state guard rejects further updates.
///
/// Forward-only: never writes through a row already in a terminal state
/// (claimed / expired / claim_stuck / lockup_refunded).
pub async fn record_claim_failure(
    pool: &PgPool,
    id: Uuid,
    error_msg: &str,
    max_attempts: i32,
) -> Result<ClaimFailureOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let bumped: Option<(i32,)> = sqlx::query_as(
        "UPDATE swap_records \
         SET claim_attempts = claim_attempts + 1, \
             last_claim_error = $2, \
             last_claim_error_at = NOW(), \
             updated_at = NOW(), \
             next_claim_attempt_at = NOW() + ( \
                 CASE \
                     WHEN claim_attempts + 1 <= 1 THEN INTERVAL '30 seconds' \
                     WHEN claim_attempts + 1 = 2 THEN INTERVAL '60 seconds' \
                     WHEN claim_attempts + 1 = 3 THEN INTERVAL '120 seconds' \
                     WHEN claim_attempts + 1 = 4 THEN INTERVAL '300 seconds' \
                     WHEN claim_attempts + 1 = 5 THEN INTERVAL '600 seconds' \
                     WHEN claim_attempts + 1 = 6 THEN INTERVAL '1800 seconds' \
                     ELSE INTERVAL '3600 seconds' \
                 END \
             ) * (0.8 + 0.4 * random()) \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded') \
         RETURNING claim_attempts",
    )
    .bind(id)
    .bind(error_msg)
    .fetch_optional(&mut *tx)
    .await?;

    let outcome = match bumped {
        None => ClaimFailureOutcome::NoOp,
        Some((attempts,)) if attempts >= max_attempts => {
            // Terminal-state guard inside this UPDATE is technically
            // redundant — we only reach this branch via the prior UPDATE
            // succeeding under the same guard within the same tx — but
            // it documents the invariant and fails closed if the UPDATE
            // chain ever changes shape.
            sqlx::query(
                "UPDATE swap_records \
                 SET status = 'claim_stuck', updated_at = NOW() \
                 WHERE id = $1 \
                   AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
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

/// Compact projection of a `swap_records` row used by the reconciler
/// to decide its next action. The reconciler does not need full
/// SwapRecord (no preimage, no boltz_response_json) — keeping the
/// projection minimal cuts per-tick bytes pulled from the DB and makes
/// it easy to reason about what the reconciler can and cannot see.
#[derive(Debug, Clone)]
pub struct ReconcilerSwap {
    pub id: Uuid,
    pub boltz_swap_id: String,
    pub status: String,
    pub cooperative_refused: bool,
    pub claim_txid: Option<String>,
    pub nym: Option<String>,
    pub amount_sat: i64,
    /// When this swap is the Lightning offer for an invoice, the claimer
    /// records a payment event against this invoice after merchant-side
    /// claim success. The reconciler only nudges claim retries.
    pub invoice_id: Option<Uuid>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ReconcilerSwap {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            boltz_swap_id: row.try_get("boltz_swap_id")?,
            status: row.try_get("status")?,
            cooperative_refused: row.try_get("cooperative_refused")?,
            claim_txid: row.try_get("claim_txid")?,
            nym: row.try_get("nym")?,
            amount_sat: row.try_get("amount_sat")?,
            invoice_id: row.try_get("invoice_id")?,
        })
    }
}

/// Reconciler scan: every non-terminal swap older than `min_age_secs`,
/// oldest-`updated_at`-first, capped at `limit`.
///
/// `min_age_secs` skips fresh rows so we don't race the webhook
/// handler on a swap that's still mid-flight. `limit` bounds peak
/// Boltz API RPM during backlog drain.
pub async fn list_non_terminal_swaps_oldest_first(
    pool: &PgPool,
    min_age_secs: u64,
    limit: u32,
) -> Result<Vec<ReconcilerSwap>, sqlx::Error> {
    sqlx::query_as::<_, ReconcilerSwap>(
        "SELECT id, boltz_swap_id, status, cooperative_refused, claim_txid, \
                nym, amount_sat, invoice_id \
         FROM swap_records \
         WHERE status NOT IN ('claimed', 'expired', 'lockup_refunded', 'claim_stuck') \
           AND updated_at < NOW() - ($1 || ' seconds')::interval \
         ORDER BY updated_at ASC \
         LIMIT $2",
    )
    .bind(min_age_secs as i64)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
}

/// Schedule an immediate retry from the reconciler. Sets
/// `next_claim_attempt_at = NOW()` so the next sweep tick (≤30s) picks
/// up the row. Forward-only: terminal-state guard prevents the
/// reconciler from "un-finishing" a row that completed concurrently.
///
/// Does not change `status`. Used when the reconciler observes that
/// Boltz still considers the swap claimable but our row hasn't been
/// retried recently (e.g., a permanent-looking error that was actually
/// transient).
pub async fn schedule_immediate_claim(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE swap_records \
         SET next_claim_attempt_at = NOW(), updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Combined reconciler action for the `swap.expired` (Boltz wall-clock
/// timer) case. Flips `cooperative_refused = TRUE` and schedules an
/// immediate retry so the next sweep tick takes the script path.
/// Single transaction for atomicity — the operator is never confused
/// by "cooperative_refused but not scheduled" or vice versa.
pub async fn schedule_script_path_retry(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE swap_records \
         SET cooperative_refused = TRUE, \
             next_claim_attempt_at = NOW(), \
             updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Reset retry bookkeeping after a successful claim attempt. Called
/// from `claim_swap` once `try_broadcast_tx` returns Ok — clears the
/// last-error fields so operators see "no errors" on a healthy row,
/// and zeros out `next_claim_attempt_at` so a hypothetical future
/// retry (after a reconciler-induced state change) doesn't wait on a
/// stale schedule.
pub async fn clear_claim_failure_state(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE swap_records \
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

/// Background-sweep query: rows that are claimable AND ready to retry.
/// `next_claim_attempt_at IS NULL` means "never tried" (or freshly reset
/// by the rescue runbook); `<= NOW()` means the backoff window has
/// elapsed. Both `claim_stuck` and `lockup_refunded` are excluded
/// implicitly via the IN-list — both are terminal.
///
/// Do not filter on `claim_txid IS NULL`: `claim_swap` persists
/// `(claim_tx_hex, claim_txid)` before first broadcast so a retry can
/// rebroadcast the exact same transaction. Filtering rows that already
/// have `claim_txid` strands swaps after a post-construction broadcast
/// error.
pub async fn get_ready_to_claim_swaps(pool: &PgPool) -> Result<Vec<SwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, SwapRecord>(&format!(
        "SELECT {SWAP_RECORD_COLUMNS} \
         FROM swap_records \
         WHERE status IN ('lockup_mempool', 'lockup_confirmed', 'claiming', 'claim_failed') \
           AND (next_claim_attempt_at IS NULL OR next_claim_attempt_at <= NOW()) \
         ORDER BY next_claim_attempt_at NULLS FIRST"
    ))
    .fetch_all(pool)
    .await
}

/// Backwards-compat alias. Kept because the existing claimer module
/// imports the old name; subsequent PRs in this rollout will switch
/// callers over to `get_ready_to_claim_swaps`.
#[deprecated(note = "use get_ready_to_claim_swaps")]
pub async fn get_unclaimed_swaps(pool: &PgPool) -> Result<Vec<SwapRecord>, sqlx::Error> {
    get_ready_to_claim_swaps(pool).await
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
/// was seen before; otherwise reads the user's CURRENT `next_addr_idx`,
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

    // Read current next_addr_idx (no increment — chain watcher advances it).
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

// --- D2 webhook idempotency ---

/// Try to record that a webhook event was processed. Returns `true` if
/// this is the first time we've seen `event_id` (caller should do the
/// work) or `false` if it was already processed (caller short-circuits
/// to 200 OK without acting).
pub async fn try_record_webhook_event(pool: &PgPool, event_id: &str) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO processed_webhook_events (event_id) VALUES ($1) \
         ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(event_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

// --- Active-user ceiling (P1 max_active_users gate) ---

/// Count rows with `is_active = TRUE` for the registration ceiling check.
/// Single-shot atomic query; used on the cheap path before signature verify.
pub async fn count_active_users(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

// --- Rate limit events ---

// NOTE: the non-atomic write-then-count pair (`record_rate_limit_event` +
// `count_rate_limit_events`) was removed in P3. All sliding-window axes now
// go through either `record_and_count_rate_limit_atomic` (Postgres path
// with advisory lock) or the in-memory limiter in `rate_limit::InMemorySliding`.

/// Atomic INSERT-then-COUNT for sliding-window rate limits, serialized on
/// the bucket key via `pg_advisory_xact_lock`. Only one transaction with
/// the same bucket can be inside this critical section at a time, so two
/// concurrent callers can't both pass under the limit and then both
/// commit past it. Returns the post-insert count.
///
/// Advisory-lock keyspace: keys are `hashtext(<bucket>)` where bucket is
/// `register:ip:...`, `meta:ip:...`, `nym:...`, etc. The registration flow
/// (`register_user_atomic`) keys on `hashtext(<npub-hex>)`. Bucket strings
/// and raw npub hex live in disjoint string spaces, and rate-limit gates
/// run before `register_user_atomic` is called (never inside its tx), so
/// no AB/BA deadlock is possible.
pub async fn record_and_count_rate_limit_atomic(
    pool: &PgPool,
    bucket: &str,
    window_secs: u32,
) -> Result<i64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(bucket)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO rate_limit_events (bucket) VALUES ($1)")
        .bind(bucket)
        .execute(&mut *tx)
        .await?;
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM rate_limit_events \
         WHERE bucket = $1 AND created_at > NOW() - ($2 || ' seconds')::interval",
    )
    .bind(bucket)
    .bind(window_secs as i32)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.0)
}

// =====================================================================
// Distinct-nym rate-limit helpers
// =====================================================================
//
// NOTE: the non-atomic write-then-count pair was removed in P3. All
// distinct-nyms axes now go through the atomic helper below.

/// Atomic INSERT-then-COUNT-DISTINCT for the distinct-nyms axes,
/// serialized on `source_key` via `pg_advisory_xact_lock`. Same atomicity
/// story as `record_and_count_rate_limit_atomic` — kills the race where
/// two concurrent callers both INSERT and then both COUNT under the limit
/// before either commit lands. Returns the post-insert distinct count.
pub async fn record_and_count_distinct_nyms_atomic(
    pool: &PgPool,
    source_key: &str,
    nym: &str,
    window_secs: u32,
) -> Result<i64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(source_key)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO nym_access_events (source_key, nym) VALUES ($1, $2)")
        .bind(source_key)
        .bind(nym)
        .execute(&mut *tx)
        .await?;
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT nym) FROM nym_access_events \
         WHERE source_key = $1 \
         AND created_at > NOW() - ($2 || ' seconds')::interval",
    )
    .bind(source_key)
    .bind(window_secs as i32)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.0)
}

// =====================================================================
// Chain watcher helpers (added 2026-04-27)
// =====================================================================

pub struct ActiveNymForWatcher {
    pub nym: String,
    pub ct_descriptor: String,
    pub next_addr_idx: i32,
}

pub async fn list_active_nyms_for_watcher(
    pool: &PgPool,
) -> Result<Vec<ActiveNymForWatcher>, sqlx::Error> {
    let rows: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT nym, ct_descriptor, next_addr_idx FROM users WHERE is_active = TRUE",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(nym, ct_descriptor, next_addr_idx)| ActiveNymForWatcher {
            nym,
            ct_descriptor,
            next_addr_idx,
        })
        .collect())
}

/// Watcher's "active" set: users whose `last_callback_at` is within the
/// last `active_window_secs`. This is the hot list scanned every fast
/// tick. Bounded in size by real callback traffic, not by the size of
/// the `users` table.
pub async fn list_recently_active_nyms_for_watcher(
    pool: &PgPool,
    active_window_secs: u32,
) -> Result<Vec<ActiveNymForWatcher>, sqlx::Error> {
    let rows: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT nym, ct_descriptor, next_addr_idx \
         FROM users \
         WHERE is_active = TRUE \
           AND last_callback_at > NOW() - ($1 || ' seconds')::interval",
    )
    .bind(active_window_secs as i32)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(nym, ct_descriptor, next_addr_idx)| ActiveNymForWatcher {
            nym,
            ct_descriptor,
            next_addr_idx,
        })
        .collect())
}

/// Mark that a user was just hit by `/lnurlp/callback`. Drives the
/// watcher's activity prioritization (P4). Best-effort: an error here is
/// logged but not propagated — failing to update activity should never
/// fail a successful payment-address lookup.
pub async fn touch_user_callback(pool: &PgPool, nym: &str) {
    if let Err(e) =
        sqlx::query("UPDATE users SET last_callback_at = NOW() WHERE nym = $1 AND is_active = TRUE")
            .bind(nym)
            .execute(pool)
            .await
    {
        tracing::warn!("touch_user_callback: nym={nym} failed: {e}");
    }
}

/// Advance `users.next_addr_idx` past `observed_idx`, but only if it hasn't
/// already advanced beyond it. Idempotent under concurrent observations:
/// the `next_addr_idx <= observed_idx` guard ensures this update is a no-op
/// when the row has already moved on (e.g. due to a request handler
/// allocation racing with the watcher).
pub async fn advance_next_addr_idx(
    pool: &PgPool,
    nym: &str,
    observed_idx: u32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users SET next_addr_idx = $2 \
         WHERE nym = $1 AND is_active = TRUE AND next_addr_idx <= $3",
    )
    .bind(nym)
    .bind((observed_idx + 1) as i32)
    .bind(observed_idx as i32)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark every still-pending reservation that targets `addr_index` for `nym`
/// as fulfilled. Called by the chain watcher when a payment is observed at
/// `derive(descriptor, addr_index)` — under last-unused mode many concurrent
/// senders may share a single addr_index, so a single observed payment can
/// flip multiple rows. Returns the number of rows updated for diagnostics.
pub async fn mark_reservations_fulfilled_at_idx(
    pool: &PgPool,
    nym: &str,
    addr_index: u32,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE outpoint_addresses \
            SET fulfilled = TRUE, fulfilled_at = NOW() \
          WHERE nym = $1 AND addr_index = $2 AND fulfilled = FALSE",
    )
    .bind(nym)
    .bind(addr_index as i32)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

// =====================================================================
// Donation pages (migration 016)
// =====================================================================

#[derive(Debug, sqlx::FromRow)]
pub struct DonationPage {
    pub nym: String,
    pub header: String,
    pub description: String,
    pub avatar_sha256: Option<String>,
    pub og_sha256: Option<String>,
    pub display_currency: String,
    pub website: Option<String>,
    pub twitter: Option<String>,
    pub instagram: Option<String>,
    pub enabled: bool,
    /// Derived from `archived_at IS NOT NULL`. The full timestamp lives in
    /// the column for audit but isn't read into Rust (would require the
    /// chrono/time sqlx feature flag).
    pub is_archived: bool,
}

pub struct UpsertDonationPage<'a> {
    pub nym: &'a str,
    pub header: &'a str,
    pub description: &'a str,
    pub display_currency: &'a str,
    pub website: Option<&'a str>,
    pub twitter: Option<&'a str>,
    pub instagram: Option<&'a str>,
    pub enabled: bool,
}

/// Insert-or-update a donation page row. Mobile sends the full v1 config on
/// every save (PUT semantics). Update path clears `archived_at` so a re-save
/// after archive un-archives — the row is already authenticated by Schnorr
/// sig at the handler. Image hashes (`avatar_sha256`, `og_sha256`) are NOT
/// touched here; they're owned by `POST /donation-page/image`.
pub async fn upsert_donation_page(
    pool: &PgPool,
    page: &UpsertDonationPage<'_>,
) -> Result<DonationPage, sqlx::Error> {
    sqlx::query_as::<_, DonationPage>(
        "INSERT INTO donation_pages \
            (nym, header, description, display_currency, \
             website, twitter, instagram, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (nym) DO UPDATE SET \
             header = EXCLUDED.header, \
             description = EXCLUDED.description, \
             display_currency = EXCLUDED.display_currency, \
             website = EXCLUDED.website, \
             twitter = EXCLUDED.twitter, \
             instagram = EXCLUDED.instagram, \
             enabled = EXCLUDED.enabled, \
             archived_at = NULL, \
             updated_at = now() \
         RETURNING nym, header, description, avatar_sha256, og_sha256, \
                   display_currency, website, twitter, \
                   instagram, enabled, (archived_at IS NOT NULL) AS is_archived",
    )
    .bind(page.nym)
    .bind(page.header)
    .bind(page.description)
    .bind(page.display_currency)
    .bind(page.website)
    .bind(page.twitter)
    .bind(page.instagram)
    .bind(page.enabled)
    .fetch_one(pool)
    .await
}

/// Soft-delete: mark `archived_at = now()`. The row is preserved so the
/// public URL keeps resolving to the "archived" template instead of 404.
/// Returns the post-archive row (or None if no donation page exists).
pub async fn archive_donation_page(
    pool: &PgPool,
    nym: &str,
) -> Result<Option<DonationPage>, sqlx::Error> {
    sqlx::query_as::<_, DonationPage>(
        "UPDATE donation_pages SET archived_at = now(), updated_at = now() \
         WHERE nym = $1 AND archived_at IS NULL \
         RETURNING nym, header, description, avatar_sha256, og_sha256, \
                   display_currency, website, twitter, \
                   instagram, enabled, (archived_at IS NOT NULL) AS is_archived",
    )
    .bind(nym)
    .fetch_optional(pool)
    .await
}

/// Update the avatar or og image hash for a nym's donation page. Used by
/// `POST /donation-page/image` after the resized WebP has been atomically
/// written to disk. `kind_column` is one of `"avatar_sha256"` or
/// `"og_sha256"` — caller validates via the `ImageKind` enum so the
/// column name is hard-coded by an enum match, not user input.
pub async fn update_donation_page_image_hash(
    pool: &PgPool,
    nym: &str,
    kind_column: &str,
    new_sha256: &str,
) -> Result<Option<DonationPage>, sqlx::Error> {
    // Hard-coded column allowlist defends against any caller that
    // sneaks an arbitrary string in. The column name is validated here
    // (not just upstream) because SQL injection via column names is
    // un-parameterizable.
    let sql = match kind_column {
        "avatar_sha256" => {
            "UPDATE donation_pages SET avatar_sha256 = $2, updated_at = now() \
             WHERE nym = $1 \
             RETURNING nym, header, description, avatar_sha256, og_sha256, \
                       display_currency, preset_amounts, website, twitter, \
                       instagram, enabled, (archived_at IS NOT NULL) AS is_archived"
        }
        "og_sha256" => {
            "UPDATE donation_pages SET og_sha256 = $2, updated_at = now() \
             WHERE nym = $1 \
             RETURNING nym, header, description, avatar_sha256, og_sha256, \
                       display_currency, preset_amounts, website, twitter, \
                       instagram, enabled, (archived_at IS NOT NULL) AS is_archived"
        }
        _ => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid image kind column: {kind_column}"
            )))
        }
    };
    sqlx::query_as::<_, DonationPage>(sql)
        .bind(nym)
        .bind(new_sha256)
        .fetch_optional(pool)
        .await
}

// =====================================================================
// Donation-page Liquid allocation (Phase 4)
// =====================================================================

#[derive(Debug)]
pub struct DonationAllocation {
    pub address: String,
    pub address_index: i32,
    pub was_existing: bool,
}

/// Cookie-pinned donation address allocator. Returns the existing binding
/// if `(nym, source_key, device_id)` already has one within the TTL,
/// otherwise allocates a fresh address from the user's ct_descriptor at
/// `users.next_addr_idx` and bumps the index.
///
/// `derive_address` is a closure: the caller knows how to derive a CT
/// address from a descriptor + index, so this fn doesn't depend on the
/// `descriptor` module directly. Keeps `db.rs` test-friendly and
/// pure-data.
///
/// Concurrency: runs the entire flow inside a tx under
/// `pg_advisory_xact_lock(hashtext('donation:'||nym))`. Same atomicity
/// pattern as `register_user_atomic` and the LUD-22 allocator. The lock
/// keyspace prefix `donation:` is disjoint from `<bare-npub-hex>` and
/// `<bucket-string>` so no AB/BA deadlock with rate-limit gates.
pub async fn lookup_or_allocate_donation_address<F>(
    pool: &PgPool,
    nym: &str,
    source_key: &str,
    device_id: uuid::Uuid,
    ttl_days: u32,
    derive_address: F,
) -> Result<DonationAllocation, sqlx::Error>
where
    F: FnOnce(&str, u32) -> Result<String, sqlx::Error>,
{
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(format!("donation:{nym}"))
        .execute(&mut *tx)
        .await?;

    // Hit path: existing binding within TTL **and not yet paid**.
    // Once a donator has paid an address, a fresh Donate click should
    // generate a NEW address — otherwise the page perpetually shows
    // the same paid address with the "Paid" status, which is confusing
    // and prevents subsequent donations.
    let cached: Option<(String, i32)> = sqlx::query_as(
        "SELECT address, address_index \
         FROM donation_allocations \
         WHERE nym = $1 AND source_key = $2 AND device_id = $3 \
           AND last_used_at > NOW() - ($4 || ' days')::interval \
           AND last_paid_at IS NULL",
    )
    .bind(nym)
    .bind(source_key)
    .bind(device_id)
    .bind(ttl_days as i32)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some((address, address_index)) = cached {
        sqlx::query(
            "UPDATE donation_allocations SET last_used_at = NOW() \
             WHERE nym = $1 AND source_key = $2 AND device_id = $3",
        )
        .bind(nym)
        .bind(source_key)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(DonationAllocation {
            address,
            address_index,
            was_existing: true,
        });
    }

    // Miss path: bump users.next_addr_idx atomically, derive address,
    // insert binding. Bumping (vs static-from-current) ensures each
    // donator gets a unique address — clean status-feedback semantics.
    let row: (String, i32) = sqlx::query_as(
        "UPDATE users SET next_addr_idx = next_addr_idx + 1 \
         WHERE nym = $1 AND is_active = TRUE \
         RETURNING ct_descriptor, next_addr_idx - 1",
    )
    .bind(nym)
    .fetch_one(&mut *tx)
    .await?;
    let (ct_descriptor, address_index) = row;
    let idx_u32 = u32::try_from(address_index)
        .map_err(|_| sqlx::Error::Protocol(format!("address index overflow: {address_index}")))?;
    let address = derive_address(&ct_descriptor, idx_u32)?;

    // ON CONFLICT here means there's an existing row for this
    // (nym, source_key, device_id) that the cached SELECT skipped —
    // either because it's been paid (we want to issue a fresh address)
    // or because it expired (TTL elapsed). Overwrite all fields so
    // the row reflects the new allocation, including clearing
    // last_paid_at so status feedback resets cleanly.
    let inserted: (String, i32) = sqlx::query_as(
        "INSERT INTO donation_allocations \
            (nym, source_key, device_id, address_index, address) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (nym, source_key, device_id) DO UPDATE \
            SET address_index = EXCLUDED.address_index, \
                address = EXCLUDED.address, \
                allocated_at = NOW(), \
                last_used_at = NOW(), \
                last_paid_at = NULL \
         RETURNING address, address_index",
    )
    .bind(nym)
    .bind(source_key)
    .bind(device_id)
    .bind(address_index)
    .bind(&address)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(DonationAllocation {
        address: inserted.0,
        address_index: inserted.1,
        was_existing: false,
    })
}

/// Cheap probe: does `(nym, source_key, device_id)` already have a live
/// donation binding (within TTL)? Used by `callback_liquid` to skip the
/// per-source rate-limit gate on cookie HITs — refreshes shouldn't burn
/// the FRESH-allocation budget. This is advisory only; the source of
/// truth is the atomic flow in `lookup_or_allocate_donation_address`.
pub async fn peek_donation_binding(
    pool: &PgPool,
    nym: &str,
    source_key: &str,
    device_id: uuid::Uuid,
    ttl_days: u32,
) -> Result<bool, sqlx::Error> {
    // Mirror the HIT condition in lookup_or_allocate_donation_address:
    // a paid binding is treated as a MISS (page should issue a fresh
    // address on the next Donate click) so the rate-limit gate fires.
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM donation_allocations \
         WHERE nym = $1 AND source_key = $2 AND device_id = $3 \
           AND last_used_at > NOW() - ($4 || ' days')::interval \
           AND last_paid_at IS NULL",
    )
    .bind(nym)
    .bind(source_key)
    .bind(device_id)
    .bind(ttl_days as i32)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// Count distinct fresh donation addresses allocated under a source_key
/// in the last `window_secs`. Used by the per-source rate-limit gate
/// applied on the MISS path of `lookup_or_allocate_donation_address`.
pub async fn count_recent_donation_allocations_per_source(
    pool: &PgPool,
    source_key: &str,
    window_secs: u32,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM donation_allocations \
         WHERE source_key = $1 \
           AND allocated_at > NOW() - ($2 || ' seconds')::interval",
    )
    .bind(source_key)
    .bind(window_secs as i32)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// List unpaid donation_allocations for a nym. Used by the chain
/// watcher to re-scan donation addresses on each tick — the lookahead
/// loop alone misses them because the MISS path of
/// `lookup_or_allocate_donation_address` bumps `next_addr_idx` past the
/// just-allocated index, leaving the index outside the watcher's
/// `[next_addr_idx, +lookahead]` scan range.
pub async fn list_unpaid_donation_allocations(
    pool: &PgPool,
    nym: &str,
) -> Result<Vec<(i32, String)>, sqlx::Error> {
    sqlx::query_as::<_, (i32, String)>(
        "SELECT address_index, address \
         FROM donation_allocations \
         WHERE nym = $1 AND last_paid_at IS NULL \
         ORDER BY address_index ASC",
    )
    .bind(nym)
    .fetch_all(pool)
    .await
}

/// Mark every still-unpaid donation_allocation that targets `addr_index`
/// for `nym` as paid. Called by the chain watcher when a payment is
/// observed at `derive(descriptor, addr_index)`. Each donation_allocation
/// row has a unique address_index (the MISS path bumps), so this updates
/// at most one row per call — but we use the same set-based UPDATE shape
/// as the LUD-22 reservation flow for consistency. Returns rows affected.
pub async fn mark_donation_paid_at_idx(
    pool: &PgPool,
    nym: &str,
    addr_index: u32,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE donation_allocations \
            SET last_paid_at = NOW() \
          WHERE nym = $1 AND address_index = $2 AND last_paid_at IS NULL",
    )
    .bind(nym)
    .bind(addr_index as i32)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Read donation-status payload for a Liquid donation: returns the
/// allocation's `last_paid_at` (None = not paid yet). Used by the
/// `/lnurlp/donate-status` poll endpoint.
pub async fn get_donation_allocation_paid_status(
    pool: &PgPool,
    nym: &str,
    address: &str,
) -> Result<Option<bool>, sqlx::Error> {
    // Use COALESCE so the boolean reads back unambiguously: TRUE = paid,
    // FALSE = waiting, None = address doesn't belong to this nym.
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT (last_paid_at IS NOT NULL) AS paid \
         FROM donation_allocations \
         WHERE nym = $1 AND address = $2",
    )
    .bind(nym)
    .bind(address)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(paid,)| paid))
}

/// Recycler: drop donation_allocations rows older than `ttl_days`. Run
/// periodically from `gc.rs` so abandoned cookies don't keep allocations
/// alive forever.
pub async fn prune_donation_allocations(pool: &PgPool, ttl_days: u32) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM donation_allocations \
         WHERE last_used_at < NOW() - ($1 || ' days')::interval",
    )
    .bind(ttl_days as i32)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn get_donation_page_by_nym(
    pool: &PgPool,
    nym: &str,
) -> Result<Option<DonationPage>, sqlx::Error> {
    sqlx::query_as::<_, DonationPage>(
        "SELECT nym, header, description, avatar_sha256, og_sha256, \
                display_currency, website, twitter, \
                instagram, enabled, (archived_at IS NOT NULL) AS is_archived \
         FROM donation_pages WHERE nym = $1",
    )
    .bind(nym)
    .fetch_optional(pool)
    .await
}

// =====================================================================
// Invoices (Phase B)
//
// Unified payment-intent abstraction. `origin` discriminates two creation
// flows: 'checkout' (anonymous browser, server-rate-limited per source) and
// 'wallet' (recipient's mobile, Schnorr-signed). Lightning offers attach
// 1:N via `swap_records.invoice_id`; Liquid offer is 1:1 and present at
// invoice creation for flows that accept Liquid or Lightning.
//
// Timestamp columns are NOT read into Rust structs as DateTime values —
// the workspace deliberately avoids the chrono/time sqlx feature flag.
// Instead, projections expose timestamps as `BIGINT` Unix epoch seconds
// via `EXTRACT(EPOCH FROM col)::BIGINT AS col_unix`. SQL boolean
// expressions (`expires_at < NOW()` etc.) handle every comparison
// server-side.
// =====================================================================

#[derive(Debug, sqlx::FromRow)]
pub struct Invoice {
    pub id: Uuid,
    /// Merchant payment-page nym; NULL for unlinked (wallet-only) invoices.
    pub nym_owner: Option<String>,
    /// Canonical recipient identity (hex x-only Schnorr pubkey). Always set.
    pub npub_owner: String,
    pub origin: String,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub amount_sat: i64,
    pub rate_minor_per_btc: Option<i64>,
    pub memo: Option<String>,
    pub recipient_label: Option<String>,
    pub bitcoin_address: Option<String>,
    pub accept_btc: bool,
    pub accept_ln: bool,
    pub accept_liquid: bool,
    pub public_description: Option<String>,
    pub invoice_number: Option<String>,
    pub liquid_address: Option<String>,
    pub liquid_address_index: Option<i32>,
    pub status: String,
    pub paid_via: Option<String>,
    pub paid_amount_sat: Option<i64>,
    pub pricing_mode: String,
    pub settlement_status: String,
    pub liquid_blinding_key_hex: Option<String>,
    /// Unix epoch seconds. See section comment above for the timestamp
    /// projection convention.
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub rate_locked_at_unix: i64,
    pub rate_locks_until_unix: i64,
    pub paid_at_unix: Option<i64>,
    pub cancelled_at_unix: Option<i64>,
}

/// Single source of truth for the `Invoice` SQL projection. Centralized
/// so a new column added to the struct is reflected in exactly one place
/// (mirrors the SwapRecord pattern). FromRow matches by alias name, so
/// the order is cosmetic.
const INVOICE_COLUMNS: &str =
    "id, nym_owner, npub_owner, origin, fiat_amount_minor, fiat_currency, amount_sat, \
     rate_minor_per_btc, memo, recipient_label, \
     bitcoin_address, accept_btc, accept_ln, accept_liquid, \
     public_description, invoice_number, \
     liquid_address, liquid_address_index, status, paid_via, paid_amount_sat, \
     pricing_mode, settlement_status, liquid_blinding_key_hex, \
     EXTRACT(EPOCH FROM created_at)::BIGINT       AS created_at_unix, \
     EXTRACT(EPOCH FROM expires_at)::BIGINT       AS expires_at_unix, \
     EXTRACT(EPOCH FROM rate_locked_at)::BIGINT   AS rate_locked_at_unix, \
     EXTRACT(EPOCH FROM rate_locks_until)::BIGINT AS rate_locks_until_unix, \
     EXTRACT(EPOCH FROM paid_at)::BIGINT          AS paid_at_unix, \
     EXTRACT(EPOCH FROM cancelled_at)::BIGINT     AS cancelled_at_unix";

pub struct NewInvoice<'a> {
    /// Merchant payment-page nym, or `None` for unlinked (wallet-only) invoices.
    pub nym_owner: Option<&'a str>,
    /// Canonical recipient identity (hex x-only Schnorr pubkey). Required.
    pub npub_owner: &'a str,
    /// 'checkout' or 'wallet'. Caller validates against the enum upstream.
    pub origin: &'a str,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<&'a str>,
    pub amount_sat: i64,
    pub rate_minor_per_btc: Option<i64>,
    /// Wall-clock seconds the rate stays locked from `now()`. For
    /// sat-denominated invoices, pass `expires_in_secs` so
    /// `rate_locks_until == expires_at` and the on-demand refresh path
    /// naturally never fires.
    pub rate_lock_secs: i64,
    pub memo: Option<&'a str>,
    pub recipient_label: Option<&'a str>,
    pub public_description: Option<&'a str>,
    pub invoice_number: Option<&'a str>,
    pub accept_btc: bool,
    pub accept_ln: bool,
    pub accept_liquid: bool,
    /// Wallet-supplied BTC mainnet address (NULL when accept_btc=FALSE).
    pub bitcoin_address: Option<&'a str>,
    /// Liquid mainnet CT address (NULL when both accept_ln=FALSE and
    /// accept_liquid=FALSE). Two supply paths feed this field:
    ///   - Wallet-origin (Get-paid): wallet supplies the address directly.
    ///   - Checkout-origin (donation page): server eagerly allocates
    ///     via `allocate_next_liquid_for_active_nym` BEFORE this insert.
    /// In both cases `liquid_address_index` on the invoice row stays
    /// NULL — the address is the chain_watcher's lookup key, not the
    /// descriptor index.
    pub liquid_address: Option<&'a str>,
    pub liquid_blinding_key_hex: Option<&'a str>,
    /// Wall-clock seconds the invoice stays valid from `now()`.
    pub expires_in_secs: i64,
}

/// Insert a new invoice row. The caller is responsible for populating
/// `liquid_address` when `accept_ln` or `accept_liquid` is TRUE — the
/// `invoices_ln_or_liquid_addr_chk` constraint requires it at INSERT
/// time. Two supply paths:
///   - Wallet-origin (Get-paid): the wallet supplies the address.
///   - Checkout-origin (donation page): the caller invokes
///     `allocate_next_liquid_for_active_nym` to bump the owner's
///     descriptor index and derive the next address, then passes the
///     result through `NewInvoice.liquid_address`.
/// Lightning offers attach via a separate `record_swap` call that sets
/// `swap_records.invoice_id`; the claimer routes the LN claim to the
/// invoice's `liquid_address` via `resolve_claim_address` branch (B).
pub async fn insert_invoice(
    pool: &PgPool,
    invoice: &NewInvoice<'_>,
) -> Result<Invoice, sqlx::Error> {
    sqlx::query_as::<_, Invoice>(&format!(
        "INSERT INTO invoices \
            (nym_owner, npub_owner, origin, fiat_amount_minor, fiat_currency, amount_sat, \
             rate_minor_per_btc, rate_locks_until, memo, recipient_label, \
             public_description, invoice_number, \
             accept_btc, accept_ln, accept_liquid, \
             bitcoin_address, liquid_address, pricing_mode, liquid_blinding_key_hex, \
             expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, \
                 NOW() + ($8 || ' seconds')::interval, $9, $10, \
                 $11, $12, $13, $14, $15, $16, $17, \
                 CASE WHEN $7::BIGINT IS NULL THEN 'sat_fixed' ELSE 'fiat_fixed' END, $18, \
                 NOW() + ($19 || ' seconds')::interval) \
         RETURNING {INVOICE_COLUMNS}"
    ))
    .bind(invoice.nym_owner)
    .bind(invoice.npub_owner)
    .bind(invoice.origin)
    .bind(invoice.fiat_amount_minor)
    .bind(invoice.fiat_currency)
    .bind(invoice.amount_sat)
    .bind(invoice.rate_minor_per_btc)
    .bind(invoice.rate_lock_secs)
    .bind(invoice.memo)
    .bind(invoice.recipient_label)
    .bind(invoice.public_description)
    .bind(invoice.invoice_number)
    .bind(invoice.accept_btc)
    .bind(invoice.accept_ln)
    .bind(invoice.accept_liquid)
    .bind(invoice.bitcoin_address)
    .bind(invoice.liquid_address)
    .bind(invoice.liquid_blinding_key_hex)
    .bind(invoice.expires_in_secs)
    .fetch_one(pool)
    .await
}

pub async fn get_invoice_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Invoice>, sqlx::Error> {
    sqlx::query_as::<_, Invoice>(&format!(
        "SELECT {INVOICE_COLUMNS} FROM invoices WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Best-effort cleanup for checkout creation failures after the invoice row
/// exists but before any payment offer was returned to the sender.
pub async fn delete_unpaid_invoice_without_swaps(
    pool: &PgPool,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "DELETE FROM invoices i \
         WHERE i.id = $1 \
           AND i.status = 'unpaid' \
           AND NOT EXISTS (SELECT 1 FROM swap_records s WHERE s.invoice_id = i.id)",
    )
    .bind(id)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

/// List invoices for an npub_owner, newest-first, with optional filters.
///
/// `status_filter`: `Some("unpaid"|"paid"|...)` filters by status;
/// `None` returns all statuses. `page` is one-based and `page_size`
/// is caller-clamped.
///
/// Predicate uses `($p::TYPE IS NULL OR ...)` so the planner can skip the
/// filter entirely when not provided. The composite index
/// `invoices_npub_owner_status_created_idx` services the ORDER BY.
pub async fn list_invoices_by_npub(
    pool: &PgPool,
    npub_owner: &str,
    status_filter: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<Vec<Invoice>, sqlx::Error> {
    let offset = (page.saturating_sub(1)).saturating_mul(page_size);
    sqlx::query_as::<_, Invoice>(&format!(
        "SELECT {INVOICE_COLUMNS} FROM invoices \
         WHERE npub_owner = $1 \
           AND ($2::TEXT IS NULL OR status = $2) \
         ORDER BY created_at DESC \
         LIMIT $3 OFFSET $4"
    ))
    .bind(npub_owner)
    .bind(status_filter)
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// List unpaid invoices' Liquid addresses for a nym_owner, ordered by
/// address_index. Returned shape `(invoice_id, address_index, address,
/// remaining amount and blinding key) gives the chain watcher everything
/// it needs to unblind candidate txs and record exact payment events.
///
/// Scoped to the legacy descriptor-allocator path
/// (`liquid_address_index IS NOT NULL`) — wallet-supplied invoices
/// (`liquid_address_index IS NULL`) are covered by `list_unpaid_invoices_with_liquid_address`.
pub async fn list_unpaid_invoice_liquid_addresses(
    pool: &PgPool,
    nym_owner: &str,
) -> Result<Vec<(Uuid, i32, String, i64, String)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, i32, String, i64, String)>(
        "SELECT id, liquid_address_index, liquid_address, amount_sat, liquid_blinding_key_hex \
         FROM invoices \
         WHERE nym_owner = $1 \
           AND status IN ('unpaid', 'in_progress', 'partially_paid') \
           AND accept_liquid = TRUE \
           AND liquid_address IS NOT NULL \
           AND liquid_blinding_key_hex IS NOT NULL \
           AND liquid_address_index IS NOT NULL \
         ORDER BY liquid_address_index ASC",
    )
    .bind(nym_owner)
    .fetch_all(pool)
    .await
}

/// Address-keyed scan for the chain watcher: every unpaid/in_progress
/// invoice with a settable Liquid address, regardless of nym_owner (so
/// linked + unlinked are covered uniformly) and regardless of how the
/// address was sourced (descriptor allocator OR wallet-supplied).
///
/// `ORDER BY created_at ASC` keeps scans deterministic if a client ever
/// reuses a wallet-supplied address. Payment events are idempotent by
/// outpoint, so repeated watcher ticks do not double count. Bounded by
/// `LIMIT 1000` so a runaway invoice pipeline can't blow the watcher's
/// per-tick budget; the next tick re-queries.
///
/// Returned shape: `(invoice_id, liquid_address, amount_sat)`.
pub async fn list_unpaid_invoices_with_liquid_address(
    pool: &PgPool,
) -> Result<Vec<(Uuid, String, i64, String)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, String, i64, String)>(
        "SELECT id, liquid_address, GREATEST(amount_sat - COALESCE(paid_amount_sat, 0), 0), liquid_blinding_key_hex \
         FROM invoices \
         WHERE status IN ('unpaid', 'in_progress', 'partially_paid') \
           AND accept_liquid = TRUE \
           AND liquid_address IS NOT NULL \
           AND liquid_blinding_key_hex IS NOT NULL \
           AND expires_at > NOW() \
         ORDER BY created_at ASC \
         LIMIT 1000",
    )
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone, Copy)]
pub struct InvoiceAccountingTolerances {
    pub btc_sat: i64,
    pub liquid_sat: i64,
    pub lightning_sat: i64,
}

impl Default for InvoiceAccountingTolerances {
    fn default() -> Self {
        Self {
            btc_sat: 300,
            liquid_sat: 60,
            lightning_sat: 1,
        }
    }
}

impl From<&crate::config::InvoiceAccountingConfig> for InvoiceAccountingTolerances {
    fn from(cfg: &crate::config::InvoiceAccountingConfig) -> Self {
        Self {
            btc_sat: cfg.btc_shortfall_tolerance_sat,
            liquid_sat: cfg.liquid_shortfall_tolerance_sat,
            lightning_sat: cfg.lightning_shortfall_tolerance_sat,
        }
    }
}

impl InvoiceAccountingTolerances {
    fn for_rail(self, rail: &str) -> i64 {
        match rail {
            "bitcoin" => self.btc_sat,
            "liquid" => self.liquid_sat,
            "lightning" => self.lightning_sat,
            _ => 0,
        }
        .max(0)
    }
}

fn payment_tolerance_sat_for_amount(
    amount_sat: i64,
    rail: &str,
    tolerances: InvoiceAccountingTolerances,
) -> i64 {
    let one_percent = (amount_sat / 100).max(1);
    tolerances.for_rail(rail).min(one_percent).max(0)
}

pub async fn record_invoice_payment(
    pool: &PgPool,
    id: Uuid,
    rail: &str,
    event_key: &str,
    amount_sat: i64,
    tolerances: InvoiceAccountingTolerances,
) -> Result<u64, sqlx::Error> {
    if amount_sat <= 0 {
        return Err(sqlx::Error::Protocol(
            "payment amount_sat must be > 0".into(),
        ));
    }
    if !matches!(rail, "bitcoin" | "liquid" | "lightning") {
        return Err(sqlx::Error::Protocol(format!(
            "unknown invoice payment rail: {rail}"
        )));
    }

    let mut tx = pool.begin().await?;
    let inv = sqlx::query_as::<_, Invoice>(&format!(
        "SELECT {INVOICE_COLUMNS} FROM invoices WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;

    if inv.status == "cancelled" {
        tx.commit().await?;
        return Ok(0);
    }

    let inserted: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO invoice_payment_events \
            (invoice_id, rail, event_key, amount_sat) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (event_key) DO NOTHING \
         RETURNING id",
    )
    .bind(id)
    .bind(rail)
    .bind(event_key)
    .bind(amount_sat)
    .fetch_optional(&mut *tx)
    .await?;

    if inserted.is_none() {
        tx.commit().await?;
        return Ok(0);
    }

    let (received_sat,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(amount_sat), 0)::BIGINT \
         FROM invoice_payment_events WHERE invoice_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;

    let rails: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT rail FROM invoice_payment_events WHERE invoice_id = $1 ORDER BY rail",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let paid_via = if rails.len() == 1 {
        rails[0].0.as_str()
    } else {
        "mixed"
    };

    let tolerance_sat = payment_tolerance_sat_for_amount(inv.amount_sat, rail, tolerances);
    let remaining_sat = inv.amount_sat.saturating_sub(received_sat);
    let expired = inv.expires_at_unix <= chrono_like_unix_now();
    let new_status = if received_sat > inv.amount_sat {
        "overpaid"
    } else if remaining_sat <= tolerance_sat {
        "paid"
    } else if expired {
        "underpaid"
    } else {
        "partially_paid"
    };
    let settlement_status = if matches!(new_status, "paid" | "overpaid") {
        "settled"
    } else {
        "none"
    };

    sqlx::query(
        "UPDATE invoices SET \
            status = $2, \
            paid_via = $3, \
            paid_amount_sat = $4, \
            settlement_status = $5, \
            paid_at = CASE WHEN $2 IN ('paid', 'overpaid') THEN COALESCE(paid_at, NOW()) ELSE paid_at END \
         WHERE id = $1",
    )
    .bind(id)
    .bind(new_status)
    .bind(paid_via)
    .bind(received_sat)
    .bind(settlement_status)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(1)
}

fn chrono_like_unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Flip an invoice to `in_progress` on the FIRST mempool sighting of a
/// payment tx (BTC watcher, or the LN claimer's `transaction.mempool`
/// hook in Step 9). Idempotent under the `WHERE status = 'unpaid'`
/// guard: a second sighting tick is a no-op (returns 0). Crucially, a
/// later `record_invoice_payment` call can still advance an
/// `in_progress` row to paid/under/over.
///
/// Returns rows_affected: 1 = flip happened; 0 = no-op (already
/// in_progress, paid, expired, cancelled, or row absent).
pub async fn mark_invoice_in_progress(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invoices SET status = 'in_progress', settlement_status = 'pending' \
         WHERE id = $1 AND status = 'unpaid'",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn mark_invoice_settlement_status(
    pool: &PgPool,
    id: Option<Uuid>,
    settlement_status: &str,
) -> Result<u64, sqlx::Error> {
    let Some(id) = id else {
        return Ok(0);
    };
    if !matches!(
        settlement_status,
        "none" | "pending" | "settled" | "claim_stuck" | "refunded" | "failed"
    ) {
        return Err(sqlx::Error::Protocol(format!(
            "unknown invoice settlement_status: {settlement_status}"
        )));
    }
    sqlx::query(
        "UPDATE invoices SET settlement_status = $2 \
         WHERE id = $1 AND status NOT IN ('paid', 'underpaid', 'overpaid', 'expired', 'cancelled')",
    )
    .bind(id)
    .bind(settlement_status)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

pub async fn mark_invoice_settlement_status_for_swap(
    pool: &PgPool,
    swap_id: Uuid,
    settlement_status: &str,
) -> Result<u64, sqlx::Error> {
    if !matches!(
        settlement_status,
        "none" | "pending" | "settled" | "claim_stuck" | "refunded" | "failed"
    ) {
        return Err(sqlx::Error::Protocol(format!(
            "unknown invoice settlement_status: {settlement_status}"
        )));
    }
    sqlx::query(
        "UPDATE invoices i SET settlement_status = $2 \
         FROM swap_records s \
         WHERE s.id = $1 \
           AND s.invoice_id = i.id \
           AND i.status NOT IN ('paid', 'underpaid', 'overpaid', 'expired', 'cancelled')",
    )
    .bind(swap_id)
    .bind(settlement_status)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

/// Cancel an unpaid invoice (recipient-initiated via signed
/// `invoice-cancel`). Idempotent: re-call on a row that's already
/// non-unpaid returns 0 rows affected. Caller verifies the Schnorr
/// signature AND that the invoice's nym maps to the verifying npub
/// upstream — this fn does not re-check ownership.
pub async fn cancel_invoice(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invoices SET status = 'cancelled', cancelled_at = NOW() \
         WHERE id = $1 AND status = 'unpaid'",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Background sweep: flip every unpaid OR in_progress invoice past its
/// outer deadline to 'expired'. Idempotent (set-based UPDATE; predicate
/// excludes already-terminal rows). Run from `gc.rs` on the periodic GC
/// cycle.
///
/// `in_progress` is included because a payer may broadcast a tx that
/// makes it to mempool (flipping the row to in_progress) but never
/// confirms (RBF replaced, mempool eviction, low-fee drop). After the
/// outer expiry we want the row out of the active corpus regardless of
/// its mempool stage. Backed by the partial index
/// `invoices_unpaid_or_inprog_expiry_idx` (migration 021).
pub async fn expire_invoices_past_deadline(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invoices SET status = CASE \
            WHEN status = 'partially_paid' THEN 'underpaid' \
            ELSE 'expired' \
         END \
         WHERE status IN ('unpaid', 'in_progress', 'partially_paid') AND expires_at < NOW()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Lazy-allocate the Liquid address for an invoice. Mirrors
/// `lookup_or_allocate_donation_address`'s atomicity pattern: one
/// transaction guarded by `pg_advisory_xact_lock(hashtext('donation:'||nym))`
/// — same lock keyspace as the legacy donation flow so the chain
/// watcher's existing single-flight assumptions still hold.
///
/// Returns:
/// - `Ok(Some((address, index)))` on first allocation (or on idempotent
///   re-read if the address was already set).
/// - `Ok(None)` if the invoice doesn't exist or its nym has no active
///   user (caller decides the user-facing error).
///
/// `derive_address` is a closure: the caller knows how to derive a CT
/// address from a descriptor + index, so this fn doesn't depend on the
/// `descriptor` module directly.
pub async fn allocate_invoice_liquid_address<F>(
    pool: &PgPool,
    invoice_id: Uuid,
    derive_address: F,
) -> Result<Option<(String, i32)>, sqlx::Error>
where
    F: FnOnce(&str, u32) -> Result<String, sqlx::Error>,
{
    let mut tx = pool.begin().await?;

    // Need the nym (nym_owner) to scope the advisory lock and bump
    // next_addr_idx. Unlinked invoices (nym_owner IS NULL) cannot use
    // this descriptor-allocator path — the caller must wallet-supply
    // the address at insert time.
    let nym: Option<(Option<String>,)> =
        sqlx::query_as("SELECT nym_owner FROM invoices WHERE id = $1 FOR UPDATE")
            .bind(invoice_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((Some(nym),)) = nym else {
        return Ok(None);
    };

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(format!("donation:{nym}"))
        .execute(&mut *tx)
        .await?;

    // Idempotent re-read: if a concurrent caller already allocated, just
    // return the existing address.
    let existing: Option<(Option<String>, Option<i32>)> = sqlx::query_as(
        "SELECT liquid_address, liquid_address_index \
         FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((Some(addr), Some(idx))) = existing {
        tx.commit().await?;
        return Ok(Some((addr, idx)));
    }

    let row: Option<(String, i32)> = sqlx::query_as(
        "UPDATE users SET next_addr_idx = next_addr_idx + 1 \
         WHERE nym = $1 AND is_active = TRUE \
         RETURNING ct_descriptor, next_addr_idx - 1",
    )
    .bind(&nym)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((ct_descriptor, address_index)) = row else {
        return Ok(None);
    };
    let idx_u32 = u32::try_from(address_index)
        .map_err(|_| sqlx::Error::Protocol(format!("address index overflow: {address_index}")))?;
    let address = derive_address(&ct_descriptor, idx_u32)?;

    sqlx::query(
        "UPDATE invoices SET liquid_address = $2, liquid_address_index = $3 \
         WHERE id = $1",
    )
    .bind(invoice_id)
    .bind(&address)
    .bind(address_index)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some((address, address_index)))
}

/// Pre-insert sibling of [`allocate_invoice_liquid_address`]: bump
/// `users.next_addr_idx` for an active nym and derive the next Liquid
/// address WITHOUT touching any invoice row. Returns `(address, index)`
/// so the caller can pass `address` into `NewInvoice.liquid_address`
/// at insert time.
///
/// Use this when creating an invoice with `accept_ln = TRUE` or
/// `accept_liquid = TRUE` and no wallet-supplied address — the
/// `invoices_ln_or_liquid_addr_chk` constraint requires
/// `liquid_address` to be set at INSERT time, so the allocator must
/// run before insert. The donation-page checkout flow is the primary
/// caller.
///
/// Shares the `donation:{nym}` advisory lock with
/// [`allocate_invoice_liquid_address`] so concurrent allocator calls
/// for the same nym serialize on the `next_addr_idx` bump.
///
/// Returns `Ok(None)` when the nym is unknown or `is_active = FALSE`.
pub async fn allocate_next_liquid_for_active_nym<F>(
    pool: &PgPool,
    nym: &str,
    derive_address: F,
) -> Result<Option<(String, i32)>, sqlx::Error>
where
    F: FnOnce(&str, u32) -> Result<String, sqlx::Error>,
{
    let mut tx = pool.begin().await?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(format!("donation:{nym}"))
        .execute(&mut *tx)
        .await?;

    let row: Option<(String, i32)> = sqlx::query_as(
        "UPDATE users SET next_addr_idx = next_addr_idx + 1 \
         WHERE nym = $1 AND is_active = TRUE \
         RETURNING ct_descriptor, next_addr_idx - 1",
    )
    .bind(nym)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((ct_descriptor, address_index)) = row else {
        return Ok(None);
    };
    let idx_u32 = u32::try_from(address_index)
        .map_err(|_| sqlx::Error::Protocol(format!("address index overflow: {address_index}")))?;
    let address = derive_address(&ct_descriptor, idx_u32)?;

    tx.commit().await?;
    Ok(Some((address, address_index)))
}

/// Read the most recent BOLT11 for an invoice (latest swap_records row
/// whose `invoice_id = $1`). Returns the invoice/BOLT11 string, or None
/// if no Lightning offer has been created yet for this invoice.
///
/// Service path: the status endpoint surfaces this so the page can render
/// a fresh QR after a rate refresh creates a new swap.
pub async fn latest_lightning_pr_for_invoice(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<(String, i64)>, sqlx::Error> {
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT invoice, amount_sat FROM swap_records \
         WHERE invoice_id = $1 \
         ORDER BY created_at DESC \
         LIMIT 1",
    )
    .bind(invoice_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

// --- BTC-to-LBTC chain swaps (Donation Page only, not publicly exposed yet) ---

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

pub async fn latest_chain_swap_for_invoice(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} FROM chain_swap_records \
         WHERE invoice_id = $1 \
         ORDER BY created_at DESC \
         LIMIT 1"
    ))
    .bind(invoice_id)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Single source of truth for the enum's variant set. Every test in
    /// this module iterates over this so adding a new variant fails
    /// loudly here instead of silently skipping coverage.
    const ALL_STATUSES: &[SwapStatus] = &[
        SwapStatus::Pending,
        SwapStatus::LockupMempool,
        SwapStatus::LockupConfirmed,
        SwapStatus::Claiming,
        SwapStatus::Claimed,
        SwapStatus::ClaimFailed,
        SwapStatus::Expired,
        SwapStatus::ClaimStuck,
        SwapStatus::LockupRefunded,
    ];

    const ALL_CHAIN_SWAP_STATUSES: &[ChainSwapStatus] = &[
        ChainSwapStatus::Pending,
        ChainSwapStatus::UserLockMempool,
        ChainSwapStatus::UserLockConfirmed,
        ChainSwapStatus::ServerLockMempool,
        ChainSwapStatus::ServerLockConfirmed,
        ChainSwapStatus::Claiming,
        ChainSwapStatus::Claimed,
        ChainSwapStatus::ClaimFailed,
        ChainSwapStatus::ClaimStuck,
        ChainSwapStatus::Expired,
        ChainSwapStatus::LockupFailed,
        ChainSwapStatus::Refunded,
    ];

    #[test]
    fn swap_status_round_trip() {
        for status in ALL_STATUSES {
            let s = status.to_string();
            let parsed: SwapStatus = s.parse().unwrap();
            assert_eq!(parsed, *status);
        }
    }

    #[test]
    fn swap_status_terminal() {
        assert!(SwapStatus::Claimed.is_terminal());
        assert!(SwapStatus::Expired.is_terminal());
        assert!(SwapStatus::ClaimStuck.is_terminal());
        assert!(SwapStatus::LockupRefunded.is_terminal());
        assert!(!SwapStatus::Pending.is_terminal());
        assert!(!SwapStatus::LockupMempool.is_terminal());
        assert!(!SwapStatus::LockupConfirmed.is_terminal());
        assert!(!SwapStatus::Claiming.is_terminal());
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
        assert!(!SwapStatus::ClaimStuck.is_claimable());
        assert!(!SwapStatus::LockupRefunded.is_claimable());
    }

    /// Cross-check: terminal and claimable are disjoint.
    #[test]
    fn swap_status_terminal_disjoint_from_claimable() {
        for status in ALL_STATUSES {
            assert!(
                !(status.is_terminal() && status.is_claimable()),
                "status {status} is both terminal and claimable"
            );
        }
    }

    #[test]
    fn swap_status_unknown_rejected() {
        assert!("garbage".parse::<SwapStatus>().is_err());
    }

    #[test]
    fn chain_swap_status_round_trip() {
        for status in ALL_CHAIN_SWAP_STATUSES {
            let s = status.to_string();
            let parsed: ChainSwapStatus = s.parse().unwrap();
            assert_eq!(parsed, *status);
        }
    }

    #[test]
    fn chain_swap_status_terminal() {
        assert!(ChainSwapStatus::Claimed.is_terminal());
        assert!(ChainSwapStatus::ClaimStuck.is_terminal());
        assert!(ChainSwapStatus::Expired.is_terminal());
        assert!(ChainSwapStatus::LockupFailed.is_terminal());
        assert!(ChainSwapStatus::Refunded.is_terminal());
        assert!(!ChainSwapStatus::Pending.is_terminal());
        assert!(!ChainSwapStatus::UserLockMempool.is_terminal());
        assert!(!ChainSwapStatus::UserLockConfirmed.is_terminal());
        assert!(!ChainSwapStatus::ServerLockMempool.is_terminal());
        assert!(!ChainSwapStatus::ServerLockConfirmed.is_terminal());
        assert!(!ChainSwapStatus::Claiming.is_terminal());
        assert!(!ChainSwapStatus::ClaimFailed.is_terminal());
    }

    #[test]
    fn chain_swap_status_unknown_rejected() {
        assert!("garbage".parse::<ChainSwapStatus>().is_err());
    }
}

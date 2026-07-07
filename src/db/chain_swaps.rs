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
    /// Funded lockup on a failed/expired swap whose BTC is still recoverable.
    /// NON-TERMINAL and the join point of the refund waterfall: set on funded
    /// failure, later drained by renegotiation (→ settle/`Claimed`) or customer
    /// self-claim (→ `Refunded`). Must never be terminalized to a dead state.
    RefundDue,
    /// Customer self-claim refund in flight (Phase 4). Set atomically from
    /// `RefundDue` under the per-swap advisory lock BEFORE the BTC refund tx is
    /// broadcast, and EXCLUDED from every claim path — this is the double-payout
    /// guard (G12): the L-BTC claim and the BTC refund spend different UTXOs on
    /// different chains and could otherwise both confirm. NON-TERMINAL: on
    /// broadcast failure it reverts to `RefundDue` (retryable); on success it
    /// advances to `Refunded`.
    Refunding,
}

impl ChainSwapStatus {
    pub fn is_terminal(self) -> bool {
        // `RefundDue` and `Refunding` are deliberately NOT terminal — the
        // reconciler must keep revisiting them so the waterfall can drain them
        // (and a failed refund broadcast can revert `Refunding` → `RefundDue`).
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
            Self::RefundDue => "refund_due",
            Self::Refunding => "refunding",
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
            "refund_due" => Ok(Self::RefundDue),
            "refunding" => Ok(Self::Refunding),
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
    pub cooperative_refused: bool,
    /// Server-lockup amount Boltz accepted after a Phase 3 quote renegotiation
    /// (get_quote/accept_quote), or NULL when the swap was never renegotiated.
    pub renegotiated_server_lock_amount_sat: Option<i64>,
    /// Customer-supplied BTC refund address (Phase 4), first-write-wins and
    /// immutable once set. NULL until the customer submits one.
    pub refund_address: Option<String>,
    /// Broadcast customer-refund transaction id (Phase 4), NULL until refunded.
    pub refund_txid: Option<String>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

impl ChainSwapRecord {
    pub fn parsed_status(&self) -> Result<ChainSwapStatus, String> {
        self.status.parse()
    }

    /// Amount to credit the merchant for this swap: the renegotiated
    /// server-lockup amount if the swap was renegotiated (Phase 3), otherwise
    /// the original server-lockup amount (= invoice under gross-up pricing).
    /// After a renegotiation the on-chain L-BTC actually claimed to the
    /// merchant is the renegotiated amount, so crediting the stale original
    /// would over- or under-credit the invoice.
    pub fn effective_server_lock_amount_sat(&self) -> i64 {
        self.renegotiated_server_lock_amount_sat
            .unwrap_or(self.server_lock_amount_sat)
    }
}

const CHAIN_SWAP_RECORD_COLUMNS: &str =
    "id, invoice_id, nym, boltz_swap_id, from_chain, to_chain, \
     lockup_address, lockup_bip21, user_lock_amount_sat, server_lock_amount_sat, \
     preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json, status, claim_txid, \
     claim_tx_hex, claim_attempts, last_claim_error, cooperative_refused, \
     renegotiated_server_lock_amount_sat, refund_address, refund_txid, \
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

/// Same as [`get_chain_swap_by_id`] but takes a `FOR UPDATE` row lock, so a
/// read-modify-write inside a transaction serializes against concurrent
/// `update_chain_swap_status` writers (which run lock-free on the pool). Used by
/// the Phase 3 renegotiation path to re-read the row under the advisory lock
/// before persisting the renegotiated amount.
pub async fn get_chain_swap_by_id_for_update<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} FROM chain_swap_records WHERE id = $1 FOR UPDATE"
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
        // Match on server_lock_amount_sat (the L-BTC settled to the merchant,
        // = the invoice/remaining amount) NOT user_lock_amount_sat: under
        // payer-pays gross-up pricing the user lockup is grossed up above the
        // invoice, so matching user_lock would never find the swap and the BTC
        // rail would silently vanish from the payment page + status API.
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} FROM chain_swap_records \
         WHERE invoice_id = $1 \
           AND status = 'pending' \
           AND server_lock_amount_sat = $2 \
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
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck', 'refunding')",
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

/// Flip `cooperative_refused` to TRUE (one-way). Set when Boltz reports
/// `swap.expired` for a chain swap, or when a cooperative claim is refused at
/// runtime, so the next claim attempt takes the script path. Never writes
/// through a terminal row. Mirrors `swaps::mark_cooperative_refused`.
pub async fn mark_chain_swap_cooperative_refused(
    pool: &PgPool,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET cooperative_refused = TRUE, updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck', 'refunding')",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Mark a funded-but-failed/expired chain swap `refund_due` (non-terminal) so
/// its BTC is recoverable rather than silently terminalized. Guarded against
/// terminal rows; NOT guarded against `refund_due` itself so this is
/// idempotent. `refund_due` is not in the terminal NOT-IN set, so a later
/// `update_chain_swap_status` can still advance it to `claimed` (renegotiation)
/// or `refunded` (self-claim) — that is the join point of the refund waterfall.
pub async fn mark_chain_swap_refund_due(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'refund_due', updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck', 'refunding')",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Records a successful Phase 3 quote renegotiation: persists the server-lockup
/// amount Boltz accepted and returns the swap to a live lifecycle state
/// (`user_lock_confirmed`) so the normal claim path drives it to settlement as
/// Boltz creates its (renegotiated) server lockup. Guarded to be idempotent —
/// only the first renegotiation on a still-live, not-yet-renegotiated row takes
/// effect (a re-delivered `lockupFailed` webhook is a no-op), and it never
/// resurrects a terminal swap. Returns rows affected (1 = applied, 0 = a
/// concurrent/duplicate call already handled it or the row is terminal).
pub async fn mark_chain_swap_renegotiated<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
    renegotiated_server_lock_amount_sat: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        // Persist the renegotiated amount UNCONDITIONALLY as long as the swap is
        // still live and not already renegotiated — crediting reads this, so it
        // must be recorded even if a concurrent `transaction.server.mempool`
        // webhook has already advanced the status past the funded lockup states.
        // The status nudge back to `user_lock_confirmed` is therefore CASE-gated:
        // only applied when still in a pre-server-lock funded state, so we never
        // REGRESS a more-advanced lifecycle state (the race SHOULD-FIX 3 flags).
        // `refund_due` is excluded from the guard so a late/duplicate
        // `lockupFailed` cannot resurrect an operator-visible refund case.
        "UPDATE chain_swap_records \
         SET renegotiated_server_lock_amount_sat = $2, \
             renegotiated_at = NOW(), \
             status = CASE \
                 WHEN status IN ('user_lock_mempool', 'user_lock_confirmed') \
                 THEN 'user_lock_confirmed' ELSE status END, \
             updated_at = NOW() \
         WHERE id = $1 \
           AND renegotiated_server_lock_amount_sat IS NULL \
           AND status NOT IN \
               ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck', 'refund_due', 'refunding')",
    )
    .bind(id)
    .bind(renegotiated_server_lock_amount_sat)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Chain swaps currently in `refund_due`, oldest first. Backs the operator
/// surface listing stranded-but-recoverable lockups.
pub async fn list_refund_due_chain_swaps(pool: &PgPool) -> Result<Vec<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE status = 'refund_due' \
         ORDER BY created_at ASC"
    ))
    .fetch_all(pool)
    .await
}

/// The `refund_due` chain swap for an invoice, if any (Phase 4). Used by the
/// customer self-claim endpoint to locate the swap whose BTC is refundable.
/// There is at most one refundable chain swap per invoice in practice; newest
/// first for determinism.
pub async fn find_refund_due_chain_swap_for_invoice(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE invoice_id = $1 AND status = 'refund_due' \
         ORDER BY created_at DESC \
         LIMIT 1"
    ))
    .bind(invoice_id)
    .fetch_optional(pool)
    .await
}

/// The already-`refunded` chain swap for an invoice, if any (Phase 4). Lets the
/// self-claim endpoint short-circuit a retried request idempotently — returning
/// the recorded `refund_txid` instead of erroring because the swap is no longer
/// `refund_due`.
pub async fn get_refunded_chain_swap_for_invoice(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE invoice_id = $1 AND status = 'refunded' \
         ORDER BY updated_at DESC \
         LIMIT 1"
    ))
    .bind(invoice_id)
    .fetch_optional(pool)
    .await
}

/// The in-flight (`refunding`) chain swap for an invoice, if any (Phase 4).
/// Lets the recovery endpoint return a distinct "recovery in progress" signal
/// (rather than "not available") when a merchant retries during the broadcast
/// window or while a stuck row awaits the reconciler backstop.
pub async fn get_refunding_chain_swap_for_invoice(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE invoice_id = $1 AND status = 'refunding' \
         ORDER BY updated_at DESC \
         LIMIT 1"
    ))
    .bind(invoice_id)
    .fetch_optional(pool)
    .await
}

/// Records the customer's BTC refund address, FIRST-WRITE-WINS and immutable
/// (G13/G14): the UPDATE only fires when `refund_address IS NULL` and the swap
/// is still `refund_due`, so a bystander who knows the public invoice URL cannot
/// overwrite an address already committed. Returns rows affected (1 = this call
/// set it; 0 = already set, or the swap is no longer `refund_due`). The caller
/// distinguishes "already set to the same address" (idempotent success) from
/// "set to a different address" (reject) by reading the row.
pub async fn set_chain_swap_refund_address(
    pool: &PgPool,
    id: Uuid,
    refund_address: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET refund_address = $2, updated_at = NOW() \
         WHERE id = $1 AND refund_address IS NULL AND status = 'refund_due'",
    )
    .bind(id)
    .bind(refund_address)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Atomically transitions `refund_due` -> `refunding` (Phase 4 G12 double-payout
/// guard). Only fires from `refund_due` with a refund address already committed;
/// `refunding` is excluded from every claim path, so once this succeeds no claim
/// can start. Runs inside the caller's advisory-locked transaction. Returns rows
/// affected (1 = we own the refund; 0 = not `refund_due`, or no address).
pub async fn mark_chain_swap_refunding<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        // `claim_txid IS NULL` is the G12 double-payout guard: a swap can reach
        // `refund_due` from `claiming`/`claim_failed` while our L-BTC claim tx is
        // still unconfirmed in the mempool (preimage already public). Refunding
        // the BTC lockup then would pay the customer AND let the merchant's claim
        // confirm — a genuine double payout. If we ever constructed/broadcast a
        // claim, refuse the refund and let the claim path win.
        "UPDATE chain_swap_records \
         SET status = 'refunding', updated_at = NOW() \
         WHERE id = $1 AND status = 'refund_due' \
           AND refund_address IS NOT NULL \
           AND claim_txid IS NULL AND claim_tx_hex IS NULL",
    )
    .bind(id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Terminal success: `refunding` -> `refunded`, recording the broadcast txid.
/// Guarded to `refunding` so it cannot terminalize a swap that reverted or was
/// never in flight. Returns rows affected.
pub async fn mark_chain_swap_refunded(
    pool: &PgPool,
    id: Uuid,
    refund_txid: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'refunded', refund_txid = $2, updated_at = NOW() \
         WHERE id = $1 AND status = 'refunding'",
    )
    .bind(id)
    .bind(refund_txid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Reverts `refunding` -> `refund_due` on a broadcast failure so the refund
/// stays recoverable (retryable by a later customer attempt or the reconciler)
/// rather than stranding funds in a non-draining state. Guarded to `refunding`.
/// Returns rows affected.
pub async fn revert_chain_swap_refunding_to_due(
    pool: &PgPool,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'refund_due', updated_at = NOW() \
         WHERE id = $1 AND status = 'refunding'",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Reconciler backstop for STUCK `refunding` rows (Phase 4). The refund executor
/// runs inline in the request handler; if the customer's connection drops (or
/// the process restarts) after the `refund_due` -> `refunding` flip but before
/// completion, the row is stranded in `refunding` — invisible to the operator
/// `refund_due` surface and rejected by the endpoint as "already in progress".
/// This reverts any `refunding` row untouched for `min_age_secs` back to
/// `refund_due` so a later customer/reconciler attempt retries it. Safe: a
/// re-broadcast spends the same lockup UTXO to the same immutable address, so at
/// most one refund tx ever confirms. `min_age_secs` must comfortably exceed a
/// normal broadcast round-trip so an ACTIVE refund is never reverted. Returns
/// the ids reverted (for alerting).
pub async fn revert_stale_refunding_chain_swaps(
    pool: &PgPool,
    min_age_secs: i64,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "UPDATE chain_swap_records \
         SET status = 'refund_due', updated_at = NOW() \
         WHERE status = 'refunding' \
           AND updated_at < NOW() - make_interval(secs => $1) \
         RETURNING id",
    )
    .bind(min_age_secs as f64)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Non-terminal chain swaps older than `min_age_secs`, oldest first, capped at
/// `max_rows`. Drives the chain-swap reconciler: unlike the claim sweep
/// (`get_ready_to_claim_chain_swaps`, which only covers server-lock/claiming
/// states), this covers EVERY non-terminal state — including `pending` and
/// `user_lock_*` — so a chain swap stranded by a dropped Boltz webhook is
/// re-driven by polling Boltz `get_swap`. Mirrors
/// `swaps::list_non_terminal_swaps_oldest_first`.
pub async fn list_non_terminal_chain_swaps_oldest_first(
    pool: &PgPool,
    min_age_secs: u64,
    limit: u32,
) -> Result<Vec<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck') \
           AND updated_at < NOW() - ($1 || ' seconds')::interval \
         ORDER BY updated_at ASC \
         LIMIT $2"
    ))
    .bind(min_age_secs as i64)
    .bind(limit as i64)
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

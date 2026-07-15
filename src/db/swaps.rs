use std::fmt;
use std::str::FromStr;

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    mark_user_used, validate_invoice_quote_attribution, InvoiceQuoteAttribution,
    LiquidClaimFeeAuthority, LiquidClaimFeeAuthorityRow,
};

pub const CLAIM_IN_FLIGHT_LEASE: &str = "2 minutes";

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

// --- Address & swap key allocation ---

pub async fn next_swap_key_index<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
) -> Result<u64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT nextval('swap_key_seq')")
        .fetch_one(executor)
        .await?;
    Ok(row.0 as u64)
}

/// The value the NEXT `nextval('swap_key_seq')` will return, without consuming
/// it. Requires `is_called`: once a value has been issued, `last_value` is that
/// issued value (so `last_value == MAX(persisted index)` is the normal steady
/// state, not a rollback) and the next issue is `last_value + 1`; before any
/// issue, `last_value` itself is next. Compared against the maximum persisted
/// index at startup to detect a database restore that rewound the sequence.
/// See migration 044.
pub async fn swap_key_seq_next_value(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT CASE WHEN is_called THEN last_value + 1 ELSE last_value END \
         FROM swap_key_seq",
    )
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Highest swap-key index persisted for `fingerprint` across reverse swaps.
/// `None` when this deployment has recorded no derivation metadata yet (fresh
/// install or pre-migration rows only), which the rollback check treats as
/// safe. See migration 044.
pub async fn max_persisted_reverse_key_index(
    pool: &PgPool,
    fingerprint: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let row: (Option<i64>,) = sqlx::query_as(
        "SELECT MAX(key_index) FROM swap_records \
         WHERE root_fingerprint = $1 AND key_index IS NOT NULL",
    )
    .bind(fingerprint)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn allocate_address_index(pool: &PgPool, nym: &str) -> Result<Option<i32>, sqlx::Error> {
    // This allocates a new Lightning Address instruction and therefore stays
    // coupled to product availability. Existing recorded swaps are claimed by
    // obligation-keyed queries that do not apply this admission predicate.
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
    /// Derivation index of the swap key from `swap_key_seq`, recorded so a
    /// rewound sequence after a DB restore is detectable. See migration 044.
    pub key_index: Option<i64>,
    /// Seed fingerprint that `key_index` is relative to. See migration 044.
    pub root_fingerprint: Option<&'a str>,
}

pub struct ReverseSwapLineage<'a> {
    pub allocation_id: Uuid,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    pub claim_public_key_hex: &'a str,
    pub preimage_hash_hex: &'a str,
}

pub async fn record_swap(pool: &PgPool, swap: &NewSwapRecord<'_>) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    insert_swap_in_tx(&mut tx, swap, None, None).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn record_swap_with_lineage(
    pool: &PgPool,
    swap: &NewSwapRecord<'_>,
    lineage: &ReverseSwapLineage<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    insert_swap_in_tx(&mut tx, swap, Some(lineage), None).await?;
    tx.commit().await?;
    Ok(())
}

/// Quote-aware reverse-swap persistence. The exact Lightning/Boltz payer
/// offer is validated in the insert transaction and stored immutably beside
/// the provider obligation. Expired offers remain valid attribution targets.
pub async fn record_swap_with_lineage_and_quote_attribution(
    pool: &PgPool,
    swap: &NewSwapRecord<'_>,
    lineage: &ReverseSwapLineage<'_>,
    attribution: InvoiceQuoteAttribution,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    insert_swap_in_tx(&mut tx, swap, Some(lineage), Some(attribution)).await?;
    tx.commit().await?;
    Ok(())
}

/// Transaction-aware swap insert used when the caller already owns an invoice
/// serialization boundary. Keeping allocation, provider result persistence,
/// and invoice revalidation on that one connection avoids nested-pool
/// starvation under concurrent lazy offer creation.
pub async fn record_swap_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    swap: &NewSwapRecord<'_>,
) -> Result<(), sqlx::Error> {
    insert_swap_in_tx(tx, swap, None, None).await
}

pub async fn record_swap_in_tx_with_lineage(
    tx: &mut Transaction<'_, Postgres>,
    swap: &NewSwapRecord<'_>,
    lineage: &ReverseSwapLineage<'_>,
) -> Result<(), sqlx::Error> {
    insert_swap_in_tx(tx, swap, Some(lineage), None).await
}

/// Transaction-aware quote-attributed counterpart used by lazy offer
/// creation while it owns the invoice serialization boundary.
pub async fn record_swap_in_tx_with_lineage_and_quote_attribution(
    tx: &mut Transaction<'_, Postgres>,
    swap: &NewSwapRecord<'_>,
    lineage: &ReverseSwapLineage<'_>,
    attribution: InvoiceQuoteAttribution,
) -> Result<(), sqlx::Error> {
    insert_swap_in_tx(tx, swap, Some(lineage), Some(attribution)).await
}

/// Test/compatibility-shaped transaction API. Production quote-aware reverse
/// swaps should carry key lineage through
/// [`record_swap_in_tx_with_lineage_and_quote_attribution`].
pub async fn record_swap_in_tx_with_quote_attribution(
    tx: &mut Transaction<'_, Postgres>,
    swap: &NewSwapRecord<'_>,
    attribution: InvoiceQuoteAttribution,
) -> Result<(), sqlx::Error> {
    insert_swap_in_tx(tx, swap, None, Some(attribution)).await
}

async fn insert_swap_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    swap: &NewSwapRecord<'_>,
    lineage: Option<&ReverseSwapLineage<'_>>,
    attribution: Option<InvoiceQuoteAttribution>,
) -> Result<(), sqlx::Error> {
    if let Some(attribution) = attribution {
        let invoice_id = swap.invoice_id.ok_or_else(|| {
            sqlx::Error::Protocol(
                "quote-attributed reverse swap requires an invoice identity".into(),
            )
        })?;
        validate_invoice_quote_attribution(
            &mut **tx,
            invoice_id,
            attribution,
            "lightning",
            "boltz_reverse",
            Some("boltz"),
            Some(swap.boltz_swap_id),
            None,
        )
        .await?;
    }
    sqlx::query(
        "INSERT INTO swap_records \
         (nym, boltz_swap_id, address, address_index, amount_sat, invoice, \
          preimage_hex, claim_key_hex, boltz_response_json, status, invoice_id, \
          key_index, root_fingerprint, key_allocation_id, key_epoch, \
          derivation_scheme_version, claim_public_key_hex, preimage_hash_hex, \
          invoice_quote_version_id, invoice_quote_offer_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11, $12, \
                 $13, $14, $15, $16, $17, $18, $19)",
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
    .bind(swap.key_index)
    .bind(swap.root_fingerprint)
    .bind(lineage.map(|lineage| lineage.allocation_id))
    .bind(lineage.map(|lineage| lineage.key_epoch))
    .bind(lineage.map(|lineage| lineage.derivation_scheme_version))
    .bind(lineage.map(|lineage| lineage.claim_public_key_hex))
    .bind(lineage.map(|lineage| lineage.preimage_hash_hex))
    .bind(attribution.map(|attribution| attribution.quote_version_id))
    .bind(attribution.map(|attribution| attribution.quote_offer_id))
    .execute(&mut **tx)
    .await?;
    if let Some(nym) = swap.nym {
        mark_user_used(&mut **tx, nym).await?;
    }
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
    /// All-null for unjournaled rows and immutable pre-054 claim bytes; a
    /// complete, validated schema-054 packet for every newer claim journal.
    #[sqlx(flatten, try_from = "LiquidClaimFeeAuthorityRow")]
    pub claim_fee_authority: LiquidClaimFeeAuthority,
    /// 'cooperative' (MuSig2 keypath, requires Boltz cosign) or 'script'
    /// (preimage-revealing script-path). The script path is the only
    /// recovery once Boltz status reaches `swap.expired`.
    pub claim_path: Option<String>,
    /// Total claim attempts (across construct+broadcast). The background
    /// sweep gives up at `config.max_claim_attempts` and transitions the
    /// row to `ClaimStuck`.
    pub claim_attempts: i32,
    /// Last claim error message — operator-facing surface for stuck swaps.
    pub last_claim_error: Option<String>,
    /// Set when Boltz refused the cooperative MuSig2 endpoint (HTTP 4xx
    /// or known refusal substrings). Future attempts skip cooperative and
    /// take the script path.
    pub cooperative_refused: bool,
    /// When this swap is the Lightning offer for an invoice, the claimer
    /// records a payment event against this invoice only after the
    /// merchant-side claim succeeds. NULL for LNURL Lightning Address
    /// swaps and for non-invoice rows.
    pub invoice_id: Option<Uuid>,
    /// Exact immutable five-minute quote/offer lineage. Both values are NULL
    /// for pre-061 and non-invoice rows, or both are present for quote-aware
    /// invoice swaps.
    pub invoice_quote_version_id: Option<Uuid>,
    pub invoice_quote_offer_id: Option<Uuid>,
    // NOTE: `next_claim_attempt_at` and `last_claim_error_at` are real
    // columns in the schema but intentionally NOT read into this struct.
    // Reading TIMESTAMPTZ requires the `time` or `chrono` sqlx feature
    // flag, which the workspace deliberately avoids. All timestamp
    // comparisons happen server-side in SQL (e.g.
    // `WHERE next_claim_attempt_at IS NULL OR next_claim_attempt_at <= NOW()`),
    // and the values are surfaced to operators through direct DB queries.
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
     claim_tx_hex, claim_actual_fee_sat, claim_actual_fee_rate_sat_vb, \
     claim_fee_decision_purpose, claim_fee_decision_rail, \
     claim_fee_decision_target, claim_fee_decision_source, \
     claim_fee_decision_rate_sat_vb, claim_fee_decision_quoted_at_unix, \
     claim_fee_decision_evaluated_at_unix, \
     claim_fee_decision_freshness_age_secs, \
     claim_fee_decision_freshness_max_age_secs, claim_fee_decision_provenance, \
     claim_fee_decision_policy_floor_sat_vb, \
     claim_fee_decision_policy_cap_sat_vb, claim_fee_decision_policy_version, \
     claim_path, claim_attempts, \
     last_claim_error, cooperative_refused, invoice_id, \
     invoice_quote_version_id, invoice_quote_offer_id";

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

/// Load and row-lock a swap by primary key. This is used only by locked claim
/// preparation: the row lock makes the status/claim-byte snapshot authoritative
/// against webhook writers until preparation commits or rolls back. Generic
/// over any executor so the claimer stays on its existing connection.
pub async fn get_swap_by_id<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<Option<SwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, SwapRecord>(&format!(
        "SELECT {SWAP_RECORD_COLUMNS} FROM swap_records WHERE id = $1 FOR UPDATE"
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
/// This guard does not enforce ordinal monotonicity between non-terminal
/// states. Both lockup mempool and confirmed states are claimable; late
/// webhook ordering only affects observability.
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
/// script path. Used by
/// the webhook handler when Boltz emits `swap.expired` — the cooperative
/// endpoint refuses post-expiry per `MusigSigner.ts`, but the on-chain
/// HTLC is still claimable until `timeoutBlockHeight` via the script
/// path.
///
/// Idempotent. Status is not touched here — the row stays claimable.
pub async fn mark_cooperative_refused<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE swap_records \
         SET cooperative_refused = TRUE, updated_at = NOW() \
         WHERE id = $1 AND cooperative_refused = FALSE \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
    )
    .bind(id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Outcome of `record_claim_failure`. Drives the caller's logging.
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
/// Called from `claim_swap` when broadcast or construction fails. Increments
/// `claim_attempts`, stamps `last_claim_error`, and computes
/// `next_claim_attempt_at` from the documented backoff schedule:
///
/// ```text
/// claim_attempts (post-increment): 1, 2, 3,  4,   5,    6,    7+
/// delay (seconds):                10, 20, 60, 300, 600, 1800, 3600 (cap)
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

/// Funded reverse swaps stranded in `claim_stuck` whose slow-recovery backoff is
/// due (issue #63). Bounded + oldest-first. Returns `(id, boltz_swap_id,
/// slow_attempts)` so the caller can compute the next backoff. `claim_stuck` is
/// reached only for a funded lockup (the retry budget ran out mid-claim), so
/// these are exactly the rows whose output may still be claimable.
pub async fn list_claim_stuck_swaps_for_slow_retry(
    pool: &PgPool,
    limit: u32,
) -> Result<Vec<(Uuid, String, i32)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, String, i32)>(
        "SELECT id, boltz_swap_id, slow_attempts \
         FROM swap_records \
         WHERE status = 'claim_stuck' \
           AND (next_slow_attempt_at IS NULL OR next_slow_attempt_at <= NOW()) \
         ORDER BY next_slow_attempt_at NULLS FIRST \
         LIMIT $1",
    )
    .bind(limit as i64)
    .fetch_all(pool)
    .await
}

/// Revive a `claim_stuck` reverse swap into the normal claim sweep for exactly
/// one more attempt — `status → 'claim_failed'` (a status the sweep selects),
/// `claim_attempts → max_attempts - 1` (so a single failure re-sticks it, no
/// burst), due immediately — and schedule the next slow revival with the
/// caller-computed capped backoff. Guarded on `status='claim_stuck'` so a
/// concurrent transition (or a claim that already succeeded) wins. Reviving to
/// `claim_failed` delegates the chain-state check to the claim path itself: on
/// the retry, an already-spent lockup is caught by the existing outspend-probe
/// recovery rather than blindly rebuilt. Returns rows affected (0 or 1).
pub async fn revive_claim_stuck_swap_for_slow_retry(
    pool: &PgPool,
    id: Uuid,
    max_attempts: i32,
    backoff_secs: u64,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE swap_records \
         SET status = 'claim_failed', \
             claim_attempts = GREATEST(0, $2 - 1), \
             next_claim_attempt_at = NOW(), \
             slow_attempts = slow_attempts + 1, \
             next_slow_attempt_at = NOW() + (($3 || ' seconds')::interval) * (0.8 + 0.4 * random()), \
             updated_at = NOW() \
         WHERE id = $1 AND status = 'claim_stuck'",
    )
    .bind(id)
    .bind(max_attempts)
    .bind(backoff_secs as i64)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
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

/// Capture one process-local reconciliation epoch from the database clock.
/// Keeping the value as integer Unix microseconds avoids adding a timestamp
/// crate solely for an opaque scan boundary; queries convert it back with
/// `to_timestamp`. A worker retains this value across bounded pages and drops
/// it only when the frozen set drains or a systemic page failure occurs.
pub async fn reconciler_scan_epoch_micros(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000000)::BIGINT")
        .fetch_one(pool)
        .await
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

pub(crate) const REVERSE_RECONCILER_SCAN_SQL: &str = "WITH scan AS ( \
         SELECT to_timestamp($2::double precision / 1000000.0) AS epoch \
     ) \
     SELECT id, boltz_swap_id, status, cooperative_refused, claim_txid, \
            nym, amount_sat, invoice_id \
     FROM swap_records, scan \
     WHERE status NOT IN ('claimed', 'expired', 'lockup_refunded', 'claim_stuck') \
       AND updated_at <= scan.epoch - ($1 || ' seconds')::interval \
       AND ($3::uuid IS NULL OR id > $3) \
     ORDER BY id ASC \
     LIMIT $4";

/// Reconciler scan: every non-terminal swap in the frozen `epoch_micros`
/// snapshot that is older than `min_age_secs` and follows the process-local
/// immutable UUID cursor, capped at `limit`.
///
/// `min_age_secs` skips fresh rows so we don't race the webhook handler on a
/// swap that's still mid-flight. The caller asks for its processing cap plus
/// one, using the extra row as proof that the epoch has not drained yet.
pub async fn list_non_terminal_swaps_oldest_first(
    pool: &PgPool,
    min_age_secs: u64,
    epoch_micros: i64,
    after_id: Option<Uuid>,
    limit: u32,
) -> Result<Vec<ReconcilerSwap>, sqlx::Error> {
    sqlx::query_as::<_, ReconcilerSwap>(REVERSE_RECONCILER_SCAN_SQL)
        .bind(min_age_secs as i64)
        .bind(epoch_micros)
        .bind(after_id)
        .bind(limit as i64)
        .fetch_all(pool)
        .await
}

/// Reverse (Lightning) swaps that reached `claimed` — merchant funds are on
/// chain — but whose invoice payment event was never recorded. This happens
/// when the process dies (or `record_invoice_payment` transiently fails)
/// between committing the `claimed` status and running
/// `flip_invoice_on_lightning_settlement`: the claim succeeded but the invoice
/// (POS receipt / payer screen / signed list) still shows unpaid, and the
/// reconciler never revisits `claimed` (terminal) rows. The settlement-repair
/// task re-runs the idempotent flip for these.
///
pub(crate) const REVERSE_SETTLEMENT_REPAIR_SCAN_SQL: &str = "WITH scan AS ( \
         SELECT to_timestamp($2::double precision / 1000000.0) AS epoch \
     ) \
     SELECT id, boltz_swap_id, status, cooperative_refused, claim_txid, \
            nym, amount_sat, invoice_id \
     FROM swap_records s, scan \
     WHERE s.status = 'claimed' \
       AND s.invoice_id IS NOT NULL \
       AND s.claim_txid IS NOT NULL \
       AND s.updated_at <= scan.epoch \
       AND s.updated_at > scan.epoch - ($1 || ' seconds')::interval \
       AND ($3::uuid IS NULL OR s.id > $3) \
       AND NOT EXISTS ( \
             SELECT 1 FROM invoice_payment_events e \
              WHERE e.invoice_id = s.invoice_id \
                AND e.event_key = 'lightning_boltz_reverse:' || s.boltz_swap_id \
         ) \
     ORDER BY s.id ASC \
     LIMIT $4";

/// Bounded by `max_age_secs` (only recently-claimed rows), the process-local
/// immutable UUID cursor, and `limit`.
pub async fn list_claimed_swaps_missing_lightning_event(
    pool: &PgPool,
    max_age_secs: u64,
    epoch_micros: i64,
    after_id: Option<Uuid>,
    limit: u32,
) -> Result<Vec<ReconcilerSwap>, sqlx::Error> {
    sqlx::query_as::<_, ReconcilerSwap>(REVERSE_SETTLEMENT_REPAIR_SCAN_SQL)
        .bind(max_age_secs as i64)
        .bind(epoch_micros)
        .bind(after_id)
        .bind(limit as i64)
        .fetch_all(pool)
        .await
}

/// Schedule an immediate retry from the reconciler. Sets
/// `next_claim_attempt_at = NOW()` so the next sweep tick (<=30s) picks
/// up the row. Forward-only: terminal-state guard prevents the
/// reconciler from "un-finishing" a row that completed concurrently.
///
/// A row in `claiming` may own an in-flight broadcast lease in
/// `next_claim_attempt_at`; do not collapse a future lease back to NOW or
/// webhook/reconciler races can generate duplicate broadcasts and false
/// failure records. Clamp longer future backoffs to the lease horizon so
/// stale failures are still nudged without entering the active broadcast
/// window. If the timestamp is already due, the row is idle and can be
/// nudged immediately.
///
/// Does not change `status`. Used when the reconciler observes that
/// Boltz still considers the swap claimable but our row hasn't been
/// retried recently (e.g., a permanent-looking error that was actually
/// transient).
pub async fn schedule_immediate_claim(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE swap_records \
         SET next_claim_attempt_at = CASE \
                 WHEN status = 'claiming' AND next_claim_attempt_at > NOW() \
                     THEN LEAST(next_claim_attempt_at, NOW() + $2::interval) \
                 ELSE NOW() \
             END, \
             updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
    )
    .bind(id)
    .bind(CLAIM_IN_FLIGHT_LEASE)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Combined reconciler action for the `swap.expired` (Boltz wall-clock
/// timer) case. Flips `cooperative_refused = TRUE` and schedules an
/// immediate retry so the next sweep tick takes the script path.
/// Single transaction for atomicity — the operator is never confused
/// by "cooperative_refused but not scheduled" or vice versa.
/// Preserves an active `claiming` lease the same way
/// `schedule_immediate_claim` does.
pub async fn schedule_script_path_retry(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE swap_records \
         SET cooperative_refused = TRUE, \
             next_claim_attempt_at = CASE \
                 WHEN status = 'claiming' AND next_claim_attempt_at > NOW() \
                     THEN LEAST(next_claim_attempt_at, NOW() + $2::interval) \
                 ELSE NOW() \
             END, \
             updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
    )
    .bind(id)
    .bind(CLAIM_IN_FLIGHT_LEASE)
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

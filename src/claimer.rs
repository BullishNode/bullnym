use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use boltz_client::network::electrum::ElectrumLiquidClient;
use boltz_client::network::{Chain, LiquidChain};
use boltz_client::swaps::boltz::{BoltzApiClientV2, CreateReverseResponse};
use boltz_client::swaps::{
    BtcLikeTransaction, ChainClient, SwapScript, SwapTransactionParams, TransactionOptions,
};
use boltz_client::util::fees::Fee;
use boltz_client::util::secrets::Preimage;
use boltz_client::Keypair;

use crate::config::Config;
use crate::db::{self, SwapStatus};
use crate::descriptor;
use crate::error::AppError;
use crate::ip_whitelist;
use crate::utxo::UtxoBackend;
use crate::AppState;

#[derive(Deserialize)]
struct WebhookEnvelope {
    data: WebhookData,
}

#[derive(Deserialize)]
struct WebhookData {
    id: String,
    status: String,
}

/// Constant-time match of a presented URL-path secret against a
/// (current, previous) pair of configured secrets.
///
/// - Returns `true` only when `presented` matches one of the configured
///   secrets exactly.
/// - Empty configured secrets never validate, even against an empty
///   presented value — otherwise a misconfigured deploy would silently
///   accept any request.
/// - Length differences fail before the constant-time compare. This
///   leaks "wrong length" via timing but the configured secret is a
///   fixed long random string; the worst case is the attacker learns
///   "you didn't pick this length", which is uninteresting.
fn url_secret_matches_pair(presented: &str, current: &str, previous: &str) -> bool {
    fn ct_eq(a: &str, b: &str) -> bool {
        if b.is_empty() || a.len() != b.len() {
            return false;
        }
        a.as_bytes().ct_eq(b.as_bytes()).into()
    }
    ct_eq(presented, current) || ct_eq(presented, previous)
}

fn webhook_url_secret_matches(presented: &str, config: &Config) -> bool {
    url_secret_matches_pair(
        presented,
        &config.boltz_webhook_url_secret,
        &config.boltz_webhook_url_secret_previous,
    )
}

/// Authenticated webhook entrypoint: `/webhook/boltz/:secret`.
/// Routes the request to the shared dispatcher only after the URL
/// segment matches a configured secret in constant time.
pub async fn webhook_with_secret(
    State(state): State<AppState>,
    Path(secret): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: String,
) -> Result<&'static str, AppError> {
    if !webhook_url_secret_matches(&secret, &state.config) {
        // Same shape as a route miss — don't leak whether the path
        // existed but the secret was wrong vs. the route doesn't exist.
        // Webhook-bomb rate-limit is still applied below.
        let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
        let caller_ip = ip_whitelist::resolve_caller_ip(
            peer_opt.map(|ConnectInfo(addr)| addr.ip()),
            xff,
            state.config.rate_limit.trust_forwarded_for,
        );
        tracing::warn!(
            "boltz webhook: URL secret mismatch from {:?}",
            caller_ip
        );
        return Err(AppError::AuthError(StatusCode::NOT_FOUND.to_string()));
    }
    dispatch_webhook(state, peer_opt, headers, body).await
}

/// Legacy unauthenticated webhook entrypoint: `/webhook/boltz`. When
/// `boltz_webhook_url_secret` is configured this path is locked down —
/// production must register the authenticated URL with Boltz instead.
/// Kept on the router so dev environments without a configured secret
/// keep working as before.
///
/// **First-time secret rollout (operational note).** The webhook URL is
/// captured Boltz-side at swap-creation time. Setting the secret on a
/// running deployment that previously created swaps without one will
/// reject all in-flight swaps' webhook deliveries (Boltz retries 5×60s
/// then abandons). Mitigation: deploy this code with the secret unset
/// first, drain in-flight swaps (~24h max via reconciler / on-chain
/// timeouts), then flip the secret on.
pub async fn webhook_unauthenticated(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: String,
) -> Result<&'static str, AppError> {
    if !state.config.boltz_webhook_url_secret.is_empty() {
        let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
        let caller_ip = ip_whitelist::resolve_caller_ip(
            peer_opt.map(|ConnectInfo(addr)| addr.ip()),
            xff,
            state.config.rate_limit.trust_forwarded_for,
        );
        tracing::warn!(
            "boltz webhook: hit on unauthenticated path while secret is configured (caller={:?})",
            caller_ip,
        );
        return Err(AppError::AuthError(StatusCode::NOT_FOUND.to_string()));
    }
    tracing::warn!(
        "boltz webhook: BOLTZ_WEBHOOK_URL_SECRET unset — accepting unauthenticated payload (DEV ONLY)"
    );
    dispatch_webhook(state, peer_opt, headers, body).await
}

/// Shared post-auth webhook handler.
///
/// Returns `Ok("ok")` (200) for every payload we successfully decode and
/// route — including unknown swap IDs and unhandled statuses — so Boltz's
/// webhook caller treats the delivery as successful and stops retrying.
/// We only return errors for malformed payloads or DB failures, which
/// Boltz should retry.
async fn dispatch_webhook(
    state: AppState,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: String,
) -> Result<&'static str, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);

    // Per-source rate-limit gate. Survives even with a leaked URL secret.
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let caller_ip = ip_whitelist::resolve_caller_ip(
        peer.map(|p| p.ip()),
        xff,
        state.config.rate_limit.trust_forwarded_for,
    );
    if let Some(ip) = caller_ip {
        if !state.ip_whitelist.contains(ip) {
            state.rate_limiter.check_webhook_per_ip(ip).await?;
        }
    }

    tracing::debug!("boltz webhook raw: {}", body);

    let envelope: WebhookEnvelope = serde_json::from_str(&body).map_err(|e| {
        tracing::error!("failed to parse webhook: {e}");
        AppError::ClaimError(format!("invalid webhook payload: {e}"))
    })?;
    let data = envelope.data;

    // Idempotency. Boltz can re-deliver the same event.
    // event_id = "{swap_id}:{status}" is deterministic; first INSERT
    // wins, duplicates short-circuit to 200 with no work done.
    let event_id = format!("{}:{}", data.id, data.status);
    let is_first = db::try_record_webhook_event(&state.db, &event_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if !is_first {
        tracing::debug!("boltz webhook: duplicate event {event_id} — short-circuiting");
        return Ok("ok");
    }

    tracing::info!("boltz webhook: swap={} status={}", data.id, data.status);

    let Some(swap) = db::get_swap_by_boltz_id(&state.db, &data.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
    else {
        // Unknown swap_id is not an error condition for Boltz to retry —
        // either we never created the swap here, or the row was purged.
        // Returning 200 stops the (5×60s) retry storm. PR #4 hardens
        // every other branch with the same posture.
        tracing::warn!("boltz webhook for unknown swap: {}", data.id);
        return Ok("ok");
    };

    let status = swap.parsed_status().map_err(AppError::DbError)?;
    if status.is_terminal() {
        tracing::debug!("ignoring webhook for {} swap {}", swap.status, data.id);
        return Ok("ok");
    }

    match data.status.as_str() {
        "transaction.mempool" | "transaction.confirmed" => {
            let new_status = if data.status == "transaction.mempool" {
                SwapStatus::LockupMempool
            } else {
                SwapStatus::LockupConfirmed
            };
            db::update_swap_status(&state.db, swap.id, new_status, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;

            try_claim_with_retry(
                &state.db,
                &swap,
                &state.config.boltz.electrum_url,
                &state.config.boltz.api_url,
                state.config.claim.max_claim_attempts,
                state.utxo_backend.as_ref(),
            )
            .await;
        }
        "invoice.settled" => {
            // Preimage was disclosed and Boltz settled the LN HTLC. This
            // arrives downstream of our successful cooperative claim. We
            // don't transition status here — the claim path itself sets
            // `Claimed` with the on-chain txid.
            tracing::info!("invoice settled for swap {}", data.id);
        }
        "swap.expired" => {
            // `swap.expired` is the wall-clock hold-invoice timer (~50% of
            // swap timeout per Boltz docs). It does NOT mean the on-chain
            // HTLC is dead — the lockup output stays claimable until
            // `timeoutBlockHeight`. After this status, however, the
            // cooperative claim endpoint refuses (per `MusigSigner.ts`),
            // so the only path is script-path with the preimage.
            //
            // Action: set `cooperative_refused = TRUE` so the next sweep
            // tick takes the script path (PR #6 implements that branch).
            // Do NOT transition to a terminal state — that would abandon
            // potentially-claimable funds.
            tracing::warn!(
                event = "swap_expired_webhook",
                swap_id = %data.id,
                "swap.expired received; flipping cooperative_refused for script-path retry"
            );
            db::mark_cooperative_refused(&state.db, swap.id)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
        }
        "transaction.failed" => {
            // Boltz tried to lock up on-chain but failed (e.g. their fee
            // estimation was rejected). The user's LN HTLC auto-cancels
            // — they don't pay, we have nothing to claim. Terminal.
            tracing::info!(
                event = "swap_transaction_failed",
                swap_id = %data.id,
                "boltz lockup failed; LN HTLC will cancel back to sender"
            );
            db::update_swap_status(&state.db, swap.id, SwapStatus::Expired, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
        }
        "invoice.expired" => {
            // The user never paid the LN invoice within its TTL. Boltz
            // never funded a lockup. Terminal Expired (same shape as
            // `transaction.failed`).
            tracing::info!(
                event = "swap_invoice_expired",
                swap_id = %data.id,
                "invoice expired before payment"
            );
            db::update_swap_status(&state.db, swap.id, SwapStatus::Expired, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
        }
        "transaction.refunded" => {
            // Boltz refunded its own lockup before we claimed it. The
            // user paid the LN invoice and is not made whole — this is
            // the fund-loss terminal state. P0 alert.
            //
            // Currently this status is not in our webhook subscription
            // filter (boltz.rs around line 65), so it arrives only via
            // the reconciler in PR #7. The handler is wired here so the
            // moment PR #10 adds the filter, the path works.
            tracing::error!(
                event = "swap_lockup_refunded",
                swap_id = %data.id,
                nym = %swap.nym,
                amount_sat = swap.amount_sat,
                "FUND LOSS: boltz refunded lockup; user paid LN side, no on-chain claim"
            );
            db::update_swap_status(&state.db, swap.id, SwapStatus::LockupRefunded, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
        }
        _ => {
            // Other Boltz statuses (`swap.created`, `minerfee.paid`, etc.)
            // are informational; we don't act on them. Logged at debug
            // so a new status appearing in the wild is visible in -v
            // logs without spamming production at info level.
            tracing::debug!("ignoring webhook status: {}", data.status);
        }
    }

    Ok("ok")
}

/// Outcome of a single `claim_swap` invocation.
#[derive(Debug, Clone, Copy)]
pub enum ClaimOutcome {
    /// Constructed (or re-broadcast) a claim tx and Electrum accepted it
    /// (or reported it was already in the utxo set — same outcome from
    /// our perspective).
    Broadcast,
    /// Another process holds the per-swap advisory lock; the next sweep
    /// tick (or webhook delivery) will try again.
    SkippedLockHeld,
    /// Row reached a terminal state (`Claimed`, `Expired`, `ClaimStuck`,
    /// `LockupRefunded`) — nothing to do.
    AlreadyTerminal,
}

/// Webhook-path single-shot claim attempt. Errors are recorded by
/// `claim_swap` itself (which calls `db::record_claim_failure` to
/// schedule the next retry on the documented backoff). The background
/// sweep is the retry mechanism — the webhook handler does not loop.
///
/// The previous implementation looped 3 times with 2s delays inside the
/// webhook handler. That blocked the response to Boltz for up to ~10
/// seconds (Boltz's webhook timeout is 15s) and overlapped poorly with
/// the background sweep's 30s tick — every webhook produced 4 claim
/// attempts before the sweep even started.
async fn try_claim_with_retry(
    pool: &sqlx::PgPool,
    swap: &db::SwapRecord,
    electrum_url: &str,
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
) {
    match claim_swap(
        pool,
        swap.id,
        electrum_url,
        boltz_url,
        max_claim_attempts,
        utxo_backend,
    )
    .await
    {
        Ok(ClaimOutcome::Broadcast) => {}
        Ok(ClaimOutcome::AlreadyTerminal) => {}
        Ok(ClaimOutcome::SkippedLockHeld) => {
            tracing::debug!(
                "webhook claim skipped (lock held) for swap {}",
                swap.boltz_swap_id
            );
        }
        Err(e) => {
            tracing::warn!(
                "webhook claim attempt failed for swap {}: {e}",
                swap.boltz_swap_id
            );
        }
    }
}

/// Returns the claim destination for this swap, allocating one from the
/// receiver's CT descriptor if it has not been set yet. Serialized on the
/// `swap_records` row via `SELECT ... FOR UPDATE`, so concurrent webhook
/// deliveries (e.g. transaction.mempool followed by transaction.confirmed)
/// cannot double-allocate.
async fn resolve_claim_address(
    pool: &sqlx::PgPool,
    swap: &db::SwapRecord,
) -> Result<String, AppError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    let row: Option<(Option<String>, Option<i32>)> = sqlx::query_as(
        "SELECT address, address_index FROM swap_records WHERE id = $1 FOR UPDATE",
    )
    .bind(swap.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    if let Some((Some(addr), Some(_))) = &row {
        tx.commit()
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        return Ok(addr.clone());
    }

    let user = db::get_user_by_nym(pool, &swap.nym)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("user not found: {}", swap.nym)))?;

    // The `is_active = TRUE` filter from the original implementation is
    // intentionally dropped here. Funds locked up against a swap we
    // created belong to the receiver regardless of their current
    // activation status — a user who deactivated between swap creation
    // and HTLC funding still gets their claim. `purge_user` already
    // refuses to run while in-flight swaps exist (see db.rs:359), and
    // it sets `ct_descriptor = ''` which would surface as a derive
    // failure here, so a purged-row corner case fails loudly rather
    // than silently strands.
    let addr_index_row: Option<(i32,)> = sqlx::query_as(
        "UPDATE users SET next_addr_idx = next_addr_idx + 1 \
         WHERE nym = $1 \
         RETURNING next_addr_idx - 1",
    )
    .bind(&swap.nym)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    let addr_index = addr_index_row
        .map(|(idx,)| idx)
        .ok_or_else(|| AppError::ClaimError(format!("address allocation failed: {}", swap.nym)))?;

    let addr_index_u32 = u32::try_from(addr_index)
        .map_err(|_| AppError::ClaimError("address index overflow".to_string()))?;
    let derived = descriptor::derive_address(&user.ct_descriptor, addr_index_u32)?;

    sqlx::query(
        "UPDATE swap_records SET address = $2, address_index = $3 WHERE id = $1",
    )
    .bind(swap.id)
    .bind(&derived)
    .bind(addr_index)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    tracing::info!(
        event = "lightning_swap_address_allocated_at_claim",
        nym = %swap.nym,
        swap_id = %swap.id,
        address_index = addr_index,
        "claim-time descriptor allocation"
    );

    Ok(derived)
}

/// Single-flight, idempotent claim.
///
/// `construct_claim` is non-deterministic on Liquid — random MuSig2
/// session nonces (`liquid.rs:703-714`) plus random asset/value
/// blinding factors (`liquid.rs:833`) yield a different valid-but-
/// conflicting tx every call. The previous implementation called
/// `construct_claim` from scratch on every retry; if a previous
/// broadcast had landed but our response was lost, the next attempt
/// produced a different tx that Electrum rejected as a double-spend
/// and we marked the row `claim_failed` even though the swap had
/// actually succeeded.
///
/// This version persists the constructed tx hex into `swap_records`
/// BEFORE the first broadcast, so subsequent attempts re-broadcast
/// the SAME tx instead of constructing a new one. Re-broadcasting
/// is idempotent at the Electrum boundary: `try_broadcast_tx`
/// (boltz-rust `wrappers.rs:199-212`) treats `"already in block
/// chain"` and `"already in utxo set"` as success.
///
/// The shape:
///
///   1. Open a transaction; try to acquire `pg_try_advisory_xact_lock`
///      keyed on `claim:<swap_id>`. Concurrent attempts return
///      `SkippedLockHeld` and try on the next tick.
///   2. Reload the row inside the lock. If terminal, return
///      `AlreadyTerminal`.
///   3. Resolve the claim destination address (allocates a fresh
///      descriptor index if none was set at swap creation).
///   4. If `claim_tx_hex` is set, deserialize it. Otherwise
///      `construct_claim` and persist `(claim_tx_hex, claim_txid,
///      claim_path)` in the same transaction. Mark status `claiming`.
///   5. Commit (releases the advisory lock).
///   6. Broadcast the tx OUTSIDE the lock — broadcast is the slow,
///      I/O-bound step and we don't want to hold a DB connection.
///      Idempotent on Electrum.
///   7. Mark status `claimed` with the on-chain txid.
async fn claim_swap(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    electrum_url: &str,
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
) -> Result<ClaimOutcome, AppError> {
    // Outer wrapper: records every Err uniformly via
    // `db::record_claim_failure`. SkippedLockHeld and AlreadyTerminal
    // are Ok variants and do NOT count as failures (no attempt was
    // really made).
    let result = claim_swap_inner(pool, swap_id, electrum_url, boltz_url, utxo_backend).await;
    if let Err(ref e) = result {
        let err_str = e.to_string();
        match db::record_claim_failure(pool, swap_id, &err_str, max_claim_attempts).await {
            Ok(db::ClaimFailureOutcome::Stuck) => {
                tracing::error!(
                    event = "swap_claim_stuck",
                    swap_id = %swap_id,
                    attempts = max_claim_attempts,
                    last_error = %err_str,
                    "swap reached max_claim_attempts; transitioned to claim_stuck"
                );
            }
            Ok(db::ClaimFailureOutcome::Scheduled) => {
                tracing::warn!(
                    event = "swap_claim_failure_scheduled",
                    swap_id = %swap_id,
                    last_error = %err_str,
                    "claim failed; scheduled for retry"
                );
            }
            Ok(db::ClaimFailureOutcome::NoOp) => {
                tracing::debug!(
                    "claim failure for {} arrived after row reached terminal state",
                    swap_id
                );
            }
            Err(db_err) => {
                tracing::error!(
                    "failed to record claim failure for swap {}: {db_err}",
                    swap_id
                );
            }
        }
    }
    result
}

async fn claim_swap_inner(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    electrum_url: &str,
    boltz_url: &str,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
) -> Result<ClaimOutcome, AppError> {
    // ----- Phase 1: acquire single-flight, prepare the claim tx.
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    // Advisory locks live on `pg_try_advisory_xact_lock` for the duration
    // of the transaction. `claim:<uuid>` lives in a disjoint string space
    // from the existing `register:` / `donation:` / raw-npub-hex usages
    // (db.rs:201, 1088), so no AB/BA deadlock is possible with those.
    let lock_key = format!("claim:{swap_id}");
    let got_lock: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)",
    )
    .bind(&lock_key)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;
    if !got_lock {
        tracing::debug!("claim_swap: lock held for {swap_id}, skipping");
        return Ok(ClaimOutcome::SkippedLockHeld);
    }

    let swap = db::get_swap_by_id(&mut *tx, swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("swap not found: {swap_id}")))?;

    let status = swap.parsed_status().map_err(AppError::DbError)?;
    if status.is_terminal() {
        tracing::debug!("claim_swap: {} already terminal ({})", swap_id, swap.status);
        return Ok(ClaimOutcome::AlreadyTerminal);
    }

    // resolve_claim_address opens its own short-lived tx with a row-level
    // FOR UPDATE on the swap row. That's fine: we hold an advisory lock
    // (in-memory, no row-level conflict) so its tx goes through cleanly.
    // PR #4 (state-machine hardening) will inline this into the outer tx.
    let output_address = resolve_claim_address(pool, &swap).await?;

    let chain = Chain::Liquid(LiquidChain::Liquid);
    let claim_tx = if let Some(hex) = swap.claim_tx_hex.as_deref() {
        // Idempotent path: a previous attempt persisted the constructed
        // tx but failed somewhere between persistence and "Claimed"
        // status. Re-broadcast THAT tx, not a fresh one.
        BtcLikeTransaction::from_hex(chain, hex).map_err(|e| {
            AppError::ClaimError(format!("decode persisted claim_tx: {e}"))
        })?
    } else {
        // Choose the claim path. `cooperative_refused` is set by either:
        //   - the webhook handler on `swap.expired` (PR #4), OR
        //   - this function on a previous attempt where Boltz returned
        //     a known cooperative-refusal error (below).
        // Once it flips, the row stays on script-path forever — no
        // ping-pong. `cooperative_refused` is a one-way flag.
        let use_cooperative = !swap.cooperative_refused;
        let constructed = match construct_claim_tx(
            &swap,
            &output_address,
            electrum_url,
            boltz_url,
            use_cooperative,
        )
        .await
        {
            Ok(tx) => tx,
            Err(e) if use_cooperative && is_cooperative_refusal(&e) => {
                // Boltz refused cooperative MuSig2 (status mismatch,
                // bad preimage, or operator-disabled). Flip the flag
                // so the next sweep tick takes the script path; this
                // attempt aborts (we'll already have committed nothing
                // since we're inside the construction tx).
                tracing::warn!(
                    event = "swap_cooperative_refused_runtime",
                    swap_id = %swap.boltz_swap_id,
                    error = %e,
                    "boltz refused cooperative claim; flipping cooperative_refused for next attempt"
                );
                // mark_cooperative_refused opens its own short tx and is
                // idempotent — safe to call from inside our locked tx
                // (different connection; advisory lock doesn't conflict).
                let _ = db::mark_cooperative_refused(pool, swap.id).await;
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        let hex = serialize_claim_tx_hex(&constructed)?;
        let txid = btc_like_txid(&constructed);
        let claim_path = if use_cooperative { "cooperative" } else { "script" };
        // `WHERE claim_tx_hex IS NULL` makes this a no-op if a concurrent
        // attempt persisted first (defensive — the advisory lock should
        // have prevented this; the guard is there to fail closed).
        sqlx::query(
            "UPDATE swap_records \
             SET claim_tx_hex = $2, claim_txid = $3, claim_path = $4 \
             WHERE id = $1 AND claim_tx_hex IS NULL",
        )
        .bind(swap.id)
        .bind(&hex)
        .bind(&txid)
        .bind(claim_path)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
        constructed
    };

    // Status → Claiming. Forward-only guard prevents regression from
    // any terminal state. PR #4 generalizes this to a CAS helper.
    sqlx::query(
        "UPDATE swap_records \
         SET status = 'claiming', updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
    )
    .bind(swap.id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    // ----- Phase 2: broadcast outside the lock.
    //
    // Broadcast is pure I/O against Electrum and may take seconds. We
    // hold no DB connection or lock during the call. If the process
    // dies between here and Phase 3, the next sweep tick re-acquires
    // the advisory lock, sees `claim_tx_hex` is set, and re-broadcasts
    // THIS exact tx (idempotent).
    let liquid_client =
        ElectrumLiquidClient::new(LiquidChain::Liquid, electrum_url, true, true, 30)
            .map_err(|e| AppError::ClaimError(format!("electrum connection failed: {e}")))?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);

    let txid = btc_like_txid(&claim_tx);

    if let Err(broadcast_err) = chain_client.try_broadcast_tx(&claim_tx).await {
        // `try_broadcast_tx` only swallows `"already in block chain"` /
        // `"already in utxo set"` (boltz-rust wrappers.rs:199-212). Other
        // mempool-acceptance phrasings vary by node implementation
        // (`"txn-already-known"`, `"transaction already in block chain"`,
        // timeouts after a successful write, etc.) and bubble as Err.
        //
        // Probe the multi-URL utxo backend for the txid before we
        // declare failure — if the tx is on the network, the broadcast
        // was effectively successful and we should mark Claimed instead
        // of feeding the failure to the backoff schedule.
        if let Some(backend) = utxo_backend {
            match backend.tx_exists(&txid).await {
                Ok(true) => {
                    tracing::info!(
                        event = "claim_broadcast_probe_recovered",
                        swap_id = %swap.boltz_swap_id,
                        txid = %txid,
                        broadcast_error = %broadcast_err,
                        "broadcast errored but tx is on chain; treating as success"
                    );
                    // fall through to Phase 3
                }
                Ok(false) => {
                    return Err(AppError::ClaimError(format!(
                        "broadcast failed: {broadcast_err}"
                    )));
                }
                Err(probe_err) => {
                    // Probe itself failed (Electrum hiccup). Conservatively
                    // assume the tx isn't on chain and propagate the
                    // original broadcast error so the wrapper records a
                    // failure and we retry on backoff. Log the probe error
                    // for diagnosis.
                    tracing::warn!(
                        "tx_exists probe failed for {}: {probe_err}; \
                         treating broadcast as failed",
                        swap.boltz_swap_id
                    );
                    return Err(AppError::ClaimError(format!(
                        "broadcast failed: {broadcast_err}"
                    )));
                }
            }
        } else {
            // No utxo backend configured (dev/test). Honor the broadcast
            // error verbatim.
            return Err(AppError::ClaimError(format!(
                "broadcast failed: {broadcast_err}"
            )));
        }
    }

    tracing::info!("swap {} claimed: txid={}", swap.boltz_swap_id, txid);

    // ----- Phase 3: mark Claimed + clear retry bookkeeping.
    db::update_swap_status(pool, swap.id, SwapStatus::Claimed, Some(&txid))
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if let Err(e) = db::clear_claim_failure_state(pool, swap.id).await {
        // Non-fatal: row is Claimed; stale last-error fields are an
        // observability nuisance only.
        tracing::warn!("clear_claim_failure_state for {}: {e}", swap.boltz_swap_id);
    }

    Ok(ClaimOutcome::Broadcast)
}

/// Build a claim tx for a freshly-funded reverse swap.
///
/// `cooperative` selects the spending path:
///
///   - `true`: MuSig2 keypath — fastest, smallest tx (~107 vB on Liquid),
///     requires Boltz to cosign via `POST /swap/reverse/{id}/claim`.
///     Default for swaps in good standing.
///   - `false`: script-path with preimage reveal — ~85 vB larger
///     (~9 sats more on Liquid), works without Boltz, and is the only
///     option once `swap.expired` has fired (Boltz refuses cooperative
///     post-expiry per `MusigSigner.ts`).
///
/// Pure I/O — called under the per-swap advisory lock so at most one
/// `construct_claim` runs per swap at a time, regardless of webhook /
/// sweep / reconciler concurrency.
async fn construct_claim_tx(
    swap: &db::SwapRecord,
    output_address: &str,
    electrum_url: &str,
    boltz_url: &str,
    cooperative: bool,
) -> Result<BtcLikeTransaction, AppError> {
    let preimage_hex = swap
        .preimage_hex
        .as_deref()
        .ok_or_else(|| AppError::ClaimError("missing preimage".to_string()))?;
    let claim_key_hex = swap
        .claim_key_hex
        .as_deref()
        .ok_or_else(|| AppError::ClaimError("missing claim key".to_string()))?;
    let response_json = swap
        .boltz_response_json
        .as_deref()
        .ok_or_else(|| AppError::ClaimError("missing boltz response".to_string()))?;

    let preimage_bytes = hex::decode(preimage_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid preimage hex: {e}")))?;
    let preimage = Preimage::from_vec(preimage_bytes)
        .map_err(|e| AppError::ClaimError(format!("invalid preimage: {e}")))?;

    let key_bytes = hex::decode(claim_key_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid claim key hex: {e}")))?;
    let secp = boltz_client::Secp256k1::new();
    let secret_key = boltz_client::bitcoin::secp256k1::SecretKey::from_slice(&key_bytes)
        .map_err(|e| AppError::ClaimError(format!("invalid secret key: {e}")))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    let boltz_response: CreateReverseResponse = serde_json::from_str(response_json)
        .map_err(|e| AppError::ClaimError(format!("invalid boltz response json: {e}")))?;

    let claim_public_key = boltz_client::PublicKey::new(keypair.public_key());
    let chain = Chain::Liquid(LiquidChain::Liquid);
    let swap_script = SwapScript::reverse_from_swap_resp(chain, &boltz_response, claim_public_key)
        .map_err(|e| AppError::ClaimError(format!("swap script build failed: {e}")))?;

    // New connection per construct call — ElectrumLiquidClient wraps a
    // TCP socket and isn't Send+Sync, so it can't be shared across tasks.
    // PR #8 swaps this for the resilient multi-URL utxo::ElectrumClient.
    let liquid_client =
        ElectrumLiquidClient::new(LiquidChain::Liquid, electrum_url, true, true, 30)
            .map_err(|e| AppError::ClaimError(format!("electrum connection failed: {e}")))?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);
    let boltz_api = BoltzApiClientV2::new(boltz_url.to_string(), None);

    let params = SwapTransactionParams {
        keys: keypair,
        output_address: output_address.to_string(),
        fee: Fee::Relative(0.1),
        swap_id: swap.boltz_swap_id.clone(),
        chain_client: &chain_client,
        boltz_client: &boltz_api,
        options: Some(TransactionOptions::default().with_cooperative(cooperative)),
    };

    swap_script
        .construct_claim(&preimage, params)
        .await
        .map_err(|e| AppError::ClaimError(format!("construct_claim failed: {e}")))
}

/// Heuristic classifier for cooperative-claim refusals from Boltz.
///
/// `boltz-rust`'s `get_reverse_partial_sig` surfaces an HTTP 4xx as
/// `Error::Serde` (the response body isn't a `PartialSig`, so JSON
/// parse fails). The status code is not preserved on the wire — we
/// have to inspect the message body for known refusal phrases.
///
/// Per the plan's risk register: misclassification toward "transient"
/// is safer than toward "refused". Premature cooperative abandonment
/// costs an extra ~9 sats of fee on a recoverable swap; the reverse
/// silently disables the optimal claim path. Only the substrings below
/// are treated as definite refusal; everything else falls through to
/// the wrapper's normal retry-with-backoff handling.
fn is_cooperative_refusal(err: &AppError) -> bool {
    let s = err.to_string().to_lowercase();
    // Phrasing taken from `boltz-backend` `lib/service/cooperative/MusigSigner.ts`
    // and the public Boltz API errors documented at
    // https://api.docs.boltz.exchange/. Update this list if Boltz's
    // error wording shifts — symptom would be cooperative attempts
    // looping at backoff cap until ClaimStuck.
    s.contains("swap expired")
        || s.contains("invalid preimage")
        || s.contains("cooperative claim disabled")
        || s.contains("cooperative signing disabled")
        || s.contains("not eligible for cooperative")
}

/// Hex-encode a fully-signed claim tx for storage in
/// `swap_records.claim_tx_hex`. Mirrors the deserialize path in
/// `BtcLikeTransaction::from_hex` so a round-trip is well-defined for
/// both Liquid (elements consensus) and Bitcoin (consensus crate).
fn serialize_claim_tx_hex(tx: &BtcLikeTransaction) -> Result<String, AppError> {
    Ok(match tx {
        BtcLikeTransaction::Liquid(t) => {
            hex::encode(boltz_client::elements::encode::serialize(t))
        }
        BtcLikeTransaction::Bitcoin(t) => {
            hex::encode(boltz_client::bitcoin::consensus::serialize(t))
        }
    })
}

fn btc_like_txid(tx: &BtcLikeTransaction) -> String {
    match tx {
        BtcLikeTransaction::Liquid(t) => t.txid().to_string(),
        BtcLikeTransaction::Bitcoin(t) => t.compute_txid().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_secret_matches_current() {
        assert!(url_secret_matches_pair("s3cr3t-current", "s3cr3t-current", ""));
    }

    #[test]
    fn url_secret_matches_previous_during_overlap() {
        assert!(url_secret_matches_pair(
            "s3cr3t-previous",
            "s3cr3t-current",
            "s3cr3t-previous"
        ));
        assert!(url_secret_matches_pair(
            "s3cr3t-current",
            "s3cr3t-current",
            "s3cr3t-previous"
        ));
    }

    #[test]
    fn url_secret_rejects_wrong() {
        assert!(!url_secret_matches_pair("nope", "s3cr3t-current", "s3cr3t-previous"));
        assert!(!url_secret_matches_pair("", "s3cr3t-current", "s3cr3t-previous"));
    }

    /// Empty configured secrets must never validate — even against an
    /// empty presented secret. Otherwise a misconfigured deploy would
    /// silently accept any presented value.
    #[test]
    fn url_secret_rejects_empty_when_unconfigured() {
        assert!(!url_secret_matches_pair("", "", ""));
        assert!(!url_secret_matches_pair("anything", "", ""));
    }

    #[test]
    fn url_secret_rejects_length_mismatch() {
        assert!(!url_secret_matches_pair("0123456789abcde", "0123456789abcdef", ""));
        assert!(!url_secret_matches_pair("0123456789abcdef0", "0123456789abcdef", ""));
    }

    #[test]
    fn cooperative_refusal_recognises_known_phrases() {
        for phrase in [
            "construct_claim failed: serde error: swap expired at line 1",
            "construct_claim failed: invalid preimage",
            "construct_claim failed: cooperative claim disabled",
            "construct_claim failed: cooperative signing disabled",
            "construct_claim failed: not eligible for cooperative",
            // case-insensitive
            "construct_claim failed: SWAP EXPIRED",
        ] {
            let e = AppError::ClaimError(phrase.to_string());
            assert!(
                is_cooperative_refusal(&e),
                "expected refusal classification for: {phrase}"
            );
        }
    }

    #[test]
    fn cooperative_refusal_rejects_unrelated_errors() {
        for phrase in [
            "broadcast failed: connection reset",
            "construct_claim failed: timeout",
            "construct_claim failed: 502 bad gateway",
            "swap script build failed: ...",
            "electrum connection failed: ...",
        ] {
            let e = AppError::ClaimError(phrase.to_string());
            assert!(
                !is_cooperative_refusal(&e),
                "did not expect refusal classification for: {phrase}"
            );
        }
    }
}

pub fn spawn_background_claimer(
    pool: sqlx::PgPool,
    config: Arc<Config>,
    utxo_backend: Option<Arc<dyn UtxoBackend>>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut first_run = true;
        // Heartbeat counter. Log liveness every N ticks so "is the
        // background claimer running?" is a grep-able question, not a
        // process-tree archaeology one. At 30s/tick × 10 ticks, that's
        // every 5 minutes — same cadence as the rate-limit GC.
        const HEARTBEAT_EVERY_N_TICKS: u32 = 10;
        let mut tick_count: u32 = 0;
        loop {
            tick_count = tick_count.wrapping_add(1);
            let ready = match db::get_ready_to_claim_swaps(&pool).await {
                Ok(swaps) => swaps,
                Err(e) => {
                    tracing::error!("background claimer: db query failed: {e}");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(30)) => continue,
                    }
                }
            };

            if !ready.is_empty() {
                if first_run {
                    tracing::info!(
                        "background claimer: found {} unclaimed swaps on startup",
                        ready.len()
                    );
                }
                for swap in &ready {
                    match claim_swap(
                        &pool,
                        swap.id,
                        &config.boltz.electrum_url,
                        &config.boltz.api_url,
                        config.claim.max_claim_attempts,
                        utxo_backend.as_ref(),
                    )
                    .await
                    {
                        Ok(ClaimOutcome::Broadcast) => {
                            tracing::info!(
                                "background claimer: claimed swap {}",
                                swap.boltz_swap_id
                            );
                        }
                        Ok(ClaimOutcome::SkippedLockHeld) => {
                            tracing::debug!(
                                "background claimer: skipped {} (lock held)",
                                swap.boltz_swap_id
                            );
                        }
                        Ok(ClaimOutcome::AlreadyTerminal) => {
                            tracing::debug!(
                                "background claimer: skipped {} (already terminal)",
                                swap.boltz_swap_id
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "background claimer: swap {}: {e}",
                                swap.boltz_swap_id
                            );
                        }
                    }
                }
            } else if first_run {
                tracing::info!("background claimer: no unclaimed swaps found");
            }

            if tick_count % HEARTBEAT_EVERY_N_TICKS == 0 {
                tracing::info!(
                    target: "claimer",
                    event = "claimer_heartbeat",
                    tick = tick_count,
                    ready_count = ready.len(),
                    "background claimer heartbeat"
                );
            }

            first_run = false;
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("background claimer: shutting down");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    });
}

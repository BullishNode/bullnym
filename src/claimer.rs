use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use lwk_wollet::elements;

use boltz_client::elements as boltz_elements;
use boltz_client::network::electrum::ElectrumLiquidClient;
use boltz_client::network::esplora::EsploraBitcoinClient;
use boltz_client::network::{BitcoinChain, Chain, LiquidChain, LiquidClient};
use boltz_client::swaps::boltz::{
    BoltzApiClientV2, CreateChainResponse, CreateReverseResponse, Side,
};
use boltz_client::swaps::{
    BtcLikeTransaction, ChainClient, SwapScript, SwapTransactionParams, TransactionOptions,
};
use boltz_client::util::fees::Fee;
use boltz_client::util::secrets::Preimage;
use boltz_client::Keypair;

use crate::config::Config;
use crate::db::{self, ChainSwapStatus, SwapStatus};
use crate::descriptor;
use crate::error::AppError;
use crate::invoice;
use crate::ip_whitelist;
use crate::utxo::UtxoBackend;
use crate::AppState;

const CLAIM_SWEEP_INTERVAL_SECS: u64 = 10;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlSecretMatch {
    Current,
    Previous,
    None,
}

fn match_url_secret_pair(presented: &str, current: &str, previous: &str) -> UrlSecretMatch {
    fn ct_eq(a: &str, b: &str) -> bool {
        if b.is_empty() || a.len() != b.len() {
            return false;
        }
        a.as_bytes().ct_eq(b.as_bytes()).into()
    }
    if ct_eq(presented, current) {
        UrlSecretMatch::Current
    } else if ct_eq(presented, previous) {
        UrlSecretMatch::Previous
    } else {
        UrlSecretMatch::None
    }
}

#[cfg(test)]
fn url_secret_matches_pair(presented: &str, current: &str, previous: &str) -> bool {
    match_url_secret_pair(presented, current, previous) != UrlSecretMatch::None
}

fn match_webhook_url_secret(presented: &str, config: &Config) -> UrlSecretMatch {
    match_url_secret_pair(
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
) -> Result<Response, AppError> {
    match match_webhook_url_secret(&secret, &state.config) {
        UrlSecretMatch::Current => {
            tracing::debug!("boltz webhook: URL secret matched current secret");
        }
        UrlSecretMatch::Previous => {
            tracing::warn!("boltz webhook: URL secret matched previous rotation secret");
        }
        UrlSecretMatch::None => {
            // Same shape as a route miss — don't leak whether the path
            // existed but the secret was wrong vs. the route doesn't exist.
            // Webhook-bomb rate-limit is still applied below.
            let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
            let caller_ip = ip_whitelist::resolve_caller_ip(
                peer_opt.map(|ConnectInfo(addr)| addr.ip()),
                xff,
                state.config.rate_limit.trust_forwarded_for,
            );
            tracing::warn!("boltz webhook: URL secret mismatch from {:?}", caller_ip);
            return Ok((StatusCode::NOT_FOUND, "").into_response());
        }
    }
    dispatch_webhook(state, peer_opt, headers, body)
        .await
        .map(IntoResponse::into_response)
}

/// Compatibility webhook entrypoint: `/webhook/boltz`.
/// See docs/reference/compatibility.md for removal policy.
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
) -> Result<Response, AppError> {
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
        return Ok((StatusCode::NOT_FOUND, "").into_response());
    }
    tracing::warn!(
        "boltz webhook: BOLTZ_WEBHOOK_URL_SECRET unset — accepting unauthenticated payload (DEV ONLY)"
    );
    dispatch_webhook(state, peer_opt, headers, body)
        .await
        .map(IntoResponse::into_response)
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
        if let Some(chain_swap) = db::get_chain_swap_by_boltz_id(&state.db, &data.id)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?
        {
            handle_chain_swap_webhook(&state, &chain_swap, &data.status).await?;
            return Ok("ok");
        }

        // Unknown swap_id is not an error condition for Boltz to retry —
        // either we never created the swap here, or the row was purged.
        // Returning 200 stops the Boltz retry storm.
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
            let is_mempool = data.status == "transaction.mempool";
            let new_status = if is_mempool {
                SwapStatus::LockupMempool
            } else {
                SwapStatus::LockupConfirmed
            };
            db::update_swap_status(&state.db, swap.id, new_status, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;

            // Lockup sightings are only payment evidence. They may show
            // the public page as "payment detected", but accounting is
            // recorded only after our claim succeeds below.
            invoice::flip_invoice_on_lightning_in_progress(
                &state.db,
                swap.invoice_id,
                &swap.boltz_swap_id,
            )
            .await;

            try_claim_with_retry(
                &state.db,
                &swap,
                &state.config.claim_liquid_electrum_urls(),
                &state.config.boltz.api_url,
                state.config.claim.max_claim_attempts,
                state.utxo_backend.as_ref(),
                db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
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
            // tick takes the script path.
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
            // This status should be rare; if it arrives, preserve a loud
            // terminal signal for operator rescue.
            tracing::error!(
                event = "swap_lockup_refunded",
                swap_id = %data.id,
                nym = %swap.nym.as_deref().unwrap_or("<invoice-only>"),
                amount_sat = swap.amount_sat,
                "FUND LOSS: boltz refunded lockup; user paid LN side, no on-chain claim"
            );
            db::update_swap_status(&state.db, swap.id, SwapStatus::LockupRefunded, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
            db::mark_invoice_settlement_status(&state.db, swap.invoice_id, "refunded")
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;

            // Do not record an invoice payment event here. A refunded
            // lockup means the merchant-side claim did not settle.
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

/// Phase 3 refund waterfall — attempt to renegotiate a mis-funded chain swap
/// (Boltz `transaction.lockupFailed`) to the amount the payer actually locked,
/// via Boltz get_quote/accept_quote, so it settles automatically instead of
/// requiring a manual/self-claim refund.
///
/// Returns `Ok(true)` when the swap is (or was already) renegotiated / owned by
/// another concurrent waterfall step — the caller must NOT flag `refund_due`.
/// Returns `Ok(false)` when Boltz declines the quote (no longer renegotiable) or
/// the row was terminalized concurrently — the caller falls through to
/// `refund_due`. `Err` is a transport/DB failure; the caller also falls through
/// to `refund_due` (fund-safe).
///
/// Serialized against the claim / customer-self-claim (Phase 4) paths via the
/// shared `chain-claim:<id>` advisory lock, so a renegotiation cannot interleave
/// with a concurrent claim of the same swap.
async fn try_renegotiate_chain_swap(
    state: &AppState,
    swap: &db::ChainSwapRecord,
) -> Result<bool, AppError> {
    // Idempotency for a re-delivered `lockupFailed` webhook: the swap is already
    // renegotiated and settling — do nothing and do NOT re-refund.
    if swap.renegotiated_server_lock_amount_sat.is_some() {
        return Ok(true);
    }

    // Step 1: read-only quote (no lock). An error here means Boltz will not
    // renegotiate this swap (too close to expiry, refund sig exists, …).
    let quote_amount = match state.boltz.get_chain_swap_quote(&swap.boltz_swap_id).await {
        Ok(amount) => amount,
        Err(e) => {
            tracing::debug!(
                "chain swap {} get_quote declined: {}",
                swap.boltz_swap_id,
                e
            );
            return Ok(false);
        }
    };
    // A zero/absent or absurd (non-i64) quote is nonsensical — treat as not
    // renegotiable rather than accepting a settlement that credits the merchant
    // nothing (or wraps negative on the `as i64` cast).
    let quote_amount_i64 = match i64::try_from(quote_amount) {
        Ok(v) if v > 0 => v,
        _ => {
            tracing::warn!(
                event = "chain_swap_renegotiation_bad_quote",
                swap_id = %swap.boltz_swap_id,
                quote_amount,
                "boltz returned a zero/absurd renegotiation quote; treating as not renegotiable"
            );
            return Ok(false);
        }
    };

    // Steps 2-3 under the shared per-swap advisory lock so a concurrent claim
    // cannot interleave. accept_quote is a network call held inside the locked
    // transaction — acceptable for this rare failure path in exchange for strict
    // serialization. NOTE: a crash in the window between Boltz accepting the
    // quote and this transaction committing would leave the DB without the
    // renegotiated amount, so a later settle would credit the stale original
    // server-lock; reconciling the credited amount from Boltz `get_swap` at
    // settle time is a tracked robustness follow-up.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    let lock_key = format!("chain-claim:{}", swap.id);
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
    if !got_lock {
        // Another waterfall step (claim / self-claim / concurrent renegotiation)
        // owns this swap — let it decide the outcome; do not refund here.
        tracing::debug!(
            "renegotiate: lock held for {}, skipping",
            swap.boltz_swap_id
        );
        return Ok(true);
    }

    // Re-read under the advisory lock WITH a row lock (FOR UPDATE) so this
    // read-modify-write serializes against the lock-free `update_chain_swap_status`
    // webhook writers as well as the claim path. Bail if another path already
    // renegotiated, terminalized, or flagged the swap `refund_due` between the
    // quote and acquiring the lock.
    let current = db::get_chain_swap_by_id_for_update(&mut *tx, swap.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("chain swap not found: {}", swap.id)))?;
    if current.renegotiated_server_lock_amount_sat.is_some() {
        return Ok(true);
    }
    let current_status = current.parsed_status().map_err(AppError::DbError)?;
    if current_status.is_terminal() {
        return Ok(false);
    }
    if matches!(
        current_status,
        ChainSwapStatus::RefundDue | ChainSwapStatus::Refunding
    ) {
        // Already an operator-visible refund case (`refund_due`) or a customer
        // self-claim refund in flight (`refunding`). Do NOT resurrect it to a
        // live state or accept a quote against a swap whose BTC is being
        // refunded; leave the waterfall where it is.
        return Ok(true);
    }

    // Accept the quote, then persist — both inside the locked transaction. On an
    // accept failure we do NOT fall through to `refund_due`: the failure may be
    // an ambiguous transport error AFTER Boltz already accepted (it is now
    // settling), so flagging `refund_due` would corrupt the operator surface and
    // risk a double-refund. Leaving the swap live is fund-safe — it either
    // settles (crediting the amount reconciled at claim time) or, if Boltz truly
    // rejected, expires into the `swap.expired`+funded → `refund_due` backstop.
    if let Err(e) = state
        .boltz
        .accept_chain_swap_quote(&swap.boltz_swap_id, quote_amount)
        .await
    {
        tracing::warn!(
            event = "chain_swap_renegotiation_accept_failed",
            swap_id = %swap.boltz_swap_id,
            invoice_id = %swap.invoice_id,
            error = %e,
            "boltz accept_quote failed (ambiguous — Boltz may have accepted); leaving swap live for reconciler/expiry backstop, NOT flagging refund_due (operator P1)"
        );
        return Ok(true);
    }
    let rows = db::mark_chain_swap_renegotiated(&mut *tx, swap.id, quote_amount_i64)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    if rows == 1 {
        tracing::warn!(
            event = "chain_swap_renegotiated",
            swap_id = %swap.boltz_swap_id,
            invoice_id = %swap.invoice_id,
            original_server_lock_sat = swap.server_lock_amount_sat,
            renegotiated_server_lock_sat = quote_amount,
            "chain swap renegotiated to actual locked amount; settling normally (merchant credited the renegotiated amount, operator P2)"
        );
    } else {
        // accept_quote succeeded but the guarded UPDATE recorded 0 rows — the
        // renegotiated amount is NOT persisted (row was concurrently
        // terminalized/refund_due, or already renegotiated). Same money-safety
        // class as the crash window: a later settle could credit the stale
        // original. Loud so operators can reconcile against Boltz `get_swap`.
        tracing::error!(
            event = "chain_swap_renegotiation_accepted_not_recorded",
            swap_id = %swap.boltz_swap_id,
            invoice_id = %swap.invoice_id,
            renegotiated_server_lock_sat = quote_amount,
            "boltz accepted the renegotiation quote but no row was updated; reconcile credited amount against Boltz get_swap before trusting settlement (operator P1)"
        );
    }
    Ok(true)
}

pub(crate) async fn handle_chain_swap_webhook(
    state: &AppState,
    swap: &db::ChainSwapRecord,
    boltz_status: &str,
) -> Result<(), AppError> {
    let status = swap.parsed_status().map_err(AppError::DbError)?;
    if status.is_terminal() {
        tracing::debug!(
            "ignoring webhook for terminal chain swap {} ({})",
            swap.boltz_swap_id,
            swap.status
        );
        return Ok(());
    }

    if status == ChainSwapStatus::Refunding {
        // A customer self-claim refund is in flight (Phase 4). The refund
        // executor owns this row under the advisory lock; the webhook/reconciler
        // path must NOT touch it — regressing it to a lifecycle state or marking
        // refund_due mid-broadcast would break the double-payout guard (G12). A
        // `transaction.claimed` here is a genuine anomaly (Boltz settled a swap
        // we are refunding) — surface it loudly for operator investigation.
        if boltz_status == "transaction.claimed" {
            tracing::error!(
                event = "chain_swap_claimed_while_refunding",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                "boltz reports claimed while a refund is in flight — potential double payout, investigate immediately (operator P1)"
            );
        } else {
            tracing::debug!(
                "ignoring {} for refunding chain swap {}",
                boltz_status,
                swap.boltz_swap_id
            );
        }
        return Ok(());
    }

    if status == ChainSwapStatus::RefundDue {
        // Already flagged recoverable. Do NOT regress to a lifecycle state on a
        // late/duplicate webhook, and do NOT re-alert (the reconciler re-drives
        // this row every tick, so re-marking would spam the P1 event). The
        // refund waterfall (Phases 3/4) + the reconciler (with Boltz get_swap
        // truth) are what drain it. A `transaction.claimed` here means the swap
        // actually settled after being marked (rare race) — surface it
        // distinctly; Phase 4 must gate any refund on a Boltz not-claimed check
        // to avoid a double payout.
        if boltz_status == "transaction.claimed" {
            tracing::warn!(
                event = "chain_swap_refund_due_but_claimed",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                "chain swap is refund_due but Boltz now reports claimed; refund must be gated on Boltz not-claimed before broadcast (Phase 4)"
            );
        } else {
            tracing::debug!(
                "ignoring {} for refund_due chain swap {}",
                boltz_status,
                swap.boltz_swap_id
            );
        }
        return Ok(());
    }

    if boltz_status == "transaction.claimed" {
        tracing::info!(
            event = "chain_swap_boltz_claimed_observed",
            swap_id = %swap.boltz_swap_id,
            local_status = %swap.status,
            "boltz reports chain swap claimed; local claim path remains authoritative for invoice accounting"
        );
        try_claim_chain_swap_with_retry(
            &state.db,
            swap,
            &state.config.claim_liquid_electrum_urls(),
            &state.config.boltz.api_url,
            state.config.claim.max_claim_attempts,
            state.utxo_backend.as_ref(),
            db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
        )
        .await;
        return Ok(());
    }

    if boltz_status == "swap.expired" {
        if matches!(
            status,
            ChainSwapStatus::UserLockMempool | ChainSwapStatus::UserLockConfirmed
        ) {
            // The payer funded the BTC lockup but the swap expired before a
            // server lockup ever existed (e.g. Boltz outage / lockup confirmed
            // too late without a lockupFailed event). Nothing is claimable, but
            // the payer's BTC is recoverable — route to refund_due instead of
            // leaving a silently-stranded, alert-less zombie. Interim funded
            // check is the local user_lock_* status (fund-safe direction; a
            // precise Boltz get_chain_txs check is the tracked refinement).
            tracing::warn!(
                event = "chain_swap_refund_due",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                nym = ?swap.nym,
                amount_sat = swap.user_lock_amount_sat,
                lockup_address = %swap.lockup_address,
                boltz_status,
                "chain swap expired with a funded user lockup and no server lockup; marking refund_due (BTC recoverable, operator P1)"
            );
            db::mark_chain_swap_refund_due(&state.db, swap.id)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
            return Ok(());
        }

        // Server lockup exists (or claim in progress): still claimable until
        // timeoutBlockHeight, but Boltz now refuses the cooperative claim. Flip
        // to the script path and keep the row sweepable — do NOT terminalize
        // (that abandons claimable funds). Mirrors the reverse-swap
        // `swap.expired` arm in dispatch_webhook.
        tracing::warn!(
            event = "chain_swap_expired_webhook",
            swap_id = %swap.boltz_swap_id,
            local_status = %swap.status,
            "chain swap.expired received; flipping cooperative_refused for script-path claim"
        );
        db::mark_chain_swap_cooperative_refused(&state.db, swap.id)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        // Nudge the claimer: if the server lockup is already confirmed/claiming
        // the script-path claim runs now; otherwise the sweep / reconciler
        // picks it up once the lockup appears.
        try_claim_chain_swap_with_retry(
            &state.db,
            swap,
            &state.config.claim_liquid_electrum_urls(),
            &state.config.boltz.api_url,
            state.config.claim.max_claim_attempts,
            state.utxo_backend.as_ref(),
            db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
        )
        .await;
        return Ok(());
    }

    if boltz_status == "transaction.lockupFailed" {
        // Phase 3 refund waterfall — step 1: `transaction.lockupFailed` means
        // the payer under- or over-paid the BTC lockup. Before flagging the
        // funds `refund_due` (a manual/self-claim recovery), try to renegotiate
        // the swap to the amount actually locked (Boltz get_quote/accept_quote)
        // so it still settles automatically and the merchant is credited the
        // renegotiated amount. If Boltz declines (no longer renegotiable — too
        // close to expiry, or a refund signature already exists) or the attempt
        // errors, we fall through to the `refund_due` marking below (fund-safe).
        match try_renegotiate_chain_swap(state, swap).await {
            Ok(true) => return Ok(()),
            Ok(false) => {
                tracing::info!(
                    event = "chain_swap_renegotiation_declined",
                    swap_id = %swap.boltz_swap_id,
                    invoice_id = %swap.invoice_id,
                    "chain swap not renegotiable; falling through to refund_due"
                );
            }
            Err(e) => {
                tracing::warn!(
                    event = "chain_swap_renegotiation_error",
                    swap_id = %swap.boltz_swap_id,
                    invoice_id = %swap.invoice_id,
                    error = %e,
                    "chain swap renegotiation attempt errored; falling through to refund_due"
                );
            }
        }
    }

    if matches!(
        boltz_status,
        "transaction.lockupFailed" | "transaction.failed" | "transaction.refunded"
    ) {
        // Funded lockup on a failed/refunded chain swap → the payer's BTC is
        // recoverable, so route to `refund_due` (non-terminal) instead of
        // terminalizing and stranding it. `transaction.lockupFailed` is funded
        // by definition (amount mismatch); `transaction.refunded` means Boltz
        // refunded its OWN server lockup — the payer's BTC is still locked and
        // refundable by us (previously mis-terminalized as done). A precise
        // funded/unfunded split via Boltz `get_chain_txs` is a tracked
        // refinement to keep genuinely-unfunded swaps out of the list; erring
        // toward `refund_due` here is the fund-safe direction. The refund
        // waterfall (renegotiation / customer self-claim) drains this state.
        tracing::warn!(
            event = "chain_swap_refund_due",
            swap_id = %swap.boltz_swap_id,
            invoice_id = %swap.invoice_id,
            nym = ?swap.nym,
            amount_sat = swap.user_lock_amount_sat,
            lockup_address = %swap.lockup_address,
            boltz_status,
            "chain swap funded lockup failed/refunded; marking refund_due (BTC recoverable, operator P1)"
        );
        db::mark_chain_swap_refund_due(&state.db, swap.id)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        return Ok(());
    }

    let Some(next) = chain_swap_status_from_boltz_status(boltz_status) else {
        tracing::debug!(
            "ignoring chain-swap webhook status: {} for {}",
            boltz_status,
            swap.boltz_swap_id
        );
        return Ok(());
    };

    tracing::info!(
        event = "chain_swap_webhook",
        swap_id = %swap.boltz_swap_id,
        from = %swap.status,
        to = %next,
        boltz_status,
        "chain swap status advanced from Boltz webhook"
    );

    db::update_chain_swap_status(&state.db, swap.id, next, None)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    if matches!(
        next,
        ChainSwapStatus::UserLockMempool
            | ChainSwapStatus::UserLockConfirmed
            | ChainSwapStatus::ServerLockMempool
            | ChainSwapStatus::ServerLockConfirmed
    ) {
        invoice::flip_invoice_on_bitcoin_boltz_in_progress(
            &state.db,
            Some(swap.invoice_id),
            &swap.boltz_swap_id,
        )
        .await;
    }

    if matches!(
        next,
        ChainSwapStatus::ServerLockMempool | ChainSwapStatus::ServerLockConfirmed
    ) {
        try_claim_chain_swap_with_retry(
            &state.db,
            swap,
            &state.config.claim_liquid_electrum_urls(),
            &state.config.boltz.api_url,
            state.config.claim.max_claim_attempts,
            state.utxo_backend.as_ref(),
            db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
        )
        .await;
    }
    Ok(())
}

fn chain_swap_status_from_boltz_status(boltz_status: &str) -> Option<ChainSwapStatus> {
    match boltz_status {
        "swap.created" => None,
        "transaction.mempool" => Some(ChainSwapStatus::UserLockMempool),
        "transaction.confirmed" => Some(ChainSwapStatus::UserLockConfirmed),
        "transaction.server.mempool" => Some(ChainSwapStatus::ServerLockMempool),
        "transaction.server.confirmed" => Some(ChainSwapStatus::ServerLockConfirmed),
        // NOTE: `swap.expired` is deliberately NOT mapped to terminal `Expired`.
        // It is the wall-clock swap timer, not the on-chain lockup timeout — the
        // server lockup stays claimable until timeoutBlockHeight. It is handled
        // in `handle_chain_swap_webhook` (flip cooperative_refused, keep
        // sweepable) so we don't abandon a still-claimable lockup.
        // 0-conf rejection is NOT a failure: Boltz just wants a confirmation
        // before proceeding, then the swap continues normally. Treat it as a
        // (re)sighting of the user lockup in the mempool — previously this was
        // terminalized as `lockup_failed`, killing a payment that would settle.
        "transaction.zeroconf.rejected" => Some(ChainSwapStatus::UserLockMempool),
        // `transaction.lockupFailed` / `transaction.failed` / `transaction.refunded`
        // are handled explicitly in `handle_chain_swap_webhook` (→ `refund_due`,
        // funds recoverable) and never reach here.
        _ => None,
    }
}

async fn try_claim_chain_swap_with_retry(
    pool: &sqlx::PgPool,
    swap: &db::ChainSwapRecord,
    electrum_urls: &[String],
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
) {
    match claim_chain_swap(
        pool,
        swap.id,
        electrum_urls,
        boltz_url,
        max_claim_attempts,
        utxo_backend,
        tolerances,
    )
    .await
    {
        Ok(ClaimOutcome::Broadcast) => {}
        Ok(ClaimOutcome::AlreadyTerminal) => {}
        Ok(ClaimOutcome::SkippedLockHeld) => {
            tracing::debug!(
                "webhook chain-swap claim skipped (lock held) for swap {}",
                swap.boltz_swap_id
            );
        }
        Err(e) => {
            tracing::warn!(
                "webhook chain-swap claim attempt failed for {}: {e}",
                swap.boltz_swap_id
            );
        }
    }
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
/// the background sweep's retry tick — every webhook produced 4 claim
/// attempts before the sweep even started.
async fn try_claim_with_retry(
    pool: &sqlx::PgPool,
    swap: &db::SwapRecord,
    electrum_urls: &[String],
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
) {
    match claim_swap(
        pool,
        swap.id,
        electrum_urls,
        boltz_url,
        max_claim_attempts,
        utxo_backend,
        tolerances,
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

/// Returns the claim destination for this swap. Three branches in order:
///
///   (A) **Cached**: a previous attempt already wrote `swap_records.address`.
///       Return it as-is. This makes claim retries fully idempotent — the
///       same destination is used across attempts whether the address came
///       from the descriptor allocator or a wallet-supplied invoice.
///
///   (B) **Invoice-bound**: the swap was created for a Get-paid invoice.
///       Read `invoices.liquid_address` (wallet-supplied at create time);
///       persist it into `swap_records.address` (with `address_index = NULL`,
///       since there is no descriptor index for wallet-supplied addresses).
///
///   (C) **Lightning Address**: the swap is for the LNURL flow. Bump
///       `users.next_addr_idx` and derive a fresh CT address from the
///       user's descriptor.
///
/// Serialized on the `swap_records` row via `SELECT ... FOR UPDATE`, so
/// concurrent webhook deliveries (e.g. transaction.mempool followed by
/// transaction.confirmed) can't double-allocate or split addresses.
async fn resolve_claim_address(
    pool: &sqlx::PgPool,
    swap: &db::SwapRecord,
) -> Result<String, AppError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    // Re-read the swap row under FOR UPDATE — `swap` may be stale (the
    // caller loaded it before this call, possibly on a previous attempt).
    let row: Option<(Option<String>, Option<i32>, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT address, address_index, invoice_id FROM swap_records WHERE id = $1 FOR UPDATE",
    )
    .bind(swap.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    let (cached_addr, _cached_idx, invoice_id) =
        row.ok_or_else(|| AppError::ClaimError(format!("swap_records row gone: {}", swap.id)))?;

    // (A) Cached destination — return as-is. Idempotent retries land on
    //     the same address regardless of how it was first resolved.
    if let Some(addr) = cached_addr {
        tx.commit()
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        return Ok(addr);
    }

    // (B) Invoice-bound — wallet supplied the destination at create time.
    //     `liquid_address_index` stays NULL: there's no descriptor cursor
    //     to bump for wallet addresses. Persist into swap_records.address
    //     so the cache branch wins on the next retry.
    if let Some(inv_id) = invoice_id {
        let inv_row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT liquid_address FROM invoices WHERE id = $1")
                .bind(inv_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;

        let addr = inv_row.and_then(|(a,)| a).ok_or_else(|| {
            AppError::ClaimError(format!("invoice {inv_id} has no liquid_address"))
        })?;

        sqlx::query("UPDATE swap_records SET address = $1, address_index = NULL WHERE id = $2")
            .bind(&addr)
            .bind(swap.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;

        tracing::info!(
            event = "lightning_swap_address_from_invoice",
            swap_id = %swap.id,
            invoice_id = %inv_id,
            "claim destination resolved from invoice.liquid_address"
        );
        return Ok(addr);
    }

    // (C) Lightning Address descriptor allocator. Funds locked up against
    //     a swap we created belong to the receiver even if they deactivate
    //     the nym before funding. `purge_user` refuses to run while swaps
    //     are in flight; if a purged row ever reaches this path, the empty
    //     descriptor fails loudly instead of silently stranding funds.
    let nym = swap.nym.as_deref().ok_or_else(|| {
        AppError::ClaimError(format!(
            "swap {} has no nym and no invoice claim destination",
            swap.id
        ))
    })?;

    let user = db::get_user_by_nym(pool, nym)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("user not found: {nym}")))?;

    let addr_index_row: Option<(i32,)> = sqlx::query_as(
        "UPDATE users SET next_addr_idx = next_addr_idx + 1 \
         WHERE nym = $1 \
         RETURNING next_addr_idx - 1",
    )
    .bind(nym)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    let addr_index = addr_index_row
        .map(|(idx,)| idx)
        .ok_or_else(|| AppError::ClaimError(format!("address allocation failed: {nym}")))?;

    let addr_index_u32 = u32::try_from(addr_index)
        .map_err(|_| AppError::ClaimError("address index overflow".to_string()))?;
    let derived = descriptor::derive_address(&user.ct_descriptor, addr_index_u32)?;

    sqlx::query("UPDATE swap_records SET address = $2, address_index = $3 WHERE id = $1")
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
        nym = %nym,
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
///      Set a short in-flight lease in `next_claim_attempt_at`.
///   5. Commit (releases the advisory lock).
///   6. Broadcast the tx OUTSIDE the lock — broadcast is the slow,
///      I/O-bound step and we don't want to hold a DB connection.
///      Idempotent on Electrum.
///   7. Mark status `claimed` with the on-chain txid.
async fn claim_swap(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    electrum_urls: &[String],
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
) -> Result<ClaimOutcome, AppError> {
    // Outer wrapper: records every Err uniformly via
    // `db::record_claim_failure`. SkippedLockHeld and AlreadyTerminal
    // are Ok variants and do NOT count as failures (no attempt was
    // really made).
    let result = claim_swap_inner(
        pool,
        swap_id,
        electrum_urls,
        boltz_url,
        utxo_backend,
        tolerances,
    )
    .await;
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
                // Do not record invoice payment here. `claim_stuck`
                // requires operator recovery; the customer-facing
                // invoice can remain payment-detected until recovered.
                if let Err(e) =
                    db::mark_invoice_settlement_status_for_swap(pool, swap_id, "claim_stuck").await
                {
                    tracing::error!(
                        event = "invoice_claim_stuck_mark_failed",
                        swap_id = %swap_id,
                        "failed to mark invoice settlement_status=claim_stuck: {e}"
                    );
                }
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
    electrum_urls: &[String],
    boltz_url: &str,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
) -> Result<ClaimOutcome, AppError> {
    // Acquire single-flight and prepare the claim tx.
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    // Advisory locks live on `pg_try_advisory_xact_lock` for the duration
    // of the transaction. `claim:<uuid>` lives in a disjoint string space
    // from the existing `register:` / `donation:` / raw-npub-hex usages
    // (db.rs:201, 1088), so no AB/BA deadlock is possible with those.
    let lock_key = format!("claim:{swap_id}");
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
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
    let output_address = resolve_claim_address(pool, &swap).await?;

    let chain = Chain::Liquid(LiquidChain::Liquid);
    let claim_tx = if let Some(hex) = swap.claim_tx_hex.as_deref() {
        // Idempotent path: a previous attempt persisted the constructed
        // tx but failed somewhere between persistence and "Claimed"
        // status. Re-broadcast THAT tx, not a fresh one.
        BtcLikeTransaction::from_hex(chain, hex)
            .map_err(|e| AppError::ClaimError(format!("decode persisted claim_tx: {e}")))?
    } else {
        // Choose the claim path. `cooperative_refused` is set by either:
        //   - the webhook handler on `swap.expired`, OR
        //   - this function on a previous attempt where Boltz returned
        //     a known cooperative-refusal error (below).
        // Once it flips, the row stays on script-path forever — no
        // ping-pong. `cooperative_refused` is a one-way flag.
        let use_cooperative = !swap.cooperative_refused;
        let constructed = match construct_claim_tx(
            &swap,
            &output_address,
            electrum_urls,
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
        let claim_path = if use_cooperative {
            "cooperative"
        } else {
            "script"
        };
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

    // Status -> Claiming. The retry timestamp doubles as an in-flight
    // lease: webhook/reconciler/background races must wait for this
    // deadline before rebroadcasting the persisted transaction.
    sqlx::query(
        "UPDATE swap_records \
         SET status = 'claiming', \
             next_claim_attempt_at = NOW() + $2::interval, \
             updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
    )
    .bind(swap.id)
    .bind(db::CLAIM_IN_FLIGHT_LEASE)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    // Broadcast outside the lock.
    //
    // Broadcast is pure I/O against Electrum and may take seconds. We
    // hold no DB connection or lock during the call. If the process
    // dies between here and the final update, the next sweep tick re-acquires
    // the advisory lock, sees `claim_tx_hex` is set, and re-broadcasts
    // THIS exact tx (idempotent).
    let liquid_client = connect_liquid_electrum(electrum_urls).await?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);

    let mut txid = btc_like_txid(&claim_tx);

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
                    // fall through to the final status update
                }
                Ok(false) => match recover_claim_from_lockup_spend(&claim_tx, backend).await {
                    Ok(Some(spending_txid)) => {
                        tracing::info!(
                            event = "claim_outspend_recovered",
                            swap_id = %swap.boltz_swap_id,
                            expected_txid = %txid,
                            recovered_txid = %spending_txid,
                            broadcast_error = %broadcast_err,
                            "claim broadcast errored and expected txid was absent, but lockup outspend was found"
                        );
                        txid = spending_txid;
                    }
                    Ok(None) => {
                        return Err(AppError::ClaimError(format!(
                            "broadcast failed: {broadcast_err}"
                        )));
                    }
                    Err(recovery_err) => {
                        tracing::warn!(
                            "claim outspend recovery failed for {}: {recovery_err}; \
                                 treating broadcast as failed",
                            swap.boltz_swap_id
                        );
                        return Err(AppError::ClaimError(format!(
                            "broadcast failed: {broadcast_err}"
                        )));
                    }
                },
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

    // Mark Claimed and clear retry bookkeeping.
    db::update_swap_status(pool, swap.id, SwapStatus::Claimed, Some(&txid))
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if let Err(e) = db::mark_invoice_settlement_status(pool, swap.invoice_id, "settled").await {
        tracing::warn!(
            event = "invoice_settlement_status_mark_failed",
            swap_id = %swap.boltz_swap_id,
            "failed to mark invoice settlement_status=settled: {e}"
        );
    }
    if let Err(e) = db::clear_claim_failure_state(pool, swap.id).await {
        // Non-fatal: row is Claimed; stale last-error fields are an
        // observability nuisance only.
        tracing::warn!("clear_claim_failure_state for {}: {e}", swap.boltz_swap_id);
    }

    // Merchant-side claim succeeded. This is the Lightning accounting
    // boundary; lockup confirmation, refund, and claim-stuck states do
    // not record invoice payment events.
    invoice::flip_invoice_on_lightning_settlement(
        pool,
        swap.invoice_id,
        swap.amount_sat,
        &swap.boltz_swap_id,
        &txid,
        tolerances,
    )
    .await;

    Ok(ClaimOutcome::Broadcast)
}

async fn claim_chain_swap(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    electrum_urls: &[String],
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
) -> Result<ClaimOutcome, AppError> {
    let result = claim_chain_swap_inner(
        pool,
        chain_swap_id,
        electrum_urls,
        boltz_url,
        utxo_backend,
        tolerances,
    )
    .await;
    if let Err(ref e) = result {
        let err_str = e.to_string();
        match db::record_chain_swap_claim_failure(pool, chain_swap_id, &err_str, max_claim_attempts)
            .await
        {
            Ok(db::ClaimFailureOutcome::Stuck) => {
                tracing::error!(
                    event = "chain_swap_claim_stuck",
                    swap_id = %chain_swap_id,
                    attempts = max_claim_attempts,
                    last_error = %err_str,
                    "chain swap reached max_claim_attempts; transitioned to claim_stuck"
                );
                if let Ok(Some(row)) = db::get_chain_swap_by_id(pool, chain_swap_id).await {
                    if let Err(e) = db::mark_invoice_settlement_status(
                        pool,
                        Some(row.invoice_id),
                        "claim_stuck",
                    )
                    .await
                    {
                        tracing::error!(
                            event = "invoice_chain_swap_claim_stuck_mark_failed",
                            swap_id = %chain_swap_id,
                            "failed to mark invoice settlement_status=claim_stuck: {e}"
                        );
                    }
                }
            }
            Ok(db::ClaimFailureOutcome::Scheduled) => {
                tracing::warn!(
                    event = "chain_swap_claim_failure_scheduled",
                    swap_id = %chain_swap_id,
                    last_error = %err_str,
                    "chain swap claim failed; scheduled for retry"
                );
            }
            Ok(db::ClaimFailureOutcome::NoOp) => {
                tracing::debug!(
                    "chain-swap claim failure for {} arrived after terminal state",
                    chain_swap_id
                );
            }
            Err(db_err) => {
                tracing::error!(
                    "failed to record chain-swap claim failure for {}: {db_err}",
                    chain_swap_id
                );
            }
        }
    }
    result
}

async fn claim_chain_swap_inner(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    electrum_urls: &[String],
    boltz_url: &str,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
) -> Result<ClaimOutcome, AppError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    let lock_key = format!("chain-claim:{chain_swap_id}");
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
    if !got_lock {
        return Ok(ClaimOutcome::SkippedLockHeld);
    }

    let swap = db::get_chain_swap_by_id(&mut *tx, chain_swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("chain swap not found: {chain_swap_id}")))?;

    let status = swap.parsed_status().map_err(AppError::DbError)?;
    if status.is_terminal() {
        return Ok(ClaimOutcome::AlreadyTerminal);
    }
    if !matches!(
        status,
        ChainSwapStatus::ServerLockMempool
            | ChainSwapStatus::ServerLockConfirmed
            | ChainSwapStatus::Claiming
            | ChainSwapStatus::ClaimFailed
    ) {
        return Ok(ClaimOutcome::AlreadyTerminal);
    }

    let invoice = db::get_invoice_by_id(pool, swap.invoice_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("invoice not found: {}", swap.invoice_id)))?;
    let output_address = invoice.liquid_address.ok_or_else(|| {
        AppError::ClaimError(format!(
            "invoice {} has no liquid_address for chain-swap claim",
            swap.invoice_id
        ))
    })?;

    let claim_tx = if let Some(hex) = swap.claim_tx_hex.as_deref() {
        BtcLikeTransaction::from_hex(Chain::Liquid(LiquidChain::Liquid), hex)
            .map_err(|e| AppError::ClaimError(format!("decode persisted chain claim_tx: {e}")))?
    } else {
        // Cooperative MuSig2 claim by default; script-path (preimage) claim once
        // `cooperative_refused` is set — by the `swap.expired` webhook or a prior
        // runtime refusal below. One-way flag, so no cooperative/script ping-pong.
        // Mirrors claim_swap_inner (reverse path).
        let use_cooperative = !swap.cooperative_refused;
        let constructed = match construct_chain_claim_tx(
            &swap,
            &output_address,
            electrum_urls,
            boltz_url,
            use_cooperative,
        )
        .await
        {
            Ok(t) => t,
            Err(e) if use_cooperative && is_cooperative_refusal(&e) => {
                tracing::warn!(
                    event = "chain_swap_cooperative_refused_runtime",
                    swap_id = %swap.boltz_swap_id,
                    error = %e,
                    "boltz refused cooperative chain claim; flipping cooperative_refused for next sweep"
                );
                let _ = db::mark_chain_swap_cooperative_refused(pool, swap.id).await;
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        let hex = serialize_claim_tx_hex(&constructed)?;
        let txid = btc_like_txid(&constructed);
        sqlx::query(
            "UPDATE chain_swap_records \
             SET claim_tx_hex = $2, claim_txid = $3 \
             WHERE id = $1 AND claim_tx_hex IS NULL",
        )
        .bind(swap.id)
        .bind(&hex)
        .bind(&txid)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
        constructed
    };

    sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'claiming', \
             next_claim_attempt_at = NOW() + $2::interval, \
             updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck')",
    )
    .bind(swap.id)
    .bind(db::CLAIM_IN_FLIGHT_LEASE)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    let liquid_client = connect_liquid_electrum(electrum_urls).await?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);
    let mut txid = btc_like_txid(&claim_tx);
    if let Err(broadcast_err) = chain_client.try_broadcast_tx(&claim_tx).await {
        if let Some(backend) = utxo_backend {
            match backend.tx_exists(&txid).await {
                Ok(true) => {
                    tracing::info!(
                        event = "chain_claim_broadcast_probe_recovered",
                        swap_id = %swap.boltz_swap_id,
                        txid = %txid,
                        broadcast_error = %broadcast_err,
                        "chain claim broadcast errored but tx is on chain; treating as success"
                    );
                }
                Ok(false) => match recover_claim_from_lockup_spend(&claim_tx, backend).await {
                    Ok(Some(spending_txid)) => {
                        tracing::info!(
                            event = "chain_claim_outspend_recovered",
                            swap_id = %swap.boltz_swap_id,
                            expected_txid = %txid,
                            recovered_txid = %spending_txid,
                            broadcast_error = %broadcast_err,
                            "chain claim broadcast errored and expected txid was absent, but lockup outspend was found"
                        );
                        txid = spending_txid;
                    }
                    Ok(None) => {
                        return Err(AppError::ClaimError(format!(
                            "broadcast chain claim failed: {broadcast_err}"
                        )));
                    }
                    Err(recovery_err) => {
                        tracing::warn!(
                            "chain claim outspend recovery failed for {}: {recovery_err}; treating broadcast as failed",
                            swap.boltz_swap_id
                        );
                        return Err(AppError::ClaimError(format!(
                            "broadcast chain claim failed: {broadcast_err}"
                        )));
                    }
                },
                Err(probe_err) => {
                    tracing::warn!(
                        "chain claim tx_exists probe failed for {}: {probe_err}; treating broadcast as failed",
                        swap.boltz_swap_id
                    );
                    return Err(AppError::ClaimError(format!(
                        "broadcast chain claim failed: {broadcast_err}"
                    )));
                }
            }
        } else {
            return Err(AppError::ClaimError(format!(
                "broadcast chain claim failed: {broadcast_err}"
            )));
        }
    }

    db::update_chain_swap_status(pool, swap.id, ChainSwapStatus::Claimed, Some(&txid))
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if let Err(e) = db::clear_chain_swap_claim_failure_state(pool, swap.id).await {
        tracing::warn!(
            "clear_chain_swap_claim_failure_state for {}: {e}",
            swap.boltz_swap_id
        );
    }
    if let Err(e) = db::mark_invoice_settlement_status(pool, Some(swap.invoice_id), "settled").await
    {
        tracing::warn!(
            event = "invoice_chain_swap_settlement_status_mark_failed",
            swap_id = %swap.boltz_swap_id,
            "failed to mark invoice settlement_status=settled: {e}"
        );
    }
    invoice::flip_invoice_on_bitcoin_boltz_settlement(
        pool,
        Some(swap.invoice_id),
        // Credit the SERVER lockup (the L-BTC actually claimed to the merchant),
        // which equals the invoice under payer-pays gross-up pricing. Crediting
        // user_lock_amount_sat would over-credit by the swap overhead (and trip
        // the overpaid tolerance) now that the payer's amount is grossed up.
        // After a Phase 3 renegotiation the settled server lockup is the
        // renegotiated amount, so credit that (effective_* falls back to the
        // original server_lock when the swap was never renegotiated).
        swap.effective_server_lock_amount_sat(),
        &swap.boltz_swap_id,
        &txid,
        tolerances,
    )
    .await;

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
    electrum_urls: &[String],
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

    // New connection per construct call: ElectrumLiquidClient wraps a TCP
    // socket and isn't Send+Sync, so it can't be shared across tasks.
    let liquid_client = connect_liquid_electrum(electrum_urls).await?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);
    // Bound the claim-path Boltz client. With no timeout a hung Boltz (as seen
    // during a degradation/DDoS) blocks the cooperative-claim round-trip
    // indefinitely, which wedges the whole sweep loop and lets funded lockups
    // drift to their timeout height — Boltz then refunds itself and the payer's
    // money is lost. 15s covers the MuSig2 round-trip while still failing fast.
    let boltz_api = BoltzApiClientV2::new(boltz_url.to_string(), Some(Duration::from_secs(15)));

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

async fn construct_chain_claim_tx(
    swap: &db::ChainSwapRecord,
    output_address: &str,
    electrum_urls: &[String],
    boltz_url: &str,
    use_cooperative: bool,
) -> Result<BtcLikeTransaction, AppError> {
    let preimage_bytes = hex::decode(&swap.preimage_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid chain preimage hex: {e}")))?;
    let preimage = Preimage::from_vec(preimage_bytes)
        .map_err(|e| AppError::ClaimError(format!("invalid chain preimage: {e}")))?;

    let claim_key_bytes = hex::decode(&swap.claim_key_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid chain claim key hex: {e}")))?;
    let refund_key_bytes = hex::decode(&swap.refund_key_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid chain refund key hex: {e}")))?;
    let secp = boltz_client::Secp256k1::new();
    let claim_secret_key =
        boltz_client::bitcoin::secp256k1::SecretKey::from_slice(&claim_key_bytes)
            .map_err(|e| AppError::ClaimError(format!("invalid chain claim secret key: {e}")))?;
    let refund_secret_key =
        boltz_client::bitcoin::secp256k1::SecretKey::from_slice(&refund_key_bytes)
            .map_err(|e| AppError::ClaimError(format!("invalid chain refund secret key: {e}")))?;
    let claim_keypair = Keypair::from_secret_key(&secp, &claim_secret_key);
    let refund_keypair = Keypair::from_secret_key(&secp, &refund_secret_key);

    let boltz_response: CreateChainResponse = serde_json::from_str(&swap.boltz_response_json)
        .map_err(|e| AppError::ClaimError(format!("invalid chain boltz response json: {e}")))?;

    let claim_public_key = boltz_client::PublicKey::new(claim_keypair.public_key());
    let refund_public_key = boltz_client::PublicKey::new(refund_keypair.public_key());
    let claim_script = SwapScript::chain_from_swap_resp(
        Chain::Liquid(LiquidChain::Liquid),
        Side::Claim,
        boltz_response.claim_details.clone(),
        claim_public_key,
    )
    .map_err(|e| AppError::ClaimError(format!("chain claim script build failed: {e}")))?;
    let lockup_script = SwapScript::chain_from_swap_resp(
        Chain::Bitcoin(BitcoinChain::Bitcoin),
        Side::Lockup,
        boltz_response.lockup_details.clone(),
        refund_public_key,
    )
    .map_err(|e| AppError::ClaimError(format!("chain lockup script build failed: {e}")))?;

    let liquid_client = connect_liquid_electrum(electrum_urls).await?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);
    // Bound the claim-path Boltz client. With no timeout a hung Boltz (as seen
    // during a degradation/DDoS) blocks the cooperative-claim round-trip
    // indefinitely, which wedges the whole sweep loop and lets funded lockups
    // drift to their timeout height — Boltz then refunds itself and the payer's
    // money is lost. 15s covers the MuSig2 round-trip while still failing fast.
    let boltz_api = BoltzApiClientV2::new(boltz_url.to_string(), Some(Duration::from_secs(15)));

    let params = SwapTransactionParams {
        keys: claim_keypair,
        output_address: output_address.to_string(),
        fee: Fee::Relative(0.1),
        swap_id: swap.boltz_swap_id.clone(),
        chain_client: &chain_client,
        boltz_client: &boltz_api,
        options: Some(
            TransactionOptions::default()
                .with_chain_claim(refund_keypair, lockup_script)
                .with_cooperative(use_cooperative),
        ),
    };

    claim_script
        .construct_claim(&preimage, params)
        .await
        .map_err(|e| AppError::ClaimError(format!("construct_chain_claim failed: {e}")))
}

/// Phase 4 merchant-recovery executor (#44). Drains a `refund_due` chain swap
/// by refunding the payer's BTC lockup to the destination address committed on
/// the swap (supplied by the merchant via the signed `/recover` endpoint).
/// Returns the broadcast refund txid on success.
///
/// Money-safety design:
///   * **G12 (double-payout):** we first verify Boltz has NOT claimed the swap
///     (merchant unpaid), then atomically flip `refund_due` -> `refunding` under
///     the shared `chain-claim:<id>` advisory lock. `refunding` is excluded from
///     every claim path, so the L-BTC claim and the BTC refund — which spend
///     different UTXOs on different chains — can never both fire. A claim only
///     ever starts from a claimable lifecycle state, never from
///     `refunding`/`refund_due`.
///   * **G14 (idempotency):** the refund address is persisted (first-write-wins)
///     before this runs; the `refunding` flip is the single-winner gate. On a
///     broadcast failure we revert `refunding` -> `refund_due` so the refund
///     stays recoverable rather than stranded.
///
/// The refund tx is constructed and broadcast OUTSIDE the advisory lock (the
/// `refunding` state, not the lock, is what fences claims), mirroring the claim
/// path where broadcast is the slow, retry-safe step.
/// Returns true if the chain-swap USER lockup transaction is CONFIRMED on-chain.
///
/// The confirmation is checked by TXID, not by address: the deployment's esplora
/// runs without an address/script-hash index (address endpoints error), but
/// txid + block endpoints work. So we ask Boltz for the lockup funding txid
/// (`/swap/chain/{id}/transactions` -> userLock.transaction.id) and then query
/// the esplora `/tx/{txid}/status`. Best-effort: on any error returns false
/// (defer the refund) — refusing to refund is the fund-safe direction.
async fn chain_lockup_confirmed(boltz_url: &str, esploras: &[String], swap_id: &str) -> bool {
    // 1) lockup funding txid from Boltz
    #[derive(serde::Deserialize)]
    struct LockTx {
        id: String,
    }
    #[derive(serde::Deserialize)]
    struct UserLock {
        transaction: LockTx,
    }
    #[derive(serde::Deserialize)]
    struct ChainTxs {
        #[serde(rename = "userLock")]
        user_lock: UserLock,
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let txs_url = format!(
        "{}/swap/chain/{}/transactions",
        boltz_url.trim_end_matches('/'),
        swap_id
    );
    let txid = match client.get(&txs_url).send().await {
        Ok(r) if r.status().is_success() => match r.json::<ChainTxs>().await {
            Ok(c) => c.user_lock.transaction.id,
            Err(_) => return false,
        },
        _ => return false,
    };

    // 2) confirmation from the esplora, txid-based (no address index needed),
    // failing over across all configured endpoints.
    #[derive(serde::Deserialize)]
    struct TxStatus {
        confirmed: bool,
    }
    crate::esplora::get_json::<TxStatus>(esploras, &format!("tx/{txid}/status"))
        .await
        .map(|s| s.confirmed)
        .unwrap_or(false)
}

pub(crate) async fn execute_chain_swap_refund(
    state: &AppState,
    swap: &db::ChainSwapRecord,
) -> Result<String, AppError> {
    let refund_address = swap.refund_address.clone().ok_or_else(|| {
        AppError::ClaimError("chain swap refund requested without a refund address".to_string())
    })?;

    // G12 (belt-and-suspenders): never refund a swap Boltz has already claimed
    // (the merchant was paid). Read-only Boltz truth, before we take the lock.
    let boltz_api = BoltzApiClientV2::new(
        state.config.boltz.api_url.clone(),
        Some(Duration::from_secs(15)),
    );
    match boltz_api.get_swap(&swap.boltz_swap_id).await {
        Ok(remote) if remote.status == "transaction.claimed" => {
            tracing::error!(
                event = "chain_swap_refund_blocked_boltz_claimed",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                "refund blocked: Boltz reports the swap claimed (merchant paid); refusing to refund (operator P1)"
            );
            return Err(AppError::ClaimError(
                "refund blocked: swap already claimed".to_string(),
            ));
        }
        Ok(_) => {}
        Err(e) => {
            // Cannot confirm Boltz state → do NOT broadcast a refund we can't
            // prove is safe. Leave the swap `refund_due` for a later retry.
            return Err(AppError::BoltzError(format!(
                "refund pre-check get_swap failed: {e}"
            )));
        }
    }

    // Lockup-confirmation gate: never attempt a refund on an UNCONFIRMED lockup.
    // Boltz emits `transaction.lockupFailed` on 0-conf detection of an underpaid
    // lockup, so `refund_due` is reached before the lockup mines. Refunding then
    // fails: Boltz won't co-sign a cooperative refund of an unconfirmed lockup,
    // and the script-path fallback is non-final pre-timeout — either way
    // `sendrawtransaction` rejects it. Defer until the lockup has >=1 conf; the
    // caller (endpoint poll / reconciler) retries and it self-heals. This avoids
    // the wasted `refunding`->revert churn and the confusing broadcast errors.
    if !chain_lockup_confirmed(
        &state.config.boltz.api_url,
        &state.config.bitcoin_watcher.effective_endpoints(),
        &swap.boltz_swap_id,
    )
    .await
    {
        tracing::info!(
            event = "chain_swap_recover_deferred_unconfirmed_lockup",
            swap_id = %swap.boltz_swap_id,
            invoice_id = %swap.invoice_id,
            lockup_address = %swap.lockup_address,
            "recovery deferred: BTC lockup not yet confirmed; retry after confirmation"
        );
        return Err(AppError::RecoveryNotAvailable(
            "recovery deferred: BTC lockup not yet confirmed".to_string(),
        ));
    }

    // Atomically claim the refund: refund_due -> refunding under the advisory
    // lock, with a FOR UPDATE re-read to serialize against status webhook writers.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    let lock_key = format!("chain-claim:{}", swap.id);
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
    if !got_lock {
        return Err(AppError::ClaimError(
            "chain swap is busy (claim/refund in progress); retry shortly".to_string(),
        ));
    }
    let current = db::get_chain_swap_by_id_for_update(&mut *tx, swap.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("chain swap not found: {}", swap.id)))?;
    let current_status = current.parsed_status().map_err(AppError::DbError)?;
    if current_status == ChainSwapStatus::Refunding {
        // A concurrent attempt already owns the refund; don't start a second
        // broadcast. The owner (or the reconciler backstop) completes it.
        return Err(AppError::ClaimError(
            "refund already in progress".to_string(),
        ));
    }
    if current_status != ChainSwapStatus::RefundDue {
        return Err(AppError::ClaimError(format!(
            "chain swap not refundable (status {current_status})"
        )));
    }
    // G12 (B3): never refund a swap for which an L-BTC claim tx was ever
    // constructed or broadcast — the claim (merchant paid) and the refund
    // (customer paid) spend different UTXOs and could both confirm. A row can
    // reach `refund_due` from `claiming`/`claim_failed` with an unconfirmed
    // claim still in the Liquid mempool; let the claim path win. (The
    // `mark_chain_swap_refunding` UPDATE also enforces this; the explicit check
    // gives a clear operator signal.)
    if current.claim_txid.is_some() || current.claim_tx_hex.is_some() {
        tracing::error!(
            event = "chain_swap_refund_blocked_claim_in_flight",
            swap_id = %swap.boltz_swap_id,
            invoice_id = %swap.invoice_id,
            claim_txid = ?current.claim_txid,
            "refund blocked: an L-BTC claim tx exists for this swap; refusing to refund to avoid a double payout (operator P1)"
        );
        return Err(AppError::ClaimError(
            "refund blocked: a claim is already in progress for this payment".to_string(),
        ));
    }
    let rows = db::mark_chain_swap_refunding(&mut *tx, swap.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if rows != 1 {
        return Err(AppError::ClaimError(
            "refund race lost; another actor advanced the swap".to_string(),
        ));
    }

    tracing::warn!(
        event = "chain_swap_refunding",
        swap_id = %swap.boltz_swap_id,
        invoice_id = %swap.invoice_id,
        refund_address = %refund_address,
        "customer self-claim refund starting; refund_due -> refunding (operator P2)"
    );

    // Build + broadcast OUTSIDE the lock. On any failure, revert so the swap
    // stays recoverable (never stranded in `refunding`).
    match build_and_broadcast_chain_refund(state, &current, &refund_address).await {
        Ok(txid) => {
            let recorded = db::mark_chain_swap_refunded(&state.db, swap.id, &txid)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
            if recorded != 1 {
                // We broadcast a refund but the row was NOT in `refunding` when
                // we tried to record it — a concurrent writer (e.g. a reconciler
                // acting on a stale snapshot) moved it out from under us. The BTC
                // IS refunded on-chain; the DB now disagrees. Loud P1 so an
                // operator reconciles against the broadcast txid.
                tracing::error!(
                    event = "chain_swap_refund_broadcast_not_recorded",
                    swap_id = %swap.boltz_swap_id,
                    invoice_id = %swap.invoice_id,
                    refund_txid = %txid,
                    "refund broadcast but status was not `refunding` at record time; reconcile the swap against this txid (operator P1)"
                );
            } else {
                tracing::warn!(
                    event = "chain_swap_refunded",
                    swap_id = %swap.boltz_swap_id,
                    invoice_id = %swap.invoice_id,
                    refund_txid = %txid,
                    "customer self-claim refund broadcast; refunding -> refunded (operator P2)"
                );
            }
            Ok(txid)
        }
        Err(e) => {
            // Revert to refund_due so a later attempt / reconciler can retry.
            // Re-broadcast is conflict-safe: any second refund tx spends the
            // same lockup UTXO, so at most one confirms.
            if let Err(revert_err) =
                db::revert_chain_swap_refunding_to_due(&state.db, swap.id).await
            {
                tracing::error!(
                    event = "chain_swap_refund_revert_failed",
                    swap_id = %swap.boltz_swap_id,
                    error = %revert_err,
                    "failed to revert refunding -> refund_due after a broadcast failure; swap stuck in refunding (operator P1)"
                );
            }
            tracing::warn!(
                event = "chain_swap_refund_broadcast_failed",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                error = %e,
                "customer self-claim refund failed to broadcast; reverted to refund_due for retry (operator P1)"
            );
            Err(e)
        }
    }
}

/// Constructs and broadcasts the BTC refund transaction spending the payer's
/// lockup UTXO back to `refund_address`. Attempts the cooperative (Boltz
/// partial-sig) refund first — valid pre-timeout and cheapest — and falls back
/// to the unilateral script path (valid only after the lockup timelock) if the
/// cooperative round-trip is refused. The Bitcoin chain client is the fork's
/// esplora client pointed at the same mempool endpoint the watcher polls.
async fn build_and_broadcast_chain_refund(
    state: &AppState,
    swap: &db::ChainSwapRecord,
    refund_address: &str,
) -> Result<String, AppError> {
    let refund_key_bytes = hex::decode(&swap.refund_key_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid chain refund key hex: {e}")))?;
    let secp = boltz_client::Secp256k1::new();
    let refund_secret_key =
        boltz_client::bitcoin::secp256k1::SecretKey::from_slice(&refund_key_bytes)
            .map_err(|e| AppError::ClaimError(format!("invalid chain refund secret key: {e}")))?;
    let refund_keypair = Keypair::from_secret_key(&secp, &refund_secret_key);
    let refund_public_key = boltz_client::PublicKey::new(refund_keypair.public_key());

    let boltz_response: CreateChainResponse = serde_json::from_str(&swap.boltz_response_json)
        .map_err(|e| AppError::ClaimError(format!("invalid chain boltz response json: {e}")))?;

    // The BTC (user lockup) side of the chain swap — the UTXO we refund.
    let lockup_script = SwapScript::chain_from_swap_resp(
        Chain::Bitcoin(BitcoinChain::Bitcoin),
        Side::Lockup,
        boltz_response.lockup_details.clone(),
        refund_public_key,
    )
    .map_err(|e| AppError::ClaimError(format!("chain lockup script build failed: {e}")))?;

    let boltz_api = BoltzApiClientV2::new(
        state.config.boltz.api_url.clone(),
        Some(Duration::from_secs(15)),
    );

    // Construct the refund tx, rotating across the esplora endpoints (#47).
    // `construct_refund` fetches the lockup UTXO from the Bitcoin chain client,
    // so a no-address-index or "up-but-broken" primary node can fail
    // construction *before* we ever reach the (already-failover'd) broadcast.
    // Building one client per endpoint lets a broken primary fall through to a
    // healthy provider. Defense-in-depth: the fork's `new_refund` already falls
    // back to Boltz for the UTXO, so a healthy primary behaves identically
    // (endpoint[0] wins on the first cooperative attempt).
    //
    // The cooperative->script fallback stays INSIDE each endpoint attempt: a
    // cooperative refusal is a Boltz answer (post-timeout / Boltz unavailable),
    // NOT an endpoint fault, so we must not rotate the esplora on it — we drop
    // to the script path on the SAME endpoint. We only rotate when BOTH paths
    // fail on an endpoint (the signature of a broken/no-index node).
    let endpoints = state.config.bitcoin_watcher.effective_endpoints();
    let mut construct_errors: Vec<String> = Vec::new();
    let mut refund_tx = None;
    for (i, endpoint) in endpoints.iter().enumerate() {
        let bitcoin_client = EsploraBitcoinClient::new(BitcoinChain::Bitcoin, endpoint, 30);
        let chain_client = ChainClient::new().with_bitcoin(bitcoin_client);

        let build = |cooperative: bool| {
            let params = SwapTransactionParams {
                keys: refund_keypair,
                output_address: refund_address.to_string(),
                // Conservative sat/vB. A too-low fee only delays the refund (RBF
                // / re-broadcast possible); precise mempool fee estimation is a
                // tracked refinement to validate in the staged broadcast test.
                fee: Fee::Relative(2.0),
                swap_id: swap.boltz_swap_id.clone(),
                chain_client: &chain_client,
                boltz_client: &boltz_api,
                options: Some(TransactionOptions::default().with_cooperative(cooperative)),
            };
            lockup_script.construct_refund(params)
        };

        // Cooperative first (pre-timeout, cheapest).
        match build(true).await {
            Ok(tx) => {
                refund_tx = Some(tx);
                break;
            }
            Err(coop_err) => {
                tracing::warn!(
                    event = "chain_swap_refund_cooperative_failed",
                    swap_id = %swap.boltz_swap_id,
                    endpoint = %endpoint,
                    error = %coop_err,
                    "cooperative refund construction failed; attempting unilateral script path on same endpoint"
                );
                // Script path on the SAME endpoint — the network rejects a
                // premature script-path spend, so this is safe.
                match build(false).await {
                    Ok(tx) => {
                        refund_tx = Some(tx);
                        break;
                    }
                    Err(script_err) => {
                        // Both paths failed here — likely an endpoint fault
                        // (no address index / up-but-broken). Rotate.
                        if i + 1 < endpoints.len() {
                            tracing::warn!(
                                event = "chain_swap_refund_construct_failover",
                                swap_id = %swap.boltz_swap_id,
                                endpoint = %endpoint,
                                "refund construction failed on this esplora endpoint; rotating to next"
                            );
                        }
                        construct_errors
                            .push(format!("{endpoint}: coop={coop_err}; script={script_err}"));
                    }
                }
            }
        }
    }
    let refund_tx = refund_tx.ok_or_else(|| {
        AppError::ClaimError(format!(
            "construct_chain_refund failed on all {} esplora endpoint(s): {}",
            endpoints.len(),
            construct_errors.join(" | ")
        ))
    })?;

    // Broadcast with esplora endpoint failover (issue #47): a single broken or
    // down node must not block the refund. `broadcast` tries each endpoint until
    // one accepts (or reports the tx already known), so we survive the kind of
    // "up-but-broken" esplora that blocked recovery before the failover existed.
    let refund_hex = serialize_claim_tx_hex(&refund_tx)?;
    let expected_txid = btc_like_txid(&refund_tx);
    crate::esplora::broadcast(
        &state.config.bitcoin_watcher.effective_endpoints(),
        &refund_hex,
        &expected_txid,
    )
    .await
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

/// Strip the URL scheme from an electrum endpoint for boltz-client's
/// `ElectrumLiquidClient`, which expects a bare `host:port` and re-adds the
/// scheme itself (`build_client` does `format!("ssl://{url}")`). Our config
/// carries the scheme (the electrum-client backend in utxo.rs wants it), so
/// passing it through unmodified yields a doubled `ssl://ssl://host:port` that
/// fails DNS resolution ("Name or service not known") — meaning claims never
/// broadcast. Strip `ssl://`/`tcp://` here so both electrum clients get the
/// form they expect.
fn electrum_host_port(url: &str) -> &str {
    url.strip_prefix("ssl://")
        .or_else(|| url.strip_prefix("tcp://"))
        .unwrap_or(url)
}

/// Connect a Liquid Electrum client for the claim/broadcast path, trying each
/// URL until one connects AND answers a cheap probe — the same provider
/// failover the UtxoBackend pool already has (#47). `ElectrumLiquidClient::new`
/// attempts the connection, so a DOWN endpoint fails here and we rotate. An
/// "up-but-broken" backend (TCP accepts, requests error) would otherwise be
/// returned healthy and pin every retry to it; a post-connect `get_genesis_hash`
/// probe (a single `blockchain.block.header` at height 0) catches that and
/// rotates too. The already-present `utxo_backend` tx-existence probe still
/// rescues an on-chain-but-errored broadcast. Returns the first client that
/// connects and validates, or an aggregated error.
async fn connect_liquid_electrum(urls: &[String]) -> Result<ElectrumLiquidClient, AppError> {
    let mut errors: Vec<String> = Vec::new();
    for (i, url) in urls.iter().enumerate() {
        let client = match ElectrumLiquidClient::new(
            LiquidChain::Liquid,
            electrum_host_port(url),
            true,
            true,
            30,
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    event = "liquid_electrum_failover",
                    endpoint = %url,
                    err = %e,
                    "Liquid electrum connect failed; trying next endpoint"
                );
                errors.push(format!("{url}: connect: {e}"));
                continue;
            }
        };
        // Post-connect validation: a genesis-header fetch is cheap and
        // deterministic; an up-but-broken node errors here and we rotate.
        if let Err(e) = client.get_genesis_hash().await {
            tracing::warn!(
                event = "liquid_electrum_failover",
                endpoint = %url,
                err = %e,
                "Liquid electrum connected but failed validation probe; trying next endpoint"
            );
            errors.push(format!("{url}: probe: {e}"));
            continue;
        }
        if i > 0 {
            tracing::warn!(
                event = "liquid_electrum_failover",
                endpoint = %url,
                "connected to failover Liquid electrum after earlier endpoint(s) failed"
            );
        }
        return Ok(client);
    }
    tracing::error!(
        event = "liquid_electrum_all_endpoints_failed",
        endpoints = urls.len(),
        "all Liquid electrum endpoints failed to connect"
    );
    Err(AppError::ClaimError(format!(
        "electrum connection failed on all {} url(s): {}",
        urls.len(),
        errors.join(" | ")
    )))
}

/// Hex-encode a fully-signed claim tx for storage in
/// `swap_records.claim_tx_hex`. Mirrors the deserialize path in
/// `BtcLikeTransaction::from_hex` so a round-trip is well-defined for
/// both Liquid (elements consensus) and Bitcoin (consensus crate).
fn serialize_claim_tx_hex(tx: &BtcLikeTransaction) -> Result<String, AppError> {
    Ok(match tx {
        BtcLikeTransaction::Liquid(t) => hex::encode(boltz_client::elements::encode::serialize(t)),
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

async fn recover_claim_from_lockup_spend(
    claim_tx: &BtcLikeTransaction,
    backend: &Arc<dyn UtxoBackend>,
) -> Result<Option<String>, AppError> {
    let BtcLikeTransaction::Liquid(tx) = claim_tx else {
        return Ok(None);
    };

    let Some(input) = tx.input.first() else {
        return Err(AppError::ClaimError(
            "claim tx has no input for outspend recovery".into(),
        ));
    };

    let lockup_txid = input.previous_output.txid.to_string();
    let lockup_vout = input.previous_output.vout;
    let raw_lockup = backend.get_raw_tx(&lockup_txid).await?;
    let lockup_tx: elements::Transaction = elements::encode::deserialize(&raw_lockup)
        .map_err(|e| AppError::ClaimError(format!("decode lockup tx: {e}")))?;
    let lockup_output = lockup_tx
        .output
        .get(lockup_vout as usize)
        .ok_or_else(|| AppError::ClaimError(format!("lockup vout {lockup_vout} missing")))?;

    let Some(spending_txid) = backend
        .find_spending_txid(&lockup_output.script_pubkey, &lockup_txid, lockup_vout)
        .await?
    else {
        return Ok(None);
    };

    let raw_spending = backend.get_raw_tx(&spending_txid).await?;
    let spending_tx: boltz_elements::Transaction =
        boltz_elements::encode::deserialize(&raw_spending)
            .map_err(|e| AppError::ClaimError(format!("decode spending tx: {e}")))?;
    if !spending_tx_matches_claim_destination(&spending_tx, tx) {
        return Err(AppError::ClaimError(format!(
            "lockup spent by {spending_txid}, but spender does not pay the claim destination"
        )));
    }

    Ok(Some(spending_txid))
}

fn spending_tx_matches_claim_destination(
    spending_tx: &boltz_elements::Transaction,
    claim_tx: &boltz_elements::Transaction,
) -> bool {
    claim_tx.output.iter().any(|claim_output| {
        !claim_output.script_pubkey.is_empty()
            && spending_tx
                .output
                .iter()
                .any(|out| out.script_pubkey == claim_output.script_pubkey)
    })
}

#[cfg(test)]
mod tests;

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
        // process-tree archaeology one. At 10s/tick x 30 ticks, that's
        // every 5 minutes — same cadence as the rate-limit GC.
        const HEARTBEAT_EVERY_N_TICKS: u32 = 30;
        let mut tick_count: u32 = 0;
        loop {
            tick_count = tick_count.wrapping_add(1);
            let ready = match db::get_ready_to_claim_swaps(&pool).await {
                Ok(swaps) => swaps,
                Err(e) => {
                    tracing::error!("background claimer: db query failed: {e}");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(CLAIM_SWEEP_INTERVAL_SECS)) => continue,
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
                        &config.claim_liquid_electrum_urls(),
                        &config.boltz.api_url,
                        config.claim.max_claim_attempts,
                        utxo_backend.as_ref(),
                        db::InvoiceAccountingTolerances::from(&config.invoice_accounting),
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
                            tracing::warn!("background claimer: swap {}: {e}", swap.boltz_swap_id);
                        }
                    }
                }
            } else if first_run {
                tracing::info!("background claimer: no unclaimed swaps found");
            }

            let ready_chain = match db::get_ready_to_claim_chain_swaps(&pool).await {
                Ok(swaps) => swaps,
                Err(e) => {
                    tracing::error!("background claimer: chain-swap db query failed: {e}");
                    Vec::new()
                }
            };
            if !ready_chain.is_empty() {
                tracing::info!(
                    "background claimer: found {} chain swap(s) ready to claim",
                    ready_chain.len()
                );
                for swap in &ready_chain {
                    match claim_chain_swap(
                        &pool,
                        swap.id,
                        &config.claim_liquid_electrum_urls(),
                        &config.boltz.api_url,
                        config.claim.max_claim_attempts,
                        utxo_backend.as_ref(),
                        db::InvoiceAccountingTolerances::from(&config.invoice_accounting),
                    )
                    .await
                    {
                        Ok(ClaimOutcome::Broadcast) => {
                            tracing::info!(
                                "background claimer: claimed chain swap {}",
                                swap.boltz_swap_id
                            );
                        }
                        Ok(ClaimOutcome::SkippedLockHeld) => {
                            tracing::debug!(
                                "background claimer: skipped chain swap {} (lock held)",
                                swap.boltz_swap_id
                            );
                        }
                        Ok(ClaimOutcome::AlreadyTerminal) => {
                            tracing::debug!(
                                "background claimer: skipped chain swap {} (already terminal)",
                                swap.boltz_swap_id
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "background claimer: chain swap {}: {e}",
                                swap.boltz_swap_id
                            );
                        }
                    }
                }
            }

            if tick_count.is_multiple_of(HEARTBEAT_EVERY_N_TICKS) {
                tracing::info!(
                    target: "claimer",
                    event = "claimer_heartbeat",
                    tick = tick_count,
                    ready_count = ready.len(),
                    ready_chain_count = ready_chain.len(),
                    "background claimer heartbeat"
                );
            }

            first_run = false;
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("background claimer: shutting down");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(CLAIM_SWEEP_INTERVAL_SECS)) => {}
            }
        }
    });
}

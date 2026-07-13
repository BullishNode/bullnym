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

use crate::admission::WorkerReporter;
use crate::builder_fee::LiquidBuilderFeeDecision;
use crate::config::Config;
use crate::db::{self, ChainSwapStatus, SwapStatus};
use crate::descriptor;
use crate::error::AppError;
use crate::fee_decision_record::{FeeConstructionPurpose, FeeDecisionRecord};
use crate::fee_policy::{FeeFreshness, LiquidFeeDecision, LiquidFeePolicy};
use crate::fee_runtime::FeeRuntime;
use crate::invoice;
use crate::ip_whitelist;
use crate::utxo::UtxoBackend;
use crate::validators;
use crate::AppState;

const CLAIM_SWEEP_INTERVAL_SECS: u64 = 10;
const REVERSE_TEST_GUARD_REJECTED: &str =
    "claim integration seam requires a malformed reverse response without persisted claim bytes";
const CHAIN_TEST_GUARD_REJECTED: &str =
    "claim integration seam requires a malformed chain response without persisted claim bytes";
/// Stable, non-secret explanation for a claim that remains pending until fee
/// policy supplies accepted live or recent same-rail evidence.
#[doc(hidden)]
pub const LIQUID_FEE_DECISION_PENDING_REASON: &str =
    "Liquid fee decision unavailable; retry after accepted live or recent same-rail evidence";

fn liquid_claim_fee(decision: &LiquidBuilderFeeDecision, _cooperative_or_script_path: bool) -> Fee {
    // Both paths use the same sat/vByte decision. `boltz-client` applies it
    // to each path's actual virtual size, so their absolute fees may differ.
    Fee::Relative(decision.rate().as_f64())
}

fn validated_chain_creation_destination(
    terms: &db::ChainSwapCreationTerms,
) -> Result<String, AppError> {
    if terms.btc_network != "bitcoin" || terms.liquid_network != "liquid" {
        return Err(AppError::ClaimError(format!(
            "chain swap creation packet has unsupported networks: {}/{}",
            terms.btc_network, terms.liquid_network
        )));
    }
    let expected_asset = elements::AssetId::LIQUID_BTC.to_string();
    if terms.liquid_asset_id != expected_asset {
        return Err(AppError::ClaimError(format!(
            "chain swap creation packet has unexpected Liquid asset {}",
            terms.liquid_asset_id
        )));
    }
    let canonical = validators::canonical_liquid_mainnet_address(
        &terms.merchant_liquid_destination,
    )
    .map_err(|error| {
        AppError::ClaimError(format!(
            "invalid immutable chain-swap Liquid destination: {error}"
        ))
    })?;
    if canonical != terms.merchant_liquid_destination {
        return Err(AppError::ClaimError(
            "immutable chain-swap Liquid destination is not canonical".into(),
        ));
    }
    Ok(canonical)
}

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

/// Preserve the standard structured [`AppError`] response body and logging,
/// but make dispatcher failures visible to Boltz at the HTTP layer so it
/// retries the same delivery. Some public endpoints intentionally encode
/// errors in HTTP 200 responses; that convention is not valid for webhooks.
fn webhook_dispatch_response(result: Result<&'static str, AppError>) -> Response {
    match result {
        Ok(body) => body.into_response(),
        Err(error) => {
            let mut response = error.into_response();
            if response.status().is_success() {
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            }
            response
        }
    }
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
    Ok(webhook_dispatch_response(
        dispatch_webhook(state, peer_opt, headers, body).await,
    ))
}

/// Compatibility webhook entrypoint: `/webhook/boltz`.
/// See docs/compatibility-ledger.md for removal policy.
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
    Ok(webhook_dispatch_response(
        dispatch_webhook(state, peer_opt, headers, body).await,
    ))
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

    tracing::info!("boltz webhook: swap={} status={}", data.id, data.status);

    let swap = db::get_swap_by_boltz_id(&state.db, &data.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if swap.is_none() {
        if let Some(chain_swap) = db::get_chain_swap_by_boltz_id(&state.db, &data.id)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?
        {
            // Chain swaps deliberately do not use permanent
            // `{swap_id}:{status}` delivery dedup as a correctness gate. The
            // shared row-locked transition below makes duplicates/reordering
            // safe, and every delivery can redrive an executor that failed
            // after the prior state commit. The reconciler calls the same path.
            handle_chain_swap_webhook(&state, &chain_swap, &data.status).await?;
            return Ok("ok");
        }
    }

    // Legacy reverse-swap delivery dedup remains scoped to that path. It is
    // intentionally checked only after ruling out a chain swap, so a chain
    // delivery cannot be permanently consumed before its transition succeeds.
    let event_id = format!("{}:{}", data.id, data.status);
    let is_first = db::try_record_webhook_event(&state.db, &event_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if !is_first {
        tracing::debug!("boltz webhook: duplicate reverse/unknown event {event_id}");
        return Ok("ok");
    }

    let Some(swap) = swap else {
        // Unknown swap_id is not an error condition for Boltz to retry —
        // either we never created the swap here, or the row was purged.
        // Returning 200 stops the Boltz retry storm.
        tracing::warn!("boltz webhook for unknown swap: {}", data.id);
        return Ok("ok");
    };

    let status = swap
        .parsed_status()
        .map_err(|e| AppError::ClaimError(format!("invalid persisted swap status: {e}")))?;
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

            try_claim_with_retry(&swap, ClaimAttemptContext::from_state(&state)).await;
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
/// Returns `Ok(false)` only when a successfully decoded quote is unusable or
/// the row was terminalized concurrently. Transport/API ambiguity returns
/// `Err` so webhook delivery or reconciliation can retry; it is never proof
/// that Bitcoin recovery is eligible.
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

    // Step 1: read-only quote (no lock). An error may be a transport failure,
    // response loss, or an explicit refusal; without durable evidence that
    // distinguishes those cases it must remain retryable.
    let quote_amount = match state.boltz.get_chain_swap_quote(&swap.boltz_swap_id).await {
        Ok(amount) => amount,
        Err(e) => {
            tracing::warn!(
                event = "chain_swap_renegotiation_quote_ambiguous",
                swap_id = %swap.boltz_swap_id,
                error = %e,
                "chain swap get_quote failed ambiguously; preserving the normal path for retry"
            );
            return Err(e);
        }
    };
    // A zero/absent or absurd (non-i64) quote is nonsensical — the provider
    // returned a concrete unusable value rather than an ambiguous transport
    // outcome. Keep the existing bounded waterfall behavior for this case.
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
        ChainSwapStatus::ServerLockMempool
            | ChainSwapStatus::ServerLockConfirmed
            | ChainSwapStatus::Claiming
            | ChainSwapStatus::ClaimFailed
    ) {
        // A late server lock is stronger than the older lockup-failure hint.
        // Its Liquid claim branch owns progress now; never mutate provider
        // terms from reordered failure evidence.
        return Ok(true);
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
    let Some(input) = chain_swap_provider_input(boltz_status) else {
        tracing::debug!(
            "ignoring chain-swap webhook status: {} for {}",
            boltz_status,
            swap.boltz_swap_id
        );
        return Ok(());
    };
    let transition = db::apply_chain_swap_provider_status(&state.db, swap.id, input)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| {
            AppError::DbError(format!(
                "chain swap disappeared while applying provider status: {}",
                swap.id
            ))
        })?;
    let mut status = transition.current_status;

    if status.is_terminal() {
        tracing::debug!(
            "ignoring webhook for terminal chain swap {} ({})",
            swap.boltz_swap_id,
            status
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
        if matches!(
            input,
            db::ChainSwapProviderStatusInput::UserLockMempool
                | db::ChainSwapProviderStatusInput::UserLockConfirmed
        ) {
            // The failure/expiry observation may have committed first. In
            // that delivery order the user-lock fold moves Pending directly
            // to RefundDue, so re-drive the invoice projection before the
            // early return. This is intentionally keyed to the current local
            // payer-lock evidence: failure hints alone never make an invoice
            // look funded, while a retry after cancellation between the row
            // commit and this side effect remains safe and convergent.
            invoice::flip_invoice_on_bitcoin_boltz_in_progress(
                &state.db,
                Some(swap.invoice_id),
                &swap.boltz_swap_id,
            )
            .await;
        }
        // A late server-lock observation has already moved `refund_due` back to
        // the normal Liquid branch atomically. Remaining evidence cannot prove
        // that recovery is ineligible, so keep the provisional recovery state.
        if boltz_status == "transaction.claimed" {
            tracing::warn!(
                event = "chain_swap_refund_due_but_claimed",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                "chain swap is refund_due but Boltz now reports claimed; refund must be gated on Boltz not-claimed before broadcast (Phase 4)"
            );
        } else if transition.changed {
            tracing::warn!(
                event = "chain_swap_refund_due",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                nym = ?swap.nym,
                amount_sat = swap.user_lock_amount_sat,
                lockup_address = %swap.lockup_address,
                boltz_status,
                "confirmed local user-lock evidence plus provider expiry/failure made Bitcoin recovery eligible (operator P1)"
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
            local_status = %status,
            "boltz reports chain swap claimed; local claim path remains authoritative for invoice accounting"
        );
        try_claim_chain_swap_with_retry(swap, ClaimAttemptContext::from_state(state)).await;
        return Ok(());
    }

    if boltz_status == "swap.expired" {
        // Server lockup exists (or claim in progress): still claimable until
        // timeoutBlockHeight. The atomic transition has flipped the one-way
        // script-path flag without regressing status.
        tracing::warn!(
            event = "chain_swap_expired_webhook",
            swap_id = %swap.boltz_swap_id,
            local_status = %status,
            cooperative_refused = transition.cooperative_refused,
            "chain swap.expired received; retaining the forward-most local branch"
        );
        // Nudge the claimer: if the server lockup is already confirmed/claiming
        // the script-path claim runs now; otherwise the sweep / reconciler
        // picks it up once the lockup appears.
        try_claim_chain_swap_with_retry(swap, ClaimAttemptContext::from_state(state)).await;
        return Ok(());
    }

    if boltz_status == "transaction.lockupFailed"
        && matches!(
            status,
            ChainSwapStatus::Pending
                | ChainSwapStatus::UserLockMempool
                | ChainSwapStatus::UserLockConfirmed
        )
    {
        // Phase 3 refund waterfall — step 1: `transaction.lockupFailed` means
        // the payer under- or over-paid the BTC lockup. Before flagging the
        // funds `refund_due` (a manual/self-claim recovery), try to renegotiate
        // the swap to the amount actually locked (Boltz get_quote/accept_quote)
        // so it still settles automatically and the merchant is credited the
        // renegotiated amount. Only a concrete unusable quote falls through to
        // the guarded `refund_due` fold below; transport/API ambiguity returns
        // an error so the same evidence remains retryable.
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
                    "chain swap renegotiation attempt errored; leaving evidence retryable"
                );
                return Err(e);
            }
        }

        // An explicit decline is applied through the same row-locked reducer
        // as every other webhook/reconciliation input. A concurrent late
        // server lock wins over an unstarted recovery branch.
        let declined = db::apply_chain_swap_provider_status(
            &state.db,
            swap.id,
            db::ChainSwapProviderStatusInput::FundingFailed,
        )
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| {
            AppError::DbError(format!(
                "chain swap disappeared while recording renegotiation decline: {}",
                swap.id
            ))
        })?;
        if declined.current_status == ChainSwapStatus::RefundDue {
            tracing::warn!(
                event = "chain_swap_refund_due",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                nym = ?swap.nym,
                amount_sat = swap.user_lock_amount_sat,
                lockup_address = %swap.lockup_address,
                boltz_status,
                "confirmed local user-lock evidence plus declined renegotiation made Bitcoin recovery eligible (operator P1)"
            );
            return Ok(());
        }
        status = declined.current_status;
    }

    if matches!(
        boltz_status,
        "transaction.lockupFailed" | "transaction.failed" | "transaction.refunded"
    ) {
        // Pending plus a provider failure is not proof of payer funding. A
        // server-lock/claim branch is stronger local evidence and remains
        // authoritative; re-drive it instead of guessing recovery success.
        if matches!(
            status,
            ChainSwapStatus::ServerLockMempool
                | ChainSwapStatus::ServerLockConfirmed
                | ChainSwapStatus::Claiming
                | ChainSwapStatus::ClaimFailed
        ) {
            tracing::warn!(
                event = "chain_swap_provider_failure_after_server_lock",
                swap_id = %swap.boltz_swap_id,
                local_status = %status,
                boltz_status,
                "provider failure disagrees with the local Liquid branch; preserving and redriving claim"
            );
            try_claim_chain_swap_with_retry(swap, ClaimAttemptContext::from_state(state)).await;
        } else {
            tracing::debug!(
                swap_id = %swap.boltz_swap_id,
                local_status = %status,
                boltz_status,
                "provider failure did not add local funding evidence; observing without authorizing recovery"
            );
        }
        return Ok(());
    }

    let next = match input {
        db::ChainSwapProviderStatusInput::UserLockMempool => ChainSwapStatus::UserLockMempool,
        db::ChainSwapProviderStatusInput::UserLockConfirmed => ChainSwapStatus::UserLockConfirmed,
        db::ChainSwapProviderStatusInput::ServerLockMempool => ChainSwapStatus::ServerLockMempool,
        db::ChainSwapProviderStatusInput::ServerLockConfirmed => {
            ChainSwapStatus::ServerLockConfirmed
        }
        db::ChainSwapProviderStatusInput::Observe
        | db::ChainSwapProviderStatusInput::SwapExpired
        | db::ChainSwapProviderStatusInput::FundingFailed => return Ok(()),
    };

    if transition.changed {
        tracing::info!(
            event = "chain_swap_webhook",
            swap_id = %swap.boltz_swap_id,
            from = %transition.previous_status,
            to = %transition.current_status,
            boltz_status,
            "chain swap provider status advanced atomically"
        );
    } else {
        tracing::debug!(
            swap_id = %swap.boltz_swap_id,
            local_status = %transition.current_status,
            boltz_status,
            "duplicate/reordered chain swap evidence left state unchanged"
        );
    }

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
        transition.current_status,
        ChainSwapStatus::ServerLockMempool
            | ChainSwapStatus::ServerLockConfirmed
            | ChainSwapStatus::Claiming
            | ChainSwapStatus::ClaimFailed
    ) {
        try_claim_chain_swap_with_retry(swap, ClaimAttemptContext::from_state(state)).await;
    }
    Ok(())
}

fn chain_swap_provider_input(boltz_status: &str) -> Option<db::ChainSwapProviderStatusInput> {
    match boltz_status {
        "swap.created" => None,
        "transaction.mempool" => Some(db::ChainSwapProviderStatusInput::UserLockMempool),
        "transaction.confirmed" => Some(db::ChainSwapProviderStatusInput::UserLockConfirmed),
        "transaction.server.mempool" => Some(db::ChainSwapProviderStatusInput::ServerLockMempool),
        "transaction.server.confirmed" => {
            Some(db::ChainSwapProviderStatusInput::ServerLockConfirmed)
        }
        // NOTE: `swap.expired` is deliberately NOT mapped to terminal `Expired`.
        // It is the wall-clock swap timer, not the on-chain lockup timeout — the
        // server lockup stays claimable until timeoutBlockHeight. It is handled
        // in `handle_chain_swap_webhook` (flip cooperative_refused, keep
        // sweepable) so we don't abandon a still-claimable lockup.
        // 0-conf rejection is NOT a failure: Boltz just wants a confirmation
        // before proceeding, then the swap continues normally. Treat it as a
        // (re)sighting of the user lockup in the mempool — previously this was
        // terminalized as `lockup_failed`, killing a payment that would settle.
        "transaction.zeroconf.rejected" => Some(db::ChainSwapProviderStatusInput::UserLockMempool),
        "swap.expired" => Some(db::ChainSwapProviderStatusInput::SwapExpired),
        // Renegotiation runs before a lockup-failure observation can authorize
        // recovery, so the first atomic fold is read-only. An explicit decline
        // is folded as FundingFailed afterward.
        "transaction.lockupFailed" | "transaction.claimed" => {
            Some(db::ChainSwapProviderStatusInput::Observe)
        }
        "transaction.failed" | "transaction.refunded" => {
            Some(db::ChainSwapProviderStatusInput::FundingFailed)
        }
        _ => None,
    }
}

struct ClaimAttemptContext<'a> {
    pool: &'a sqlx::PgPool,
    claim_clients: Option<&'a LiquidClaimClientFactory>,
    boltz_url: &'a str,
    max_claim_attempts: i32,
    utxo_backend: Option<&'a Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_runtime: &'a FeeRuntime,
}

impl<'a> ClaimAttemptContext<'a> {
    fn from_state(state: &'a AppState) -> Self {
        Self {
            pool: &state.db,
            claim_clients: state.liquid_claim_client_factory.as_deref(),
            boltz_url: &state.config.boltz.api_url,
            max_claim_attempts: state.config.claim.max_claim_attempts,
            utxo_backend: state.utxo_backend.as_ref(),
            tolerances: db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
            fee_runtime: state.fee_runtime.as_ref(),
        }
    }
}

async fn try_claim_chain_swap_with_retry(
    swap: &db::ChainSwapRecord,
    context: ClaimAttemptContext<'_>,
) {
    let fee_decision = context
        .fee_runtime
        .liquid_construction_decision_now(FeeConstructionPurpose::ChainLiquidClaim)
        .ok();
    match claim_chain_swap(
        context.pool,
        swap.id,
        context.claim_clients,
        context.boltz_url,
        context.max_claim_attempts,
        context.utxo_backend,
        context.tolerances,
        fee_decision.as_ref().map(|(decision, _)| decision),
        fee_decision.as_ref().map(|(_, record)| record),
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
        Ok(ClaimOutcome::PendingFeeUnavailable { reason }) => {
            tracing::info!(
                swap_id = %swap.boltz_swap_id,
                reason,
                "webhook chain-swap claim remains pending"
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
    /// No accepted live or recent same-rail Liquid fee decision exists. No
    /// bytes or retry-failure state were written; a later sweep may retry.
    PendingFeeUnavailable { reason: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimFailureScope {
    Local,
    Systemic,
}

/// Health of one rail-specific claimer sweep. A malformed persisted
/// obligation must remain isolated, while database and provider-wide failures
/// make the worker cycle unhealthy for admission hysteresis.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ClaimCycleHealth {
    systemic_failure: bool,
}

impl ClaimCycleHealth {
    fn observe_error(&mut self, error: &AppError) {
        if classify_claim_failure(error) == ClaimFailureScope::Systemic {
            self.systemic_failure = true;
        }
    }

    fn report(self, reporter: &WorkerReporter) {
        if self.systemic_failure {
            reporter.cycle_failed();
        } else {
            reporter.cycle_succeeded();
        }
    }
}

fn classify_claim_failure(error: &AppError) -> ClaimFailureScope {
    match error {
        AppError::DbError(_) | AppError::ElectrumError(_) | AppError::BoltzError(_) => {
            ClaimFailureScope::Systemic
        }
        AppError::ClaimError(message) => {
            if is_cooperative_refusal(error) || is_local_claim_error(message) {
                ClaimFailureScope::Local
            } else {
                // Unknown claim-path errors fail closed. Known malformed-data and
                // business-local shapes are enumerated below; the remaining
                // errors are connection, provider, construction, or broadcast
                // failures shared by the worker's operating environment.
                ClaimFailureScope::Systemic
            }
        }
        _ => ClaimFailureScope::Local,
    }
}

fn is_local_claim_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "swap_records row gone:",
        "swap not found:",
        "chain swap not found:",
        "invoice not found:",
        "user not found:",
        "address allocation failed:",
        "address index overflow",
        "decode persisted",
        "missing ",
        "invalid ",
        "swap script build failed:",
        "chain claim script build failed:",
        "chain lockup script build failed:",
    ]
    .iter()
    .any(|prefix| message.starts_with(prefix))
        || message.contains(" has no ")
        || message.contains(" no nym and no invoice ")
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
async fn try_claim_with_retry(swap: &db::SwapRecord, context: ClaimAttemptContext<'_>) {
    let fee_decision = context
        .fee_runtime
        .liquid_construction_decision_now(FeeConstructionPurpose::ReverseLiquidClaim)
        .ok();
    match claim_swap(
        context.pool,
        swap.id,
        context.claim_clients,
        context.boltz_url,
        context.max_claim_attempts,
        context.utxo_backend,
        context.tolerances,
        fee_decision.as_ref().map(|(decision, _)| decision),
        fee_decision.as_ref().map(|(_, record)| record),
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
        Ok(ClaimOutcome::PendingFeeUnavailable { reason }) => {
            tracing::info!(
                swap_id = %swap.boltz_swap_id,
                reason,
                "webhook reverse-swap claim remains pending"
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
/// Runs inside the caller's locked claim-preparation transaction. The
/// `SELECT ... FOR UPDATE` serializes concurrent webhook deliveries (e.g.
/// transaction.mempool followed by transaction.confirmed) so they cannot
/// double-allocate or split addresses, without checking out another pool
/// connection while the advisory-lock connection is already held.
async fn resolve_claim_address(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    swap: &db::SwapRecord,
) -> Result<String, AppError> {
    // Re-read the swap row under FOR UPDATE — `swap` may be stale (the
    // caller loaded it before this call, possibly on a previous attempt).
    let row: Option<(Option<String>, Option<i32>, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT address, address_index, invoice_id FROM swap_records WHERE id = $1 FOR UPDATE",
    )
    .bind(swap.id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    let (cached_addr, _cached_idx, invoice_id) =
        row.ok_or_else(|| AppError::ClaimError(format!("swap_records row gone: {}", swap.id)))?;

    // (A) Cached destination — return as-is. Idempotent retries land on
    //     the same address regardless of how it was first resolved.
    if let Some(addr) = cached_addr {
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
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;

        let addr = inv_row.and_then(|(a,)| a).ok_or_else(|| {
            AppError::ClaimError(format!("invoice {inv_id} has no liquid_address"))
        })?;

        sqlx::query("UPDATE swap_records SET address = $1, address_index = NULL WHERE id = $2")
            .bind(&addr)
            .bind(swap.id)
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;

        tracing::info!(
            event = "lightning_swap_address_from_invoice_prepared",
            swap_id = %swap.id,
            invoice_id = %inv_id,
            "claim destination prepared from invoice.liquid_address; pending claim transaction commit"
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

    let user = db::get_user_by_nym(&mut **tx, nym)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("user not found: {nym}")))?;

    let addr_index_row: Option<(i32,)> = sqlx::query_as(
        "UPDATE users SET next_addr_idx = next_addr_idx + 1 \
         WHERE nym = $1 \
         RETURNING next_addr_idx - 1",
    )
    .bind(nym)
    .fetch_optional(&mut **tx)
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
        .execute(&mut **tx)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    tracing::info!(
        event = "lightning_swap_address_allocation_prepared",
        nym = %nym,
        swap_id = %swap.id,
        address_index = addr_index,
        "claim-time descriptor allocation prepared; pending claim transaction commit"
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
///   3. If no transaction is journaled and no accepted fee decision is
///      available, return `PendingFeeUnavailable` without allocating a
///      destination or consuming an attempt.
///   4. Resolve the claim destination address (allocates a fresh
///      descriptor index if none was set at swap creation).
///   5. If `claim_tx_hex` is set, deserialize it. Otherwise
///      `construct_claim` and persist `(claim_tx_hex, claim_txid,
///      claim_path)` in the same transaction. Mark status `claiming`.
///      Set a short in-flight lease in `next_claim_attempt_at`.
///   6. Commit (releases the advisory lock).
///   7. Broadcast the tx OUTSIDE the lock — broadcast is the slow,
///      I/O-bound step and we don't want to hold a DB connection.
///      Idempotent on Electrum.
///   8. Mark status `claimed` with the on-chain txid.
#[allow(clippy::too_many_arguments)]
async fn claim_swap(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
) -> Result<ClaimOutcome, AppError> {
    claim_swap_with_guard(
        pool,
        swap_id,
        claim_clients,
        boltz_url,
        max_claim_attempts,
        utxo_backend,
        tolerances,
        fee_decision,
        fee_record,
        false,
    )
    .await
}

/// Constrained-pool integration seam. It executes the exact production path,
/// but only while the persisted provider response is malformed and no claim
/// bytes exist, guaranteeing a local construction error before any
/// Electrum/Boltz call or broadcast.
/// Normal application code calls the private [`claim_swap`] entry point.
#[doc(hidden)]
pub async fn exercise_reverse_claim_with_malformed_response(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    fee_decision: &LiquidFeeDecision,
) -> Result<ClaimOutcome, AppError> {
    let factory = LiquidClaimClientFactory::try_new(vec!["tcp://127.0.0.1:1".to_string()])?;
    let fee_record = liquid_fee_record_for_compatibility_seam(
        FeeConstructionPurpose::ReverseLiquidClaim,
        fee_decision,
    )?;
    claim_swap_with_guard(
        pool,
        swap_id,
        Some(&factory),
        "http://127.0.0.1:1",
        20,
        None,
        db::InvoiceAccountingTolerances::default(),
        Some(fee_decision),
        Some(&fee_record),
        true,
    )
    .await
}

/// Exercise production claim preparation without a usable fee quote. This
/// seam performs no network I/O: unjournaled bytes remain pending before any
/// claim client is required.
#[doc(hidden)]
pub async fn exercise_reverse_claim_without_fee(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
) -> Result<ClaimOutcome, AppError> {
    claim_swap_with_guard(
        pool,
        swap_id,
        None,
        "http://127.0.0.1:1",
        20,
        None,
        db::InvoiceAccountingTolerances::default(),
        None,
        None,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn claim_swap_with_guard(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
    require_malformed_response: bool,
) -> Result<ClaimOutcome, AppError> {
    // Outer wrapper: records every Err uniformly via
    // `db::record_claim_failure`. Pending/skip outcomes are Ok variants and do
    // not count as failures because no construction attempt was made.
    let result = claim_swap_inner(
        pool,
        swap_id,
        claim_clients,
        boltz_url,
        utxo_backend,
        tolerances,
        fee_decision,
        fee_record,
        require_malformed_response,
    )
    .await;
    if require_malformed_response
        && matches!(
            &result,
            Err(AppError::ClaimError(message)) if message == REVERSE_TEST_GUARD_REJECTED
        )
    {
        return result;
    }
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
                    return Err(AppError::DbError(e.to_string()));
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
                return Err(AppError::DbError(db_err.to_string()));
            }
        }
    }
    result
}

/// Preserve preparation writes that were already durable before claim
/// construction in the old two-transaction flow (notably the resolved reverse
/// destination and descriptor cursor), then return the original local/provider
/// error. Cooperative-refusal callers also set their one-way flag on this
/// transaction before committing here.
async fn commit_claim_preparation_error<T>(
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    error: AppError,
) -> Result<T, AppError> {
    if let Err(commit_error) = tx.commit().await {
        tracing::error!(
            event = "claim_preparation_error_commit_failed",
            original_error = %error,
            error = %commit_error,
            "failed to commit handled claim-preparation state"
        );
        return Err(AppError::DbError(format!(
            "commit handled claim-preparation state after {error}: {commit_error}"
        )));
    }
    Err(error)
}

#[allow(clippy::too_many_arguments)]
async fn claim_swap_inner(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
    require_malformed_response: bool,
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

    let status = swap
        .parsed_status()
        .map_err(|e| AppError::ClaimError(format!("invalid persisted swap status: {e}")))?;
    if !status.is_claimable() {
        tracing::debug!("claim_swap: {} is not claimable ({})", swap_id, swap.status);
        return Ok(ClaimOutcome::AlreadyTerminal);
    }
    if require_malformed_response
        && (swap.claim_tx_hex.is_some()
            || swap.boltz_response_json.as_deref().is_some_and(|response| {
                serde_json::from_str::<CreateReverseResponse>(response).is_ok()
            }))
    {
        return Err(AppError::ClaimError(
            REVERSE_TEST_GUARD_REJECTED.to_string(),
        ));
    }

    if swap.claim_tx_hex.is_none() && (fee_decision.is_none() || fee_record.is_none()) {
        return Ok(ClaimOutcome::PendingFeeUnavailable {
            reason: LIQUID_FEE_DECISION_PENDING_REASON,
        });
    }
    let claim_clients = claim_clients.ok_or_else(|| {
        AppError::ClaimError("Liquid claim client factory is unavailable".to_string())
    })?;

    // Destination resolution uses this same transaction/connection. Returning
    // to the pool here would self-starve at max_connections=1 and can deadlock
    // a saturated pool when multiple claim preparations each hold one slot.
    let output_address = resolve_claim_address(&mut tx, &swap).await?;

    let chain = Chain::Liquid(LiquidChain::Liquid);
    let claim_tx = if let Some(hex) = swap.claim_tx_hex.as_deref() {
        // Idempotent path: a previous attempt persisted the constructed
        // tx but failed somewhere between persistence and "Claimed"
        // status. Re-broadcast THAT tx, not a fresh one.
        match BtcLikeTransaction::from_hex(chain, hex)
            .map_err(|e| AppError::ClaimError(format!("decode persisted claim_tx: {e}")))
        {
            Ok(tx) => tx,
            Err(error) => return commit_claim_preparation_error(tx, error).await,
        }
    } else {
        let fee_record = fee_record.expect("unjournaled claims require fee decision metadata");
        let fee_decision = LiquidBuilderFeeDecision::from(
            fee_decision.expect("unjournaled claims require a policy decision"),
        );
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
            claim_clients,
            boltz_url,
            &fee_decision,
            use_cooperative,
        )
        .await
        {
            Ok(tx) => tx,
            Err(e) if use_cooperative && is_cooperative_refusal(&e) => {
                // Boltz refused cooperative MuSig2 (status mismatch,
                // bad preimage, or operator-disabled). Flip the flag
                // so the next sweep tick takes the script path. The flag and
                // any newly resolved destination must commit before this
                // attempt returns the refusal to the retry wrapper.
                tracing::warn!(
                    event = "swap_cooperative_refused_runtime",
                    swap_id = %swap.boltz_swap_id,
                    error = %e,
                    "boltz refused cooperative claim; flipping cooperative_refused for next attempt"
                );
                db::mark_cooperative_refused(&mut *tx, swap.id)
                    .await
                    .map_err(|db_error| AppError::DbError(db_error.to_string()))?;
                return commit_claim_preparation_error(tx, e).await;
            }
            Err(e) => return commit_claim_preparation_error(tx, e).await,
        };
        let (actual_fee_sat, actual_fee_rate_sat_vb) = liquid_actual_fee(&constructed)?;
        let quoted_at = checked_fee_i64(
            "claim_fee_decision_quoted_at_unix",
            fee_record.quoted_at_unix(),
        )?;
        let evaluated_at = checked_fee_i64(
            "claim_fee_decision_evaluated_at_unix",
            fee_record.evaluated_at_unix(),
        )?;
        let freshness_age = checked_fee_i64(
            "claim_fee_decision_freshness_age_secs",
            fee_record.freshness_age_secs(),
        )?;
        let freshness_max_age = checked_fee_i64(
            "claim_fee_decision_freshness_max_age_secs",
            fee_record.freshness_max_age_secs(),
        )?;
        let hex = match serialize_claim_tx_hex(&constructed) {
            Ok(hex) => hex,
            Err(error) => return commit_claim_preparation_error(tx, error).await,
        };
        let txid = btc_like_txid(&constructed);
        let claim_path = if use_cooperative {
            "cooperative"
        } else {
            "script"
        };
        // `WHERE claim_tx_hex IS NULL` makes this a no-op if a concurrent
        // attempt persisted first (defensive — the advisory lock should
        // have prevented this; the guard is there to fail closed).
        let persisted = sqlx::query(
            "UPDATE swap_records \
             SET claim_tx_hex = $2, claim_txid = $3, claim_path = $4, \
                 claim_actual_fee_sat = $5, claim_actual_fee_rate_sat_vb = $6, \
                 claim_fee_decision_purpose = $7, claim_fee_decision_rail = $8, \
                 claim_fee_decision_target = $9, claim_fee_decision_source = $10, \
                 claim_fee_decision_rate_sat_vb = $11, \
                 claim_fee_decision_quoted_at_unix = $12, \
                 claim_fee_decision_evaluated_at_unix = $13, \
                 claim_fee_decision_freshness_age_secs = $14, \
                 claim_fee_decision_freshness_max_age_secs = $15, \
                 claim_fee_decision_provenance = $16, \
                 claim_fee_decision_policy_floor_sat_vb = $17, \
                 claim_fee_decision_policy_cap_sat_vb = $18, \
                 claim_fee_decision_policy_version = $19 \
             WHERE id = $1 AND claim_tx_hex IS NULL",
        )
        .bind(swap.id)
        .bind(&hex)
        .bind(&txid)
        .bind(claim_path)
        .bind(actual_fee_sat)
        .bind(actual_fee_rate_sat_vb)
        .bind(fee_record.purpose().as_str())
        .bind(fee_record.rail().as_str())
        .bind(fee_record.target().as_str())
        .bind(fee_record.source().as_str())
        .bind(fee_record.rate().as_f64())
        .bind(quoted_at)
        .bind(evaluated_at)
        .bind(freshness_age)
        .bind(freshness_max_age)
        .bind(fee_record.provenance_for_persistence())
        .bind(fee_record.policy_floor().as_f64())
        .bind(fee_record.policy_cap().as_f64())
        .bind(fee_record.policy_version())
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
        if persisted.rows_affected() != 1 {
            return Err(AppError::DbError(format!(
                "reverse claim preparation lost its locked row: {}",
                swap.id
            )));
        }
        constructed
    };

    // Status -> Claiming. The retry timestamp doubles as an in-flight
    // lease: webhook/reconciler/background races must wait for this
    // deadline before rebroadcasting the persisted transaction.
    let marked_claiming = sqlx::query(
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
    if marked_claiming.rows_affected() != 1 {
        return Err(AppError::DbError(format!(
            "reverse claim preparation could not publish claiming state: {}",
            swap.id
        )));
    }

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
    let liquid_client = claim_clients.connect().await?;
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

#[allow(clippy::too_many_arguments)]
async fn claim_chain_swap(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
) -> Result<ClaimOutcome, AppError> {
    claim_chain_swap_with_guard(
        pool,
        chain_swap_id,
        claim_clients,
        boltz_url,
        max_claim_attempts,
        utxo_backend,
        tolerances,
        fee_decision,
        fee_record,
        false,
    )
    .await
}

/// Constrained-pool integration seam for chain claims. The persisted provider
/// response must be malformed and no claim bytes may exist, guaranteeing that
/// the exact production path fails locally before Electrum/Boltz I/O or
/// broadcast.
#[doc(hidden)]
pub async fn exercise_chain_claim_with_malformed_response(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    fee_decision: &LiquidFeeDecision,
) -> Result<ClaimOutcome, AppError> {
    let factory = LiquidClaimClientFactory::try_new(vec!["tcp://127.0.0.1:1".to_string()])?;
    let fee_record = liquid_fee_record_for_compatibility_seam(
        FeeConstructionPurpose::ChainLiquidClaim,
        fee_decision,
    )?;
    claim_chain_swap_with_guard(
        pool,
        chain_swap_id,
        Some(&factory),
        "http://127.0.0.1:1",
        20,
        None,
        db::InvoiceAccountingTolerances::default(),
        Some(fee_decision),
        Some(&fee_record),
        true,
    )
    .await
}

/// Exercise production chain-claim preparation without a usable fee quote.
/// Unjournaled bytes remain pending before any network client is required.
#[doc(hidden)]
pub async fn exercise_chain_claim_without_fee(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
) -> Result<ClaimOutcome, AppError> {
    claim_chain_swap_with_guard(
        pool,
        chain_swap_id,
        None,
        "http://127.0.0.1:1",
        20,
        None,
        db::InvoiceAccountingTolerances::default(),
        None,
        None,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn claim_chain_swap_with_guard(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
    require_malformed_response: bool,
) -> Result<ClaimOutcome, AppError> {
    let result = claim_chain_swap_inner(
        pool,
        chain_swap_id,
        claim_clients,
        boltz_url,
        utxo_backend,
        tolerances,
        fee_decision,
        fee_record,
        require_malformed_response,
    )
    .await;
    if require_malformed_response
        && matches!(
            &result,
            Err(AppError::ClaimError(message)) if message == CHAIN_TEST_GUARD_REJECTED
        )
    {
        return result;
    }
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
                let row = db::get_chain_swap_by_id(pool, chain_swap_id)
                    .await
                    .map_err(|db_error| AppError::DbError(db_error.to_string()))?;
                if let Some(row) = row {
                    db::mark_invoice_settlement_status(pool, Some(row.invoice_id), "claim_stuck")
                        .await
                        .map_err(|e| {
                            tracing::error!(
                                event = "invoice_chain_swap_claim_stuck_mark_failed",
                                swap_id = %chain_swap_id,
                                "failed to mark invoice settlement_status=claim_stuck: {e}"
                            );
                            AppError::DbError(e.to_string())
                        })?;
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
                return Err(AppError::DbError(db_err.to_string()));
            }
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn claim_chain_swap_inner(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
    require_malformed_response: bool,
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

    let swap = db::get_chain_swap_by_id_for_update(&mut *tx, chain_swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("chain swap not found: {chain_swap_id}")))?;
    swap.verify_creation_response_integrity()
        .map_err(AppError::ClaimError)?;

    let status = swap
        .parsed_status()
        .map_err(|e| AppError::ClaimError(format!("invalid persisted chain status: {e}")))?;
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
    if require_malformed_response
        && (swap.claim_tx_hex.is_some()
            || serde_json::from_str::<CreateChainResponse>(&swap.boltz_response_json).is_ok())
    {
        return Err(AppError::ClaimError(CHAIN_TEST_GUARD_REJECTED.to_string()));
    }

    if swap.claim_tx_hex.is_none() && (fee_decision.is_none() || fee_record.is_none()) {
        return Ok(ClaimOutcome::PendingFeeUnavailable {
            reason: LIQUID_FEE_DECISION_PENDING_REASON,
        });
    }
    let claim_clients = claim_clients.ok_or_else(|| {
        AppError::ClaimError("Liquid claim client factory is unavailable".to_string())
    })?;

    // Post-051 swaps claim only to the immutable destination committed before
    // the payer saw the Bitcoin address. Never re-resolve it through the
    // mutable invoice relationship. Historical rows have no creation packet,
    // so they retain the explicit legacy fallback.
    let output_address = if let Some(terms) = swap.creation_terms.as_ref() {
        validated_chain_creation_destination(terms)?
    } else {
        let invoice = db::get_invoice_by_id(&mut *tx, swap.invoice_id)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?
            .ok_or_else(|| {
                AppError::ClaimError(format!("invoice not found: {}", swap.invoice_id))
            })?;
        invoice.liquid_address.ok_or_else(|| {
            AppError::ClaimError(format!(
                "legacy invoice {} has no liquid_address for chain-swap claim",
                swap.invoice_id
            ))
        })?
    };

    let claim_tx = if let Some(hex) = swap.claim_tx_hex.as_deref() {
        match BtcLikeTransaction::from_hex(Chain::Liquid(LiquidChain::Liquid), hex)
            .map_err(|e| AppError::ClaimError(format!("decode persisted chain claim_tx: {e}")))
        {
            Ok(tx) => tx,
            Err(error) => return commit_claim_preparation_error(tx, error).await,
        }
    } else {
        let fee_record =
            fee_record.expect("unjournaled chain claims require fee decision metadata");
        let fee_decision = LiquidBuilderFeeDecision::from(
            fee_decision.expect("unjournaled chain claims require a policy decision"),
        );
        // Cooperative MuSig2 claim by default; script-path (preimage) claim once
        // `cooperative_refused` is set — by the `swap.expired` webhook or a prior
        // runtime refusal below. One-way flag, so no cooperative/script ping-pong.
        // Mirrors claim_swap_inner (reverse path).
        let use_cooperative = !swap.cooperative_refused;
        let constructed = match construct_chain_claim_tx(
            &swap,
            &output_address,
            claim_clients,
            boltz_url,
            &fee_decision,
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
                db::mark_chain_swap_cooperative_refused(&mut *tx, swap.id)
                    .await
                    .map_err(|db_error| AppError::DbError(db_error.to_string()))?;
                return commit_claim_preparation_error(tx, e).await;
            }
            Err(e) => return commit_claim_preparation_error(tx, e).await,
        };
        let (actual_fee_sat, actual_fee_rate_sat_vb) = liquid_actual_fee(&constructed)?;
        let quoted_at = checked_fee_i64(
            "claim_fee_decision_quoted_at_unix",
            fee_record.quoted_at_unix(),
        )?;
        let evaluated_at = checked_fee_i64(
            "claim_fee_decision_evaluated_at_unix",
            fee_record.evaluated_at_unix(),
        )?;
        let freshness_age = checked_fee_i64(
            "claim_fee_decision_freshness_age_secs",
            fee_record.freshness_age_secs(),
        )?;
        let freshness_max_age = checked_fee_i64(
            "claim_fee_decision_freshness_max_age_secs",
            fee_record.freshness_max_age_secs(),
        )?;
        let hex = match serialize_claim_tx_hex(&constructed) {
            Ok(hex) => hex,
            Err(error) => return commit_claim_preparation_error(tx, error).await,
        };
        let txid = btc_like_txid(&constructed);
        let persisted = sqlx::query(
            "UPDATE chain_swap_records \
             SET claim_tx_hex = $2, claim_txid = $3, \
                 claim_actual_fee_sat = $4, claim_actual_fee_rate_sat_vb = $5, \
                 claim_fee_decision_purpose = $6, claim_fee_decision_rail = $7, \
                 claim_fee_decision_target = $8, claim_fee_decision_source = $9, \
                 claim_fee_decision_rate_sat_vb = $10, \
                 claim_fee_decision_quoted_at_unix = $11, \
                 claim_fee_decision_evaluated_at_unix = $12, \
                 claim_fee_decision_freshness_age_secs = $13, \
                 claim_fee_decision_freshness_max_age_secs = $14, \
                 claim_fee_decision_provenance = $15, \
                 claim_fee_decision_policy_floor_sat_vb = $16, \
                 claim_fee_decision_policy_cap_sat_vb = $17, \
                 claim_fee_decision_policy_version = $18 \
             WHERE id = $1 AND claim_tx_hex IS NULL",
        )
        .bind(swap.id)
        .bind(&hex)
        .bind(&txid)
        .bind(actual_fee_sat)
        .bind(actual_fee_rate_sat_vb)
        .bind(fee_record.purpose().as_str())
        .bind(fee_record.rail().as_str())
        .bind(fee_record.target().as_str())
        .bind(fee_record.source().as_str())
        .bind(fee_record.rate().as_f64())
        .bind(quoted_at)
        .bind(evaluated_at)
        .bind(freshness_age)
        .bind(freshness_max_age)
        .bind(fee_record.provenance_for_persistence())
        .bind(fee_record.policy_floor().as_f64())
        .bind(fee_record.policy_cap().as_f64())
        .bind(fee_record.policy_version())
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
        if persisted.rows_affected() != 1 {
            return Err(AppError::DbError(format!(
                "chain claim preparation lost its locked row: {}",
                swap.id
            )));
        }
        constructed
    };

    let marked_claiming = sqlx::query(
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
    if marked_claiming.rows_affected() != 1 {
        return Err(AppError::DbError(format!(
            "chain claim preparation could not publish claiming state: {}",
            swap.id
        )));
    }

    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    let liquid_client = claim_clients.connect().await?;
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
    claim_clients: &LiquidClaimClientFactory,
    boltz_url: &str,
    fee_decision: &LiquidBuilderFeeDecision,
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
    let liquid_client = claim_clients.connect().await?;
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
        fee: liquid_claim_fee(fee_decision, cooperative),
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
    claim_clients: &LiquidClaimClientFactory,
    boltz_url: &str,
    fee_decision: &LiquidBuilderFeeDecision,
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

    let liquid_client = claim_clients.connect().await?;
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
        fee: liquid_claim_fee(fee_decision, use_cooperative),
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
///     before this runs. Exact signed bytes and intent commit in the same
///     transaction as the single-winner `refunding` flip. A failed or ambiguous
///     broadcast remains there and only those committed bytes may be replayed.
///
/// Construction and journaling happen under the advisory transaction lock;
/// broadcast happens after commit without holding a database connection.
/// Returns true if the chain-swap USER lockup transaction is CONFIRMED on-chain.
///
/// The confirmation is checked by TXID, not by address: the deployment's esplora
/// runs without an address/script-hash index (address endpoints error), but
/// txid + block endpoints work. So we ask Boltz for the lockup funding txid
/// (`/swap/chain/{id}/transactions` -> userLock.transaction.id) and then query
/// the esplora `/tx/{txid}/status`. An observed unconfirmed transaction is
/// `Ok(false)`; an unavailable provider is a typed backend error so worker
/// health cannot mistake an outage for a healthy deferral.
async fn chain_lockup_confirmed(
    boltz_url: &str,
    esploras: &[String],
    swap_id: &str,
) -> Result<bool, AppError> {
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
        Err(error) => {
            return Err(AppError::BoltzError(format!(
                "build recovery confirmation client: {error}"
            )))
        }
    };
    let txs_url = format!(
        "{}/swap/chain/{}/transactions",
        boltz_url.trim_end_matches('/'),
        swap_id
    );
    let response = client.get(&txs_url).send().await.map_err(|error| {
        AppError::BoltzError(format!("fetch recovery lockup transaction: {error}"))
    })?;
    if !response.status().is_success() {
        return Err(AppError::BoltzError(format!(
            "fetch recovery lockup transaction returned HTTP {}",
            response.status()
        )));
    }
    let txid = match response.json::<ChainTxs>().await {
        Ok(c) => c.user_lock.transaction.id,
        Err(error) => {
            return Err(AppError::BoltzError(format!(
                "decode recovery lockup transaction: {error}"
            )))
        }
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
        .ok_or_else(|| {
            AppError::ElectrumError(format!(
                "Bitcoin lockup confirmation is unavailable for {txid}"
            ))
        })
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
    let bitcoin_recovery_backend = state.bitcoin_recovery_backend.as_deref().ok_or_else(|| {
        AppError::ElectrumError("Bitcoin recovery evidence client is unavailable".into())
    })?;
    match chain_lockup_confirmed(
        &state.config.boltz.api_url,
        bitcoin_recovery_backend.endpoints(),
        &swap.boltz_swap_id,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
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
        Err(error) => return Err(error),
    }

    tracing::warn!(
        event = "chain_swap_refunding",
        swap_id = %swap.boltz_swap_id,
        invoice_id = %swap.invoice_id,
        refund_address = %refund_address,
        "journaled Bitcoin recovery starting (operator P2)"
    );

    crate::chain_recovery::execute_journaled_recovery(state, swap.id).await
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
        || s.contains("not eligible for a cooperative claim")
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

/// Retained, process-local witness for the exact Liquid claim client path.
///
/// The underlying Boltz Electrum client owns a socket and is intentionally
/// created per operation, so it cannot live in [`AppState`]. This factory is
/// the initialized hard fact instead: it validates and retains the immutable
/// failover configuration used by every claim construction and broadcast.
/// Reachability remains transient worker evidence and is checked by
/// [`connect`](Self::connect), never promoted to a permanent hard failure.
#[derive(Debug)]
pub struct LiquidClaimClientFactory {
    urls: Vec<String>,
}

impl LiquidClaimClientFactory {
    pub fn try_new(urls: Vec<String>) -> Result<Self, AppError> {
        let urls: Vec<String> = urls
            .into_iter()
            .filter(|url| crate::config::valid_electrum_endpoint(url))
            .collect();
        if urls.is_empty() {
            return Err(AppError::ClaimError(
                "no valid Liquid claim client endpoint is configured".to_string(),
            ));
        }
        Ok(Self { urls })
    }

    #[cfg(test)]
    fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Connect a Liquid Electrum client for the claim/broadcast path, trying
    /// each validated URL until one connects and answers a cheap probe — the
    /// same provider failover the UtxoBackend pool already has (#47).
    async fn connect(&self) -> Result<ElectrumLiquidClient, AppError> {
        connect_liquid_electrum(&self.urls).await
    }
}

async fn connect_liquid_electrum(urls: &[String]) -> Result<ElectrumLiquidClient, AppError> {
    let mut errors: Vec<String> = Vec::new();
    for (i, url) in urls.iter().enumerate() {
        let tls = url.starts_with("ssl://");
        let client = match ElectrumLiquidClient::new(
            LiquidChain::Liquid,
            electrum_host_port(url),
            tls,
            tls,
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

fn liquid_actual_fee(tx: &BtcLikeTransaction) -> Result<(i64, f64), AppError> {
    let BtcLikeTransaction::Liquid(transaction) = tx else {
        return Err(AppError::ClaimError(
            "Liquid claim builder returned a non-Liquid transaction".into(),
        ));
    };
    let mut fee_outputs = transaction.output.iter().filter(|output| output.is_fee());
    let fee_output = fee_outputs.next().ok_or_else(|| {
        AppError::ClaimError("constructed Liquid claim has no explicit fee output".into())
    })?;
    if fee_outputs.next().is_some() {
        return Err(AppError::ClaimError(
            "constructed Liquid claim has multiple fee outputs".into(),
        ));
    }
    match fee_output.asset {
        boltz_elements::confidential::Asset::Explicit(asset)
            if asset == boltz_elements::AssetId::LIQUID_BTC => {}
        _ => {
            return Err(AppError::ClaimError(
                "constructed Liquid claim fee is not explicit L-BTC".into(),
            ))
        }
    }
    let fee_sat = match fee_output.value {
        boltz_elements::confidential::Value::Explicit(value) if value > 0 => value,
        _ => {
            return Err(AppError::ClaimError(
                "constructed Liquid claim fee is not a positive explicit value".into(),
            ))
        }
    };
    // Liquid claims are constructed through boltz-client with
    // `is_discount_ct = true`, so the relative fee is applied to Elements'
    // discounted confidential-transaction virtual size. Record the actual
    // effective rate on that same basis.
    let vsize = transaction.discount_vsize();
    if vsize == 0 {
        return Err(AppError::ClaimError(
            "constructed Liquid claim has zero discounted virtual size".into(),
        ));
    }
    let fee_sat_i64 = i64::try_from(fee_sat)
        .map_err(|_| AppError::ClaimError("Liquid claim fee exceeds BIGINT storage".into()))?;
    Ok((fee_sat_i64, fee_sat as f64 / vsize as f64))
}

fn checked_fee_i64(field: &'static str, value: u64) -> Result<i64, AppError> {
    i64::try_from(value)
        .map_err(|_| AppError::ClaimError(format!("{field} exceeds BIGINT storage")))
}

fn liquid_fee_record_for_compatibility_seam(
    purpose: FeeConstructionPurpose,
    decision: &LiquidFeeDecision,
) -> Result<FeeDecisionRecord, AppError> {
    let evaluated_at_unix =
        match decision.freshness() {
            FeeFreshness::Fresh { age_secs, .. } => decision
                .observed_at_unix()
                .checked_add(age_secs)
                .ok_or_else(|| AppError::ClaimError("fee decision clock overflow".into()))?,
            _ => {
                return Err(AppError::ClaimError(
                    LIQUID_FEE_DECISION_PENDING_REASON.into(),
                ))
            }
        };
    FeeDecisionRecord::from_liquid(
        purpose,
        decision,
        &LiquidFeePolicy::default(),
        evaluated_at_unix,
    )
    .map_err(|error| AppError::ClaimError(format!("invalid Liquid fee decision record: {error}")))
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

#[derive(Debug, Default)]
struct ClaimClientStartup {
    initialized: bool,
}

impl ClaimClientStartup {
    /// Returns `true` only for the call that first proves initialization.
    /// Once latched, the probe closure is never invoked again.
    async fn ensure_initialized<F, Fut>(&mut self, probe: F) -> Result<bool, AppError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), AppError>>,
    {
        if self.initialized {
            return Ok(false);
        }
        probe().await?;
        self.initialized = true;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;

/// Owned runtime dependencies for the long-lived reverse and chain claim
/// sweeps. Worker health reporters are grouped separately because they are
/// mutable rail-local state, not claim-construction capabilities.
pub struct BackgroundClaimerDependencies {
    pool: sqlx::PgPool,
    config: Arc<Config>,
    claim_clients: Option<Arc<LiquidClaimClientFactory>>,
    utxo_backend: Option<Arc<dyn UtxoBackend>>,
    fee_runtime: Arc<FeeRuntime>,
    cancel: CancellationToken,
}

impl BackgroundClaimerDependencies {
    pub fn new(
        pool: sqlx::PgPool,
        config: Arc<Config>,
        claim_clients: Option<Arc<LiquidClaimClientFactory>>,
        utxo_backend: Option<Arc<dyn UtxoBackend>>,
        fee_runtime: Arc<FeeRuntime>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            pool,
            config,
            claim_clients,
            utxo_backend,
            fee_runtime,
            cancel,
        }
    }
}

/// Rail-local admission reporters consumed by the background claimer task.
pub struct BackgroundClaimerReporters {
    reverse: WorkerReporter,
    chain: WorkerReporter,
}

impl BackgroundClaimerReporters {
    pub fn new(reverse: WorkerReporter, chain: WorkerReporter) -> Self {
        Self { reverse, chain }
    }
}

pub fn spawn_background_claimer(
    dependencies: BackgroundClaimerDependencies,
    reporters: BackgroundClaimerReporters,
) -> tokio::task::JoinHandle<()> {
    let BackgroundClaimerDependencies {
        pool,
        config,
        claim_clients,
        utxo_backend,
        fee_runtime,
        cancel,
    } = dependencies;
    let BackgroundClaimerReporters {
        reverse: mut reverse_reporter,
        chain: mut chain_reporter,
    } = reporters;
    tokio::spawn(async move {
        let mut first_reverse_run = true;
        let mut claim_client_startup = ClaimClientStartup::default();
        // Heartbeat counter. Log liveness every N ticks so "is the
        // background claimer running?" is a grep-able question, not a
        // process-tree archaeology one. At 10s/tick x 30 ticks, that's
        // every 5 minutes — same cadence as the rate-limit GC.
        const HEARTBEAT_EVERY_N_TICKS: u32 = 30;
        let mut tick_count: u32 = 0;
        loop {
            // The factory is the immutable hard capability, but #68 also
            // requires this process to prove the exact socket/client path
            // before an empty DB scan may open swap admission. Probe once;
            // transient startup failures stay under worker hysteresis and are
            // retried, while later operation failures are observed by the
            // ordinary claim cycles.
            if let Some(factory) = claim_clients.as_deref() {
                match claim_client_startup
                    .ensure_initialized(|| async {
                        let client = factory.connect().await?;
                        drop(client);
                        Ok(())
                    })
                    .await
                {
                    Ok(initialized_now) => {
                        if initialized_now {
                            tracing::info!(
                                event = "liquid_claim_client_initialized",
                                "Liquid claim client path initialized for this process"
                            );
                        }
                    }
                    Err(error) => {
                        reverse_reporter.cycle_failed();
                        chain_reporter.cycle_failed();
                        tracing::warn!(
                            event = "liquid_claim_client_startup_failed",
                            error = %error,
                            "Liquid claim client initialization failed; retrying"
                        );
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                reverse_reporter.intentional_shutdown();
                                chain_reporter.intentional_shutdown();
                                return;
                            }
                            _ = tokio::time::sleep(Duration::from_secs(CLAIM_SWEEP_INTERVAL_SECS)) => {}
                        }
                        continue;
                    }
                }
            }

            tick_count = tick_count.wrapping_add(1);
            let mut ready_count = 0;
            match db::get_ready_to_claim_swaps(&pool).await {
                Ok(ready) => {
                    ready_count = ready.len();
                    let mut health = ClaimCycleHealth::default();
                    if !ready.is_empty() {
                        if first_reverse_run {
                            tracing::info!(
                                "background claimer: found {} unclaimed swaps on startup",
                                ready.len()
                            );
                        }
                        for swap in &ready {
                            reverse_reporter.progress();
                            let fee_decision = fee_runtime
                                .liquid_construction_decision_now(
                                    FeeConstructionPurpose::ReverseLiquidClaim,
                                )
                                .ok();
                            match claim_swap(
                                &pool,
                                swap.id,
                                claim_clients.as_deref(),
                                &config.boltz.api_url,
                                config.claim.max_claim_attempts,
                                utxo_backend.as_ref(),
                                db::InvoiceAccountingTolerances::from(&config.invoice_accounting),
                                fee_decision.as_ref().map(|(decision, _)| decision),
                                fee_decision.as_ref().map(|(_, record)| record),
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
                                Ok(ClaimOutcome::PendingFeeUnavailable { reason }) => {
                                    tracing::info!(
                                        swap_id = %swap.boltz_swap_id,
                                        reason,
                                        "background claimer: reverse swap remains pending"
                                    );
                                }
                                Err(e) => {
                                    health.observe_error(&e);
                                    tracing::warn!(
                                        "background claimer: swap {}: {e}",
                                        swap.boltz_swap_id
                                    );
                                }
                            }
                        }
                    } else if first_reverse_run {
                        tracing::info!("background claimer: no unclaimed swaps found");
                    }
                    health.report(&reverse_reporter);
                    first_reverse_run = false;
                }
                Err(e) => {
                    tracing::error!("background claimer: db query failed: {e}");
                    reverse_reporter.cycle_failed();
                }
            }

            let mut ready_chain_count = 0;
            match db::get_ready_to_claim_chain_swaps(&pool).await {
                Ok(ready_chain) => {
                    ready_chain_count = ready_chain.len();
                    let mut health = ClaimCycleHealth::default();
                    if !ready_chain.is_empty() {
                        tracing::info!(
                            "background claimer: found {} chain swap(s) ready to claim",
                            ready_chain.len()
                        );
                        for swap in &ready_chain {
                            chain_reporter.progress();
                            let fee_decision = fee_runtime
                                .liquid_construction_decision_now(
                                    FeeConstructionPurpose::ChainLiquidClaim,
                                )
                                .ok();
                            match claim_chain_swap(
                                &pool,
                                swap.id,
                                claim_clients.as_deref(),
                                &config.boltz.api_url,
                                config.claim.max_claim_attempts,
                                utxo_backend.as_ref(),
                                db::InvoiceAccountingTolerances::from(&config.invoice_accounting),
                                fee_decision.as_ref().map(|(decision, _)| decision),
                                fee_decision.as_ref().map(|(_, record)| record),
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
                                Ok(ClaimOutcome::PendingFeeUnavailable { reason }) => {
                                    tracing::info!(
                                        swap_id = %swap.boltz_swap_id,
                                        reason,
                                        "background claimer: chain swap remains pending"
                                    );
                                }
                                Err(e) => {
                                    health.observe_error(&e);
                                    tracing::warn!(
                                        "background claimer: chain swap {}: {e}",
                                        swap.boltz_swap_id
                                    );
                                }
                            }
                        }
                    }
                    health.report(&chain_reporter);
                }
                Err(e) => {
                    tracing::error!("background claimer: chain-swap db query failed: {e}");
                    chain_reporter.cycle_failed();
                }
            }

            if tick_count.is_multiple_of(HEARTBEAT_EVERY_N_TICKS) {
                tracing::info!(
                    target: "claimer",
                    event = "claimer_heartbeat",
                    tick = tick_count,
                    ready_count = ready_count,
                    ready_chain_count = ready_chain_count,
                    "background claimer heartbeat"
                );
            }

            tokio::select! {
                _ = cancel.cancelled() => {
                    reverse_reporter.intentional_shutdown();
                    chain_reporter.intentional_shutdown();
                    tracing::info!("background claimer: shutting down");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(CLAIM_SWEEP_INTERVAL_SECS)) => {}
            }
        }
    })
}

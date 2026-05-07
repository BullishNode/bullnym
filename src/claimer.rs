use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;

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
            )
            .await;
        }
        "invoice.settled" => {
            tracing::info!("invoice settled for swap {}", data.id);
        }
        "swap.expired" | "transaction.failed" => {
            // NOTE: PR #4 (state machine hardening) revisits this branch.
            // `swap.expired` should NOT terminal-state — the on-chain HTLC
            // may still be claimable until `timeoutBlockHeight`, and after
            // `swap.expired` only the script-path can recover it. For now
            // (PR #2: webhook auth only) preserve existing behavior to
            // keep the diff focused.
            db::update_swap_status(&state.db, swap.id, SwapStatus::Expired, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
        }
        _ => {
            tracing::debug!("ignoring webhook status: {}", data.status);
        }
    }

    Ok("ok")
}

async fn try_claim_with_retry(
    pool: &sqlx::PgPool,
    swap: &db::SwapRecord,
    electrum_url: &str,
    boltz_url: &str,
) {
    // Resolve the claim destination once. Swaps created post-MRH-deprecation
    // arrive with `address: None` and need a descriptor index allocated here;
    // legacy swaps already have it set from swap-creation time. The helper is
    // serialized on the swap row (FOR UPDATE) so concurrent webhook deliveries
    // do not double-allocate.
    let output_address = match resolve_claim_address(pool, swap).await {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!(
                "failed to resolve claim address for swap {}: {e}",
                swap.boltz_swap_id
            );
            db::update_swap_status(pool, swap.id, SwapStatus::ClaimFailed, None)
                .await
                .ok();
            return;
        }
    };

    for attempt in 1..=3 {
        if attempt > 1 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match claim_swap(pool, swap, &output_address, electrum_url, boltz_url).await {
            Ok(()) => return,
            Err(e) => {
                tracing::warn!(
                    "claim attempt {attempt}/3 failed for swap {}: {e}",
                    swap.boltz_swap_id
                );
            }
        }
    }
    tracing::error!(
        "all claim attempts failed for swap {}",
        swap.boltz_swap_id
    );
    db::update_swap_status(pool, swap.id, SwapStatus::ClaimFailed, None)
        .await
        .ok();
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

    let addr_index_row: Option<(i32,)> = sqlx::query_as(
        "UPDATE users SET next_addr_idx = next_addr_idx + 1 \
         WHERE nym = $1 AND is_active = TRUE \
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

async fn claim_swap(
    pool: &sqlx::PgPool,
    swap: &db::SwapRecord,
    output_address: &str,
    electrum_url: &str,
    boltz_url: &str,
) -> Result<(), AppError> {
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

    // New connection per claim — ElectrumLiquidClient wraps a TCP socket
    // and isn't Send+Sync, so it can't be shared across tasks.
    let liquid_client =
        ElectrumLiquidClient::new(LiquidChain::Liquid, electrum_url, true, true, 30)
            .map_err(|e| AppError::ClaimError(format!("electrum connection failed: {e}")))?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);
    let boltz_api = BoltzApiClientV2::new(boltz_url.to_string(), None);

    db::update_swap_status(pool, swap.id, SwapStatus::Claiming, None)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    let params = SwapTransactionParams {
        keys: keypair,
        output_address: output_address.to_string(),
        fee: Fee::Relative(0.1),
        swap_id: swap.boltz_swap_id.clone(),
        chain_client: &chain_client,
        boltz_client: &boltz_api,
        options: Some(TransactionOptions::default()),
    };

    let claim_tx = swap_script
        .construct_claim(&preimage, params)
        .await
        .map_err(|e| AppError::ClaimError(format!("construct_claim failed: {e}")))?;

    chain_client
        .try_broadcast_tx(&claim_tx)
        .await
        .map_err(|e| AppError::ClaimError(format!("broadcast failed: {e}")))?;

    let txid_str = match &claim_tx {
        BtcLikeTransaction::Liquid(tx) => tx.txid().to_string(),
        BtcLikeTransaction::Bitcoin(tx) => tx.compute_txid().to_string(),
    };
    tracing::info!("swap {} claimed: txid={}", swap.boltz_swap_id, txid_str);

    db::update_swap_status(pool, swap.id, SwapStatus::Claimed, Some(&txid_str))
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    Ok(())
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
}

pub fn spawn_background_claimer(
    pool: sqlx::PgPool,
    config: Arc<Config>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut first_run = true;
        loop {
            let unclaimed = match db::get_unclaimed_swaps(&pool).await {
                Ok(swaps) => swaps,
                Err(e) => {
                    tracing::error!("background claimer: db query failed: {e}");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(30)) => continue,
                    }
                }
            };

            if !unclaimed.is_empty() {
                if first_run {
                    tracing::info!(
                        "background claimer: found {} unclaimed swaps on startup",
                        unclaimed.len()
                    );
                }
                for swap in &unclaimed {
                    let output_address = match resolve_claim_address(&pool, swap).await {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::warn!(
                                "background claimer: address resolution failed for swap {}: {e}",
                                swap.boltz_swap_id
                            );
                            continue;
                        }
                    };
                    match claim_swap(
                        &pool,
                        swap,
                        &output_address,
                        &config.boltz.electrum_url,
                        &config.boltz.api_url,
                    )
                    .await
                    {
                        Ok(()) => {
                            tracing::info!(
                                "background claimer: claimed swap {}",
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

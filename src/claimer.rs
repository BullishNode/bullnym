use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
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
use crate::error::AppError;
use crate::ip_whitelist;
use crate::AppState;

/// HTTP header Boltz uses to authenticate its webhook deliveries.
/// Confirm at impl time against Boltz's current docs — header name has
/// historically varied (`Boltz-Hmac-Signature` / `X-Boltz-Hmac` etc.).
const BOLTZ_HMAC_HEADER: &str = "boltz-hmac-signature";

#[derive(Deserialize)]
struct WebhookEnvelope {
    data: WebhookData,
}

#[derive(Deserialize)]
struct WebhookData {
    id: String,
    status: String,
}

pub async fn webhook(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: String,
) -> Result<&'static str, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);

    // D2 #1 — per-source rate-limit gate. Independent of HMAC; bounds
    // webhook-bomb cost even if the secret leaks.
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

    // D2 #2 — HMAC verify. When the secret is empty we log loudly and
    // skip the check (legacy/dev mode). Production MUST set
    // `BOLTZ_WEBHOOK_SECRET` in `.env`.
    if state.config.boltz_webhook_secret.is_empty() {
        tracing::warn!(
            "boltz webhook: BOLTZ_WEBHOOK_SECRET unset — accepting unauthenticated payload (DEV ONLY)"
        );
    } else {
        let provided_sig = headers
            .get(BOLTZ_HMAC_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                tracing::warn!(
                    "boltz webhook: missing {} header from {:?}",
                    BOLTZ_HMAC_HEADER,
                    caller_ip
                );
                AppError::AuthError("missing webhook signature".into())
            })?;
        verify_hmac(&state.config.boltz_webhook_secret, body.as_bytes(), provided_sig)
            .map_err(|e| {
                tracing::warn!("boltz webhook: HMAC verify failed from {:?}: {e}", caller_ip);
                AppError::AuthError("invalid webhook signature".into())
            })?;
    }

    tracing::debug!("boltz webhook raw: {}", body);

    let envelope: WebhookEnvelope = serde_json::from_str(&body).map_err(|e| {
        tracing::error!("failed to parse webhook: {e}");
        AppError::ClaimError(format!("invalid webhook payload: {e}"))
    })?;
    let data = envelope.data;

    // D2 #3 — idempotency. Boltz can re-deliver the same event.
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

    let swap = db::get_swap_by_boltz_id(&state.db, &data.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| {
            tracing::warn!("webhook for unknown swap: {}", data.id);
            AppError::ClaimError(format!("unknown swap: {}", data.id))
        })?;

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
    for attempt in 1..=3 {
        if attempt > 1 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match claim_swap(pool, swap, electrum_url, boltz_url).await {
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

async fn claim_swap(
    pool: &sqlx::PgPool,
    swap: &db::SwapRecord,
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
        output_address: swap.address.clone(),
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

/// HMAC-SHA256 of `body` with `secret`, compared in constant time
/// against a hex-encoded `provided`. Returns `Err` on length mismatch,
/// hex decode failure, or signature mismatch — all indistinguishable
/// from each other to the caller (no oracle).
fn verify_hmac(secret: &str, body: &[u8], provided_hex: &str) -> Result<(), String> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    let provided = hex::decode(provided_hex).map_err(|_| "bad hex".to_string())?;
    if expected.len() != provided.len() {
        return Err("length mismatch".into());
    }
    if expected.ct_eq(&provided).into() {
        Ok(())
    } else {
        Err("signature mismatch".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_hmac_accepts_correct_signature() {
        let secret = "supersecret";
        let body = b"{\"id\":\"abc\",\"status\":\"transaction.confirmed\"}";
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        assert!(verify_hmac(secret, body, &sig).is_ok());
    }

    #[test]
    fn verify_hmac_rejects_wrong_secret() {
        let body = b"hello";
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(b"right").unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        assert!(verify_hmac("wrong", body, &sig).is_err());
    }

    #[test]
    fn verify_hmac_rejects_tampered_body() {
        let secret = "supersecret";
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(b"original");
        let sig = hex::encode(mac.finalize().into_bytes());
        assert!(verify_hmac(secret, b"tampered", &sig).is_err());
    }

    #[test]
    fn verify_hmac_rejects_garbage_hex() {
        assert!(verify_hmac("k", b"body", "not-hex").is_err());
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
                    match claim_swap(
                        &pool,
                        swap,
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

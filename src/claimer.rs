use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use serde::Deserialize;

use boltz_client::network::electrum::ElectrumLiquidClient;
use boltz_client::network::LiquidChain;
use boltz_client::network::Chain;
use boltz_client::swaps::boltz::{BoltzApiClientV2, CreateReverseResponse};
use boltz_client::swaps::{
    BtcLikeTransaction, ChainClient, SwapScript, SwapTransactionParams, TransactionOptions,
};
use boltz_client::util::fees::Fee;
use boltz_client::util::secrets::Preimage;
use boltz_client::Keypair;

use crate::config::Config;
use crate::db;
use crate::error::AppError;
use crate::AppState;

#[derive(Deserialize)]
pub struct BoltzWebhookEnvelope {
    pub data: BoltzWebhookData,
}

#[derive(Deserialize)]
pub struct BoltzWebhookData {
    pub id: String,
    pub status: String,
}

/// POST /webhook/boltz — receives status updates from Boltz.
/// On lockup events, triggers a cooperative MuSig2 claim.
pub async fn webhook(
    State(state): State<AppState>,
    body: String,
) -> Result<&'static str, AppError> {
    tracing::info!("boltz webhook raw: {}", body);

    let envelope: BoltzWebhookEnvelope = serde_json::from_str(&body)
        .map_err(|e| {
            tracing::error!("failed to parse webhook: {e}");
            AppError::ClaimError(format!("invalid webhook payload: {e}"))
        })?;
    let payload = envelope.data;

    tracing::info!("boltz webhook: swap={} status={}", payload.id, payload.status);

    let swap = db::get_swap_by_boltz_id(&state.db, &payload.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| {
            tracing::warn!("webhook for unknown swap: {}", payload.id);
            AppError::ClaimError(format!("unknown swap: {}", payload.id))
        })?;

    // Idempotency: skip swaps that have reached a terminal state
    match swap.status.as_str() {
        "claimed" | "expired" => {
            tracing::debug!("ignoring webhook for {} swap {}", swap.status, payload.id);
            return Ok("ok");
        }
        _ => {}
    }

    match payload.status.as_str() {
        "transaction.mempool" | "transaction.confirmed" => {
            let new_status = if payload.status == "transaction.mempool" {
                "lockup_mempool"
            } else {
                "lockup_confirmed"
            };
            db::update_swap_status(&state.db, swap.id, new_status, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;

            // Attempt cooperative claim with retry — electrum may not have
            // the lockup tx yet when the webhook arrives
            try_claim_with_retry(&state.db, &swap, &state.config.boltz.electrum_url, &state.config.boltz.api_url).await;
        }
        "invoice.settled" => {
            tracing::info!("invoice settled for swap {}", payload.id);
        }
        "swap.expired" | "transaction.failed" => {
            db::update_swap_status(&state.db, swap.id, "expired", None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
        }
        _ => {
            tracing::debug!("ignoring webhook status: {}", payload.status);
        }
    }

    Ok("ok")
}

/// Try to claim a swap with up to 3 attempts and 2s delay between retries.
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
    tracing::error!("all claim attempts failed for swap {}", swap.boltz_swap_id);
    db::update_swap_status(pool, swap.id, "claim_failed", None)
        .await
        .ok();
}

/// Execute a cooperative MuSig2 claim for a single swap.
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

    // Reconstruct preimage
    let preimage_bytes = hex::decode(preimage_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid preimage hex: {e}")))?;
    let preimage = Preimage::from_vec(preimage_bytes)
        .map_err(|e| AppError::ClaimError(format!("invalid preimage: {e}")))?;

    // Reconstruct keypair
    let key_bytes = hex::decode(claim_key_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid claim key hex: {e}")))?;
    let secp = boltz_client::Secp256k1::new();
    let secret_key = boltz_client::bitcoin::secp256k1::SecretKey::from_slice(&key_bytes)
        .map_err(|e| AppError::ClaimError(format!("invalid secret key: {e}")))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    // Reconstruct boltz response
    let boltz_response: CreateReverseResponse = serde_json::from_str(response_json)
        .map_err(|e| AppError::ClaimError(format!("invalid boltz response json: {e}")))?;

    let claim_public_key = boltz_client::PublicKey::new(keypair.public_key());

    // Build swap script from response
    let chain = Chain::Liquid(LiquidChain::Liquid);
    let swap_script = SwapScript::reverse_from_swap_resp(chain, &boltz_response, claim_public_key)
        .map_err(|e| AppError::ClaimError(format!("failed to build swap script: {e}")))?;

    // Build chain client for Liquid electrum
    let liquid_client =
        ElectrumLiquidClient::new(LiquidChain::Liquid, electrum_url, true, true, 30)
            .map_err(|e| AppError::ClaimError(format!("electrum connection failed: {e}")))?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);

    let boltz_api = BoltzApiClientV2::new(boltz_url.to_string(), None);

    // Mark as claiming before sharing preimage with Boltz
    db::update_swap_status(pool, swap.id, "claiming", None)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    // Construct the cooperative MuSig2 claim transaction
    let params = SwapTransactionParams {
        keys: keypair,
        output_address: swap.address.clone(),
        fee: Fee::Relative(0.1), // 0.1 sat/vB — Liquid default minrelaytxfee with ELIP-200 CT discount
        swap_id: swap.boltz_swap_id.clone(),
        chain_client: &chain_client,
        boltz_client: &boltz_api,
        options: Some(TransactionOptions::default()), // cooperative: true
    };

    let claim_tx = swap_script
        .construct_claim(&preimage, params)
        .await
        .map_err(|e| AppError::ClaimError(format!("construct_claim failed: {e}")))?;

    // Broadcast the signed claim transaction
    chain_client
        .try_broadcast_tx(&claim_tx)
        .await
        .map_err(|e| AppError::ClaimError(format!("broadcast failed: {e}")))?;

    // Extract txid from the Liquid transaction
    let txid_str = match &claim_tx {
        BtcLikeTransaction::Liquid(tx) => tx.txid().to_string(),
        BtcLikeTransaction::Bitcoin(tx) => tx.compute_txid().to_string(),
    };
    tracing::info!(
        "swap {} claimed successfully: txid={}",
        swap.boltz_swap_id,
        txid_str
    );

    db::update_swap_status(pool, swap.id, "claimed", Some(&txid_str))
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    Ok(())
}

/// Background task: periodically scans for unclaimed swaps and attempts to claim them.
/// Runs every 30 seconds. Handles both crash recovery (on first run) and retrying
/// swaps that failed during webhook-triggered claims.
pub fn spawn_background_claimer(
    pool: sqlx::PgPool,
    config: Arc<Config>,
) {
    tokio::spawn(async move {
        let mut first_run = true;
        loop {
            let unclaimed = match db::get_unclaimed_swaps(&pool).await {
                Ok(swaps) => swaps,
                Err(e) => {
                    tracing::error!("background claimer: db query failed: {e}");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
            };

            if !unclaimed.is_empty() {
                if first_run {
                    tracing::info!("background claimer: found {} unclaimed swaps on startup", unclaimed.len());
                }
                for swap in &unclaimed {
                    match claim_swap(&pool, swap, &config.boltz.electrum_url, &config.boltz.api_url).await {
                        Ok(()) => {
                            tracing::info!("background claimer: claimed swap {}", swap.boltz_swap_id);
                        }
                        Err(e) => {
                            tracing::warn!("background claimer: swap {} not claimable yet: {e}", swap.boltz_swap_id);
                        }
                    }
                }
            } else if first_run {
                tracing::info!("background claimer: no unclaimed swaps found");
            }

            first_run = false;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

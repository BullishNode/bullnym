use axum::extract::State;
use axum::Json;
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

use crate::boltz::BoltzService;
use crate::db;
use crate::error::AppError;
use crate::AppState;

#[derive(Deserialize)]
pub struct BoltzWebhook {
    pub id: String,
    pub status: String,
}

/// POST /webhook/boltz — receives status updates from Boltz.
/// On lockup events, triggers a cooperative MuSig2 claim.
pub async fn webhook(
    State(state): State<AppState>,
    Json(payload): Json<BoltzWebhook>,
) -> Result<&'static str, AppError> {
    tracing::info!("boltz webhook: swap={} status={}", payload.id, payload.status);

    let swap = db::get_swap_by_boltz_id(&state.db, &payload.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| {
            tracing::warn!("webhook for unknown swap: {}", payload.id);
            AppError::ClaimError(format!("unknown swap: {}", payload.id))
        })?;

    match payload.status.as_str() {
        "transaction.mempool" | "transaction.confirmed" => {
            // Update status
            let new_status = if payload.status == "transaction.mempool" {
                "lockup_mempool"
            } else {
                "lockup_confirmed"
            };
            db::update_swap_status(&state.db, swap.id, new_status, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;

            // Attempt cooperative claim
            if let Err(e) = claim_swap(
                &state.db,
                &swap,
                &state.config.boltz.electrum_url,
                &state.config.boltz.api_url,
            )
            .await
            {
                tracing::error!("claim failed for swap {}: {e}", payload.id);
                db::update_swap_status(&state.db, swap.id, "claim_failed", None)
                    .await
                    .ok();
            }
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
        fee: Fee::Absolute(300), // Liquid fees are minimal
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

/// Crash recovery: scan for swaps that were left in a claimable state and attempt to claim them.
pub async fn recover_unclaimed_swaps(
    pool: &sqlx::PgPool,
    _boltz_service: &BoltzService,
    electrum_url: &str,
    boltz_url: &str,
) -> Result<(), AppError> {
    let unclaimed = db::get_unclaimed_swaps(pool)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    if unclaimed.is_empty() {
        tracing::info!("crash recovery: no unclaimed swaps found");
        return Ok(());
    }

    tracing::info!(
        "crash recovery: found {} unclaimed swaps, attempting claims",
        unclaimed.len()
    );

    for swap in &unclaimed {
        match claim_swap(pool, swap, electrum_url, boltz_url).await {
            Ok(()) => {
                tracing::info!("crash recovery: claimed swap {}", swap.boltz_swap_id);
            }
            Err(e) => {
                tracing::error!(
                    "crash recovery: failed to claim swap {}: {e}",
                    swap.boltz_swap_id
                );
            }
        }
    }

    Ok(())
}

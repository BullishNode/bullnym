use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LnurlPayMetadata {
    pub callback: String,
    pub max_sendable: u64,
    pub min_sendable: u64,
    pub metadata: String,
    pub tag: String,
}

#[derive(Deserialize)]
pub struct CallbackParams {
    pub amount: u64,
}

#[derive(Serialize)]
pub struct CallbackResponse {
    pub pr: String,
    pub routes: Vec<()>,
}

fn build_metadata(nym: &str, domain: &str) -> String {
    let identifier = format!("{nym}@{domain}");
    let plain = format!("Sats for {nym}");
    serde_json::to_string(&vec![
        vec!["text/identifier", &identifier],
        vec!["text/plain", &plain],
    ])
    .expect("metadata serialization cannot fail")
}

pub async fn metadata(
    State(state): State<AppState>,
    Path(nym): Path<String>,
) -> Result<Json<LnurlPayMetadata>, AppError> {
    let user = db::get_user_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::NymNotFound(nym.clone()))?;

    if !user.is_active {
        return Err(AppError::NymNotFound(nym));
    }

    let callback = format!("https://{}/lnurlp/callback/{}", state.config.domain, nym);
    let metadata_str = build_metadata(&nym, &state.config.domain);

    Ok(Json(LnurlPayMetadata {
        callback,
        max_sendable: state.config.limits.max_sendable_msat,
        min_sendable: state.config.limits.min_sendable_msat,
        metadata: metadata_str,
        tag: "payRequest".to_string(),
    }))
}

pub async fn callback(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    Query(params): Query<CallbackParams>,
) -> Result<Json<CallbackResponse>, AppError> {
    if params.amount < state.config.limits.min_sendable_msat {
        return Err(AppError::InvalidAmount(format!(
            "minimum is {} msat",
            state.config.limits.min_sendable_msat
        )));
    }
    if params.amount > state.config.limits.max_sendable_msat {
        return Err(AppError::InvalidAmount(format!(
            "maximum is {} msat",
            state.config.limits.max_sendable_msat
        )));
    }
    if params.amount % 1000 != 0 {
        return Err(AppError::InvalidAmount(
            "amount must be a multiple of 1000 msat".to_string(),
        ));
    }

    let amount_sat = params.amount / 1000;

    let user = db::get_user_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::NymNotFound(nym.clone()))?;

    if !user.is_active {
        return Err(AppError::NymNotFound(nym.clone()));
    }

    let addr_index = db::allocate_address_index(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::NymNotFound(nym.clone()))?;

    let addr_index_u32 = u32::try_from(addr_index).map_err(|_| {
        AppError::DbError("address index overflow".to_string())
    })?;

    let address = descriptor::derive_address(&user.ct_descriptor, addr_index_u32)?;

    let swap_key_index = db::next_swap_key_index(&state.db)
        .await
        .map_err(|e| AppError::BoltzError(format!("swap key allocation failed: {e}")))?;

    let metadata_str = build_metadata(&nym, &state.config.domain);
    let description_hash_hex = hex::encode(Sha256::digest(metadata_str.as_bytes()));

    let result = state
        .boltz
        .create_reverse_swap(swap_key_index, amount_sat, &address, &description_hash_hex)
        .await?;

    let preimage_hex = hex::encode(&result.preimage);
    let claim_key_hex = hex::encode(result.claim_keypair.secret_bytes());
    let boltz_response_json = serde_json::to_string(&result.boltz_response)
        .map_err(|e| AppError::BoltzError(format!("failed to serialize boltz response: {e}")))?;

    db::record_swap(
        &state.db,
        &db::NewSwapRecord {
            nym: &nym,
            boltz_swap_id: &result.swap_id,
            address: &address,
            address_index: addr_index,
            amount_sat,
            invoice: &result.invoice,
            preimage_hex: &preimage_hex,
            claim_key_hex: &claim_key_hex,
            boltz_response_json: &boltz_response_json,
        },
    )
    .await
    .map_err(|e| AppError::DbError(format!("failed to record swap {}: {e}", result.swap_id)))?;

    Ok(Json(CallbackResponse {
        pr: result.invoice,
        routes: vec![],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_valid_json() {
        let meta = build_metadata("francis", "bullpay.ca");
        let parsed: serde_json::Value = serde_json::from_str(&meta).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn metadata_contains_identifier() {
        let meta = build_metadata("francis", "bullpay.ca");
        assert!(meta.contains("francis@bullpay.ca"));
        assert!(meta.contains("text/identifier"));
    }

    #[test]
    fn metadata_contains_plain_text() {
        let meta = build_metadata("francis", "bullpay.ca");
        assert!(meta.contains("Sats for francis"));
        assert!(meta.contains("text/plain"));
    }

    #[test]
    fn metadata_has_two_entries() {
        let meta = build_metadata("test", "example.com");
        let parsed: Vec<Vec<String>> = serde_json::from_str(&meta).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0][0], "text/identifier");
        assert_eq!(parsed[1][0], "text/plain");
    }

    #[test]
    fn description_hash_is_deterministic() {
        let meta = build_metadata("francis", "bullpay.ca");
        let hash1 = hex::encode(Sha256::digest(meta.as_bytes()));
        let hash2 = hex::encode(Sha256::digest(build_metadata("francis", "bullpay.ca").as_bytes()));
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn description_hash_differs_per_nym() {
        let h1 = hex::encode(Sha256::digest(build_metadata("alice", "bullpay.ca").as_bytes()));
        let h2 = hex::encode(Sha256::digest(build_metadata("bob", "bullpay.ca").as_bytes()));
        assert_ne!(h1, h2);
    }
}

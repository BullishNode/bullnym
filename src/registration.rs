use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

use crate::auth;
use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::AppState;

static NYM_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9\-]{1,30}[a-z0-9]$").unwrap());

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub nym: String,
    pub ct_descriptor: String,
    pub npub: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub nym: String,
    pub lightning_address: String,
    pub nip05: String,
}

#[derive(Deserialize)]
pub struct UpdateRequest {
    pub npub: String,
    pub ct_descriptor: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct UpdateResponse {
    pub nym: String,
    pub lightning_address: String,
}

/// POST /register — create a new Lightning Address with nostr auth
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    // Validate nym format
    if !NYM_REGEX.is_match(&req.nym) {
        return Err(AppError::NymInvalid(
            "must be 3-32 chars, lowercase alphanumeric and hyphens, cannot start/end with hyphen"
                .to_string(),
        ));
    }

    // Validate descriptor
    descriptor::validate_descriptor(
        &req.ct_descriptor,
        state.config.limits.max_descriptor_len,
    )?;

    // Verify schnorr signature: SHA256(nym + ct_descriptor)
    let message = format!("{}{}", req.nym, req.ct_descriptor);
    auth::verify_signature(&req.npub, message.as_bytes(), &req.signature)?;

    // Insert user
    db::create_user(&state.db, &req.nym, &req.npub, &req.ct_descriptor).await?;

    // Create BIP 353 DNS record (best-effort)
    if let Some(dns) = &state.dns {
        let address = descriptor::derive_address(&req.ct_descriptor, 0)?;
        match dns.create_bip353_record(&req.nym, &address).await {
            Ok(record_id) => {
                if let Err(e) =
                    db::update_dns_record_id(&state.db, &req.nym, &record_id).await
                {
                    tracing::error!("failed to store dns_record_id for {}: {e}", req.nym);
                }
            }
            Err(e) => tracing::error!("failed to create DNS record for {}: {e}", req.nym),
        }
    }

    let lightning_address = format!("{}@{}", req.nym, state.config.domain);
    let nip05 = lightning_address.clone();

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            nym: req.nym,
            lightning_address,
            nip05,
        }),
    ))
}

/// PUT /register — update descriptor for an existing registration
pub async fn update_registration(
    State(state): State<AppState>,
    Json(req): Json<UpdateRequest>,
) -> Result<Json<UpdateResponse>, AppError> {
    // Verify schnorr signature: SHA256(ct_descriptor)
    auth::verify_signature(&req.npub, req.ct_descriptor.as_bytes(), &req.signature)?;

    // Validate descriptor
    descriptor::validate_descriptor(
        &req.ct_descriptor,
        state.config.limits.max_descriptor_len,
    )?;

    // Update
    let user = db::update_user_descriptor(&state.db, &req.npub, &req.ct_descriptor)
        .await?
        .ok_or_else(|| AppError::NymNotFound("no registration found for this key".to_string()))?;

    // Update DNS record with new address at index 0
    if let (Some(dns), Some(record_id)) = (&state.dns, &user.dns_record_id) {
        let address = descriptor::derive_address(&req.ct_descriptor, 0)?;
        if let Err(e) = dns
            .update_bip353_record(record_id, &user.nym, &address)
            .await
        {
            tracing::error!("failed to update DNS record for {}: {e}", user.nym);
        }
    }

    let lightning_address = format!("{}@{}", user.nym, state.config.domain);

    Ok(Json(UpdateResponse {
        nym: user.nym,
        lightning_address,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_nyms() {
        assert!(NYM_REGEX.is_match("francis"));
        assert!(NYM_REGEX.is_match("my-nym"));
        assert!(NYM_REGEX.is_match("abc"));
        assert!(NYM_REGEX.is_match("user123"));
        assert!(NYM_REGEX.is_match("a-b"));
        assert!(NYM_REGEX.is_match("a".repeat(32).as_str()));
    }

    #[test]
    fn too_short() {
        assert!(!NYM_REGEX.is_match("ab"));
        assert!(!NYM_REGEX.is_match("a"));
        assert!(!NYM_REGEX.is_match(""));
    }

    #[test]
    fn too_long() {
        assert!(!NYM_REGEX.is_match(&"a".repeat(33)));
    }

    #[test]
    fn uppercase_rejected() {
        assert!(!NYM_REGEX.is_match("Francis"));
        assert!(!NYM_REGEX.is_match("ABC"));
    }

    #[test]
    fn starts_with_hyphen_rejected() {
        assert!(!NYM_REGEX.is_match("-mynym"));
    }

    #[test]
    fn ends_with_hyphen_rejected() {
        assert!(!NYM_REGEX.is_match("mynym-"));
    }

    #[test]
    fn spaces_rejected() {
        assert!(!NYM_REGEX.is_match("has space"));
    }

    #[test]
    fn underscores_rejected() {
        assert!(!NYM_REGEX.is_match("has_underscore"));
    }

    #[test]
    fn special_chars_rejected() {
        assert!(!NYM_REGEX.is_match("user@name"));
        assert!(!NYM_REGEX.is_match("user.name"));
        assert!(!NYM_REGEX.is_match("user!name"));
    }
}

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth;
use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::AppState;

/// Accepted clock-skew window for the `reservations` auth timestamp. Wider
/// than NIP-98 default (60s) because mobile clocks drift more than desktop.
const RESERVATIONS_TS_WINDOW_SECS: u64 = 300;

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
    if !NYM_REGEX.is_match(&req.nym) {
        return Err(AppError::NymInvalid(
            "must be 3-32 chars, lowercase alphanumeric and hyphens, cannot start/end with hyphen"
                .to_string(),
        ));
    }

    descriptor::validate_descriptor(
        &req.ct_descriptor,
        state.config.limits.max_descriptor_len,
    )?;

    let message = format!("{}{}", req.nym, req.ct_descriptor);
    auth::verify_signature(&req.npub, message.as_bytes(), &req.signature)?;

    // Check if npub already has an active registration
    if let Some(active) = db::get_user_by_npub(&state.db, &req.npub).await? {
        return Err(AppError::NymTaken(format!(
            "this key already has an active address: {}@{}",
            active.nym, state.config.domain
        )));
    }

    // Check if npub has an inactive registration — reactivate with new nym
    if let Some(_inactive) = db::get_inactive_user_by_npub(&state.db, &req.npub).await? {
        db::reactivate_user(&state.db, &req.npub, &req.nym, &req.ct_descriptor).await?;
    } else {
        // Fresh registration
        db::create_user(&state.db, &req.nym, &req.npub, &req.ct_descriptor).await?;
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
    auth::verify_signature(&req.npub, req.ct_descriptor.as_bytes(), &req.signature)?;

    descriptor::validate_descriptor(
        &req.ct_descriptor,
        state.config.limits.max_descriptor_len,
    )?;

    let user = db::update_user_descriptor(&state.db, &req.npub, &req.ct_descriptor)
        .await?
        .ok_or_else(|| AppError::NymNotFound("no registration found for this key".to_string()))?;

    let lightning_address = format!("{}@{}", user.nym, state.config.domain);

    Ok(Json(UpdateResponse {
        nym: user.nym,
        lightning_address,
    }))
}

#[derive(Deserialize)]
pub struct DeleteRequest {
    pub npub: String,
    pub signature: String,
    /// When true, hard-delete all swap_records / outpoint_addresses for the
    /// nym in addition to deactivating it. The nym row itself is kept so the
    /// name stays reserved and the original npub can re-register it.
    /// Requires the signature to be over `b"purge"` (not `b"delete"`).
    #[serde(default)]
    pub purge: bool,
}

/// DELETE /register — deactivate a Lightning Address registration.
///
/// `purge=false` (default): soft-delete only — preserves `swap_records`.
/// `purge=true`: also drops swap history. Refuses if non-terminal swaps
/// exist (their rows hold the only copy of the Boltz claim key).
pub async fn delete_registration(
    State(state): State<AppState>,
    Json(req): Json<DeleteRequest>,
) -> Result<StatusCode, AppError> {
    let challenge: &[u8] = if req.purge { b"purge" } else { b"delete" };
    auth::verify_signature(&req.npub, challenge, &req.signature)?;

    if req.purge {
        match db::purge_user(&state.db, &req.npub).await? {
            db::PurgeOutcome::Purged(user) => {
                tracing::info!("purged registration for {}", user.nym);
                Ok(StatusCode::NO_CONTENT)
            }
            db::PurgeOutcome::NotFound => Err(AppError::NymNotFound(
                "no registration found for this key".to_string(),
            )),
            db::PurgeOutcome::InFlightSwaps(n) => Err(AppError::PurgeBlocked(n)),
        }
    } else {
        let user = db::deactivate_user(&state.db, &req.npub).await?.ok_or_else(
            || AppError::NymNotFound("no registration found for this key".to_string()),
        )?;
        tracing::info!("deactivated registration for {}", user.nym);
        Ok(StatusCode::NO_CONTENT)
    }
}

// --- Lookup ---

#[derive(Deserialize)]
pub struct LookupParams {
    pub npub: String,
}

#[derive(Serialize)]
pub struct LookupResponse {
    pub nym: String,
    pub active: bool,
}

/// GET /register/lookup?npub=<hex> — check if an npub has a registration
pub async fn lookup_by_npub(
    State(state): State<AppState>,
    Query(params): Query<LookupParams>,
) -> Result<Json<LookupResponse>, AppError> {
    if let Some(user) = db::get_user_by_npub(&state.db, &params.npub).await? {
        return Ok(Json(LookupResponse { nym: user.nym, active: true }));
    }
    if let Some(user) = db::get_inactive_user_by_npub(&state.db, &params.npub).await? {
        return Ok(Json(LookupResponse { nym: user.nym, active: false }));
    }
    Err(AppError::NymNotFound("no registration for this key".to_string()))
}

// --- Reservation sync ---

#[derive(Deserialize)]
pub struct ReservationsAuthParams {
    pub ts: u64,
    pub sig: String,
    pub npub: String,
}

#[derive(Serialize)]
pub struct ReservationItem {
    pub outpoint: String,
    pub addr_index: i32,
    pub fulfilled: bool,
}

#[derive(Serialize)]
pub struct ReservationsResponse {
    pub reservations: Vec<ReservationItem>,
    pub next_addr_idx: i32,
}

/// GET /api/reservations/:nym
///
/// Auth via Schnorr signature over `sha256("reservations:" || nym || ":" || ts)`,
/// where ts is a unix timestamp within ±RESERVATIONS_TS_WINDOW_SECS of server
/// clock. The signing key must match the `npub` on record for this nym.
pub async fn list_reservations(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    Query(params): Query<ReservationsAuthParams>,
) -> Result<Json<ReservationsResponse>, AppError> {
    // Clock skew check.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let skew = if now > params.ts { now - params.ts } else { params.ts - now };
    if skew > RESERVATIONS_TS_WINDOW_SECS {
        return Err(AppError::AuthError("timestamp outside allowed window".into()));
    }

    // Verify sig over "reservations:{nym}:{ts}".
    let message = format!("reservations:{}:{}", nym, params.ts);
    auth::verify_signature(&params.npub, message.as_bytes(), &params.sig)?;

    // Bind to the nym owner on record.
    let user = db::get_user_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::NymNotFound(nym.clone()))?;
    if !user.is_active {
        return Err(AppError::NymNotFound(nym));
    }
    if user.npub != params.npub {
        return Err(AppError::AuthError("signer does not own this nym".into()));
    }

    let rows = db::list_reservations_for_nym(&state.db, &nym).await?;
    let reservations = rows
        .into_iter()
        .map(|r| ReservationItem {
            outpoint: r.outpoint,
            addr_index: r.addr_index,
            fulfilled: r.fulfilled,
        })
        .collect();

    Ok(Json(ReservationsResponse {
        reservations,
        next_addr_idx: user.next_addr_idx,
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

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;

use crate::auth;
use crate::certification::{self, CertificationScope};
use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::ip_whitelist;
use crate::reserved_nyms;
use crate::AppState;

/// Resolve the caller IP using the same logic as `/lnurlp/callback`:
/// rightmost X-Forwarded-For when `trust_forwarded_for`, otherwise the TCP
/// peer. Returns `None` if neither source is available.
fn caller_ip(state: &AppState, peer: Option<SocketAddr>, headers: &HeaderMap) -> Option<IpAddr> {
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    ip_whitelist::resolve_caller_ip(
        peer.map(|p| p.ip()),
        xff,
        state.config.rate_limit.trust_forwarded_for,
    )
}

/// Apply the per-IP register rate limit. Whitelisted callers bypass.
/// Called at the top of every `/register*` handler before any sig work.
async fn gate_register_per_ip(
    state: &AppState,
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
) -> Result<Option<IpAddr>, AppError> {
    let ip = caller_ip(state, peer, headers);
    let is_certification_allowed = certification::allows_scope(
        state,
        CertificationScope::RegistrationSetup,
        peer,
        headers,
        "register",
        None,
    );
    if let Some(ip) = ip {
        if !state.ip_whitelist.contains(ip) && !is_certification_allowed {
            state.rate_limiter.check_register_per_ip(ip).await?;
        }
    }
    Ok(ip)
}

static NYM_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[a-z0-9]|[a-z0-9][a-z0-9\-]{0,30}[a-z0-9])$").unwrap());
static NOSTR_PUBKEY_HEX_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{64}$").unwrap());

const LIFETIME_NYM_CAP: i64 = 1;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub nym: String,
    pub ct_descriptor: String,
    #[serde(default)]
    pub verification_npub: Option<String>,
    pub npub: String,
    pub signature: String,
    pub timestamp: u64,
}

/// Wire-shape view of per-npub lifetime nym usage. It remains on
/// register/lookup/delete responses for client compatibility; the policy cap
/// is now the fixed value one. `remaining` is `(cap - used).max(0)`.
#[derive(Serialize, Clone, Copy)]
pub struct QuotaView {
    pub used: i64,
    pub cap: i64,
    pub remaining: i64,
}

impl QuotaView {
    fn new(used: i64, cap: i64) -> Self {
        Self {
            used,
            cap,
            remaining: (cap - used).max(0),
        }
    }
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub nym: String,
    pub lightning_address: String,
    /// Public NIP-05 identifier only when publication is actually configured:
    /// the registration supplied `verification_npub` and `[features].nip05`
    /// is enabled. Otherwise `null`.
    pub nip05: Option<String>,
    /// Lifetime nym quota AFTER this register. Mobile reads this so it
    /// doesn't need a follow-up `/register/lookup` round trip.
    pub quota: QuotaView,
}

/// Response body for `DELETE /register`. Returns the quota AFTER the
/// deactivation (which is unchanged — deactivate doesn't free a slot).
#[derive(Serialize)]
pub struct DeleteResponse {
    pub quota: QuotaView,
}

#[derive(Deserialize)]
pub struct UpdateRequest {
    pub npub: String,
    /// Active nym for this npub. Included so the v2 sig binds the action to a
    /// specific nym (cross-nym sig replay rejected). Server still asserts the
    /// (npub, nym) pair matches the stored row.
    pub nym: String,
    pub ct_descriptor: String,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Serialize)]
pub struct UpdateResponse {
    pub nym: String,
    pub lightning_address: String,
}

/// POST /register — create a new Lightning Address with nostr auth
pub async fn register(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);

    // Gate before any CPU-expensive work (sig verify, descriptor parse).
    let ip = gate_register_per_ip(&state, peer, &headers).await?;
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);
    let is_certification_allowed = certification::allows_scope(
        &state,
        CertificationScope::RegistrationSetup,
        peer,
        &headers,
        "register",
        Some(&req.npub),
    );

    // Hard ceiling on active users. New registrations are blocked once
    // the cap is reached; updates / lookups / deletes still work.
    if !is_whitelisted {
        state.rate_limiter.check_max_active_users().await?;
    }

    if !NYM_REGEX.is_match(&req.nym) {
        return Err(AppError::NymInvalid(
            "must be 1-32 chars, lowercase alphanumeric and hyphens, cannot start/end with hyphen"
                .to_string(),
        ));
    }

    if reserved_nyms::is_reserved(&req.nym) {
        return Err(AppError::NymReserved);
    }

    descriptor::validate_descriptor(&req.ct_descriptor, state.config.limits.max_descriptor_len)?;
    // NIP-05 is opt-in: the verification key is stored only when the client
    // deliberately supplies one. The server never falls back to the auth key
    // (`npub`) — publishing that at `/.well-known/nostr.json` would collapse
    // the ADR-004 role separation (see ISS-S-01). Omission => no NIP-05 record.
    let verification_npub = req.verification_npub.as_deref();
    if let Some(vn) = verification_npub {
        if !NOSTR_PUBKEY_HEX_REGEX.is_match(vn) {
            return Err(AppError::AuthError(
                "verification_npub must be a 64-character hex public key".to_string(),
            ));
        }
    }

    // Distinct-npubs-per-IP cap, applied after the cheap input
    // validation but BEFORE the Schnorr verify. Recording the npub here
    // (without it being verified) is fine because the limiter only counts
    // distinct values — adversarial garbage just consumes the attacker's
    // own bucket faster.
    if !is_whitelisted && !is_certification_allowed {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_register_distinct_npubs_per_ip(ip, &req.npub)
                .await?;
        }
    }

    let register_fields = match verification_npub {
        Some(vn) => vec![req.ct_descriptor.as_str(), vn],
        None => vec![req.ct_descriptor.as_str()],
    };
    auth::verify_la_v2(
        "register",
        &req.npub,
        &req.nym,
        &register_fields,
        req.timestamp,
        &req.signature,
    )?;

    // Atomic register flow under an advisory lock keyed on `npub`.
    // The lifetime nym stays reserved forever. Re-registering that same nym
    // reactivates its row so swap history follows the FK; a different nym is
    // rejected for this npub.
    match db::register_user_atomic(
        &state.db,
        &req.npub,
        &req.nym,
        &req.ct_descriptor,
        verification_npub,
        LIFETIME_NYM_CAP,
    )
    .await?
    {
        db::RegisterOutcome::Created(_) | db::RegisterOutcome::Reactivated(_) => {}
        db::RegisterOutcome::KeyAlreadyRegistered { nym } => {
            return Err(AppError::KeyAlreadyRegistered {
                nym,
                domain: state.config.domain.clone(),
            });
        }
        db::RegisterOutcome::NymAlreadyAssigned { nym } => {
            return Err(AppError::NymAlreadyAssigned {
                nym,
                domain: state.config.domain.clone(),
            });
        }
        db::RegisterOutcome::NameTaken => return Err(AppError::NameTaken),
    }

    let lightning_address = format!("{}@{}", req.nym, state.config.domain);
    let nip05 = if verification_npub.is_some() && state.config.features.nip05 {
        Some(lightning_address.clone())
    } else {
        None
    };
    let used = db::count_lifetime_nyms_by_npub(&state.db, &req.npub).await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            nym: req.nym,
            lightning_address,
            nip05,
            quota: QuotaView::new(used, LIFETIME_NYM_CAP),
        }),
    ))
}

/// PUT /register — update descriptor for an existing registration
pub async fn update_registration(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<UpdateRequest>,
) -> Result<Json<UpdateResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let _ = gate_register_per_ip(&state, peer, &headers).await?;

    auth::verify_la_v2(
        "update",
        &req.npub,
        &req.nym,
        &[&req.ct_descriptor],
        req.timestamp,
        &req.signature,
    )?;

    descriptor::validate_descriptor(&req.ct_descriptor, state.config.limits.max_descriptor_len)?;

    // Pre-flight: confirm the (npub, nym) pair matches a current registration
    // BEFORE the descriptor write. Catches stale-nym replays.
    let current = db::get_user_by_npub(&state.db, &req.npub)
        .await?
        .ok_or_else(|| AppError::NymNotFound("no registration found for this key".to_string()))?;
    if current.nym != req.nym {
        return Err(AppError::AuthError(
            "signer's claimed nym does not match the registration on file".to_string(),
        ));
    }

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
    /// Active nym for this npub. Included so the v2 sig binds the action to a
    /// specific nym (cross-nym sig replay rejected). Server still asserts the
    /// (npub, nym) pair matches the stored row.
    pub nym: String,
    pub signature: String,
    /// When true, hard-delete all swap_records / outpoint_addresses for the
    /// nym in addition to deactivating it. The nym row itself is kept so the
    /// name stays reserved and the original npub can re-register it. Requires
    /// the signature to be over action `"purge"` (not `"delete"`).
    #[serde(default)]
    pub purge: bool,
    pub timestamp: u64,
}

/// DELETE /register — deactivate a Lightning Address registration.
///
/// `purge=false` (default): soft-delete only — preserves `swap_records`.
/// `purge=true`: also drops swap history. Refuses if non-terminal swaps
/// exist (their rows hold the only copy of the Boltz claim key).
pub async fn delete_registration(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let _ = gate_register_per_ip(&state, peer, &headers).await?;

    let action = if req.purge { "purge" } else { "delete" };
    auth::verify_la_v2(
        action,
        &req.npub,
        &req.nym,
        &[],
        req.timestamp,
        &req.signature,
    )?;

    // Pre-flight: confirm the (npub, nym) pair matches a current registration
    // BEFORE the deactivate/purge fires. Catches a mismatched claimed nym and
    // protects grandfathered multi-nym owners.
    let current = db::get_user_by_npub(&state.db, &req.npub)
        .await?
        .ok_or_else(|| AppError::NymNotFound("no registration found for this key".to_string()))?;
    if current.nym != req.nym {
        return Err(AppError::AuthError(
            "signer's claimed nym does not match the registration on file".to_string(),
        ));
    }

    if req.purge {
        match db::purge_user(&state.db, &req.npub).await? {
            db::PurgeOutcome::Purged(user) => {
                tracing::info!("purged registration for {}", user.nym);
            }
            db::PurgeOutcome::NotFound => {
                return Err(AppError::NymNotFound(
                    "no registration found for this key".to_string(),
                ));
            }
            db::PurgeOutcome::InFlightSwaps(n) => return Err(AppError::PurgeBlocked(n)),
        }
    } else {
        let user = db::deactivate_user(&state.db, &req.npub)
            .await?
            .ok_or_else(|| {
                AppError::NymNotFound("no registration found for this key".to_string())
            })?;
        tracing::info!("deactivated registration for {}", user.nym);
    }

    let used = db::count_lifetime_nyms_by_npub(&state.db, &req.npub).await?;
    Ok(Json(DeleteResponse {
        quota: QuotaView::new(used, LIFETIME_NYM_CAP),
    }))
}

// --- Lookup ---

#[derive(Deserialize)]
pub struct LookupParams {
    pub npub: String,
}

#[derive(Serialize)]
pub struct LookupResponse {
    /// Active nym, or the most-recent inactive nym when `active == false`
    /// (i.e. `previous_nyms[0].nym`). Kept for older clients that don't
    /// read `previous_nyms`.
    pub nym: String,
    pub active: bool,
    pub quota: QuotaView,
    /// All inactive nyms for this npub, most-recent first.
    pub previous_nyms: Vec<db::PreviousNym>,
    /// Compatibility field. New clients MUST read `quota.used`; see
    /// docs/reference/compatibility.md for removal policy.
    pub lifetime_nyms_used: i64,
    /// Compatibility field. New clients MUST read `quota.cap`.
    pub lifetime_nyms_cap: i64,
}

/// GET /register/lookup?npub=<hex> — check if an npub has a registration
pub async fn lookup_by_npub(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(params): Query<LookupParams>,
) -> Result<Json<LookupResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = gate_register_per_ip(&state, peer, &headers).await?;

    // Bound how many distinct npubs one IP can probe. The per-IP
    // register rate caps query speed; this caps total enumeration
    // breadth even for a slow attacker.
    if let Some(ip) = ip {
        if !state.ip_whitelist.contains(ip)
            && !certification::allows_scope(
                &state,
                CertificationScope::RegistrationSetup,
                peer,
                &headers,
                "register_lookup",
                Some(&params.npub),
            )
        {
            state
                .rate_limiter
                .check_lookup_distinct_npubs_per_ip(ip, &params.npub)
                .await?;
        }
    }

    let (active_nym, previous_nyms, used) =
        db::lookup_status_by_npub(&state.db, &params.npub).await?;
    let quota = QuotaView::new(used, LIFETIME_NYM_CAP);
    if let Some(nym) = active_nym {
        return Ok(Json(LookupResponse {
            nym,
            active: true,
            quota,
            previous_nyms,
            lifetime_nyms_used: used,
            lifetime_nyms_cap: LIFETIME_NYM_CAP,
        }));
    }
    if let Some(head) = previous_nyms.first() {
        let nym = head.nym.clone();
        return Ok(Json(LookupResponse {
            nym,
            active: false,
            quota,
            previous_nyms,
            lifetime_nyms_used: used,
            lifetime_nyms_cap: LIFETIME_NYM_CAP,
        }));
    }
    Err(AppError::NymNotFound(
        "no registration for this key".to_string(),
    ))
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
    auth::check_ts_freshness(params.ts)?;

    // Verify sig over "reservations:{nym}:{ts}".
    let message = format!("reservations:{}:{}", nym, params.ts);
    auth::verify_signature(&params.npub, message.as_bytes(), &params.sig)?;

    // Bind to the nym owner on record.
    let user = db::get_active_user_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::NymNotFound(nym.clone()))?;
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
mod tests;

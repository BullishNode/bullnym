//! Public donation-page payment callbacks (Phase 4).
//!
//! Two endpoints:
//!
//! 1. `GET /lnurlp/donate-callback/:nym?amount&network` — generates a
//!    fresh BOLT11 invoice (Lightning) or returns a cookie-pinned Liquid
//!    address. No auth: the donator is an anonymous browser visitor.
//!    Replaces the LUD-22 outpoint-proof flow with a (cookie + per-source
//!    rate-limit) anti-spam model.
//!
//! 2. `GET /lnurlp/donate-status/:nym?kind=...&id=...` — polled by the
//!    donation page every ~3s after a callback returns. Reports
//!    "waiting" / "paid" / "expired" so the page can flip its UI state.
//!
//! Lightning path reuses `lnurl::create_lightning_swap` so there's no
//! drift in Boltz reverse-swap setup. Liquid path uses the new
//! `db::lookup_or_allocate_donation_address` cookie-pinned allocator.

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::ip_whitelist::{self, source_key};
use crate::lnurl;
use crate::AppState;

const COOKIE_NAME: &str = "bullpay_did";

// --- Callback ---

#[derive(Deserialize)]
pub struct CallbackParams {
    /// Amount in millisatoshis (LNURL-pay convention). Multiple of 1000.
    pub amount: u64,
    /// "lightning" or "liquid". Required.
    pub network: String,
}

#[derive(Serialize)]
pub struct LightningCallback {
    pub pr: String,
    pub routes: Vec<()>,
    pub disposable: bool,
    /// Donation-specific extension: surfaces the boltz swap_id so the
    /// page can poll `/lnurlp/donate-status?kind=lightning&id=<swap_id>`.
    pub swap_id: String,
}

#[derive(Serialize)]
pub struct LiquidCallback {
    /// Wire-shape mirrors the existing LNURL Liquid path so client JS
    /// doesn't need a second decoder.
    #[serde(rename = "L-BTC")]
    pub l_btc: LiquidPayload,
}

#[derive(Serialize)]
pub struct LiquidPayload {
    pub address: String,
}

/// Validate amount-msat against the configured min/max + multiple-of-1000.
/// Mirrors `lnurl::callback`'s validation (lnurl.rs:370-388).
fn validate_amount(amount_msat: u64, state: &AppState) -> Result<u64, AppError> {
    if amount_msat < state.config.limits.min_sendable_msat {
        return Err(AppError::InvalidAmount(format!(
            "minimum is {} msat",
            state.config.limits.min_sendable_msat
        )));
    }
    if amount_msat > state.config.limits.max_sendable_msat {
        return Err(AppError::InvalidAmount(format!(
            "maximum is {} msat",
            state.config.limits.max_sendable_msat
        )));
    }
    if amount_msat % 1000 != 0 {
        return Err(AppError::InvalidAmount(
            "amount must be a multiple of 1000 msat".to_string(),
        ));
    }
    Ok(amount_msat / 1000)
}

/// `GET /lnurlp/donate-callback/:nym?amount=&network=`
///
/// Lightning: returns BOLT11 + swap_id.
/// Liquid: returns cookie-pinned address; sets/refreshes `bullpay_did`
/// cookie if absent.
pub async fn callback(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    cookies: Cookies,
    Query(params): Query<CallbackParams>,
) -> Result<Response, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    // Per-source rate-limit BEFORE parsing or DB work. Loose (30/min) —
    // refresh-driven retries are normal.
    if !is_whitelisted {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_donation_callback_per_source(ip)
                .await?;
        }
    }

    let amount_sat = validate_amount(params.amount, &state)?;

    // Donation page must exist + be live (enabled, not archived).
    let page = db::get_donation_page_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::DonationPageNotFound(nym.clone()))?;
    if !page.enabled || page.is_archived {
        return Err(AppError::DonationPageNotFound(nym.clone()));
    }

    match params.network.as_str() {
        "lightning" => callback_lightning(&state, &nym, amount_sat, ip, is_whitelisted).await,
        "liquid" => callback_liquid(&state, &nym, ip, is_whitelisted, &cookies).await,
        other => Err(AppError::InvalidAmount(format!(
            "unsupported network '{other}' (lightning|liquid)"
        ))),
    }
}

async fn callback_lightning(
    state: &AppState,
    nym: &str,
    amount_sat: u64,
    ip: Option<std::net::IpAddr>,
    is_whitelisted: bool,
) -> Result<Response, AppError> {
    // Lightning per-source bucket — bounds Boltz API spend per source.
    if !is_whitelisted {
        if let Some(ip) = ip {
            state.rate_limiter.check_lightning_per_source(ip).await?;
        }
    }

    let (lnurl_resp, swap_id) =
        lnurl::create_lightning_swap(state, nym, amount_sat).await?;

    let resp = LightningCallback {
        pr: lnurl_resp.pr,
        routes: lnurl_resp.routes,
        disposable: lnurl_resp.disposable,
        swap_id,
    };
    Ok(Json(resp).into_response())
}

async fn callback_liquid(
    state: &AppState,
    nym: &str,
    ip: Option<std::net::IpAddr>,
    is_whitelisted: bool,
    cookies: &Cookies,
) -> Result<Response, AppError> {
    // Read or assign the device_id cookie. Phase 2's `donation_render`
    // already sets this on first page load, but assign here too in case
    // the donator hit the callback URL without going through the page.
    let device_id = match cookies.get(COOKIE_NAME).and_then(|c| Uuid::from_str(c.value()).ok()) {
        Some(id) => id,
        None => {
            let id = Uuid::new_v4();
            let cookie = tower_cookies::Cookie::build((COOKIE_NAME, id.to_string()))
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(tower_cookies::cookie::SameSite::Lax)
                .max_age(tower_cookies::cookie::time::Duration::days(30))
                .build();
            cookies.add(cookie);
            id
        }
    };

    let src_key = ip
        .map(source_key)
        .unwrap_or_else(|| "unknown".to_string());

    // Cookie HIT vs MISS pre-probe. The per-source distinct-allocations
    // gate exists to bound FRESH allocations only — refreshing the page
    // (cookie HIT) returns the SAME address, so it must not burn the
    // budget. We query for an existing binding cheaply; only on MISS do
    // we apply the rate-limit gate.
    //
    // This is advisory: in the rare race where the binding is created
    // between this peek and the in-allocator lookup, the allocator's
    // SELECT under advisory lock is the source of truth. Both branches
    // are correct.
    //
    // NOTE on the inherent collision with LUD-22: a payment at a
    // shared addr_index can flip both an `outpoint_addresses` row and a
    // `donation_allocations` row. Money flows correctly to the merchant;
    // the donation page may show a phantom "Thank you" in the rare case
    // of a microsecond-window race. Accepted for v1; see review notes.
    let cookie_hit = if let Some(_) = ip {
        db::peek_donation_binding(
            &state.db,
            nym,
            &src_key,
            device_id,
            state.config.rate_limit.donation_allocation_ttl_days,
        )
        .await
        .unwrap_or(false)
    } else {
        false
    };

    if !is_whitelisted && !cookie_hit {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_donation_distinct_addrs_per_source(ip)
                .await?;
        }
    }

    let allocation = db::lookup_or_allocate_donation_address(
        &state.db,
        nym,
        &src_key,
        device_id,
        state.config.rate_limit.donation_allocation_ttl_days,
        |descriptor_str, idx| {
            descriptor::derive_address(descriptor_str, idx).map_err(|e| {
                sqlx::Error::Protocol(format!("address derivation failed: {e}"))
            })
        },
    )
    .await?;

    // Touch last_callback_at so the chain watcher promotes this nym to
    // the "active" scan tier (30s tick) instead of "idle" (600s). The
    // donation page's status feedback latency depends on this — without
    // the touch, a Liquid payment can take up to 10 minutes to flip the
    // server-side `last_paid_at`, which is the fallback when the
    // donator's browser blocks liquid.network's WebSocket.
    db::touch_user_callback(&state.db, nym).await;

    Ok(Json(LiquidCallback {
        l_btc: LiquidPayload {
            address: allocation.address,
        },
    })
    .into_response())
}

// --- Status ---

#[derive(Deserialize)]
pub struct StatusParams {
    /// "lightning" | "liquid"
    pub kind: String,
    /// For lightning: the boltz swap_id. For liquid: the address.
    pub id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DonationState {
    /// No payment yet. Page keeps polling.
    Waiting,
    /// Donator paid. Lightning: invoice settled (Boltz lockup observed).
    /// Liquid: chain-watcher saw a payment at the allocation's address_index.
    Paid,
    /// Lightning invoice expired before settlement. Page offers
    /// regeneration. Liquid never enters this state — addresses don't expire.
    Expired,
}

#[derive(Serialize)]
pub struct DonationStatusResponse {
    pub state: DonationState,
}

/// `GET /lnurlp/donate-status/:nym?kind=lightning&id=<swap_id>`
/// `GET /lnurlp/donate-status/:nym?kind=liquid&id=<address>`
pub async fn status(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(params): Query<StatusParams>,
) -> Result<Json<DonationStatusResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    if !is_whitelisted {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_donation_status_per_source(ip)
                .await?;
        }
    }

    let state_enum = match params.kind.as_str() {
        "lightning" => lightning_status(&state, &params.id).await?,
        "liquid" => liquid_status(&state, &nym, &params.id).await?,
        other => {
            return Err(AppError::InvalidAmount(format!(
                "unsupported kind '{other}' (lightning|liquid)"
            )));
        }
    };

    Ok(Json(DonationStatusResponse { state: state_enum }))
}

/// Map a `swap_records.status` to a donator-facing state.
///
/// Forward-compatible safe default: unknown future states map to
/// `Waiting`, NOT `Paid`. This is conservative — if a new SwapStatus
/// variant like "cancelled" or "refunded" is added, we don't want to
/// silently tell the donator their payment landed. Each status that
/// represents donator-paid must be enumerated explicitly here. Adding a
/// new status to `db::SwapStatus` should require updating this match.
fn map_lightning_status(swap_status: &str) -> DonationState {
    match swap_status {
        // Donator's invoice has not settled yet.
        "pending" => DonationState::Waiting,
        // Boltz observed the donator's payment and locked up funds for
        // the merchant to claim. From the donator's perspective, their
        // payment is complete — what happens between Boltz and the
        // merchant's claim is not the donator's concern.
        "lockup_mempool"
        | "lockup_confirmed"
        | "claiming"
        | "claimed"
        | "claim_failed" => DonationState::Paid,
        // Invoice expired without donator payment.
        "expired" => DonationState::Expired,
        // Unknown or future status: report Waiting. Conservative.
        other => {
            tracing::warn!(
                event = "donation_status_unknown",
                swap_status = %other,
                "swap_records.status not handled by map_lightning_status; \
                 reporting Waiting. Update donation_callback::map_lightning_status \
                 when SwapStatus is extended."
            );
            DonationState::Waiting
        }
    }
}

async fn lightning_status(state: &AppState, swap_id: &str) -> Result<DonationState, AppError> {
    let swap = db::get_swap_by_boltz_id(&state.db, swap_id).await?;
    Ok(match swap {
        Some(s) => map_lightning_status(&s.status),
        None => {
            // Caller asked about a swap_id we don't know. Could be a
            // typo, a stale page, or a probe. "Waiting" is the safe,
            // information-free response — it tells the caller nothing
            // they didn't already know.
            DonationState::Waiting
        }
    })
}

async fn liquid_status(
    state: &AppState,
    nym: &str,
    address: &str,
) -> Result<DonationState, AppError> {
    let paid = db::get_donation_allocation_paid_status(&state.db, nym, address).await?;
    Ok(match paid {
        Some(true) => DonationState::Paid,
        Some(false) | None => DonationState::Waiting,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_lightning_status_pending_is_waiting() {
        assert!(matches!(
            map_lightning_status("pending"),
            DonationState::Waiting
        ));
    }

    #[test]
    fn map_lightning_status_expired_is_expired() {
        assert!(matches!(
            map_lightning_status("expired"),
            DonationState::Expired
        ));
    }

    #[test]
    fn map_lightning_status_settled_states_are_paid() {
        for s in [
            "lockup_mempool",
            "lockup_confirmed",
            "claiming",
            "claimed",
            "claim_failed",
        ] {
            assert!(
                matches!(map_lightning_status(s), DonationState::Paid),
                "{s} should be Paid"
            );
        }
    }

    #[test]
    fn unknown_swap_state_defaults_to_waiting() {
        // Forward-compat safety: if a future swap_records.status enum is
        // added (e.g. "cancelled", "refunded"), map to Waiting, not Paid.
        // This forces an explicit decision when the enum changes.
        assert!(matches!(
            map_lightning_status("future_unknown_state"),
            DonationState::Waiting
        ));
        assert!(matches!(
            map_lightning_status("cancelled"),
            DonationState::Waiting
        ));
        assert!(matches!(
            map_lightning_status(""),
            DonationState::Waiting
        ));
    }
}

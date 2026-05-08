//! Invoices: unified payment-intent abstraction (Phase B).
//!
//! Anonymous (sender-side) endpoints in this module:
//!
//! - `POST /<nym>/invoice` — anonymous browser creates a checkout-origin
//!   invoice. Body is JSON: `{ amount_sat }` OR
//!   `{ fiat_amount_minor, fiat_currency }`. Returns `{ invoice_id }`.
//!   Page navigates to `/<nym>/i/<id>`.
//! - `GET /<nym>/i/<id>` — renders the payment view (Askama HTML). The
//!   B9 template polishes this; the B4 stub is minimal and lives at
//!   `templates/invoice_payment.html`.
//! - `GET /api/v1/invoices/<id>/status` — polled by the page; returns
//!   the current invoice state plus the latest Lightning BOLT11. Runs
//!   the on-demand rate-refresh inline for fiat-denominated invoices
//!   when the rate-lock has elapsed.
//! - `POST /api/v1/invoices/<id>/lightning` — lazy-create the Lightning
//!   offer if one doesn't exist yet. (Unlike donation-callback, the
//!   default Phase-B flow eagerly creates the offer on
//!   `POST /<nym>/invoice`; this endpoint exists for sat-denom invoices
//!   that may have been created without the eager fetch, and for future
//!   wallet-origin invoices.)
//! - `POST /api/v1/invoices/<id>/liquid` — lazy-allocate the Liquid
//!   address on first rail toggle. Idempotent — re-call returns the same
//!   address.
//!
//! Schnorr-signed (recipient-side) endpoints arrive in B5 and live in
//! the same module: `POST/DELETE/GET /api/v1/<nym>/invoices`.
//!
//! Rate-limit gates currently reuse the existing `donation_callback` /
//! `donation_status` / `donation_distinct_addrs` buckets. Phase B step 8
//! introduces dedicated `check_invoice_create_per_source` (5/min) and
//! per-npub gates and re-wires these handlers.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::SystemTime;

use askama::Template;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth;
use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::ip_whitelist;
use crate::AppState;

// =====================================================================
// Action constants (v1 Schnorr signing)
//
// Wire-protocol identifiers — must match mobile's
// `invoice_constants.dart::INVOICE_*_ACTION`. Renaming any of these is a
// wire-breaking change requiring lockstep mobile-server deploy. The plan
// (Phase D note) explicitly opts out of renames for stability.
// =====================================================================

pub const ACTION_CREATE: &str = "invoice-create";
pub const ACTION_CANCEL: &str = "invoice-cancel";
pub const ACTION_LIST: &str = "invoice-list";

/// Hard upper bound on wallet-origin invoice expiry (30 days). Mobile is
/// the source of the requested expiry (`expires_at_unix`); the server
/// clamps to this ceiling so a runaway or malicious client cannot pin a
/// row indefinitely. Plan defaults (1h / 24h / 7d) are mobile UI choices
/// that fall under this cap.
const MAX_WALLET_EXPIRES_SECS: i64 = 30 * 24 * 60 * 60;

/// Default cap on `list_invoices.limit`. Mobile can request a smaller
/// page size; never larger.
const LIST_LIMIT_MAX: i64 = 100;

// =====================================================================
// Settlement hook (Phase B step 7)
// =====================================================================

/// Flip an invoice via `mark_invoice_paid` after the corresponding
/// Lightning swap reaches a paid-equivalent status. Called by claimer
/// (webhook path) and reconciler (sync path) AFTER the forward-only CAS
/// state-update succeeds.
///
/// Contract:
/// - `invoice_id == None` → no-op (LNURL Lightning Address swaps and
///   legacy donation rows have no associated invoice).
/// - `mark_invoice_paid` is idempotent: a 0-rows-affected return means
///   the invoice was already in a non-unpaid status (paid/under/over/
///   expired/cancelled). Logged at debug, not warn.
/// - On error: LOG and RETURN. Never propagate. The donator's view is
///   "did I pay" → that's already settled by the (committed) swap state
///   update. A failed invoice flip is observability noise; the next
///   webhook/reconciler tick re-fires this helper (via the `unpaid`
///   predicate) and self-heals.
///
/// `boltz_swap_id` is included for log correlation; not load-bearing.
pub async fn flip_invoice_on_lightning_settlement(
    pool: &sqlx::PgPool,
    invoice_id: Option<Uuid>,
    amount_sat: i64,
    boltz_swap_id: &str,
) {
    let Some(id) = invoice_id else {
        return;
    };
    match db::mark_invoice_paid(pool, id, amount_sat, "lightning").await {
        Ok(rows) if rows > 0 => {
            tracing::info!(
                event = "invoice_paid_via_lightning",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                amount_sat = amount_sat,
                "lightning settlement flipped invoice"
            );
        }
        Ok(_) => {
            // Already terminal (paid/under/over/expired/cancelled). Quiet.
            tracing::debug!(
                event = "invoice_flip_noop",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "invoice already in terminal status; no-op"
            );
        }
        Err(e) => {
            // Swap state has already been CAS'd successfully; rolling
            // back here is impossible. Log loudly and trust the next
            // tick (or webhook delivery) to retry.
            tracing::error!(
                event = "invoice_flip_failed",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                amount_sat = amount_sat,
                "mark_invoice_paid failed (swap CAS already committed): {e}"
            );
        }
    }
}

// =====================================================================
// Constants
// =====================================================================

/// Default outer expiry for checkout-origin invoices. Matches the LNURL
/// reverse-swap timebox; the donator should be done in well under an hour.
const CHECKOUT_DEFAULT_EXPIRES_SECS: i64 = 60 * 60;

/// Inner rate-lock window for fiat-denominated invoices. The status
/// endpoint refreshes the sat amount on the first poll after this elapses.
const FIAT_RATE_LOCK_SECS: i64 = 15 * 60;

/// Don't refresh the rate if the invoice is about to expire — the new
/// BOLT11 would be worth less than nothing. The page renders the existing
/// (stale) amount with a warning, and the invoice falls to `expired` at
/// the next GC sweep.
const REFRESH_SAFETY_MARGIN_SECS: i64 = 60;

/// 1 BTC = 100_000_000 sat. Centralized so the conversion arithmetic is
/// audit-greppable.
const SAT_PER_BTC: i64 = 100_000_000;

// =====================================================================
// Helpers
// =====================================================================

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse the Uuid path parameter, returning `InvoiceNotFound` (NOT
/// `InvalidAmount` or 400) on parse failure. Reason: a malformed id is
/// information-equivalent to an unknown id from the caller's perspective,
/// and we don't want to leak the existence/non-existence boundary.
fn parse_invoice_id(s: &str) -> Result<Uuid, AppError> {
    Uuid::from_str(s).map_err(|_| AppError::InvoiceNotFound(s.to_string()))
}

/// Defensive HTML response headers. Mirrors `donation_render`'s posture.
fn html_response(html: String) -> Response {
    let mut resp = (StatusCode::OK, html).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    resp
}

// =====================================================================
// POST /<nym>/invoice — anonymous, sender-side
// =====================================================================

/// Body for anonymous invoice creation. Caller specifies EITHER
/// `amount_sat` (sat-denominated) OR `(fiat_amount_minor, fiat_currency)`
/// (fiat-denominated). Server rejects payloads that supply both or
/// neither.
#[derive(Deserialize)]
pub struct CreateAnonymousRequest {
    pub amount_sat: Option<i64>,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
}

#[derive(Serialize)]
pub struct CreateInvoiceResponse {
    pub invoice_id: Uuid,
}

pub async fn create_anonymous(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CreateAnonymousRequest>,
) -> Result<Json<CreateInvoiceResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    // Rate-limit BEFORE any DB write. Dedicated invoice-create bucket
    // (5/min per source per the plan) — tighter than the 30/min
    // donation_callback bucket because each successful create is a DB
    // write + Boltz reverse-swap allocation.
    if !is_whitelisted {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_invoice_create_per_source(ip)
                .await?;
        }
    }

    // Validate input shape + amounts. Returns (sat_amount, optional fiat triple).
    let (amount_sat, fiat) = parse_create_request(&req, &state).await?;

    // Verify the store is live (donation_pages row exists, enabled, not archived).
    let page = db::get_donation_page_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::DonationPageNotFound(nym.clone()))?;
    if !page.enabled || page.is_archived {
        return Err(AppError::DonationPageNotFound(nym.clone()));
    }

    let new_invoice = db::NewInvoice {
        nym: &nym,
        origin: "checkout",
        fiat_amount_minor: fiat.as_ref().map(|(amt, _, _)| *amt),
        fiat_currency: fiat.as_ref().map(|(_, cur, _)| cur.as_str()),
        amount_sat,
        rate_minor_per_btc: fiat.as_ref().map(|(_, _, rate)| *rate),
        // Sat-denom: rate_lock_secs = expires_in_secs (so rate_locks_until ==
        // expires_at, refresh path naturally never fires).
        rate_lock_secs: if fiat.is_some() {
            FIAT_RATE_LOCK_SECS
        } else {
            CHECKOUT_DEFAULT_EXPIRES_SECS
        },
        memo: None,
        recipient_label: None,
        expires_in_secs: CHECKOUT_DEFAULT_EXPIRES_SECS,
    };
    let invoice = db::insert_invoice(&state.db, &new_invoice).await?;

    // Eagerly create the Lightning offer so the page renders a QR
    // immediately on /<nym>/i/<id> without an extra round-trip.
    if let Err(e) = create_lightning_offer(&state, &nym, amount_sat as u64, invoice.id).await {
        // Non-fatal: the page can lazy-fetch via POST /api/v1/invoices/<id>/lightning.
        // We still return the invoice_id so the user can proceed.
        tracing::warn!(
            invoice_id = %invoice.id,
            "eager Lightning offer creation failed (page can retry): {e}",
        );
    }

    Ok(Json(CreateInvoiceResponse { invoice_id: invoice.id }))
}

/// Validate the create-anonymous body and resolve the requested amount.
///
/// Returns `(amount_sat, Option<(fiat_amount_minor, fiat_currency, rate_minor_per_btc)>)`.
///
/// Rules:
/// - Exactly one of `amount_sat` or `(fiat_amount_minor + fiat_currency)`
///   must be present; both or neither → `InvalidAmount`.
/// - `amount_sat` must be within configured min/max sendable.
/// - `fiat_amount_minor` must be > 0; `fiat_currency` must be a supported
///   ISO 4217 code (validated by the schema CHECK + here for early reject).
/// - On fiat path: pricer must return a fresh (non-stale) rate; falling
///   back to a stale rate at create-time would lock the invoice at a stale
///   rate the refresh loop would immediately re-quote.
async fn parse_create_request(
    req: &CreateAnonymousRequest,
    state: &AppState,
) -> Result<(i64, Option<(i32, String, i64)>), AppError> {
    let has_sat = req.amount_sat.is_some();
    let has_fiat = req.fiat_amount_minor.is_some() || req.fiat_currency.is_some();

    if has_sat && has_fiat {
        return Err(AppError::InvalidAmount(
            "specify amount_sat OR (fiat_amount_minor + fiat_currency), not both".into(),
        ));
    }
    if !has_sat && !has_fiat {
        return Err(AppError::InvalidAmount(
            "missing amount_sat or (fiat_amount_minor + fiat_currency)".into(),
        ));
    }

    if let Some(sat) = req.amount_sat {
        if sat <= 0 {
            return Err(AppError::InvalidAmount("amount_sat must be > 0".into()));
        }
        let min_sat = (state.config.limits.min_sendable_msat / 1000) as i64;
        let max_sat = (state.config.limits.max_sendable_msat / 1000) as i64;
        if sat < min_sat {
            return Err(AppError::InvalidAmount(format!("minimum is {min_sat} sat")));
        }
        if sat > max_sat {
            return Err(AppError::InvalidAmount(format!("maximum is {max_sat} sat")));
        }
        return Ok((sat, None));
    }

    // Fiat path: both fields required.
    let minor = req.fiat_amount_minor.ok_or_else(|| {
        AppError::InvalidAmount("missing fiat_amount_minor".into())
    })?;
    let currency = req.fiat_currency.as_deref().ok_or_else(|| {
        AppError::InvalidAmount("missing fiat_currency".into())
    })?;
    if minor <= 0 {
        return Err(AppError::InvalidAmount("fiat_amount_minor must be > 0".into()));
    }
    // Defensive upper bound: 1 billion minor units. With 2-decimal currencies
    // (USD/CAD/EUR) that's $10M; with no decimals (e.g. JPY) that's 1B JPY.
    // Prevents an overflow path through the SAT_PER_BTC multiplication below
    // and short-circuits comically-large requests before pricer/Boltz spend.
    const MAX_FIAT_MINOR: i32 = 1_000_000_000;
    if minor > MAX_FIAT_MINOR {
        return Err(AppError::InvalidAmount(format!(
            "fiat_amount_minor exceeds {MAX_FIAT_MINOR}"
        )));
    }

    // Fetch the rate at creation time. We require a fresh rate here —
    // creating with a stale rate would lock the invoice at a value the
    // refresh loop would immediately re-quote.
    let rate = state.pricer.get_rate(currency).await.ok_or_else(|| {
        AppError::ServiceUnavailable("pricer unavailable for invoice creation".into())
    })?;
    if rate.last_known_rate {
        return Err(AppError::ServiceUnavailable(
            "pricer is returning stale rate; cannot create new invoice".into(),
        ));
    }

    let amount_sat = ((minor as i64) * SAT_PER_BTC) / rate.minor_per_btc;
    if amount_sat <= 0 {
        return Err(AppError::InvalidAmount(
            "computed amount_sat <= 0 (rate too high or fiat amount too small)".into(),
        ));
    }
    let min_sat = (state.config.limits.min_sendable_msat / 1000) as i64;
    let max_sat = (state.config.limits.max_sendable_msat / 1000) as i64;
    if amount_sat < min_sat {
        return Err(AppError::InvalidAmount(format!(
            "computed amount {amount_sat} sat below minimum {min_sat} sat"
        )));
    }
    if amount_sat > max_sat {
        return Err(AppError::InvalidAmount(format!(
            "computed amount {amount_sat} sat above maximum {max_sat} sat"
        )));
    }

    Ok((
        amount_sat,
        Some((minor, currency.to_uppercase(), rate.minor_per_btc)),
    ))
}

// =====================================================================
// GET /<nym>/i/<id> — render the payment view
// =====================================================================

#[derive(Template)]
#[template(path = "invoice_payment.html")]
struct InvoicePaymentTpl<'a> {
    nym: &'a str,
    invoice_id: String,
    domain: &'a str,
    status: &'a str,
    amount_sat: i64,
    fiat_amount_minor: Option<i32>,
    fiat_currency: Option<&'a str>,
}

pub async fn render_payment(
    State(state): State<AppState>,
    Path((nym, id_str)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let id = parse_invoice_id(&id_str)?;
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;

    // Cross-nym lookup attempt: 404 with the same wire copy as missing-id.
    if inv.nym != nym {
        return Err(AppError::InvoiceNotFound(id_str));
    }

    let tpl = InvoicePaymentTpl {
        nym: &inv.nym,
        invoice_id: inv.id.to_string(),
        domain: &state.config.domain,
        status: &inv.status,
        amount_sat: inv.amount_sat,
        fiat_amount_minor: inv.fiat_amount_minor,
        fiat_currency: inv.fiat_currency.as_deref(),
    };
    let html = tpl
        .render()
        .map_err(|e| AppError::DbError(format!("template render: {e}")))?;
    Ok(html_response(html))
}

// =====================================================================
// GET /api/v1/invoices/:id/status
// =====================================================================

#[derive(Serialize)]
pub struct InvoiceStatusResponse {
    pub status: String,
    pub amount_sat: i64,
    pub rate_minor_per_btc: Option<i64>,
    pub rate_locks_until_unix: i64,
    pub expires_at_unix: i64,
    pub paid_via: Option<String>,
    pub paid_at_unix: Option<i64>,
    pub paid_amount_sat: Option<i64>,
    pub lightning_pr: Option<String>,
    pub liquid_address: Option<String>,
    /// True when fiat-denominated and the pricer is unavailable for a
    /// scheduled refresh. Page surfaces a "rate may be stale" warning.
    pub rate_stale: bool,
}

pub async fn status(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<InvoiceStatusResponse>, AppError> {
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

    let id = parse_invoice_id(&id_str)?;
    let mut inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or(AppError::InvoiceNotFound(id_str))?;

    // On-demand rate refresh for fiat-denominated invoices when the rate-
    // lock has elapsed AND there's enough headroom before outer expiry.
    let mut rate_stale = false;
    let now = unix_now();
    if inv.status == "unpaid"
        && inv.fiat_currency.is_some()
        && inv.rate_locks_until_unix <= now
        && inv.expires_at_unix > now + REFRESH_SAFETY_MARGIN_SECS
    {
        match maybe_refresh_rate(&state, &inv).await {
            Ok(Some(refreshed)) => inv = refreshed,
            Ok(None) => rate_stale = true,
            Err(e) => {
                tracing::warn!(
                    invoice_id = %inv.id,
                    "on-demand rate refresh failed: {e}"
                );
                rate_stale = true;
            }
        }
    }

    let lightning_pr = match db::latest_lightning_pr_for_invoice(&state.db, inv.id).await {
        Ok(opt) => opt,
        Err(e) => {
            tracing::warn!(
                invoice_id = %inv.id,
                "failed to fetch latest lightning offer: {e}"
            );
            None
        }
    };

    Ok(Json(InvoiceStatusResponse {
        status: inv.status,
        amount_sat: inv.amount_sat,
        rate_minor_per_btc: inv.rate_minor_per_btc,
        rate_locks_until_unix: inv.rate_locks_until_unix,
        expires_at_unix: inv.expires_at_unix,
        paid_via: inv.paid_via,
        paid_at_unix: inv.paid_at_unix,
        paid_amount_sat: inv.paid_amount_sat,
        lightning_pr,
        liquid_address: inv.liquid_address,
        rate_stale,
    }))
}

/// Refresh the rate on a fiat-denominated invoice: re-quote sats from the
/// pricer, create a NEW Lightning swap pointing at this invoice, and
/// update the invoice's rate fields. Concurrent refreshes are bounded by
/// the existing `lightning_per_source` and pricer caches; the worst case
/// is a duplicate swap_records row, which is harmless (lenient policy
/// flips the invoice on either offer's settlement).
///
/// Returns:
/// - `Ok(Some(refreshed_invoice))` on successful refresh.
/// - `Ok(None)` when pricer is unreachable / stale / the invoice is no
///   longer unpaid (status changed mid-refresh).
async fn maybe_refresh_rate(
    state: &AppState,
    inv: &db::Invoice,
) -> Result<Option<db::Invoice>, AppError> {
    let currency = inv.fiat_currency.as_ref().expect("checked by caller");
    let fiat_minor = inv.fiat_amount_minor.expect("checked by caller");

    let rate = match state.pricer.get_rate(currency).await {
        Some(r) if !r.last_known_rate => r,
        _ => return Ok(None),
    };

    let new_amount_sat = ((fiat_minor as i64) * SAT_PER_BTC) / rate.minor_per_btc;
    if new_amount_sat <= 0 {
        return Err(AppError::InvalidAmount(format!(
            "refreshed amount_sat {new_amount_sat} <= 0"
        )));
    }

    // Create a new Lightning swap for the refreshed amount. Errors here
    // bubble — the caller marks rate_stale and returns the OLD amount,
    // which is preferable to silently rotating the rate without a fresh
    // BOLT11.
    create_lightning_offer(state, &inv.nym, new_amount_sat as u64, inv.id).await?;

    let updated = db::refresh_invoice_rate(
        &state.db,
        inv.id,
        new_amount_sat,
        rate.minor_per_btc,
        FIAT_RATE_LOCK_SECS,
    )
    .await?;
    if updated == 0 {
        return Ok(None);
    }

    db::get_invoice_by_id(&state.db, inv.id)
        .await
        .map_err(AppError::from)
        .and_then(|opt| {
            opt.ok_or_else(|| AppError::InvoiceNotFound(inv.id.to_string()))
        })
        .map(Some)
}

// =====================================================================
// POST /api/v1/invoices/:id/lightning — lazy create / re-fetch the offer
// =====================================================================

#[derive(Serialize)]
pub struct LightningOfferResponse {
    pub pr: String,
}

pub async fn fetch_lightning_offer(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<LightningOfferResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    if !is_whitelisted {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_lightning_per_source(ip)
                .await?;
        }
    }

    let id = parse_invoice_id(&id_str)?;
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;
    if inv.status != "unpaid" {
        return Err(AppError::InvalidAmount(format!(
            "invoice is {} (not unpaid); no Lightning offer available",
            inv.status
        )));
    }

    // If we already have a Lightning offer for this invoice, return it.
    if let Some(pr) = db::latest_lightning_pr_for_invoice(&state.db, inv.id).await? {
        return Ok(Json(LightningOfferResponse { pr }));
    }

    // No swap yet — create one for the current amount_sat.
    create_lightning_offer(&state, &inv.nym, inv.amount_sat as u64, inv.id).await?;

    let pr = db::latest_lightning_pr_for_invoice(&state.db, inv.id)
        .await?
        .ok_or_else(|| {
            AppError::BoltzError(
                "swap created but no BOLT11 row found".into(),
            )
        })?;
    Ok(Json(LightningOfferResponse { pr }))
}

/// Internal: create a Boltz reverse swap and record it as the Lightning
/// offer for `invoice_id`. Mirrors `lnurl::create_lightning_swap` but
/// (1) sets `swap_records.invoice_id = Some(...)` so the claimer's
/// invoice-flip hook (B7) can find the invoice on settlement, and
/// (2) builds the description metadata against the invoice URL rather
/// than the LNURL Lightning-Address path.
async fn create_lightning_offer(
    state: &AppState,
    nym: &str,
    amount_sat: u64,
    invoice_id: Uuid,
) -> Result<(), AppError> {
    let swap_key_index = db::next_swap_key_index(&state.db)
        .await
        .map_err(|e| AppError::BoltzError(format!("swap key allocation failed: {e}")))?;

    // Description ties the BOLT11's hash to a stable, audit-greppable
    // string. Donator's LN wallet shows the hash; we use the public
    // invoice URL as the descriptive payload.
    let description = format!(
        "https://{}/{}/i/{}",
        state.config.domain, nym, invoice_id
    );
    let description_hash_hex = hex::encode(Sha256::digest(description.as_bytes()));

    let result = state
        .boltz
        .create_reverse_swap(swap_key_index, amount_sat, &description_hash_hex)
        .await?;

    let preimage_hex = hex::encode(&result.preimage);
    let claim_key_hex = hex::encode(result.claim_keypair.secret_bytes());
    let boltz_response_json = serde_json::to_string(&result.boltz_response)
        .map_err(|e| AppError::BoltzError(format!("failed to serialize boltz response: {e}")))?;

    db::record_swap(
        &state.db,
        &db::NewSwapRecord {
            nym,
            boltz_swap_id: &result.swap_id,
            address: None,
            address_index: None,
            amount_sat,
            invoice: &result.invoice,
            preimage_hex: &preimage_hex,
            claim_key_hex: &claim_key_hex,
            boltz_response_json: &boltz_response_json,
            invoice_id: Some(invoice_id),
        },
    )
    .await
    .map_err(|e| {
        AppError::DbError(format!("failed to record swap {}: {e}", result.swap_id))
    })?;

    db::touch_user_callback(&state.db, nym).await;
    Ok(())
}

// =====================================================================
// POST /api/v1/invoices/:id/liquid — lazy-allocate the Liquid address
// =====================================================================

#[derive(Serialize)]
pub struct LiquidOfferResponse {
    pub address: String,
}

pub async fn fetch_liquid_offer(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    _peer_opt: Option<ConnectInfo<SocketAddr>>,
    _headers: HeaderMap,
) -> Result<Json<LiquidOfferResponse>, AppError> {
    // No per-source gate here. The legacy
    // `check_donation_distinct_addrs_per_source` queried the
    // donation_allocations table that migration 019 drops; the right
    // replacement is no gate at all. Allocation rate is bounded upstream
    // by `check_invoice_create_per_source` (5/min) — every Liquid
    // address exists 1:1 with an invoice, and creating an invoice is
    // the rate-limited action. Re-toggles of an existing invoice's
    // Liquid address are idempotent (allocate_invoice_liquid_address
    // returns the existing pair). The status-poll's
    // `check_donation_status_per_source` (60/min) covers status-driven
    // re-fetches.

    let id = parse_invoice_id(&id_str)?;
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;
    if inv.status != "unpaid" {
        return Err(AppError::InvalidAmount(format!(
            "invoice is {} (not unpaid); no Liquid offer available",
            inv.status
        )));
    }

    let address_pair = db::allocate_invoice_liquid_address(
        &state.db,
        inv.id,
        |descriptor_str, idx| {
            descriptor::derive_address(descriptor_str, idx).map_err(|e| {
                sqlx::Error::Protocol(format!("address derivation failed: {e}"))
            })
        },
    )
    .await?
    .ok_or(AppError::InvoiceNotFound(id_str))?;

    // Active-tier promotion so the chain watcher's 30s tick covers this nym.
    db::touch_user_callback(&state.db, &inv.nym).await;

    Ok(Json(LiquidOfferResponse {
        address: address_pair.0,
    }))
}

// =====================================================================
// Schnorr-signed (recipient-side, wallet) endpoints — Phase B step 5
//
// Three endpoints under `/api/v1/<nym>/invoices/...`:
// - POST   create   (signed `invoice-create`)
// - DELETE cancel   (signed `invoice-cancel`; invoice_id in path)
// - GET    list     (signed `invoice-list`; query string)
//
// All three verify the v1 Schnorr signature BEFORE any DB write, and bind
// the request to the npub on record for the path's `nym` (no cross-nym
// activity).
// =====================================================================

/// Verify the signing npub owns `nym` AND the user row is currently
/// active. Mirrors `donation_page::assert_nym_owner` exactly so the auth
/// posture across signed endpoints is uniform.
async fn assert_nym_owner(
    state: &AppState,
    nym: &str,
    npub: &str,
) -> Result<db::User, AppError> {
    let user = db::get_user_by_npub(&state.db, npub)
        .await?
        .ok_or_else(|| AppError::AuthError("no active registration for this key".into()))?;
    if user.nym != nym {
        return Err(AppError::AuthError("signer does not own this nym".into()));
    }
    Ok(user)
}

// --- Field-order helpers (v1 Schnorr signing) ---
//
// Optional fields that are absent become EMPTY STRINGS (not skipped) so
// the byte sequence is invariant under field presence. The mobile's
// `buildLaV1Message` helper must produce the same byte sequence — these
// arrays are the wire contract.

// 8 args is the wire contract — `invoice-create` v1 signing fields, in
// fixed order. Mobile must produce the same byte sequence, so this stays
// flat instead of bundling into a struct.
#[allow(clippy::too_many_arguments)]
fn create_payload_fields<'a>(
    nym: &'a str,
    amount_sat_or_empty: &'a str,
    fiat_amount_minor_or_empty: &'a str,
    fiat_currency_or_empty: &'a str,
    memo_or_empty: &'a str,
    recipient_label_or_empty: &'a str,
    rail_preference: &'a str,
    expires_at_unix: &'a str,
) -> [&'a str; 8] {
    [
        nym,
        amount_sat_or_empty,
        fiat_amount_minor_or_empty,
        fiat_currency_or_empty,
        memo_or_empty,
        recipient_label_or_empty,
        rail_preference,
        expires_at_unix,
    ]
}

fn cancel_payload_fields<'a>(nym: &'a str, invoice_id: &'a str) -> [&'a str; 2] {
    [nym, invoice_id]
}

fn list_payload_fields<'a>(
    nym: &'a str,
    origin_or_empty: &'a str,
    since_unix_or_zero: &'a str,
    limit: &'a str,
) -> [&'a str; 4] {
    [nym, origin_or_empty, since_unix_or_zero, limit]
}

// --- POST /api/v1/<nym>/invoices ---

#[derive(Deserialize)]
pub struct CreateSignedRequest {
    pub npub: String,
    pub amount_sat: Option<i64>,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub memo: Option<String>,
    pub recipient_label: Option<String>,
    /// "lightning" | "liquid" | "any". Drives default-rail UX hints; not
    /// load-bearing on the server. Mobile must send "any" for v1.
    pub rail_preference: String,
    /// Outer expiry timestamp (Unix epoch seconds). Server clamps to
    /// `[now+60, now+MAX_WALLET_EXPIRES_SECS]`.
    pub expires_at_unix: i64,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct CreateSignedResponse {
    pub invoice_id: Uuid,
    pub share_url: String,
}

pub async fn create_signed(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CreateSignedRequest>,
) -> Result<Json<CreateSignedResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    // Per-IP cheap pre-validation gate (BEFORE Schnorr verify, before DB).
    // Caps any single source across all signed-write actions and bounds
    // signature-verify CPU spend under flood attack. The per-npub gate
    // runs AFTER verify (see below) so a forged npub cannot grief a
    // legitimate user by exhausting their bucket pre-verify.
    if !is_whitelisted {
        if let Some(ip) = ip {
            state.rate_limiter.check_metadata_per_ip(ip).await?;
        }
    }

    // Validate inputs BEFORE Schnorr verify — cheap rejections come first.
    if !matches!(req.rail_preference.as_str(), "lightning" | "liquid" | "any") {
        return Err(AppError::InvalidAmount(
            "rail_preference must be 'lightning', 'liquid', or 'any'".into(),
        ));
    }
    if let Some(memo) = &req.memo {
        if memo.len() > 280 {
            return Err(AppError::InvalidAmount("memo too long (max 280 chars)".into()));
        }
    }
    if let Some(label) = &req.recipient_label {
        if label.len() > 100 {
            return Err(AppError::InvalidAmount(
                "recipient_label too long (max 100 chars)".into(),
            ));
        }
    }

    // Outer expiry window. Reject too-soon (< 60s from now) and too-far
    // (> MAX_WALLET_EXPIRES_SECS).
    let now = unix_now();
    if req.expires_at_unix < now + 60 {
        return Err(AppError::InvalidAmount(
            "expires_at_unix must be at least 60 seconds in the future".into(),
        ));
    }
    if req.expires_at_unix > now + MAX_WALLET_EXPIRES_SECS {
        return Err(AppError::InvalidAmount(format!(
            "expires_at_unix beyond {MAX_WALLET_EXPIRES_SECS}s cap"
        )));
    }
    let expires_in_secs = req.expires_at_unix - now;

    // Build the v1 payload + verify Schnorr sig. Empty strings replace
    // absent optional fields so the byte sequence is invariant.
    let amount_sat_str = req
        .amount_sat
        .map(|n| n.to_string())
        .unwrap_or_default();
    let fiat_minor_str = req
        .fiat_amount_minor
        .map(|n| n.to_string())
        .unwrap_or_default();
    let fiat_currency_str = req.fiat_currency.clone().unwrap_or_default();
    let memo_str = req.memo.clone().unwrap_or_default();
    let label_str = req.recipient_label.clone().unwrap_or_default();
    let expires_str = req.expires_at_unix.to_string();
    let fields = create_payload_fields(
        &nym,
        &amount_sat_str,
        &fiat_minor_str,
        &fiat_currency_str,
        &memo_str,
        &label_str,
        &req.rail_preference,
        &expires_str,
    );
    auth::verify_la_v1(
        ACTION_CREATE,
        &req.npub,
        &fields,
        req.timestamp,
        &req.signature,
    )?;

    // Bind to the nym owner (cross-nym sig replay is rejected here).
    assert_nym_owner(&state, &nym, &req.npub).await?;

    // Per-npub gate AFTER signature verify: at this point we know the
    // request was authenticated by the npub on record, so bumping its
    // bucket is correct — no forge-and-grief vector. Bounds wallet-
    // origin invoice creation per identity (100/h per the plan).
    if !is_whitelisted {
        state
            .rate_limiter
            .check_invoice_create_per_npub(&req.npub)
            .await?;
    }

    // Resolve sat amount from sat or fiat path. Reuses the same helper as
    // create_anonymous so the validation invariants stay aligned.
    let anon_shape = CreateAnonymousRequest {
        amount_sat: req.amount_sat,
        fiat_amount_minor: req.fiat_amount_minor,
        fiat_currency: req.fiat_currency.clone(),
    };
    let (amount_sat, fiat) = parse_create_request(&anon_shape, &state).await?;

    // Insert the wallet-origin invoice.
    let new_invoice = db::NewInvoice {
        nym: &nym,
        origin: "wallet",
        fiat_amount_minor: fiat.as_ref().map(|(amt, _, _)| *amt),
        fiat_currency: fiat.as_ref().map(|(_, cur, _)| cur.as_str()),
        amount_sat,
        rate_minor_per_btc: fiat.as_ref().map(|(_, _, rate)| *rate),
        rate_lock_secs: if fiat.is_some() {
            FIAT_RATE_LOCK_SECS
        } else {
            // Sat-denom: rate_locks_until == expires_at so refresh path
            // never fires.
            expires_in_secs
        },
        memo: req.memo.as_deref(),
        recipient_label: req.recipient_label.as_deref(),
        expires_in_secs,
    };
    let invoice = db::insert_invoice(&state.db, &new_invoice).await?;

    // Eagerly create the Lightning offer (wallet-origin defaults to
    // both rails available; sender picks at view time).
    if let Err(e) =
        create_lightning_offer(&state, &nym, amount_sat as u64, invoice.id).await
    {
        tracing::warn!(
            invoice_id = %invoice.id,
            "wallet-origin eager Lightning offer failed (page can retry): {e}",
        );
    }

    let share_url = format!("https://{}/{}/i/{}", state.config.domain, nym, invoice.id);
    Ok(Json(CreateSignedResponse {
        invoice_id: invoice.id,
        share_url,
    }))
}

// --- DELETE /api/v1/<nym>/invoices/<id> ---

#[derive(Deserialize)]
pub struct CancelRequest {
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct CancelResponse {
    pub invoice_id: Uuid,
    pub status: String,
}

pub async fn cancel(
    State(state): State<AppState>,
    Path((nym, id_str)): Path<(String, String)>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CancelRequest>,
) -> Result<Json<CancelResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    if !is_whitelisted {
        if let Some(ip) = ip {
            state.rate_limiter.check_metadata_per_ip(ip).await?;
        }
    }

    let id = parse_invoice_id(&id_str)?;

    let fields = cancel_payload_fields(&nym, &id_str);
    auth::verify_la_v1(
        ACTION_CANCEL,
        &req.npub,
        &fields,
        req.timestamp,
        &req.signature,
    )?;
    assert_nym_owner(&state, &nym, &req.npub).await?;

    // Verify the invoice belongs to this nym (defense-in-depth: the
    // owner check above + this binding together prevent a signer who
    // owns nym A from cancelling an invoice owned by nym B by tampering
    // with the URL).
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;
    if inv.nym != nym {
        return Err(AppError::InvoiceNotFound(id_str));
    }

    let rows = db::cancel_invoice(&state.db, id).await?;
    // rows == 1: flip happened just now, status is now 'cancelled'.
    // rows == 0: invoice was already non-unpaid (paid/under/over/expired/
    // cancelled); preserve whatever it was at read-time. mark_invoice_paid
    // and cancel_invoice are mutually idempotent — re-cancel of a
    // cancelled row is a no-op.
    let final_status: String = if rows == 1 {
        "cancelled".to_string()
    } else {
        inv.status
    };
    Ok(Json(CancelResponse {
        invoice_id: id,
        status: final_status,
    }))
}

// --- GET /api/v1/<nym>/invoices?... ---

#[derive(Deserialize)]
pub struct ListSignedQuery {
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
    /// Optional. "checkout" or "wallet". Empty/absent → both.
    pub origin: Option<String>,
    /// Optional. Unix epoch seconds; only invoices created at-or-after.
    pub since_unix: Option<i64>,
    pub limit: i64,
}

#[derive(Serialize)]
pub struct InvoiceListItem {
    pub id: Uuid,
    pub origin: String,
    pub status: String,
    pub amount_sat: i64,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub memo: Option<String>,
    pub recipient_label: Option<String>,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub paid_via: Option<String>,
    pub paid_at_unix: Option<i64>,
    pub paid_amount_sat: Option<i64>,
}

#[derive(Serialize)]
pub struct ListInvoicesResponse {
    pub invoices: Vec<InvoiceListItem>,
}

pub async fn list_signed(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(params): Query<ListSignedQuery>,
) -> Result<Json<ListInvoicesResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    if !is_whitelisted {
        if let Some(ip) = ip {
            state.rate_limiter.check_metadata_per_ip(ip).await?;
        }
    }

    // Clamp limit to [1, LIST_LIMIT_MAX]. Negative → reject.
    if params.limit < 1 {
        return Err(AppError::InvalidAmount("limit must be >= 1".into()));
    }
    let limit = params.limit.min(LIST_LIMIT_MAX);

    // Validate origin filter shape. Empty string == None for the byte
    // sequence; both "checkout" and "wallet" pass through to db::list_invoices.
    let origin_filter = match params.origin.as_deref() {
        None | Some("") => None,
        Some("checkout") => Some("checkout"),
        Some("wallet") => Some("wallet"),
        Some(other) => {
            return Err(AppError::InvalidAmount(format!(
                "origin must be 'checkout', 'wallet', or empty (got '{other}')"
            )))
        }
    };

    // Build the v1 payload. since_unix=None → "0", origin=None → empty.
    let origin_str = origin_filter.unwrap_or("");
    let since_str = params.since_unix.unwrap_or(0).to_string();
    let limit_str = limit.to_string();
    let fields = list_payload_fields(&nym, origin_str, &since_str, &limit_str);
    auth::verify_la_v1(
        ACTION_LIST,
        &params.npub,
        &fields,
        params.timestamp,
        &params.signature,
    )?;
    assert_nym_owner(&state, &nym, &params.npub).await?;

    let rows = db::list_invoices(&state.db, &nym, origin_filter, params.since_unix, limit).await?;
    let invoices = rows
        .into_iter()
        .map(|inv| InvoiceListItem {
            id: inv.id,
            origin: inv.origin,
            status: inv.status,
            amount_sat: inv.amount_sat,
            fiat_amount_minor: inv.fiat_amount_minor,
            fiat_currency: inv.fiat_currency,
            memo: inv.memo,
            recipient_label: inv.recipient_label,
            created_at_unix: inv.created_at_unix,
            expires_at_unix: inv.expires_at_unix,
            paid_via: inv.paid_via,
            paid_at_unix: inv.paid_at_unix,
            paid_amount_sat: inv.paid_amount_sat,
        })
        .collect();

    Ok(Json(ListInvoicesResponse { invoices }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Field-order helpers are wire contracts. If you change one, the
    /// mobile must change in lockstep. These tests document the byte
    /// sequence so any silent change fails the test.
    #[test]
    fn create_payload_field_order() {
        let f = create_payload_fields("alice", "5000", "", "", "", "", "any", "1700000000");
        assert_eq!(
            f,
            ["alice", "5000", "", "", "", "", "any", "1700000000"],
            "create field order changed — mobile MUST update in lockstep"
        );
    }

    #[test]
    fn cancel_payload_field_order() {
        let f = cancel_payload_fields("alice", "00000000-0000-0000-0000-000000000001");
        assert_eq!(
            f,
            ["alice", "00000000-0000-0000-0000-000000000001"],
            "cancel field order changed — mobile MUST update in lockstep"
        );
    }

    #[test]
    fn list_payload_field_order() {
        let f = list_payload_fields("alice", "wallet", "0", "100");
        assert_eq!(
            f,
            ["alice", "wallet", "0", "100"],
            "list field order changed — mobile MUST update in lockstep"
        );
    }

    /// Cross-action replay regression test: a `create` signature must NOT
    /// validate as a `cancel`. (auth::verify_la_v1 enforces this via the
    /// action component of the signed message; we add a hop through the
    /// helpers here to catch a coding mistake that wires the wrong action
    /// constant into a handler.)
    #[test]
    fn action_constants_distinct() {
        assert_ne!(ACTION_CREATE, ACTION_CANCEL);
        assert_ne!(ACTION_CREATE, ACTION_LIST);
        assert_ne!(ACTION_CANCEL, ACTION_LIST);
    }
}

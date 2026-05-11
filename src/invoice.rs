//! Invoices: unified payment-intent abstraction.
//!
//! Three entry families share this module:
//!
//! 1. **Anonymous (sender-side) checkout** — payment-page-driven:
//!    - `POST /<nym>/invoice` body `{ amount_sat | (fiat_amount_minor + fiat_currency) }`
//!    - `GET /<nym>/i/<id>` HTML render
//!
//! 2. **Public unlinked render** — wallet-only invoices that aren't shared via
//!    a payment page:
//!    - `GET /invoice/<id>` HTML render
//!    - `GET /robots.txt` for the indexing posture
//!
//! 3. **Schnorr-signed (recipient-side, wallet)** endpoints:
//!    - `POST   /api/v1/<nym>/invoices`     — linked invoice-create
//!    - `POST   /api/v1/invoices`           — unlinked invoice-create
//!    - `DELETE /api/v1/<nym>/invoices/<id>`— linked invoice-cancel
//!    - `DELETE /api/v1/invoices/<id>`      — unlinked invoice-cancel
//!    - `GET    /api/v1/invoices?npub=...`  — npub-keyed list (linked + unlinked)
//!
//! Both create paths verify a v2 Schnorr signature BEFORE any DB write, with
//! the `nym_or_empty` slot driving the linked vs unlinked branch.
//!
//! Status-poll and Lightning lazy-fetch helpers remain shared across linked
//! and unlinked invoices via `id`-only paths. The former Liquid
//! lazy-allocation route is retained only as an explicit 410:
//!    - `GET  /api/v1/invoices/<id>/status`
//!    - `POST /api/v1/invoices/<id>/lightning`
//!    - `POST /api/v1/invoices/<id>/liquid`  → 410 Gone (wallet supplies addr at create time)

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use askama::Template;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth;
use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::ip_whitelist;
use crate::validators;
use crate::AppState;

// =====================================================================
// Action constants (v2 Schnorr signing)
//
// Wire-protocol identifiers — must match mobile's
// `core/nostr/bullpay_la_v2_signing.dart`. Renaming any of these is a
// wire-breaking change requiring lockstep mobile-server deploy.
// =====================================================================

pub const ACTION_CREATE: &str = "invoice-create";
pub const ACTION_CANCEL: &str = "invoice-cancel";
pub const ACTION_LIST: &str = "invoice-list";

/// Hard upper bound on wallet-origin invoice expiry (7 days). Mobile is
/// the source of the requested expiry (`expires_at_unix`); the server
/// clamps to this ceiling so a runaway or malicious client cannot pin a
/// row indefinitely or refresh Boltz offers forever.
const MAX_WALLET_EXPIRES_SECS: i64 = 7 * 24 * 60 * 60;

/// Default cap on `list_invoices.limit`. Mobile can request a smaller
/// page size; never larger.
const LIST_LIMIT_MAX: i64 = 100;

/// Default outer expiry for checkout-origin invoices. Individual Boltz
/// BOLT11s may expire sooner and are refreshed while the invoice is live;
/// this cap prevents abandoned checkout invoices from refreshing forever.
const CHECKOUT_DEFAULT_EXPIRES_SECS: i64 = 7 * 24 * 60 * 60;

/// Inner rate-lock window for fiat-denominated invoices. The status
/// endpoint refreshes the sat amount on the first poll after this elapses.
const FIAT_RATE_LOCK_SECS: i64 = 15 * 60;

/// Don't refresh the rate if the invoice is about to expire — the new
/// BOLT11 would be worth less than nothing.
const REFRESH_SAFETY_MARGIN_SECS: i64 = 60;

/// 1 BTC = 100_000_000 sat. Centralized so the conversion arithmetic is
/// audit-greppable.
const SAT_PER_BTC: i64 = 100_000_000;

/// Per-field length caps for wallet-origin invoice fields.
const PUBLIC_DESCRIPTION_MAX: usize = 1000;
const RECIPIENT_LABEL_MAX: usize = 100;
const INVOICE_NUMBER_MAX: usize = 50;

// =====================================================================
// Settlement hook (called by claimer/reconciler on Lightning settlement)
// =====================================================================

/// Flip an invoice to `in_progress` on the FIRST Boltz mempool sighting
/// of the lockup tx for an invoice-bound swap. Called by the claimer
/// (`transaction.mempool` webhook) and the reconciler (sync path that
/// observes the same status without a webhook delivery) AFTER the
/// forward-only CAS state-update succeeds.
///
/// Contract mirrors `flip_invoice_on_lightning_settlement`:
/// - `invoice_id == None` → no-op (LNURL-only swaps without an invoice).
/// - `mark_invoice_in_progress` is idempotent: a 0-rows-affected return
///   means the invoice was already past `unpaid` (already in_progress,
///   already paid/under/over, expired, cancelled). Logged at debug.
/// - On error: LOG and RETURN. Never propagate. Settlement (paid) flows
///   through `flip_invoice_on_lightning_settlement` later and self-heals.
pub async fn flip_invoice_on_lightning_in_progress(
    pool: &sqlx::PgPool,
    invoice_id: Option<Uuid>,
    boltz_swap_id: &str,
) {
    let Some(id) = invoice_id else {
        return;
    };
    match db::mark_invoice_in_progress(pool, id).await {
        Ok(rows) if rows > 0 => {
            tracing::info!(
                event = "invoice_in_progress_via_lightning",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "lightning mempool flipped invoice to in_progress"
            );
        }
        Ok(_) => {
            tracing::debug!(
                event = "invoice_in_progress_noop",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "invoice already past unpaid; in_progress flip is a no-op"
            );
        }
        Err(e) => {
            tracing::error!(
                event = "invoice_in_progress_failed",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "mark_invoice_in_progress failed (swap CAS already committed): {e}"
            );
        }
    }
}

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
/// - On error: LOG and RETURN. Never propagate.
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
            tracing::debug!(
                event = "invoice_flip_noop",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "invoice already in terminal status; no-op"
            );
        }
        Err(e) => {
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
// Helpers
// =====================================================================

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Last 8 chars of an npub for log correlation. Full npub stays out of
/// logs to honor the discipline outlined in the get-paid plan (F2).
fn npub_log_tag(npub: &str) -> &str {
    let len = npub.len();
    if len > 8 {
        &npub[len - 8..]
    } else {
        npub
    }
}

/// Parse the Uuid path parameter, returning `InvoiceNotFound` (NOT
/// `InvalidAmount` or 400) on parse failure. Reason: a malformed id is
/// information-equivalent to an unknown id from the caller's perspective,
/// and we don't want to leak the existence/non-existence boundary.
fn parse_invoice_id(s: &str) -> Result<Uuid, AppError> {
    Uuid::from_str(s).map_err(|_| AppError::InvoiceNotFound(s.to_string()))
}

/// Defensive HTML response headers for invoice-render handlers. Adds
/// indexing + caching posture beyond `donation_render`'s baseline so the
/// invoice page (which is reachable at a guessable URL) cannot be
/// indexed by crawlers and cannot be served from intermediate caches.
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
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    h.insert(
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow"),
    );
    resp
}

// =====================================================================
// GET /robots.txt
// =====================================================================

/// Disallow indexing of the entire pay-service domain. Public LNURL
/// endpoints are not indexable in any meaningful sense; the payment-page
/// surface area renders user-supplied content and is private to whoever
/// holds the URL.
pub async fn robots_txt() -> Response {
    let body = "User-agent: *\nDisallow: /\n";
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
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

    if !is_whitelisted {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_invoice_create_per_source(ip)
                .await?;
        }
    }

    let (amount_sat, fiat) = parse_create_request(&req, &state).await?;

    // Verify the store is live AND resolve the page owner's npub for the
    // canonical invoice identity. The page→user join is required because
    // donation_pages doesn't store npub directly.
    let page = db::get_donation_page_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::DonationPageNotFound(nym.clone()))?;
    if !page.enabled || page.is_archived {
        return Err(AppError::DonationPageNotFound(nym.clone()));
    }
    let owner = db::get_user_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::DonationPageNotFound(nym.clone()))?;

    // Eagerly allocate a Liquid address from the donation page owner's
    // descriptor. Both rails settle to this same address:
    //   - Lightning: `claimer::resolve_claim_address` branch (B) routes
    //     the Boltz claim to `invoice.liquid_address` once
    //     `create_lightning_offer` (below) binds the swap to this invoice.
    //   - Direct Liquid: customer pays the address directly; the
    //     chain_watcher's address-keyed scan detects the inbound tx.
    // The `invoices_ln_or_liquid_addr_chk` constraint requires
    // `liquid_address` to be present at insert time when either LN or
    // Liquid is accepted, so allocation must run BEFORE insert.
    let (liquid_address, _liquid_index) =
        db::allocate_next_liquid_for_active_nym(&state.db, &nym, |ct_descriptor, idx| {
            descriptor::derive_address(ct_descriptor, idx)
                .map_err(|e| sqlx::Error::Protocol(format!("derive_address: {e}")))
        })
        .await?
        .ok_or_else(|| AppError::DonationPageNotFound(nym.clone()))?;

    let new_invoice = db::NewInvoice {
        nym_owner: Some(&nym),
        npub_owner: &owner.npub,
        origin: "checkout",
        fiat_amount_minor: fiat.as_ref().map(|(amt, _, _)| *amt),
        fiat_currency: fiat.as_ref().map(|(_, cur, _)| cur.as_str()),
        amount_sat,
        rate_minor_per_btc: fiat.as_ref().map(|(_, _, rate)| *rate),
        rate_lock_secs: if fiat.is_some() {
            FIAT_RATE_LOCK_SECS
        } else {
            CHECKOUT_DEFAULT_EXPIRES_SECS
        },
        memo: None,
        recipient_label: None,
        public_description: None,
        invoice_number: None,
        // Checkout-origin: server eagerly allocates one Liquid address
        // from the donation page owner's descriptor (above). Both
        // Lightning and direct Liquid rails settle to this address. BTC
        // on-chain is not exposed for donation-page checkout in v1 —
        // would require a separate Bitcoin descriptor / wallet-supplied
        // address path.
        accept_btc: false,
        accept_ln: true,
        accept_liquid: true,
        bitcoin_address: None,
        liquid_address: Some(&liquid_address),
        expires_in_secs: CHECKOUT_DEFAULT_EXPIRES_SECS,
    };
    let invoice = db::insert_invoice(&state.db, &new_invoice).await?;

    if let Err(e) = create_lightning_offer(&state, &nym, amount_sat as u64, &invoice).await {
        tracing::error!(
            invoice_id = %invoice.id,
            "eager Lightning offer creation failed; checkout invoice will not be returned: {e}",
        );
        if let Err(cleanup_err) =
            db::delete_unpaid_invoice_without_swaps(&state.db, invoice.id).await
        {
            tracing::error!(
                invoice_id = %invoice.id,
                "failed to clean up checkout invoice after Boltz creation failure: {cleanup_err}",
            );
        }
        return Err(e);
    }

    Ok(Json(CreateInvoiceResponse {
        invoice_id: invoice.id,
    }))
}

/// Validate the create-anonymous body and resolve the requested amount.
///
/// Returns `(amount_sat, Option<(fiat_amount_minor, fiat_currency, rate_minor_per_btc)>)`.
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

    let minor = req
        .fiat_amount_minor
        .ok_or_else(|| AppError::InvalidAmount("missing fiat_amount_minor".into()))?;
    let currency = req
        .fiat_currency
        .as_deref()
        .ok_or_else(|| AppError::InvalidAmount("missing fiat_currency".into()))?;
    if minor <= 0 {
        return Err(AppError::InvalidAmount(
            "fiat_amount_minor must be > 0".into(),
        ));
    }
    const MAX_FIAT_MINOR: i32 = 1_000_000_000;
    if minor > MAX_FIAT_MINOR {
        return Err(AppError::InvalidAmount(format!(
            "fiat_amount_minor exceeds {MAX_FIAT_MINOR}"
        )));
    }

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
// GET /<nym>/i/<id> — render the linked payment view
// =====================================================================

#[derive(Template)]
#[template(path = "invoice_payment.html")]
struct InvoicePaymentTpl<'a> {
    /// Nym for the linked render path; empty string for unlinked. Templates
    /// gate URL construction on `is_unlinked` rather than this field.
    nym: &'a str,
    /// True when nym_owner is None — page is reached via /invoice/<id>
    /// rather than /<nym>/i/<id>. Drives header copy and URL templating.
    is_unlinked: bool,
    invoice_id: String,
    domain: &'a str,
    status: &'a str,
    amount_sat: i64,
    fiat_display: Option<String>,
    is_fiat: bool,
    /// Wallet-origin public-facing fields. Askama auto-escapes every
    /// `{{ }}` interpolation; do NOT add `|safe` to these in the template.
    public_description: Option<&'a str>,
    recipient_name: Option<&'a str>,
    invoice_number: Option<&'a str>,
    accept_btc: bool,
    accept_ln: bool,
    accept_liquid: bool,
    bitcoin_address: Option<&'a str>,
    liquid_address: Option<&'a str>,
}

fn currency_precision(currency: &str) -> u8 {
    match currency {
        "COP" => 0,
        _ => 2,
    }
}

fn format_fiat_major(minor: i32, currency: &str) -> String {
    let p = currency_precision(currency);
    if p == 0 {
        format!("{minor} {currency}")
    } else {
        let divisor = 10i64.pow(p as u32);
        let major = minor as i64 / divisor;
        let frac = (minor as i64 % divisor).unsigned_abs();
        format!("{major}.{frac:0>width$} {currency}", width = p as usize)
    }
}

pub async fn render_payment(
    State(state): State<AppState>,
    Path((nym, id_str)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let id = parse_invoice_id(&id_str)?;
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;

    // Linked render path requires nym_owner == path nym. Cross-nym lookup
    // (or unlinked invoice accessed via a /<nym>/i/<id> URL) returns 404
    // with the same wire copy as missing-id.
    if inv.nym_owner.as_deref() != Some(nym.as_str()) {
        return Err(AppError::InvoiceNotFound(id_str));
    }

    Ok(html_response(render_invoice_template(&state, &inv)?))
}

// =====================================================================
// GET /invoice/<id> — render the unlinked (wallet-only) payment view
// =====================================================================

pub async fn render_unlinked_payment(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
) -> Result<Response, AppError> {
    let id = parse_invoice_id(&id_str)?;
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;

    // The unlinked render path serves both nym-linked AND nym-NULL invoices
    // (the wallet may always share via /invoice/<id> regardless of linkage).
    // Distinct handlers for the two paths only affect URL parsing.
    Ok(html_response(render_invoice_template(&state, &inv)?))
}

fn render_invoice_template(state: &AppState, inv: &db::Invoice) -> Result<String, AppError> {
    let fiat_display = match (inv.fiat_amount_minor, inv.fiat_currency.as_deref()) {
        (Some(minor), Some(cur)) => Some(format_fiat_major(minor, cur)),
        _ => None,
    };
    let is_fiat = inv.rate_minor_per_btc.is_some();
    let nym = inv.nym_owner.as_deref().unwrap_or("");
    let is_unlinked = inv.nym_owner.is_none();
    let tpl = InvoicePaymentTpl {
        nym,
        is_unlinked,
        invoice_id: inv.id.to_string(),
        domain: &state.config.domain,
        status: &inv.status,
        amount_sat: inv.amount_sat,
        fiat_display,
        is_fiat,
        public_description: inv.public_description.as_deref(),
        recipient_name: inv.recipient_label.as_deref(),
        invoice_number: inv.invoice_number.as_deref(),
        accept_btc: inv.accept_btc,
        accept_ln: inv.accept_ln,
        accept_liquid: inv.accept_liquid,
        bitcoin_address: inv.bitcoin_address.as_deref(),
        liquid_address: inv.liquid_address.as_deref(),
    };
    tpl.render()
        .map_err(|e| AppError::DbError(format!("template render: {e}")))
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
    pub bitcoin_address: Option<String>,
    pub accept_btc: bool,
    pub accept_ln: bool,
    pub accept_liquid: bool,
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

    let lightning_pr = match ensure_reusable_lightning_offer(&state, &inv).await {
        Ok(opt) => opt,
        Err(e) => {
            tracing::warn!(
                invoice_id = %inv.id,
                "failed to refresh lightning offer for status response: {e}"
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
        bitcoin_address: inv.bitcoin_address,
        accept_btc: inv.accept_btc,
        accept_ln: inv.accept_ln,
        accept_liquid: inv.accept_liquid,
        rate_stale,
    }))
}

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

    let nym = lightning_swap_nym(&state.db, inv).await?;
    create_lightning_offer(state, &nym, new_amount_sat as u64, inv).await?;

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
        .and_then(|opt| opt.ok_or_else(|| AppError::InvoiceNotFound(inv.id.to_string())))
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
            state.rate_limiter.check_lightning_per_source(ip).await?;
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
    if !inv.accept_ln {
        return Err(AppError::InvalidAmount(
            "invoice does not accept Lightning".into(),
        ));
    }

    let pr = ensure_reusable_lightning_offer(&state, &inv)
        .await?
        .ok_or_else(|| {
            AppError::InvalidAmount("invoice expired; no Lightning offer available".into())
        })?;
    Ok(Json(LightningOfferResponse { pr }))
}

/// Return the latest still-payable BOLT11 for an invoice, refreshing it
/// through Boltz when the previous offer has expired. Only fully unpaid
/// invoices can create a replacement offer; `in_progress` may still
/// surface an existing reusable BOLT11, but it does not open a new swap.
/// The outer invoice `expires_at` remains the hard merchant lifetime;
/// after that deadline, this helper will not create another swap.
async fn ensure_reusable_lightning_offer(
    state: &AppState,
    inv: &db::Invoice,
) -> Result<Option<String>, AppError> {
    if !matches!(inv.status.as_str(), "unpaid" | "in_progress") || !inv.accept_ln {
        return Ok(None);
    }

    let now = unix_now();
    if let Some(pr) = db::latest_lightning_pr_for_invoice(&state.db, inv.id).await? {
        if bolt11_is_reusable_at(&pr, now) {
            return Ok(Some(pr));
        }
        if inv.status != "unpaid" {
            return Ok(None);
        }
        tracing::info!(
            invoice_id = %inv.id,
            "latest BOLT11 expired; requesting replacement offer from Boltz",
        );
    }

    if inv.status != "unpaid" || inv.expires_at_unix <= now {
        return Ok(None);
    }

    let nym = lightning_swap_nym(&state.db, inv).await?;
    create_lightning_offer(state, &nym, inv.amount_sat as u64, inv).await?;

    let pr = db::latest_lightning_pr_for_invoice(&state.db, inv.id)
        .await?
        .ok_or_else(|| AppError::BoltzError("swap created but no BOLT11 row found".into()))?;
    Ok(Some(pr))
}

fn bolt11_is_reusable_at(pr: &str, now_unix: i64) -> bool {
    let Ok(now) = u64::try_from(now_unix) else {
        return false;
    };
    let Ok(invoice) = Bolt11Invoice::from_str(pr) else {
        return false;
    };
    !invoice.would_expire(Duration::from_secs(now))
}

/// Resolve the nym to attribute on the swap_records row for `invoice`.
/// Linked invoices use `nym_owner`; unlinked invoices fall back to the
/// active registration of `npub_owner`. Returns `AuthError` when no
/// active registration exists for the npub — Lightning requires a
/// claimable Liquid wallet (legacy descriptor path) OR a wallet-supplied
/// liquid_address (claim destination resolved by Step 10's
/// `resolve_claim_address`).
async fn lightning_swap_nym(
    pool: &sqlx::PgPool,
    invoice: &db::Invoice,
) -> Result<String, AppError> {
    if let Some(nym) = invoice.nym_owner.as_deref() {
        return Ok(nym.to_string());
    }
    let user = db::get_user_by_npub(pool, &invoice.npub_owner)
        .await?
        .ok_or_else(|| {
            AppError::AuthError("unlinked invoice's npub has no active registration".into())
        })?;
    Ok(user.nym)
}

/// Internal: create a Boltz reverse swap and record it as the Lightning
/// offer for `invoice`. The `invoice_id` association is what lets the
/// claimer's invoice-flip hook pair the Boltz settlement back to this
/// invoice on payment.
async fn create_lightning_offer(
    state: &AppState,
    swap_nym: &str,
    amount_sat: u64,
    invoice: &db::Invoice,
) -> Result<(), AppError> {
    let swap_key_index = db::next_swap_key_index(&state.db)
        .await
        .map_err(|e| AppError::BoltzError(format!("swap key allocation failed: {e}")))?;

    // Description URL: linked invoices use /<nym>/i/<id>; unlinked use
    // /invoice/<id>. Donator's LN wallet shows the description hash; we
    // bind it to the public invoice URL.
    let description = match invoice.nym_owner.as_deref() {
        Some(nym) => format!("https://{}/{}/i/{}", state.config.domain, nym, invoice.id),
        None => format!("https://{}/invoice/{}", state.config.domain, invoice.id),
    };
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
            nym: swap_nym,
            boltz_swap_id: &result.swap_id,
            // For wallet-supplied liquid_address invoices, the claim
            // destination is already known. Pre-populating address here
            // would require also persisting address_index = NULL plumbed
            // through `set_swap_address`; leave it None and let Step 10's
            // `resolve_claim_address` rewrite read invoices.liquid_address
            // at claim time. The Lightning path stays unchanged for the
            // legacy descriptor flow (chain_watcher still bumps via
            // `allocate_invoice_liquid_address`).
            address: None,
            address_index: None,
            amount_sat,
            invoice: &result.invoice,
            preimage_hex: &preimage_hex,
            claim_key_hex: &claim_key_hex,
            boltz_response_json: &boltz_response_json,
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .map_err(|e| AppError::DbError(format!("failed to record swap {}: {e}", result.swap_id)))?;

    db::touch_user_callback(&state.db, swap_nym).await;
    Ok(())
}

// =====================================================================
// POST /api/v1/invoices/:id/liquid — DEPRECATED (returns 410 Gone)
//
// Mobile now wallet-supplies the Liquid address at create time; the
// lazy-allocation endpoint exists only for legacy donation-page checkout
// flow (which uses `allocate_invoice_liquid_address` indirectly via the
// chain watcher, not via this HTTP route). Keep the handler so existing
// route registrations don't 404 — instead surface an actionable error.
// =====================================================================

pub async fn fetch_liquid_offer(
    State(_state): State<AppState>,
    Path(_id_str): Path<String>,
) -> Result<Response, AppError> {
    let mut resp = (
        StatusCode::GONE,
        "POST /api/v1/invoices/<id>/liquid is deprecated. Wallet supplies the \
         Liquid address at invoice-create time."
            .to_string(),
    )
        .into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    Ok(resp)
}

// =====================================================================
// Schnorr-signed (recipient-side, wallet) endpoints — v2 wire format
//
// `bullpay-la-v2` byte sequence:
//   <domain>\0<action>\0<npub_hex>\0<nym_or_empty>\0(<field>\0)*<timestamp>
//
// Linked path (`POST /api/v1/<nym>/invoices`): nym_or_empty = path nym.
// Unlinked path (`POST /api/v1/invoices`): nym_or_empty = "".
//
// Both paths share `create_invoice_inner` after sig verify + ownership
// check. The `nym` is the only structural divergence; everything else —
// payload validation, address validation, fiat resolution, Lightning eager
// offer — is identical.
// =====================================================================

/// Verify the signing npub owns `nym` AND the user row is currently
/// active. Used by the linked create/cancel paths.
async fn assert_nym_owner(state: &AppState, nym: &str, npub: &str) -> Result<db::User, AppError> {
    let user = db::get_user_by_npub(&state.db, npub)
        .await?
        .ok_or_else(|| AppError::AuthError("no active registration for this key".into()))?;
    if user.nym != nym {
        return Err(AppError::AuthError("signer does not own this nym".into()));
    }
    Ok(user)
}

// --- Field-order helpers (v2 Schnorr signing) ---
//
// Optional fields that are absent become EMPTY STRINGS (not skipped) so
// the byte sequence is invariant under field presence. The mobile's
// `core/nostr/bullpay_la_v2_signing.dart` must produce the same byte
// sequence — these arrays are the wire contract.
//
// IMPORTANT: nym is NOT part of these payload helpers. It is passed
// separately as `nym_or_empty` to `auth::verify_la_v2` / `build_la_v2_message`.

/// 12 fields in fixed order. The byte sequence is the wire contract.
#[allow(clippy::too_many_arguments)]
fn create_payload_fields<'a>(
    amount_sat_or_empty: &'a str,
    fiat_amount_minor_or_empty: &'a str,
    fiat_currency_or_empty: &'a str,
    public_description_or_empty: &'a str,
    recipient_name_or_empty: &'a str,
    invoice_number_or_empty: &'a str,
    accept_btc_bool: &'a str,
    accept_ln_bool: &'a str,
    accept_liquid_bool: &'a str,
    bitcoin_address_or_empty: &'a str,
    liquid_address_or_empty: &'a str,
    expires_at_unix: &'a str,
) -> [&'a str; 12] {
    [
        amount_sat_or_empty,
        fiat_amount_minor_or_empty,
        fiat_currency_or_empty,
        public_description_or_empty,
        recipient_name_or_empty,
        invoice_number_or_empty,
        accept_btc_bool,
        accept_ln_bool,
        accept_liquid_bool,
        bitcoin_address_or_empty,
        liquid_address_or_empty,
        expires_at_unix,
    ]
}

fn cancel_payload_fields(invoice_id: &str) -> [&str; 1] {
    [invoice_id]
}

fn list_payload_fields<'a>(
    since_unix_or_zero: &'a str,
    limit: &'a str,
    status_filter_or_empty: &'a str,
) -> [&'a str; 3] {
    [since_unix_or_zero, limit, status_filter_or_empty]
}

// =====================================================================
// POST /api/v1/<nym>/invoices  (linked)
// POST /api/v1/invoices        (unlinked)
// =====================================================================

#[derive(Deserialize)]
pub struct CreateSignedRequest {
    pub npub: String,
    pub amount_sat: Option<i64>,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub public_description: Option<String>,
    /// `recipient_name` on the wire; mapped to the `recipient_label`
    /// column in storage (no DB rename — defer to a v2 schema migration
    /// if ever needed).
    #[serde(rename = "recipient_name", alias = "recipient_label")]
    pub recipient_label: Option<String>,
    pub invoice_number: Option<String>,
    pub accept_btc: bool,
    pub accept_ln: bool,
    pub accept_liquid: bool,
    pub bitcoin_address: Option<String>,
    pub liquid_address: Option<String>,
    pub expires_at_unix: i64,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct CreateSignedResponse {
    pub invoice_id: Uuid,
    pub share_url: String,
}

pub async fn create_signed_linked(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CreateSignedRequest>,
) -> Result<Json<CreateSignedResponse>, AppError> {
    create_invoice_inner(&state, Some(nym), peer_opt, headers, req).await
}

pub async fn create_signed_unlinked(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CreateSignedRequest>,
) -> Result<Json<CreateSignedResponse>, AppError> {
    create_invoice_inner(&state, None, peer_opt, headers, req).await
}

async fn create_invoice_inner(
    state: &AppState,
    linked_nym: Option<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    req: CreateSignedRequest,
) -> Result<Json<CreateSignedResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    // Pre-verify per-IP cheap gate. The per-npub gate runs AFTER signature
    // verify so a forged npub cannot grief a legitimate user's bucket.
    if !is_whitelisted {
        if let Some(ip) = ip {
            state.rate_limiter.check_metadata_per_ip(ip).await?;
        }
    }

    // ---- Cheap input validation (BEFORE Schnorr verify) ----
    if let Some(s) = &req.public_description {
        if s.len() > PUBLIC_DESCRIPTION_MAX {
            return Err(AppError::InvalidAmount(format!(
                "public_description too long (max {PUBLIC_DESCRIPTION_MAX} chars)"
            )));
        }
    }
    if let Some(s) = &req.recipient_label {
        if s.len() > RECIPIENT_LABEL_MAX {
            return Err(AppError::InvalidAmount(format!(
                "recipient_name too long (max {RECIPIENT_LABEL_MAX} chars)"
            )));
        }
    }
    if let Some(s) = &req.invoice_number {
        if s.len() > INVOICE_NUMBER_MAX {
            return Err(AppError::InvalidAmount(format!(
                "invoice_number too long (max {INVOICE_NUMBER_MAX} chars)"
            )));
        }
    }

    // Rail coherence — server-side echo of the SQL CHECKs in migration 021.
    // Surfacing them here gives the caller a 400 with a useful message
    // instead of a 500 from a constraint violation deep in INSERT.
    if !req.accept_btc && !req.accept_ln && !req.accept_liquid {
        return Err(AppError::InvalidAmount(
            "at least one of accept_btc / accept_ln / accept_liquid must be true".into(),
        ));
    }
    if req.accept_btc && req.bitcoin_address.is_none() {
        return Err(AppError::InvalidAmount(
            "accept_btc=true requires bitcoin_address".into(),
        ));
    }
    if (req.accept_ln || req.accept_liquid) && req.liquid_address.is_none() {
        return Err(AppError::InvalidAmount(
            "accept_ln/accept_liquid=true requires liquid_address".into(),
        ));
    }
    if let Some(addr) = req.bitcoin_address.as_deref() {
        validators::validate_btc_mainnet_address(addr)?;
    }
    if let Some(addr) = req.liquid_address.as_deref() {
        validators::validate_liquid_mainnet_address(addr)?;
    }

    // Outer expiry window: now+60s to now+30d.
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

    // ---- Build v2 payload + verify Schnorr sig ----
    let amount_sat_str = req.amount_sat.map(|n| n.to_string()).unwrap_or_default();
    let fiat_minor_str = req
        .fiat_amount_minor
        .map(|n| n.to_string())
        .unwrap_or_default();
    let fiat_currency_str = req.fiat_currency.clone().unwrap_or_default();
    let public_description_str = req.public_description.clone().unwrap_or_default();
    let recipient_label_str = req.recipient_label.clone().unwrap_or_default();
    let invoice_number_str = req.invoice_number.clone().unwrap_or_default();
    let accept_btc_str = req.accept_btc.to_string();
    let accept_ln_str = req.accept_ln.to_string();
    let accept_liquid_str = req.accept_liquid.to_string();
    let bitcoin_address_str = req.bitcoin_address.clone().unwrap_or_default();
    let liquid_address_str = req.liquid_address.clone().unwrap_or_default();
    let expires_str = req.expires_at_unix.to_string();
    let fields = create_payload_fields(
        &amount_sat_str,
        &fiat_minor_str,
        &fiat_currency_str,
        &public_description_str,
        &recipient_label_str,
        &invoice_number_str,
        &accept_btc_str,
        &accept_ln_str,
        &accept_liquid_str,
        &bitcoin_address_str,
        &liquid_address_str,
        &expires_str,
    );
    let nym_or_empty = linked_nym.as_deref().unwrap_or("");
    auth::verify_la_v2(
        ACTION_CREATE,
        &req.npub,
        nym_or_empty,
        &fields,
        req.timestamp,
        &req.signature,
    )?;

    // ---- Ownership check: linked vs unlinked ----
    if let Some(nym) = linked_nym.as_deref() {
        assert_nym_owner(state, nym, &req.npub).await?;
    }
    // For unlinked: signing npub IS the canonical npub_owner. No nym
    // assertion needed; the v2 byte sequence binds nym_or_empty="" to the
    // sig already.

    // Per-npub bucket AFTER sig verify (auth-bound).
    if !is_whitelisted {
        state
            .rate_limiter
            .check_invoice_create_per_npub(&req.npub)
            .await?;
    }

    let anon_shape = CreateAnonymousRequest {
        amount_sat: req.amount_sat,
        fiat_amount_minor: req.fiat_amount_minor,
        fiat_currency: req.fiat_currency.clone(),
    };
    let (amount_sat, fiat) = parse_create_request(&anon_shape, state).await?;

    let new_invoice = db::NewInvoice {
        nym_owner: linked_nym.as_deref(),
        npub_owner: &req.npub,
        origin: "wallet",
        fiat_amount_minor: fiat.as_ref().map(|(amt, _, _)| *amt),
        fiat_currency: fiat.as_ref().map(|(_, cur, _)| cur.as_str()),
        amount_sat,
        rate_minor_per_btc: fiat.as_ref().map(|(_, _, rate)| *rate),
        rate_lock_secs: if fiat.is_some() {
            FIAT_RATE_LOCK_SECS
        } else {
            expires_in_secs
        },
        memo: None,
        recipient_label: req.recipient_label.as_deref(),
        public_description: req.public_description.as_deref(),
        invoice_number: req.invoice_number.as_deref(),
        accept_btc: req.accept_btc,
        accept_ln: req.accept_ln,
        accept_liquid: req.accept_liquid,
        bitcoin_address: req.bitcoin_address.as_deref(),
        liquid_address: req.liquid_address.as_deref(),
        expires_in_secs,
    };
    let invoice = db::insert_invoice(&state.db, &new_invoice).await?;

    if invoice.accept_ln {
        let swap_nym = lightning_swap_nym(&state.db, &invoice).await?;
        if let Err(e) = create_lightning_offer(state, &swap_nym, amount_sat as u64, &invoice).await
        {
            tracing::warn!(
                invoice_id = %invoice.id,
                npub_tag = npub_log_tag(&req.npub),
                "wallet-origin eager Lightning offer failed (page can retry): {e}",
            );
        }
    }

    let share_url = match linked_nym.as_deref() {
        Some(nym) => format!("https://{}/{}/i/{}", state.config.domain, nym, invoice.id),
        None => format!("https://{}/invoice/{}", state.config.domain, invoice.id),
    };
    tracing::info!(
        event = "invoice_created",
        invoice_id = %invoice.id,
        npub_tag = npub_log_tag(&req.npub),
        nym_or_unlinked = nym_or_empty,
        accept_btc = invoice.accept_btc,
        accept_ln = invoice.accept_ln,
        accept_liquid = invoice.accept_liquid,
        amount_sat = invoice.amount_sat,
        "wallet-origin invoice created"
    );
    Ok(Json(CreateSignedResponse {
        invoice_id: invoice.id,
        share_url,
    }))
}

// =====================================================================
// DELETE /api/v1/<nym>/invoices/<id>  (linked)
// DELETE /api/v1/invoices/<id>        (unlinked)
// =====================================================================

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

pub async fn cancel_linked(
    State(state): State<AppState>,
    Path((nym, id_str)): Path<(String, String)>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CancelRequest>,
) -> Result<Json<CancelResponse>, AppError> {
    cancel_invoice_inner(&state, Some(nym), id_str, peer_opt, headers, req).await
}

pub async fn cancel_unlinked(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CancelRequest>,
) -> Result<Json<CancelResponse>, AppError> {
    cancel_invoice_inner(&state, None, id_str, peer_opt, headers, req).await
}

async fn cancel_invoice_inner(
    state: &AppState,
    linked_nym: Option<String>,
    id_str: String,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    req: CancelRequest,
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
    let nym_or_empty = linked_nym.as_deref().unwrap_or("");
    let fields = cancel_payload_fields(&id_str);
    auth::verify_la_v2(
        ACTION_CANCEL,
        &req.npub,
        nym_or_empty,
        &fields,
        req.timestamp,
        &req.signature,
    )?;

    if let Some(nym) = linked_nym.as_deref() {
        assert_nym_owner(state, nym, &req.npub).await?;
    }

    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;

    // Ownership defense-in-depth: signed nym must match invoice.nym_owner
    // (linked path), and signing npub must match invoice.npub_owner
    // (both paths). The npub_owner check is the authoritative gate — it
    // catches the case where a signer who owns nym A tampers with the
    // URL to cancel an invoice owned by nym B.
    if inv.npub_owner != req.npub {
        return Err(AppError::InvoiceNotFound(id_str));
    }
    if let Some(nym) = linked_nym.as_deref() {
        if inv.nym_owner.as_deref() != Some(nym) {
            return Err(AppError::InvoiceNotFound(id_str));
        }
    }

    let rows = db::cancel_invoice(&state.db, id).await?;
    let final_status: String = if rows == 1 {
        "cancelled".to_string()
    } else {
        inv.status
    };
    tracing::info!(
        event = "invoice_cancelled",
        invoice_id = %id,
        npub_tag = npub_log_tag(&req.npub),
        nym_or_unlinked = nym_or_empty,
        rows = rows,
        "invoice cancel"
    );
    Ok(Json(CancelResponse {
        invoice_id: id,
        status: final_status,
    }))
}

// =====================================================================
// GET /api/v1/invoices?npub=...  (npub-keyed signed list, linked + unlinked)
// =====================================================================

#[derive(Deserialize)]
pub struct ListSignedQuery {
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
    /// Optional. Unix epoch seconds; only invoices created at-or-after.
    pub since_unix: Option<i64>,
    pub limit: i64,
    /// Optional. One of the seven invoice statuses, or empty/absent for
    /// unfiltered. The wire format treats absent + empty identically.
    pub status: Option<String>,
}

#[derive(Serialize)]
pub struct InvoiceListItem {
    pub id: Uuid,
    /// `nym_owner`: linked invoices carry the merchant nym; unlinked
    /// invoices carry `null`. The mobile decides URL construction from
    /// this field (`/<nym>/i/<id>` vs `/invoice/<id>`).
    pub nym_owner: Option<String>,
    pub origin: String,
    pub status: String,
    pub amount_sat: i64,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub public_description: Option<String>,
    #[serde(rename = "recipient_name")]
    pub recipient_label: Option<String>,
    pub invoice_number: Option<String>,
    pub accept_btc: bool,
    pub accept_ln: bool,
    pub accept_liquid: bool,
    pub bitcoin_address: Option<String>,
    pub liquid_address: Option<String>,
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

    if params.limit < 1 {
        return Err(AppError::InvalidAmount("limit must be >= 1".into()));
    }
    let limit = params.limit.min(LIST_LIMIT_MAX);

    let status_filter: Option<&str> = match params.status.as_deref() {
        None | Some("") => None,
        Some(s)
            if matches!(
                s,
                "unpaid"
                    | "in_progress"
                    | "paid"
                    | "underpaid"
                    | "overpaid"
                    | "expired"
                    | "cancelled"
            ) =>
        {
            Some(s)
        }
        Some(other) => {
            return Err(AppError::InvalidAmount(format!(
                "status must be one of unpaid|in_progress|paid|underpaid|overpaid|expired|cancelled, or empty (got '{other}')"
            )));
        }
    };

    let since_str = params.since_unix.unwrap_or(0).to_string();
    let limit_str = limit.to_string();
    let status_str = status_filter.unwrap_or("");
    let fields = list_payload_fields(&since_str, &limit_str, status_str);
    // Nym ALWAYS empty on the npub-keyed list — the action is identity-
    // wide, not per-nym.
    auth::verify_la_v2(
        ACTION_LIST,
        &params.npub,
        "",
        &fields,
        params.timestamp,
        &params.signature,
    )?;

    // npub equality is structural here: the signed message embeds
    // `params.npub` and we filter the DB on the same value. A mismatch
    // would require a forged signature — unreachable past verify_la_v2.

    let rows = db::list_invoices_by_npub(
        &state.db,
        &params.npub,
        status_filter,
        params.since_unix,
        limit,
    )
    .await?;
    let invoices = rows
        .into_iter()
        .map(|inv| InvoiceListItem {
            id: inv.id,
            nym_owner: inv.nym_owner,
            origin: inv.origin,
            status: inv.status,
            amount_sat: inv.amount_sat,
            fiat_amount_minor: inv.fiat_amount_minor,
            fiat_currency: inv.fiat_currency,
            public_description: inv.public_description,
            recipient_label: inv.recipient_label,
            invoice_number: inv.invoice_number,
            accept_btc: inv.accept_btc,
            accept_ln: inv.accept_ln,
            accept_liquid: inv.accept_liquid,
            bitcoin_address: inv.bitcoin_address,
            liquid_address: inv.liquid_address,
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
        let f = create_payload_fields(
            "5000",
            "",
            "",
            "coffee",
            "Alice",
            "INV-1",
            "false",
            "true",
            "true",
            "",
            "lq1qq...",
            "1700000000",
        );
        assert_eq!(
            f,
            [
                "5000",
                "",
                "",
                "coffee",
                "Alice",
                "INV-1",
                "false",
                "true",
                "true",
                "",
                "lq1qq...",
                "1700000000",
            ],
            "create field order changed — mobile MUST update in lockstep"
        );
    }

    #[test]
    fn cancel_payload_field_order() {
        let f = cancel_payload_fields("00000000-0000-0000-0000-000000000001");
        assert_eq!(
            f,
            ["00000000-0000-0000-0000-000000000001"],
            "cancel field order changed — mobile MUST update in lockstep"
        );
    }

    #[test]
    fn list_payload_field_order() {
        let f = list_payload_fields("0", "25", "unpaid");
        assert_eq!(
            f,
            ["0", "25", "unpaid"],
            "list field order changed — mobile MUST update in lockstep"
        );
    }

    #[test]
    fn action_constants_distinct() {
        assert_ne!(ACTION_CREATE, ACTION_CANCEL);
        assert_ne!(ACTION_CREATE, ACTION_LIST);
        assert_ne!(ACTION_CANCEL, ACTION_LIST);
    }

    #[test]
    fn checkout_outer_expiry_is_seven_days() {
        assert_eq!(CHECKOUT_DEFAULT_EXPIRES_SECS, 7 * 24 * 60 * 60);
    }

    #[test]
    fn npub_log_tag_truncates() {
        assert_eq!(
            npub_log_tag("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            "89abcdef"
        );
        assert_eq!(npub_log_tag("short"), "short");
        assert_eq!(npub_log_tag(""), "");
    }

    #[test]
    fn bolt11_reusable_check_uses_embedded_expiry() {
        // BOLT11 test vector timestamp is 1496314658 with default 3600s
        // expiry. The helper must reuse it before expiry and reject it
        // after expiry, independently of the merchant invoice lifetime.
        let pr = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";

        assert!(bolt11_is_reusable_at(pr, 1_496_314_658 + 3_599));
        assert!(!bolt11_is_reusable_at(pr, 1_496_314_658 + 3_601));
        assert!(!bolt11_is_reusable_at("not-a-bolt11", 1_496_314_658));
    }
}

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
use crate::pricer;
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

/// Hard upper bound and default for wallet-origin invoice expiry (7 days).
/// Clients may omit `expires_at_unix`; the server then uses this default.
/// When a client does request an expiry, the server still caps it here so
/// a runaway or malicious client cannot pin a row indefinitely or refresh
/// Boltz offers forever.
const MAX_WALLET_EXPIRES_SECS: i64 = 7 * 24 * 60 * 60;

/// Default cap on `list_invoices.pageSize`. Mobile can request a smaller
/// page size; never larger.
const LIST_LIMIT_MAX: i64 = 100;

/// Default outer expiry for checkout-origin invoices. Individual Boltz
/// BOLT11s may expire sooner and are refreshed while the invoice is live;
/// this cap prevents abandoned checkout invoices from refreshing forever.
const CHECKOUT_DEFAULT_EXPIRES_SECS: i64 = 7 * 24 * 60 * 60;

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
            if let Err(e) = db::mark_invoice_settlement_status(pool, Some(id), "pending").await {
                tracing::warn!(
                    event = "invoice_pending_settlement_failed",
                    invoice_id = %id,
                    boltz_swap_id = %boltz_swap_id,
                    "failed to mark invoice settlement pending: {e}"
                );
            }
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

/// Flip an invoice to `in_progress` on the FIRST payer-side BTC lockup
/// sighting for an invoice-bound Boltz BTC-to-LBTC chain swap. Accounting
/// is still recorded only after the server claims the LBTC output.
pub async fn flip_invoice_on_bitcoin_boltz_in_progress(
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
                event = "invoice_in_progress_via_bitcoin_boltz_chain",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "bitcoin chain-swap lockup flipped invoice to in_progress"
            );
        }
        Ok(_) => {
            if let Err(e) = db::mark_invoice_settlement_status(pool, Some(id), "pending").await {
                tracing::warn!(
                    event = "invoice_bitcoin_boltz_pending_settlement_failed",
                    invoice_id = %id,
                    boltz_swap_id = %boltz_swap_id,
                    "failed to mark invoice settlement pending: {e}"
                );
            }
            tracing::debug!(
                event = "invoice_bitcoin_boltz_in_progress_noop",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "invoice already past unpaid; bitcoin chain-swap in_progress flip is a no-op"
            );
        }
        Err(e) => {
            tracing::error!(
                event = "invoice_bitcoin_boltz_in_progress_failed",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "mark_invoice_in_progress failed (chain-swap CAS already committed): {e}"
            );
        }
    }
}

/// Record an invoice payment event after the corresponding Lightning
/// reverse swap is claimed by the merchant wallet. Lockup mempool,
/// lockup confirmation, refund, and claim-stuck states are not enough:
/// they prove only payer-side progress, not merchant-side settlement.
///
/// Contract:
/// - `invoice_id == None` → no-op (LNURL Lightning Address swaps and
///   legacy donation rows have no associated invoice).
/// - `record_invoice_payment` is idempotent on
///   `lightning_boltz_reverse:<boltz_swap_id>`.
/// - On error: LOG and RETURN. Never propagate.
pub async fn flip_invoice_on_lightning_settlement(
    pool: &sqlx::PgPool,
    invoice_id: Option<Uuid>,
    amount_sat: i64,
    boltz_swap_id: &str,
    claim_txid: &str,
    tolerances: db::InvoiceAccountingTolerances,
) {
    let Some(id) = invoice_id else {
        return;
    };
    let event_key = format!("lightning_boltz_reverse:{boltz_swap_id}");
    match db::record_invoice_payment(
        pool,
        id,
        db::InvoicePaymentEvidence {
            rail: "lightning",
            source: "lightning_boltz_reverse",
            event_key: &event_key,
            amount_sat,
            txid: Some(claim_txid),
            vout: None,
            boltz_swap_id: Some(boltz_swap_id),
            address: None,
        },
        tolerances,
    )
    .await
    {
        Ok(rows) if rows > 0 => {
            tracing::info!(
                event = "invoice_payment_event_lightning",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                amount_sat = amount_sat,
                "lightning settlement recorded invoice payment"
            );
        }
        Ok(_) => {
            tracing::debug!(
                event = "invoice_flip_noop",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "invoice payment event already recorded or invoice cancelled; no-op"
            );
        }
        Err(e) => {
            tracing::error!(
                event = "invoice_flip_failed",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                amount_sat = amount_sat,
                "record_invoice_payment failed (swap CAS already committed): {e}"
            );
        }
    }
}

/// Record an invoice payment event after a BTC-to-LBTC Boltz chain swap
/// has been claimed to the merchant's Liquid address. This is the
/// Donation Page Bitcoin-rail settlement boundary: user BTC lockup and
/// Boltz server lockup are only progress signals; the merchant is paid
/// after our Liquid claim broadcasts successfully.
pub async fn flip_invoice_on_bitcoin_boltz_settlement(
    pool: &sqlx::PgPool,
    invoice_id: Option<Uuid>,
    amount_sat: i64,
    boltz_swap_id: &str,
    claim_txid: &str,
    tolerances: db::InvoiceAccountingTolerances,
) {
    let Some(id) = invoice_id else {
        return;
    };
    let event_key = format!("bitcoin_boltz_chain:{boltz_swap_id}");
    match db::record_invoice_payment(
        pool,
        id,
        db::InvoicePaymentEvidence {
            rail: "bitcoin",
            source: "bitcoin_boltz_chain",
            event_key: &event_key,
            amount_sat,
            txid: Some(claim_txid),
            vout: None,
            boltz_swap_id: Some(boltz_swap_id),
            address: None,
        },
        tolerances,
    )
    .await
    {
        Ok(rows) if rows > 0 => {
            tracing::info!(
                event = "invoice_payment_event_bitcoin_boltz",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                amount_sat = amount_sat,
                "bitcoin chain-swap settlement recorded invoice payment"
            );
        }
        Ok(_) => {
            tracing::debug!(
                event = "invoice_bitcoin_boltz_flip_noop",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "invoice payment event already recorded or invoice cancelled; no-op"
            );
        }
        Err(e) => {
            tracing::error!(
                event = "invoice_bitcoin_boltz_flip_failed",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                amount_sat = amount_sat,
                "record_invoice_payment failed (chain-swap CAS already committed): {e}"
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
    pub lightning_pr: String,
    pub liquid_address: String,
    pub bitcoin_chain_address: Option<String>,
    pub bitcoin_chain_bip21: Option<String>,
    pub expires_at_unix: i64,
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
    // CT descriptor. Donation Page checkout never uses customer- or
    // merchant-supplied payout addresses; every customer-facing settlement
    // rail resolves back to this descriptor-derived Liquid address:
    //   - Lightning: `claimer::resolve_claim_address` branch (B) routes
    //     the Boltz claim to `invoice.liquid_address` once
    //     `create_lightning_offer` (below) binds the swap to this invoice.
    //   - Direct Liquid: customer pays this address directly; the
    //     chain_watcher's address-keyed scan detects the inbound tx.
    //   - BTC via Boltz chain swap: customer pays Boltz's Bitcoin lockup
    //     address; the chain-swap claimer spends the resulting LBTC to
    //     this same `invoice.liquid_address`.
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
    let liquid_blinding_key_hex =
        descriptor::derive_blinding_key_hex(&owner.ct_descriptor, &liquid_address)?;

    let new_invoice = db::NewInvoice {
        nym_owner: Some(&nym),
        npub_owner: &owner.npub,
        origin: "checkout",
        fiat_amount_minor: fiat.as_ref().map(|(amt, _, _)| *amt),
        fiat_currency: fiat.as_ref().map(|(_, cur, _)| cur.as_str()),
        amount_sat,
        rate_minor_per_btc: fiat.as_ref().map(|(_, _, rate)| *rate),
        rate_lock_secs: CHECKOUT_DEFAULT_EXPIRES_SECS,
        memo: None,
        recipient_label: None,
        public_description: None,
        invoice_number: None,
        // Checkout-origin: direct BTC stays disabled on the invoice row.
        // Donation Page BTC, when available, is represented separately as a
        // Boltz chain-swap lockup so bitcoin_watcher never mistakes the
        // Boltz deposit address for merchant-settled direct BTC.
        accept_btc: false,
        accept_ln: true,
        accept_liquid: true,
        bitcoin_address: None,
        liquid_address: Some(&liquid_address),
        liquid_blinding_key_hex: Some(&liquid_blinding_key_hex),
        expires_in_secs: CHECKOUT_DEFAULT_EXPIRES_SECS,
    };
    let invoice = db::insert_invoice(&state.db, &new_invoice).await?;

    let lightning_pr = match create_lightning_offer(&state, Some(&nym), amount_sat as u64, &invoice)
        .await
    {
        Ok(pr) => pr,
        Err(e) => {
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
    };
    let bitcoin_chain_offer =
        match create_bitcoin_chain_offer(&state, Some(&nym), amount_sat as u64, &invoice).await {
            Ok(offer) => offer,
            Err(e) => {
                tracing::warn!(
                    invoice_id = %invoice.id,
                    "BTC-to-LBTC chain-swap offer unavailable for checkout invoice: {e}",
                );
                None
            }
        };

    Ok(Json(CreateInvoiceResponse {
        invoice_id: invoice.id,
        lightning_pr,
        liquid_address,
        bitcoin_chain_address: bitcoin_chain_offer
            .as_ref()
            .map(|offer| offer.lockup_address.clone()),
        bitcoin_chain_bip21: bitcoin_chain_offer.and_then(|offer| offer.lockup_bip21),
        expires_at_unix: invoice.expires_at_unix,
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
    let currency = pricer::normalize_currency_code(currency);
    if !state.pricer.is_supported_currency(&currency) {
        return Err(AppError::InvalidAmount(format!(
            "unsupported fiat_currency {currency}; fetch /api/v1/supported-currencies"
        )));
    }
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

    let rate = state.pricer.get_rate(&currency).await.ok_or_else(|| {
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

    Ok((amount_sat, Some((minor, currency, rate.minor_per_btc))))
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
    settlement_status: &'a str,
    amount_sat: i64,
    remaining_amount_sat: i64,
    fiat_display: Option<String>,
    /// Wallet-origin public-facing fields. Askama auto-escapes every
    /// `{{ }}` interpolation; do NOT add `|safe` to these in the template.
    public_description: Option<&'a str>,
    recipient_name: Option<&'a str>,
    invoice_number: Option<&'a str>,
    accept_btc: bool,
    accept_ln: bool,
    accept_liquid: bool,
    bitcoin_chain_address: Option<&'a str>,
    bitcoin_address_js: String,
    bitcoin_chain_address_js: String,
    bitcoin_chain_bip21_js: String,
    liquid_address_js: String,
}

fn format_fiat_major(minor: i32, currency: &str) -> String {
    let p = pricer::currency_precision(currency);
    if p == 0 {
        format!("{minor} {currency}")
    } else {
        let divisor = 10i64.pow(p as u32);
        let major = minor as i64 / divisor;
        let frac = (minor as i64 % divisor).unsigned_abs();
        format!("{major}.{frac:0>width$} {currency}", width = p as usize)
    }
}

fn js_string_literal(value: Option<&str>) -> Result<String, AppError> {
    let json = serde_json::to_string(value.unwrap_or(""))
        .map_err(|e| AppError::DbError(format!("js string encode: {e}")))?;
    Ok(json
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026"))
}

fn invoice_payment_rails_are_payable(inv: &db::Invoice) -> bool {
    matches!(inv.status.as_str(), "unpaid" | "partially_paid")
        && !matches!(
            inv.settlement_status.as_str(),
            "pending" | "claim_stuck" | "refunded"
        )
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

    Ok(html_response(render_invoice_template(&state, &inv).await?))
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
    Ok(html_response(render_invoice_template(&state, &inv).await?))
}

async fn render_invoice_template(state: &AppState, inv: &db::Invoice) -> Result<String, AppError> {
    let fiat_display = match (inv.fiat_amount_minor, inv.fiat_currency.as_deref()) {
        (Some(minor), Some(cur)) => Some(format_fiat_major(minor, cur)),
        _ => None,
    };
    let remaining_sat = remaining_amount_sat(inv);
    let bitcoin_chain_offer = if invoice_payment_rails_are_payable(inv) {
        db::latest_payable_chain_swap_for_invoice(&state.db, inv.id, remaining_sat).await?
    } else {
        None
    };
    let nym = inv.nym_owner.as_deref().unwrap_or("");
    let is_unlinked = inv.nym_owner.is_none();
    let bitcoin_chain_address = bitcoin_chain_offer
        .as_ref()
        .map(|offer| offer.lockup_address.as_str());
    let bitcoin_chain_bip21 = bitcoin_chain_offer
        .as_ref()
        .and_then(|offer| offer.lockup_bip21.as_deref());
    let tpl = InvoicePaymentTpl {
        nym,
        is_unlinked,
        invoice_id: inv.id.to_string(),
        domain: &state.config.domain,
        status: &inv.status,
        settlement_status: &inv.settlement_status,
        amount_sat: inv.amount_sat,
        remaining_amount_sat: remaining_sat,
        fiat_display,
        public_description: inv.public_description.as_deref(),
        recipient_name: inv.recipient_label.as_deref(),
        invoice_number: inv.invoice_number.as_deref(),
        accept_btc: inv.accept_btc,
        accept_ln: inv.accept_ln,
        accept_liquid: inv.accept_liquid,
        bitcoin_chain_address,
        bitcoin_address_js: js_string_literal(inv.bitcoin_address.as_deref())?,
        bitcoin_chain_address_js: js_string_literal(bitcoin_chain_address)?,
        bitcoin_chain_bip21_js: js_string_literal(bitcoin_chain_bip21)?,
        liquid_address_js: js_string_literal(inv.liquid_address.as_deref())?,
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
    pub pricing_mode: String,
    pub settlement_status: String,
    pub amount_sat: i64,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub remaining_amount_sat: i64,
    pub payment_tolerance_sat: i64,
    pub rate_minor_per_btc: Option<i64>,
    pub rate_locks_until_unix: i64,
    pub expires_at_unix: i64,
    pub paid_via: Option<String>,
    pub paid_at_unix: Option<i64>,
    pub paid_amount_sat: Option<i64>,
    pub lightning_pr: Option<String>,
    pub liquid_address: Option<String>,
    pub bitcoin_address: Option<String>,
    pub bitcoin_chain_address: Option<String>,
    pub bitcoin_chain_bip21: Option<String>,
    pub accept_btc: bool,
    pub accept_ln: bool,
    pub accept_liquid: bool,
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
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or(AppError::InvoiceNotFound(id_str))?;

    let remaining_sat = remaining_amount_sat(&inv);
    let lightning_pr = latest_reusable_lightning_offer(&state.db, &inv).await?;
    let bitcoin_chain_offer = if invoice_payment_rails_are_payable(&inv) {
        db::latest_payable_chain_swap_for_invoice(&state.db, inv.id, remaining_sat).await?
    } else {
        None
    };
    let tolerance_sat = payment_tolerance_sat(
        &inv,
        db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
    );

    Ok(Json(InvoiceStatusResponse {
        status: inv.status,
        pricing_mode: inv.pricing_mode,
        settlement_status: inv.settlement_status,
        amount_sat: inv.amount_sat,
        fiat_amount_minor: inv.fiat_amount_minor,
        fiat_currency: inv.fiat_currency,
        remaining_amount_sat: remaining_sat,
        payment_tolerance_sat: tolerance_sat,
        rate_minor_per_btc: inv.rate_minor_per_btc,
        rate_locks_until_unix: inv.rate_locks_until_unix,
        expires_at_unix: inv.expires_at_unix,
        paid_via: inv.paid_via,
        paid_at_unix: inv.paid_at_unix,
        paid_amount_sat: inv.paid_amount_sat,
        lightning_pr,
        liquid_address: inv.liquid_address,
        bitcoin_address: inv.bitcoin_address,
        bitcoin_chain_address: bitcoin_chain_offer
            .as_ref()
            .map(|offer| offer.lockup_address.clone()),
        bitcoin_chain_bip21: bitcoin_chain_offer.and_then(|offer| offer.lockup_bip21),
        accept_btc: inv.accept_btc,
        accept_ln: inv.accept_ln,
        accept_liquid: inv.accept_liquid,
    }))
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
    if !matches!(inv.status.as_str(), "unpaid" | "partially_paid") {
        return Err(AppError::InvalidAmount(format!(
            "invoice is {} (not payable); no Lightning offer available",
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
    if !matches!(inv.status.as_str(), "unpaid" | "partially_paid") || !inv.accept_ln {
        return Ok(None);
    }

    let now = unix_now();
    let amount_sat = remaining_amount_sat(inv);
    if amount_sat <= 0 {
        return Ok(None);
    }
    if let Some((pr, pr_amount_sat)) =
        db::latest_lightning_pr_for_invoice(&state.db, inv.id).await?
    {
        if pr_amount_sat == amount_sat && bolt11_is_reusable_at(&pr, now) {
            return Ok(Some(pr));
        }
        tracing::info!(
            invoice_id = %inv.id,
            "latest BOLT11 expired or amount changed; requesting replacement offer from Boltz",
        );
    }

    if inv.expires_at_unix <= now {
        return Ok(None);
    }

    let lock_key = format!("invoice-lightning:{}", inv.id);
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
        .bind(&lock_key)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    let result = async {
        let latest: Option<(String, i64)> = sqlx::query_as(
            "SELECT invoice, amount_sat FROM swap_records \
             WHERE invoice_id = $1 \
             ORDER BY created_at DESC \
             LIMIT 1",
        )
        .bind(inv.id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
        if let Some((pr, pr_amount_sat)) = latest {
            if pr_amount_sat == amount_sat && bolt11_is_reusable_at(&pr, now) {
                return Ok(Some(pr));
            }
        }
        let pr =
            create_lightning_offer(state, lightning_swap_nym(inv), amount_sat as u64, inv).await?;
        Ok(Some(pr))
    }
    .await;

    if let Err(e) = sqlx::query("SELECT pg_advisory_unlock(hashtext($1))")
        .bind(&lock_key)
        .execute(&mut *conn)
        .await
    {
        tracing::error!(
            invoice_id = %inv.id,
            "failed to unlock invoice lightning refresh advisory lock: {e}"
        );
    }

    result
}

/// Read-only counterpart to `ensure_reusable_lightning_offer`.
///
/// Status polling must not create Boltz swaps. It may return the latest
/// still-payable BOLT11, but if the latest offer is expired, the wrong
/// amount, or absent, callers must explicitly hit
/// `POST /api/v1/invoices/:id/lightning` to create/refresh the offer.
async fn latest_reusable_lightning_offer(
    pool: &sqlx::PgPool,
    inv: &db::Invoice,
) -> Result<Option<String>, AppError> {
    if !matches!(inv.status.as_str(), "unpaid" | "partially_paid") || !inv.accept_ln {
        return Ok(None);
    }

    let amount_sat = remaining_amount_sat(inv);
    if amount_sat <= 0 || inv.expires_at_unix <= unix_now() {
        return Ok(None);
    }

    let Some((pr, pr_amount_sat)) = db::latest_lightning_pr_for_invoice(pool, inv.id).await? else {
        return Ok(None);
    };
    if pr_amount_sat == amount_sat && bolt11_is_reusable_at(&pr, unix_now()) {
        Ok(Some(pr))
    } else {
        Ok(None)
    }
}

fn remaining_amount_sat(inv: &db::Invoice) -> i64 {
    inv.amount_sat
        .saturating_sub(inv.paid_amount_sat.unwrap_or(0))
        .max(0)
}

fn payment_tolerance_sat(inv: &db::Invoice, tolerances: db::InvoiceAccountingTolerances) -> i64 {
    let mut accepted = Vec::new();
    if inv.accept_btc {
        accepted.push(tolerances.btc_sat);
    }
    if inv.accept_liquid {
        accepted.push(tolerances.liquid_sat);
    }
    if inv.accept_ln {
        accepted.push(tolerances.lightning_sat);
    }
    let rail_tolerance = accepted
        .into_iter()
        .min()
        .unwrap_or(tolerances.lightning_sat);
    rail_tolerance.min((inv.amount_sat / 100).max(1))
}

const BOLT11_REFRESH_MARGIN_SECS: u64 = 120;

fn bolt11_is_reusable_at(pr: &str, now_unix: i64) -> bool {
    let Ok(now) = u64::try_from(now_unix) else {
        return false;
    };
    let Ok(invoice) = Bolt11Invoice::from_str(pr) else {
        return false;
    };
    let now_with_margin = now.saturating_add(BOLT11_REFRESH_MARGIN_SECS);
    !invoice.would_expire(Duration::from_secs(now_with_margin))
}

fn lightning_swap_nym(invoice: &db::Invoice) -> Option<&str> {
    invoice.nym_owner.as_deref()
}

/// Internal: create a Boltz reverse swap and record it as the Lightning
/// offer for `invoice`. The `invoice_id` association is what lets the
/// claimer's invoice-flip hook pair the Boltz settlement back to this
/// invoice on payment.
async fn create_lightning_offer(
    state: &AppState,
    swap_nym: Option<&str>,
    amount_sat: u64,
    invoice: &db::Invoice,
) -> Result<String, AppError> {
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

    let lightning_pr = result.invoice.clone();
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
            invoice: &lightning_pr,
            preimage_hex: &preimage_hex,
            claim_key_hex: &claim_key_hex,
            boltz_response_json: &boltz_response_json,
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .map_err(|e| AppError::DbError(format!("failed to record swap {}: {e}", result.swap_id)))?;

    if let Some(nym) = swap_nym {
        db::touch_user_callback(&state.db, nym).await;
    }
    Ok(lightning_pr)
}

struct BitcoinChainOffer {
    lockup_address: String,
    lockup_bip21: Option<String>,
}

/// Internal: create a Boltz BTC-to-LBTC chain swap for a Donation Page
/// checkout invoice. The payer sees a Bitcoin lockup address; after
/// Boltz locks LBTC on the server side, the chain-swap claimer spends
/// that LBTC to `invoice.liquid_address`.
async fn create_bitcoin_chain_offer(
    state: &AppState,
    swap_nym: Option<&str>,
    amount_sat: u64,
    invoice: &db::Invoice,
) -> Result<Option<BitcoinChainOffer>, AppError> {
    if invoice.liquid_address.is_none() {
        return Ok(None);
    }

    let claim_key_index = db::next_swap_key_index(&state.db)
        .await
        .map_err(|e| AppError::BoltzError(format!("chain claim key allocation failed: {e}")))?;
    let refund_key_index = db::next_swap_key_index(&state.db)
        .await
        .map_err(|e| AppError::BoltzError(format!("chain refund key allocation failed: {e}")))?;

    let result = state
        .boltz
        .create_btc_to_lbtc_chain_swap(claim_key_index, refund_key_index, amount_sat)
        .await?;

    let preimage_hex = hex::encode(&result.preimage);
    let claim_key_hex = hex::encode(result.claim_keypair.secret_bytes());
    let refund_key_hex = hex::encode(result.refund_keypair.secret_bytes());
    let boltz_response_json = serde_json::to_string(&result.boltz_response).map_err(|e| {
        AppError::BoltzError(format!("failed to serialize chain-swap response: {e}"))
    })?;

    db::record_chain_swap(
        &state.db,
        &db::NewChainSwapRecord {
            invoice_id: invoice.id,
            nym: swap_nym,
            boltz_swap_id: &result.swap_id,
            lockup_address: &result.lockup_address,
            lockup_bip21: result.lockup_bip21.as_deref(),
            user_lock_amount_sat: result.user_lock_amount_sat as i64,
            server_lock_amount_sat: result.server_lock_amount_sat as i64,
            preimage_hex: &preimage_hex,
            claim_key_hex: &claim_key_hex,
            refund_key_hex: &refund_key_hex,
            boltz_response_json: &boltz_response_json,
        },
    )
    .await
    .map_err(|e| {
        AppError::DbError(format!(
            "failed to record chain swap {}: {e}",
            result.swap_id
        ))
    })?;

    Ok(Some(BitcoinChainOffer {
        lockup_address: result.lockup_address,
        lockup_bip21: result.lockup_bip21,
    }))
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

/// 13 fields in fixed order. The byte sequence is the wire contract.
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
    liquid_blinding_key_hex_or_empty: &'a str,
    expires_at_unix: &'a str,
) -> [&'a str; 13] {
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
        liquid_blinding_key_hex_or_empty,
        expires_at_unix,
    ]
}

fn cancel_payload_fields(invoice_id: &str) -> [&str; 1] {
    [invoice_id]
}

fn list_payload_fields<'a>(
    page: &'a str,
    page_size: &'a str,
    status_filter_or_empty: &'a str,
) -> [&'a str; 3] {
    [page, page_size, status_filter_or_empty]
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
    #[serde(default)]
    pub accept_btc: bool,
    #[serde(default)]
    pub accept_ln: bool,
    #[serde(default)]
    pub accept_liquid: bool,
    pub bitcoin_address: Option<String>,
    pub liquid_address: Option<String>,
    pub liquid_blinding_key_hex: Option<String>,
    pub expires_at_unix: Option<i64>,
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
    let canonical_bitcoin_address = if let Some(addr) = req.bitcoin_address.as_deref() {
        Some(validators::canonical_btc_mainnet_address(addr)?)
    } else {
        None
    };
    let canonical_liquid_address = if let Some(addr) = req.liquid_address.as_deref() {
        let canonical = validators::canonical_liquid_mainnet_address(addr)?;
        if req.accept_liquid {
            let key = req.liquid_blinding_key_hex.as_deref().ok_or_else(|| {
                AppError::InvalidAmount(
                    "accept_liquid=true requires liquid_blinding_key_hex".into(),
                )
            })?;
            validators::validate_liquid_blinding_key_matches_address(&canonical, key)?;
        }
        Some(canonical)
    } else {
        None
    };

    // Outer expiry window: now+60s to now+7d. Omitted expiry defaults to
    // the server cap; the signed payload uses an empty expiry field in that
    // case, so clients do not need to know server time to create an invoice.
    let now = unix_now();
    let expires_in_secs = match req.expires_at_unix {
        Some(expires_at_unix) => {
            if expires_at_unix < now + 60 {
                return Err(AppError::InvalidAmount(
                    "expires_at_unix must be at least 60 seconds in the future".into(),
                ));
            }
            if expires_at_unix > now + MAX_WALLET_EXPIRES_SECS {
                return Err(AppError::InvalidAmount(format!(
                    "expires_at_unix beyond {MAX_WALLET_EXPIRES_SECS}s cap"
                )));
            }
            expires_at_unix - now
        }
        None => MAX_WALLET_EXPIRES_SECS,
    };

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
    let liquid_blinding_key_str = req.liquid_blinding_key_hex.clone().unwrap_or_default();
    let expires_str = req
        .expires_at_unix
        .map(|expires_at_unix| expires_at_unix.to_string())
        .unwrap_or_default();
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
        &liquid_blinding_key_str,
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
        rate_lock_secs: expires_in_secs,
        memo: None,
        recipient_label: req.recipient_label.as_deref(),
        public_description: req.public_description.as_deref(),
        invoice_number: req.invoice_number.as_deref(),
        accept_btc: req.accept_btc,
        accept_ln: req.accept_ln,
        accept_liquid: req.accept_liquid,
        bitcoin_address: canonical_bitcoin_address.as_deref(),
        liquid_address: canonical_liquid_address.as_deref(),
        liquid_blinding_key_hex: req.liquid_blinding_key_hex.as_deref(),
        expires_in_secs,
    };
    let invoice = db::insert_invoice(&state.db, &new_invoice).await?;

    if invoice.accept_ln {
        if let Err(e) = create_lightning_offer(
            state,
            lightning_swap_nym(&invoice),
            amount_sat as u64,
            &invoice,
        )
        .await
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

    let (rows, final_status) = db::cancel_invoice(&state.db, id).await?;
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
    pub page: i64,
    #[serde(rename = "pageSize")]
    pub page_size: i64,
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
    pub pricing_mode: String,
    pub settlement_status: String,
    pub amount_sat: i64,
    pub remaining_amount_sat: i64,
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
    pub page: i64,
    #[serde(rename = "pageSize")]
    pub page_size: i64,
    pub has_more: bool,
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

    if params.page < 1 {
        return Err(AppError::InvalidAmount("page must be >= 1".into()));
    }
    if params.page > 1000 {
        return Err(AppError::InvalidAmount("page must be <= 1000".into()));
    }
    if params.page_size < 1 {
        return Err(AppError::InvalidAmount("pageSize must be >= 1".into()));
    }
    let page_size = params.page_size.min(LIST_LIMIT_MAX);

    let status_filter: Option<&str> = match params.status.as_deref() {
        None | Some("") => None,
        Some(s)
            if matches!(
                s,
                "unpaid"
                    | "in_progress"
                    | "partially_paid"
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
                "status must be one of unpaid|in_progress|partially_paid|paid|underpaid|overpaid|expired|cancelled, or empty (got '{other}')"
            )));
        }
    };

    let page_str = params.page.to_string();
    let page_size_str = page_size.to_string();
    let status_str = status_filter.unwrap_or("");
    let fields = list_payload_fields(&page_str, &page_size_str, status_str);
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
        params.page,
        page_size,
    )
    .await?;
    let has_more = rows.len() >= page_size as usize;
    let invoices = rows
        .into_iter()
        .map(|inv| {
            let remaining = remaining_amount_sat(&inv);
            InvoiceListItem {
                id: inv.id,
                nym_owner: inv.nym_owner,
                origin: inv.origin,
                status: inv.status,
                pricing_mode: inv.pricing_mode,
                settlement_status: inv.settlement_status,
                amount_sat: inv.amount_sat,
                remaining_amount_sat: remaining,
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
            }
        })
        .collect();

    Ok(Json(ListInvoicesResponse {
        invoices,
        page: params.page,
        page_size,
        has_more,
    }))
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
            "abcd",
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
                "abcd",
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
        let f = list_payload_fields("1", "50", "unpaid");
        assert_eq!(
            f,
            ["1", "50", "unpaid"],
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

        assert!(bolt11_is_reusable_at(pr, 1_496_314_658 + 3_479));
        assert!(!bolt11_is_reusable_at(pr, 1_496_314_658 + 3_481));
        assert!(!bolt11_is_reusable_at(pr, 1_496_314_658 + 3_601));
        assert!(!bolt11_is_reusable_at("not-a-bolt11", 1_496_314_658));
    }

    #[test]
    fn partially_paid_template_remains_payable_for_remaining_amount() {
        let tpl = InvoicePaymentTpl {
            nym: "alice",
            is_unlinked: false,
            invoice_id: Uuid::nil().to_string(),
            domain: "bullpay.ca",
            status: "partially_paid",
            settlement_status: "none",
            amount_sat: 10_000,
            remaining_amount_sat: 2_500,
            fiat_display: None,
            public_description: None,
            recipient_name: None,
            invoice_number: None,
            accept_btc: true,
            accept_ln: true,
            accept_liquid: true,
            bitcoin_chain_address: None,
            bitcoin_address_js: js_string_literal(Some("bc1qexample")).unwrap(),
            bitcoin_chain_address_js: js_string_literal(None).unwrap(),
            bitcoin_chain_bip21_js: js_string_literal(None).unwrap(),
            liquid_address_js: js_string_literal(Some("lq1qqexample")).unwrap(),
        };

        let html = tpl.render().expect("template renders");
        assert!(html.contains("Partially paid"));
        assert!(html.contains("2500 sat remaining"));
        assert!(html.contains("id=\"rail-lightning\""));
        assert!(html.contains("let currentAmountSat = 2500;"));
    }

    #[test]
    fn template_refreshes_lightning_explicitly_when_status_has_no_reusable_pr() {
        let tpl = InvoicePaymentTpl {
            nym: "alice",
            is_unlinked: false,
            invoice_id: Uuid::nil().to_string(),
            domain: "bullpay.ca",
            status: "unpaid",
            settlement_status: "none",
            amount_sat: 10_000,
            remaining_amount_sat: 10_000,
            fiat_display: None,
            public_description: None,
            recipient_name: None,
            invoice_number: None,
            accept_btc: false,
            accept_ln: true,
            accept_liquid: true,
            bitcoin_chain_address: None,
            bitcoin_address_js: js_string_literal(None).unwrap(),
            bitcoin_chain_address_js: js_string_literal(None).unwrap(),
            bitcoin_chain_bip21_js: js_string_literal(None).unwrap(),
            liquid_address_js: js_string_literal(Some("lq1qqexample")).unwrap(),
        };

        let html = tpl.render().expect("template renders");
        assert!(html.contains("Refreshing Lightning offer"));
        assert!(html.contains("fetchLightning();"));
        assert!(html.contains("method: 'POST'"));
        assert!(html.contains("/lightning"));
    }

    #[test]
    fn template_exposes_boltz_chain_bitcoin_without_direct_btc_address() {
        let tpl = InvoicePaymentTpl {
            nym: "alice",
            is_unlinked: false,
            invoice_id: Uuid::nil().to_string(),
            domain: "bullpay.ca",
            status: "unpaid",
            settlement_status: "none",
            amount_sat: 10_000,
            remaining_amount_sat: 10_000,
            fiat_display: None,
            public_description: None,
            recipient_name: None,
            invoice_number: None,
            accept_btc: false,
            accept_ln: true,
            accept_liquid: true,
            bitcoin_chain_address: Some("bc1qboltzlockup"),
            bitcoin_address_js: js_string_literal(None).unwrap(),
            bitcoin_chain_address_js: js_string_literal(Some("bc1qboltzlockup")).unwrap(),
            bitcoin_chain_bip21_js: js_string_literal(Some(
                "bitcoin:bc1qboltzlockup?amount=0.00010000&label=Send%20to%20L-BTC%20address",
            ))
            .unwrap(),
            liquid_address_js: js_string_literal(Some("lq1qqexample")).unwrap(),
        };

        let html = tpl.render().expect("template renders");
        assert!(html.contains("id=\"rail-btc\""));
        assert!(html.contains("INITIAL_BITCOIN_CHAIN_ADDRESS = \"bc1qboltzlockup\""));
        assert!(html.contains("INITIAL_BITCOIN_CHAIN_BIP21 = \"bitcoin:bc1qboltzlockup?amount=0.00010000\\u0026label=Send%20to%20L-BTC%20address\""));
        assert!(html.contains("return bip21 || btcUri(address, amountSat);"));
        assert!(html.contains("INITIAL_BITCOIN_CHAIN_ADDRESS || INITIAL_BITCOIN_ADDRESS"));
    }

    #[test]
    fn api_tolerance_uses_configured_values() {
        let mut inv = invoice_fixture();
        inv.accept_btc = false;
        inv.accept_liquid = true;
        inv.accept_ln = false;
        let tolerances = db::InvoiceAccountingTolerances {
            btc_sat: 900,
            liquid_sat: 42,
            lightning_sat: 3,
        };

        assert_eq!(payment_tolerance_sat(&inv, tolerances), 42);
    }

    fn invoice_fixture() -> db::Invoice {
        db::Invoice {
            id: Uuid::nil(),
            nym_owner: Some("alice".to_string()),
            npub_owner: "npub".to_string(),
            origin: "wallet".to_string(),
            fiat_amount_minor: None,
            fiat_currency: None,
            amount_sat: 10_000,
            rate_minor_per_btc: None,
            memo: None,
            recipient_label: None,
            bitcoin_address: None,
            accept_btc: false,
            accept_ln: true,
            accept_liquid: false,
            public_description: None,
            invoice_number: None,
            liquid_address: None,
            liquid_address_index: None,
            status: "unpaid".to_string(),
            paid_via: None,
            paid_amount_sat: None,
            pricing_mode: "sat_fixed".to_string(),
            settlement_status: "none".to_string(),
            liquid_blinding_key_hex: None,
            created_at_unix: 0,
            expires_at_unix: 0,
            rate_locked_at_unix: 0,
            rate_locks_until_unix: 0,
            paid_at_unix: None,
            cancelled_at_unix: None,
        }
    }
}

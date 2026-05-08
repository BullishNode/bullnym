//! Public HTML rendering for `GET /<nym>` (Phase 2).
//!
//! Wired as `Router::fallback(...)` so all explicit routes (`/health`,
//! `/register`, `/.well-known/...`) take precedence. Single-segment paths
//! that don't match any explicit route fall through here and are
//! interpreted as donation-page slugs.
//!
//! Three render branches:
//! 1. Path sanity / reserved-slug fail → 404 (`donation_404.html`).
//! 2. Row absent → 404.
//! 3. `archived_at IS NOT NULL` → 200 + `donation_archived.html`.
//! 4. Live → 200 + `donation_page.html` with embedded Pricer rate.
//!
//! On first visit, sets a `bullpay_did` UUID cookie (HttpOnly, Secure,
//! SameSite=Lax). Phase 4 uses this cookie to pin Liquid donation
//! addresses per (source_ip, device_id).

use askama::Template;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use std::net::SocketAddr;
use tower_cookies::{Cookie, Cookies};
use uuid::Uuid;

use crate::db;
use crate::donation_page::SUPPORTED_CURRENCIES;
use crate::ip_whitelist;
use crate::reserved_nyms;
use crate::AppState;

// Phase B step 10: cookie issuance is deprecated; the helpers below are
// retained as dead code so a binary rollback to the legacy donate-callback
// flow doesn't require restoring deleted code. Phase D removes them.
#[allow(dead_code)]
const COOKIE_NAME: &str = "bullpay_did";
#[allow(dead_code)]
const COOKIE_MAX_AGE_DAYS: i64 = 30;

#[derive(Template)]
#[template(path = "store_amount.html")]
struct DonationPageTpl<'a> {
    nym: &'a str,
    header: &'a str,
    description: &'a str,
    public_url: String,
    avatar_url: Option<String>,
    og_url: Option<String>,
    display_currency: &'a str,
    website: Option<&'a str>,
    twitter: Option<&'a str>,
    instagram: Option<&'a str>,
    /// Legacy field — kept on the struct so call sites don't need to
    /// drop it during the Phase B cutover. The new `store_amount.html`
    /// template doesn't reference it; the donate-callback URL is gone.
    /// Phase D removes the field once `donation_callback.rs` is deleted.
    #[allow(dead_code)]
    callback_url: String,
    /// Minor units per BTC. 0 means rate unavailable; the JS gates the
    /// Continue button accordingly.
    minor_per_btc: i64,
    precision: u8,
    last_known_rate: bool,
    /// All currencies the server supports for fiat-denominated invoices.
    /// Rendered as `<option>` entries on the unit dropdown so the sender
    /// is not constrained to the merchant's display preference.
    supported_currencies: &'static [&'static str],
}

#[derive(Template)]
#[template(path = "donation_404.html")]
struct DonationNotFoundTpl<'a> {
    nym: &'a str,
    domain: &'a str,
}

#[derive(Template)]
#[template(path = "donation_archived.html")]
struct DonationArchivedTpl<'a> {
    nym: &'a str,
    domain: &'a str,
}

/// Reject obviously-malicious paths. The fallback only handles a single
/// path segment (`/alice`); axum routing already strips the leading slash
/// when extracting `Path<String>`, but this is defense-in-depth.
fn is_valid_slug(s: &str) -> bool {
    if s.is_empty() || s.len() > 32 {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Issue a `bullpay_did` UUID cookie if the caller doesn't already have
/// one. Idempotent: a re-render with the cookie present is a no-op so
/// the device_id stays stable across reloads.
#[allow(dead_code)]
fn ensure_device_cookie(cookies: &Cookies) {
    if cookies.get(COOKIE_NAME).is_some() {
        return;
    }
    let id = Uuid::new_v4().to_string();
    let cookie = Cookie::build((COOKIE_NAME, id))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(tower_cookies::cookie::SameSite::Lax)
        .max_age(tower_cookies::cookie::time::Duration::days(COOKIE_MAX_AGE_DAYS))
        .build();
    cookies.add(cookie);
}

/// Add a few defensive response headers that apply to all donation-page
/// HTML responses.
fn apply_security_headers(resp: &mut Response) {
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
    // CSP: no remote scripts/styles/images. The donation page renders
    // entirely from inline assets; the only outbound network call is the
    // donate-callback fetch (same-origin).
    // CSP: tight default with two narrow exceptions:
    // - 'unsafe-inline' for script and style — the page bundles its JS/CSS
    //   inline, no remote CDN. User-controlled fields are askama-escaped
    //   so injection through them is blocked.
    // - connect-src widened to wss://liquid.network so the donation page
    //   can subscribe directly to the public Esplora WebSocket for
    //   instant 0-conf Liquid payment notification (Phase 4 UX). The
    //   Lightning path remains same-origin (server-side polling).
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; \
             img-src 'self' data:; \
             script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; \
             connect-src 'self' wss://liquid.network; \
             frame-ancestors 'none'; \
             base-uri 'none'",
        ),
    );
    // 60s freshness gives a CDN/browser cache the chance to absorb a
    // viral-link burst, while keeping mutations (e.g. archive) visible
    // within a minute.
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
}

fn render_404(state: &AppState, nym: &str) -> Response {
    let body = DonationNotFoundTpl {
        nym,
        domain: &state.config.domain,
    }
    .render()
    .unwrap_or_else(|_| "Not found".to_string());
    let mut resp = (StatusCode::NOT_FOUND, body).into_response();
    apply_security_headers(&mut resp);
    resp
}

fn render_archived(state: &AppState, nym: &str) -> Response {
    let body = DonationArchivedTpl {
        nym,
        domain: &state.config.domain,
    }
    .render()
    .unwrap_or_else(|_| "Archived".to_string());
    let mut resp = (StatusCode::OK, body).into_response();
    apply_security_headers(&mut resp);
    resp
}

async fn render_live(state: &AppState, page: &db::DonationPage) -> Response {
    let domain = &state.config.domain;
    let public_url = format!("https://{domain}/{}", page.nym);
    let callback_url = format!("/lnurlp/donate-callback/{}", page.nym);

    // Image URLs only render if the corresponding hash is set (Phase 3
    // populates them on upload; v1 may not have either yet).
    let avatar_url = page
        .avatar_sha256
        .as_ref()
        .map(|_| format!("https://{domain}/img/{}/avatar.webp", page.nym));
    let og_url = page
        .og_sha256
        .as_ref()
        .map(|_| format!("https://{domain}/img/{}/og.webp", page.nym));

    // Fetch the fiat rate. None ⇒ embed minor_per_btc=0 and the JS hides
    // fiat conversion + disables the Donate button. The page still
    // renders (better than a hard 5xx).
    let rate = state.pricer.get_rate(&page.display_currency).await;
    let (minor_per_btc, precision, last_known_rate) = match &rate {
        Some(r) => (r.minor_per_btc, r.precision, r.last_known_rate),
        None => (0, 2, false),
    };

    let body = DonationPageTpl {
        nym: &page.nym,
        header: &page.header,
        description: &page.description,
        public_url,
        avatar_url,
        og_url,
        display_currency: &page.display_currency,
        website: page.website.as_deref(),
        twitter: page.twitter.as_deref(),
        instagram: page.instagram.as_deref(),
        callback_url,
        minor_per_btc,
        precision,
        last_known_rate,
        supported_currencies: SUPPORTED_CURRENCIES,
    }
    .render()
    .unwrap_or_else(|e| format!("template render failed: {e}"));

    let mut resp = (StatusCode::OK, body).into_response();
    apply_security_headers(&mut resp);
    resp
}

/// `Router::fallback` handler. Matches any path that no explicit route
/// claims. We extract the path manually (not via `Path<String>`) so we
/// can reject multi-segment paths cleanly.
pub async fn render_or_404(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let raw_path = uri.path();
    // Strip leading slash and reject anything with another slash, dot, or
    // backslash. The fallback only handles single-segment slugs.
    let nym = raw_path.strip_prefix('/').unwrap_or(raw_path);
    // Tolerate a single trailing slash (`/<nym>/`) — browsers and link-
    // sharers commonly auto-append. Strip exactly one and re-validate;
    // anything fancier (multiple slashes, intermediate slashes) still
    // fails `is_valid_slug` below.
    let nym = nym.strip_suffix('/').unwrap_or(nym);
    if !is_valid_slug(nym) {
        return render_404(&state, nym);
    }
    if reserved_nyms::is_reserved(nym) {
        // Reserved slugs should never have donation pages (registration
        // blocks them), but defense-in-depth keeps the fallback honest if
        // an explicit route is ever removed without updating the reserved
        // list.
        return render_404(&state, nym);
    }

    // Per-source rate-limit. Volumetric scraping protection.
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    if let Some(ip) = ip {
        if !state.ip_whitelist.contains(ip) {
            if let Err(e) = state.rate_limiter.check_donation_html_per_source(ip).await {
                return e.into_response();
            }
        }
    }

    // DB lookup.
    let page = match db::get_donation_page_by_nym(&state.db, nym).await {
        Ok(Some(p)) => p,
        Ok(None) => return render_404(&state, nym),
        Err(e) => {
            tracing::error!(event = "donation_render_db_error", nym = %nym, error = %e);
            return render_404(&state, nym);
        }
    };

    // Phase B step 10: device-cookie issuance removed. The new flow uses
    // URL pinning (`/<nym>/i/<invoice_id>`) instead of cookie pinning.
    // The `ensure_device_cookie` helper and `COOKIE_NAME` constant remain
    // in this file as dead code (Phase D removes them).

    if page.is_archived {
        return render_archived(&state, nym);
    }
    if !page.enabled {
        // Draft state: treat as 404 publicly. Owner can still edit via
        // the mobile app (which uses the GET /donation-page/:nym
        // endpoint, not the public HTML).
        return render_404(&state, nym);
    }

    render_live(&state, &page).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_accepts_simple() {
        assert!(is_valid_slug("alice"));
        assert!(is_valid_slug("my-shop"));
        assert!(is_valid_slug("user123"));
    }

    #[test]
    fn slug_rejects_uppercase() {
        assert!(!is_valid_slug("Alice"));
    }

    #[test]
    fn slug_rejects_dots_and_slashes() {
        assert!(!is_valid_slug("a.b"));
        assert!(!is_valid_slug("a/b"));
        assert!(!is_valid_slug("../etc/passwd"));
    }

    #[test]
    fn slug_rejects_empty_and_long() {
        assert!(!is_valid_slug(""));
        assert!(!is_valid_slug(&"a".repeat(33)));
    }

    #[test]
    fn slug_rejects_underscores_and_special() {
        assert!(!is_valid_slug("a_b"));
        assert!(!is_valid_slug("a@b"));
    }
}

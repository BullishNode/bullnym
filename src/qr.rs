//! `GET /qr.svg?data=<encoded>` — server-side QR code generator.
//!
//! Used by the donation page to render the BOLT11 invoice or Liquid
//! address as a QR. Doing it server-side keeps the page CSP tight
//! (`img-src 'self' data:` is enough; no client-side QR lib to ship)
//! and keeps the page's bundled JS footprint small.

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::net::SocketAddr;

use crate::error::AppError;
use crate::ip_whitelist;
use crate::AppState;

/// Hard cap on the input data length. BOLT11 invoices for typical
/// donation amounts are <600 chars; mainnet Liquid CT addresses are
/// ~80 chars. 4 KiB is plenty.
const MAX_DATA_LEN: usize = 4096;

#[derive(Deserialize)]
pub struct QrParams {
    pub data: String,
}

pub async fn generate(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(params): Query<QrParams>,
) -> Result<Response, AppError> {
    if params.data.is_empty() {
        return Err(AppError::InvalidAmount("data is required".to_string()));
    }
    if params.data.len() > MAX_DATA_LEN {
        return Err(AppError::InvalidAmount(format!(
            "data exceeds {MAX_DATA_LEN} chars"
        )));
    }

    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(
        peer,
        &headers,
        state.config.rate_limit.trust_forwarded_for,
    );
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    // Reuse the donation-html per-source rate-limit. QR encoding has
    // similar cost profile (cheap CPU, public unauth surface) so the
    // 60/min default is appropriate without adding a new knob.
    if !is_whitelisted {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_donation_html_per_source(ip)
                .await?;
        }
    }

    let qr = qrcode::QrCode::new(params.data.as_bytes()).map_err(|e| {
        AppError::InvalidAmount(format!("qr encode failed: {e}"))
    })?;

    // Render with the page's color palette (dark scheme) so the QR
    // visually matches the surrounding UI without extra CSS work on
    // the template side.
    let svg = qr
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(256, 256)
        .dark_color(qrcode::render::svg::Color("#0E0E0E"))
        .light_color(qrcode::render::svg::Color("#F5F5F5"))
        .build();

    let mut resp = (StatusCode::OK, svg).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml"),
    );
    // QRs for the same data are deterministic; let the browser cache.
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok(resp)
}

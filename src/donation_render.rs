//! Public HTML rendering for `GET /<nym>`.
//!
//! Wired as `Router::fallback(...)` so all explicit routes (`/health`,
//! `/register`, `/.well-known/...`) take precedence. Single-segment paths
//! that don't match any explicit route fall through here and are
//! interpreted as donation-page slugs.
//!
//! Public render branches:
//! 1. Path sanity / reserved-slug fail → 404 (`donation_404.html`).
//! 2. Row absent → 404.
//! 3. `archived_at IS NOT NULL` → 200 + `donation_archived.html`.
//! 4. Live → the matching Payment Page or POS PWA shell.
//! 5. Missing or invalid PWA shell → fixed, non-cacheable 503.

use askama::Template;
use axum::extract::{ConnectInfo, Path as AxumPath, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::db;
use crate::ip_whitelist;
use crate::og_image;
use crate::reserved_nyms;
use crate::AppState;

/// How a live surface is being published — decides whether the nym may appear
/// in the served page. `Nym` is the classic nym path (`/<nym>` or
/// `/<nym>/pos`); `Alias` is the nym-free `/a/<slug>` path, where the nym is
/// scrubbed from HTML, config, image URLs, and manifest.
enum PublicBase<'a> {
    Nym { nym: &'a str, base_path: &'a str },
    Alias { slug: &'a str, base_path: &'a str },
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
    social_meta: String,
}

#[derive(Debug, Default)]
pub struct PwaShells {
    pub donation: Option<PathBuf>,
    pub pos: Option<PathBuf>,
    pub invoice: Option<PathBuf>,
}

#[derive(Serialize)]
struct PwaConfigView<'a> {
    /// Present on nym pages (installed-PWA back-compat); omitted entirely on
    /// alias pages so the served config never carries the nym.
    #[serde(skip_serializing_if = "Option::is_none")]
    nym: Option<&'a str>,
    /// Public base path the client appends `/invoice` to. `/<nym>`,
    /// `/<nym>/pos`, or `/a/<slug>` — the client no longer composes this from
    /// the nym, so alias pages stay nym-free.
    invoice_base: &'a str,
    /// Stable namespace key for client-side storage (settings, history, PIN).
    /// Equals the nym on nym pages (no migration for installed PWAs) and the
    /// slug on alias pages.
    page_key: &'a str,
    mode: &'a str,
    currency: &'a str,
    header: &'a str,
    description: &'a str,
    website: Option<&'a str>,
    twitter: Option<&'a str>,
    instagram: Option<&'a str>,
    minor_per_btc: i64,
    last_known_rate: bool,
    liquid_btc_asset_id: &'a str,
    domain: &'a str,
}

#[derive(Serialize)]
struct WebManifest<'a> {
    name: &'a str,
    short_name: String,
    start_url: String,
    scope: &'static str,
    display: &'static str,
    background_color: &'static str,
    theme_color: &'static str,
    icons: [WebManifestIcon<'a>; 4],
}

#[derive(Serialize)]
struct WebManifestIcon<'a> {
    src: &'a str,
    sizes: &'a str,
    #[serde(rename = "type")]
    content_type: &'a str,
    purpose: &'a str,
}

impl PwaShells {
    pub fn load(dist_dir: impl AsRef<Path>) -> Self {
        let dist_dir = dist_dir.as_ref();
        let mut missing = Vec::new();
        let donation = shell_path(dist_dir, "donation");
        let pos = shell_path(dist_dir, "pos");
        let invoice = shell_path(dist_dir, "invoice");
        check_shell_readable(&donation, "donation", &mut missing);
        check_shell_readable(&pos, "pos", &mut missing);
        check_shell_readable(&invoice, "invoice", &mut missing);
        if !missing.is_empty() {
            tracing::warn!(
                event = "pwa_shells_missing",
                missing = ?missing,
                "PWA shell(s) unavailable at startup; affected public surfaces will return 503"
            );
        }
        Self {
            donation: Some(donation),
            pos: Some(pos),
            invoice: Some(invoice),
        }
    }

    async fn shell_for(&self, is_pos: bool) -> Option<String> {
        let shell_kind = if is_pos { "pos" } else { "donation" };
        let path = if is_pos {
            self.pos.as_ref()
        } else {
            self.donation.as_ref()
        }?;
        read_shell(path, shell_kind).await
    }

    pub(crate) async fn invoice_shell(&self) -> Option<String> {
        read_shell(self.invoice.as_ref()?, "invoice").await
    }
}

async fn read_shell(path: &Path, shell_kind: &str) -> Option<String> {
    match tokio::fs::read_to_string(path).await {
        Ok(shell) => Some(shell),
        Err(e) => {
            tracing::warn!(
                event = "pwa_shell_read_error",
                shell_kind,
                error_kind = ?e.kind(),
                "PWA shell is unavailable"
            );
            None
        }
    }
}

fn shell_path(dist_dir: &Path, app: &str) -> PathBuf {
    dist_dir.join("apps").join(app).join("index.html")
}

fn check_shell_readable(path: &Path, app: &str, missing: &mut Vec<String>) {
    if let Err(e) = std::fs::read_to_string(path) {
        missing.push(format!("{app}: {} ({e})", path.display()));
    }
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

const DONATION_CSP: &str = "default-src 'self'; \
             img-src 'self' data:; \
             script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; \
             connect-src 'self' wss://liquid.network wss://liquid.bullbitcoin.com; \
             frame-ancestors 'none'; \
             base-uri 'none'";

const POS_CSP: &str = "default-src 'self'; \
             img-src 'self' data:; \
             script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; \
             connect-src 'self' https: wss://liquid.network wss://liquid.bullbitcoin.com; \
             frame-ancestors 'none'; \
             base-uri 'none'";
const PWA_SHELL_HEADER: &str = "x-bullnym-pwa-shell";

/// Add a few defensive response headers that apply to all donation-page
/// HTML responses.
fn apply_security_headers(resp: &mut Response, is_pos: bool) {
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
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow, noarchive"),
    );
    // CSP: tight default with two narrow exceptions:
    // - 'unsafe-inline' for script and style — the page bundles its JS/CSS
    //   inline, no remote CDN. User-controlled fields are askama-escaped
    //   so injection through them is blocked.
    // - connect-src widened to wss://liquid.network so the donation page
    //   can subscribe directly to the public Esplora WebSocket for
    //   instant zero-conf Liquid payment notification. The
    //   Lightning path remains same-origin (server-side polling).
    // - POS terminals also need arbitrary HTTPS card-service origins for
    //   Bolt Card LNURL-withdraw. Keep script-src pinned; only connect-src
    //   changes for live POS pages.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(if is_pos { POS_CSP } else { DONATION_CSP }),
    );
    // Short browser freshness plus shared-cache stale serving absorbs crawler
    // bursts while keeping Page edits visible quickly.
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60, s-maxage=60, stale-while-revalidate=300"),
    );
}

fn mark_pwa_shell_response(resp: &mut Response, is_pos: bool) {
    let value = if is_pos { "pos" } else { "donation" };
    resp.headers_mut()
        .insert(PWA_SHELL_HEADER, HeaderValue::from_static(value));
}

fn pwa_unavailable_response(is_pos: bool) -> Response {
    let mut resp = (
        StatusCode::SERVICE_UNAVAILABLE,
        "Payment page temporarily unavailable",
    )
        .into_response();
    apply_security_headers(&mut resp, is_pos);
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn render_404(state: &AppState, nym: &str) -> Response {
    let body = DonationNotFoundTpl {
        nym,
        domain: &state.config.domain,
    }
    .render()
    .unwrap_or_else(|_| "Not found".to_string());
    let mut resp = (StatusCode::NOT_FOUND, body).into_response();
    apply_security_headers(&mut resp, false);
    resp
}

fn render_archived(state: &AppState, display_name: &str, public_path: &str) -> Response {
    let public_url = format!("https://{}{}", state.config.domain, public_path);
    let image_url = og_image::fallback_url(&state.config.domain, true);
    let body = DonationArchivedTpl {
        nym: display_name,
        social_meta: social_meta_tags(
            "Page unavailable",
            "This Bull Bitcoin Payment Page is no longer available.",
            &public_url,
            &image_url,
        ),
    }
    .render()
    .unwrap_or_else(|_| "Archived".to_string());
    let mut resp = (StatusCode::OK, body).into_response();
    apply_security_headers(&mut resp, false);
    resp
}

fn escape_json_for_script(json: &str) -> String {
    json.replace('<', "\\u003c")
}

fn html_escape_attr(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

fn short_manifest_name(name: &str) -> String {
    name.chars().take(12).collect()
}

fn web_manifest_for_page<'a>(
    page: &'a db::DonationPage,
    start_path: &str,
    fallback_name: &'a str,
) -> WebManifest<'a> {
    let name = if page.header.trim().is_empty() {
        fallback_name
    } else {
        page.header.as_str()
    };
    WebManifest {
        name,
        short_name: short_manifest_name(name),
        start_url: start_path.to_string(),
        scope: "/",
        display: "standalone",
        background_color: "#161512",
        theme_color: "#161512",
        icons: [
            WebManifestIcon {
                src: "/pwa-assets/icons/icon-192.png",
                sizes: "192x192",
                content_type: "image/png",
                purpose: "any",
            },
            WebManifestIcon {
                src: "/pwa-assets/icons/icon-192.png",
                sizes: "192x192",
                content_type: "image/png",
                purpose: "maskable",
            },
            WebManifestIcon {
                src: "/pwa-assets/icons/icon-512.png",
                sizes: "512x512",
                content_type: "image/png",
                purpose: "any",
            },
            WebManifestIcon {
                src: "/pwa-assets/icons/icon-512.png",
                sizes: "512x512",
                content_type: "image/png",
                purpose: "maskable",
            },
        ],
    }
}

fn social_meta_tags(header: &str, description: &str, public_url: &str, image_url: &str) -> String {
    let title = og_image::social_title(header);
    let description = og_image::social_description(description);
    let description = if description.is_empty() {
        "Send bitcoin with a Bull Bitcoin Payment Page.".to_string()
    } else {
        description
    };
    let alt = format!("{title} — Bull Bitcoin Payment Page");
    format!(
        r#"<title>{title}</title>
<link rel="canonical" href="{public_url}">
<meta name="description" content="{description}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Bull Bitcoin">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{description}">
<meta property="og:url" content="{public_url}">
<meta property="og:image" content="{image_url}">
<meta property="og:image:url" content="{image_url}">
<meta property="og:image:secure_url" content="{image_url}">
<meta property="og:image:type" content="image/jpeg">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="{alt}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{title}">
<meta name="twitter:description" content="{description}">
<meta name="twitter:image" content="{image_url}">
<meta name="twitter:image:alt" content="{alt}">"#,
        title = html_escape_attr(&title),
        description = html_escape_attr(&description),
        public_url = html_escape_attr(public_url),
        image_url = html_escape_attr(image_url),
        alt = html_escape_attr(&alt),
    )
}

async fn stored_generated_og_url(
    image_root: &str,
    domain: &str,
    nym: &str,
    key: &str,
    version: i32,
) -> Option<String> {
    let path = og_image::generated_path_for_version(image_root, version, key);
    match tokio::fs::try_exists(&path).await {
        Ok(true) => Some(og_image::generated_url(domain, version, key)),
        Ok(false) => {
            tracing::warn!(
                event = "og_render_file_missing",
                nym,
                path = %path.display()
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                event = "og_render_file_check_failed",
                nym,
                path = %path.display(),
                error = %error
            );
            None
        }
    }
}

fn inject_pwa_shell(
    shell: &str,
    config: &PwaConfigView<'_>,
    public_url: &str,
    image_url: &str,
    manifest_href: &str,
) -> Option<String> {
    const REQUIRED_MARKERS: [&str; 3] = [
        "<!-- BULLNYM_CONFIG -->",
        "<!-- BULLNYM_MANIFEST -->",
        "<!-- BULLNYM_OG -->",
    ];
    if REQUIRED_MARKERS
        .iter()
        .any(|marker| shell.matches(marker).count() != 1)
    {
        return None;
    }

    let json = serde_json::to_string(config).ok()?;
    let json = escape_json_for_script(&json);
    let config_script =
        format!(r#"<script id="bullnym-config" type="application/json">{json}</script>"#);
    let manifest_link = format!(
        r#"<link rel="manifest" href="{}">"#,
        html_escape_attr(manifest_href)
    );
    // Built PWA shells historically carried a static title. Remove both known
    // variants before inserting the authoritative social metadata so crawlers
    // never have to choose between duplicate <title> elements.
    let shell = shell
        .replace("<title>bullnym</title>", "")
        .replace("<title>bullnym POS</title>", "");
    Some(
        shell
            .replace("<!-- BULLNYM_CONFIG -->", &config_script)
            .replace("<!-- BULLNYM_MANIFEST -->", &manifest_link)
            .replace(
                "<!-- BULLNYM_OG -->",
                &social_meta_tags(config.header, config.description, public_url, image_url),
            ),
    )
}

/// Which per-source bucket a public donation-surface GET bills against.
/// Manifest fetches are kept separate from HTML so a normal page load +
/// install-metadata fetch doesn't double-bill the scraping budget.
enum DonationRateBucket {
    Html,
    Manifest,
}

async fn check_donation_rate_limit(
    state: &AppState,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    bucket: DonationRateBucket,
) -> Result<(), Response> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, headers, state.config.rate_limit.trust_forwarded_for);
    if let Some(ip) = ip {
        if !state.ip_whitelist.contains(ip) {
            let checked = match bucket {
                DonationRateBucket::Html => {
                    state.rate_limiter.check_donation_html_per_source(ip).await
                }
                DonationRateBucket::Manifest => {
                    state
                        .rate_limiter
                        .check_donation_manifest_per_source(ip)
                        .await
                }
            };
            if let Err(e) = checked {
                return Err(e.into_response());
            }
        }
    }
    Ok(())
}

pub async fn service_worker(State(state): State<AppState>) -> Response {
    let path = Path::new(&state.config.pwa.dist_dir).join("sw.js");
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(e) => {
            tracing::error!(event = "service_worker_read_error", error = %e);
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    let mut resp = (StatusCode::OK, bytes).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

/// `GET /:nym/manifest.webmanifest` — Payment Page PWA manifest.
pub async fn manifest(
    State(state): State<AppState>,
    AxumPath(nym): AxumPath<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let start_path = format!("/{nym}");
    manifest_for_kind(
        &state,
        &nym,
        db::KIND_PAYMENT_PAGE,
        &start_path,
        peer_opt,
        &headers,
    )
    .await
}

/// `GET /:nym/pos/manifest.webmanifest` — POS terminal PWA manifest. Served
/// even for a POS-only nym so the keyless terminal is installable and starts
/// at `/<nym>/pos` rather than the Payment Page.
pub async fn manifest_pos(
    State(state): State<AppState>,
    AxumPath(nym): AxumPath<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let start_path = format!("/{nym}/pos");
    manifest_for_kind(&state, &nym, db::KIND_POS, &start_path, peer_opt, &headers).await
}

async fn manifest_for_kind(
    state: &AppState,
    nym: &str,
    kind: &str,
    start_path: &str,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
) -> Response {
    if !is_valid_slug(nym) || reserved_nyms::is_reserved(nym) {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Err(resp) =
        check_donation_rate_limit(state, peer_opt, headers, DonationRateBucket::Manifest).await
    {
        return resp;
    }

    let page = match db::get_donation_page_by_nym(&state.db, nym, kind).await {
        Ok(Some(p)) if p.enabled && !p.is_archived => p,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(event = "manifest_db_error", nym = %nym, error = %e);
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    let manifest = web_manifest_for_page(&page, start_path, nym);

    let body = match serde_json::to_string(&manifest) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(event = "manifest_serialize_error", nym = %nym, error = %e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut resp = (StatusCode::OK, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/manifest+json"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}

/// `GET /a/:slug/manifest.webmanifest` — PWA manifest for an alias surface.
/// Resolves the slug to its `(nym, kind)` row and serves a manifest whose name
/// and start_url reference the slug, never the nym.
pub async fn manifest_alias(
    State(state): State<AppState>,
    AxumPath(slug): AxumPath<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    manifest_alias_for_kind(state, slug, db::KIND_PAYMENT_PAGE, peer_opt, headers).await
}

/// `GET /a/:slug/pos/manifest.webmanifest` — manifest for the POS surface
/// selected through the same owner-level alias.
pub async fn manifest_alias_pos(
    State(state): State<AppState>,
    AxumPath(slug): AxumPath<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    manifest_alias_for_kind(state, slug, db::KIND_POS, peer_opt, headers).await
}

async fn manifest_alias_for_kind(
    state: AppState,
    slug: String,
    kind: &'static str,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    if !is_valid_slug(&slug) {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Err(resp) =
        check_donation_rate_limit(&state, peer_opt, &headers, DonationRateBucket::Manifest).await
    {
        return resp;
    }

    let page = match db::get_donation_page_by_alias(&state.db, &slug, kind).await {
        Ok(Some(p)) if p.enabled && !p.is_archived => p,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(event = "manifest_alias_db_error", slug = %slug, error = %e);
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    let start_path = if kind == db::KIND_POS {
        format!("/a/{slug}/pos")
    } else {
        format!("/a/{slug}")
    };
    let manifest = web_manifest_for_page(&page, &start_path, &slug);

    let body = match serde_json::to_string(&manifest) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(event = "manifest_alias_serialize_error", slug = %slug, error = %e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut resp = (StatusCode::OK, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/manifest+json"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}

/// Render a live donation surface. `base` decides both the public path the
/// surface is served at (which drives the PWA manifest link + start URL) and
/// whether the nym is allowed to appear in the served page:
/// - `PublicBase::Nym` → served at `/<nym>` (Payment Page) or `/<nym>/pos`;
///   the nym appears in config (installed-PWA back-compat).
/// - `PublicBase::Alias` → served at `/a/<slug>`; the nym is scrubbed from the
///   embedded config and manifest.
///
/// The selected surface kind alone determines which shell is served.
async fn render_live(state: &AppState, page: &db::DonationPage, base: PublicBase<'_>) -> Response {
    let domain = &state.config.domain;

    // Derive the public path, the client-storage key, and the optional nym for
    // the embedded config in one place so the alias branch stays nym-free.
    // Generated OG images are content-addressed and never contain a nym.
    let (base_path, page_key, config_nym) = match base {
        PublicBase::Nym { nym, base_path } => (
            base_path.to_string(),
            nym.to_string(),
            Some(nym.to_string()),
        ),
        PublicBase::Alias { slug, base_path } => (base_path.to_string(), slug.to_string(), None),
    };
    let public_url = format!("https://{domain}{base_path}");
    let is_pos = page.kind == db::KIND_POS;
    let manifest_href = format!("{base_path}/manifest.webmanifest");

    let og_url = if !is_pos {
        match (
            page.generated_og_key.as_deref(),
            page.generated_og_template_version,
        ) {
            (Some(key), Some(version)) => stored_generated_og_url(
                &state.config.donation.image_root_path,
                domain,
                &page.nym,
                key,
                version,
            )
            .await
            .unwrap_or_else(|| og_image::fallback_url(domain, false)),
            // Missing, partial, or failed generated state always uses the
            // permanent branded fallback until reconciliation succeeds.
            _ => og_image::fallback_url(domain, false),
        }
    } else {
        og_image::fallback_url(domain, false)
    };
    // Public Page HTML must never wait on a live pricing HTTP request. Seed
    // the PWA from memory when available; its rate store immediately refreshes
    // through `/api/v1/rate` after the browser loads.
    let rate = state.pricer.cached_rate(&page.display_currency);
    let (minor_per_btc, last_known_rate) = match &rate {
        Some(r) => (r.minor_per_btc, r.last_known_rate),
        None => (0, false),
    };

    if let Some(shell) = state.pwa_shells.shell_for(is_pos).await {
        let mode = if is_pos { "pos" } else { "donation" };
        let config = PwaConfigView {
            nym: config_nym.as_deref(),
            invoice_base: &base_path,
            page_key: &page_key,
            mode,
            currency: &page.display_currency,
            header: &page.header,
            description: &page.description,
            website: page.website.as_deref(),
            twitter: page.twitter.as_deref(),
            instagram: page.instagram.as_deref(),
            minor_per_btc,
            last_known_rate,
            liquid_btc_asset_id: crate::invoice::LIQUID_BTC_ASSET_ID,
            domain,
        };
        let Some(body) = inject_pwa_shell(&shell, &config, &public_url, &og_url, &manifest_href)
        else {
            tracing::warn!(
                event = "pwa_shell_injection_error",
                shell_kind = mode,
                "PWA shell is missing its required injection markers"
            );
            return pwa_unavailable_response(is_pos);
        };
        let mut resp = (StatusCode::OK, body).into_response();
        apply_security_headers(&mut resp, is_pos);
        mark_pwa_shell_response(&mut resp, is_pos);
        return resp;
    }

    pwa_unavailable_response(is_pos)
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
    if let Err(resp) =
        check_donation_rate_limit(&state, peer_opt, &headers, DonationRateBucket::Html).await
    {
        return resp;
    }

    // DB lookup. The fallback serves the Payment Page surface only; POS has
    // its own explicit `/<nym>/pos` route.
    let page = match db::get_donation_page_by_nym(&state.db, nym, db::KIND_PAYMENT_PAGE).await {
        Ok(Some(p)) => p,
        Ok(None) => return render_404(&state, nym),
        Err(e) => {
            tracing::error!(event = "donation_render_db_error", nym = %nym, error = %e);
            return render_404(&state, nym);
        }
    };

    if page.is_archived {
        return render_archived(&state, nym, &format!("/{nym}"));
    }
    if !page.enabled {
        // Draft state: treat as 404 publicly. Owner can still edit via
        // the mobile app (which uses the GET /donation-page/:nym
        // endpoint, not the public HTML).
        return render_404(&state, nym);
    }

    let base_path = format!("/{nym}");
    render_live(
        &state,
        &page,
        PublicBase::Nym {
            nym,
            base_path: &base_path,
        },
    )
    .await
}

/// `GET /:nym/pos` — public POS terminal shell for the nym's POS surface
/// (kind = 'pos'). Explicit route: it takes precedence over the single-segment
/// fallback, and a POS-only nym renders here while `/<nym>` 404s.
pub async fn render_pos(
    State(state): State<AppState>,
    AxumPath(nym): AxumPath<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    if !is_valid_slug(&nym) || reserved_nyms::is_reserved(&nym) {
        return render_404(&state, &nym);
    }

    if let Err(resp) =
        check_donation_rate_limit(&state, peer_opt, &headers, DonationRateBucket::Html).await
    {
        return resp;
    }

    let page = match db::get_donation_page_by_nym(&state.db, &nym, db::KIND_POS).await {
        Ok(Some(p)) => p,
        Ok(None) => return render_404(&state, &nym),
        Err(e) => {
            tracing::error!(event = "pos_render_db_error", nym = %nym, error = %e);
            return render_404(&state, &nym);
        }
    };

    if page.is_archived {
        return render_archived(&state, &nym, &format!("/{nym}/pos"));
    }
    if !page.enabled {
        return render_404(&state, &nym);
    }

    let base_path = format!("/{nym}/pos");
    render_live(
        &state,
        &page,
        PublicBase::Nym {
            nym: &nym,
            base_path: &base_path,
        },
    )
    .await
}

/// `GET /a/:slug` — public donation surface served under a merchant-chosen
/// alias slug, decoupled from the nym. Resolves the slug to its `(nym, kind)`
/// row and renders the Payment Page or POS surface accordingly, with the nym
/// scrubbed from the served page (see `render_live` / `PublicBase::Alias`).
pub async fn render_alias(
    State(state): State<AppState>,
    AxumPath(slug): AxumPath<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    render_alias_for_kind(state, slug, db::KIND_PAYMENT_PAGE, peer_opt, headers).await
}

/// `GET /a/:slug/pos` — POS selected by the same owner-level permanent alias.
pub async fn render_alias_pos(
    State(state): State<AppState>,
    AxumPath(slug): AxumPath<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    render_alias_for_kind(state, slug, db::KIND_POS, peer_opt, headers).await
}

async fn render_alias_for_kind(
    state: AppState,
    slug: String,
    kind: &'static str,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    if !is_valid_slug(&slug) {
        return render_404(&state, &slug);
    }

    if let Err(resp) =
        check_donation_rate_limit(&state, peer_opt, &headers, DonationRateBucket::Html).await
    {
        return resp;
    }

    let page = match db::get_donation_page_by_alias(&state.db, &slug, kind).await {
        Ok(Some(p)) => p,
        Ok(None) => return render_404(&state, &slug),
        Err(e) => {
            tracing::error!(event = "alias_render_db_error", slug = %slug, error = %e);
            return render_404(&state, &slug);
        }
    };

    let base_path = if kind == db::KIND_POS {
        format!("/a/{slug}/pos")
    } else {
        format!("/a/{slug}")
    };
    if page.is_archived {
        return render_archived(&state, &slug, &base_path);
    }
    if !page.enabled {
        return render_404(&state, &slug);
    }

    render_live(
        &state,
        &page,
        PublicBase::Alias {
            slug: &slug,
            base_path: &base_path,
        },
    )
    .await
}

#[cfg(test)]
mod tests;

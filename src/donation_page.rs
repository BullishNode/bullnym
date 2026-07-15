//! Donation page CRUD endpoints.
//!
//! - `PUT /donation-page` — save (upsert). One donation page per nym.
//! - `DELETE /donation-page` — archive (soft-delete; preserves the row so
//!   the public URL keeps resolving to a deletion notice instead of 404).
//! - `GET /donation-page/:nym` — public read of current state. Used by
//!   mobile to populate the editor before save.
//!
//! All write actions are authenticated via the Bullpay Schnorr scheme
//! (`bullpay-la-v2\0<action>\0<npub>\0<nym>\0<fields...>\0<timestamp>`). The
//! mobile must hold the same Nostr identity that registered the nym; the handler
//! looks up the active user by npub and asserts `req.nym == user.nym`
//! before doing any DB write.

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::LazyLock;

use crate::auth;
use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::ip_whitelist;
use crate::og_image;
use crate::pricer::{normalize_currency_code, PricerClient};
use crate::reserved_nyms;
use crate::AppState;

// --- Action names ---
//
// One save action covers create + update because the row is 1:1 with nym
// and the mobile always sends the full v1 config (PUT semantics). The
// archive action carries no payload beyond `nym`.
pub const ACTION_SAVE: &str = "donation-page-save";
pub const ACTION_ARCHIVE: &str = "donation-page-archive";

// --- Limits ---
const MAX_HEADER_LEN: usize = 80;
const MAX_DESCRIPTION_BYTES: usize = og_image::DESCRIPTION_MAX_BYTES;
const MAX_LEGACY_DESCRIPTION_BYTES: usize = 280;
const MAX_SOCIAL_LINK_LEN: usize = 200;
const MAX_SOCIAL_HANDLE_LEN: usize = 50;

static TWITTER_HANDLE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]{1,50}$").unwrap());
static INSTAGRAM_HANDLE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._]{1,50}$").unwrap());

/// Alias slug charset — mirrors NYM_REGEX (`registration.rs`): 1-32 chars,
/// lowercase letters, digits, and interior hyphens, with no leading or
/// trailing hyphen. Kept in sync with that rule so aliases and nyms share the
/// same URL-safe shape. Underscore is intentionally excluded.
static ALIAS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[a-z0-9]|[a-z0-9][a-z0-9\-]{0,30}[a-z0-9])$").unwrap());

// --- Request / response wire types ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveDonationPageRequest {
    pub nym: String,
    pub npub: String,
    pub ct_descriptor: String,
    pub header: String,
    pub description: String,
    pub display_currency: String,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default)]
    pub twitter: Option<String>,
    #[serde(default)]
    pub instagram: Option<String>,
    pub enabled: bool,
    /// Surface discriminator: `payment_page` or `pos`.
    pub kind: String,
    /// Optional permanent owner-level public slug, shared by Page and POS.
    /// It is the terminal signed field after `kind`. Omission preserves the
    /// claim, an empty value is invalid, and a non-empty value claims it once.
    /// See `docs/compatibility-ledger.md`.
    #[serde(default)]
    pub alias: Option<String>,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct ArchiveDonationPageRequest {
    pub nym: String,
    pub npub: String,
    /// Surface to archive: `payment_page` or `pos`.
    pub kind: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct DonationPageView {
    pub nym: String,
    pub header: String,
    pub description: String,
    pub display_currency: String,
    pub website: Option<String>,
    pub twitter: Option<String>,
    pub instagram: Option<String>,
    pub kind: String,
    pub enabled: bool,
    pub is_archived: bool,
    /// Permanent owner-level alias shared by Page and POS, if claimed.
    pub alias: Option<String>,
    /// Public URL the user can share. When an alias is set this is the
    /// nym-free `/a/<alias>` link (the whole point of the feature); otherwise
    /// it falls back to the nym path — `/<nym>/pos` for POS, `/<nym>` for the
    /// Payment Page.
    pub public_url: String,
}

impl DonationPageView {
    fn from_row(row: db::DonationPage, domain: &str) -> Self {
        let public_url = match row.alias.as_deref() {
            Some(alias) if row.kind == db::KIND_POS => {
                format!("https://{domain}/a/{alias}/pos")
            }
            Some(alias) => format!("https://{domain}/a/{alias}"),
            None if row.kind == db::KIND_POS => format!("https://{domain}/{}/pos", row.nym),
            None => format!("https://{domain}/{}", row.nym),
        };
        Self {
            nym: row.nym,
            header: row.header,
            description: row.description,
            display_currency: row.display_currency,
            website: row.website,
            twitter: row.twitter,
            instagram: row.instagram,
            kind: row.kind,
            enabled: row.enabled,
            is_archived: row.is_archived,
            alias: row.alias,
            public_url,
        }
    }
}

// --- Validation helpers ---

fn validate_lengths(
    req: &SaveDonationPageRequest,
    pricer: &PricerClient,
    max_descriptor_len: usize,
) -> Result<(), AppError> {
    if req.header.trim().is_empty() || req.header.len() > MAX_HEADER_LEN {
        return Err(AppError::DonationPageInvalid(format!(
            "header must be 1..={MAX_HEADER_LEN} UTF-8 bytes"
        )));
    }
    // This is the hard API safety ceiling. Surface-specific rules, including
    // the Payment Page grapheme cap, are applied after `kind` is resolved.
    if req.description.len() > MAX_DESCRIPTION_BYTES {
        return Err(AppError::DonationPageInvalid(format!(
            "description must be at most {MAX_DESCRIPTION_BYTES} UTF-8 bytes"
        )));
    }
    let normalized_currency = normalize_currency_code(&req.display_currency);
    if req.display_currency != normalized_currency {
        return Err(AppError::DonationPageInvalid(
            "display_currency must be a canonical uppercase ISO 4217 code".to_string(),
        ));
    }
    if !pricer.is_supported_currency(&req.display_currency) {
        return Err(AppError::DonationPageInvalid(
            "display_currency is not supported; fetch /api/v1/supported-currencies".to_string(),
        ));
    }
    descriptor::validate_descriptor(&req.ct_descriptor, max_descriptor_len)?;
    if let Some(w) = &req.website {
        if w.len() > MAX_SOCIAL_LINK_LEN {
            return Err(AppError::DonationPageInvalid(
                "website too long".to_string(),
            ));
        }
        if !w.is_empty() && !w.starts_with("https://") {
            return Err(AppError::DonationPageInvalid(
                "website must start with https://".to_string(),
            ));
        }
    }
    if let Some(t) = &req.twitter {
        if !t.is_empty() && !TWITTER_HANDLE_REGEX.is_match(t) {
            return Err(AppError::DonationPageInvalid(
                "twitter handle: 1-50 chars, alphanumeric and underscore only".to_string(),
            ));
        }
        if t.len() > MAX_SOCIAL_HANDLE_LEN {
            return Err(AppError::DonationPageInvalid(
                "twitter handle too long".to_string(),
            ));
        }
    }
    if let Some(i) = &req.instagram {
        if !i.is_empty() && !INSTAGRAM_HANDLE_REGEX.is_match(i) {
            return Err(AppError::DonationPageInvalid(
                "instagram handle: 1-50 chars, alphanumeric, dot, underscore only".to_string(),
            ));
        }
        if i.len() > MAX_SOCIAL_HANDLE_LEN {
            return Err(AppError::DonationPageInvalid(
                "instagram handle too long".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_description_for_kind(
    req: &SaveDonationPageRequest,
    kind: &str,
) -> Result<(), AppError> {
    if kind == db::KIND_PAYMENT_PAGE {
        if !og_image::is_valid_payment_page_description(&req.description) {
            return Err(AppError::DonationPageInvalid(format!(
                "description must be 1..={} visible characters and at most {} UTF-8 bytes",
                og_image::DESCRIPTION_MAX_GRAPHEMES,
                og_image::DESCRIPTION_MAX_BYTES
            )));
        }
    } else if req.description.len() > MAX_LEGACY_DESCRIPTION_BYTES {
        // POS retains its optional description contract. Payment Page uses the
        // same approved 120-character contract for every Payment Page save.
        return Err(AppError::DonationPageInvalid(format!(
            "description must be at most {MAX_LEGACY_DESCRIPTION_BYTES} UTF-8 bytes"
        )));
    }
    Ok(())
}

/// Build the v2-signing payload fields in fixed order — POST-NYM fields only.
/// The nym is the first signed field but is passed to `verify_la_v2` as the
/// explicit `nym_or_empty` parameter, NOT as part of `payload_fields`.
///
/// The order MUST stay in lockstep with the mobile
/// (`donation_page_constants.dart::buildSavePayloadFields`).
/// Optional social fields that are absent become empty strings (NOT skipped)
/// so their NUL-separated positions remain stable. `ct_descriptor` and `kind`
/// are required signed fields. `alias` is the sole
/// optional trailing field and MUST stay last.
// The positional list is the signed wire contract; grouping it into a struct
// would obscure the byte-exact field order this helper exists to test.
#[allow(clippy::too_many_arguments)]
fn save_payload_fields<'a>(
    header: &'a str,
    description: &'a str,
    display_currency: &'a str,
    website: &'a str,
    twitter: &'a str,
    instagram: &'a str,
    enabled_str: &'a str,
    ct_descriptor: &'a str,
    kind: &'a str,
    alias: Option<&'a str>,
) -> Vec<&'a str> {
    let mut fields = vec![
        header,
        description,
        display_currency,
        website,
        twitter,
        instagram,
        enabled_str,
        ct_descriptor,
        kind,
    ];
    if let Some(alias) = alias {
        fields.push(alias);
    }
    fields
}

/// Confirm permanent nym ownership. Page/POS availability is independent of
/// Lightning Address availability, so an offline LA owner remains authorized.
async fn assert_nym_owner(state: &AppState, nym: &str, npub: &str) -> Result<db::User, AppError> {
    let user = db::get_user_by_npub_any(&state.db, npub)
        .await?
        .ok_or_else(|| AppError::AuthError("no permanent registration for this key".to_string()))?;
    if user.nym != nym {
        return Err(AppError::AuthError(
            "signer does not own this nym".to_string(),
        ));
    }
    Ok(user)
}

// --- Handlers ---

/// PUT /donation-page — upsert a donation page (one row per nym).
pub async fn save(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<SaveDonationPageRequest>,
) -> Result<Json<DonationPageView>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    // Per-IP metadata rate-limit (cheap pre-validation gate).
    if !is_whitelisted {
        if let Some(ip) = ip {
            state.rate_limiter.check_api_per_ip(ip).await?;
        }
    }

    // Cheap input validation BEFORE signature verification.
    validate_lengths(&req, &state.pricer, state.config.limits.max_descriptor_len)?;

    // Enum-validate the required signed surface discriminator before
    // signature verification.
    let kind = db::normalize_kind(&req.kind).ok_or_else(|| {
        AppError::DonationPageInvalid("kind must be 'payment_page' or 'pos'".to_string())
    })?;

    validate_description_for_kind(&req, kind)?;

    // Validate the optional terminal alias before signature verification.
    //
    // The alias is a permanent insert-only owner claim. Omission is a no-op;
    // empty is never a clear operation.
    let alias_update: Option<&str> = match req.alias.as_deref() {
        None => None,
        Some("") => {
            return Err(AppError::DonationPageInvalid(
                "alias cannot be empty or cleared once claimed".to_string(),
            ));
        }
        Some(s) => {
            if !ALIAS_REGEX.is_match(s) {
                return Err(AppError::DonationPageInvalid(
                    "alias must be 1-32 chars: lowercase letters, digits, and hyphens, \
                     with no leading or trailing hyphen"
                        .to_string(),
                ));
            }
            if reserved_nyms::is_reserved_alias(s) {
                return Err(AppError::DonationPageInvalid(
                    "this link name is reserved; choose another".to_string(),
                ));
            }
            Some(s)
        }
    };

    // Build the signed payload and verify the Schnorr sig. The exact byte
    // sequence here MUST match the mobile's signing helper.
    let website = req.website.as_deref().unwrap_or("");
    let twitter = req.twitter.as_deref().unwrap_or("");
    let instagram = req.instagram.as_deref().unwrap_or("");
    let enabled_str = if req.enabled { "1" } else { "0" };
    let fields = save_payload_fields(
        &req.header,
        &req.description,
        &req.display_currency,
        website,
        twitter,
        instagram,
        enabled_str,
        &req.ct_descriptor,
        &req.kind,
        req.alias.as_deref(),
    );
    auth::verify_la_v2(
        ACTION_SAVE,
        &req.npub,
        &req.nym,
        &fields,
        req.timestamp,
        &req.signature,
    )?;

    // Verify the npub owns the nym AND is active.
    assert_nym_owner(&state, &req.nym, &req.npub).await?;

    // Persist the merchant's Page mutation before doing any rendering work.
    // Changed content clears the old generated key in the upsert, so public
    // HTML immediately selects the bundled fallback until this best-effort
    // post-commit step (or the reconciler) attaches the matching new key.
    let row = db::upsert_donation_page(
        &state.db,
        &db::UpsertDonationPage {
            nym: &req.nym,
            kind,
            ct_descriptor: &req.ct_descriptor,
            header: &req.header,
            description: &req.description,
            display_currency: &req.display_currency,
            website: req.website.as_deref().filter(|s| !s.is_empty()),
            twitter: req.twitter.as_deref().filter(|s| !s.is_empty()),
            instagram: req.instagram.as_deref().filter(|s| !s.is_empty()),
            enabled: req.enabled,
            generated_og_template_version: (kind == db::KIND_PAYMENT_PAGE)
                .then_some(og_image::TEMPLATE_VERSION),
            alias: alias_update,
        },
    )
    .await
    .map_err(|error| match error {
        db::UpsertDonationPageError::Database(error) => AppError::from(error),
        db::UpsertDonationPageError::NameTaken => AppError::NameTaken,
        db::UpsertDonationPageError::AliasAlreadyAssigned { alias } => {
            AppError::AliasAlreadyAssigned { alias }
        }
    })?;

    if kind == db::KIND_PAYMENT_PAGE {
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            og_image::publish(
                &state.config.donation.image_root_path,
                &req.header,
                &req.description,
            ),
        )
        .await
        {
            Ok(Ok(published)) => {
                match db::attach_generated_og_if_current(
                    &state.db,
                    &req.nym,
                    kind,
                    &req.header,
                    &req.description,
                    published.template_version,
                    &published.key,
                )
                .await
                {
                    Ok(0) => tracing::debug!(
                        event = "donation_page_og_attach_obsolete",
                        nym = %req.nym,
                        "Page changed while its OG image rendered"
                    ),
                    Ok(_) => {}
                    Err(error) => tracing::warn!(
                        event = "donation_page_og_attach_failed",
                        nym = %req.nym,
                        error = %error
                    ),
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    event = "donation_page_og_render_failed",
                    nym = %req.nym,
                    error = %error
                );
            }
            Err(_) => {
                tracing::warn!(event = "donation_page_og_render_timed_out", nym = %req.nym);
            }
        }
    }

    Ok(Json(DonationPageView::from_row(row, &state.config.domain)))
}

/// DELETE /donation-page — soft-archive. The row is preserved.
pub async fn archive(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<ArchiveDonationPageRequest>,
) -> Result<Json<DonationPageView>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    if !is_whitelisted {
        if let Some(ip) = ip {
            state.rate_limiter.check_api_per_ip(ip).await?;
        }
    }

    let kind = db::normalize_kind(&req.kind).ok_or_else(|| {
        AppError::DonationPageInvalid("kind must be 'payment_page' or 'pos'".to_string())
    })?;
    let archive_fields = [&req.kind[..]];
    auth::verify_la_v2(
        ACTION_ARCHIVE,
        &req.npub,
        &req.nym,
        &archive_fields,
        req.timestamp,
        &req.signature,
    )?;

    assert_nym_owner(&state, &req.nym, &req.npub).await?;

    let row = db::archive_donation_page(&state.db, &req.nym, kind)
        .await?
        .ok_or_else(|| {
            AppError::DonationPageNotFound(
                "no donation page to archive (already archived or never existed)".to_string(),
            )
        })?;

    Ok(Json(DonationPageView::from_row(row, &state.config.domain)))
}

#[derive(Deserialize)]
pub struct GetDonationPageParams {
    /// Surface to read: `payment_page` (default) or `pos`.
    #[serde(default)]
    pub kind: Option<String>,
}

/// GET /donation-page/:nym?kind= — public read of current state. Used by
/// mobile to populate the editor before save. No auth required (data becomes
/// public when the page is rendered at `https://<domain>/<nym>` anyway).
/// `kind` selects the surface and defaults to the Payment Page.
pub async fn get(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(nym): Path<String>,
    Query(params): Query<GetDonationPageParams>,
) -> Result<Json<DonationPageView>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    if !is_whitelisted {
        if let Some(ip) = ip {
            state.rate_limiter.check_api_per_ip(ip).await?;
        }
    }

    let kind = match params.kind.as_deref() {
        None => db::KIND_PAYMENT_PAGE,
        Some(k) => db::normalize_kind(k).ok_or_else(|| {
            AppError::DonationPageInvalid("kind must be 'payment_page' or 'pos'".to_string())
        })?,
    };

    let row = db::get_donation_page_by_nym(&state.db, &nym, kind)
        .await?
        .ok_or_else(|| AppError::DonationPageNotFound(nym.clone()))?;

    Ok(Json(DonationPageView::from_row(row, &state.config.domain)))
}

#[cfg(test)]
mod tests;

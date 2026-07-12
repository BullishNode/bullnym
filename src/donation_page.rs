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
use crate::image_pipeline::{self, ImageKind};
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
/// same URL-safe shape. Underscore is intentionally excluded (which is also
/// what keeps `payment_page` from ever validating as an alias — see the
/// signed-field confusion guard).
static ALIAS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[a-z0-9]|[a-z0-9][a-z0-9\-]{0,30}[a-z0-9])$").unwrap());

// --- Request / response wire types ---

#[derive(Deserialize)]
pub struct SaveDonationPageRequest {
    pub nym: String,
    pub npub: String,
    #[serde(default)]
    pub ct_descriptor: Option<String>,
    pub header: String,
    pub description: String,
    pub display_currency: String,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default)]
    pub twitter: Option<String>,
    #[serde(default)]
    pub instagram: Option<String>,
    #[serde(default)]
    pub pos_mode: Option<bool>,
    pub enabled: bool,
    /// Surface discriminator: `payment_page` (default when omitted) or `pos`.
    /// Optional and trailing in the signed payload so legacy clients that
    /// omit it verify against the pre-POS byte layout. See
    /// `docs/compatibility-ledger.md`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Merchant-chosen public URL slug for this surface, served at
    /// `/a/<alias>`, decoupled from the nym. Optional and the NEWEST trailing
    /// field in the signed payload (after `kind`), so any client that omits it
    /// verifies against the older byte layout. Tri-state: absent leaves the
    /// stored alias unchanged, `""` clears it, a non-empty value claims it.
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
    /// Surface to archive: `payment_page` (default) or `pos`. Optional and
    /// trailing in the signed payload; legacy clients omit it and archive the
    /// Payment Page row.
    #[serde(default)]
    pub kind: Option<String>,
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
    pub pos_mode: bool,
    pub enabled: bool,
    pub is_archived: bool,
    pub avatar_sha256: Option<String>,
    pub og_sha256: Option<String>,
    /// Merchant-chosen alias slug for this surface, if one is claimed. `None`
    /// means the surface is only reachable via its nym path.
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
            pos_mode: row.pos_mode,
            enabled: row.enabled,
            is_archived: row.is_archived,
            avatar_sha256: row.avatar_sha256,
            og_sha256: row.og_sha256,
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
    // This is the hard storage/API safety ceiling. Surface-specific rules,
    // including the new Payment Page grapheme cap, are applied after `kind` is
    // resolved.
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
    if let Some(ct_descriptor) = req.ct_descriptor.as_deref().filter(|s| !s.is_empty()) {
        descriptor::validate_descriptor(ct_descriptor, max_descriptor_len)?;
    }
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
    if kind == db::KIND_PAYMENT_PAGE && req.kind.is_some() {
        if !og_image::is_valid_payment_page_description(&req.description) {
            return Err(AppError::DonationPageInvalid(format!(
                "description must be 1..={} visible characters and at most {} UTF-8 bytes",
                og_image::DESCRIPTION_MAX_GRAPHEMES,
                og_image::DESCRIPTION_MAX_BYTES
            )));
        }
    } else if req.description.len() > MAX_LEGACY_DESCRIPTION_BYTES {
        // Requests that omit `kind` are the shipped legacy wire shape. Keep
        // their former optional/280-byte contract so a server rollout does not
        // strand older clients; generated metadata/images still truncate that
        // content safely. Explicit modern Payment Page saves use the strict
        // short-description contract above.
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
/// Optional fields that are absent become empty strings (NOT skipped) so the
/// number and order of NUL separators is invariant to which fields are set.
/// `pos_mode`, `ct_descriptor`, `kind`, and `alias` are optional trailing
/// fields for shipped Bull Wallet compatibility; each is appended only when the
/// client sent it, so a legacy client that omits them verifies against the
/// older byte layout. `alias` is the newest field and MUST stay last (after
/// `kind`). Its validated value domain is kept disjoint from the other
/// trailing fields (see the save handler) so a captured legacy message can
/// never be replayed as an alias claim. See `docs/compatibility-ledger.md`.
fn save_payload_fields<'a>(
    header: &'a str,
    description: &'a str,
    display_currency: &'a str,
    website: &'a str,
    twitter: &'a str,
    instagram: &'a str,
    enabled_str: &'a str,
    pos_mode_str: Option<&'a str>,
    ct_descriptor: Option<&'a str>,
    kind: Option<&'a str>,
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
    ];
    if let Some(pos_mode_str) = pos_mode_str {
        fields.push(pos_mode_str);
    }
    if let Some(ct_descriptor) = ct_descriptor {
        fields.push(ct_descriptor);
    }
    if let Some(kind) = kind {
        fields.push(kind);
    }
    if let Some(alias) = alias {
        fields.push(alias);
    }
    fields
}

/// Confirm the signing npub owns `nym` AND the user row is currently active.
/// Returns the user record on success.
async fn assert_nym_owner(state: &AppState, nym: &str, npub: &str) -> Result<db::User, AppError> {
    let user = db::get_user_by_npub(&state.db, npub)
        .await?
        .ok_or_else(|| AppError::AuthError("no active registration for this key".to_string()))?;
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
            state.rate_limiter.check_metadata_per_ip(ip).await?;
        }
    }

    // Cheap input validation BEFORE signature verification.
    validate_lengths(&req, &state.pricer, state.config.limits.max_descriptor_len)?;

    // Resolve and enum-validate the surface kind BEFORE signature verification
    // so the trailing signed field can never be confused with another value
    // (KR-3). Omitted => the Payment Page surface, matching the legacy
    // single-row contract.
    let kind = match req.kind.as_deref() {
        None => db::KIND_PAYMENT_PAGE,
        Some(k) => db::normalize_kind(k).ok_or_else(|| {
            AppError::DonationPageInvalid("kind must be 'payment_page' or 'pos'".to_string())
        })?,
    };

    validate_description_for_kind(&req, kind)?;

    // Validate the alias slug BEFORE signature verification, alongside `kind`,
    // so the newest trailing signed field's value domain is provably disjoint
    // from the other optional trailing fields — pos_mode {"0","1"}, kind
    // {"pos","payment_page"}, and ct_descriptor (parenthesised) — and a
    // captured legacy message can't be replayed as an alias claim (KR-3).
    // Charset excludes "payment_page" (underscore) and descriptors; the
    // reserved-alias blocklist rejects "0"/"1"/"pos" and brand names.
    //
    // Tri-state for the upsert: absent leaves the stored alias unchanged,
    // `Some("")` clears it, a validated non-empty value claims it.
    let alias_update: Option<Option<&str>> = match req.alias.as_deref() {
        None => None,
        Some("") => Some(None),
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
            Some(Some(s))
        }
    };

    // A POS surface owns its own wallet (idx 103), so it MUST carry a
    // descriptor. Without one, anonymous checkout on the POS branch has
    // nothing to settle to; the POS branch deliberately has no
    // Lightning-Address cursor fallback, so it would hard-fail at allocation.
    // Reject at save time — there are no legacy POS clients to grandfather
    // (KR-1).
    if kind == db::KIND_POS
        && req
            .ct_descriptor
            .as_deref()
            .filter(|s| !s.is_empty())
            .is_none()
    {
        return Err(AppError::DonationPageInvalid(
            "a POS surface requires ct_descriptor".to_string(),
        ));
    }

    // Build the signed payload and verify the Schnorr sig. The exact byte
    // sequence here MUST match the mobile's signing helper.
    let website = req.website.as_deref().unwrap_or("");
    let twitter = req.twitter.as_deref().unwrap_or("");
    let instagram = req.instagram.as_deref().unwrap_or("");
    let enabled_str = if req.enabled { "1" } else { "0" };
    let pos_mode_str = req
        .pos_mode
        .map(|pos_mode| if pos_mode { "1" } else { "0" });
    let fields = save_payload_fields(
        &req.header,
        &req.description,
        &req.display_currency,
        website,
        twitter,
        instagram,
        enabled_str,
        pos_mode_str,
        req.ct_descriptor.as_deref(),
        req.kind.as_deref(),
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

    // Conflict rule: a nym must not end up with two POS surfaces. Reject
    // enabling pos_mode on the Payment Page row when a separate POS row
    // already exists (Q5). New clients use `kind` and stop sending pos_mode.
    if kind == db::KIND_PAYMENT_PAGE
        && req.pos_mode == Some(true)
        && db::get_donation_page_by_nym(&state.db, &req.nym, db::KIND_POS)
            .await?
            .is_some()
    {
        return Err(AppError::DonationPageInvalid(
            "cannot enable pos_mode on the payment page while a separate POS surface exists"
                .to_string(),
        ));
    }

    // Rendering is server-owned and best-effort. The image is atomically
    // written before its key is put in the row. A failure deliberately clears
    // any prior generated key so changed text can never show a stale card; the
    // public HTML will use the permanent branded fallback instead.
    let generated_og = if kind == db::KIND_PAYMENT_PAGE {
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
            Ok(Ok(published)) => Some(published),
            Ok(Err(error)) => {
                tracing::warn!(
                    event = "donation_page_og_render_failed",
                    nym = %req.nym,
                    error = %error
                );
                None
            }
            Err(_) => {
                tracing::warn!(event = "donation_page_og_render_timed_out", nym = %req.nym);
                None
            }
        }
    } else {
        None
    };

    let row = db::upsert_donation_page(
        &state.db,
        &db::UpsertDonationPage {
            nym: &req.nym,
            kind,
            ct_descriptor: req.ct_descriptor.as_deref().filter(|s| !s.is_empty()),
            header: &req.header,
            description: &req.description,
            display_currency: &req.display_currency,
            website: req.website.as_deref().filter(|s| !s.is_empty()),
            twitter: req.twitter.as_deref().filter(|s| !s.is_empty()),
            instagram: req.instagram.as_deref().filter(|s| !s.is_empty()),
            pos_mode: req.pos_mode,
            enabled: req.enabled,
            generated_og_key: generated_og.as_ref().map(|image| image.key.as_str()),
            generated_og_template_version: (kind == db::KIND_PAYMENT_PAGE)
                .then_some(og_image::TEMPLATE_VERSION),
            alias: alias_update,
        },
    )
    .await?;

    // If an alias was just claimed, make sure the content-addressed image
    // copies exist so `/a/<alias>` can serve avatar/OG without the nym in the
    // URL. New uploads already dual-write; this backfills images uploaded
    // before that shipped. Best-effort and non-fatal.
    if matches!(alias_update, Some(Some(_))) {
        backfill_alias_image_hashes(&state, &row).await;
    }

    Ok(Json(DonationPageView::from_row(row, &state.config.domain)))
}

/// Best-effort: ensure the content-addressed (`/img/_h/<sha>.<ext>`) copies of
/// a page's avatar/OG images exist, copying from the nym-keyed path when
/// missing. Called when a merchant claims an alias so pre-existing images
/// become servable on the nym-free alias page. Failures are logged, never
/// propagated — a missing image just doesn't render.
async fn backfill_alias_image_hashes(state: &AppState, row: &db::DonationPage) {
    let items: Vec<(String, ImageKind)> = [
        row.avatar_sha256
            .as_ref()
            .map(|h| (h.clone(), ImageKind::Avatar)),
        row.og_sha256.as_ref().map(|h| (h.clone(), ImageKind::Og)),
    ]
    .into_iter()
    .flatten()
    .collect();
    if items.is_empty() {
        return;
    }
    let root = state.config.donation.image_root_path.clone();
    let nym = row.nym.clone();
    let _ = tokio::task::spawn_blocking(move || {
        for (sha, kind) in items {
            let hash_path = image_pipeline::image_hash_path(&root, &sha, kind);
            if hash_path.exists() {
                continue;
            }
            let nym_path = image_pipeline::image_path(&root, &nym, kind);
            match std::fs::read(&nym_path) {
                Ok(bytes) => {
                    if let Err(e) = image_pipeline::atomic_write(&hash_path, &bytes) {
                        tracing::warn!(event = "alias_image_backfill_write_failed", error = %e);
                    }
                }
                Err(e) => {
                    tracing::warn!(event = "alias_image_backfill_read_failed", error = %e);
                }
            }
        }
    })
    .await;
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
            state.rate_limiter.check_metadata_per_ip(ip).await?;
        }
    }

    // Resolve + enum-validate kind before signature verification. Omitted =>
    // Payment Page (legacy behavior). `kind` is the sole optional-trailing
    // signed field for archive, so an old client that omits it verifies
    // against the pre-POS empty field list.
    let kind = match req.kind.as_deref() {
        None => db::KIND_PAYMENT_PAGE,
        Some(k) => db::normalize_kind(k).ok_or_else(|| {
            AppError::DonationPageInvalid("kind must be 'payment_page' or 'pos'".to_string())
        })?,
    };
    let archive_fields: Vec<&str> = match req.kind.as_deref() {
        Some(k) => vec![k],
        None => vec![],
    };
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
            state.rate_limiter.check_metadata_per_ip(ip).await?;
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

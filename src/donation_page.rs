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

use axum::extract::{ConnectInfo, Multipart, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::LazyLock;

use crate::auth;
use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::image_pipeline::{self, ImageKind, PipelineConfig};
use crate::ip_whitelist;
use crate::pricer::{normalize_currency_code, PricerClient};
use crate::AppState;

// --- Action names ---
//
// One save action covers create + update because the row is 1:1 with nym
// and the mobile always sends the full v1 config (PUT semantics). The
// archive action carries no payload beyond `nym`.
pub const ACTION_SAVE: &str = "donation-page-save";
pub const ACTION_ARCHIVE: &str = "donation-page-archive";
pub const ACTION_IMAGE: &str = "donation-page-image";

// --- Limits ---
const MAX_HEADER_LEN: usize = 80;
const MAX_DESCRIPTION_LEN: usize = 280;
const MAX_SOCIAL_LINK_LEN: usize = 200;
const MAX_SOCIAL_HANDLE_LEN: usize = 50;

static TWITTER_HANDLE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]{1,50}$").unwrap());
static INSTAGRAM_HANDLE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._]{1,50}$").unwrap());

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
    pub enabled: bool,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct ArchiveDonationPageRequest {
    pub nym: String,
    pub npub: String,
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
    pub enabled: bool,
    pub is_archived: bool,
    pub avatar_sha256: Option<String>,
    pub og_sha256: Option<String>,
    /// Public URL the user can share. Constructed from server domain + nym.
    pub public_url: String,
}

impl DonationPageView {
    fn from_row(row: db::DonationPage, domain: &str) -> Self {
        let public_url = format!("https://{domain}/{}", row.nym);
        Self {
            nym: row.nym,
            header: row.header,
            description: row.description,
            display_currency: row.display_currency,
            website: row.website,
            twitter: row.twitter,
            instagram: row.instagram,
            enabled: row.enabled,
            is_archived: row.is_archived,
            avatar_sha256: row.avatar_sha256,
            og_sha256: row.og_sha256,
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
    if req.header.is_empty() || req.header.len() > MAX_HEADER_LEN {
        return Err(AppError::DonationPageInvalid(format!(
            "header must be 1..={MAX_HEADER_LEN} chars"
        )));
    }
    if req.description.is_empty() || req.description.len() > MAX_DESCRIPTION_LEN {
        return Err(AppError::DonationPageInvalid(format!(
            "description must be 1..={MAX_DESCRIPTION_LEN} chars"
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

/// Build the v2-signing payload fields in fixed order — POST-NYM fields only.
/// The nym is the first signed field but is passed to `verify_la_v2` as the
/// explicit `nym_or_empty` parameter, NOT as part of `payload_fields`.
///
/// The order MUST stay in lockstep with the mobile
/// (`donation_page_constants.dart::buildSavePayloadFields`).
/// Optional fields that are absent become empty strings (NOT skipped) so the
/// number and order of NUL separators is invariant to which fields are set.
fn save_payload_fields<'a>(
    header: &'a str,
    description: &'a str,
    display_currency: &'a str,
    website: &'a str,
    twitter: &'a str,
    instagram: &'a str,
    enabled_str: &'a str,
    ct_descriptor: Option<&'a str>,
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
    if let Some(ct_descriptor) = ct_descriptor {
        fields.push(ct_descriptor);
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
        req.ct_descriptor.as_deref(),
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

    let row = db::upsert_donation_page(
        &state.db,
        &db::UpsertDonationPage {
            nym: &req.nym,
            ct_descriptor: req.ct_descriptor.as_deref().filter(|s| !s.is_empty()),
            header: &req.header,
            description: &req.description,
            display_currency: &req.display_currency,
            website: req.website.as_deref().filter(|s| !s.is_empty()),
            twitter: req.twitter.as_deref().filter(|s| !s.is_empty()),
            instagram: req.instagram.as_deref().filter(|s| !s.is_empty()),
            enabled: req.enabled,
        },
    )
    .await?;

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
            state.rate_limiter.check_metadata_per_ip(ip).await?;
        }
    }

    auth::verify_la_v2(
        ACTION_ARCHIVE,
        &req.npub,
        &req.nym,
        &[],
        req.timestamp,
        &req.signature,
    )?;

    assert_nym_owner(&state, &req.nym, &req.npub).await?;

    let row = db::archive_donation_page(&state.db, &req.nym)
        .await?
        .ok_or_else(|| {
            AppError::DonationPageNotFound(
                "no donation page to archive (already archived or never existed)".to_string(),
            )
        })?;

    Ok(Json(DonationPageView::from_row(row, &state.config.domain)))
}

/// POST /donation-page/image — multipart upload of avatar or OG image.
///
/// Multipart fields (in any order; all required):
/// - `nym`         (text)
/// - `npub`        (text, hex)
/// - `kind`        (text, "avatar" | "og")
/// - `sha256`      (text, hex of file bytes — must match the bytes server-side)
/// - `timestamp`   (text, unix seconds)
/// - `signature`   (text, hex Schnorr sig)
/// - `file`        (binary, JPEG/PNG/WebP, ≤2 MiB)
///
/// Wire format:
///   bullpay-la-v2\0donation-page-image\0<npub>\0<nym>\0<kind>\0<sha256>\0<timestamp>
pub async fn upload_image(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<DonationPageView>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);

    // Cheap source-IP gate FIRST — bytes for the multipart parse haven't
    // been fully read yet, but the per-route 2 MiB layer already bounded
    // the body. This stops a multipart-flood from a single source.
    if !is_whitelisted {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_donation_image_uploads_per_source(ip)
                .await?;
        }
    }

    // Parse multipart fields. Field-name allowlist is closed; anything
    // unexpected is silently dropped (no surprise behavior on stray
    // fields), but truly required fields are checked at the end.
    let mut nym: Option<String> = None;
    let mut npub: Option<String> = None;
    let mut kind_str: Option<String> = None;
    let mut sha256_hex: Option<String> = None;
    let mut timestamp: Option<u64> = None;
    let mut signature: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;

    // Cap multipart field count to defend against thousands-of-fields DoS.
    // The 2 MiB body limit caps total bytes; this caps allocation count.
    const MAX_MULTIPART_FIELDS: usize = 64;
    let mut field_count = 0usize;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::MultipartInvalid(format!("parse: {e}")))?
    {
        field_count += 1;
        if field_count > MAX_MULTIPART_FIELDS {
            return Err(AppError::MultipartInvalid("too many fields".into()));
        }
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "nym" => nym = Some(text_field(field).await?),
            "npub" => npub = Some(text_field(field).await?),
            "kind" => kind_str = Some(text_field(field).await?),
            "sha256" => sha256_hex = Some(text_field(field).await?),
            "timestamp" => {
                let s = text_field(field).await?;
                timestamp =
                    Some(s.parse().map_err(|_| {
                        AppError::MultipartInvalid("timestamp must be a u64".into())
                    })?);
            }
            "signature" => signature = Some(text_field(field).await?),
            "file" => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::MultipartInvalid(format!("file read: {e}")))?;
                file_bytes = Some(bytes.to_vec());
            }
            _ => {
                // Drain unknown fields so the caller doesn't stall on a
                // half-read body.
                let _ = field.bytes().await;
            }
        }
    }

    let nym = nym.ok_or_else(|| AppError::MultipartInvalid("missing 'nym'".into()))?;
    let npub = npub.ok_or_else(|| AppError::MultipartInvalid("missing 'npub'".into()))?;
    let kind_str = kind_str.ok_or_else(|| AppError::MultipartInvalid("missing 'kind'".into()))?;
    let claimed_sha =
        sha256_hex.ok_or_else(|| AppError::MultipartInvalid("missing 'sha256'".into()))?;
    let timestamp =
        timestamp.ok_or_else(|| AppError::MultipartInvalid("missing 'timestamp'".into()))?;
    let signature =
        signature.ok_or_else(|| AppError::MultipartInvalid("missing 'signature'".into()))?;
    let file_bytes =
        file_bytes.ok_or_else(|| AppError::MultipartInvalid("missing 'file'".into()))?;

    let kind = ImageKind::parse(&kind_str)
        .ok_or_else(|| AppError::ImageInvalid("kind must be 'avatar' or 'og'".into()))?;

    // Verify Schnorr sig FIRST against the claimed_sha. The sig binds
    // (action, npub, nym, kind, claimed_sha256, timestamp). Verifying
    // the sig before computing the file's actual SHA-256 means an
    // attacker can't burn server CPU on a 2 MiB file hash with an
    // invalid sig.
    auth::verify_la_v2(
        ACTION_IMAGE,
        &npub,
        &nym,
        &[kind.as_str(), &claimed_sha],
        timestamp,
        &signature,
    )?;

    // Now compute SHA-256 and confirm it matches the signed claim.
    // This catches truncated/corrupted uploads where the bytes don't
    // match what the mobile signed.
    let computed_sha = {
        let mut h = Sha256::new();
        h.update(&file_bytes);
        hex::encode(h.finalize())
    };
    if !computed_sha.eq_ignore_ascii_case(&claimed_sha) {
        return Err(AppError::ImageInvalid(
            "claimed sha256 does not match received bytes".into(),
        ));
    }

    // Confirm the npub owns the nym and is active.
    assert_nym_owner(&state, &nym, &npub).await?;

    // Per-npub rate-limit (DB-backed, after sig verify).
    if !is_whitelisted {
        state
            .rate_limiter
            .check_donation_image_uploads_per_npub(&npub)
            .await?;
    }

    // Donation page must already exist before image upload.
    db::get_donation_page_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| {
            AppError::DonationPageNotFound(
                "create the donation page before uploading images".to_string(),
            )
        })?;

    // Run the image pipeline (decode/resize/re-encode) and the disk write
    // inside a single spawn_blocking. Worst-case decode of a near-cap
    // input could be hundreds of ms of synchronous CPU; offloading
    // prevents that from stalling the tokio runtime under concurrent
    // uploads.
    let pipeline_cfg = PipelineConfig {
        max_bytes: state.config.donation.image_max_bytes,
        max_dimension: state.config.donation.image_max_dimension,
        max_pixels: state.config.donation.image_max_pixels,
        avatar_size: state.config.donation.avatar_size,
        og_width: state.config.donation.og_width,
        og_height: state.config.donation.og_height,
    };
    let path = image_pipeline::image_path(&state.config.donation.image_root_path, &nym, kind);
    let processed = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let p = image_pipeline::process(&file_bytes, kind, &pipeline_cfg)?;
        image_pipeline::atomic_write(&path, &p.bytes).map_err(|e| {
            tracing::error!(event = "image_atomic_write_failed", error = %e);
            AppError::ImageInvalid("could not persist image".into())
        })?;
        Ok(p)
    })
    .await
    .map_err(|e| AppError::ImageInvalid(format!("image task join: {e}")))??;

    // Update the row with the new sha256. Output bytes differ from input
    // bytes (we re-encoded), so persist the SOURCE sha — that's what the
    // signature committed to and what the donation_render template uses
    // as a cache-buster query param.
    let column = match kind {
        ImageKind::Avatar => "avatar_sha256",
        ImageKind::Og => "og_sha256",
    };
    let row =
        db::update_donation_page_image_hash(&state.db, &nym, column, &processed.source_sha256)
            .await?
            .ok_or_else(|| {
                AppError::DonationPageNotFound("donation page disappeared mid-upload".to_string())
            })?;

    Ok(Json(DonationPageView::from_row(row, &state.config.domain)))
}

/// Read a multipart text field with a small length cap. Used for the
/// short fields (nym, npub, signature, etc.) — image bytes go through
/// `field.bytes()` directly.
async fn text_field(field: axum::extract::multipart::Field<'_>) -> Result<String, AppError> {
    const MAX_TEXT_FIELD: usize = 4096;
    let bytes = field
        .bytes()
        .await
        .map_err(|e| AppError::MultipartInvalid(format!("text field read: {e}")))?;
    if bytes.len() > MAX_TEXT_FIELD {
        return Err(AppError::MultipartInvalid("text field too large".into()));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| AppError::MultipartInvalid("text field not utf-8".into()))
}

/// GET /donation-page/:nym — public read of current state. Used by mobile
/// to populate the editor before save. No auth required (data becomes
/// public when the page is rendered at `https://<domain>/<nym>` anyway).
pub async fn get(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(nym): Path<String>,
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

    let row = db::get_donation_page_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::DonationPageNotFound(nym.clone()))?;

    Ok(Json(DonationPageView::from_row(row, &state.config.domain)))
}

#[cfg(test)]
mod tests;

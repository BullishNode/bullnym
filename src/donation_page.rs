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

use axum::extract::{ConnectInfo, Multipart, Path, Query, State};
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
use crate::reserved_nyms;
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

/// Alias slug charset — mirrors NYM_REGEX (`registration.rs`): 1-32 chars,
/// lowercase letters, digits, and interior hyphens, with no leading or
/// trailing hyphen. Kept in sync with that rule so aliases and nyms share the
/// same URL-safe shape. Underscore is intentionally excluded (which is also
/// what keeps `payment_page` from ever validating as an alias — see the
/// signed-field confusion guard).
static ALIAS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[a-z0-9]|[a-z0-9][a-z0-9\-]{0,30}[a-z0-9])$").unwrap()
});

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
    /// `docs/reference/compatibility.md`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Owner-level public URL slug shared by Payment Page and POS, served at
    /// `/a/<alias>` and `/a/<alias>/pos`. Optional and the NEWEST trailing
    /// field in the signed payload (after `kind`), so any client that omits it
    /// verifies against the older byte layout. Tri-state: absent leaves the
    /// owner's alias unchanged, `""` deactivates it, and a non-empty value
    /// claims or reactivates its lifetime reservation.
    /// See `docs/reference/compatibility.md`.
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
    /// Merchant-chosen alias slug shared by this npub's Payment Page and POS,
    /// if the lifetime claim is currently active. `None` uses the nym routes.
    pub alias: Option<String>,
    /// Public URL the user can share. When an alias is set this is the
    /// nym-free `/a/<alias>` link (the whole point of the feature); otherwise
    /// it falls back to the nym path — `/<nym>/pos` for POS, `/<nym>` for the
    /// Payment Page.
    pub public_url: String,
}

impl DonationPageView {
    fn from_row(row: db::DonationPage, domain: &str) -> Self {
        let public_url = public_surface_url(domain, &row.nym, &row.kind, row.alias.as_deref());
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

fn public_surface_url(domain: &str, nym: &str, kind: &str, alias: Option<&str>) -> String {
    match alias {
        Some(alias) if kind == db::KIND_POS => format!("https://{domain}/a/{alias}/pos"),
        Some(alias) => format!("https://{domain}/a/{alias}"),
        None if kind == db::KIND_POS => format!("https://{domain}/{nym}/pos"),
        None => format!("https://{domain}/{nym}"),
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
    // description is OPTIONAL for both payment pages and POS — an empty
    // description is allowed; only the upper bound is enforced when one is set.
    if req.description.len() > MAX_DESCRIPTION_LEN {
        return Err(AppError::DonationPageInvalid(format!(
            "description must be at most {MAX_DESCRIPTION_LEN} chars"
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
/// `pos_mode`, `ct_descriptor`, `kind`, and `alias` are optional trailing
/// fields for shipped Bull Wallet compatibility; each is appended only when the
/// client sent it, so a legacy client that omits them verifies against the
/// older byte layout. `alias` is the newest field and MUST stay last (after
/// `kind`). Its validated value domain is kept disjoint from the other
/// trailing fields (see the save handler) so a captured legacy message can
/// never be replayed as an alias claim. See `docs/reference/compatibility.md`.
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

    // Validate the alias slug BEFORE signature verification, alongside `kind`,
    // so the newest trailing signed field's value domain is provably disjoint
    // from the other optional trailing fields — pos_mode {"0","1"}, kind
    // {"pos","payment_page"}, and ct_descriptor (parenthesised) — and a
    // captured legacy message can't be replayed as an alias claim (KR-3).
    // Charset excludes "payment_page" (underscore) and descriptors; the
    // reserved-alias blocklist rejects "0"/"1"/"pos" and brand names.
    //
    // Tri-state for the upsert: absent leaves the owner's alias unchanged,
    // `Some("")` deactivates it, and a validated non-empty value claims or
    // reactivates its lifetime reservation.
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
    if kind == db::KIND_POS && req.ct_descriptor.as_deref().filter(|s| !s.is_empty()).is_none() {
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

    let row = match db::upsert_donation_page(
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
            alias: alias_update,
        },
    )
    .await
    {
        Ok(row) => row,
        Err(db::UpsertDonationPageError::NameTaken) => return Err(AppError::NameTaken),
        Err(db::UpsertDonationPageError::AliasAlreadyAssigned) => {
            return Err(AppError::AliasAlreadyAssigned)
        }
        Err(db::UpsertDonationPageError::OwnerInactive) => {
            return Err(AppError::NymNotFound(req.nym.clone()))
        }
        Err(db::UpsertDonationPageError::Database(error)) => return Err(error.into()),
    };

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

    // Donation page must already exist before image upload. Images belong to
    // the Payment Page surface (the POS terminal has no avatar/OG image).
    db::get_donation_page_by_nym(&state.db, &nym, db::KIND_PAYMENT_PAGE)
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
    let image_root = state.config.donation.image_root_path.clone();
    let processed = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let p = image_pipeline::process(&file_bytes, kind, &pipeline_cfg)?;
        image_pipeline::atomic_write(&path, &p.bytes).map_err(|e| {
            tracing::error!(event = "image_atomic_write_failed", error = %e);
            AppError::ImageInvalid("could not persist image".into())
        })?;
        // Content-addressed copy so an alias page can serve this image at
        // /img/_h/<sha>.<ext> without leaking the nym in the URL. Best-effort:
        // the nym path is already durable, so a failure here doesn't fail the
        // upload — the alias-claim backfill and the next upload both retry.
        let hash_path = image_pipeline::image_hash_path(&image_root, &p.source_sha256, kind);
        if let Err(e) = image_pipeline::atomic_write(&hash_path, &p.bytes) {
            tracing::warn!(event = "image_hash_write_failed", error = %e);
        }
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
    let row = db::update_donation_page_image_hash(
        &state.db,
        &nym,
        db::KIND_PAYMENT_PAGE,
        column,
        &processed.source_sha256,
    )
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

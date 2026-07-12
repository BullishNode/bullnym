//! Deterministic, server-owned Open Graph images for Payment Pages.
//!
//! Rendering happens on Page mutation (and in a bounded repair worker), never
//! on the public Page GET path. Generated files are immutable and addressed by
//! a SHA-256 key derived only from the template version, title, and short
//! description. The brand frame and full Bull Bitcoin lockup are mandatory in
//! every output, including the fixed fallback images.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use cosmic_text::{
    fontdb, Attrs, Buffer, Color, Family, FontSystem, Metrics, Shaping, SwashCache, Weight, Wrap,
};
use image::codecs::jpeg::JpegEncoder;
use image::imageops::{self, FilterType};
use image::{DynamicImage, Pixel, Rgba, RgbaImage};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use unicode_segmentation::UnicodeSegmentation;

use crate::image_pipeline;

pub const WIDTH: u32 = 1200;
pub const HEIGHT: u32 = 630;
/// Bump whenever layout, colors, logo bytes, fonts, or encoding changes. Old
/// version directories are intentionally retained for already-shared posts.
pub const TEMPLATE_VERSION: i32 = 1;
pub const DESCRIPTION_MAX_GRAPHEMES: usize = 120;
pub const DESCRIPTION_MAX_BYTES: usize = 512;

const TEMPLATE_KEY: &[u8] = b"bullnym-payment-page-og";
const JPEG_QUALITY: u8 = 88;
const MAX_OUTPUT_BYTES: usize = 1_000_000;
const RECONCILE_INTERVAL: Duration = Duration::from_secs(600);
const RECONCILE_BATCH_SIZE: i64 = 25;
const VERIFY_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const VERIFY_BATCH_SIZE: i64 = 100;
const RETRY_BASE_SECS: i32 = 30;
const RETRY_MAX_SECS: i32 = 60 * 60;

const BACKGROUND: Rgba<u8> = Rgba([0xF5, 0xF0, 0xE8, 0xFF]);
const FOREGROUND: Rgba<u8> = Rgba([0x21, 0x1F, 0x1A, 0xFF]);
const BULL_RED: Rgba<u8> = Rgba([0xB7, 0x00, 0x0B, 0xFF]);

const LOGO_BYTES: &[u8] = include_bytes!("../pwa/public/bb-logo-light.png");

const FONT_BYTES: &[&[u8]] = &[
    include_bytes!("../assets/og/fonts/NotoSans-Regular.ttf"),
    include_bytes!("../assets/og/fonts/NotoSans-Bold.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansArabic-Regular.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansArabic-Bold.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansDevanagari-Regular.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansDevanagari-Bold.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansBengali-Regular.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansBengali-Bold.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansThai-Regular.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansThai-Bold.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansGeorgian-Regular.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansGeorgian-Bold.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansArmenian-Regular.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansArmenian-Bold.ttf"),
    include_bytes!("../assets/og/fonts/NotoSansCJK-Regular.ttc"),
    include_bytes!("../assets/og/fonts/NotoSansSymbols2-Regular.ttf"),
    include_bytes!("../assets/og/fonts/NotoEmoji-Variable.ttf"),
];

static RENDER_PERMIT: Semaphore = Semaphore::const_new(1);
static RENDERER: LazyLock<Mutex<Option<RendererState>>> = LazyLock::new(|| Mutex::new(None));

#[derive(Debug)]
pub struct OgImageError(String);

impl OgImageError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for OgImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OgImageError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedOgImage {
    pub key: String,
    pub template_version: i32,
}

struct RendererState {
    font_system: FontSystem,
    swash_cache: SwashCache,
    logo: RgbaImage,
}

impl RendererState {
    fn new() -> Result<Self, OgImageError> {
        let mut db = fontdb::Database::new();
        for bytes in FONT_BYTES {
            db.load_font_data(bytes.to_vec());
        }
        db.set_sans_serif_family("Noto Sans");

        let logo_source = image::load_from_memory(LOGO_BYTES)
            .map_err(|e| OgImageError::new(format!("decode Bull Bitcoin logo: {e}")))?
            .to_rgba8();
        let logo = crop_transparent(&logo_source)
            .ok_or_else(|| OgImageError::new("Bull Bitcoin logo has no visible pixels"))?;
        let logo_width = 330;
        let logo_height = ((logo.height() as f64 * logo_width as f64) / logo.width() as f64)
            .round()
            .max(1.0) as u32;
        let logo = imageops::resize(&logo, logo_width, logo_height, FilterType::Lanczos3);

        Ok(Self {
            font_system: FontSystem::new_with_locale_and_db("en-US".to_string(), db),
            swash_cache: SwashCache::new(),
            logo,
        })
    }
}

/// Collapse control/newline whitespace into a stable single-line social value.
pub fn normalized_social_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Legacy rows may predate the non-empty title rule. Keep their previews
/// useful and branded instead of emitting an empty `<title>` or card region.
pub fn social_title(value: &str) -> String {
    let normalized = normalized_social_text(value);
    if normalized.is_empty() {
        "Bull Bitcoin Payment Page".to_string()
    } else {
        normalized
    }
}

/// The metadata/image description for legacy rows is safely bounded even
/// before those merchants edit into the new 120-character contract.
pub fn social_description(value: &str) -> String {
    truncate_graphemes(&normalized_social_text(value), DESCRIPTION_MAX_GRAPHEMES)
}

pub fn description_grapheme_count(value: &str) -> usize {
    UnicodeSegmentation::graphemes(value, true).count()
}

pub fn is_valid_payment_page_description(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && value.len() <= DESCRIPTION_MAX_BYTES
        && description_grapheme_count(value) <= DESCRIPTION_MAX_GRAPHEMES
}

pub fn content_key(title: &str, description: &str) -> String {
    let title = social_title(title);
    let description = social_description(description);
    let mut hasher = Sha256::new();
    hasher.update(TEMPLATE_KEY);
    hasher.update(TEMPLATE_VERSION.to_be_bytes());
    hasher.update([0]);
    hasher.update(title.as_bytes());
    hasher.update([0]);
    hasher.update(description.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn generated_path(root: &str, key: &str) -> PathBuf {
    generated_path_for_version(root, TEMPLATE_VERSION, key)
}

pub fn generated_path_for_version(root: &str, version: i32, key: &str) -> PathBuf {
    Path::new(root)
        .join("og")
        .join(format!("v{version}"))
        .join(format!("{key}.jpg"))
}

pub fn generated_url(domain: &str, version: i32, key: &str) -> String {
    format!("https://{domain}/img/og/v{version}/{key}.jpg")
}

pub fn fallback_url(domain: &str, unavailable: bool) -> String {
    let name = fallback_filename(unavailable);
    format!("https://{domain}/img/og/{name}")
}

fn fallback_path(root: &str, unavailable: bool) -> PathBuf {
    Path::new(root)
        .join("og")
        .join(fallback_filename(unavailable))
}

fn fallback_filename(unavailable: bool) -> String {
    if unavailable {
        format!("fallback-unavailable-v{TEMPLATE_VERSION}.jpg")
    } else {
        format!("fallback-live-v{TEMPLATE_VERSION}.jpg")
    }
}

/// Ensure branded fallbacks exist before the HTTP server starts. Failing here
/// is deliberate: serving Page metadata that points at an absent/unbranded
/// fallback violates the public contract.
pub async fn ensure_fallbacks(root: &str) -> Result<(), OgImageError> {
    let root = root.to_string();
    let permit = RENDER_PERMIT
        .acquire()
        .await
        .map_err(|_| OgImageError::new("OG renderer semaphore closed"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        for (unavailable, title, description) in [
            (
                false,
                "Bull Bitcoin Payment Page",
                "Send bitcoin with a simple, secure payment page.",
            ),
            (
                true,
                "Page unavailable",
                "This Bull Bitcoin Payment Page is no longer available.",
            ),
        ] {
            let path = fallback_path(&root, unavailable);
            let bytes = render_jpeg(title, description)?;
            image_pipeline::atomic_write(&path, &bytes)
                .map_err(|e| OgImageError::new(format!("write {}: {e}", path.display())))?;
        }
        Ok(())
    })
    .await
    .map_err(|e| OgImageError::new(format!("fallback render task: {e}")))?
}

/// Render and atomically publish a custom Page image. An existing content key
/// is a cache hit and avoids all shaping/encoding work.
pub async fn publish(
    root: &str,
    title: &str,
    description: &str,
) -> Result<PublishedOgImage, OgImageError> {
    let key = content_key(title, description);
    let path = generated_path(root, &key);
    if tokio::fs::try_exists(&path)
        .await
        .map_err(|e| OgImageError::new(format!("check {}: {e}", path.display())))?
    {
        return Ok(PublishedOgImage {
            key,
            template_version: TEMPLATE_VERSION,
        });
    }

    let permit = RENDER_PERMIT
        .acquire()
        .await
        .map_err(|_| OgImageError::new("OG renderer semaphore closed"))?;

    // Recheck after waiting: another save/backfill may have published it.
    if tokio::fs::try_exists(&path)
        .await
        .map_err(|e| OgImageError::new(format!("check {}: {e}", path.display())))?
    {
        return Ok(PublishedOgImage {
            key,
            template_version: TEMPLATE_VERSION,
        });
    }

    let title = social_title(title);
    let description = social_description(description);
    let render_path = path.clone();
    tokio::task::spawn_blocking(move || {
        // Keep ownership inside the non-cancellable blocking task. If an HTTP
        // caller times out while awaiting this JoinHandle, the render still
        // holds the sole permit until it actually finishes.
        let _permit = permit;
        let bytes = render_jpeg(&title, &description)?;
        image_pipeline::atomic_write(&render_path, &bytes)
            .map_err(|e| OgImageError::new(format!("write {}: {e}", render_path.display())))
    })
    .await
    .map_err(|e| OgImageError::new(format!("OG render task: {e}")))??;

    Ok(PublishedOgImage {
        key,
        template_version: TEMPLATE_VERSION,
    })
}

fn render_jpeg(title: &str, description: &str) -> Result<Vec<u8>, OgImageError> {
    let mut guard = RENDERER
        .lock()
        .map_err(|_| OgImageError::new("OG renderer lock poisoned"))?;
    if guard.is_none() {
        *guard = Some(RendererState::new()?);
    }
    let renderer = guard
        .as_mut()
        .ok_or_else(|| OgImageError::new("OG renderer unavailable"))?;

    let mut canvas = RgbaImage::from_pixel(WIDTH, HEIGHT, BACKGROUND);
    imageops::overlay(&mut canvas, &renderer.logo, 80, 56);
    fill_rect(&mut canvas, 80, 164, 76, 8, BULL_RED);
    fill_rect(&mut canvas, 0, HEIGHT - 12, WIDTH, 12, BULL_RED);

    let (title, title_size) = fit_text(
        &mut renderer.font_system,
        title,
        1040.0,
        2,
        &[72.0, 68.0, 64.0, 60.0, 56.0, 52.0],
        true,
    );
    draw_text(
        &mut canvas,
        &mut renderer.font_system,
        &mut renderer.swash_cache,
        &title,
        80,
        196,
        1040.0,
        176,
        title_size,
        title_size * 1.08,
        true,
        FOREGROUND,
    );

    let (description, description_size) = fit_text(
        &mut renderer.font_system,
        description,
        1040.0,
        3,
        &[32.0, 30.0, 28.0, 26.0],
        false,
    );
    draw_text(
        &mut canvas,
        &mut renderer.font_system,
        &mut renderer.swash_cache,
        &description,
        80,
        404,
        1040.0,
        156,
        description_size,
        description_size * 1.3,
        false,
        FOREGROUND,
    );

    let mut bytes = Vec::with_capacity(160 * 1024);
    let mut encoder = JpegEncoder::new_with_quality(&mut bytes, JPEG_QUALITY);
    encoder
        .encode_image(&DynamicImage::ImageRgba8(canvas).to_rgb8())
        .map_err(|e| OgImageError::new(format!("encode OG JPEG: {e}")))?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(OgImageError::new(format!(
            "encoded OG image is {} bytes (max {MAX_OUTPUT_BYTES})",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn fit_text(
    font_system: &mut FontSystem,
    text: &str,
    width: f32,
    max_lines: usize,
    sizes: &[f32],
    bold: bool,
) -> (String, f32) {
    let normalized = normalized_social_text(text);
    let fallback_size = sizes.last().copied().unwrap_or(24.0);
    for size in sizes {
        if layout_line_count(font_system, &normalized, width, *size, bold) <= max_lines {
            return (normalized, *size);
        }
    }

    let graphemes: Vec<&str> = UnicodeSegmentation::graphemes(normalized.as_str(), true).collect();
    for keep in (0..graphemes.len()).rev() {
        let candidate = format!("{}…", graphemes[..keep].concat().trim_end());
        if layout_line_count(font_system, &candidate, width, fallback_size, bold) <= max_lines {
            return (candidate, fallback_size);
        }
    }
    ("…".to_string(), fallback_size)
}

fn layout_line_count(
    font_system: &mut FontSystem,
    text: &str,
    width: f32,
    font_size: f32,
    bold: bool,
) -> usize {
    if text.is_empty() {
        return 0;
    }
    let line_height = font_size * if bold { 1.08 } else { 1.3 };
    let mut buffer = Buffer::new(font_system, Metrics::new(font_size, line_height));
    buffer.set_size(Some(width), None);
    buffer.set_wrap(Wrap::WordOrGlyph);
    let attrs = text_attrs(bold);
    buffer.set_text(text, &attrs, Shaping::Advanced, None);
    buffer.shape_until_scroll(font_system, false);
    buffer.layout_runs().count()
}

#[allow(clippy::too_many_arguments)]
fn draw_text(
    canvas: &mut RgbaImage,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    text: &str,
    x_offset: i32,
    y_offset: i32,
    width: f32,
    max_height: u32,
    font_size: f32,
    line_height: f32,
    bold: bool,
    color: Rgba<u8>,
) {
    if text.is_empty() {
        return;
    }
    let mut buffer = Buffer::new(font_system, Metrics::new(font_size, line_height));
    buffer.set_size(Some(width), None);
    buffer.set_wrap(Wrap::WordOrGlyph);
    let attrs = text_attrs(bold);
    buffer.set_text(text, &attrs, Shaping::Advanced, None);
    buffer.draw(
        font_system,
        swash_cache,
        Color::rgba(color[0], color[1], color[2], color[3]),
        |x, y, w, h, glyph_color| {
            // Bitmap/color fonts with an invalid strike scale can report
            // enormous glyph surfaces. Refuse those and clip every normal
            // glyph to its assigned text box so merchant content can never
            // paint over the fixed logo or brand accents.
            let max_glyph_extent = (font_size * 3.0).ceil() as u32;
            if w > max_glyph_extent || h > max_glyph_extent {
                return;
            }
            let x = x + x_offset;
            let y = y + y_offset;
            let glyph = Rgba([
                glyph_color.r(),
                glyph_color.g(),
                glyph_color.b(),
                glyph_color.a(),
            ]);
            for dy in 0..h {
                for dx in 0..w {
                    let px = x + dx as i32;
                    let py = y + dy as i32;
                    if px < x_offset
                        || py < y_offset
                        || px >= x_offset + width.ceil() as i32
                        || py >= y_offset + max_height as i32
                        || px >= WIDTH as i32
                        || py >= HEIGHT as i32
                    {
                        continue;
                    }
                    canvas.get_pixel_mut(px as u32, py as u32).blend(&glyph);
                }
            }
        },
    );
}

fn text_attrs(bold: bool) -> Attrs<'static> {
    let attrs = Attrs::new().family(Family::SansSerif);
    if bold {
        attrs.weight(Weight::BOLD)
    } else {
        attrs
    }
}

fn fill_rect(image: &mut RgbaImage, x: u32, y: u32, width: u32, height: u32, color: Rgba<u8>) {
    for py in y..y.saturating_add(height).min(image.height()) {
        for px in x..x.saturating_add(width).min(image.width()) {
            image.put_pixel(px, py, color);
        }
    }
}

fn crop_transparent(image: &RgbaImage) -> Option<RgbaImage> {
    let mut min_x = image.width();
    let mut min_y = image.height();
    let mut max_x = 0;
    let mut max_y = 0;
    let mut found = false;
    for (x, y, pixel) in image.enumerate_pixels() {
        if pixel[3] == 0 {
            continue;
        }
        found = true;
        min_x = min_x.min(x);
        min_y = min_y.min(y);
        max_x = max_x.max(x);
        max_y = max_y.max(y);
    }
    found.then(|| {
        imageops::crop_imm(image, min_x, min_y, max_x - min_x + 1, max_y - min_y + 1).to_image()
    })
}

fn truncate_graphemes(value: &str, max: usize) -> String {
    let graphemes: Vec<&str> = UnicodeSegmentation::graphemes(value, true).collect();
    if graphemes.len() <= max {
        return value.to_string();
    }
    let keep = max.saturating_sub(1);
    format!("{}…", graphemes[..keep].concat().trim_end())
}

#[derive(sqlx::FromRow)]
struct ReconcilePage {
    nym: String,
    kind: String,
    header: String,
    description: String,
    generated_og_key: Option<String>,
    generated_og_template_version: Option<i32>,
    generated_og_failure_count: i32,
}

#[derive(Debug, Default)]
struct ReconcileOutcome {
    selected: usize,
    failures: usize,
}

#[derive(Debug, Clone)]
struct VerifyCursor {
    nym: String,
    kind: String,
}

/// Repair missing/stale images in small idempotent batches. Failed work gets a
/// durable exponential retry time while retaining any last-known-good asset.
/// A slower periodic sweep verifies that current DB references also exist on
/// this host, which repairs fresh/restored image volumes and local storage in a
/// horizontally scaled deployment.
pub fn spawn_reconciler(
    pool: PgPool,
    image_root: String,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut verify_cursor: Option<VerifyCursor> = None;
        let mut verify_due = tokio::time::Instant::now();
        loop {
            let mut wait = RECONCILE_INTERVAL;
            match reconcile_once(&pool, &image_root).await {
                Ok(outcome) if outcome.selected > 0 => {
                    tracing::info!(
                        event = "og_reconcile_batch",
                        selected = outcome.selected,
                        failures = outcome.failures
                    );
                    // Every selected row either publishes or receives a future
                    // retry time, so an immediate follow-up cannot hot-loop on
                    // the same failed batch. It also prevents the verification
                    // sweep from being starved by a trickle of new rows.
                    wait = Duration::from_secs(2);
                }
                Err(error) => {
                    tracing::warn!(event = "og_reconcile_failed", error = %error);
                }
                Ok(_) if tokio::time::Instant::now() >= verify_due => {
                    match verify_current_files_once(&pool, &image_root, verify_cursor.as_ref())
                        .await
                    {
                        Ok((selected, failures, next_cursor))
                            if selected >= VERIFY_BATCH_SIZE as usize =>
                        {
                            tracing::info!(event = "og_verify_batch", selected, failures);
                            verify_cursor = next_cursor;
                            wait = Duration::from_secs(2);
                        }
                        Ok((selected, failures, _)) => {
                            tracing::info!(event = "og_verify_complete", selected, failures);
                            verify_cursor = None;
                            verify_due = tokio::time::Instant::now() + VERIFY_INTERVAL;
                        }
                        Err(error) => {
                            tracing::warn!(event = "og_verify_failed", error = %error);
                        }
                    }
                }
                Ok(_) => {
                    wait =
                        wait.min(verify_due.saturating_duration_since(tokio::time::Instant::now()));
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
        }
    })
}

async fn reconcile_once(pool: &PgPool, root: &str) -> Result<ReconcileOutcome, OgImageError> {
    let pages = sqlx::query_as::<_, ReconcilePage>(
        "SELECT nym, kind, header, description, generated_og_key, \
                generated_og_template_version, generated_og_failure_count \
         FROM donation_pages \
         WHERE kind = 'payment_page' \
           AND enabled = TRUE \
           AND archived_at IS NULL \
           AND (generated_og_key IS NULL \
                OR generated_og_template_version IS DISTINCT FROM $1) \
           AND (generated_og_retry_after IS NULL OR generated_og_retry_after <= now()) \
         ORDER BY (generated_og_template_version IS NOT DISTINCT FROM $1) ASC, \
                  generated_og_retry_after ASC NULLS FIRST, \
                  updated_at ASC \
         LIMIT $2",
    )
    .bind(TEMPLATE_VERSION)
    .bind(RECONCILE_BATCH_SIZE)
    .fetch_all(pool)
    .await
    .map_err(|e| OgImageError::new(format!("select OG reconcile batch: {e}")))?;

    let mut outcome = ReconcileOutcome {
        selected: pages.len(),
        failures: 0,
    };
    for page in pages {
        let published = match publish(root, &page.header, &page.description).await {
            Ok(published) => published,
            Err(error) => {
                outcome.failures += 1;
                tracing::warn!(
                    event = "og_reconcile_render_failed",
                    nym = %page.nym,
                    error = %error
                );
                schedule_retry(pool, &page, false).await?;
                continue;
            }
        };
        attach_published(pool, &page, &published).await?;
    }
    Ok(outcome)
}

async fn attach_published(
    pool: &PgPool,
    page: &ReconcilePage,
    published: &PublishedOgImage,
) -> Result<(), OgImageError> {
    sqlx::query(
        "UPDATE donation_pages \
         SET generated_og_key = $7, generated_og_template_version = $8, \
             generated_og_failure_count = 0, generated_og_retry_after = NULL \
         WHERE nym = $1 AND kind = $2 \
           AND header = $3 AND description = $4 \
           AND generated_og_key IS NOT DISTINCT FROM $5 \
           AND generated_og_template_version IS NOT DISTINCT FROM $6 \
           AND enabled = TRUE AND archived_at IS NULL",
    )
    .bind(&page.nym)
    .bind(&page.kind)
    .bind(&page.header)
    .bind(&page.description)
    .bind(page.generated_og_key.as_deref())
    .bind(page.generated_og_template_version)
    .bind(&published.key)
    .bind(published.template_version)
    .execute(pool)
    .await
    .map_err(|e| OgImageError::new(format!("publish reconciled OG key: {e}")))?;
    Ok(())
}

fn retry_delay_secs(failure_count: i32) -> i32 {
    let exponent = failure_count.clamp(0, 7) as u32;
    RETRY_BASE_SECS
        .saturating_mul(1_i32 << exponent)
        .min(RETRY_MAX_SECS)
}

async fn schedule_retry(
    pool: &PgPool,
    page: &ReconcilePage,
    clear_missing_key: bool,
) -> Result<(), OgImageError> {
    let delay_secs = retry_delay_secs(page.generated_og_failure_count);
    sqlx::query(
        "UPDATE donation_pages \
         SET generated_og_key = CASE WHEN $7 THEN NULL ELSE generated_og_key END, \
             generated_og_template_version = CASE \
                 WHEN generated_og_key IS NULL THEN $9 \
                 ELSE generated_og_template_version \
             END, \
             generated_og_failure_count = LEAST(generated_og_failure_count + 1, 30), \
             generated_og_retry_after = now() + make_interval(secs => $8::double precision) \
         WHERE nym = $1 AND kind = $2 \
           AND header = $3 AND description = $4 \
           AND generated_og_key IS NOT DISTINCT FROM $5 \
           AND generated_og_template_version IS NOT DISTINCT FROM $6 \
           AND enabled = TRUE AND archived_at IS NULL",
    )
    .bind(&page.nym)
    .bind(&page.kind)
    .bind(&page.header)
    .bind(&page.description)
    .bind(page.generated_og_key.as_deref())
    .bind(page.generated_og_template_version)
    .bind(clear_missing_key)
    .bind(f64::from(delay_secs))
    .bind(TEMPLATE_VERSION)
    .execute(pool)
    .await
    .map_err(|e| OgImageError::new(format!("schedule OG retry: {e}")))?;
    Ok(())
}

async fn verify_current_files_once(
    pool: &PgPool,
    root: &str,
    after: Option<&VerifyCursor>,
) -> Result<(usize, usize, Option<VerifyCursor>), OgImageError> {
    let pages = sqlx::query_as::<_, ReconcilePage>(
        "SELECT nym, kind, header, description, generated_og_key, \
                generated_og_template_version, generated_og_failure_count \
         FROM donation_pages \
         WHERE kind = 'payment_page' \
           AND enabled = TRUE \
           AND archived_at IS NULL \
           AND generated_og_key IS NOT NULL \
           AND generated_og_template_version = $1 \
           AND ($2::text IS NULL OR (nym, kind) > ($2, $3)) \
         ORDER BY nym, kind \
         LIMIT $4",
    )
    .bind(TEMPLATE_VERSION)
    .bind(after.map(|cursor| cursor.nym.as_str()))
    .bind(after.map(|cursor| cursor.kind.as_str()))
    .bind(VERIFY_BATCH_SIZE)
    .fetch_all(pool)
    .await
    .map_err(|e| OgImageError::new(format!("select OG verification batch: {e}")))?;

    let selected = pages.len();
    let next_cursor = pages.last().map(|page| VerifyCursor {
        nym: page.nym.clone(),
        kind: page.kind.clone(),
    });
    let mut failures = 0;
    for page in pages {
        let Some(key) = page.generated_og_key.as_deref() else {
            continue;
        };
        let path = generated_path_for_version(root, TEMPLATE_VERSION, key);
        let exists = tokio::fs::try_exists(&path)
            .await
            .map_err(|e| OgImageError::new(format!("check {}: {e}", path.display())))?;
        if exists {
            continue;
        }

        tracing::warn!(
            event = "og_current_file_missing",
            nym = %page.nym,
            path = %path.display()
        );
        match publish(root, &page.header, &page.description).await {
            Ok(published) => attach_published(pool, &page, &published).await?,
            Err(error) => {
                failures += 1;
                tracing::warn!(
                    event = "og_missing_file_repair_failed",
                    nym = %page.nym,
                    error = %error
                );
                schedule_retry(pool, &page, true).await?;
            }
        }
    }

    Ok((selected, failures, next_cursor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::ImageReader;

    #[test]
    fn social_description_is_grapheme_bounded() {
        let input = "👨‍👩‍👧‍👦".repeat(DESCRIPTION_MAX_GRAPHEMES + 5);
        let output = social_description(&input);
        assert_eq!(
            description_grapheme_count(&output),
            DESCRIPTION_MAX_GRAPHEMES
        );
        assert!(output.ends_with('…'));
    }

    #[test]
    fn payment_page_description_validation_matches_visible_and_byte_caps() {
        assert!(!is_valid_payment_page_description(""));
        assert!(!is_valid_payment_page_description("   "));
        assert!(is_valid_payment_page_description(&"a".repeat(120)));
        assert!(!is_valid_payment_page_description(&"a".repeat(121)));
        assert!(is_valid_payment_page_description(&"😀".repeat(120)));
        assert!(!is_valid_payment_page_description(&"👨‍👩‍👧‍👦".repeat(21)));
    }

    #[test]
    fn content_key_is_deterministic_and_content_sensitive() {
        assert_eq!(
            content_key("Title", "Description"),
            content_key("Title", "Description")
        );
        assert_ne!(
            content_key("Title", "Description"),
            content_key("Other", "Description")
        );
        assert_eq!(
            content_key("  Title\n", "Description"),
            content_key("Title", "Description")
        );
        assert_eq!(
            content_key("   ", "Description"),
            content_key("Bull Bitcoin Payment Page", "Description")
        );
    }

    #[test]
    fn stored_template_version_controls_the_asset_location() {
        let key = "ab".repeat(32);
        assert_eq!(
            generated_path_for_version("/images", 7, &key),
            Path::new("/images")
                .join("og")
                .join("v7")
                .join(format!("{key}.jpg"))
        );
        assert_eq!(
            generated_url("bullpay.ca", 7, &key),
            format!("https://bullpay.ca/img/og/v7/{key}.jpg")
        );
    }

    #[test]
    fn retry_delay_is_exponential_and_capped() {
        assert_eq!(retry_delay_secs(0), 30);
        assert_eq!(retry_delay_secs(1), 60);
        assert_eq!(retry_delay_secs(6), 1_920);
        assert_eq!(retry_delay_secs(7), RETRY_MAX_SECS);
        assert_eq!(retry_delay_secs(100), RETRY_MAX_SECS);
    }

    #[test]
    fn rendered_card_is_jpeg_with_exact_social_dimensions() {
        let bytes = render_jpeg(
            "Support independent journalism",
            "Help us publish careful reporting without ads.",
        )
        .expect("render social card");
        if let Ok(path) = std::env::var("BULLNYM_OG_PREVIEW_PATH") {
            std::fs::write(path, &bytes).expect("write requested visual fixture");
        }
        assert!(bytes.len() < MAX_OUTPUT_BYTES);
        let image = ImageReader::new(std::io::Cursor::new(bytes))
            .with_guessed_format()
            .expect("guess JPEG")
            .decode()
            .expect("decode JPEG");
        assert_eq!((image.width(), image.height()), (WIDTH, HEIGHT));
        let rgb = image.to_rgb8();
        let branded_pixels = (56..145)
            .flat_map(|y| (80..420).map(move |x| (x, y)))
            .filter(|(x, y)| {
                let pixel = rgb.get_pixel(*x, *y).0;
                pixel[0].abs_diff(BACKGROUND[0]) > 20
                    || pixel[1].abs_diff(BACKGROUND[1]) > 20
                    || pixel[2].abs_diff(BACKGROUND[2]) > 20
            })
            .count();
        assert!(
            branded_pixels > 2_000,
            "the mandatory Bull Bitcoin lockup must be visible"
        );
        // The fixed red footer is part of every branded frame.
        let footer = rgb.get_pixel(600, HEIGHT - 6).0;
        assert!(footer[0] > 120 && footer[1] < 50 && footer[2] < 60);
    }

    #[test]
    fn multilingual_and_rtl_text_render_without_failure() {
        let bytes = render_jpeg(
            "ادعم عملي 支持我的工作",
            "شكراً لدعمكم 🙏 한국어와 বাংলা도 지원합니다",
        )
        .expect("render multilingual card");
        if let Ok(path) = std::env::var("BULLNYM_OG_MULTILINGUAL_PREVIEW_PATH") {
            std::fs::write(path, bytes).expect("write requested multilingual fixture");
        }
    }

    #[tokio::test]
    async fn publish_is_content_addressed_and_fallbacks_are_always_present() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "bullnym-og-publish-{unique}-{}",
            std::process::id()
        ));
        let root_str = root.to_string_lossy();

        ensure_fallbacks(&root_str).await.expect("write fallbacks");
        assert!(fallback_path(&root_str, false).is_file());
        assert!(fallback_path(&root_str, true).is_file());

        let first = publish(&root_str, "A Page", "A short description")
            .await
            .expect("publish custom image");
        let second = publish(&root_str, "A Page", "A short description")
            .await
            .expect("deduplicate custom image");
        assert_eq!(first, second);
        assert!(generated_path(&root_str, &first.key).is_file());

        std::fs::remove_dir_all(root).expect("remove test image directory");
    }
}

//! Donation-page image upload pipeline (Phase 3).
//!
//! Pipeline order is load-bearing — the cheapest checks run first so that
//! rejected uploads burn the least server work:
//!
//! 1. Caller already has body-size cap enforced via `DefaultBodyLimit`
//!    on the route layer (2 MiB by default). Bytes never enter memory
//!    beyond that.
//! 2. Magic-byte sniff (first 12 bytes). Reject extension-/Content-Type-
//!    only matches. Magic bytes pin the decoder format — never trust
//!    filename or `Content-Type` header.
//! 3. Header-only dimension probe via `image::ImageReader::into_dimensions()`
//!    — rejects image-bombs without allocating the full pixel buffer.
//! 4. Full decode (now safe; dimensions are bounded).
//! 5. Resize to target box (avatar 256×256, OG 1200×630).
//! 6. Lossless WebP encode.
//! 7. Atomic write: `<root>/<nym>/<kind>.webp.tmp` → fsync → rename.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use image::{imageops::FilterType, ImageReader};
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// Which donation-page image slot the bytes are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Avatar,
    Og,
}

impl ImageKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Avatar => "avatar",
            Self::Og => "og",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "avatar" => Some(Self::Avatar),
            "og" => Some(Self::Og),
            _ => None,
        }
    }
}

/// Detected source format. Used to pin the decoder so an attacker can't
/// confuse it with a misleading Content-Type header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SniffedFormat {
    Jpeg,
    Png,
    Webp,
}

impl SniffedFormat {
    fn to_image_format(self) -> image::ImageFormat {
        match self {
            Self::Jpeg => image::ImageFormat::Jpeg,
            Self::Png => image::ImageFormat::Png,
            Self::Webp => image::ImageFormat::WebP,
        }
    }
}

/// Magic-byte sniff. Returns `None` if the first 12 bytes don't match a
/// supported format.
fn sniff_format(bytes: &[u8]) -> Option<SniffedFormat> {
    if bytes.len() < 12 {
        return None;
    }
    // JPEG: FF D8 FF
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(SniffedFormat::Jpeg);
    }
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(SniffedFormat::Png);
    }
    // WebP: "RIFF" .... "WEBP"
    if &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some(SniffedFormat::Webp);
    }
    None
}

#[derive(Debug)]
pub struct ProcessedImage {
    /// Lossless WebP-encoded bytes ready for atomic write.
    pub webp_bytes: Vec<u8>,
    /// SHA-256 of the ORIGINAL upload bytes (for sig verification +
    /// `donation_pages.<kind>_sha256` column).
    pub source_sha256: String,
}

pub struct PipelineConfig {
    pub max_bytes: usize,
    pub max_dimension: u32,
    pub avatar_size: u32,
    pub og_width: u32,
    pub og_height: u32,
}

/// Run the full decode/resize/re-encode pipeline. Returns the WebP-encoded
/// output bytes and the SHA-256 of the original input.
///
/// Errors:
/// - `ImageInvalid` for: oversize body, unrecognized magic bytes, decode
///   failure, encoder failure.
/// - `ImageDimensionsTooLarge` for: header-reported dimensions exceed
///   `max_dimension`.
pub fn process(
    bytes: &[u8],
    kind: ImageKind,
    cfg: &PipelineConfig,
) -> Result<ProcessedImage, AppError> {
    if bytes.is_empty() {
        return Err(AppError::ImageInvalid("empty body".into()));
    }
    if bytes.len() > cfg.max_bytes {
        // Belt-and-braces — the per-route body limit should catch this
        // first, but keep the inner check in case the route is wired
        // without the layer.
        return Err(AppError::ImageInvalid(format!(
            "{} bytes exceeds cap {}",
            bytes.len(),
            cfg.max_bytes
        )));
    }

    let sniffed = sniff_format(bytes).ok_or_else(|| {
        AppError::ImageInvalid("unrecognized magic bytes (only JPEG/PNG/WebP accepted)".into())
    })?;
    let format = sniffed.to_image_format();

    // SHA-256 of original upload — used by callers for sig verification
    // and persisted on the donation_pages row.
    let source_sha256 = {
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    };

    // Header-only dimension probe (no full decode yet).
    let reader = ImageReader::with_format(Cursor::new(bytes), format);
    let (w, h) = reader
        .into_dimensions()
        .map_err(|e| AppError::ImageInvalid(format!("dimension probe failed: {e}")))?;
    if w > cfg.max_dimension || h > cfg.max_dimension {
        return Err(AppError::ImageDimensionsTooLarge {
            max: cfg.max_dimension,
        });
    }

    // Full decode now that dimensions are bounded.
    let img = ImageReader::with_format(Cursor::new(bytes), format)
        .decode()
        .map_err(|e| AppError::ImageInvalid(format!("decode failed: {e}")))?;

    let resized = match kind {
        ImageKind::Avatar => {
            // Square crop centered, then resize to avatar_size. The
            // `resize_to_fill` helper handles both in one step.
            img.resize_to_fill(cfg.avatar_size, cfg.avatar_size, FilterType::Lanczos3)
        }
        ImageKind::Og => img.resize_to_fill(cfg.og_width, cfg.og_height, FilterType::Lanczos3),
    };

    // Encode to lossless WebP. The lossy WebP encoder requires libwebp
    // (system dep); lossless gives us larger output but no FFI deps,
    // which is the right trade for a 2 MiB upload cap.
    let mut out = Vec::with_capacity(64 * 1024);
    {
        let encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut out);
        resized
            .write_with_encoder(encoder)
            .map_err(|e| AppError::ImageInvalid(format!("webp encode failed: {e}")))?;
    }

    Ok(ProcessedImage {
        webp_bytes: out,
        source_sha256,
    })
}

/// Compute the on-disk path for a donation-page image. Both `nym` and
/// `kind` are caller-validated (NYM_REGEX upstream + `ImageKind` enum)
/// so neither can introduce path-traversal characters.
pub fn image_path(root: &str, nym: &str, kind: ImageKind) -> PathBuf {
    Path::new(root)
        .join(nym)
        .join(format!("{}.webp", kind.as_str()))
}

/// Atomic write: write to `<final>.tmp.<uuid>`, fsync, rename to `<final>`.
/// Creates the parent dir on first write for the nym. Synchronous — the
/// caller wraps in `tokio::task::spawn_blocking`.
///
/// The UUID-suffixed tmp filename defuses the concurrent-uploads-to-same-
/// (nym,kind) race: each writer gets its own tmp file; rename is atomic;
/// last writer's bytes win cleanly (no half-mixed file). Stray .tmp.<uuid>
/// files left by request cancellation can be GC'd by a periodic cleanup.
pub fn atomic_write(final_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::fs;
    use std::io::Write;

    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_suffix = format!("webp.tmp.{}", uuid::Uuid::new_v4());
    let tmp_path = final_path.with_extension(tmp_suffix);
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp_path, final_path) {
        // Best-effort cleanup of the tmp file on rename failure.
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_jpeg() {
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xE0];
        bytes.extend(std::iter::repeat(0).take(20));
        assert_eq!(sniff_format(&bytes), Some(SniffedFormat::Jpeg));
    }

    #[test]
    fn sniff_png() {
        let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend(std::iter::repeat(0).take(20));
        assert_eq!(sniff_format(&bytes), Some(SniffedFormat::Png));
    }

    #[test]
    fn sniff_webp() {
        let mut bytes = b"RIFF".to_vec();
        bytes.extend([0, 0, 0, 0]);
        bytes.extend(b"WEBP");
        bytes.extend(std::iter::repeat(0).take(20));
        assert_eq!(sniff_format(&bytes), Some(SniffedFormat::Webp));
    }

    #[test]
    fn sniff_rejects_too_short() {
        assert_eq!(sniff_format(&[0xFF, 0xD8]), None);
    }

    #[test]
    fn sniff_rejects_php_in_jpeg_jacket() {
        // <?php — no magic bytes match.
        let bytes = b"<?php echo 'hi'; ?>".to_vec();
        assert_eq!(sniff_format(&bytes), None);
    }

    #[test]
    fn image_kind_parse() {
        assert_eq!(ImageKind::parse("avatar"), Some(ImageKind::Avatar));
        assert_eq!(ImageKind::parse("og"), Some(ImageKind::Og));
        assert_eq!(ImageKind::parse("AVATAR"), None);
        assert_eq!(ImageKind::parse("../etc/passwd"), None);
    }

    #[test]
    fn image_path_no_traversal() {
        // Both inputs are already validated upstream, but verify the
        // assembled path stays under root for the nominal case.
        let p = image_path("/tmp/imgs", "alice", ImageKind::Avatar);
        assert_eq!(p.to_str().unwrap(), "/tmp/imgs/alice/avatar.webp");
    }

    fn make_test_png(width: u32, height: u32) -> Vec<u8> {
        let img = image::RgbImage::new(width, height);
        let mut out = Vec::new();
        let encoder = image::codecs::png::PngEncoder::new(&mut out);
        image::ImageEncoder::write_image(
            encoder,
            img.as_raw(),
            width,
            height,
            image::ExtendedColorType::Rgb8,
        )
        .unwrap();
        out
    }

    fn default_cfg() -> PipelineConfig {
        PipelineConfig {
            max_bytes: 2 * 1024 * 1024,
            max_dimension: 10_000,
            avatar_size: 256,
            og_width: 1200,
            og_height: 630,
        }
    }

    #[test]
    fn process_resizes_avatar_to_square() {
        let png = make_test_png(800, 600);
        let result = process(&png, ImageKind::Avatar, &default_cfg()).unwrap();
        // Round-trip the encoded WebP to confirm dimensions.
        let img = image::load_from_memory(&result.webp_bytes).unwrap();
        assert_eq!(img.width(), 256);
        assert_eq!(img.height(), 256);
        // SHA-256 should match a fresh hash of the input.
        let mut h = Sha256::new();
        h.update(&png);
        assert_eq!(result.source_sha256, hex::encode(h.finalize()));
    }

    #[test]
    fn process_resizes_og_to_1200x630() {
        let png = make_test_png(2400, 1260);
        let result = process(&png, ImageKind::Og, &default_cfg()).unwrap();
        let img = image::load_from_memory(&result.webp_bytes).unwrap();
        assert_eq!(img.width(), 1200);
        assert_eq!(img.height(), 630);
    }

    #[test]
    fn process_rejects_unrecognized_bytes() {
        let bytes = b"this is definitely not an image of any kind".repeat(2);
        let err = process(&bytes, ImageKind::Avatar, &default_cfg()).unwrap_err();
        assert!(matches!(err, AppError::ImageInvalid(_)));
    }

    #[test]
    fn process_rejects_oversize_body() {
        let mut cfg = default_cfg();
        cfg.max_bytes = 100;
        let png = make_test_png(50, 50);
        assert!(png.len() > 100);
        let err = process(&png, ImageKind::Avatar, &cfg).unwrap_err();
        assert!(matches!(err, AppError::ImageInvalid(_)));
    }

    #[test]
    fn process_rejects_huge_dimensions() {
        let mut cfg = default_cfg();
        cfg.max_dimension = 100;
        let png = make_test_png(200, 200);
        let err = process(&png, ImageKind::Avatar, &cfg).unwrap_err();
        assert!(matches!(err, AppError::ImageDimensionsTooLarge { .. }));
    }

    #[test]
    fn process_rejects_empty() {
        let err = process(&[], ImageKind::Avatar, &default_cfg()).unwrap_err();
        assert!(matches!(err, AppError::ImageInvalid(_)));
    }

    #[test]
    fn atomic_write_creates_parent_and_renames() {
        let tmp = std::env::temp_dir().join(format!("pay-service-test-{}", uuid::Uuid::new_v4()));
        let target = tmp.join("alice").join("avatar.webp");
        atomic_write(&target, b"hello").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
        // Cleanup.
        std::fs::remove_dir_all(&tmp).ok();
    }
}

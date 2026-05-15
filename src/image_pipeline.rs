//! Donation-page image upload pipeline.
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
//! 6. Encode avatar as WebP and OG as JPEG.
//! 7. Atomic write: `<root>/<nym>/<kind>.<ext>.tmp` → fsync → rename.

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
    /// Encoded bytes ready for atomic write.
    pub bytes: Vec<u8>,
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

/// Run the full decode/resize/re-encode pipeline. Returns encoded
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

    // Encode avatar as WebP for page display. Encode OG as JPEG because
    // social-media crawlers handle JPEG more consistently than WebP.
    let mut out = Vec::with_capacity(64 * 1024);
    match kind {
        ImageKind::Avatar => {
            let encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut out);
            resized
                .write_with_encoder(encoder)
                .map_err(|e| AppError::ImageInvalid(format!("webp encode failed: {e}")))?;
        }
        ImageKind::Og => {
            let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 85);
            encoder
                .encode_image(&resized.to_rgb8())
                .map_err(|e| AppError::ImageInvalid(format!("jpeg encode failed: {e}")))?;
        }
    }

    Ok(ProcessedImage {
        bytes: out,
        source_sha256,
    })
}

/// Compute the on-disk path for a donation-page image. Both `nym` and
/// `kind` are caller-validated (NYM_REGEX upstream + `ImageKind` enum)
/// so neither can introduce path-traversal characters.
pub fn image_path(root: &str, nym: &str, kind: ImageKind) -> PathBuf {
    let ext = match kind {
        ImageKind::Avatar => "webp",
        ImageKind::Og => "jpg",
    };
    Path::new(root)
        .join(nym)
        .join(format!("{}.{}", kind.as_str(), ext))
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
    let tmp_suffix = format!("img.tmp.{}", uuid::Uuid::new_v4());
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
mod tests;

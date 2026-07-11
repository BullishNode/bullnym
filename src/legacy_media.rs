//! Read-only compatibility helpers for Payment Page media created by older
//! Bullnym versions. New uploads are not supported.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyMediaKind {
    Avatar,
    Og,
}

impl LegacyMediaKind {
    fn stem(self) -> &'static str {
        match self {
            Self::Avatar => "avatar",
            Self::Og => "og",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Avatar => "webp",
            Self::Og => "jpg",
        }
    }
}

pub fn nym_path(root: &str, nym: &str, kind: LegacyMediaKind) -> PathBuf {
    Path::new(root)
        .join(nym)
        .join(format!("{}.{}", kind.stem(), kind.extension()))
}

pub fn content_path(root: &str, sha256_hex: &str, kind: LegacyMediaKind) -> PathBuf {
    Path::new(root)
        .join("_h")
        .join(format!("{sha256_hex}.{}", kind.extension()))
}

/// Preserve an existing nym-keyed file under its content-addressed alias path.
/// This is the only remaining write: it copies already accepted legacy media
/// and never processes payer- or merchant-supplied request bytes.
pub fn write_legacy_copy(final_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::fs;
    use std::io::Write;

    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = final_path.with_extension(format!("legacy.tmp.{}", uuid::Uuid::new_v4()));
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if let Err(error) = fs::rename(&tmp_path, final_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_existing_media_paths() {
        assert_eq!(
            nym_path("/data", "alice", LegacyMediaKind::Avatar),
            Path::new("/data/alice/avatar.webp")
        );
        assert_eq!(
            content_path("/data", "deadbeef", LegacyMediaKind::Og),
            Path::new("/data/_h/deadbeef.jpg")
        );
    }
}

//! Private LNURL payer-comment domain contract.
//!
//! Comments are exact payer-supplied text. They are never normalized, parsed
//! as markup, or formatted into a public/provider-facing value. Persistence
//! and authenticated projection live in [`crate::db`]; this module owns the
//! input bounds and privacy-safe value types shared by those seams.

use std::fmt;

use unicode_segmentation::UnicodeSegmentation;

/// Maximum number of user-perceived Unicode characters accepted from LUD-12.
pub const LNURL_COMMENT_MAX_GRAPHEMES: usize = 120;

/// Value advertised through LUD-06 `commentAllowed`.
pub const LNURL_COMMENT_ALLOWED: u16 = 120;

/// Defensive UTF-8 ceiling applied before grapheme segmentation.
pub const LNURL_COMMENT_MAX_BYTES: usize = 512;

/// An exact, non-empty payer comment accepted at the LNURL callback boundary.
///
/// Empty callback values are represented as `None` by
/// [`LnurlPayerComment::from_optional`]. The inner text is deliberately private
/// and this type's `Debug` implementation never renders it.
#[derive(Clone, PartialEq, Eq)]
pub struct LnurlPayerComment {
    value: String,
    grapheme_count: u16,
}

impl LnurlPayerComment {
    /// Validate an optional callback comment without changing its bytes.
    ///
    /// A present empty string is equivalent to the optional field being
    /// absent. Every non-empty accepted value is preserved byte-for-byte.
    pub fn from_optional(
        value: Option<String>,
    ) -> Result<Option<Self>, LnurlCommentValidationError> {
        value
            .filter(|value| !value.is_empty())
            .map(Self::try_from)
            .transpose()
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub const fn grapheme_count(&self) -> u16 {
        self.grapheme_count
    }
}

impl TryFrom<String> for LnurlPayerComment {
    type Error = LnurlCommentValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(LnurlCommentValidationError::Empty);
        }
        if value.len() > LNURL_COMMENT_MAX_BYTES {
            return Err(LnurlCommentValidationError::TooManyBytes {
                actual: value.len(),
                maximum: LNURL_COMMENT_MAX_BYTES,
            });
        }

        let grapheme_count = UnicodeSegmentation::graphemes(value.as_str(), true).count();
        if grapheme_count > LNURL_COMMENT_MAX_GRAPHEMES {
            return Err(LnurlCommentValidationError::TooManyGraphemes {
                actual: grapheme_count,
                maximum: LNURL_COMMENT_MAX_GRAPHEMES,
            });
        }

        Ok(Self {
            value,
            grapheme_count: u16::try_from(grapheme_count)
                .expect("the validated LNURL comment grapheme count fits u16"),
        })
    }
}

impl fmt::Debug for LnurlPayerComment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LnurlPayerComment")
            .field("value", &"<redacted>")
            .field("grapheme_count", &self.grapheme_count)
            .field("utf8_bytes", &self.value.len())
            .finish()
    }
}

/// Privacy-safe comment validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LnurlCommentValidationError {
    Empty,
    TooManyBytes { actual: usize, maximum: usize },
    TooManyGraphemes { actual: usize, maximum: usize },
}

impl fmt::Display for LnurlCommentValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("LNURL comment is empty"),
            Self::TooManyBytes { actual, maximum } => write!(
                formatter,
                "LNURL comment is {actual} UTF-8 bytes; maximum is {maximum}"
            ),
            Self::TooManyGraphemes { actual, maximum } => write!(
                formatter,
                "LNURL comment has {actual} user-visible characters; maximum is {maximum}"
            ),
        }
    }
}

impl std::error::Error for LnurlCommentValidationError {}

/// Stable, opaque callback identity supplied by LNURL metadata.
///
/// The coordinator issues fresh randomness in each metadata callback instead
/// of deriving identity from ambiguous `(nym, amount, comment)` values. Exact
/// callback retries retain this digest; a newly resolved payment gets a new
/// one.
#[derive(Clone, PartialEq, Eq)]
pub struct LnurlCommentIntentKey(String);

impl LnurlCommentIntentKey {
    pub fn from_digest(digest: [u8; 32]) -> Self {
        Self(hex::encode(digest))
    }

    /// Parse the opaque callback token issued by LNURL metadata.
    ///
    /// Tokens are canonical lowercase SHA-256 digests. Rejecting alternate
    /// spellings keeps one callback URL mapped to exactly one persisted key.
    pub fn from_callback_token(value: &str) -> Result<Self, LnurlCommentIntentTokenError> {
        if is_canonical_digest(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(LnurlCommentIntentTokenError)
        }
    }

    pub(crate) fn from_stored(value: String) -> Result<Self, LnurlCommentStoredValueError> {
        if is_canonical_digest(&value) {
            Ok(Self(value))
        } else {
            Err(LnurlCommentStoredValueError::IntentKey)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Privacy-safe malformed callback-token error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LnurlCommentIntentTokenError;

impl fmt::Display for LnurlCommentIntentTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid LNURL comment intent token")
    }
}

impl std::error::Error for LnurlCommentIntentTokenError {}

impl fmt::Debug for LnurlCommentIntentKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LnurlCommentIntentKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LnurlCommentRail {
    Lightning,
    Liquid,
}

impl LnurlCommentRail {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lightning => "lightning",
            Self::Liquid => "liquid",
        }
    }

    pub(crate) fn from_stored(value: &str) -> Result<Self, LnurlCommentStoredValueError> {
        match value {
            "lightning" => Ok(Self::Lightning),
            "liquid" => Ok(Self::Liquid),
            _ => Err(LnurlCommentStoredValueError::Rail),
        }
    }
}

/// Stored-value corruption reported without rendering private row content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LnurlCommentStoredValueError {
    IntentKey,
    Rail,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_exact_multilingual_text() {
        let value = "Coffee for Ana ☕\nありがとう".to_string();
        let comment = LnurlPayerComment::try_from(value.clone()).unwrap();
        assert_eq!(comment.as_str(), value);
        assert_eq!(
            comment.grapheme_count() as usize,
            value.graphemes(true).count()
        );
    }

    #[test]
    fn counts_user_visible_graphemes_not_unicode_scalars() {
        let family = "👨‍👩‍👧‍👦";
        let value = family.repeat(LNURL_COMMENT_MAX_GRAPHEMES);
        let comment = LnurlPayerComment::try_from(value).unwrap_err();
        assert!(matches!(
            comment,
            LnurlCommentValidationError::TooManyBytes { .. }
        ));

        let combining = "e\u{301}".repeat(LNURL_COMMENT_MAX_GRAPHEMES);
        let comment = LnurlPayerComment::try_from(combining).unwrap();
        assert_eq!(
            comment.grapheme_count() as usize,
            LNURL_COMMENT_MAX_GRAPHEMES
        );
    }

    #[test]
    fn rejects_121_user_visible_characters() {
        let error = LnurlPayerComment::try_from("a".repeat(121)).unwrap_err();
        assert_eq!(
            error,
            LnurlCommentValidationError::TooManyGraphemes {
                actual: 121,
                maximum: 120,
            }
        );
    }

    #[test]
    fn applies_byte_bound_before_segmentation() {
        let error = LnurlPayerComment::try_from("😀".repeat(129)).unwrap_err();
        assert_eq!(
            error,
            LnurlCommentValidationError::TooManyBytes {
                actual: 516,
                maximum: 512,
            }
        );
    }

    #[test]
    fn optional_empty_comment_is_absent() {
        assert!(LnurlPayerComment::from_optional(None).unwrap().is_none());
        assert!(LnurlPayerComment::from_optional(Some(String::new()))
            .unwrap()
            .is_none());
    }

    #[test]
    fn debug_never_renders_comment_or_intent_digest() {
        let secret = "private order 123";
        let comment = LnurlPayerComment::try_from(secret.to_string()).unwrap();
        let debug = format!("{comment:?}");
        assert!(!debug.contains(secret));
        assert!(debug.contains("<redacted>"));

        let key = LnurlCommentIntentKey::from_digest([0xab; 32]);
        let key_debug = format!("{key:?}");
        assert!(!key_debug.contains(key.as_str()));
    }

    #[test]
    fn callback_token_requires_one_canonical_lowercase_digest() {
        let token = "ab".repeat(32);
        assert_eq!(
            LnurlCommentIntentKey::from_callback_token(&token)
                .unwrap()
                .as_str(),
            token
        );
        assert!(LnurlCommentIntentKey::from_callback_token(&"AB".repeat(32)).is_err());
        assert!(LnurlCommentIntentKey::from_callback_token(&"a".repeat(63)).is_err());
        assert!(LnurlCommentIntentKey::from_callback_token(&"g".repeat(64)).is_err());
    }
}

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

#[derive(Debug)]
pub enum AppError {
    // --- Identity / registration ---
    NymNotFound(String),
    /// Name already registered (by anyone).
    NymTaken,
    /// The submitted string is permanently reserved as either a nym or alias.
    NameTaken,
    /// The submitted nym fails the format rules (`internal_reason` is for
    /// logging; the wire copy is fixed).
    NymInvalid(String),
    /// Submitted nym matches a reserved server slug (e.g. "register",
    /// "health"). Blocked at create time so `/<nym>` fallback can't shadow
    /// explicit routes.
    NymReserved,
    /// Donation-page payload failed validation (length, range, format).
    /// Inner string is operator-facing only; wire copy is a fixed message.
    DonationPageInvalid(String),
    /// No donation page exists for this nym (or it was archived and the
    /// caller queried via a path that treats archived as gone).
    DonationPageNotFound(String),
    /// Invoice ID does not resolve, or the path's nym does not match the
    /// invoice's owning nym. Same wire copy in both cases — never reveal
    /// existence cross-nym.
    InvoiceNotFound(String),
    /// A recovery-policy BTC address is malformed, non-canonical, or on the
    /// wrong network. Inner string is operator-facing.
    RecoveryAddressInvalid(String),
    /// Automatic recovery cannot proceed for this swap because its immutable
    /// evidence or lifecycle state is not eligible. Inner string is
    /// operator-facing.
    RecoveryNotAvailable(String),
    /// Image upload rejected (magic-byte sniff fail, decode error, etc.).
    /// Inner string is operator-facing.
    ImageInvalid(String),
    /// Multipart form was malformed: missing required field, oversize text
    /// field, etc. Distinct from `ImageInvalid` so the wire copy doesn't
    /// blame the user's image when the form was actually wrong.
    MultipartInvalid(String),
    /// Decoded image dimensions exceeded `image_max_dimension`. Image-
    /// bomb defense — the full pixel buffer was never allocated.
    ImageDimensionsTooLarge {
        max: u32,
    },
    /// Decoded image area exceeded `image_max_pixels`. Image-bomb defense
    /// paired with the per-axis cap.
    ImagePixelsTooLarge {
        max_pixels: u64,
    },
    /// The caller's wallet already has an active address.
    KeyAlreadyRegistered {
        nym: String,
        domain: String,
    },
    /// Wallet has registered the cap of lifetime nyms. Carries both `used`
    /// and `cap` so the wire envelope ships the same `quota` object the
    /// mobile receives on lookup.
    NymQuotaExceeded {
        used: i64,
        cap: i64,
    },
    /// This wallet already owns a different permanent nym.
    NymAlreadyAssigned {
        nym: String,
        domain: String,
    },
    /// CT descriptor was rejected (`internal_reason` is for logging).
    InvalidDescriptor(String),
    /// Generic wallet auth failure (Schnorr sig fail, ts skew, npub parse).
    AuthError(String),

    // --- Liquid LUD-22 / proof of funds ---
    ProofOfFundsRequired {
        min_sat: u64,
    },
    ProofOfFundsInvalid(String),
    UtxoNotFound,
    UtxoSpent,
    PubkeyUtxoMismatch,

    // --- Amount validation (LNURL callback) ---
    InvalidAmount(String),
    /// LUD-12 comment validation or stable-retry failure. The inner value is
    /// always server-authored static text and must never contain payer input.
    InvalidComment(&'static str),
    /// Wallet-origin invoice tried to reuse a BTC receive address that is
    /// already assigned to an invoice. Address reuse makes chain payment
    /// attribution ambiguous, so it is rejected at create time.
    BitcoinAddressAlreadyUsed,
    /// Wallet-origin invoice tried to reuse a Liquid receive address that is
    /// already assigned to an invoice. Address reuse makes chain payment
    /// attribution ambiguous, so it is rejected at create time.
    LiquidAddressAlreadyUsed,
    /// This wallet already owns a different permanent alias. Alias ownership
    /// is insert-only, so the client must keep using the existing value.
    AliasAlreadyAssigned {
        alias: String,
    },

    // --- Capacity / rate-limit ---
    /// One source (IP, pubkey, etc.) is making too many requests.
    RateLimitedSender,
    /// One recipient (nym) is being targeted too aggressively.
    RateLimitedRecipient,
    /// Too many distinct keys / nyms / outpoints from one source.
    RateLimitedNetwork,
    /// Server-side blockchain backend (Electrum) is throttled.
    BackendThrottled,
    /// Recipient has too many in-flight payment reservations.
    TooManyPendingReservations,
    /// Hard ceiling reached (e.g. `max_active_users`). Durable, not burst —
    /// clients should not retry-with-backoff. Internal `_reason` is for logs.
    ServiceUnavailable(String),
    /// A money-admission prerequisite is not currently healthy. Detailed rail
    /// and dependency reasons are emitted by the admission component only;
    /// the wire response is deliberately fixed and retryable.
    MoneyAdmissionUnavailable,
    /// Deactivation is blocked by `_pending` in-flight swaps.
    PurgeBlocked(usize),

    // --- Backend failures (user-facing) ---
    ElectrumError(String),
    BoltzError(String),
    /// Server-internal: claim flow failure on the Boltz webhook path. Never
    /// returned to a wallet — only logged and returned to Boltz. Kept here
    /// because the webhook handler shares the same error stack.
    ClaimError(String),
    /// Generic database / unexpected internal error.
    DbError(String),
}

/// Coarse classification of an `AppError`. Single source of truth for
/// "what kind of error is this" — `is_rate_limit()` (soft-fallback signal),
/// future log-grouping, and any future per-class metric all derive from
/// `AppError::class()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Caller-side validation failure or auth failure.
    Auth,
    /// Identity / namespace conflict (nym taken, quota, key collision).
    Identity,
    /// Soft rate-limit — sender, recipient, or network. The Liquid LUD-22
    /// path treats this as a reason to fall back to Lightning.
    RateLimit,
    /// Hard capacity ceiling (max active users, in-flight reservation cap,
    /// purge-blocked). Not a transient burst; clients shouldn't retry-with-
    /// backoff on these.
    Capacity,
    /// Backend infrastructure failure (Electrum/Boltz/database). Soft for
    /// LUD-22 fallback only when it's a backend-throttle, not a hard error.
    Backend,
    /// Unexpected internal error.
    Internal,
}

impl AppError {
    /// Coarse classification — the only place where each variant's category
    /// is decided. `is_rate_limit()` and any future class-based logic must
    /// derive from this.
    pub fn class(&self) -> ErrorClass {
        match self {
            Self::AuthError(_) => ErrorClass::Auth,

            Self::NymNotFound(_)
            | Self::NymTaken
            | Self::NameTaken
            | Self::NymInvalid(_)
            | Self::NymReserved
            | Self::DonationPageInvalid(_)
            | Self::DonationPageNotFound(_)
            | Self::InvoiceNotFound(_)
            | Self::ImageInvalid(_)
            | Self::ImageDimensionsTooLarge { .. }
            | Self::ImagePixelsTooLarge { .. }
            | Self::MultipartInvalid(_)
            | Self::KeyAlreadyRegistered { .. }
            | Self::NymQuotaExceeded { .. }
            | Self::NymAlreadyAssigned { .. }
            | Self::InvalidDescriptor(_)
            | Self::ProofOfFundsRequired { .. }
            | Self::ProofOfFundsInvalid(_)
            | Self::UtxoNotFound
            | Self::UtxoSpent
            | Self::PubkeyUtxoMismatch
            | Self::InvalidAmount(_)
            | Self::InvalidComment(_)
            | Self::RecoveryAddressInvalid(_)
            | Self::RecoveryNotAvailable(_)
            | Self::BitcoinAddressAlreadyUsed
            | Self::LiquidAddressAlreadyUsed
            | Self::AliasAlreadyAssigned { .. } => ErrorClass::Identity,

            Self::RateLimitedSender
            | Self::RateLimitedRecipient
            | Self::RateLimitedNetwork
            | Self::BackendThrottled
            | Self::TooManyPendingReservations => ErrorClass::RateLimit,

            Self::ServiceUnavailable(_) | Self::PurgeBlocked(_) => ErrorClass::Capacity,

            Self::MoneyAdmissionUnavailable
            | Self::ElectrumError(_)
            | Self::BoltzError(_)
            | Self::ClaimError(_) => ErrorClass::Backend,

            Self::DbError(_) => ErrorClass::Internal,
        }
    }

    /// Stable enum the mobile uses as i18n key.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NymNotFound(_) => "NymNotFound",
            Self::NymTaken => "NymTaken",
            Self::NameTaken => "NameTaken",
            Self::NymInvalid(_) => "NymInvalid",
            Self::NymReserved => "NymReserved",
            Self::DonationPageInvalid(_) => "DonationPageInvalid",
            Self::DonationPageNotFound(_) => "DonationPageNotFound",
            Self::InvoiceNotFound(_) => "InvoiceNotFound",
            Self::RecoveryAddressInvalid(_) => "RecoveryAddressInvalid",
            Self::RecoveryNotAvailable(_) => "RecoveryNotAvailable",
            Self::ImageInvalid(_) => "ImageInvalid",
            Self::ImageDimensionsTooLarge { .. } => "ImageDimensionsTooLarge",
            Self::ImagePixelsTooLarge { .. } => "ImagePixelsTooLarge",
            Self::MultipartInvalid(_) => "MultipartInvalid",
            Self::KeyAlreadyRegistered { .. } => "KeyAlreadyRegistered",
            Self::NymQuotaExceeded { .. } => "NymQuotaExceeded",
            Self::NymAlreadyAssigned { .. } => "NymAlreadyAssigned",
            Self::InvalidDescriptor(_) => "InvalidDescriptor",
            Self::AuthError(_) => "AuthError",

            Self::ProofOfFundsRequired { .. } => "ProofOfFundsRequired",
            Self::ProofOfFundsInvalid(_) => "ProofOfFundsInvalid",
            Self::UtxoNotFound => "UtxoNotFound",
            Self::UtxoSpent => "UtxoSpent",
            Self::PubkeyUtxoMismatch => "PubkeyUtxoMismatch",

            Self::InvalidAmount(_) => "InvalidAmount",
            Self::InvalidComment(_) => "InvalidComment",
            Self::BitcoinAddressAlreadyUsed => "BitcoinAddressAlreadyUsed",
            Self::LiquidAddressAlreadyUsed => "LiquidAddressAlreadyUsed",
            Self::AliasAlreadyAssigned { .. } => "AliasAlreadyAssigned",

            Self::RateLimitedSender => "RateLimitedSender",
            Self::RateLimitedRecipient => "RateLimitedRecipient",
            Self::RateLimitedNetwork => "RateLimitedNetwork",
            Self::BackendThrottled => "BackendThrottled",
            Self::TooManyPendingReservations => "TooManyPendingReservations",
            Self::ServiceUnavailable(_) => "ServiceUnavailable",
            Self::MoneyAdmissionUnavailable => "ServiceUnavailable",
            Self::PurgeBlocked(_) => "PurgeBlocked",

            Self::ElectrumError(_) => "ElectrumError",
            Self::BoltzError(_) => "BoltzError",
            Self::ClaimError(_) => "ClaimError",
            Self::DbError(_) => "InternalError",
        }
    }

    /// Soft rate-limit signals that the LUD-22 (Liquid) path treats as a
    /// reason to fall back to Lightning instead of failing the callback.
    /// Derives from `class()` so adding a new rate-limit variant only
    /// requires one edit (in `class()`).
    pub fn is_rate_limit(&self) -> bool {
        self.class() == ErrorClass::RateLimit
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NymNotFound(nym) => write!(f, "nym not found: {nym}"),
            Self::NymTaken => write!(f, "nym already taken"),
            Self::NameTaken => write!(f, "public name already taken"),
            Self::NymInvalid(reason) => write!(f, "invalid nym: {reason}"),
            Self::NymReserved => write!(f, "nym is reserved"),
            Self::DonationPageInvalid(reason) => write!(f, "donation page invalid: {reason}"),
            Self::DonationPageNotFound(nym) => write!(f, "no donation page for {nym}"),
            Self::InvoiceNotFound(id) => write!(f, "invoice not found: {id}"),
            Self::RecoveryAddressInvalid(reason) => write!(f, "recovery address invalid: {reason}"),
            Self::RecoveryNotAvailable(reason) => write!(f, "recovery not available: {reason}"),
            Self::ImageInvalid(reason) => write!(f, "image invalid: {reason}"),
            Self::ImageDimensionsTooLarge { max } => {
                write!(f, "image dimensions exceed {max}px cap")
            }
            Self::ImagePixelsTooLarge { max_pixels } => {
                write!(f, "image pixel area exceeds {max_pixels} pixel cap")
            }
            Self::MultipartInvalid(reason) => write!(f, "multipart invalid: {reason}"),
            Self::KeyAlreadyRegistered { nym, domain } => {
                write!(f, "key already has active address: {nym}@{domain}")
            }
            Self::NymQuotaExceeded { used, cap } => {
                write!(f, "nym quota exceeded: {used}/{cap} per key")
            }
            Self::NymAlreadyAssigned { nym, domain } => {
                write!(f, "key already owns permanent nym: {nym}@{domain}")
            }
            Self::InvalidDescriptor(reason) => write!(f, "invalid descriptor: {reason}"),
            Self::AuthError(reason) => write!(f, "auth error: {reason}"),

            Self::ProofOfFundsRequired { min_sat } => {
                write!(f, "proof of funds required (min {min_sat} sat)")
            }
            Self::ProofOfFundsInvalid(r) => write!(f, "proof of funds invalid: {r}"),
            Self::UtxoNotFound => write!(f, "utxo not found"),
            Self::UtxoSpent => write!(f, "utxo spent"),
            Self::PubkeyUtxoMismatch => write!(f, "pubkey/utxo mismatch"),

            Self::InvalidAmount(reason) => write!(f, "invalid amount: {reason}"),
            Self::InvalidComment(reason) => write!(f, "invalid comment: {reason}"),
            Self::BitcoinAddressAlreadyUsed => write!(f, "bitcoin address already used"),
            Self::LiquidAddressAlreadyUsed => write!(f, "liquid address already used"),
            Self::AliasAlreadyAssigned { alias } => {
                write!(f, "permanent alias already assigned: {alias}")
            }

            Self::RateLimitedSender => write!(f, "rate limited (sender)"),
            Self::RateLimitedRecipient => write!(f, "rate limited (recipient)"),
            Self::RateLimitedNetwork => write!(f, "rate limited (network)"),
            Self::BackendThrottled => write!(f, "backend throttled"),
            Self::TooManyPendingReservations => write!(f, "too many pending reservations"),
            Self::ServiceUnavailable(r) => write!(f, "service unavailable: {r}"),
            Self::MoneyAdmissionUnavailable => write!(f, "money admission unavailable"),
            Self::PurgeBlocked(n) => write!(f, "purge blocked: {n} in-flight swap(s)"),

            Self::ElectrumError(msg) => write!(f, "electrum error: {msg}"),
            Self::BoltzError(msg) => write!(f, "boltz error: {msg}"),
            Self::ClaimError(msg) => write!(f, "claim error: {msg}"),
            Self::DbError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Server-side log (full detail).
        match &self {
            AppError::DbError(msg) => tracing::error!("database error: {msg}"),
            AppError::BoltzError(msg) => tracing::error!("boltz error: {msg}"),
            AppError::ClaimError(msg) => tracing::error!("claim error: {msg}"),
            AppError::ElectrumError(msg) => tracing::error!("electrum error: {msg}"),
            AppError::ProofOfFundsInvalid(msg) => tracing::warn!("proof invalid: {msg}"),
            AppError::ServiceUnavailable(msg) => tracing::error!("service unavailable: {msg}"),
            AppError::MoneyAdmissionUnavailable => {
                tracing::warn!("money admission temporarily unavailable")
            }
            _ => tracing::warn!("{self}"),
        }

        // User-facing copy. Intentionally factual — no apologies, no fake
        // remediation paths, no tone of voice. Direction is included only
        // when there is a real action the user can take.
        let reason: String = match &self {
            AppError::NymNotFound(_) => "No Lightning Address is registered with this name.".into(),
            AppError::NymTaken => "This name is already registered.".into(),
            AppError::NameTaken => "This public name is permanently reserved. Choose a different name.".into(),
            AppError::NymInvalid(_) => "This name contains characters that are not allowed. Names must be 1–32 characters: lowercase letters, numbers, and hyphens, with no leading or trailing hyphen.".into(),
            AppError::NymReserved => "This name is reserved by the server. Choose a different name.".into(),
            AppError::DonationPageInvalid(reason) => format!("Donation page rejected: {reason}."),
            AppError::DonationPageNotFound(_) => "No donation page exists for this name.".into(),
            AppError::InvoiceNotFound(_) => "Invoice not found.".into(),
            AppError::RecoveryAddressInvalid(_) => "This is not a valid Bitcoin address for the correct network. Check the address and try again.".into(),
            AppError::RecoveryNotAvailable(_) => "Automatic Bitcoin recovery is not currently available for this payment.".into(),
            AppError::ImageInvalid(_) => "Image was rejected. Use a JPEG, PNG, or WebP file under 2 MB.".into(),
            AppError::ImageDimensionsTooLarge { max } => format!(
                "Image dimensions are too large. Maximum {max}×{max} pixels."
            ),
            AppError::ImagePixelsTooLarge { max_pixels } => format!(
                "Image dimensions are too large. Maximum {max_pixels} total pixels."
            ),
            AppError::MultipartInvalid(_) => "Upload form was malformed. Retry from the app.".into(),
            AppError::KeyAlreadyRegistered { nym, domain } => format!(
                "This wallet's Lightning Address is already online at {nym}@{domain}. \
                 A wallet cannot claim a second name."
            ),
            AppError::NymQuotaExceeded { cap, .. } => format!(
                "This wallet has reached its lifetime Lightning Address name limit ({cap}). \
                 Permanently owned names cannot be replaced."
            ),
            AppError::NymAlreadyAssigned { nym, domain } => format!(
                "This wallet permanently owns {nym}@{domain}. Register that owned name to bring its Lightning Address online; a wallet cannot claim a second name."
            ),
            AppError::InvalidDescriptor(reason) => format!("The wallet descriptor was rejected: {reason}."),
            AppError::AuthError(_) => "Wallet signature did not verify.".into(),

            AppError::ProofOfFundsRequired { min_sat } => format!(
                "Proof of funds is required. The wallet must hold at least {min_sat} sats in a single UTXO."
            ),
            AppError::ProofOfFundsInvalid(_) => "Proof of funds signature did not verify.".into(),
            AppError::UtxoNotFound => "The UTXO referenced in the proof of funds was not found on the Liquid network. The UTXO may not be confirmed yet.".into(),
            AppError::UtxoSpent => "The UTXO referenced in the proof of funds has already been spent.".into(),
            AppError::PubkeyUtxoMismatch => "The proof-of-funds public key does not match the script of the referenced UTXO.".into(),

            AppError::InvalidAmount(reason) => reason.clone(),
            AppError::InvalidComment(reason) => (*reason).to_string(),
            AppError::BitcoinAddressAlreadyUsed => {
                "This Bitcoin address is already assigned to an invoice. Generate a fresh receive address and try again.".into()
            }
            AppError::LiquidAddressAlreadyUsed => {
                "This Liquid address is already assigned to an invoice. Generate a fresh receive address and try again.".into()
            }
            AppError::AliasAlreadyAssigned { alias } => {
                format!("This wallet permanently owns the link name {alias}.")
            }

            AppError::RateLimitedSender => "Request rate limit exceeded for this source. Retry later.".into(),
            AppError::RateLimitedRecipient => "This Lightning Address has reached its request rate limit on the server. Retry later.".into(),
            AppError::RateLimitedNetwork => "Too many distinct wallets have used this service from this network. Retry later, or switch networks.".into(),
            AppError::BackendThrottled => "Liquid network backend is rate-limited. Retry later.".into(),
            AppError::TooManyPendingReservations => "This Lightning Address has reached the maximum number of unfulfilled payment reservations. Retry once existing reservations complete or expire.".into(),
            AppError::ServiceUnavailable(reason) => {
                if reason.contains("active user ceiling") {
                    "The maximum number of registered users has been reached. New registrations are not being accepted.".into()
                } else {
                    format!("Service temporarily unavailable: {reason}.")
                }
            },
            AppError::MoneyAdmissionUnavailable => {
                "This payment method is temporarily unavailable. Try again later.".into()
            }
            AppError::PurgeBlocked(n) => format!(
                "Deactivation is blocked: {n} payment(s) are still in flight. \
                 These payments must complete or expire first."
            ),

            AppError::ElectrumError(_) => "Blockchain backend is unreachable.".into(),
            AppError::BoltzError(_) => "Lightning swap service is unavailable.".into(),
            AppError::ClaimError(_) => "Swap claim failed.".into(),
            AppError::DbError(_) => "Internal server error.".into(),
        };

        // Structured details for variants that carry data the mobile can use
        // to render a localized template (no need to parse `reason`).
        let details: Option<Value> = match &self {
            AppError::KeyAlreadyRegistered { nym, domain } => {
                Some(json!({"nym": nym, "domain": domain}))
            }
            AppError::NymQuotaExceeded { used, cap } => Some(json!({
                "quota": {
                    "used": used,
                    "cap": cap,
                    "remaining": (cap - used).max(0),
                },
            })),
            AppError::NymAlreadyAssigned { nym, domain } => {
                Some(json!({"nym": nym, "domain": domain}))
            }
            AppError::AliasAlreadyAssigned { alias } => Some(json!({"alias": alias})),
            AppError::PurgeBlocked(n) => Some(json!({"pending_count": n})),
            AppError::ProofOfFundsRequired { min_sat } => Some(json!({"min_sat": min_sat})),
            _ => None,
        };

        // HTTP status. LNURL spec (LUD-06) requires 200 + JSON body for the
        // public LNURL endpoints; we use the same envelope for our custom
        // endpoints for consistency. Auth: 401. Hard ceiling: 503.
        let status = match &self {
            AppError::AuthError(_) => StatusCode::UNAUTHORIZED,
            AppError::NameTaken
            | AppError::NymAlreadyAssigned { .. }
            | AppError::BitcoinAddressAlreadyUsed
            | AppError::LiquidAddressAlreadyUsed
            | AppError::AliasAlreadyAssigned { .. } => StatusCode::CONFLICT,
            AppError::ServiceUnavailable(_) | AppError::MoneyAdmissionUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            _ => StatusCode::OK,
        };

        let mut body = json!({
            "status": "ERROR",
            "code": self.code(),
            "reason": reason,
        });
        if let Some(d) = details {
            body["details"] = d;
        }

        (status, axum::Json(body)).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.constraint() == Some("public_names_shared_namespace_key") {
                return AppError::NameTaken;
            }
            if db_err.constraint() == Some("public_names_owner_kind_lifetime_key") {
                return AppError::NymAlreadyAssigned {
                    nym: String::new(),
                    domain: String::new(),
                };
            }
            // Race-condition catch only: `register_user_atomic` already
            // serializes same-npub registers under an advisory lock, so this
            // branch is unreachable from that path. Defensive only — if
            // any future code path INSERTs into `users` without going through
            // the atomic flow, the wrong-error-code regression we hit (a
            // generic `InternalError`) reproduces. Do NOT delete as dead.
            if db_err.constraint() == Some("users_nym_key") {
                return AppError::NymTaken;
            }
            if db_err.constraint() == Some("users_npub_active_key") {
                // Loser of a concurrent same-npub-active race. We don't
                // have nym/domain at this point; ship empty placeholders so
                // the wire shape stays consistent and the mobile shows the
                // canned copy. Mobile clients of the atomic flow never see
                // this — only future ad-hoc inserters would.
                return AppError::KeyAlreadyRegistered {
                    nym: String::new(),
                    domain: String::new(),
                };
            }
            if db_err.constraint() == Some("invoice_payment_addresses_bitcoin_address_key") {
                return AppError::BitcoinAddressAlreadyUsed;
            }
            if db_err.constraint() == Some("invoice_payment_addresses_liquid_address_key") {
                return AppError::LiquidAddressAlreadyUsed;
            }
            // A second reverse swap tried to persist an already-used Boltz swap
            // id (issue #69). Boltz ids are unique, so this is an integrity
            // incident (retry/concurrency/import defect), never a normal path.
            // Fail closed with a distinctive message; DbError logs at error
            // level in `into_response`, so it is alertable. The caller never
            // reaches BOLT11 exposure because the insert is rejected first.
            if db_err.constraint() == Some("swap_records_boltz_swap_id_key") {
                return AppError::DbError(
                    "reverse swap boltz_swap_id collision (unique violation)".to_string(),
                );
            }
        }
        AppError::DbError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn response_json(error: AppError) -> (StatusCode, Value) {
        let response = error.into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("read error response body");
        let value = serde_json::from_slice(&body).expect("parse error response JSON");
        (status, value)
    }

    #[tokio::test]
    async fn permanent_name_errors_describe_ownership_and_availability() {
        let cases = [
            (
                AppError::KeyAlreadyRegistered {
                    nym: "alice".to_string(),
                    domain: "pay.example.com".to_string(),
                },
                StatusCode::OK,
                "This wallet's Lightning Address is already online at alice@pay.example.com. A wallet cannot claim a second name.",
            ),
            (
                AppError::NymQuotaExceeded { used: 1, cap: 1 },
                StatusCode::OK,
                "This wallet has reached its lifetime Lightning Address name limit (1). Permanently owned names cannot be replaced.",
            ),
            (
                AppError::NymAlreadyAssigned {
                    nym: "alice".to_string(),
                    domain: "pay.example.com".to_string(),
                },
                StatusCode::CONFLICT,
                "This wallet permanently owns alice@pay.example.com. Register that owned name to bring its Lightning Address online; a wallet cannot claim a second name.",
            ),
        ];

        for (error, expected_status, expected_reason) in cases {
            let (status, body) = response_json(error).await;
            assert_eq!(status, expected_status);
            assert_eq!(body["reason"], expected_reason);

            let reason = body["reason"]
                .as_str()
                .expect("error reason must be a string")
                .to_ascii_lowercase();
            for stale_instruction in [
                "reactivat",
                "use a different wallet",
                "deactivate it before registering a different name",
            ] {
                assert!(
                    !reason.contains(stale_instruction),
                    "stale permanent-name instruction leaked: {stale_instruction}"
                );
            }
        }
    }

    #[tokio::test]
    async fn alias_already_assigned_exposes_exact_owned_alias() {
        let response = AppError::AliasAlreadyAssigned {
            alias: "coffee".to_string(),
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("read alias conflict response body");
        let value: Value = serde_json::from_slice(&body).expect("parse alias conflict JSON");

        assert_eq!(value["status"], "ERROR");
        assert_eq!(value["code"], "AliasAlreadyAssigned");
        assert_eq!(value["details"], json!({"alias": "coffee"}));
    }

    #[tokio::test]
    async fn money_admission_response_is_generic_and_retryable() {
        let response = AppError::MoneyAdmissionUnavailable.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("read admission response body");
        let value: Value = serde_json::from_slice(&body).expect("parse admission response JSON");

        assert_eq!(value["status"], "ERROR");
        assert_eq!(value["code"], "ServiceUnavailable");
        assert_eq!(
            value["reason"],
            "This payment method is temporarily unavailable. Try again later."
        );

        let wire = String::from_utf8(body.to_vec()).expect("response is UTF-8");
        for private_term in [
            "claimer",
            "reconciler",
            "workers",
            "schema",
            "journal",
            "fee_policy",
            "recovery_commitment",
        ] {
            assert!(
                !wire.contains(private_term),
                "private admission term leaked: {private_term}"
            );
        }
    }
}

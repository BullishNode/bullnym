use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

#[derive(Debug)]
pub enum AppError {
    // --- Identity / registration ---
    NymNotFound(String),
    /// Name already registered (by anyone).
    NymTaken,
    /// The submitted nym fails the format rules (`internal_reason` is for
    /// logging; the wire copy is fixed).
    NymInvalid(String),
    /// The caller's wallet already has an active address.
    KeyAlreadyRegistered { nym: String, domain: String },
    /// Wallet has registered the cap of lifetime nyms. Carries both `used`
    /// and `cap` so the wire envelope ships the same `quota` object the
    /// mobile receives on lookup.
    NymQuotaExceeded { used: i64, cap: i64 },
    /// CT descriptor was rejected (`internal_reason` is for logging).
    InvalidDescriptor(String),
    /// Generic wallet auth failure (Schnorr sig fail, ts skew, npub parse).
    AuthError(String),

    // --- Liquid LUD-22 / proof of funds ---
    ProofOfFundsRequired { min_sat: u64 },
    ProofOfFundsInvalid(String),
    UtxoNotFound,
    UtxoSpent,
    PubkeyUtxoMismatch,

    // --- Amount validation (LNURL callback) ---
    InvalidAmount(String),

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
            | Self::NymInvalid(_)
            | Self::KeyAlreadyRegistered { .. }
            | Self::NymQuotaExceeded { .. }
            | Self::InvalidDescriptor(_)
            | Self::ProofOfFundsRequired { .. }
            | Self::ProofOfFundsInvalid(_)
            | Self::UtxoNotFound
            | Self::UtxoSpent
            | Self::PubkeyUtxoMismatch
            | Self::InvalidAmount(_) => ErrorClass::Identity,

            Self::RateLimitedSender
            | Self::RateLimitedRecipient
            | Self::RateLimitedNetwork
            | Self::BackendThrottled
            | Self::TooManyPendingReservations => ErrorClass::RateLimit,

            Self::ServiceUnavailable(_) | Self::PurgeBlocked(_) => ErrorClass::Capacity,

            Self::ElectrumError(_) | Self::BoltzError(_) | Self::ClaimError(_) => {
                ErrorClass::Backend
            }

            Self::DbError(_) => ErrorClass::Internal,
        }
    }

    /// Stable enum the mobile uses as i18n key.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NymNotFound(_) => "NymNotFound",
            Self::NymTaken => "NymTaken",
            Self::NymInvalid(_) => "NymInvalid",
            Self::KeyAlreadyRegistered { .. } => "KeyAlreadyRegistered",
            Self::NymQuotaExceeded { .. } => "NymQuotaExceeded",
            Self::InvalidDescriptor(_) => "InvalidDescriptor",
            Self::AuthError(_) => "AuthError",

            Self::ProofOfFundsRequired { .. } => "ProofOfFundsRequired",
            Self::ProofOfFundsInvalid(_) => "ProofOfFundsInvalid",
            Self::UtxoNotFound => "UtxoNotFound",
            Self::UtxoSpent => "UtxoSpent",
            Self::PubkeyUtxoMismatch => "PubkeyUtxoMismatch",

            Self::InvalidAmount(_) => "InvalidAmount",

            Self::RateLimitedSender => "RateLimitedSender",
            Self::RateLimitedRecipient => "RateLimitedRecipient",
            Self::RateLimitedNetwork => "RateLimitedNetwork",
            Self::BackendThrottled => "BackendThrottled",
            Self::TooManyPendingReservations => "TooManyPendingReservations",
            Self::ServiceUnavailable(_) => "ServiceUnavailable",
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
            Self::NymInvalid(reason) => write!(f, "invalid nym: {reason}"),
            Self::KeyAlreadyRegistered { nym, domain } => {
                write!(f, "key already has active address: {nym}@{domain}")
            }
            Self::NymQuotaExceeded { used, cap } => {
                write!(f, "nym quota exceeded: {used}/{cap} per key")
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

            Self::RateLimitedSender => write!(f, "rate limited (sender)"),
            Self::RateLimitedRecipient => write!(f, "rate limited (recipient)"),
            Self::RateLimitedNetwork => write!(f, "rate limited (network)"),
            Self::BackendThrottled => write!(f, "backend throttled"),
            Self::TooManyPendingReservations => write!(f, "too many pending reservations"),
            Self::ServiceUnavailable(r) => write!(f, "service unavailable: {r}"),
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
            _ => tracing::warn!("{self}"),
        }

        // User-facing copy. Intentionally factual — no apologies, no fake
        // remediation paths, no tone of voice. Direction is included only
        // when there is a real action the user can take.
        let reason: String = match &self {
            AppError::NymNotFound(_) => "No Lightning Address is registered with this name.".into(),
            AppError::NymTaken => "This name is already registered.".into(),
            AppError::NymInvalid(_) => "This name contains characters that are not allowed. Names must be 3–32 characters: lowercase letters, numbers, and hyphens, with no leading or trailing hyphen.".into(),
            AppError::KeyAlreadyRegistered { nym, domain } => format!(
                "This wallet already has an active Lightning Address: {nym}@{domain}. \
                 Deactivate it before registering a different name."
            ),
            AppError::NymQuotaExceeded { cap, .. } => format!(
                "This wallet has registered the maximum of {cap} lifetime Lightning Addresses. \
                 Reactivate one of the existing addresses, or use a different wallet."
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

            AppError::RateLimitedSender => "Request rate limit exceeded for this source. Retry later.".into(),
            AppError::RateLimitedRecipient => "This Lightning Address has reached its request rate limit on the server. Retry later.".into(),
            AppError::RateLimitedNetwork => "Too many distinct wallets have used this service from this network. Retry later, or switch networks.".into(),
            AppError::BackendThrottled => "Liquid network backend is rate-limited. Retry later.".into(),
            AppError::TooManyPendingReservations => "This Lightning Address has reached the maximum number of unfulfilled payment reservations. Retry once existing reservations complete or expire.".into(),
            AppError::ServiceUnavailable(_) => "The maximum number of registered users has been reached. New registrations are not being accepted.".into(),
            AppError::PurgeBlocked(n) => format!(
                "Deactivation is blocked: {n} payment(s) are still in flight. \
                 These payments must complete or expire first."
            ),

            AppError::ElectrumError(_) => "Liquid network is unreachable.".into(),
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
            AppError::PurgeBlocked(n) => Some(json!({"pending_count": n})),
            AppError::ProofOfFundsRequired { min_sat } => Some(json!({"min_sat": min_sat})),
            _ => None,
        };

        // HTTP status. LNURL spec (LUD-06) requires 200 + JSON body for the
        // public LNURL endpoints; we use the same envelope for our custom
        // endpoints for consistency. Auth: 401. Hard ceiling: 503.
        let status = match &self {
            AppError::AuthError(_) => StatusCode::UNAUTHORIZED,
            AppError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
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
        }
        AppError::DbError(e.to_string())
    }
}

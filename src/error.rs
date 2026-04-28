use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    // --- Registration / identity ---
    NymNotFound(String),
    NymTaken(String),
    NymInvalid(String),
    InvalidDescriptor(String),
    InvalidAmount(String),
    AuthError(String),
    PurgeBlocked(usize),

    // --- Proof of funds (Liquid callback) ---
    ProofOfFundsRequired(u64),      // carries min_proof_value_sat for message template
    ProofOfFundsInvalid(String),    // sig / format failure (reason is internal, user sees generic copy)
    UtxoNotFound,
    UtxoSpent,
    PubkeyUtxoMismatch,

    // --- Rate limiting ---
    TooManyPendingReservations,
    RateLimited,

    // --- Backend failures ---
    ElectrumError(String),
    BoltzError(String),
    ClaimError(String),
    DbError(String),
}

impl AppError {
    /// Machine-readable code exposed to clients for error discrimination.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NymNotFound(_) => "NymNotFound",
            Self::NymTaken(_) => "NymTaken",
            Self::NymInvalid(_) => "NymInvalid",
            Self::InvalidDescriptor(_) => "InvalidDescriptor",
            Self::InvalidAmount(_) => "InvalidAmount",
            Self::AuthError(_) => "AuthError",
            Self::PurgeBlocked(_) => "PurgeBlocked",
            Self::ProofOfFundsRequired(_) => "ProofOfFundsRequired",
            Self::ProofOfFundsInvalid(_) => "ProofOfFundsInvalid",
            Self::UtxoNotFound => "UtxoNotFound",
            Self::UtxoSpent => "UtxoSpent",
            Self::PubkeyUtxoMismatch => "PubkeyUtxoMismatch",
            Self::TooManyPendingReservations => "TooManyPendingReservations",
            Self::RateLimited => "RateLimited",
            Self::ElectrumError(_) => "ElectrumError",
            Self::BoltzError(_) => "BoltzError",
            Self::ClaimError(_) => "ClaimError",
            Self::DbError(_) => "InternalError",
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NymNotFound(nym) => write!(f, "nym not found: {nym}"),
            Self::NymTaken(nym) => write!(f, "nym already taken: {nym}"),
            Self::NymInvalid(reason) => write!(f, "invalid nym: {reason}"),
            Self::InvalidDescriptor(reason) => write!(f, "invalid descriptor: {reason}"),
            Self::InvalidAmount(reason) => write!(f, "invalid amount: {reason}"),
            Self::AuthError(reason) => write!(f, "auth error: {reason}"),
            Self::PurgeBlocked(n) => write!(f, "purge blocked: {n} in-flight swap(s)"),
            Self::ProofOfFundsRequired(min) => write!(f, "proof of funds required (min {min} sat)"),
            Self::ProofOfFundsInvalid(r) => write!(f, "proof of funds invalid: {r}"),
            Self::UtxoNotFound => write!(f, "utxo not found"),
            Self::UtxoSpent => write!(f, "utxo spent"),
            Self::PubkeyUtxoMismatch => write!(f, "pubkey/utxo mismatch"),
            Self::TooManyPendingReservations => write!(f, "too many pending reservations"),
            Self::RateLimited => write!(f, "rate limited"),
            Self::ElectrumError(msg) => write!(f, "electrum error: {msg}"),
            Self::BoltzError(msg) => write!(f, "swap service error: {msg}"),
            Self::ClaimError(msg) => write!(f, "claim error: {msg}"),
            Self::DbError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Log full details server-side only.
        match &self {
            AppError::DbError(msg) => tracing::error!("database error: {msg}"),
            AppError::BoltzError(msg) => tracing::error!("boltz error: {msg}"),
            AppError::ClaimError(msg) => tracing::error!("claim error: {msg}"),
            AppError::ElectrumError(msg) => tracing::error!("electrum error: {msg}"),
            AppError::ProofOfFundsInvalid(msg) => tracing::warn!("proof invalid: {msg}"),
            _ => tracing::warn!("{self}"),
        }

        // User-facing copy. Must be safe to show to arbitrary payers.
        let reason: String = match &self {
            AppError::NymNotFound(_) => "Lightning address not found".into(),
            AppError::NymTaken(_) => "This name is already taken".into(),
            AppError::NymInvalid(r) => r.clone(),
            AppError::InvalidDescriptor(_) => "Invalid wallet descriptor".into(),
            AppError::InvalidAmount(r) => r.clone(),
            AppError::AuthError(r) => r.clone(),
            AppError::PurgeBlocked(n) => format!(
                "Cannot purge while {n} swap(s) are still in flight. \
                 Wait for them to settle or expire, then try again."
            ),
            AppError::ProofOfFundsRequired(min) => format!(
                "To request payment details from this Lightning Address, \
                 you must have at least {min} sats in your wallet."
            ),
            AppError::ProofOfFundsInvalid(_) => {
                "Your wallet could not prove it has enough funds. Please \
                 restart your wallet and try again.".into()
            }
            AppError::UtxoNotFound => {
                "The funds your wallet tried to use aren't yet visible on \
                 the Liquid network. Please wait a moment for them to \
                 confirm, then try again.".into()
            }
            AppError::UtxoSpent => {
                "The funds your wallet tried to use have already been spent \
                 in another transaction.".into()
            }
            AppError::PubkeyUtxoMismatch => {
                "Your wallet provided funds that don't match its signature. \
                 This is likely a wallet bug — please report it.".into()
            }
            AppError::TooManyPendingReservations => {
                "This recipient has too many payments waiting. Please try \
                 again in a few minutes.".into()
            }
            AppError::RateLimited => {
                "You've made too many requests to this Lightning Address. \
                 Please wait and try again.".into()
            }
            AppError::ElectrumError(_) => "Liquid network temporarily unavailable".into(),
            AppError::BoltzError(_) => "Payment service temporarily unavailable".into(),
            AppError::ClaimError(_) => "Claim service temporarily unavailable".into(),
            AppError::DbError(_) => "Internal server error".into(),
        };

        // Auth errors: standard HTTP 401. Everything else: HTTP 200 + LNURL body.
        let status = match &self {
            AppError::AuthError(_) => StatusCode::UNAUTHORIZED,
            _ => StatusCode::OK,
        };

        let body = json!({
            "status": "ERROR",
            "code": self.code(),
            "reason": reason,
        });

        (status, axum::Json(body)).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.constraint() == Some("users_nym_key") {
                return AppError::NymTaken("name already registered".to_string());
            }
            if db_err.constraint() == Some("users_npub_key") {
                return AppError::AuthError("this key is already registered".to_string());
            }
        }
        AppError::DbError(e.to_string())
    }
}

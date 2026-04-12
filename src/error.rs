use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    NymNotFound(String),
    NymTaken(String),
    NymInvalid(String),
    InvalidDescriptor(String),
    InvalidAmount(String),
    AuthError(String),
    BoltzError(String),
    ClaimError(String),
    DbError(String),
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
            Self::BoltzError(msg) => write!(f, "swap service error: {msg}"),
            Self::ClaimError(msg) => write!(f, "claim error: {msg}"),
            Self::DbError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Log full details server-side only
        match &self {
            AppError::DbError(msg) => tracing::error!("database error: {msg}"),
            AppError::BoltzError(msg) => tracing::error!("boltz error: {msg}"),
            AppError::ClaimError(msg) => tracing::error!("claim error: {msg}"),
            _ => tracing::warn!("{self}"),
        }

        // Sanitized user-facing message — no internal details
        let reason = match &self {
            AppError::NymNotFound(_) => "Lightning address not found",
            AppError::NymTaken(_) => "This name is already taken",
            AppError::NymInvalid(r) => r.as_str(),
            AppError::InvalidDescriptor(_) => "Invalid wallet descriptor",
            AppError::InvalidAmount(r) => r.as_str(),
            AppError::AuthError(_) => "Authentication failed",
            AppError::BoltzError(_) => "Payment service temporarily unavailable",
            AppError::ClaimError(_) => "Claim service temporarily unavailable",
            AppError::DbError(_) => "Internal server error",
        };

        // Non-auth errors use LNURL format (HTTP 200 + status/reason).
        // Auth errors use standard HTTP 401.
        let status = match &self {
            AppError::AuthError(_) => StatusCode::UNAUTHORIZED,
            _ => StatusCode::OK,
        };

        let body = json!({
            "status": "ERROR",
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


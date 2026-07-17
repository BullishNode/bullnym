//! Opaque current-object storage for seed-derived wallet backup streams.

use std::fmt;
use std::net::SocketAddr;
use std::time::Instant;

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth;
use crate::db::{self, WalletBackupMutationOutcome};
use crate::error::AppError;
use crate::ip_whitelist;
use crate::AppState;

pub const BACKUP_PROTOCOL_VERSION: u8 = 1;
pub const BACKUP_AUTH_DOMAIN: &[u8] = b"bullbitcoin-wallet-backup-v1";
pub const BACKUP_ETAG_DOMAIN: &[u8] = b"bullbitcoin-wallet-backup-etag-v1";
pub const MAX_CIPHERTEXT_BYTES: usize = 2 * 1024 * 1024;
pub const STORE_BODY_LIMIT_BYTES: usize = 3 * 1024 * 1024;
const SMALL_BODY_LIMIT_BYTES: usize = 8 * 1024;
pub const TOMBSTONE_RETENTION_SECS: i32 = 600;

const FETCH_ACTION: &str = "backup-fetch";
const STORE_ACTION: &str = "backup-store";
const DELETE_ACTION: &str = "backup-delete";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupStream {
    KeychainManifest,
    WalletMetadata,
}

impl BackupStream {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeychainManifest => "keychain_manifest",
            Self::WalletMetadata => "wallet_metadata",
        }
    }
}

impl fmt::Display for BackupStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchRequest {
    version: u8,
    stream: BackupStream,
    npub: String,
    timestamp: u64,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRequest {
    version: u8,
    stream: BackupStream,
    npub: String,
    generation: u64,
    expected_etag: RequiredNullableString,
    ciphertext: String,
    ciphertext_sha256: String,
    ciphertext_bytes: u64,
    timestamp: u64,
    signature: String,
}

struct RequiredNullableString(Option<String>);

impl<'de> Deserialize<'de> for RequiredNullableString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NullableStringVisitor;

        impl serde::de::Visitor<'_> for NullableStringVisitor {
            type Value = RequiredNullableString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string or null")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(None))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(None))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(Some(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(Some(value)))
            }
        }

        deserializer.deserialize_any(NullableStringVisitor)
    }
}

impl RequiredNullableString {
    fn as_deref(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteRequest {
    version: u8,
    stream: BackupStream,
    npub: String,
    generation: u64,
    expected_etag: String,
    timestamp: u64,
    signature: String,
}

#[derive(Serialize)]
pub struct FetchResponse {
    version: u8,
    found: bool,
    generation: u64,
    etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<i64>,
}

#[derive(Serialize)]
pub struct MutationResponse {
    version: u8,
    generation: u64,
    etag: String,
}

#[derive(Debug)]
pub enum WalletBackupError {
    InvalidRequest(&'static str),
    Authentication,
    HeadConflict,
    BlobTooLarge,
    RateLimited,
    Capacity,
    Internal,
}

impl WalletBackupError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "BackupInvalidRequest",
            Self::Authentication => "BackupAuthError",
            Self::HeadConflict => "BackupHeadConflict",
            Self::BlobTooLarge => "BackupBlobTooLarge",
            Self::RateLimited => "RateLimited",
            Self::Capacity => "BackupCapacityExceeded",
            Self::Internal => "InternalError",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::Authentication => StatusCode::UNAUTHORIZED,
            Self::HeadConflict => StatusCode::CONFLICT,
            Self::BlobTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Capacity => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for WalletBackupError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        let reason = match self {
            Self::InvalidRequest(reason) => reason,
            Self::Authentication => "Wallet backup signature did not verify.",
            Self::HeadConflict => "Wallet backup changed. Fetch the current head and retry.",
            Self::BlobTooLarge => "Wallet backup exceeds the maximum object size.",
            Self::RateLimited => "Wallet backup request rate limit exceeded. Retry later.",
            Self::Capacity => "Wallet backup storage is temporarily at capacity.",
            Self::Internal => "Internal server error.",
        };
        tracing::warn!(
            event = "wallet_backup_request_failed",
            code,
            status = status.as_u16(),
            "wallet backup request rejected"
        );
        private_no_store(
            (
                status,
                Json(json!({
                    "status": "ERROR",
                    "code": code,
                    "reason": reason,
                })),
            )
                .into_response(),
        )
    }
}

impl From<AppError> for WalletBackupError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::RateLimitedSender
            | AppError::RateLimitedRecipient
            | AppError::RateLimitedNetwork => Self::RateLimited,
            AppError::AuthError(_) => Self::Authentication,
            other => {
                tracing::error!(
                    event = "wallet_backup_internal_error",
                    error_class = ?other.class(),
                    "wallet backup operation failed"
                );
                Self::Internal
            }
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/wallet-backups/fetch",
            post(fetch).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/v1/wallet-backups",
            put(store).layer(DefaultBodyLimit::max(STORE_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/v1/wallet-backups",
            delete(delete_backup).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT_BYTES)),
        )
}

async fn json_request<T>(request: Request, state: &AppState) -> Result<T, WalletBackupError>
where
    T: serde::de::DeserializeOwned,
{
    match Json::<T>::from_request(request, state).await {
        Ok(Json(request)) => Ok(request),
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            Err(WalletBackupError::BlobTooLarge)
        }
        Err(_) => Err(WalletBackupError::InvalidRequest(
            "Wallet backup request body is invalid.",
        )),
    }
}

fn validate_version(version: u8) -> Result<(), WalletBackupError> {
    if version == BACKUP_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(WalletBackupError::InvalidRequest(
            "Unsupported wallet backup protocol version.",
        ))
    }
}

fn decode_canonical_hex<const N: usize>(
    value: &str,
    reason: &'static str,
) -> Result<[u8; N], WalletBackupError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WalletBackupError::InvalidRequest(reason));
    }
    let decoded = hex::decode(value).map_err(|_| WalletBackupError::InvalidRequest(reason))?;
    decoded
        .try_into()
        .map_err(|_| WalletBackupError::InvalidRequest(reason))
}

fn validate_signature(signature: &str) -> Result<(), WalletBackupError> {
    decode_canonical_hex::<64>(signature, "Wallet backup signature is invalid.").map(|_| ())
}

fn validate_generation(generation: u64) -> Result<i64, WalletBackupError> {
    if generation == 0 {
        return Err(WalletBackupError::InvalidRequest(
            "Wallet backup generation must be positive.",
        ));
    }
    i64::try_from(generation)
        .map_err(|_| WalletBackupError::InvalidRequest("Wallet backup generation is out of range."))
}

#[allow(clippy::too_many_arguments)]
pub fn build_signing_message(
    action: &str,
    stream: BackupStream,
    npub: &str,
    generation: u64,
    expected_etag: Option<&str>,
    ciphertext_sha256: Option<&str>,
    ciphertext_bytes: u64,
    timestamp: u64,
) -> Vec<u8> {
    let generation = generation.to_string();
    let ciphertext_bytes = ciphertext_bytes.to_string();
    let timestamp = timestamp.to_string();
    let fields = [
        action,
        stream.as_str(),
        npub,
        generation.as_str(),
        expected_etag.unwrap_or(""),
        ciphertext_sha256.unwrap_or(""),
        ciphertext_bytes.as_str(),
        timestamp.as_str(),
    ];
    let capacity =
        BACKUP_AUTH_DOMAIN.len() + fields.iter().map(|field| field.len() + 1).sum::<usize>();
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(BACKUP_AUTH_DOMAIN);
    for field in fields {
        message.push(0);
        message.extend_from_slice(field.as_bytes());
    }
    message
}

pub fn compute_etag(
    stream: BackupStream,
    npub: &str,
    generation: u64,
    ciphertext_sha256: Option<&str>,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(BACKUP_ETAG_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(stream.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(npub.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(generation.to_string().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(ciphertext_sha256.unwrap_or("").as_bytes());
    Sha256::digest(bytes).into()
}

#[allow(clippy::too_many_arguments)]
fn verify_request_signature(
    action: &str,
    stream: BackupStream,
    npub: &str,
    generation: u64,
    expected_etag: Option<&str>,
    ciphertext_sha256: Option<&str>,
    ciphertext_bytes: u64,
    timestamp: u64,
    signature: &str,
) -> Result<(), WalletBackupError> {
    validate_signature(signature)?;
    auth::check_ts_freshness(timestamp).map_err(|_| WalletBackupError::Authentication)?;
    let message = build_signing_message(
        action,
        stream,
        npub,
        generation,
        expected_etag,
        ciphertext_sha256,
        ciphertext_bytes,
        timestamp,
    );
    auth::verify_signature(npub, &message, signature).map_err(|_| WalletBackupError::Authentication)
}

async fn source_gate(
    state: &AppState,
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<(Option<std::net::IpAddr>, bool), WalletBackupError> {
    let ip = ip_whitelist::caller_ip(peer, headers, state.config.rate_limit.trust_forwarded_for);
    let whitelisted = ip
        .map(|source| state.ip_whitelist.contains(source))
        .unwrap_or(false);
    if !whitelisted {
        if let Some(source) = ip {
            if mutation {
                state
                    .rate_limiter
                    .check_wallet_backup_mutation_per_ip(source)
                    .await?;
            } else {
                state
                    .rate_limiter
                    .check_wallet_backup_fetch_per_ip(source)
                    .await?;
            }
        }
    }
    Ok((ip, whitelisted))
}

fn record_success(
    action: &'static str,
    stream: BackupStream,
    started: Instant,
    ciphertext_bytes: usize,
    outcome: &'static str,
) {
    let size_bucket = match ciphertext_bytes {
        0 => "none",
        1..=65_536 => "up_to_64k",
        65_537..=524_288 => "64k_to_512k",
        524_289..=1_048_576 => "512k_to_1m",
        _ => "1m_to_2m",
    };
    tracing::info!(
        event = "wallet_backup_request",
        action,
        stream = stream.as_str(),
        status = 200,
        outcome,
        latency_ms = started.elapsed().as_millis() as u64,
        size_bucket,
        "wallet backup request completed"
    );
}

fn private_no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

pub async fn fetch(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, WalletBackupError> {
    let started = Instant::now();
    let _ = source_gate(
        &state,
        peer.map(|ConnectInfo(address)| address),
        &headers,
        false,
    )
    .await?;
    let request: FetchRequest = json_request(request, &state).await?;
    validate_version(request.version)?;
    let author = decode_canonical_hex::<32>(
        &request.npub,
        "Wallet backup public key must be 64 lowercase hexadecimal characters.",
    )?;
    verify_request_signature(
        FETCH_ACTION,
        request.stream,
        &request.npub,
        0,
        None,
        None,
        0,
        request.timestamp,
        &request.signature,
    )?;

    let head = db::fetch_wallet_backup_head(&state.db, request.stream.as_str(), &author).await?;
    let response = match head {
        None => FetchResponse {
            version: BACKUP_PROTOCOL_VERSION,
            found: false,
            generation: 0,
            etag: None,
            ciphertext: None,
            ciphertext_sha256: None,
            ciphertext_bytes: None,
            updated_at: None,
        },
        Some(head) if head.is_tombstone() => FetchResponse {
            version: BACKUP_PROTOCOL_VERSION,
            found: false,
            generation: u64::try_from(head.generation).map_err(|_| WalletBackupError::Internal)?,
            etag: Some(hex::encode(head.etag())),
            ciphertext: None,
            ciphertext_sha256: None,
            ciphertext_bytes: None,
            updated_at: Some(head.updated_at_unix),
        },
        Some(head) => FetchResponse {
            version: BACKUP_PROTOCOL_VERSION,
            found: true,
            generation: u64::try_from(head.generation).map_err(|_| WalletBackupError::Internal)?,
            etag: Some(hex::encode(head.etag())),
            ciphertext: Some(
                BASE64_STANDARD.encode(head.ciphertext().ok_or(WalletBackupError::Internal)?),
            ),
            ciphertext_sha256: Some(hex::encode(
                head.ciphertext_sha256()
                    .ok_or(WalletBackupError::Internal)?,
            )),
            ciphertext_bytes: Some(
                u64::try_from(head.ciphertext_bytes.ok_or(WalletBackupError::Internal)?)
                    .map_err(|_| WalletBackupError::Internal)?,
            ),
            updated_at: Some(head.updated_at_unix),
        },
    };
    let ciphertext_bytes = response.ciphertext_bytes.unwrap_or(0) as usize;
    let outcome = if response.found {
        "live"
    } else if response.generation > 0 {
        "tombstone"
    } else {
        "absent"
    };
    record_success(
        FETCH_ACTION,
        request.stream,
        started,
        ciphertext_bytes,
        outcome,
    );
    Ok(private_no_store(Json(response).into_response()))
}

pub async fn store(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, WalletBackupError> {
    let started = Instant::now();
    let (source, whitelisted) = source_gate(
        &state,
        peer.map(|ConnectInfo(address)| address),
        &headers,
        true,
    )
    .await?;
    let request: StoreRequest = json_request(request, &state).await?;
    validate_version(request.version)?;
    let generation = validate_generation(request.generation)?;
    let author = decode_canonical_hex::<32>(
        &request.npub,
        "Wallet backup public key must be 64 lowercase hexadecimal characters.",
    )?;
    let expected_etag = request
        .expected_etag
        .as_deref()
        .map(|etag| decode_canonical_hex::<32>(etag, "Wallet backup ETag is invalid."))
        .transpose()?;
    let declared_hash = decode_canonical_hex::<32>(
        &request.ciphertext_sha256,
        "Wallet backup ciphertext hash is invalid.",
    )?;
    if request.ciphertext_bytes > MAX_CIPHERTEXT_BYTES as u64 {
        return Err(WalletBackupError::BlobTooLarge);
    }
    verify_request_signature(
        STORE_ACTION,
        request.stream,
        &request.npub,
        request.generation,
        request.expected_etag.as_deref(),
        Some(&request.ciphertext_sha256),
        request.ciphertext_bytes,
        request.timestamp,
        &request.signature,
    )?;
    let ciphertext = BASE64_STANDARD.decode(&request.ciphertext).map_err(|_| {
        WalletBackupError::InvalidRequest("Wallet backup ciphertext is not base64.")
    })?;
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(WalletBackupError::BlobTooLarge);
    }
    if BASE64_STANDARD.encode(&ciphertext) != request.ciphertext {
        return Err(WalletBackupError::InvalidRequest(
            "Wallet backup ciphertext base64 is not canonical.",
        ));
    }
    if request.ciphertext_bytes != ciphertext.len() as u64 {
        return Err(WalletBackupError::InvalidRequest(
            "Wallet backup ciphertext byte count does not match.",
        ));
    }
    if Sha256::digest(&ciphertext).as_slice() != declared_hash {
        return Err(WalletBackupError::InvalidRequest(
            "Wallet backup ciphertext hash does not match.",
        ));
    }
    if !whitelisted {
        state
            .rate_limiter
            .check_wallet_backup_mutation_per_key(&request.npub)
            .await?;
        if let Some(source) = source {
            state
                .rate_limiter
                .check_wallet_backup_distinct_keys_per_ip(source, &request.npub)
                .await?;
        }
    }

    let etag = compute_etag(
        request.stream,
        &request.npub,
        request.generation,
        Some(&request.ciphertext_sha256),
    );
    let outcome = db::store_wallet_backup(
        &state.db,
        request.stream.as_str(),
        &author,
        generation,
        expected_etag.as_ref().map(|etag| etag.as_slice()),
        &etag,
        &ciphertext,
        &declared_hash,
        state.config.rate_limit.wallet_backup_global_stored_bytes,
    )
    .await?;
    let outcome_label = match outcome {
        WalletBackupMutationOutcome::Applied => "stored",
        WalletBackupMutationOutcome::ExactRetry => "exact_retry",
        WalletBackupMutationOutcome::HeadConflict => return Err(WalletBackupError::HeadConflict),
        WalletBackupMutationOutcome::GlobalCapacityExceeded => {
            return Err(WalletBackupError::Capacity)
        }
    };
    record_success(
        STORE_ACTION,
        request.stream,
        started,
        ciphertext.len(),
        outcome_label,
    );
    Ok(private_no_store(
        Json(MutationResponse {
            version: BACKUP_PROTOCOL_VERSION,
            generation: request.generation,
            etag: hex::encode(etag),
        })
        .into_response(),
    ))
}

pub async fn delete_backup(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, WalletBackupError> {
    let started = Instant::now();
    let (source, whitelisted) = source_gate(
        &state,
        peer.map(|ConnectInfo(address)| address),
        &headers,
        true,
    )
    .await?;
    let request: DeleteRequest = json_request(request, &state).await?;
    validate_version(request.version)?;
    let generation = validate_generation(request.generation)?;
    let author = decode_canonical_hex::<32>(
        &request.npub,
        "Wallet backup public key must be 64 lowercase hexadecimal characters.",
    )?;
    let expected_etag =
        decode_canonical_hex::<32>(&request.expected_etag, "Wallet backup ETag is invalid.")?;
    verify_request_signature(
        DELETE_ACTION,
        request.stream,
        &request.npub,
        request.generation,
        Some(&request.expected_etag),
        None,
        0,
        request.timestamp,
        &request.signature,
    )?;
    if !whitelisted {
        state
            .rate_limiter
            .check_wallet_backup_mutation_per_key(&request.npub)
            .await?;
        if let Some(source) = source {
            state
                .rate_limiter
                .check_wallet_backup_distinct_keys_per_ip(source, &request.npub)
                .await?;
        }
    }

    let tombstone_etag = compute_etag(request.stream, &request.npub, request.generation, None);
    let outcome = db::delete_wallet_backup(
        &state.db,
        request.stream.as_str(),
        &author,
        generation,
        &expected_etag,
        &tombstone_etag,
    )
    .await?;
    let outcome_label = match outcome {
        WalletBackupMutationOutcome::Applied => "deleted",
        WalletBackupMutationOutcome::ExactRetry => "exact_retry",
        WalletBackupMutationOutcome::HeadConflict => return Err(WalletBackupError::HeadConflict),
        WalletBackupMutationOutcome::GlobalCapacityExceeded => {
            return Err(WalletBackupError::Internal)
        }
    };
    record_success(DELETE_ACTION, request.stream, started, 0, outcome_label);
    Ok(private_no_store(
        Json(MutationResponse {
            version: BACKUP_PROTOCOL_VERSION,
            generation: request.generation,
            etag: hex::encode(tombstone_etag),
        })
        .into_response(),
    ))
}

#[cfg(test)]
mod tests;

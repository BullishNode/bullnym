//! Merchant-signed fiat-settlement configuration API.
//!
//! The API key is accepted only on a signed write and is immediately wrapped,
//! encrypted, and dropped. No response type contains a key or a provider
//! payment instruction.

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use uuid::Uuid;

use crate::auth;
use crate::bull_bitcoin::{
    CredentialCipher, FiatCurrency, Product, ScopedApiKey, COMMON_DISCLOSURE, TERMS_REFERENCE,
    TERMS_VERSION,
};
use crate::db::{self, CredentialLifecycle, FiatSettlementStoreError, NewEncryptedCredential};
use crate::error::AppError;
use crate::registration;
use crate::AppState;

pub const CONTRACT_VERSION: u16 = 1;
pub const BODY_LIMIT_BYTES: usize = 2_048;

pub const ACTION_SET: &str = "fiat-settlement-set";
pub const ACTION_DELETE_PRODUCT: &str = "fiat-settlement-delete";
pub const ACTION_GET: &str = "fiat-settlement-get";
pub const ACTION_DELETE_CREDENTIAL: &str = "bull-bitcoin-credential-delete";

const VERSION_FIELD: &str = "1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrencyDisclosure {
    pub currency: FiatCurrency,
    pub disclosure: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FiatSettlementOptionsResponse {
    pub version: u16,
    pub terms_version: &'static str,
    pub terms_reference: &'static str,
    pub common_disclosure: &'static str,
    pub currencies: Vec<CurrencyDisclosure>,
}

pub async fn options() -> Json<FiatSettlementOptionsResponse> {
    Json(FiatSettlementOptionsResponse {
        version: CONTRACT_VERSION,
        terms_version: TERMS_VERSION,
        terms_reference: TERMS_REFERENCE,
        common_disclosure: COMMON_DISCLOSURE,
        currencies: FiatCurrency::ALL
            .into_iter()
            .map(|currency| CurrencyDisclosure {
                currency,
                disclosure: currency.disclosure(),
            })
            .collect(),
    })
}

/// Intentionally has no `Debug`: `api_key` is a bearer secret.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetRequest {
    pub version: u16,
    pub npub: String,
    pub fiat_percentage: u8,
    pub fiat_currency: Option<FiatCurrency>,
    pub terms_version: Option<String>,
    pub api_key: Option<String>,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteProductRequest {
    pub version: u16,
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationQuery {
    pub version: u16,
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteCredentialRequest {
    pub version: u16,
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SettingResponse {
    pub product: Product,
    pub fiat_percentage: u8,
    pub fiat_currency: FiatCurrency,
    pub terms_version: String,
    pub terms_accepted_at_unix: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Absent,
    Active,
    DeletionPending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationResponse {
    pub version: u16,
    pub settings: Vec<SettingResponse>,
    pub credential_status: CredentialStatus,
}

pub async fn set(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(product): Path<String>,
    Json(request): Json<SetRequest>,
) -> Result<Response, AppError> {
    gate(&state, peer_opt, &headers, "fiat_settlement_set").await?;
    let product = Product::from_str(&product)
        .map_err(|_| AppError::InvalidAmount("Unsupported settlement product.".into()))?;
    let verified = verify_set_request(product, request)?;

    if verified.percentage == 0 {
        let result = db::delete_fiat_settlement_setting(&state.db, verified.npub(), product)
            .await
            .map_err(map_store_error)?;
        return configuration_response(result);
    }

    if !state.config.features.bull_bitcoin_fiat_settlement {
        return Err(AppError::ServiceUnavailable(
            "fiat settlement is not accepting new settings".into(),
        ));
    }
    let currency = verified
        .currency
        .ok_or_else(|| AppError::InvalidAmount("A fiat currency is required.".into()))?;

    let encrypted = match verified.api_key {
        Some(ref api_key) => {
            let key = state
                .config
                .bull_bitcoin_credential_encryption_key
                .clone()
                .ok_or_else(|| {
                    AppError::ServiceUnavailable(
                        "fiat settlement credential encryption is unavailable".into(),
                    )
                })?;
            let id = Uuid::new_v4();
            let encrypted = CredentialCipher::new(key)
                .encrypt(id, verified.npub(), &api_key)
                .map_err(|_| {
                    AppError::DbError("Bull Bitcoin credential encryption failed".into())
                })?;
            Some(NewEncryptedCredential { id, encrypted })
        }
        None => None,
    };

    let result = db::upsert_fiat_settlement_setting(
        &state.db,
        verified.npub(),
        product,
        i16::from(verified.percentage),
        currency,
        verified.signed_at_unix,
        encrypted,
    )
    .await
    .map_err(map_store_error)?;
    configuration_response(result)
}

pub async fn delete_product(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(product): Path<String>,
    Json(request): Json<DeleteProductRequest>,
) -> Result<Response, AppError> {
    gate(&state, peer_opt, &headers, "fiat_settlement_delete_product").await?;
    let product = Product::from_str(&product)
        .map_err(|_| AppError::InvalidAmount("Unsupported settlement product.".into()))?;
    verify_identity_request(
        ACTION_DELETE_PRODUCT,
        request.version,
        &request.npub,
        &[VERSION_FIELD, product.as_str()],
        request.timestamp,
        &request.signature,
    )?;
    let result = db::delete_fiat_settlement_setting(&state.db, &request.npub, product)
        .await
        .map_err(map_store_error)?;
    configuration_response(result)
}

pub async fn configuration(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(query): Query<ConfigurationQuery>,
) -> Result<Response, AppError> {
    gate(&state, peer_opt, &headers, "fiat_settlement_configuration").await?;
    verify_identity_request(
        ACTION_GET,
        query.version,
        &query.npub,
        &[VERSION_FIELD],
        query.timestamp,
        &query.signature,
    )?;
    let result = db::select_fiat_settlement_configuration(&state.db, &query.npub)
        .await
        .map_err(map_store_error)?;
    configuration_response(result)
}

pub async fn delete_credential(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(request): Json<DeleteCredentialRequest>,
) -> Result<Response, AppError> {
    gate(
        &state,
        peer_opt,
        &headers,
        "fiat_settlement_delete_credential",
    )
    .await?;
    verify_identity_request(
        ACTION_DELETE_CREDENTIAL,
        request.version,
        &request.npub,
        &[VERSION_FIELD],
        request.timestamp,
        &request.signature,
    )?;
    let result = db::request_bull_bitcoin_credential_deletion(&state.db, &request.npub)
        .await
        .map_err(map_store_error)?;
    configuration_response(result)
}

struct VerifiedSetRequest {
    npub: String,
    percentage: u8,
    currency: Option<FiatCurrency>,
    api_key: Option<ScopedApiKey>,
    signed_at_unix: i64,
}

impl VerifiedSetRequest {
    fn npub(&self) -> &str {
        &self.npub
    }
}

fn verify_set_request(
    product: Product,
    request: SetRequest,
) -> Result<VerifiedSetRequest, AppError> {
    if request.version != CONTRACT_VERSION || request.fiat_percentage > 100 {
        return Err(AppError::InvalidAmount(
            "Unsupported fiat-settlement configuration.".into(),
        ));
    }
    validate_canonical_npub(&request.npub)?;

    let api_key = match request.api_key {
        Some(value) => Some(
            ScopedApiKey::parse(value)
                .map_err(|_| AppError::InvalidAmount("Invalid scoped API key.".into()))?,
        ),
        None => None,
    };
    let currency_field = request
        .fiat_currency
        .map(FiatCurrency::as_str)
        .unwrap_or("");
    let terms_field = request.terms_version.as_deref().unwrap_or("");
    reject_nul("terms_version", terms_field)?;

    if request.fiat_percentage == 0 {
        if request.fiat_currency.is_some() || request.terms_version.is_some() || api_key.is_some() {
            return Err(AppError::InvalidAmount(
                "Bitcoin-only configuration must omit fiat fields and API key.".into(),
            ));
        }
    } else if request.fiat_currency.is_none() || terms_field != TERMS_VERSION {
        return Err(AppError::InvalidAmount(
            "The current terms and one supported fiat currency are required.".into(),
        ));
    }

    let percentage_field = request.fiat_percentage.to_string();
    let key_field = api_key.as_ref().map(ScopedApiKey::expose).unwrap_or("");
    auth::verify_la_v2(
        ACTION_SET,
        &request.npub,
        "",
        &[
            VERSION_FIELD,
            product.as_str(),
            &percentage_field,
            currency_field,
            terms_field,
            key_field,
        ],
        request.timestamp,
        &request.signature,
    )?;

    let signed_at_unix = i64::try_from(request.timestamp)
        .map_err(|_| AppError::AuthError("fiat-settlement timestamp is out of range".into()))?;
    Ok(VerifiedSetRequest {
        npub: request.npub,
        percentage: request.fiat_percentage,
        currency: request.fiat_currency,
        api_key,
        signed_at_unix,
    })
}

fn verify_identity_request(
    action: &str,
    version: u16,
    npub: &str,
    fields: &[&str],
    timestamp: u64,
    signature: &str,
) -> Result<(), AppError> {
    if version != CONTRACT_VERSION {
        return Err(AppError::AuthError(
            "unsupported fiat-settlement contract version".into(),
        ));
    }
    validate_canonical_npub(npub)?;
    auth::verify_la_v2(action, npub, "", fields, timestamp, signature)
}

fn validate_canonical_npub(npub: &str) -> Result<(), AppError> {
    reject_nul("npub", npub)?;
    let parsed = XOnlyPublicKey::from_str(npub)
        .map_err(|_| AppError::AuthError("invalid fiat-settlement npub".into()))?;
    if parsed.to_string() != npub {
        return Err(AppError::AuthError(
            "fiat-settlement npub must be canonical lowercase hex".into(),
        ));
    }
    Ok(())
}

fn reject_nul(field: &str, value: &str) -> Result<(), AppError> {
    if value.as_bytes().contains(&0) {
        return Err(AppError::AuthError(format!(
            "fiat-settlement {field} contains a NUL separator"
        )));
    }
    Ok(())
}

async fn gate(
    state: &AppState,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    endpoint: &'static str,
) -> Result<(), AppError> {
    registration::gate_registration_setup_per_ip(
        state,
        peer_opt.map(|ConnectInfo(address)| address),
        headers,
        endpoint,
    )
    .await
    .map(|_| ())
}

fn map_store_error(error: FiatSettlementStoreError) -> AppError {
    match error {
        FiatSettlementStoreError::SourceIdentityNotActive => {
            AppError::AuthError("fiat-settlement identity is unavailable".into())
        }
        FiatSettlementStoreError::CredentialRequired => AppError::InvalidAmount(
            "Import the scoped Bull Bitcoin API key before enabling fiat settlement.".into(),
        ),
        FiatSettlementStoreError::CredentialDraining => AppError::ServiceUnavailable(
            "the previous scoped credential still supervises a settlement".into(),
        ),
        FiatSettlementStoreError::Sqlx(_) => {
            AppError::DbError("fiat-settlement persistence failed".into())
        }
    }
}

fn configuration_response(
    configuration: db::FiatSettlementConfiguration,
) -> Result<Response, AppError> {
    let settings = configuration
        .settings
        .into_iter()
        .map(|row| {
            let product = Product::from_str(&row.product)
                .map_err(|_| AppError::DbError("invalid stored settlement product".into()))?;
            let fiat_currency = FiatCurrency::from_str(&row.fiat_currency)
                .map_err(|_| AppError::DbError("invalid stored fiat currency".into()))?;
            let fiat_percentage = u8::try_from(row.fiat_percentage)
                .map_err(|_| AppError::DbError("invalid stored fiat percentage".into()))?;
            Ok(SettingResponse {
                product,
                fiat_percentage,
                fiat_currency,
                terms_version: row.terms_version,
                terms_accepted_at_unix: row.terms_accepted_at_unix,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let credential_status = match configuration.credential {
        CredentialLifecycle::Absent => CredentialStatus::Absent,
        CredentialLifecycle::Active => CredentialStatus::Active,
        CredentialLifecycle::DeletionPending => CredentialStatus::DeletionPending,
    };
    Ok(private_no_store(
        Json(ConfigurationResponse {
            version: CONTRACT_VERSION,
            settings,
            credential_status,
        })
        .into_response(),
    ))
}

fn private_no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    response.headers_mut().insert(
        axum::http::header::PRAGMA,
        HeaderValue::from_static("no-cache"),
    );
    response.headers_mut().insert(
        axum::http::header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Message, Secp256k1};
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_keypair() -> (Keypair, String) {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
        let (npub, _) = keypair.x_only_public_key();
        (keypair, npub.to_string())
    }

    fn sign(keypair: &Keypair, message: &[u8]) -> String {
        let digest = Sha256::digest(message);
        let message = Message::from_digest(*digest.as_ref());
        Secp256k1::new().sign_schnorr(&message, keypair).to_string()
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn signed_set_request(keypair: &Keypair, npub: &str, timestamp: u64) -> SetRequest {
        let api_key = format!("bbak-{}", "ab".repeat(32));
        let percentage = "50";
        let message = auth::build_la_v2_message(
            ACTION_SET,
            npub,
            "",
            &[
                VERSION_FIELD,
                Product::Invoice.as_str(),
                percentage,
                "CAD",
                TERMS_VERSION,
                &api_key,
            ],
            timestamp,
        );
        SetRequest {
            version: CONTRACT_VERSION,
            npub: npub.into(),
            fiat_percentage: 50,
            fiat_currency: Some(FiatCurrency::CAD),
            terms_version: Some(TERMS_VERSION.into()),
            api_key: Some(api_key),
            timestamp,
            signature: sign(keypair, &message),
        }
    }

    #[test]
    fn set_signature_binds_every_logical_field() {
        let (keypair, npub) = test_keypair();
        let timestamp = now();
        assert!(verify_set_request(
            Product::Invoice,
            signed_set_request(&keypair, &npub, timestamp)
        )
        .is_ok());

        let mut tampered = signed_set_request(&keypair, &npub, timestamp);
        tampered.fiat_percentage = 51;
        assert!(verify_set_request(Product::Invoice, tampered).is_err());

        let wrong_product = signed_set_request(&keypair, &npub, timestamp);
        assert!(verify_set_request(Product::Pos, wrong_product).is_err());
    }

    #[test]
    fn key_is_validated_before_nul_delimited_signature_verification() {
        let (keypair, npub) = test_keypair();
        let mut request = signed_set_request(&keypair, &npub, now());
        request.api_key = Some(format!("bbak-{}\0suffix", "ab".repeat(32)));
        assert!(matches!(
            verify_set_request(Product::Invoice, request),
            Err(AppError::InvalidAmount(_))
        ));
    }

    #[test]
    fn bitcoin_only_delete_contract_requires_no_terms_or_key() {
        let (keypair, npub) = test_keypair();
        let timestamp = now();
        let message = auth::build_la_v2_message(
            ACTION_SET,
            &npub,
            "",
            &[VERSION_FIELD, Product::Pos.as_str(), "0", "", "", ""],
            timestamp,
        );
        let request = SetRequest {
            version: CONTRACT_VERSION,
            npub,
            fiat_percentage: 0,
            fiat_currency: None,
            terms_version: None,
            api_key: None,
            timestamp,
            signature: sign(&keypair, &message),
        };
        assert!(verify_set_request(Product::Pos, request).is_ok());
    }
}

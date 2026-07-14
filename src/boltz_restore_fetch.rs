//! Bounded, unwired transport boundary for Boltz xpub restore reconciliation.
//!
//! The pinned `boltz-client` exposes the exact endpoints and response types, but
//! currently materializes response bodies with an unbounded `Response::text`.
//! This adapter keeps those pinned wire types while imposing Bullnym's response,
//! timeout, URL, status, and error-sanitization policy before offline validation.

use std::fmt;
use std::time::Duration;

use boltz_client::swaps::boltz::{SwapRestoreIndexResponse, SwapRestoreResponse};
use boltz_client::util::secrets::SwapMasterKey;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::boltz_restore::{validate_restore_records, ValidatedBoltzRestoreSet};

/// Restore lists are provider evidence, not an unbounded history export.
pub const MAX_BOLTZ_RESTORE_LIST_BYTES: usize = 1024 * 1024;
/// The pinned summary is one integer (including `-1`), so 4 KiB is ample headroom.
pub const MAX_BOLTZ_RESTORE_INDEX_BYTES: usize = 4 * 1024;

const BOLTZ_RESTORE_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
// The maximum-gap restore scan is intentionally heavier than establishing the
// HTTPS connection. Keep its whole-request budget separate and bounded.
const BOLTZ_RESTORE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const JSON_MEDIA_TYPE: &str = "application/json";
// `SwapMasterKey::get_master_xpub` returns the already-derived swap-account
// xpub. Boltz must therefore append each direct child index to `m`, rather than
// applying its unrelated default path below that account key.
const BOLTZ_RESTORE_DERIVATION_PATH: &str = "m";
// Boltz bounds xpub restore scans to 1..=150 keys. Use the full bounded window:
// Bullnym durably reserves keys before provider I/O, so failed calls leave
// permanent sparse indexes that a smaller/default window could truncate.
const BOLTZ_RESTORE_GAP_LIMIT: u32 = 150;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoltzRestoreEndpoint {
    Records,
    Index,
}

impl BoltzRestoreEndpoint {
    fn relative_path(self) -> &'static str {
        match self {
            Self::Records => "swap/restore",
            Self::Index => "swap/restore/index",
        }
    }
}

impl fmt::Display for BoltzRestoreEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Records => formatter.write_str("restore records"),
            Self::Index => formatter.write_str("restore index"),
        }
    }
}

/// Typed failures deliberately contain no URL, xpub, seed, response body, or
/// upstream error string. In particular, provider-controlled validation detail
/// is collapsed at this network boundary before it can reach ordinary logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoltzRestoreFetchError {
    InvalidBaseUrl,
    ClientInitialization,
    TimedOut {
        endpoint: BoltzRestoreEndpoint,
    },
    Unavailable {
        endpoint: BoltzRestoreEndpoint,
    },
    AuthenticationRejected {
        endpoint: BoltzRestoreEndpoint,
    },
    UnexpectedStatus {
        endpoint: BoltzRestoreEndpoint,
        status: u16,
    },
    UnexpectedContentType {
        endpoint: BoltzRestoreEndpoint,
    },
    ResponseTooLarge {
        endpoint: BoltzRestoreEndpoint,
        limit_bytes: usize,
    },
    MalformedJson {
        endpoint: BoltzRestoreEndpoint,
    },
    InvalidRecords,
    SummaryMismatch,
}

impl fmt::Display for BoltzRestoreFetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl => formatter.write_str("invalid Boltz restore base URL"),
            Self::ClientInitialization => {
                formatter.write_str("could not initialize Boltz restore HTTP client")
            }
            Self::TimedOut { endpoint } => {
                write!(formatter, "Boltz {endpoint} request timed out")
            }
            Self::Unavailable { endpoint } => {
                write!(formatter, "Boltz {endpoint} endpoint is unavailable")
            }
            Self::AuthenticationRejected { endpoint } => {
                write!(formatter, "Boltz {endpoint} authentication was rejected")
            }
            Self::UnexpectedStatus { endpoint, status } => {
                write!(formatter, "Boltz {endpoint} returned HTTP {status}")
            }
            Self::UnexpectedContentType { endpoint } => {
                write!(formatter, "Boltz {endpoint} did not return JSON")
            }
            Self::ResponseTooLarge {
                endpoint,
                limit_bytes,
            } => write!(
                formatter,
                "Boltz {endpoint} exceeded the {limit_bytes}-byte response limit"
            ),
            Self::MalformedJson { endpoint } => {
                write!(formatter, "Boltz {endpoint} returned malformed JSON")
            }
            Self::InvalidRecords => {
                formatter.write_str("Boltz restore records failed offline validation")
            }
            Self::SummaryMismatch => formatter
                .write_str("Boltz restore index does not match the validated record high-water"),
        }
    }
}

impl std::error::Error for BoltzRestoreFetchError {}

/// Unwired client for fetching and validating one exact Boltz restore snapshot.
///
/// Production construction accepts only HTTPS. Redirects are disabled so the
/// xpub cannot be forwarded to a provider-selected location. The adapter sends
/// only the public master xpub and its fixed public scan contract; it never
/// serializes `SwapMasterKey` itself.
pub struct BoltzRestoreFetcher {
    client: reqwest::Client,
    records_url: Url,
    index_url: Url,
}

impl BoltzRestoreFetcher {
    pub fn new(base_url: &str) -> Result<Self, BoltzRestoreFetchError> {
        Self::build(
            base_url,
            BOLTZ_RESTORE_CONNECT_TIMEOUT,
            BOLTZ_RESTORE_REQUEST_TIMEOUT,
            false,
        )
    }

    /// Deterministic integration-test transport. Production construction above
    /// remains HTTPS-only; this seam accepts only an HTTP loopback host and
    /// retains the same redirect, body, status, and validation policy.
    #[doc(hidden)]
    pub fn from_loopback_for_integration_tests(
        base_url: &str,
    ) -> Result<Self, BoltzRestoreFetchError> {
        Self::build(
            base_url,
            BOLTZ_RESTORE_CONNECT_TIMEOUT,
            BOLTZ_RESTORE_REQUEST_TIMEOUT,
            true,
        )
    }

    /// Fetch the pinned restore list and summary, validate every record against
    /// the local secret key, then require the summary to equal the validated
    /// record high-water. Nothing is persisted or admitted by this boundary.
    pub async fn fetch_and_validate(
        &self,
        swap_master_key: &SwapMasterKey,
    ) -> Result<ValidatedBoltzRestoreSet, BoltzRestoreFetchError> {
        let xpub = swap_master_key.get_master_xpub().to_string();
        let request = RestoreRequest::for_swap_account_xpub(&xpub);

        let records: Vec<SwapRestoreResponse> = self
            .post_json(
                BoltzRestoreEndpoint::Records,
                &self.records_url,
                &request,
                MAX_BOLTZ_RESTORE_LIST_BYTES,
            )
            .await?;
        let index: SwapRestoreIndexResponse = self
            .post_json(
                BoltzRestoreEndpoint::Index,
                &self.index_url,
                &request,
                MAX_BOLTZ_RESTORE_INDEX_BYTES,
            )
            .await?;

        let validated = validate_restore_records(swap_master_key, &records)
            .map_err(|_| BoltzRestoreFetchError::InvalidRecords)?;
        validated
            .validate_reported_high_water(&index)
            .map_err(|_| BoltzRestoreFetchError::SummaryMismatch)?;
        Ok(validated)
    }

    fn build(
        base_url: &str,
        connect_timeout: Duration,
        request_timeout: Duration,
        allow_loopback_http: bool,
    ) -> Result<Self, BoltzRestoreFetchError> {
        let base_url = normalize_base_url(base_url, allow_loopback_http)?;
        let records_url = base_url
            .join(BoltzRestoreEndpoint::Records.relative_path())
            .map_err(|_| BoltzRestoreFetchError::InvalidBaseUrl)?;
        let index_url = base_url
            .join(BoltzRestoreEndpoint::Index.relative_path())
            .map_err(|_| BoltzRestoreFetchError::InvalidBaseUrl)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .build()
            .map_err(|_| BoltzRestoreFetchError::ClientInitialization)?;
        Ok(Self {
            client,
            records_url,
            index_url,
        })
    }

    async fn post_json<T: DeserializeOwned>(
        &self,
        endpoint: BoltzRestoreEndpoint,
        url: &Url,
        request: &RestoreRequest<'_>,
        limit_bytes: usize,
    ) -> Result<T, BoltzRestoreFetchError> {
        let mut response = self
            .client
            .post(url.clone())
            .header(ACCEPT, JSON_MEDIA_TYPE)
            .json(request)
            .send()
            .await
            .map_err(|error| transport_error(endpoint, &error))?;

        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(BoltzRestoreFetchError::AuthenticationRejected { endpoint });
            }
            status if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() => {
                return Err(BoltzRestoreFetchError::Unavailable { endpoint });
            }
            status => {
                return Err(BoltzRestoreFetchError::UnexpectedStatus {
                    endpoint,
                    status: status.as_u16(),
                });
            }
        }

        if !has_json_content_type(&response) {
            return Err(BoltzRestoreFetchError::UnexpectedContentType { endpoint });
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit_bytes as u64)
        {
            return Err(BoltzRestoreFetchError::ResponseTooLarge {
                endpoint,
                limit_bytes,
            });
        }

        let mut body = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(0)
                .min(limit_bytes),
        );
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| transport_error(endpoint, &error))?
        {
            if chunk.len() > limit_bytes.saturating_sub(body.len()) {
                return Err(BoltzRestoreFetchError::ResponseTooLarge {
                    endpoint,
                    limit_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }

        serde_json::from_slice(&body)
            .map_err(|_| BoltzRestoreFetchError::MalformedJson { endpoint })
    }

    #[cfg(test)]
    fn new_for_test(
        base_url: &str,
        request_timeout: Duration,
    ) -> Result<Self, BoltzRestoreFetchError> {
        Self::build(
            base_url,
            BOLTZ_RESTORE_CONNECT_TIMEOUT,
            request_timeout,
            true,
        )
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RestoreRequest<'a> {
    xpub: &'a str,
    derivation_path: &'static str,
    gap_limit: u32,
}

impl<'a> RestoreRequest<'a> {
    fn for_swap_account_xpub(xpub: &'a str) -> Self {
        Self {
            xpub,
            derivation_path: BOLTZ_RESTORE_DERIVATION_PATH,
            gap_limit: BOLTZ_RESTORE_GAP_LIMIT,
        }
    }
}

fn normalize_base_url(raw: &str, allow_loopback_http: bool) -> Result<Url, BoltzRestoreFetchError> {
    let mut url = Url::parse(raw).map_err(|_| BoltzRestoreFetchError::InvalidBaseUrl)?;
    let is_https = url.scheme() == "https";
    let is_test_loopback = allow_loopback_http
        && url.scheme() == "http"
        && url.host_str().is_some_and(is_loopback_host);
    if (!is_https && !is_test_loopback)
        || url.host_str().is_none()
        || url.port() == Some(0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.cannot_be_a_base()
    {
        return Err(BoltzRestoreFetchError::InvalidBaseUrl);
    }

    let normalized_path = format!("{}/", url.path().trim_end_matches('/'));
    url.set_path(&normalized_path);
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn has_json_content_type(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(JSON_MEDIA_TYPE))
}

fn transport_error(
    endpoint: BoltzRestoreEndpoint,
    error: &reqwest::Error,
) -> BoltzRestoreFetchError {
    if error.is_timeout() {
        BoltzRestoreFetchError::TimedOut { endpoint }
    } else {
        BoltzRestoreFetchError::Unavailable { endpoint }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::body::{Body, Bytes};
    use axum::extract::State;
    use axum::http::Response;
    use axum::routing::post;
    use axum::Router;
    use boltz_client::network::Network;
    use serde_json::{json, Value};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const RESTORE_FIXTURE: &str = include_str!("../tests/fixtures/boltz-xpub-restore-v1.json");
    const INDEX_FIXTURE: &str = include_str!("../tests/fixtures/boltz-xpub-restore-index-v1.json");

    #[derive(Clone)]
    struct FakeResponse {
        status: StatusCode,
        content_type: Option<&'static str>,
        body: Arc<Vec<u8>>,
        delay: Duration,
    }

    impl FakeResponse {
        fn json(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: StatusCode::OK,
                content_type: Some(JSON_MEDIA_TYPE),
                body: Arc::new(body.into()),
                delay: Duration::ZERO,
            }
        }

        fn status(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
            Self {
                status,
                content_type: Some(JSON_MEDIA_TYPE),
                body: Arc::new(body.into()),
                delay: Duration::ZERO,
            }
        }
    }

    #[derive(Clone)]
    struct FakeState {
        records: FakeResponse,
        index: FakeResponse,
        requests: Arc<Mutex<Vec<(BoltzRestoreEndpoint, Value)>>>,
    }

    struct FakeServer {
        base_url: String,
        requests: Arc<Mutex<Vec<(BoltzRestoreEndpoint, Value)>>>,
        task: JoinHandle<()>,
    }

    impl FakeServer {
        async fn spawn(records: FakeResponse, index: FakeResponse) -> Self {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let state = FakeState {
                records,
                index,
                requests: Arc::clone(&requests),
            };
            let app = Router::new()
                .route("/v2/swap/restore", post(restore_records))
                .route("/v2/swap/restore/index", post(restore_index))
                .with_state(state);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                base_url: format!("http://{address}/v2"),
                requests,
                task,
            }
        }

        fn requests(&self) -> Vec<(BoltzRestoreEndpoint, Value)> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for FakeServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn restore_records(State(state): State<FakeState>, body: Bytes) -> Response<Body> {
        respond(&state, BoltzRestoreEndpoint::Records, body).await
    }

    async fn restore_index(State(state): State<FakeState>, body: Bytes) -> Response<Body> {
        respond(&state, BoltzRestoreEndpoint::Index, body).await
    }

    async fn respond(
        state: &FakeState,
        endpoint: BoltzRestoreEndpoint,
        request_body: Bytes,
    ) -> Response<Body> {
        let request = serde_json::from_slice(&request_body).unwrap_or(Value::Null);
        state.requests.lock().unwrap().push((endpoint, request));
        let response = match endpoint {
            BoltzRestoreEndpoint::Records => &state.records,
            BoltzRestoreEndpoint::Index => &state.index,
        };
        if !response.delay.is_zero() {
            tokio::time::sleep(response.delay).await;
        }
        let mut builder = Response::builder().status(response.status);
        if let Some(content_type) = response.content_type {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        builder.body(Body::from((*response.body).clone())).unwrap()
    }

    fn master_key() -> SwapMasterKey {
        SwapMasterKey::from_mnemonic(TEST_MNEMONIC, None, Network::Mainnet).unwrap()
    }

    fn valid_responses() -> (FakeResponse, FakeResponse) {
        (
            FakeResponse::json(RESTORE_FIXTURE.as_bytes().to_vec()),
            FakeResponse::json(INDEX_FIXTURE.as_bytes().to_vec()),
        )
    }

    async fn fixture_client(
        records: FakeResponse,
        index: FakeResponse,
    ) -> (FakeServer, BoltzRestoreFetcher) {
        let server = FakeServer::spawn(records, index).await;
        let client =
            BoltzRestoreFetcher::new_for_test(&server.base_url, Duration::from_secs(1)).unwrap();
        (server, client)
    }

    #[tokio::test]
    async fn sends_exact_account_relative_contract_to_both_restore_endpoints() {
        let (records, index) = valid_responses();
        let (server, client) = fixture_client(records, index).await;
        let master = master_key();
        let expected_xpub = master.get_master_xpub().to_string();

        let validated = client.fetch_and_validate(&master).await.unwrap();

        assert_eq!(validated.records.len(), 2);
        assert_eq!(validated.max_child_index, Some(102));
        let requests = server.requests();
        let exact_request = json!({
            "xpub": &expected_xpub,
            "derivationPath": "m",
            "gapLimit": 150,
        });
        assert_eq!(
            requests,
            [
                (BoltzRestoreEndpoint::Records, exact_request.clone()),
                (BoltzRestoreEndpoint::Index, exact_request),
            ]
        );
        for (_, request) in server.requests() {
            let encoded = serde_json::to_string(&request).unwrap();
            assert!(!encoded.contains("mnemonic"));
            assert!(!encoded.contains("xprv"));
            assert!(!encoded.contains(TEST_MNEMONIC));
        }
    }

    #[test]
    fn restore_request_cannot_fall_back_to_provider_derivation_defaults() {
        let request =
            serde_json::to_value(RestoreRequest::for_swap_account_xpub("public-account-xpub"))
                .unwrap();

        assert_eq!(
            request,
            json!({
                "xpub": "public-account-xpub",
                "derivationPath": BOLTZ_RESTORE_DERIVATION_PATH,
                "gapLimit": BOLTZ_RESTORE_GAP_LIMIT,
            })
        );
        assert_eq!(request["derivationPath"], "m");
        assert_eq!(request["gapLimit"], 150);
        assert!(request.get("derivation_path").is_none());
        assert!(request.get("gap_limit").is_none());
        assert!(!request.to_string().contains("m/44/0/0/0"));
    }

    #[tokio::test]
    async fn malformed_record_or_index_json_fails_closed() {
        let (_, valid_index) = valid_responses();
        let (_records_server, client) =
            fixture_client(FakeResponse::json(b"not-json".to_vec()), valid_index).await;
        assert_eq!(
            client.fetch_and_validate(&master_key()).await.unwrap_err(),
            BoltzRestoreFetchError::MalformedJson {
                endpoint: BoltzRestoreEndpoint::Records
            }
        );

        let (valid_records, _) = valid_responses();
        let (_index_server, client) = fixture_client(
            valid_records,
            FakeResponse::json(br#"{"missing":true}"#.to_vec()),
        )
        .await;
        assert_eq!(
            client.fetch_and_validate(&master_key()).await.unwrap_err(),
            BoltzRestoreFetchError::MalformedJson {
                endpoint: BoltzRestoreEndpoint::Index
            }
        );
    }

    #[tokio::test]
    async fn oversized_record_or_index_body_is_rejected_before_deserialization() {
        let (_, valid_index) = valid_responses();
        let oversized = vec![b' '; MAX_BOLTZ_RESTORE_LIST_BYTES + 1];
        let (_records_server, client) =
            fixture_client(FakeResponse::json(oversized), valid_index).await;

        assert_eq!(
            client.fetch_and_validate(&master_key()).await.unwrap_err(),
            BoltzRestoreFetchError::ResponseTooLarge {
                endpoint: BoltzRestoreEndpoint::Records,
                limit_bytes: MAX_BOLTZ_RESTORE_LIST_BYTES,
            }
        );

        let (valid_records, _) = valid_responses();
        let oversized = vec![b' '; MAX_BOLTZ_RESTORE_INDEX_BYTES + 1];
        let (_index_server, client) =
            fixture_client(valid_records, FakeResponse::json(oversized)).await;
        assert_eq!(
            client.fetch_and_validate(&master_key()).await.unwrap_err(),
            BoltzRestoreFetchError::ResponseTooLarge {
                endpoint: BoltzRestoreEndpoint::Index,
                limit_bytes: MAX_BOLTZ_RESTORE_INDEX_BYTES,
            }
        );
    }

    #[tokio::test]
    async fn connect_and_whole_request_timeouts_are_independent() {
        let (mut records, index) = valid_responses();
        records.delay = Duration::from_millis(60);
        let server = FakeServer::spawn(records, index).await;
        let client = BoltzRestoreFetcher::build(
            &server.base_url,
            Duration::from_millis(20),
            Duration::from_millis(250),
            true,
        )
        .unwrap();

        let validated = client.fetch_and_validate(&master_key()).await.unwrap();
        assert_eq!(validated.records.len(), 2);
        assert_eq!(validated.max_child_index, Some(102));
    }

    #[tokio::test]
    async fn slow_provider_is_cut_off_by_the_request_timeout() {
        let (mut records, index) = valid_responses();
        records.delay = Duration::from_millis(200);
        let server = FakeServer::spawn(records, index).await;
        let client =
            BoltzRestoreFetcher::new_for_test(&server.base_url, Duration::from_millis(20)).unwrap();

        assert_eq!(
            client.fetch_and_validate(&master_key()).await.unwrap_err(),
            BoltzRestoreFetchError::TimedOut {
                endpoint: BoltzRestoreEndpoint::Records
            }
        );
    }

    #[tokio::test]
    async fn auth_and_unavailable_errors_do_not_embed_provider_bodies() {
        const SENTINEL: &str = "provider-body-must-not-escape";
        let (_, index) = valid_responses();
        let (_auth_server, client) = fixture_client(
            FakeResponse::status(StatusCode::UNAUTHORIZED, SENTINEL.as_bytes().to_vec()),
            index,
        )
        .await;
        let auth = client.fetch_and_validate(&master_key()).await.unwrap_err();
        assert_eq!(
            auth,
            BoltzRestoreFetchError::AuthenticationRejected {
                endpoint: BoltzRestoreEndpoint::Records
            }
        );
        assert!(!format!("{auth:?} {auth}").contains(SENTINEL));

        let (_, index) = valid_responses();
        let (_unavailable_server, client) = fixture_client(
            FakeResponse::status(
                StatusCode::SERVICE_UNAVAILABLE,
                SENTINEL.as_bytes().to_vec(),
            ),
            index,
        )
        .await;
        let unavailable = client.fetch_and_validate(&master_key()).await.unwrap_err();
        assert_eq!(
            unavailable,
            BoltzRestoreFetchError::Unavailable {
                endpoint: BoltzRestoreEndpoint::Records
            }
        );
        assert!(!format!("{unavailable:?} {unavailable}").contains(SENTINEL));

        let poisoned_records = RESTORE_FIXTURE.replacen("RstrRev00001", SENTINEL, 1);
        let (_, index) = valid_responses();
        let (_validation_server, client) =
            fixture_client(FakeResponse::json(poisoned_records.into_bytes()), index).await;
        let invalid = client.fetch_and_validate(&master_key()).await.unwrap_err();
        assert_eq!(invalid, BoltzRestoreFetchError::InvalidRecords);
        assert!(!format!("{invalid:?} {invalid}").contains(SENTINEL));
    }

    #[tokio::test]
    async fn provider_summary_must_equal_validated_record_high_water() {
        let (records, _) = valid_responses();
        let (_server, client) = fixture_client(
            records,
            FakeResponse::json(serde_json::to_vec(&json!({ "index": 101 })).unwrap()),
        )
        .await;

        assert_eq!(
            client.fetch_and_validate(&master_key()).await.unwrap_err(),
            BoltzRestoreFetchError::SummaryMismatch
        );
    }

    #[tokio::test]
    async fn exact_200_and_json_content_type_are_required() {
        let (_, index) = valid_responses();
        let (_status_server, client) = fixture_client(
            FakeResponse::status(StatusCode::CREATED, RESTORE_FIXTURE.as_bytes().to_vec()),
            index,
        )
        .await;
        assert_eq!(
            client.fetch_and_validate(&master_key()).await.unwrap_err(),
            BoltzRestoreFetchError::UnexpectedStatus {
                endpoint: BoltzRestoreEndpoint::Records,
                status: 201,
            }
        );

        let (mut records, index) = valid_responses();
        records.content_type = Some("text/plain");
        let (_content_type_server, client) = fixture_client(records, index).await;
        assert_eq!(
            client.fetch_and_validate(&master_key()).await.unwrap_err(),
            BoltzRestoreFetchError::UnexpectedContentType {
                endpoint: BoltzRestoreEndpoint::Records
            }
        );
    }

    #[test]
    fn production_timeout_policy_keeps_connect_fast_and_restore_bounded() {
        assert_eq!(BOLTZ_RESTORE_CONNECT_TIMEOUT, Duration::from_secs(2));
        assert_eq!(BOLTZ_RESTORE_REQUEST_TIMEOUT, Duration::from_secs(10));
        assert!(BOLTZ_RESTORE_REQUEST_TIMEOUT > BOLTZ_RESTORE_CONNECT_TIMEOUT);
        assert!(BOLTZ_RESTORE_REQUEST_TIMEOUT <= Duration::from_secs(10));
    }

    #[test]
    fn production_constructor_requires_a_clean_https_base_url() {
        assert!(BoltzRestoreFetcher::new("https://api.boltz.exchange/v2").is_ok());
        for invalid in [
            "http://api.boltz.exchange/v2",
            "https://user:password@api.boltz.exchange/v2",
            "https://api.boltz.exchange/v2?x=1",
            "https://api.boltz.exchange/v2#fragment",
            "not-a-url",
        ] {
            assert!(matches!(
                BoltzRestoreFetcher::new(invalid),
                Err(BoltzRestoreFetchError::InvalidBaseUrl)
            ));
        }
    }
}

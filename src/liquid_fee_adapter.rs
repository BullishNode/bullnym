use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    redirect::Policy,
    Url,
};
use serde::Deserialize;
use std::{
    fmt,
    net::IpAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const REQUEST_TIMEOUT: Duration = Duration::from_millis(1_500);
const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024;
// This is a representation-safety limit, not an operational fee policy. A
// later policy layer remains responsible for independently configured bounds.
const MAX_REPRESENTABLE_FEE_SAT_PER_VBYTE: f64 = u32::MAX as f64;

/// A narrow client for a Liquid Esplora `/fee-estimates` endpoint.
///
/// Construction accepts only a credential-free HTTPS base endpoint. The
/// adapter observes target-1 evidence only; it does not choose fallbacks or
/// make spending decisions.
#[derive(Clone)]
pub struct LiquidEsploraTargetOneFeeAdapter {
    client: reqwest::Client,
    fee_estimates_url: Url,
}

impl LiquidEsploraTargetOneFeeAdapter {
    /// Builds an adapter for `<configured_https_endpoint>/fee-estimates`.
    pub fn new(configured_https_endpoint: &str) -> Result<Self, LiquidFeeAdapterError> {
        Self::build(configured_https_endpoint, REQUEST_TIMEOUT, false)
    }

    /// Fetches and validates the endpoint's target-1 rate in sat/vByte.
    pub async fn observe(
        &self,
    ) -> Result<LiquidEsploraTargetOneFeeObservation, LiquidFeeAdapterError> {
        self.observe_with_clock(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| LiquidFeeAdapterError::InvalidObservationTime)
                .map(|duration| duration.as_secs())
        })
        .await
    }

    async fn observe_with_clock<F>(
        &self,
        observe_unix_time: F,
    ) -> Result<LiquidEsploraTargetOneFeeObservation, LiquidFeeAdapterError>
    where
        F: FnOnce() -> Result<u64, LiquidFeeAdapterError>,
    {
        let mut response = self
            .client
            .get(self.fee_estimates_url.clone())
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(map_request_error)?;

        if !response.status().is_success() {
            return Err(LiquidFeeAdapterError::UnexpectedStatus);
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if !matches!(content_type, Some(value) if value.eq_ignore_ascii_case("application/json")) {
            return Err(LiquidFeeAdapterError::UnexpectedContentType);
        }

        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BODY_BYTES as u64)
        {
            return Err(LiquidFeeAdapterError::ResponseTooLarge);
        }

        let mut body = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or_default()
                .min(MAX_RESPONSE_BODY_BYTES as u64) as usize,
        );
        while let Some(chunk) = response.chunk().await.map_err(map_request_error)? {
            let next_length = body
                .len()
                .checked_add(chunk.len())
                .ok_or(LiquidFeeAdapterError::ResponseTooLarge)?;
            if next_length > MAX_RESPONSE_BODY_BYTES {
                return Err(LiquidFeeAdapterError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }

        let response: FeeEstimatesResponse =
            serde_json::from_slice(&body).map_err(|_| LiquidFeeAdapterError::MalformedResponse)?;
        let target_one_fee_sat_per_vbyte = response
            .target_one
            .as_f64()
            .filter(|fee| {
                fee.is_finite() && *fee > 0.0 && *fee <= MAX_REPRESENTABLE_FEE_SAT_PER_VBYTE
            })
            .ok_or(LiquidFeeAdapterError::InvalidTargetOneFee)?;

        // Attach time only after transport, content, schema, and value checks
        // have all succeeded.
        let observed_at_unix = observe_unix_time()?;

        Ok(LiquidEsploraTargetOneFeeObservation {
            target_one_fee_sat_per_vbyte,
            observed_at: LiquidObservedAtUnixSeconds(observed_at_unix),
            source: LiquidFeeObservationSource::ConfiguredTargetOneEstimate,
        })
    }

    fn build(
        configured_endpoint: &str,
        timeout: Duration,
        allow_loopback_http: bool,
    ) -> Result<Self, LiquidFeeAdapterError> {
        let mut endpoint =
            Url::parse(configured_endpoint).map_err(|_| LiquidFeeAdapterError::InvalidEndpoint)?;

        let is_https = endpoint.scheme() == "https";
        let is_allowed_test_endpoint = allow_loopback_http
            && endpoint.scheme() == "http"
            && endpoint
                .host_str()
                .and_then(|host| host.parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback());
        if (!is_https && !is_allowed_test_endpoint)
            || endpoint.cannot_be_a_base()
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.port() == Some(0)
        {
            return Err(LiquidFeeAdapterError::InvalidEndpoint);
        }

        endpoint
            .path_segments_mut()
            .map_err(|_| LiquidFeeAdapterError::InvalidEndpoint)?
            .pop_if_empty()
            .push("fee-estimates");
        let fee_estimates_url = endpoint;

        let client = reqwest::Client::builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| LiquidFeeAdapterError::ClientInitialization)?;

        Ok(Self {
            client,
            fee_estimates_url,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_loopback_http(
        configured_endpoint: &str,
        timeout: Duration,
    ) -> Result<Self, LiquidFeeAdapterError> {
        Self::build(configured_endpoint, timeout, true)
    }
}

#[derive(Debug, Deserialize)]
struct FeeEstimatesResponse {
    #[serde(rename = "1")]
    target_one: serde_json::Number,
}

/// Timestamp attached only after a response has passed transport, schema, and
/// value validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LiquidObservedAtUnixSeconds(u64);

impl LiquidObservedAtUnixSeconds {
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Non-secret provenance for the validated Liquid observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidFeeObservationSource {
    ConfiguredTargetOneEstimate,
}

impl LiquidFeeObservationSource {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::ConfiguredTargetOneEstimate => "liquid_esplora_target_1_fee",
        }
    }
}

/// Validated target-1 transport evidence. Policy code must still decide
/// whether and how to use it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LiquidEsploraTargetOneFeeObservation {
    target_one_fee_sat_per_vbyte: f64,
    observed_at: LiquidObservedAtUnixSeconds,
    source: LiquidFeeObservationSource,
}

impl LiquidEsploraTargetOneFeeObservation {
    pub const fn target_one_fee_sat_per_vbyte(self) -> f64 {
        self.target_one_fee_sat_per_vbyte
    }

    pub const fn observed_at(self) -> LiquidObservedAtUnixSeconds {
        self.observed_at
    }

    pub const fn source(self) -> LiquidFeeObservationSource {
        self.source
    }
}

/// Stable error categories intentionally omit URLs, bodies, and transport
/// internals so secrets cannot escape through logs or API responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidFeeAdapterError {
    InvalidEndpoint,
    ClientInitialization,
    Timeout,
    Unavailable,
    UnexpectedStatus,
    UnexpectedContentType,
    ResponseTooLarge,
    MalformedResponse,
    InvalidTargetOneFee,
    InvalidObservationTime,
}

impl fmt::Display for LiquidFeeAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEndpoint => "invalid Liquid fee endpoint",
            Self::ClientInitialization => "Liquid fee client initialization failed",
            Self::Timeout => "Liquid fee endpoint timed out",
            Self::Unavailable => "Liquid fee endpoint unavailable",
            Self::UnexpectedStatus => "Liquid fee endpoint returned an unexpected status",
            Self::UnexpectedContentType => "Liquid fee endpoint returned unexpected content",
            Self::ResponseTooLarge => "Liquid fee endpoint response exceeded its size limit",
            Self::MalformedResponse => "Liquid fee endpoint response was malformed",
            Self::InvalidTargetOneFee => "Liquid fee endpoint returned an invalid target-1 fee",
            Self::InvalidObservationTime => "Liquid fee observation time was invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LiquidFeeAdapterError {}

fn map_request_error(error: reqwest::Error) -> LiquidFeeAdapterError {
    if error.is_timeout() {
        LiquidFeeAdapterError::Timeout
    } else {
        LiquidFeeAdapterError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
        task::JoinHandle,
    };

    const TEST_TIMEOUT: Duration = Duration::from_millis(1_500);

    struct FakeHttpResponse {
        status: &'static str,
        content_type: Option<&'static str>,
        location: Option<&'static str>,
        include_content_length: bool,
        close_without_response: bool,
        body: Vec<u8>,
        delay: Duration,
    }

    impl FakeHttpResponse {
        fn json(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: "200 OK",
                content_type: Some("application/json; charset=utf-8"),
                location: None,
                include_content_length: true,
                close_without_response: false,
                body: body.into(),
                delay: Duration::ZERO,
            }
        }
    }

    struct FakeHttpServer {
        base_endpoint: String,
        request_rx: oneshot::Receiver<String>,
        task: JoinHandle<()>,
    }

    impl FakeHttpServer {
        fn adapter(&self, timeout: Duration) -> LiquidEsploraTargetOneFeeAdapter {
            LiquidEsploraTargetOneFeeAdapter::new_for_test_loopback_http(
                &self.base_endpoint,
                timeout,
            )
            .expect("loopback fake endpoint must be valid")
        }

        async fn finish(self) -> String {
            let request = self
                .request_rx
                .await
                .expect("fake server must record one request");
            self.task.await.expect("fake server task must finish");
            request
        }
    }

    async fn spawn_fake_http_server(response: FakeHttpResponse) -> FakeHttpServer {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake HTTP server");
        let address = listener.local_addr().expect("read fake server address");
        let (request_tx, request_rx) = oneshot::channel();

        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fee request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1_024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.expect("read fee request");
                if read == 0 || request.len() + read > 16 * 1_024 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let _ = request_tx.send(String::from_utf8_lossy(&request).into_owned());

            tokio::time::sleep(response.delay).await;
            if response.close_without_response {
                return;
            }
            let mut headers = format!("HTTP/1.1 {}\r\nConnection: close\r\n", response.status);
            if let Some(content_type) = response.content_type {
                headers.push_str(&format!("Content-Type: {content_type}\r\n"));
            }
            if let Some(location) = response.location {
                headers.push_str(&format!("Location: {location}\r\n"));
            }
            if response.include_content_length {
                headers.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
            }
            headers.push_str("\r\n");

            // Timeout and early body-limit cases may close the client socket.
            // Those write errors are expected fake-server outcomes.
            if stream.write_all(headers.as_bytes()).await.is_ok() {
                let _ = stream.write_all(&response.body).await;
            }
        });

        FakeHttpServer {
            base_endpoint: format!("http://{address}/api"),
            request_rx,
            task,
        }
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must be after epoch")
            .as_secs()
    }

    async fn observe_error(body: &str) -> LiquidFeeAdapterError {
        let server = spawn_fake_http_server(FakeHttpResponse::json(body)).await;
        let result = server.adapter(TEST_TIMEOUT).observe().await;
        server.finish().await;
        result.expect_err("fixture must be rejected")
    }

    #[tokio::test]
    async fn observes_exact_target_one_with_units_time_source_and_request_contract() {
        let server =
            spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.125,"2":4.5,"6":2.25}"#))
                .await;
        let adapter = server.adapter(TEST_TIMEOUT);
        let before = unix_now();

        let observation = adapter.observe().await.expect("valid fee observation");
        let after = unix_now();

        assert_eq!(observation.target_one_fee_sat_per_vbyte(), 0.125);
        assert!((before..=after).contains(&observation.observed_at().as_u64()));
        assert_eq!(
            observation.source(),
            LiquidFeeObservationSource::ConfiguredTargetOneEstimate
        );
        assert_eq!(
            observation.source().stable_label(),
            "liquid_esplora_target_1_fee"
        );
        let request = server.finish().await;
        assert!(request.starts_with("GET /api/fee-estimates HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains("accept: application/json\r\n"));
    }

    #[tokio::test]
    async fn requires_exact_target_one_numeric_json_while_allowing_other_targets() {
        for body in [
            "not-json",
            r#"{}"#,
            r#"[]"#,
            r#"{"01":0.1}"#,
            r#"{"1":"0.1"}"#,
            r#"{"1":true}"#,
            r#"{"1":null}"#,
            r#"{"1":{"rate":0.1}}"#,
            r#"{"1":0.1,"1":0.2}"#,
            r#"{"1":0.1} trailing"#,
        ] {
            assert_eq!(
                observe_error(body).await,
                LiquidFeeAdapterError::MalformedResponse,
                "body should fail strict target-1 schema validation: {body}"
            );
        }

        let server = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"144":99,"1":0.2,"2":88,"custom":{"ignored":true}}"#,
        ))
        .await;
        let observation = server
            .adapter(TEST_TIMEOUT)
            .observe()
            .await
            .expect("real fee-estimate maps may include other targets");
        assert_eq!(observation.target_one_fee_sat_per_vbyte(), 0.2);
        server.finish().await;
    }

    #[tokio::test]
    async fn rejects_zero_and_negative_target_one_fees() {
        for body in [r#"{"1":0}"#, r#"{"1":-0.0}"#, r#"{"1":-1}"#] {
            assert_eq!(
                observe_error(body).await,
                LiquidFeeAdapterError::InvalidTargetOneFee
            );
        }
    }

    #[tokio::test]
    async fn rejects_non_finite_and_unrepresentable_target_one_fees() {
        for body in [
            r#"{"1":NaN}"#,
            r#"{"1":Infinity}"#,
            r#"{"1":-Infinity}"#,
            r#"{"1":1e400}"#,
        ] {
            assert_eq!(
                observe_error(body).await,
                LiquidFeeAdapterError::MalformedResponse
            );
        }
        assert_eq!(
            observe_error(r#"{"1":4294967296}"#).await,
            LiquidFeeAdapterError::InvalidTargetOneFee
        );
    }

    #[tokio::test]
    async fn accepts_positive_fractional_and_representation_boundary_values() {
        for expected in [f64::MIN_POSITIVE, 0.000_001, 0.1, u32::MAX as f64] {
            let body = format!(r#"{{"1":{expected}}}"#);
            let server = spawn_fake_http_server(FakeHttpResponse::json(body)).await;
            let observation = server
                .adapter(TEST_TIMEOUT)
                .observe()
                .await
                .expect("finite positive representable target-1 fee must pass");
            assert_eq!(observation.target_one_fee_sat_per_vbyte(), expected);
            server.finish().await;
        }
    }

    #[tokio::test]
    async fn enforces_request_timeout() {
        let server = spawn_fake_http_server(FakeHttpResponse {
            delay: Duration::from_millis(100),
            ..FakeHttpResponse::json(br#"{"1":0.1}"#)
        })
        .await;

        let error = server
            .adapter(Duration::from_millis(25))
            .observe()
            .await
            .expect_err("delayed endpoint must time out");

        assert_eq!(error, LiquidFeeAdapterError::Timeout);
        server.finish().await;
    }

    #[tokio::test]
    async fn bounds_declared_and_streamed_response_bodies() {
        for include_content_length in [true, false] {
            let server = spawn_fake_http_server(FakeHttpResponse {
                include_content_length,
                body: vec![b' '; MAX_RESPONSE_BODY_BYTES + 1],
                ..FakeHttpResponse::json(Vec::new())
            })
            .await;

            let error = server
                .adapter(TEST_TIMEOUT)
                .observe()
                .await
                .expect_err("oversized response must fail");

            assert_eq!(error, LiquidFeeAdapterError::ResponseTooLarge);
            server.finish().await;
        }
    }

    #[tokio::test]
    async fn rejects_missing_or_wrong_content_type_before_parsing_body() {
        for content_type in [None, Some("text/html"), Some("application/problem+json")] {
            let server = spawn_fake_http_server(FakeHttpResponse {
                content_type,
                ..FakeHttpResponse::json(br#"{"1":0.1}"#)
            })
            .await;

            let error = server
                .adapter(TEST_TIMEOUT)
                .observe()
                .await
                .expect_err("non-JSON content type must fail");

            assert_eq!(error, LiquidFeeAdapterError::UnexpectedContentType);
            server.finish().await;
        }
    }

    #[tokio::test]
    async fn accepts_case_insensitive_json_content_type_with_parameters() {
        let server = spawn_fake_http_server(FakeHttpResponse {
            content_type: Some("Application/JSON ; charset=utf-8"),
            ..FakeHttpResponse::json(br#"{"1":0.1}"#)
        })
        .await;

        let observation = server
            .adapter(TEST_TIMEOUT)
            .observe()
            .await
            .expect("valid JSON content type must pass");
        assert_eq!(observation.target_one_fee_sat_per_vbyte(), 0.1);
        server.finish().await;
    }

    #[tokio::test]
    async fn reports_http_and_transport_unavailability_without_details() {
        let secret_body = br#"{"error":"operator-secret"}"#;
        let server = spawn_fake_http_server(FakeHttpResponse {
            status: "503 Service Unavailable",
            ..FakeHttpResponse::json(secret_body)
        })
        .await;
        let status_error = server
            .adapter(TEST_TIMEOUT)
            .observe()
            .await
            .expect_err("503 response must fail");
        assert_eq!(status_error, LiquidFeeAdapterError::UnexpectedStatus);
        for diagnostic in [format!("{status_error:?}"), status_error.to_string()] {
            assert!(!diagnostic.contains("operator-secret"));
            assert!(!diagnostic.contains(&server.base_endpoint));
        }
        server.finish().await;

        let server = spawn_fake_http_server(FakeHttpResponse {
            close_without_response: true,
            ..FakeHttpResponse::json(Vec::new())
        })
        .await;
        let unavailable = server
            .adapter(TEST_TIMEOUT)
            .observe()
            .await
            .expect_err("closed connection must be unavailable");
        assert_eq!(unavailable, LiquidFeeAdapterError::Unavailable);
        assert_eq!(unavailable.to_string(), "Liquid fee endpoint unavailable");
        server.finish().await;
    }

    #[tokio::test]
    async fn refuses_redirects() {
        let server = spawn_fake_http_server(FakeHttpResponse {
            status: "302 Found",
            location: Some("http://127.0.0.1:9/redirected"),
            ..FakeHttpResponse::json(Vec::new())
        })
        .await;

        let error = server
            .adapter(TEST_TIMEOUT)
            .observe()
            .await
            .expect_err("redirect response must not be followed");

        assert_eq!(error, LiquidFeeAdapterError::UnexpectedStatus);
        let request = server.finish().await;
        assert!(request.starts_with("GET /api/fee-estimates HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn clock_is_called_only_after_full_transport_schema_and_value_validation() {
        let clock_calls = Arc::new(AtomicUsize::new(0));
        for body in [r#"{"1":0}"#, r#"{"2":0.1}"#, "not-json"] {
            let server = spawn_fake_http_server(FakeHttpResponse::json(body)).await;
            let calls = Arc::clone(&clock_calls);
            let result = server
                .adapter(TEST_TIMEOUT)
                .observe_with_clock(move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(123)
                })
                .await;
            assert!(result.is_err());
            server.finish().await;
        }
        assert_eq!(clock_calls.load(Ordering::SeqCst), 0);

        let server = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.1}"#)).await;
        let calls = Arc::clone(&clock_calls);
        let observation = server
            .adapter(TEST_TIMEOUT)
            .observe_with_clock(move || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(123)
            })
            .await
            .expect("fully validated evidence must reach the clock");
        assert_eq!(clock_calls.load(Ordering::SeqCst), 1);
        assert_eq!(observation.observed_at().as_u64(), 123);
        server.finish().await;
    }

    #[tokio::test]
    async fn clock_failure_after_full_validation_returns_invalid_observation_time() {
        let server = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.1}"#)).await;
        let clock_calls = AtomicUsize::new(0);

        let error = server
            .adapter(TEST_TIMEOUT)
            .observe_with_clock(|| {
                clock_calls.fetch_add(1, Ordering::SeqCst);
                Err(LiquidFeeAdapterError::InvalidObservationTime)
            })
            .await
            .expect_err("clock failure must reject otherwise valid evidence");

        assert_eq!(error, LiquidFeeAdapterError::InvalidObservationTime);
        assert_eq!(clock_calls.load(Ordering::SeqCst), 1);
        server.finish().await;
    }

    #[tokio::test]
    async fn observation_diagnostics_expose_no_endpoint() {
        let server = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.1}"#)).await;
        let observation = server
            .adapter(TEST_TIMEOUT)
            .observe()
            .await
            .expect("valid target-1 evidence must pass");
        let diagnostic = format!("{observation:?}");
        assert!(diagnostic.contains("ConfiguredTargetOneEstimate"));
        assert!(!diagnostic.contains(&server.base_endpoint));
        server.finish().await;
    }

    #[test]
    fn public_constructor_requires_secret_free_https_base_endpoint() {
        for endpoint in [
            "https://fees.example/api",
            "https://fees.example/api/",
            "https://[::1]:443/esplora",
        ] {
            assert!(LiquidEsploraTargetOneFeeAdapter::new(endpoint).is_ok());
        }
        for endpoint in [
            "http://fees.example/api",
            "https://user:secret@fees.example/api",
            "https://fees.example/api?token=secret",
            "https://fees.example/api#fragment",
            "https://fees.example:0/api",
            "not a URL",
        ] {
            let error = LiquidEsploraTargetOneFeeAdapter::new(endpoint)
                .err()
                .expect("unsafe endpoint must fail");
            assert_eq!(error, LiquidFeeAdapterError::InvalidEndpoint);
            for diagnostic in [format!("{error:?}"), error.to_string()] {
                assert!(!diagnostic.contains(endpoint));
                assert!(!diagnostic.contains("secret"));
                assert!(!diagnostic.contains("token"));
            }
        }
    }

    #[test]
    fn test_http_escape_hatch_accepts_only_literal_loopback_addresses() {
        assert!(
            LiquidEsploraTargetOneFeeAdapter::new_for_test_loopback_http(
                "http://127.0.0.1:3000/api",
                TEST_TIMEOUT,
            )
            .is_ok()
        );
        for endpoint in [
            "http://localhost:3000/api",
            "http://192.0.2.1:3000/api",
            "http://user:secret@127.0.0.1:3000/api",
        ] {
            assert_eq!(
                LiquidEsploraTargetOneFeeAdapter::new_for_test_loopback_http(
                    endpoint,
                    TEST_TIMEOUT,
                )
                .err(),
                Some(LiquidFeeAdapterError::InvalidEndpoint)
            );
        }
    }

    #[test]
    fn production_timeout_is_within_required_bounds() {
        assert!(
            (Duration::from_secs(1)..=Duration::from_secs(2)).contains(&REQUEST_TIMEOUT),
            "production Liquid fee timeout left 1-2s bound"
        );
    }
}

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

use crate::fee_policy::{
    FeeObservation, FeeObservationSource, FeePolicyError, FeeProvenance, SatPerVbyte,
};

const REQUEST_TIMEOUT: Duration = Duration::from_millis(1_500);
const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024;
pub const MAX_MEMPOOL_FEE_SOURCES: usize = 4;
// Four 1.5s per-source deadlines plus scheduling headroom. Production can
// therefore try every configured source while retaining a hard overall bound.
pub const MEMPOOL_FEE_ACQUISITION_TIMEOUT: Duration = Duration::from_secs(7);
const MAX_SOURCE_ID_BYTES: usize = 64;
const DEFAULT_SOURCE_ID: &str = "configured";
// This is a representation-safety limit, not an operational fee policy. The
// policy layer remains responsible for its independently configured bounds.
const MAX_REPRESENTABLE_FEE_SAT_PER_VBYTE: f64 = u32::MAX as f64;

/// A caller-assigned, non-secret identity for one configured fee source.
///
/// Identities are deliberately narrower than URLs: they are stable persistence
/// keys, never endpoint labels, and cannot carry credentials or log controls.
#[derive(Clone, PartialEq, Eq)]
pub struct MempoolFeeSourceIdentity(String);

impl MempoolFeeSourceIdentity {
    pub fn new(value: impl Into<String>) -> Result<Self, MempoolFeeAdapterError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_SOURCE_ID_BYTES
            && value.bytes().enumerate().all(|(index, byte)| match byte {
                b'a'..=b'z' | b'0'..=b'9' => true,
                b'-' | b'_' => index > 0,
                _ => false,
            });
        if !valid {
            return Err(MempoolFeeAdapterError::InvalidSourceIdentity);
        }
        Ok(Self(value))
    }

    /// Expose the sanitized stable key only at a persistence boundary.
    pub fn expose_for_persistence(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MempoolFeeSourceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MempoolFeeSourceIdentity(<redacted>)")
    }
}

/// A narrow client for the mempool-compatible Precise Fees endpoint.
///
/// Construction accepts only a credential-free HTTPS base endpoint. The
/// adapter deliberately does not choose fallbacks or make spending decisions.
#[derive(Clone)]
pub struct MempoolFastestFeeAdapter {
    client: reqwest::Client,
    precise_fees_url: Url,
    source_identity: MempoolFeeSourceIdentity,
}

impl MempoolFastestFeeAdapter {
    /// Builds an adapter for `<configured_https_endpoint>/v1/fees/precise`.
    pub fn new(configured_https_endpoint: &str) -> Result<Self, MempoolFeeAdapterError> {
        Self::new_with_source_identity(DEFAULT_SOURCE_ID, configured_https_endpoint)
    }

    /// Builds one explicitly named configured source.
    pub fn new_with_source_identity(
        source_identity: &str,
        configured_https_endpoint: &str,
    ) -> Result<Self, MempoolFeeAdapterError> {
        Self::build(
            configured_https_endpoint,
            MempoolFeeSourceIdentity::new(source_identity)?,
            REQUEST_TIMEOUT,
            false,
        )
    }

    /// Fetches and validates the endpoint's `fastestFee` and `minimumFee`.
    /// `fastestFee` remains the priority observation in sat/vByte.
    pub async fn observe(&self) -> Result<MempoolFastestFeeObservation, MempoolFeeAdapterError> {
        let mut response = self
            .client
            .get(self.precise_fees_url.clone())
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(map_request_error)?;

        if !response.status().is_success() {
            return Err(MempoolFeeAdapterError::UnexpectedStatus);
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if !matches!(content_type, Some(value) if value.eq_ignore_ascii_case("application/json")) {
            return Err(MempoolFeeAdapterError::UnexpectedContentType);
        }

        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BODY_BYTES as u64)
        {
            return Err(MempoolFeeAdapterError::ResponseTooLarge);
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
                .ok_or(MempoolFeeAdapterError::ResponseTooLarge)?;
            if next_length > MAX_RESPONSE_BODY_BYTES {
                return Err(MempoolFeeAdapterError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }

        let response: PreciseFeesResponse =
            serde_json::from_slice(&body).map_err(|_| MempoolFeeAdapterError::MalformedResponse)?;
        let fastest_fee_sat_per_vbyte = validate_representable_fee(
            response.fastest_fee,
            MempoolFeeAdapterError::InvalidFastestFee,
        )?;
        let minimum_fee_sat_per_vbyte = validate_representable_fee(
            response.minimum_fee,
            MempoolFeeAdapterError::InvalidMinimumFee,
        )?;
        if fastest_fee_sat_per_vbyte < minimum_fee_sat_per_vbyte {
            return Err(MempoolFeeAdapterError::InconsistentPreciseFees);
        }

        let observed_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MempoolFeeAdapterError::InvalidObservationTime)?
            .as_secs();

        Ok(MempoolFastestFeeObservation {
            fastest_fee_sat_per_vbyte,
            minimum_fee_sat_per_vbyte,
            observed_at: ObservedAtUnixSeconds(observed_at_unix),
            source: MempoolFeeObservationSource::ConfiguredPreciseFees,
            source_identity: self.source_identity.clone(),
        })
    }

    fn build(
        configured_endpoint: &str,
        source_identity: MempoolFeeSourceIdentity,
        timeout: Duration,
        allow_loopback_http: bool,
    ) -> Result<Self, MempoolFeeAdapterError> {
        let mut endpoint =
            Url::parse(configured_endpoint).map_err(|_| MempoolFeeAdapterError::InvalidEndpoint)?;

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
            return Err(MempoolFeeAdapterError::InvalidEndpoint);
        }

        endpoint
            .path_segments_mut()
            .map_err(|_| MempoolFeeAdapterError::InvalidEndpoint)?
            .pop_if_empty()
            .push("v1")
            .push("fees")
            .push("precise");
        let precise_fees_url = endpoint;

        let client = reqwest::Client::builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| MempoolFeeAdapterError::ClientInitialization)?;

        Ok(Self {
            client,
            precise_fees_url,
            source_identity,
        })
    }

    #[cfg(test)]
    fn new_for_test_loopback_http(
        configured_endpoint: &str,
        timeout: Duration,
    ) -> Result<Self, MempoolFeeAdapterError> {
        Self::new_for_test_loopback_http_with_identity(
            DEFAULT_SOURCE_ID,
            configured_endpoint,
            timeout,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_loopback_http_with_identity(
        source_identity: &str,
        configured_endpoint: &str,
        timeout: Duration,
    ) -> Result<Self, MempoolFeeAdapterError> {
        Self::build(
            configured_endpoint,
            MempoolFeeSourceIdentity::new(source_identity)?,
            timeout,
            true,
        )
    }
}

#[derive(Debug, Deserialize)]
struct PreciseFeesResponse {
    #[serde(rename = "fastestFee")]
    fastest_fee: serde_json::Number,
    #[serde(rename = "minimumFee")]
    minimum_fee: serde_json::Number,
}

fn validate_representable_fee(
    value: serde_json::Number,
    invalid_error: MempoolFeeAdapterError,
) -> Result<f64, MempoolFeeAdapterError> {
    value
        .as_f64()
        .filter(|fee| fee.is_finite() && *fee > 0.0 && *fee <= MAX_REPRESENTABLE_FEE_SAT_PER_VBYTE)
        .ok_or(invalid_error)
}

/// Timestamp attached only after a response has passed transport and schema
/// validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObservedAtUnixSeconds(u64);

impl ObservedAtUnixSeconds {
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Non-secret provenance for the validated observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolFeeObservationSource {
    ConfiguredPreciseFees,
}

impl MempoolFeeObservationSource {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::ConfiguredPreciseFees => "mempool_precise_fastest_fee",
        }
    }
}

/// A transport observation. Policy code must still decide whether and how to
/// use it.
#[derive(Debug, Clone, PartialEq)]
pub struct MempoolFastestFeeObservation {
    fastest_fee_sat_per_vbyte: f64,
    minimum_fee_sat_per_vbyte: f64,
    observed_at: ObservedAtUnixSeconds,
    source: MempoolFeeObservationSource,
    source_identity: MempoolFeeSourceIdentity,
}

impl MempoolFastestFeeObservation {
    pub const fn fastest_fee_sat_per_vbyte(&self) -> f64 {
        self.fastest_fee_sat_per_vbyte
    }

    pub const fn minimum_fee_sat_per_vbyte(&self) -> f64 {
        self.minimum_fee_sat_per_vbyte
    }

    pub const fn observed_at(&self) -> ObservedAtUnixSeconds {
        self.observed_at
    }

    pub const fn source(&self) -> MempoolFeeObservationSource {
        self.source
    }

    pub fn source_identity(&self) -> &MempoolFeeSourceIdentity {
        &self.source_identity
    }

    /// Convert validated transport evidence into the pure policy domain.
    ///
    /// This is a lossless units/time mapping only. Freshness, persisted-LKG
    /// selection, and economic-bound rejection remain policy responsibilities.
    pub fn try_into_policy_observation(self) -> Result<FeeObservation, FeePolicyError> {
        let provenance = format!(
            "{}:{}",
            self.source.stable_label(),
            self.source_identity.expose_for_persistence()
        );
        Ok(FeeObservation::new(
            SatPerVbyte::try_from(self.fastest_fee_sat_per_vbyte)?,
            self.observed_at.as_u64(),
            FeeObservationSource::LiveBitcoin,
            FeeProvenance::new(provenance)?,
        ))
    }
}

/// A bounded ordered set of explicitly configured precise-fee sources.
///
/// This helper performs one construction-time acquisition attempt. It neither
/// polls nor persists, and it has no constant or last-known-good fallback.
/// Returning `false` from `accept_quote` treats a transport-valid observation
/// as policy-rejected and advances to the next configured source.
#[derive(Clone)]
pub struct OrderedMempoolFeeSources {
    sources: Vec<MempoolFastestFeeAdapter>,
    acquisition_timeout: Duration,
}

impl OrderedMempoolFeeSources {
    pub fn new(sources: Vec<MempoolFastestFeeAdapter>) -> Result<Self, MempoolFeeAdapterError> {
        Self::build(sources, MEMPOOL_FEE_ACQUISITION_TIMEOUT)
    }

    fn build(
        sources: Vec<MempoolFastestFeeAdapter>,
        acquisition_timeout: Duration,
    ) -> Result<Self, MempoolFeeAdapterError> {
        if sources.is_empty() {
            return Err(MempoolFeeAdapterError::NoConfiguredSources);
        }
        if sources.len() > MAX_MEMPOOL_FEE_SOURCES {
            return Err(MempoolFeeAdapterError::TooManyConfiguredSources);
        }
        for (index, source) in sources.iter().enumerate() {
            if sources[..index]
                .iter()
                .any(|prior| prior.source_identity == source.source_identity)
            {
                return Err(MempoolFeeAdapterError::DuplicateSourceIdentity);
            }
        }

        Ok(Self {
            sources,
            acquisition_timeout,
        })
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Whether persisted provenance names this exact adapter contract and one
    /// of the currently configured source identities.
    pub(crate) fn authorizes_provenance(&self, provenance: &FeeProvenance) -> bool {
        let expected_prefix = MempoolFeeObservationSource::ConfiguredPreciseFees.stable_label();
        provenance
            .expose_for_persistence()
            .strip_prefix(expected_prefix)
            .and_then(|suffix| suffix.strip_prefix(':'))
            .is_some_and(|source_identity| {
                self.sources.iter().any(|source| {
                    source.source_identity.expose_for_persistence() == source_identity
                })
            })
    }

    pub async fn observe_first_acceptable<F>(
        &self,
        mut accept_quote: F,
    ) -> Result<MempoolFastestFeeObservation, MempoolFeeAdapterError>
    where
        F: FnMut(&MempoolFastestFeeObservation) -> bool,
    {
        let acquisition = async {
            for source in &self.sources {
                let observation = match source.observe().await {
                    Ok(observation) => observation,
                    Err(_) => continue,
                };
                if accept_quote(&observation) {
                    return Ok(observation);
                }
            }
            // This exact error means every configured source was attempted and
            // rejected. It is the only result from this helper after which a
            // caller may separately consider persisted last-known-good data.
            Err(MempoolFeeAdapterError::AllConfiguredSourcesFailed)
        };

        tokio::time::timeout(self.acquisition_timeout, acquisition)
            .await
            .unwrap_or(Err(MempoolFeeAdapterError::AcquisitionBudgetExhausted))
    }

    #[cfg(test)]
    fn new_for_test_budget(
        sources: Vec<MempoolFastestFeeAdapter>,
        acquisition_timeout: Duration,
    ) -> Result<Self, MempoolFeeAdapterError> {
        Self::build(sources, acquisition_timeout)
    }
}

/// Stable error categories intentionally omit URLs, bodies, and transport
/// internals so secrets cannot escape through logs or API responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolFeeAdapterError {
    InvalidEndpoint,
    InvalidSourceIdentity,
    DuplicateSourceIdentity,
    NoConfiguredSources,
    TooManyConfiguredSources,
    ClientInitialization,
    Timeout,
    Unavailable,
    UnexpectedStatus,
    UnexpectedContentType,
    ResponseTooLarge,
    MalformedResponse,
    InvalidFastestFee,
    InvalidMinimumFee,
    InconsistentPreciseFees,
    InvalidObservationTime,
    AllConfiguredSourcesFailed,
    AcquisitionBudgetExhausted,
}

impl fmt::Display for MempoolFeeAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEndpoint => "invalid fee endpoint",
            Self::InvalidSourceIdentity => "invalid fee source identity",
            Self::DuplicateSourceIdentity => "duplicate fee source identity",
            Self::NoConfiguredSources => "no fee sources configured",
            Self::TooManyConfiguredSources => "too many fee sources configured",
            Self::ClientInitialization => "fee client initialization failed",
            Self::Timeout => "fee endpoint timed out",
            Self::Unavailable => "fee endpoint unavailable",
            Self::UnexpectedStatus => "fee endpoint returned an unexpected status",
            Self::UnexpectedContentType => "fee endpoint returned unexpected content",
            Self::ResponseTooLarge => "fee endpoint response exceeded its size limit",
            Self::MalformedResponse => "fee endpoint response was malformed",
            Self::InvalidFastestFee => "fee endpoint returned an invalid fastest fee",
            Self::InvalidMinimumFee => "fee endpoint returned an invalid minimum fee",
            Self::InconsistentPreciseFees => "fee endpoint returned inconsistent precise fees",
            Self::InvalidObservationTime => "fee observation time was invalid",
            Self::AllConfiguredSourcesFailed => "all configured fee sources failed",
            Self::AcquisitionBudgetExhausted => "fee acquisition budget was exhausted",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MempoolFeeAdapterError {}

fn map_request_error(error: reqwest::Error) -> MempoolFeeAdapterError {
    if error.is_timeout() {
        MempoolFeeAdapterError::Timeout
    } else {
        MempoolFeeAdapterError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee_policy::{
        BitcoinFeePolicy, FeeFreshness, FeeObservation, FeeObservationRejection,
        FeeObservationSource, FeePolicyError, FeeProvenance, FeeRail, LiveBitcoin, SatPerVbyte,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
        task::JoinHandle,
    };

    const TEST_TIMEOUT: Duration = Duration::from_millis(250);

    struct FakeHttpResponse {
        status: &'static str,
        content_type: Option<&'static str>,
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
        fn adapter(&self, timeout: Duration) -> MempoolFastestFeeAdapter {
            MempoolFastestFeeAdapter::new_for_test_loopback_http(&self.base_endpoint, timeout)
                .expect("loopback fake endpoint must be valid")
        }

        fn named_adapter(
            &self,
            source_identity: &str,
            timeout: Duration,
        ) -> MempoolFastestFeeAdapter {
            MempoolFastestFeeAdapter::new_for_test_loopback_http_with_identity(
                source_identity,
                &self.base_endpoint,
                timeout,
            )
            .expect("named loopback fake endpoint must be valid")
        }

        async fn finish(self) -> String {
            let request = self
                .request_rx
                .await
                .expect("fake server must record one request");
            self.task.await.expect("fake server task must finish");
            request
        }

        async fn assert_uncontacted(mut self) {
            assert!(
                tokio::time::timeout(Duration::from_millis(25), &mut self.request_rx)
                    .await
                    .is_err(),
                "later source was contacted after an earlier source was accepted"
            );
            self.task.abort();
            let _ = self.task.await;
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

    async fn observe_error(body: &str) -> MempoolFeeAdapterError {
        let server = spawn_fake_http_server(FakeHttpResponse::json(body)).await;
        let result = server.adapter(TEST_TIMEOUT).observe().await;
        server.finish().await;
        result.expect_err("fixture must be rejected")
    }

    fn compose_live_observation(
        result: Result<MempoolFastestFeeObservation, MempoolFeeAdapterError>,
    ) -> Result<FeeObservation, MempoolFeeAdapterError> {
        result.map(|observation| {
            observation
                .try_into_policy_observation()
                .expect("an adapter-validated observation must satisfy the policy domain")
        })
    }

    fn explicit_last_known_good(rate: f64, observed_at_unix: u64) -> FeeObservation {
        FeeObservation::new(
            SatPerVbyte::try_from(rate).expect("fixture rate must be valid"),
            observed_at_unix,
            FeeObservationSource::BitcoinLastKnownGood,
            FeeProvenance::new("persisted-bitcoin-fee-row")
                .expect("fixture provenance must be valid"),
        )
    }

    #[tokio::test]
    async fn observes_fastest_fee_with_explicit_units_time_and_source() {
        let server = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":12.5,"halfHourFee":10.125,"hourFee":8.75,"economyFee":0.2,"minimumFee":0.1}"#,
        ))
        .await;
        let adapter = server.adapter(TEST_TIMEOUT);
        let before = unix_now();

        let observation = adapter.observe().await.expect("valid fee observation");
        let after = unix_now();

        assert_eq!(observation.fastest_fee_sat_per_vbyte(), 12.5);
        assert_eq!(observation.minimum_fee_sat_per_vbyte(), 0.1);
        assert!((before..=after).contains(&observation.observed_at().as_u64()));
        assert_eq!(
            observation.source(),
            MempoolFeeObservationSource::ConfiguredPreciseFees
        );
        assert_eq!(
            observation.source().stable_label(),
            "mempool_precise_fastest_fee"
        );
        assert_eq!(
            observation.source_identity().expose_for_persistence(),
            DEFAULT_SOURCE_ID
        );
        let observation_time = observation.observed_at().as_u64();
        let policy_observation = observation.try_into_policy_observation().unwrap();
        assert_eq!(policy_observation.rate().as_f64(), 12.5);
        assert_eq!(policy_observation.observed_at_unix(), observation_time);
        assert_eq!(
            policy_observation.source(),
            FeeObservationSource::LiveBitcoin
        );
        assert_eq!(
            policy_observation.provenance().expose_for_persistence(),
            "mempool_precise_fastest_fee:configured"
        );
        let policy_decision = crate::fee_policy::BitcoinFeePolicy::default()
            .decide(
                Some(&policy_observation),
                None,
                policy_observation.observed_at_unix(),
            )
            .unwrap();
        assert_eq!(policy_decision.rate(), policy_observation.rate());
        let request = server.finish().await;
        assert!(request.starts_with("GET /api/v1/fees/precise HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains("accept: application/json\r\n"));
    }

    #[test]
    fn configured_production_bases_append_only_the_exact_precise_route() {
        let configured = crate::config::FeePolicyConfig::default().bitcoin.sources;
        let expected = [
            (
                "bull-bitcoin",
                "https://mempool.bullbitcoin.com/api",
                "https://mempool.bullbitcoin.com/api/v1/fees/precise",
            ),
            (
                "mempool-space",
                "https://mempool.space/api",
                "https://mempool.space/api/v1/fees/precise",
            ),
        ];
        assert_eq!(configured.len(), expected.len());

        for (source, (expected_id, expected_base, expected_precise_url)) in
            configured.iter().zip(expected)
        {
            assert_eq!(source.id, expected_id);
            assert_eq!(source.endpoint, expected_base);
            let adapter = MempoolFastestFeeAdapter::new(&source.endpoint)
                .expect("configured production API base must be valid");
            assert_eq!(adapter.precise_fees_url.as_str(), expected_precise_url);
        }
    }

    #[tokio::test]
    async fn rejects_malformed_or_non_numeric_json() {
        for body in [
            "not-json",
            r#"{}"#,
            r#"[]"#,
            r#"{"fastestFee":12}"#,
            r#"{"minimumFee":1}"#,
            r#"{"fastestFee":"12","minimumFee":1}"#,
            r#"{"fastestFee":true,"minimumFee":1}"#,
            r#"{"fastestFee":null,"minimumFee":1}"#,
            r#"{"fastestFee":NaN,"minimumFee":1}"#,
            r#"{"fastestFee":1,"fastestFee":2,"minimumFee":1}"#,
            r#"{"fastestFee":12,"minimumFee":"1"}"#,
            r#"{"fastestFee":12,"minimumFee":true}"#,
            r#"{"fastestFee":12,"minimumFee":null}"#,
            r#"{"fastestFee":12,"minimumFee":NaN}"#,
        ] {
            assert_eq!(
                observe_error(body).await,
                MempoolFeeAdapterError::MalformedResponse,
                "body should fail strict schema validation: {body}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_zero_and_negative_fastest_fees() {
        for body in [
            r#"{"fastestFee":0,"minimumFee":1}"#,
            r#"{"fastestFee":-1,"minimumFee":1}"#,
        ] {
            assert_eq!(
                observe_error(body).await,
                MempoolFeeAdapterError::InvalidFastestFee
            );
        }
    }

    #[tokio::test]
    async fn rejects_overflow_and_extreme_fastest_fees() {
        assert_eq!(
            observe_error(r#"{"fastestFee":1e400,"minimumFee":1}"#).await,
            MempoolFeeAdapterError::MalformedResponse
        );
        assert_eq!(
            observe_error(r#"{"fastestFee":4294967296,"minimumFee":1}"#).await,
            MempoolFeeAdapterError::InvalidFastestFee
        );
    }

    #[tokio::test]
    async fn rejects_invalid_or_inconsistent_minimum_fee() {
        for body in [
            r#"{"fastestFee":12,"minimumFee":0}"#,
            r#"{"fastestFee":12,"minimumFee":-1}"#,
            r#"{"fastestFee":12,"minimumFee":4294967296}"#,
        ] {
            assert_eq!(
                observe_error(body).await,
                MempoolFeeAdapterError::InvalidMinimumFee
            );
        }
        assert_eq!(
            observe_error(r#"{"fastestFee":12,"minimumFee":1e400}"#).await,
            MempoolFeeAdapterError::MalformedResponse
        );
        assert_eq!(
            observe_error(r#"{"fastestFee":1.5,"minimumFee":2}"#).await,
            MempoolFeeAdapterError::InconsistentPreciseFees
        );

        let boundary = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":4294967295,"minimumFee":4294967295}"#,
        ))
        .await;
        let observation = boundary
            .adapter(TEST_TIMEOUT)
            .observe()
            .await
            .expect("largest representable equal fees must remain valid");
        assert_eq!(
            observation.fastest_fee_sat_per_vbyte(),
            MAX_REPRESENTABLE_FEE_SAT_PER_VBYTE
        );
        assert_eq!(
            observation.minimum_fee_sat_per_vbyte(),
            MAX_REPRESENTABLE_FEE_SAT_PER_VBYTE
        );
        boundary.finish().await;
    }

    #[tokio::test]
    async fn enforces_request_timeout() {
        let server = spawn_fake_http_server(FakeHttpResponse {
            delay: Duration::from_millis(100),
            ..FakeHttpResponse::json(br#"{"fastestFee":12,"minimumFee":1}"#)
        })
        .await;

        let error = server
            .adapter(Duration::from_millis(25))
            .observe()
            .await
            .expect_err("delayed endpoint must time out");

        assert_eq!(error, MempoolFeeAdapterError::Timeout);
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

            assert_eq!(error, MempoolFeeAdapterError::ResponseTooLarge);
            server.finish().await;
        }
    }

    #[tokio::test]
    async fn rejects_wrong_content_type_before_parsing_body() {
        let server = spawn_fake_http_server(FakeHttpResponse {
            content_type: Some("text/html"),
            ..FakeHttpResponse::json(br#"{"fastestFee":12,"minimumFee":1}"#)
        })
        .await;

        let error = server
            .adapter(TEST_TIMEOUT)
            .observe()
            .await
            .expect_err("wrong content type must fail");

        assert_eq!(error, MempoolFeeAdapterError::UnexpectedContentType);
        server.finish().await;
    }

    #[tokio::test]
    async fn reports_http_and_transport_unavailability_without_details() {
        let server = spawn_fake_http_server(FakeHttpResponse {
            status: "503 Service Unavailable",
            ..FakeHttpResponse::json(br#"{"error":"maintenance"}"#)
        })
        .await;
        let status_error = server
            .adapter(TEST_TIMEOUT)
            .observe()
            .await
            .expect_err("503 response must fail");
        assert_eq!(status_error, MempoolFeeAdapterError::UnexpectedStatus);
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
        assert_eq!(unavailable, MempoolFeeAdapterError::Unavailable);

        let diagnostic = unavailable.to_string();
        assert_eq!(diagnostic, "fee endpoint unavailable");
        server.finish().await;
    }

    #[tokio::test]
    async fn valid_fastest_fee_maps_losslessly_and_live_wins() {
        let server = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":12.125,"halfHourFee":10,"minimumFee":1}"#,
        ))
        .await;
        let adapter_observation = server
            .adapter(TEST_TIMEOUT)
            .observe()
            .await
            .expect("valid fastestFee must produce an adapter observation");
        let adapter_rate = adapter_observation.fastest_fee_sat_per_vbyte();
        let observed_at_unix = adapter_observation.observed_at().as_u64();
        let live = compose_live_observation(Ok(adapter_observation))
            .expect("validated adapter evidence must compose into policy evidence");
        let fallback = explicit_last_known_good(3.0, observed_at_unix);

        let decision = BitcoinFeePolicy::default()
            .decide(Some(&live), Some(&fallback), observed_at_unix)
            .expect("fresh live evidence must win over a fresh fallback");

        assert_eq!(adapter_rate, 12.125);
        assert_eq!(live.rate().as_f64(), adapter_rate);
        assert_eq!(live.observed_at_unix(), observed_at_unix);
        assert_eq!(live.source(), FeeObservationSource::LiveBitcoin);
        assert_eq!(decision.rate().as_f64(), adapter_rate);
        assert_eq!(decision.observed_rate().as_f64(), adapter_rate);
        assert_eq!(decision.observed_at_unix(), observed_at_unix);
        assert_eq!(decision.source(), FeeObservationSource::LiveBitcoin);
        assert_eq!(
            decision.freshness(),
            FeeFreshness::Fresh {
                age_secs: 0,
                max_age_secs: BitcoinFeePolicy::default().live_max_age_secs(),
            }
        );
        server.finish().await;
    }

    #[tokio::test]
    async fn policy_rejects_out_of_bounds_adapter_quotes_without_constructing_a_rate() {
        let policy = BitcoinFeePolicy::default();

        for quoted_rate in [0.125, 750.0] {
            let minimum_fee = if quoted_rate < 1.0 { 0.1 } else { 1.0 };
            let body = format!(r#"{{"fastestFee":{quoted_rate},"minimumFee":{minimum_fee}}}"#);
            let server = spawn_fake_http_server(FakeHttpResponse::json(body)).await;
            let adapter_observation = server
                .adapter(TEST_TIMEOUT)
                .observe()
                .await
                .expect("representable positive quote must pass the adapter");
            let live = compose_live_observation(Ok(adapter_observation))
                .expect("adapter evidence must compose into policy evidence");
            let observed_at_unix = live.observed_at_unix();
            let typed_live = LiveBitcoin::try_from_observation(live.clone())
                .expect("adapter evidence has the Bitcoin live source");

            assert_eq!(live.rate().as_f64(), quoted_rate);
            assert_eq!(
                live.provenance().expose_for_persistence(),
                "mempool_precise_fastest_fee:configured"
            );
            assert!(matches!(
                policy.decide_typed(Some(&typed_live), None, observed_at_unix),
                Err(FeePolicyError::TemporarilyUnavailable {
                    rail: FeeRail::Bitcoin,
                    live: FeeObservationRejection::OutsideBounds { rate, .. },
                    last_known_good: FeeObservationRejection::Missing,
                }) if rate.as_f64() == quoted_rate
            ));
            server.finish().await;
        }
    }

    #[test]
    fn configured_source_set_is_nonempty_bounded_unique_and_sanitized() {
        assert_eq!(
            OrderedMempoolFeeSources::new(Vec::new())
                .err()
                .expect("empty source set must fail"),
            MempoolFeeAdapterError::NoConfiguredSources
        );

        let too_many = (0..=MAX_MEMPOOL_FEE_SOURCES)
            .map(|index| {
                MempoolFastestFeeAdapter::new_with_source_identity(
                    &format!("source-{index}"),
                    "https://fees.example/api",
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            OrderedMempoolFeeSources::new(too_many)
                .err()
                .expect("oversized source set must fail"),
            MempoolFeeAdapterError::TooManyConfiguredSources
        );

        let duplicate = vec![
            MempoolFastestFeeAdapter::new_with_source_identity(
                "same-source",
                "https://one.example/api",
            )
            .unwrap(),
            MempoolFastestFeeAdapter::new_with_source_identity(
                "same-source",
                "https://two.example/api",
            )
            .unwrap(),
        ];
        assert_eq!(
            OrderedMempoolFeeSources::new(duplicate)
                .err()
                .expect("duplicate source identity must fail"),
            MempoolFeeAdapterError::DuplicateSourceIdentity
        );

        for identity in [
            "",
            "UPPERCASE",
            "-leading",
            "source/endpoint",
            "source\ncredential",
        ] {
            let error = MempoolFastestFeeAdapter::new_with_source_identity(
                identity,
                "https://fees.example/api",
            )
            .err()
            .expect("unsafe source identity must fail");
            assert_eq!(error, MempoolFeeAdapterError::InvalidSourceIdentity);
            assert_eq!(error.to_string(), "invalid fee source identity");
            if !identity.is_empty() {
                assert!(!error.to_string().contains(identity));
            }
        }
        let oversized = "x".repeat(MAX_SOURCE_ID_BYTES + 1);
        let error = MempoolFastestFeeAdapter::new_with_source_identity(
            &oversized,
            "https://fees.example/api",
        )
        .err()
        .expect("oversized source identity must fail");
        assert_eq!(error, MempoolFeeAdapterError::InvalidSourceIdentity);
        assert!(!error.to_string().contains(&oversized));
    }

    #[test]
    fn configured_source_set_authorizes_only_precise_provenance_from_a_current_identity() {
        let sources = OrderedMempoolFeeSources::new(vec![
            MempoolFastestFeeAdapter::new_with_source_identity(
                "primary",
                "https://one.example/api",
            )
            .unwrap(),
            MempoolFastestFeeAdapter::new_with_source_identity(
                "secondary",
                "https://two.example/api",
            )
            .unwrap(),
        ])
        .unwrap();

        for authorized in [
            "mempool_precise_fastest_fee:primary",
            "mempool_precise_fastest_fee:secondary",
        ] {
            assert!(sources.authorizes_provenance(&FeeProvenance::new(authorized).unwrap()));
        }
        for rejected in [
            "mempool_precise_fastest_fee:removed",
            "mempool_precise_fastest_fee:",
            "mempool_precise_fastest_fee:primary:extra",
            "legacy-bitcoin-route:primary",
        ] {
            assert!(!sources.authorizes_provenance(&FeeProvenance::new(rejected).unwrap()));
        }
    }

    #[tokio::test]
    async fn ordered_valid_sources_choose_first_even_when_later_quote_disagrees() {
        let primary = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":14,"minimumFee":1}"#,
        ))
        .await;
        let secondary = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":21,"minimumFee":2}"#,
        ))
        .await;
        let sources = OrderedMempoolFeeSources::new(vec![
            primary.named_adapter("primary", TEST_TIMEOUT),
            secondary.named_adapter("secondary", TEST_TIMEOUT),
        ])
        .unwrap();

        let observation = sources
            .observe_first_acceptable(|_| true)
            .await
            .expect("first valid configured source must win");

        assert_eq!(sources.len(), 2);
        assert!(!sources.is_empty());
        assert_eq!(observation.fastest_fee_sat_per_vbyte(), 14.0);
        assert_eq!(observation.minimum_fee_sat_per_vbyte(), 1.0);
        assert_eq!(
            observation.source_identity().expose_for_persistence(),
            "primary"
        );
        let observation_diagnostic = format!("{observation:?}");
        assert!(observation_diagnostic.contains("<redacted>"));
        assert!(!observation_diagnostic.contains("primary"));
        assert!(!observation_diagnostic.contains(&primary.base_endpoint));
        let policy_observation = observation
            .clone()
            .try_into_policy_observation()
            .expect("accepted source must map losslessly");
        assert_eq!(
            policy_observation.provenance().expose_for_persistence(),
            "mempool_precise_fastest_fee:primary"
        );
        assert!(!format!("{policy_observation:?}").contains("primary"));
        primary.finish().await;
        secondary.assert_uncontacted().await;
    }

    #[tokio::test]
    async fn schema_rejection_advances_to_next_ordered_source() {
        let inconsistent = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":1,"minimumFee":2}"#,
        ))
        .await;
        let valid = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":9.5,"minimumFee":1.25}"#,
        ))
        .await;
        let sources = OrderedMempoolFeeSources::new(vec![
            inconsistent.named_adapter("inconsistent", TEST_TIMEOUT),
            valid.named_adapter("valid", TEST_TIMEOUT),
        ])
        .unwrap();

        let observation = sources
            .observe_first_acceptable(|_| true)
            .await
            .expect("later schema-valid source must be tried");

        assert_eq!(observation.fastest_fee_sat_per_vbyte(), 9.5);
        assert_eq!(
            observation.source_identity().expose_for_persistence(),
            "valid"
        );
        inconsistent.finish().await;
        valid.finish().await;
    }

    #[tokio::test]
    async fn caller_policy_rejection_advances_without_clamping_or_fallback() {
        let unsafe_quote = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":750,"minimumFee":1}"#,
        ))
        .await;
        let safe_quote = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":15,"minimumFee":1}"#,
        ))
        .await;
        let sources = OrderedMempoolFeeSources::new(vec![
            unsafe_quote.named_adapter("unsafe", TEST_TIMEOUT),
            safe_quote.named_adapter("safe", TEST_TIMEOUT),
        ])
        .unwrap();

        let observation = sources
            .observe_first_acceptable(|quote| quote.fastest_fee_sat_per_vbyte() <= 500.0)
            .await
            .expect("policy rejection must advance to a safe live source");

        assert_eq!(observation.fastest_fee_sat_per_vbyte(), 15.0);
        assert_eq!(
            observation.source_identity().expose_for_persistence(),
            "safe"
        );
        unsafe_quote.finish().await;
        safe_quote.finish().await;
    }

    #[tokio::test]
    async fn per_source_timeout_advances_within_total_budget() {
        let slow = spawn_fake_http_server(FakeHttpResponse {
            delay: Duration::from_millis(100),
            ..FakeHttpResponse::json(br#"{"fastestFee":8,"minimumFee":1}"#)
        })
        .await;
        let healthy = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":11,"minimumFee":1}"#,
        ))
        .await;
        let sources = OrderedMempoolFeeSources::new_for_test_budget(
            vec![
                slow.named_adapter("slow", Duration::from_millis(25)),
                healthy.named_adapter("healthy", TEST_TIMEOUT),
            ],
            Duration::from_millis(200),
        )
        .unwrap();

        let observation = sources
            .observe_first_acceptable(|_| true)
            .await
            .expect("a timed-out source must not block the next source");

        assert_eq!(observation.fastest_fee_sat_per_vbyte(), 11.0);
        assert_eq!(
            observation.source_identity().expose_for_persistence(),
            "healthy"
        );
        slow.finish().await;
        healthy.finish().await;
    }

    #[tokio::test]
    async fn all_source_failures_return_one_fixed_sanitized_error() {
        let unavailable = spawn_fake_http_server(FakeHttpResponse {
            status: "503 Service Unavailable",
            ..FakeHttpResponse::json(br#"{"error":"private-body"}"#)
        })
        .await;
        let malformed = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":12,"minimumFee":0}"#,
        ))
        .await;
        let sources = OrderedMempoolFeeSources::new(vec![
            unavailable.named_adapter("private-primary", TEST_TIMEOUT),
            malformed.named_adapter("private-secondary", TEST_TIMEOUT),
        ])
        .unwrap();

        let error = sources
            .observe_first_acceptable(|_| true)
            .await
            .expect_err("all failed sources must not manufacture evidence");

        assert_eq!(error, MempoolFeeAdapterError::AllConfiguredSourcesFailed);
        let diagnostic = error.to_string();
        assert_eq!(diagnostic, "all configured fee sources failed");
        for secret in [
            "private-primary",
            "private-secondary",
            "private-body",
            &unavailable.base_endpoint,
            &malformed.base_endpoint,
        ] {
            assert!(!diagnostic.contains(secret));
        }
        unavailable.finish().await;
        malformed.finish().await;
    }

    #[tokio::test]
    async fn total_acquisition_budget_stops_before_later_sources() {
        let slow = spawn_fake_http_server(FakeHttpResponse {
            delay: Duration::from_millis(100),
            ..FakeHttpResponse::json(br#"{"fastestFee":8,"minimumFee":1}"#)
        })
        .await;
        let later = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":10,"minimumFee":1}"#,
        ))
        .await;
        let sources = OrderedMempoolFeeSources::new_for_test_budget(
            vec![
                slow.named_adapter("slow", TEST_TIMEOUT),
                later.named_adapter("later", TEST_TIMEOUT),
            ],
            Duration::from_millis(25),
        )
        .unwrap();

        let error = sources
            .observe_first_acceptable(|_| true)
            .await
            .expect_err("total acquisition budget must terminate the attempt");

        assert_eq!(error, MempoolFeeAdapterError::AcquisitionBudgetExhausted);
        assert_eq!(error.to_string(), "fee acquisition budget was exhausted");
        slow.finish().await;
        later.assert_uncontacted().await;
    }

    #[tokio::test]
    async fn adapter_failures_are_absent_and_only_explicit_fresh_lkg_rescues() {
        let invalid_server = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":0,"minimumFee":1}"#,
        ))
        .await;
        let invalid = invalid_server.adapter(TEST_TIMEOUT).observe().await;
        invalid_server.finish().await;

        let malformed_server = spawn_fake_http_server(FakeHttpResponse::json("not-json")).await;
        let malformed = malformed_server.adapter(TEST_TIMEOUT).observe().await;
        malformed_server.finish().await;

        let timeout_server = spawn_fake_http_server(FakeHttpResponse {
            delay: Duration::from_millis(100),
            ..FakeHttpResponse::json(br#"{"fastestFee":12,"minimumFee":1}"#)
        })
        .await;
        let timeout = timeout_server
            .adapter(Duration::from_millis(25))
            .observe()
            .await;
        timeout_server.finish().await;

        let policy = BitcoinFeePolicy::default();
        let now = 50_000;
        let fresh_lkg = explicit_last_known_good(4.0, now);
        let stale_lkg =
            explicit_last_known_good(4.0, now - policy.last_known_good_max_age_secs() - 1);
        for (adapter_result, expected_error) in [
            (invalid, MempoolFeeAdapterError::InvalidFastestFee),
            (malformed, MempoolFeeAdapterError::MalformedResponse),
            (timeout, MempoolFeeAdapterError::Timeout),
        ] {
            let composed = compose_live_observation(adapter_result);
            assert_eq!(composed.as_ref().unwrap_err(), &expected_error);
            let live = composed.ok();
            assert!(live.is_none(), "adapter failure became live evidence");
            assert!(matches!(
                policy.decide(live.as_ref(), None, now),
                Err(FeePolicyError::NoFreshBitcoinQuote {
                    live: None,
                    last_known_good: None,
                })
            ));
            assert!(matches!(
                policy.decide(live.as_ref(), Some(&stale_lkg), now),
                Err(FeePolicyError::NoFreshBitcoinQuote {
                    live: None,
                    last_known_good: Some(FeeFreshness::Stale { .. }),
                })
            ));

            let rescued = policy
                .decide(live.as_ref(), Some(&fresh_lkg), now)
                .expect("only explicit fresh LKG evidence may rescue an adapter failure");
            assert_eq!(rescued.source(), FeeObservationSource::BitcoinLastKnownGood);
            assert_eq!(rescued.rate().as_f64(), 4.0);
        }
    }

    #[tokio::test]
    async fn composed_provenance_is_explicitly_persistable_but_debug_redacted() {
        let server = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":8.5,"minimumFee":1}"#,
        ))
        .await;
        let live = compose_live_observation(server.adapter(TEST_TIMEOUT).observe().await)
            .expect("valid adapter evidence must compose");
        let decision = BitcoinFeePolicy::default()
            .decide(Some(&live), None, live.observed_at_unix())
            .expect("fresh live evidence must decide");
        let stable_label = "mempool_precise_fastest_fee:configured";

        assert_eq!(live.provenance().expose_for_persistence(), stable_label);
        assert_eq!(decision.provenance().expose_for_persistence(), stable_label);
        for diagnostic in [format!("{live:?}"), format!("{decision:?}")] {
            assert!(diagnostic.contains("<redacted>"));
            assert!(!diagnostic.contains(stable_label));
            assert!(!diagnostic.contains(&server.base_endpoint));
        }
        server.finish().await;
    }

    #[tokio::test]
    async fn future_and_stale_composed_live_evidence_fail_closed() {
        let server = spawn_fake_http_server(FakeHttpResponse::json(
            br#"{"fastestFee":6,"minimumFee":1}"#,
        ))
        .await;
        let live = compose_live_observation(server.adapter(TEST_TIMEOUT).observe().await)
            .expect("valid adapter evidence must compose");
        let policy = BitcoinFeePolicy::default();
        let observed_at_unix = live.observed_at_unix();
        let before_observation = observed_at_unix
            .checked_sub(1)
            .expect("wall-clock fixture must not be the Unix epoch");
        let after_freshness_window = observed_at_unix
            .checked_add(policy.live_max_age_secs() + 1)
            .expect("wall-clock fixture must leave room for the freshness window");

        assert!(matches!(
            policy.decide(Some(&live), None, before_observation),
            Err(FeePolicyError::NoFreshBitcoinQuote {
                live: Some(FeeFreshness::FromFuture {
                    lead_secs: 1,
                    max_age_secs,
                }),
                last_known_good: None,
            }) if max_age_secs == policy.live_max_age_secs()
        ));
        assert!(matches!(
            policy.decide(Some(&live), None, after_freshness_window),
            Err(FeePolicyError::NoFreshBitcoinQuote {
                live: Some(FeeFreshness::Stale {
                    age_secs,
                    max_age_secs,
                }),
                last_known_good: None,
            }) if age_secs == policy.live_max_age_secs() + 1
                && max_age_secs == policy.live_max_age_secs()
        ));
        server.finish().await;
    }

    #[test]
    fn public_constructor_requires_secret_free_https_base_endpoint() {
        assert!(MempoolFastestFeeAdapter::new("https://fees.example/api").is_ok());
        for endpoint in [
            "http://fees.example/api",
            "https://user:secret@fees.example/api",
            "https://fees.example/api?token=secret",
            "https://fees.example/api#fragment",
            "not a URL",
        ] {
            let error = MempoolFastestFeeAdapter::new(endpoint)
                .err()
                .expect("unsafe endpoint must fail");
            assert_eq!(error, MempoolFeeAdapterError::InvalidEndpoint);
            assert!(!error.to_string().contains(endpoint));
        }
    }

    #[test]
    fn production_timeout_is_within_required_bounds() {
        assert!(
            (Duration::from_secs(1)..=Duration::from_secs(2)).contains(&REQUEST_TIMEOUT),
            "production fee timeout left 1-2s bound"
        );
        assert!((1..=4).contains(&MAX_MEMPOOL_FEE_SOURCES));
        assert!(
            MEMPOOL_FEE_ACQUISITION_TIMEOUT
                > REQUEST_TIMEOUT * u32::try_from(MAX_MEMPOOL_FEE_SOURCES).unwrap()
        );
        assert!(MEMPOOL_FEE_ACQUISITION_TIMEOUT <= Duration::from_secs(8));
    }
}

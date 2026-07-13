use crate::liquid_fee_adapter::{
    LiquidEsploraTargetOneFeeAdapter, LiquidEsploraTargetOneFeeObservation,
};
use std::{collections::HashSet, error::Error, fmt, time::Duration};
use tokio::time::{timeout, Instant};

pub const MAX_LIQUID_FEE_SOURCES: usize = 4;
pub const MAX_LIQUID_FEE_SOURCE_ID_BYTES: usize = 64;
pub const MAX_LIQUID_FEE_ACQUISITION_BUDGET: Duration = Duration::from_secs(8);

/// A stable operator-selected source identifier.
///
/// IDs are deliberately narrower than arbitrary labels: lowercase ASCII
/// letters and digits for the first byte, then lowercase ASCII letters,
/// digits, `_`, and `-`. Ordinary diagnostics redact the value; callers must
/// explicitly use [`Self::stable_label`] when they need selected provenance.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LiquidFeeSourceId(String);

impl LiquidFeeSourceId {
    pub fn new(value: impl Into<String>) -> Result<Self, LiquidFeeSourcesBuildError> {
        let value = value.into();
        if !valid_source_id(&value) {
            return Err(LiquidFeeSourcesBuildError::InvalidSourceId);
        }
        Ok(Self(value))
    }

    pub fn stable_label(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for LiquidFeeSourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiquidFeeSourceId(<redacted>)")
    }
}

fn valid_source_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_LIQUID_FEE_SOURCE_ID_BYTES {
        return false;
    }
    let is_alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if !bytes.first().copied().is_some_and(is_alphanumeric) {
        return false;
    }
    bytes
        .iter()
        .skip(1)
        .copied()
        .all(|byte| is_alphanumeric(byte) || matches!(byte, b'_' | b'-'))
}

/// One ordered Liquid fee source and its dedicated single-observation adapter.
#[derive(Clone)]
pub struct LiquidFeeSource {
    id: LiquidFeeSourceId,
    adapter: LiquidEsploraTargetOneFeeAdapter,
}

impl LiquidFeeSource {
    pub fn new(
        id: impl Into<String>,
        configured_https_endpoint: &str,
    ) -> Result<Self, LiquidFeeSourcesBuildError> {
        let id = LiquidFeeSourceId::new(id)?;
        let adapter = LiquidEsploraTargetOneFeeAdapter::new(configured_https_endpoint)
            .map_err(|_| LiquidFeeSourcesBuildError::InvalidSourceEndpoint)?;
        Ok(Self { id, adapter })
    }

    pub fn from_adapter(id: LiquidFeeSourceId, adapter: LiquidEsploraTargetOneFeeAdapter) -> Self {
        Self { id, adapter }
    }

    pub fn id(&self) -> &LiquidFeeSourceId {
        &self.id
    }
}

impl fmt::Debug for LiquidFeeSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiquidFeeSource")
            .field("id", &self.id)
            .field("adapter", &"<redacted>")
            .finish()
    }
}

/// A validated source observation accepted by caller-owned policy evaluation.
pub struct SelectedLiquidFee<T> {
    source_id: LiquidFeeSourceId,
    observation: LiquidEsploraTargetOneFeeObservation,
    policy_value: T,
}

impl<T> SelectedLiquidFee<T> {
    pub fn source_id(&self) -> &LiquidFeeSourceId {
        &self.source_id
    }

    pub const fn observation(&self) -> LiquidEsploraTargetOneFeeObservation {
        self.observation
    }

    pub fn policy_value(&self) -> &T {
        &self.policy_value
    }

    pub fn into_policy_value(self) -> T {
        self.policy_value
    }
}

impl<T> fmt::Debug for SelectedLiquidFee<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedLiquidFee")
            .field("source_id", &self.source_id)
            .field("observation", &self.observation)
            .field("policy_value", &"<opaque>")
            .finish()
    }
}

/// An immutable, ordered set of bounded Liquid fee sources.
#[derive(Clone)]
pub struct LiquidFeeSources {
    sources: Vec<LiquidFeeSource>,
    overall_budget: Duration,
}

impl LiquidFeeSources {
    pub fn new(sources: Vec<LiquidFeeSource>) -> Result<Self, LiquidFeeSourcesBuildError> {
        Self::build(sources, MAX_LIQUID_FEE_ACQUISITION_BUDGET)
    }

    fn build(
        sources: Vec<LiquidFeeSource>,
        overall_budget: Duration,
    ) -> Result<Self, LiquidFeeSourcesBuildError> {
        if sources.is_empty() {
            return Err(LiquidFeeSourcesBuildError::NoSources);
        }
        if sources.len() > MAX_LIQUID_FEE_SOURCES {
            return Err(LiquidFeeSourcesBuildError::TooManySources);
        }
        if overall_budget.is_zero() || overall_budget > MAX_LIQUID_FEE_ACQUISITION_BUDGET {
            return Err(LiquidFeeSourcesBuildError::InvalidOverallBudget);
        }

        let mut seen = HashSet::with_capacity(sources.len());
        for source in &sources {
            if !seen.insert(source.id.stable_label()) {
                return Err(LiquidFeeSourcesBuildError::DuplicateSourceId);
            }
        }

        Ok(Self {
            sources,
            overall_budget,
        })
    }

    #[cfg(test)]
    fn new_with_budget_for_test(
        sources: Vec<LiquidFeeSource>,
        overall_budget: Duration,
    ) -> Result<Self, LiquidFeeSourcesBuildError> {
        Self::build(sources, overall_budget)
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Observe sources in their configured order until caller policy accepts
    /// one. Adapter and policy rejection are both local to that source and
    /// advance to the next source without inventing a quote.
    pub async fn acquire<T, F>(
        &self,
        mut evaluate: F,
    ) -> Result<SelectedLiquidFee<T>, LiquidFeeAcquisitionError>
    where
        F: FnMut(&LiquidFeeSourceId, LiquidEsploraTargetOneFeeObservation) -> Option<T>,
    {
        let deadline = Instant::now() + self.overall_budget;
        let last_index = self.sources.len() - 1;

        for (index, source) in self.sources.iter().enumerate() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(LiquidFeeAcquisitionError::BudgetExhausted)?;

            let observation = match timeout(remaining, source.adapter.observe()).await {
                Ok(Ok(observation)) => observation,
                Ok(Err(_)) => continue,
                Err(_) if index == last_index => {
                    return Err(LiquidFeeAcquisitionError::AllSourcesFailed);
                }
                Err(_) => return Err(LiquidFeeAcquisitionError::BudgetExhausted),
            };

            if let Some(policy_value) = evaluate(&source.id, observation) {
                return Ok(SelectedLiquidFee {
                    source_id: source.id.clone(),
                    observation,
                    policy_value,
                });
            }
        }

        Err(LiquidFeeAcquisitionError::AllSourcesFailed)
    }
}

impl fmt::Debug for LiquidFeeSources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiquidFeeSources")
            .field("source_count", &self.sources.len())
            .field("overall_budget", &self.overall_budget)
            .field("sources", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidFeeSourcesBuildError {
    NoSources,
    TooManySources,
    InvalidSourceId,
    DuplicateSourceId,
    InvalidSourceEndpoint,
    InvalidOverallBudget,
}

impl fmt::Display for LiquidFeeSourcesBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NoSources => "at least one Liquid fee source is required",
            Self::TooManySources => "too many Liquid fee sources",
            Self::InvalidSourceId => "invalid Liquid fee source identifier",
            Self::DuplicateSourceId => "duplicate Liquid fee source identifier",
            Self::InvalidSourceEndpoint => "invalid Liquid fee source endpoint",
            Self::InvalidOverallBudget => "invalid Liquid fee acquisition budget",
        };
        formatter.write_str(message)
    }
}

impl Error for LiquidFeeSourcesBuildError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidFeeAcquisitionError {
    AllSourcesFailed,
    BudgetExhausted,
}

impl fmt::Display for LiquidFeeAcquisitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AllSourcesFailed => "all Liquid fee sources failed",
            Self::BudgetExhausted => "Liquid fee acquisition budget exhausted",
        };
        formatter.write_str(message)
    }
}

impl Error for LiquidFeeAcquisitionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
        task::JoinHandle,
    };

    const TEST_ADAPTER_TIMEOUT: Duration = Duration::from_millis(1_500);

    struct FakeHttpResponse {
        status: &'static str,
        content_type: Option<&'static str>,
        close_without_response: bool,
        body: Vec<u8>,
        delay: Duration,
    }

    impl FakeHttpResponse {
        fn json(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: "200 OK",
                content_type: Some("application/json"),
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
        fn source(&self, id: &str, adapter_timeout: Duration) -> LiquidFeeSource {
            let id = LiquidFeeSourceId::new(id).expect("fixture source ID must be valid");
            let adapter = LiquidEsploraTargetOneFeeAdapter::new_for_test_loopback_http(
                &self.base_endpoint,
                adapter_timeout,
            )
            .expect("loopback fake endpoint must be valid");
            LiquidFeeSource::from_adapter(id, adapter)
        }

        async fn finish(self) -> String {
            let request = self
                .request_rx
                .await
                .expect("fake server must record one request");
            self.task.await.expect("fake server task must finish");
            request
        }

        async fn assert_not_requested(self) {
            let Self {
                request_rx, task, ..
            } = self;
            assert!(
                timeout(Duration::from_millis(50), request_rx)
                    .await
                    .is_err(),
                "later source unexpectedly received a request"
            );
            task.abort();
            let _ = task.await;
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
            let mut headers = format!(
                "HTTP/1.1 {}\r\nConnection: close\r\nContent-Length: {}\r\n",
                response.status,
                response.body.len()
            );
            if let Some(content_type) = response.content_type {
                headers.push_str(&format!("Content-Type: {content_type}\r\n"));
            }
            headers.push_str("\r\n");
            if stream.write_all(headers.as_bytes()).await.is_ok() {
                let _ = stream.write_all(&response.body).await;
            }
        });

        FakeHttpServer {
            base_endpoint: format!("http://{address}/esplora"),
            request_rx,
            task,
        }
    }

    fn inert_source(id: &str) -> LiquidFeeSource {
        LiquidFeeSource::new(id, "https://fees.example/esplora")
            .expect("fixture source must be valid")
    }

    #[test]
    fn source_ids_are_stable_sanitized_bounded_and_debug_redacted() {
        for valid in [
            "a",
            "primary",
            "liquid-main_1",
            "trailing-",
            "trailing_",
            &"a".repeat(MAX_LIQUID_FEE_SOURCE_ID_BYTES),
        ] {
            let id = LiquidFeeSourceId::new(valid).expect("sanitized ID must pass");
            assert_eq!(id.stable_label(), valid);
            let diagnostic = format!("{id:?}");
            assert_eq!(diagnostic, "LiquidFeeSourceId(<redacted>)");
        }

        for invalid in [
            "",
            "Uppercase",
            "contains space",
            "contains/slash",
            "unicode-é",
            "-leading",
            ".hidden",
            "liquid.esplora-2",
            &"a".repeat(MAX_LIQUID_FEE_SOURCE_ID_BYTES + 1),
        ] {
            let error =
                LiquidFeeSourceId::new(invalid).expect_err("unsanitized ID must be rejected");
            assert_eq!(error, LiquidFeeSourcesBuildError::InvalidSourceId);
            assert_eq!(format!("{error:?}"), "InvalidSourceId");
            assert_eq!(error.to_string(), "invalid Liquid fee source identifier");
        }
    }

    #[test]
    fn source_id_cross_shapes_match_the_runtime_configuration_contract() {
        for accepted in ["a", "a-", "a_", "a-b_", "9-source-"] {
            assert!(LiquidFeeSourceId::new(accepted).is_ok(), "ID={accepted}");
        }
        for rejected in ["-a", "_a", ".a", "a.", "a/b", "A-source"] {
            assert!(
                matches!(
                    LiquidFeeSourceId::new(rejected),
                    Err(LiquidFeeSourcesBuildError::InvalidSourceId)
                ),
                "ID={rejected}"
            );
        }
    }

    #[test]
    fn source_set_requires_one_to_four_unique_ids_and_at_most_eight_seconds() {
        assert!(matches!(
            LiquidFeeSources::new(Vec::new()),
            Err(LiquidFeeSourcesBuildError::NoSources)
        ));
        assert_eq!(MAX_LIQUID_FEE_SOURCES, 4);
        assert_eq!(MAX_LIQUID_FEE_ACQUISITION_BUDGET, Duration::from_secs(8));

        let four = (0..4)
            .map(|index| inert_source(&format!("source-{index}")))
            .collect();
        assert_eq!(LiquidFeeSources::new(four).unwrap().len(), 4);

        let five = (0..5)
            .map(|index| inert_source(&format!("source-{index}")))
            .collect();
        assert!(matches!(
            LiquidFeeSources::new(five),
            Err(LiquidFeeSourcesBuildError::TooManySources)
        ));

        assert!(matches!(
            LiquidFeeSources::new(vec![inert_source("same"), inert_source("same")]),
            Err(LiquidFeeSourcesBuildError::DuplicateSourceId)
        ));
        for invalid_budget in [
            Duration::ZERO,
            Duration::from_secs(8) + Duration::from_nanos(1),
        ] {
            assert!(matches!(
                LiquidFeeSources::new_with_budget_for_test(
                    vec![inert_source("primary")],
                    invalid_budget,
                ),
                Err(LiquidFeeSourcesBuildError::InvalidOverallBudget)
            ));
        }
    }

    #[test]
    fn source_and_set_diagnostics_redact_ids_endpoints_and_configuration_errors() {
        let id = "operator-secret-source";
        let endpoint = "https://fees.example/private-path";
        let source = LiquidFeeSource::new(id, endpoint).unwrap();
        let source_diagnostic = format!("{source:?}");
        assert!(source_diagnostic.contains("<redacted>"));
        assert!(!source_diagnostic.contains(id));
        assert!(!source_diagnostic.contains(endpoint));

        let sources = LiquidFeeSources::new(vec![source]).unwrap();
        let set_diagnostic = format!("{sources:?}");
        assert!(set_diagnostic.contains("<redacted>"));
        assert!(!set_diagnostic.contains(id));
        assert!(!set_diagnostic.contains(endpoint));

        let unsafe_endpoint = "https://user:secret@fees.example/private";
        let error = LiquidFeeSource::new("primary", unsafe_endpoint).unwrap_err();
        assert_eq!(error, LiquidFeeSourcesBuildError::InvalidSourceEndpoint);
        for diagnostic in [format!("{error:?}"), error.to_string()] {
            assert!(!diagnostic.contains(unsafe_endpoint));
            assert!(!diagnostic.contains("secret"));
        }
    }

    #[tokio::test]
    async fn preserves_order_and_policy_disagreement_advances_to_the_next_source() {
        let first = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.1}"#)).await;
        let second = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.2}"#)).await;
        let third = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.3}"#)).await;
        let sources = LiquidFeeSources::new(vec![
            first.source("first", TEST_ADAPTER_TIMEOUT),
            second.source("second", TEST_ADAPTER_TIMEOUT),
            third.source("third", TEST_ADAPTER_TIMEOUT),
        ])
        .unwrap();
        let mut evaluated = Vec::new();

        let selected = sources
            .acquire(|source_id, observation| {
                let rate = observation.target_one_fee_sat_per_vbyte();
                evaluated.push((source_id.stable_label().to_owned(), rate));
                (rate >= 0.3).then_some("accepted-policy-value")
            })
            .await
            .expect("third source must be accepted");

        assert_eq!(
            evaluated,
            vec![
                ("first".to_owned(), 0.1),
                ("second".to_owned(), 0.2),
                ("third".to_owned(), 0.3),
            ]
        );
        assert_eq!(selected.source_id().stable_label(), "third");
        assert_eq!(selected.observation().target_one_fee_sat_per_vbyte(), 0.3);
        assert_eq!(selected.policy_value(), &"accepted-policy-value");
        let diagnostic = format!("{selected:?}");
        assert!(diagnostic.contains("<redacted>"));
        assert!(diagnostic.contains("<opaque>"));
        assert!(!diagnostic.contains("third"));
        assert!(!diagnostic.contains("accepted-policy-value"));

        for request in [
            first.finish().await,
            second.finish().await,
            third.finish().await,
        ] {
            assert!(request.starts_with("GET /esplora/fee-estimates HTTP/1.1\r\n"));
        }
    }

    #[tokio::test]
    async fn schema_and_transport_failures_advance_without_policy_evaluation() {
        let malformed = spawn_fake_http_server(FakeHttpResponse::json("not-json")).await;
        let unavailable = spawn_fake_http_server(FakeHttpResponse {
            close_without_response: true,
            ..FakeHttpResponse::json(Vec::new())
        })
        .await;
        let valid = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.25}"#)).await;
        let sources = LiquidFeeSources::new(vec![
            malformed.source("malformed", TEST_ADAPTER_TIMEOUT),
            unavailable.source("unavailable", TEST_ADAPTER_TIMEOUT),
            valid.source("valid", TEST_ADAPTER_TIMEOUT),
        ])
        .unwrap();
        let mut policy_calls = 0;

        let selected = sources
            .acquire(|source_id, observation| {
                policy_calls += 1;
                assert_eq!(source_id.stable_label(), "valid");
                Some(observation.target_one_fee_sat_per_vbyte())
            })
            .await
            .expect("valid third source must recover acquisition");

        assert_eq!(policy_calls, 1);
        assert_eq!(selected.into_policy_value(), 0.25);
        malformed.finish().await;
        unavailable.finish().await;
        valid.finish().await;
    }

    #[tokio::test]
    async fn per_source_adapter_timeout_advances_to_the_next_source() {
        let slow = spawn_fake_http_server(FakeHttpResponse {
            delay: Duration::from_millis(100),
            ..FakeHttpResponse::json(br#"{"1":0.1}"#)
        })
        .await;
        let valid = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.2}"#)).await;
        let sources = LiquidFeeSources::new_with_budget_for_test(
            vec![
                slow.source("slow", Duration::from_millis(25)),
                valid.source("valid", TEST_ADAPTER_TIMEOUT),
            ],
            Duration::from_secs(1),
        )
        .unwrap();

        let selected = sources
            .acquire(|_, observation| Some(observation.target_one_fee_sat_per_vbyte()))
            .await
            .expect("second source must recover the first adapter timeout");

        assert_eq!(selected.source_id().stable_label(), "valid");
        assert_eq!(selected.into_policy_value(), 0.2);
        slow.finish().await;
        valid.finish().await;
    }

    #[tokio::test]
    async fn all_sources_failed_is_returned_only_after_every_source_is_attempted() {
        let malformed = spawn_fake_http_server(FakeHttpResponse::json("not-json")).await;
        let rejected = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.2}"#)).await;
        let unavailable = spawn_fake_http_server(FakeHttpResponse {
            close_without_response: true,
            ..FakeHttpResponse::json(Vec::new())
        })
        .await;
        let sources = LiquidFeeSources::new(vec![
            malformed.source("malformed", TEST_ADAPTER_TIMEOUT),
            rejected.source("rejected", TEST_ADAPTER_TIMEOUT),
            unavailable.source("unavailable", TEST_ADAPTER_TIMEOUT),
        ])
        .unwrap();
        let mut policy_calls = 0;

        let error = sources
            .acquire(|source_id, _| -> Option<()> {
                policy_calls += 1;
                assert_eq!(source_id.stable_label(), "rejected");
                None
            })
            .await
            .expect_err("every source must fail or be rejected");

        assert_eq!(error, LiquidFeeAcquisitionError::AllSourcesFailed);
        assert_eq!(policy_calls, 1);
        malformed.finish().await;
        rejected.finish().await;
        unavailable.finish().await;
    }

    #[tokio::test]
    async fn budget_exhaustion_stops_before_later_sources_are_attempted() {
        let slow = spawn_fake_http_server(FakeHttpResponse {
            delay: Duration::from_millis(100),
            ..FakeHttpResponse::json(br#"{"1":0.1}"#)
        })
        .await;
        let later = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.2}"#)).await;
        let sources = LiquidFeeSources::new_with_budget_for_test(
            vec![
                slow.source("slow", TEST_ADAPTER_TIMEOUT),
                later.source("later", TEST_ADAPTER_TIMEOUT),
            ],
            Duration::from_millis(25),
        )
        .unwrap();

        let error = sources
            .acquire(|_, observation| Some(observation))
            .await
            .expect_err("overall budget must prevent the later source attempt");

        assert_eq!(error, LiquidFeeAcquisitionError::BudgetExhausted);
        let diagnostic = error.to_string();
        assert_eq!(diagnostic, "Liquid fee acquisition budget exhausted");
        assert!(!diagnostic.contains("slow"));
        assert!(!diagnostic.contains("later"));
        slow.finish().await;
        later.assert_not_requested().await;
    }

    #[tokio::test]
    async fn budget_expiry_on_the_final_attempt_is_all_sources_failed() {
        let only = spawn_fake_http_server(FakeHttpResponse {
            delay: Duration::from_millis(100),
            ..FakeHttpResponse::json(br#"{"1":0.1}"#)
        })
        .await;
        let sources = LiquidFeeSources::new_with_budget_for_test(
            vec![only.source("only", TEST_ADAPTER_TIMEOUT)],
            Duration::from_millis(25),
        )
        .unwrap();

        let error = sources
            .acquire(|_, observation| Some(observation))
            .await
            .expect_err("the final bounded attempt must time out");

        assert_eq!(error, LiquidFeeAcquisitionError::AllSourcesFailed);
        only.finish().await;
    }

    #[tokio::test]
    async fn policy_rejection_of_every_valid_source_is_all_sources_failed() {
        let first = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.1}"#)).await;
        let second = spawn_fake_http_server(FakeHttpResponse::json(br#"{"1":0.2}"#)).await;
        let sources = LiquidFeeSources::new(vec![
            first.source("first", TEST_ADAPTER_TIMEOUT),
            second.source("second", TEST_ADAPTER_TIMEOUT),
        ])
        .unwrap();
        let mut seen = Vec::new();

        let error = sources
            .acquire(|source_id, observation| -> Option<()> {
                seen.push((
                    source_id.stable_label().to_owned(),
                    observation.target_one_fee_sat_per_vbyte(),
                ));
                None
            })
            .await
            .expect_err("caller policy rejects both sources");

        assert_eq!(error, LiquidFeeAcquisitionError::AllSourcesFailed);
        assert_eq!(
            seen,
            vec![("first".to_owned(), 0.1), ("second".to_owned(), 0.2)]
        );
        first.finish().await;
        second.finish().await;
    }
}

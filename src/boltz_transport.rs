//! Injectable Boltz transport and deterministic scripted fault harness.
//!
//! Production uses [`HttpBoltzTransport`]. Tests may inject
//! [`ScriptedBoltzTransport`] into [`crate::boltz::BoltzService`] so creation,
//! polling, quote, and acceptance calls cross the same typed boundary as live
//! traffic without opening a socket. Inbound webhook plans remain separate
//! from provider responses and are deliberately delivered through the real
//! HTTP handler by the integration target.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use boltz_client::error::Error as BoltzClientError;
use boltz_client::swaps::boltz::{
    BoltzApiClientV2, CreateChainRequest, CreateChainResponse, CreateReverseRequest,
    CreateReverseResponse, GetChainPairsResponse, GetReversePairsResponse, GetSwapResponse,
    HeightResponse, SwapRestoreResponse,
};
use boltz_client::util::secrets::SwapMasterKey;
use sha2::{Digest, Sha256};

use crate::boltz::{ChainSwapQuoteProviderError, ChainSwapQuoteProviderErrorKind};

/// Raw quote endpoint method retained at the transport boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoltzQuoteMethod {
    Get,
    Accept { amount_sat: u64 },
}

/// Status and body returned by the quote endpoint before protocol decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoltzQuoteHttpResponse {
    pub status: u16,
    pub body: String,
}

/// Every Boltz operation consumed by user-facing creation and reconciliation.
#[async_trait]
pub trait BoltzTransport: Send + Sync {
    async fn get_reverse_pairs(&self) -> Result<GetReversePairsResponse, BoltzClientError>;
    async fn get_chain_pairs(&self) -> Result<GetChainPairsResponse, BoltzClientError>;
    async fn get_height(&self) -> Result<HeightResponse, BoltzClientError>;
    async fn create_reverse(
        &self,
        request: CreateReverseRequest,
    ) -> Result<CreateReverseResponse, BoltzClientError>;
    /// Create the fixed-checkout reverse swap with the exact payer-pricing
    /// extension fields that are not represented by boltz-client's typed
    /// request. Keeping this operation on the shared boundary preserves the
    /// production JSON while making its network outcome injectable.
    async fn create_fixed_checkout_reverse(
        &self,
        request: CreateReverseRequest,
        onchain_amount_sat: u64,
        pair_hash: &str,
    ) -> Result<CreateReverseResponse, BoltzClientError>;
    async fn create_chain(
        &self,
        request: CreateChainRequest,
    ) -> Result<CreateChainResponse, BoltzClientError>;
    async fn get_swap(&self, swap_id: &str) -> Result<GetSwapResponse, BoltzClientError>;
    /// Fetch the bounded, high-water-checked xpub restore set. This is a
    /// positive reconciliation boundary, never proof that an absent create
    /// request was not accepted.
    async fn restore_swaps(
        &self,
        swap_master_key: &SwapMasterKey,
    ) -> Result<Vec<SwapRestoreResponse>, BoltzClientError>;
    async fn quote_request(
        &self,
        swap_id: &str,
        method: BoltzQuoteMethod,
    ) -> Result<BoltzQuoteHttpResponse, ChainSwapQuoteProviderError>;
}

/// Live HTTP implementation selected by the ordinary service constructor.
pub struct HttpBoltzTransport {
    api: BoltzApiClientV2,
    base_url: String,
    quote_client: reqwest::Client,
    restore_fetcher: Option<crate::boltz_restore_fetch::BoltzRestoreFetcher>,
}

impl HttpBoltzTransport {
    pub fn try_new(base_url: &str) -> Option<Self> {
        if !crate::config::valid_http_endpoint(base_url) {
            return None;
        }
        let quote_client = reqwest::Client::builder().build().ok()?;
        let api = BoltzApiClientV2::with_client(
            base_url.to_owned(),
            quote_client.clone(),
            Some(Duration::from_secs(10)),
        );
        Some(Self {
            api,
            base_url: base_url.to_owned(),
            quote_client,
            restore_fetcher: crate::boltz_restore_fetch::BoltzRestoreFetcher::new(base_url).ok(),
        })
    }
}

#[async_trait]
impl BoltzTransport for HttpBoltzTransport {
    async fn get_reverse_pairs(&self) -> Result<GetReversePairsResponse, BoltzClientError> {
        self.api.get_reverse_pairs().await
    }

    async fn get_chain_pairs(&self) -> Result<GetChainPairsResponse, BoltzClientError> {
        self.api.get_chain_pairs().await
    }

    async fn get_height(&self) -> Result<HeightResponse, BoltzClientError> {
        self.api.get_height().await
    }

    async fn create_reverse(
        &self,
        request: CreateReverseRequest,
    ) -> Result<CreateReverseResponse, BoltzClientError> {
        self.api.post_reverse_req(request).await
    }

    async fn create_fixed_checkout_reverse(
        &self,
        request: CreateReverseRequest,
        onchain_amount_sat: u64,
        pair_hash: &str,
    ) -> Result<CreateReverseResponse, BoltzClientError> {
        let mut request = serde_json::to_value(request).map_err(|error| {
            BoltzClientError::Protocol(format!(
                "failed to encode fixed-checkout reverse request: {error}"
            ))
        })?;
        let object = request.as_object_mut().ok_or_else(|| {
            BoltzClientError::Protocol(
                "fixed-checkout reverse request did not encode as an object".into(),
            )
        })?;
        object.insert(
            "onchainAmount".into(),
            serde_json::Value::from(onchain_amount_sat),
        );
        object.insert(
            "pairHash".into(),
            serde_json::Value::String(pair_hash.to_owned()),
        );
        let mut response = self
            .quote_client
            .post(format!(
                "{}/swap/reverse",
                self.base_url.trim_end_matches('/')
            ))
            .timeout(Duration::from_secs(10))
            .json(&request)
            .send()
            .await
            .map_err(|error| BoltzClientError::HTTP(error.to_string()))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() <= 128 && value.is_ascii())
            .unwrap_or("<missing-or-invalid>")
            .to_owned();
        const MAX_RESPONSE_BYTES: usize = 256 * 1024;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| BoltzClientError::HTTP(error.to_string()))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(BoltzClientError::Protocol(format!(
                    "fixed-checkout reverse response exceeded {MAX_RESPONSE_BYTES} bytes: status={status} content_type={content_type}"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let body_sha256 = hex::encode(Sha256::digest(&body));
        let (safe_keys, unknown_key_count) = safe_reverse_response_keys(&body);
        if !status.is_success() {
            return Err(BoltzClientError::HTTPStatusNotSuccess(
                status,
                serde_json::json!({
                    "error": "fixed-checkout reverse provider returned non-success",
                    "contentType": content_type,
                    "bodySize": body.len(),
                    "bodySha256": body_sha256,
                    "safeTopLevelKeys": safe_keys,
                    "unknownTopLevelKeyCount": unknown_key_count,
                }),
            ));
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&body);
        serde_path_to_error::deserialize::<_, CreateReverseResponse>(&mut deserializer).map_err(
            |error| {
                let inner = error.inner();
                let serde_error = match inner.classify() {
                    serde_json::error::Category::Io => "io",
                    serde_json::error::Category::Syntax => "syntax",
                    serde_json::error::Category::Data => "data",
                    serde_json::error::Category::Eof => "eof",
                };
                let path = safe_serde_path(&error.path().to_string());
                BoltzClientError::Protocol(format!(
                    "fixed-checkout reverse response was invalid: status={status} content_type={content_type} body_size={} body_sha256={body_sha256} serde_path={path} serde_error={serde_error}@{}:{} safe_top_level_keys=[{}] unknown_top_level_key_count={unknown_key_count}",
                    body.len(),
                    inner.line(),
                    inner.column(),
                    safe_keys.join(","),
                ))
            },
        )
    }

    async fn create_chain(
        &self,
        request: CreateChainRequest,
    ) -> Result<CreateChainResponse, BoltzClientError> {
        self.api.post_chain_req(request).await
    }

    async fn get_swap(&self, swap_id: &str) -> Result<GetSwapResponse, BoltzClientError> {
        self.api.get_swap(swap_id).await
    }

    async fn restore_swaps(
        &self,
        swap_master_key: &SwapMasterKey,
    ) -> Result<Vec<SwapRestoreResponse>, BoltzClientError> {
        let fetcher = self.restore_fetcher.as_ref().ok_or_else(|| {
            BoltzClientError::Generic("Boltz restore transport is unavailable".into())
        })?;
        fetcher
            .fetch_validated_records(swap_master_key)
            .await
            .map_err(|_| BoltzClientError::Generic("Boltz restore reconciliation failed".into()))
    }

    async fn quote_request(
        &self,
        swap_id: &str,
        method: BoltzQuoteMethod,
    ) -> Result<BoltzQuoteHttpResponse, ChainSwapQuoteProviderError> {
        let url = format!(
            "{}/swap/chain/{}/quote",
            self.base_url.trim_end_matches('/'),
            swap_id
        );
        let request = match method {
            BoltzQuoteMethod::Get => self.quote_client.get(url),
            BoltzQuoteMethod::Accept { amount_sat } => self
                .quote_client
                .post(url)
                .json(&serde_json::json!({ "amount": amount_sat })),
        }
        .timeout(Duration::from_secs(10));
        let response = request
            .send()
            .await
            .map_err(|error| ChainSwapQuoteProviderError {
                kind: if error.is_timeout() {
                    ChainSwapQuoteProviderErrorKind::Timeout
                } else {
                    ChainSwapQuoteProviderErrorKind::Transport
                },
                terminal_evidence_sha256: None,
            })?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .map_err(|_| ChainSwapQuoteProviderError {
                kind: ChainSwapQuoteProviderErrorKind::Transport,
                terminal_evidence_sha256: None,
            })?;
        Ok(BoltzQuoteHttpResponse { status, body })
    }
}

fn safe_reverse_response_keys(body: &[u8]) -> (Vec<&'static str>, usize) {
    const ALLOWED: &[&str] = &[
        "id",
        "invoice",
        "swapTree",
        "lockupAddress",
        "refundPublicKey",
        "timeoutBlockHeight",
        "onchainAmount",
        "blindingKey",
    ];
    let Ok(serde_json::Value::Object(object)) = serde_json::from_slice(body) else {
        return (Vec::new(), 0);
    };
    let mut found: Vec<_> = ALLOWED
        .iter()
        .copied()
        .filter(|key| object.contains_key(*key))
        .collect();
    found.sort_unstable();
    let unknown = object.len().saturating_sub(found.len());
    (found, unknown)
}

fn safe_serde_path(path: &str) -> String {
    if path.is_empty() {
        return "<root>".into();
    }
    if path.len() <= 128
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._[]".contains(&byte))
    {
        path.to_owned()
    } else {
        "<redacted>".into()
    }
}

/// Finite, reconstructible API errors for deterministic scripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptedBoltzError {
    Timeout,
    Transport,
    HttpStatus(u16),
    Protocol,
}

impl ScriptedBoltzError {
    fn into_client_error(self) -> BoltzClientError {
        match self {
            Self::Timeout => BoltzClientError::HTTP("scripted request timed out".into()),
            Self::Transport => BoltzClientError::HTTP("scripted error sending request".into()),
            Self::HttpStatus(status) => match reqwest::StatusCode::from_u16(status) {
                Ok(status) => BoltzClientError::HTTPStatusNotSuccess(
                    status,
                    serde_json::json!({ "error": "scripted status" }),
                ),
                Err(_) => BoltzClientError::Generic("invalid scripted HTTP status".into()),
            },
            Self::Protocol => BoltzClientError::Protocol("scripted protocol failure".into()),
        }
    }
}

/// Ordered provider operations. Each transport call consumes exactly one step.
#[derive(Debug)]
pub enum ScriptedBoltzStep {
    GetReversePairs(Result<GetReversePairsResponse, ScriptedBoltzError>),
    GetChainPairs(Result<GetChainPairsResponse, ScriptedBoltzError>),
    GetHeight(Result<HeightResponse, ScriptedBoltzError>),
    CreateReverse(Box<Result<CreateReverseResponse, ScriptedBoltzError>>),
    CreateFixedCheckoutReverse {
        onchain_amount_sat: u64,
        pair_hash: String,
        result: Box<Result<CreateReverseResponse, ScriptedBoltzError>>,
    },
    CreateChain(Box<Result<CreateChainResponse, ScriptedBoltzError>>),
    GetSwap {
        swap_id: String,
        result: Result<GetSwapResponse, ScriptedBoltzError>,
    },
    RestoreSwaps(Box<Result<Vec<SwapRestoreResponse>, ScriptedBoltzError>>),
    Quote {
        swap_id: String,
        result: Result<BoltzQuoteHttpResponse, ChainSwapQuoteProviderError>,
    },
    AcceptQuote {
        swap_id: String,
        amount_sat: u64,
        result: Result<BoltzQuoteHttpResponse, ChainSwapQuoteProviderError>,
    },
}

impl ScriptedBoltzStep {
    fn kind(&self) -> &'static str {
        match self {
            Self::GetReversePairs(_) => "get_reverse_pairs",
            Self::GetChainPairs(_) => "get_chain_pairs",
            Self::GetHeight(_) => "get_height",
            Self::CreateReverse(_) => "create_reverse",
            Self::CreateFixedCheckoutReverse { .. } => "create_fixed_checkout_reverse",
            Self::CreateChain(_) => "create_chain",
            Self::GetSwap { .. } => "get_swap",
            Self::RestoreSwaps(_) => "restore_swaps",
            Self::Quote { .. } => "quote",
            Self::AcceptQuote { .. } => "accept_quote",
        }
    }
}

/// Low-cardinality call evidence retained by a scripted transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedBoltzCall {
    GetReversePairs,
    GetChainPairs,
    GetHeight,
    CreateReverse {
        amount_sat: Option<u64>,
    },
    CreateFixedCheckoutReverse {
        onchain_amount_sat: u64,
        pair_hash: String,
    },
    CreateChain {
        server_lock_amount_sat: Option<u64>,
    },
    GetSwap {
        swap_id: String,
    },
    RestoreSwaps,
    Quote {
        swap_id: String,
    },
    AcceptQuote {
        swap_id: String,
        amount_sat: u64,
    },
}

/// Thread-safe one-shot script used by restart tests and worker harnesses.
pub struct ScriptedBoltzTransport {
    steps: Mutex<VecDeque<ScriptedBoltzStep>>,
    calls: Mutex<Vec<ScriptedBoltzCall>>,
}

impl ScriptedBoltzTransport {
    pub fn new(steps: impl IntoIterator<Item = ScriptedBoltzStep>) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<ScriptedBoltzCall> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn remaining_steps(&self) -> usize {
        self.steps
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    fn record(&self, call: ScriptedBoltzCall) {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(call);
    }

    fn next(&self, expected: &'static str) -> Result<ScriptedBoltzStep, BoltzClientError> {
        let step = self
            .steps
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .ok_or_else(|| {
                BoltzClientError::Generic(format!(
                    "scripted Boltz transport exhausted before {expected}"
                ))
            })?;
        if step.kind() != expected {
            return Err(BoltzClientError::Generic(format!(
                "scripted Boltz transport expected {expected}, found {}",
                step.kind()
            )));
        }
        Ok(step)
    }

    fn quote_next(
        &self,
        expected: &'static str,
    ) -> Result<ScriptedBoltzStep, ChainSwapQuoteProviderError> {
        self.next(expected)
            .map_err(|_| ChainSwapQuoteProviderError {
                kind: ChainSwapQuoteProviderErrorKind::Transport,
                terminal_evidence_sha256: None,
            })
    }
}

#[async_trait]
impl BoltzTransport for ScriptedBoltzTransport {
    async fn get_reverse_pairs(&self) -> Result<GetReversePairsResponse, BoltzClientError> {
        self.record(ScriptedBoltzCall::GetReversePairs);
        match self.next("get_reverse_pairs")? {
            ScriptedBoltzStep::GetReversePairs(result) => {
                result.map_err(ScriptedBoltzError::into_client_error)
            }
            _ => unreachable!("step kind checked"),
        }
    }

    async fn get_chain_pairs(&self) -> Result<GetChainPairsResponse, BoltzClientError> {
        self.record(ScriptedBoltzCall::GetChainPairs);
        match self.next("get_chain_pairs")? {
            ScriptedBoltzStep::GetChainPairs(result) => {
                result.map_err(ScriptedBoltzError::into_client_error)
            }
            _ => unreachable!("step kind checked"),
        }
    }

    async fn get_height(&self) -> Result<HeightResponse, BoltzClientError> {
        self.record(ScriptedBoltzCall::GetHeight);
        match self.next("get_height")? {
            ScriptedBoltzStep::GetHeight(result) => {
                result.map_err(ScriptedBoltzError::into_client_error)
            }
            _ => unreachable!("step kind checked"),
        }
    }

    async fn create_reverse(
        &self,
        request: CreateReverseRequest,
    ) -> Result<CreateReverseResponse, BoltzClientError> {
        self.record(ScriptedBoltzCall::CreateReverse {
            amount_sat: request.invoice_amount,
        });
        match self.next("create_reverse")? {
            ScriptedBoltzStep::CreateReverse(result) => {
                (*result).map_err(ScriptedBoltzError::into_client_error)
            }
            _ => unreachable!("step kind checked"),
        }
    }

    async fn create_fixed_checkout_reverse(
        &self,
        _request: CreateReverseRequest,
        onchain_amount_sat: u64,
        pair_hash: &str,
    ) -> Result<CreateReverseResponse, BoltzClientError> {
        self.record(ScriptedBoltzCall::CreateFixedCheckoutReverse {
            onchain_amount_sat,
            pair_hash: pair_hash.to_owned(),
        });
        match self.next("create_fixed_checkout_reverse")? {
            ScriptedBoltzStep::CreateFixedCheckoutReverse {
                onchain_amount_sat: expected_amount,
                pair_hash: expected_hash,
                result,
            } if expected_amount == onchain_amount_sat && expected_hash == pair_hash => {
                (*result).map_err(ScriptedBoltzError::into_client_error)
            }
            ScriptedBoltzStep::CreateFixedCheckoutReverse { .. } => Err(BoltzClientError::Generic(
                "scripted fixed-checkout request mismatch".into(),
            )),
            _ => unreachable!("step kind checked"),
        }
    }

    async fn create_chain(
        &self,
        request: CreateChainRequest,
    ) -> Result<CreateChainResponse, BoltzClientError> {
        self.record(ScriptedBoltzCall::CreateChain {
            server_lock_amount_sat: request.server_lock_amount,
        });
        match self.next("create_chain")? {
            ScriptedBoltzStep::CreateChain(result) => {
                (*result).map_err(ScriptedBoltzError::into_client_error)
            }
            _ => unreachable!("step kind checked"),
        }
    }

    async fn get_swap(&self, swap_id: &str) -> Result<GetSwapResponse, BoltzClientError> {
        self.record(ScriptedBoltzCall::GetSwap {
            swap_id: swap_id.to_owned(),
        });
        match self.next("get_swap")? {
            ScriptedBoltzStep::GetSwap {
                swap_id: expected,
                result,
            } if expected == swap_id => result.map_err(ScriptedBoltzError::into_client_error),
            ScriptedBoltzStep::GetSwap { .. } => Err(BoltzClientError::Generic(
                "scripted get_swap identity mismatch".into(),
            )),
            _ => unreachable!("step kind checked"),
        }
    }

    async fn restore_swaps(
        &self,
        _swap_master_key: &SwapMasterKey,
    ) -> Result<Vec<SwapRestoreResponse>, BoltzClientError> {
        self.record(ScriptedBoltzCall::RestoreSwaps);
        match self.next("restore_swaps")? {
            ScriptedBoltzStep::RestoreSwaps(result) => {
                (*result).map_err(ScriptedBoltzError::into_client_error)
            }
            _ => unreachable!("step kind checked"),
        }
    }

    async fn quote_request(
        &self,
        swap_id: &str,
        method: BoltzQuoteMethod,
    ) -> Result<BoltzQuoteHttpResponse, ChainSwapQuoteProviderError> {
        match method {
            BoltzQuoteMethod::Get => {
                self.record(ScriptedBoltzCall::Quote {
                    swap_id: swap_id.to_owned(),
                });
                match self.quote_next("quote")? {
                    ScriptedBoltzStep::Quote {
                        swap_id: expected,
                        result,
                    } if expected == swap_id => result,
                    ScriptedBoltzStep::Quote { .. } => Err(ChainSwapQuoteProviderError {
                        kind: ChainSwapQuoteProviderErrorKind::Transport,
                        terminal_evidence_sha256: None,
                    }),
                    _ => unreachable!("step kind checked"),
                }
            }
            BoltzQuoteMethod::Accept { amount_sat } => {
                self.record(ScriptedBoltzCall::AcceptQuote {
                    swap_id: swap_id.to_owned(),
                    amount_sat,
                });
                match self.quote_next("accept_quote")? {
                    ScriptedBoltzStep::AcceptQuote {
                        swap_id: expected,
                        amount_sat: expected_amount,
                        result,
                    } if expected == swap_id && expected_amount == amount_sat => result,
                    ScriptedBoltzStep::AcceptQuote { .. } => Err(ChainSwapQuoteProviderError {
                        kind: ChainSwapQuoteProviderErrorKind::Transport,
                        terminal_evidence_sha256: None,
                    }),
                    _ => unreachable!("step kind checked"),
                }
            }
        }
    }
}

/// One source event in a deterministic inbound webhook plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptedBoltzWebhookEvent {
    pub swap_id: String,
    pub status: String,
}

/// One delivery instruction. Missing source indexes are dropped, repeated
/// indexes are duplicates, and instruction order models reordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptedBoltzWebhookInstruction {
    pub event_index: usize,
    pub delay: Duration,
}

/// Materialized webhook delivery suitable for the real Axum webhook route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptedBoltzWebhookDelivery {
    pub delay: Duration,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptedBoltzWebhookPlanError {
    EventIndexOutOfBounds,
}

/// Deterministic dropped/duplicated/delayed/reordered webhook plan.
pub struct ScriptedBoltzWebhookPlan {
    events: Vec<ScriptedBoltzWebhookEvent>,
    instructions: Vec<ScriptedBoltzWebhookInstruction>,
}

impl ScriptedBoltzWebhookPlan {
    pub fn new(
        events: Vec<ScriptedBoltzWebhookEvent>,
        instructions: Vec<ScriptedBoltzWebhookInstruction>,
    ) -> Self {
        Self {
            events,
            instructions,
        }
    }

    pub fn into_deliveries(
        self,
    ) -> Result<Vec<ScriptedBoltzWebhookDelivery>, ScriptedBoltzWebhookPlanError> {
        self.instructions
            .into_iter()
            .map(|instruction| {
                let event = self
                    .events
                    .get(instruction.event_index)
                    .ok_or(ScriptedBoltzWebhookPlanError::EventIndexOutOfBounds)?;
                Ok(ScriptedBoltzWebhookDelivery {
                    delay: instruction.delay,
                    payload: serde_json::json!({
                        "event": "swap.update",
                        "data": {
                            "id": event.swap_id,
                            "status": event.status,
                        }
                    }),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod response_diagnostic_tests {
    use super::{safe_reverse_response_keys, safe_serde_path};

    #[test]
    fn response_diagnostics_never_copy_provider_values_or_unknown_key_names() {
        let body = br#"{"id":"secret-value","swapTree":{},"secret-in-key-name":"secret"}"#;
        let (keys, unknown) = safe_reverse_response_keys(body);
        assert_eq!(keys, vec!["id", "swapTree"]);
        assert_eq!(unknown, 1);
        assert!(!format!("{keys:?}").contains("secret"));
    }

    #[test]
    fn serde_paths_are_bounded_to_safe_field_syntax() {
        assert_eq!(safe_serde_path("swapTree.claimLeaf"), "swapTree.claimLeaf");
        assert_eq!(safe_serde_path("field\nsecret"), "<redacted>");
        assert_eq!(safe_serde_path(&"a".repeat(129)), "<redacted>");
    }
}

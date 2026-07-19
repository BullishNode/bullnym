use async_trait::async_trait;
use chrono::DateTime;
use lightning_invoice::{Bolt11Invoice, Currency};
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::{redirect::Policy, Client, StatusCode, Url};
use serde_json::Value;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use super::{
    BitcoinAmountSat, BitcoinNetwork, BullBitcoinApi, BullBitcoinError, CreateSellRequest,
    CreatedSellOrder, FiatAmountMinor, FiatCurrency, OrderObservation, PayerInstruction,
    ScopedApiKey,
};
use crate::config::BullBitcoinConfig;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RpcCallKind {
    EligibilityPreflight,
    CreateOrder,
    ReadOrder,
}

#[derive(Clone, Debug)]
pub struct HttpBullBitcoinApi {
    endpoint: Url,
    client: Client,
}

impl HttpBullBitcoinApi {
    pub fn new(config: &BullBitcoinConfig) -> Result<Self, BullBitcoinError> {
        let endpoint = Url::parse(&config.api_url).map_err(|_| BullBitcoinError::Transport)?;
        if endpoint.scheme() != "https" && !is_loopback_endpoint(&endpoint) {
            // This client always transmits a bearer secret. Plain HTTP is
            // reserved for an in-process/local deployment test endpoint.
            return Err(BullBitcoinError::Transport);
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .timeout(Duration::from_millis(config.request_timeout_ms))
            // Never forward the custom bearer header through an upstream
            // redirect. Endpoint changes are explicit operator config.
            .redirect(Policy::none())
            .build()
            .map_err(|_| BullBitcoinError::Transport)?;
        Ok(Self { endpoint, client })
    }

    async fn post_rpc(
        &self,
        key: &ScopedApiKey,
        body: String,
        call_kind: RpcCallKind,
    ) -> Result<Value, BullBitcoinError> {
        let api_key =
            HeaderValue::from_str(key.expose()).map_err(|_| BullBitcoinError::InvalidApiKey)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .header("X-API-Key", api_key)
            .body(body)
            .send()
            .await
            .map_err(classify_transport_error)?;
        let status = response.status();
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            return Err(BullBitcoinError::Authentication);
        }
        if status == StatusCode::NOT_FOUND {
            return Err(BullBitcoinError::NotFound);
        }
        if status.is_redirection() || status.is_server_error() {
            return Err(BullBitcoinError::Upstream);
        }
        if !status.is_success() {
            return Err(if call_kind == RpcCallKind::CreateOrder {
                BullBitcoinError::Policy
            } else {
                BullBitcoinError::Upstream
            });
        }

        let bytes = bounded_response_body(response).await?;
        let envelope: Value =
            serde_json::from_slice(&bytes).map_err(|_| BullBitcoinError::MalformedResponse)?;
        if let Some(error) = envelope.get("error").filter(|value| !value.is_null()) {
            return Err(classify_rpc_error(error, call_kind));
        }
        envelope
            .get("result")
            .cloned()
            .ok_or(BullBitcoinError::MalformedResponse)
    }
}

#[async_trait]
impl BullBitcoinApi for HttpBullBitcoinApi {
    async fn validate_sell_to_balance(
        &self,
        key: &ScopedApiKey,
        currency: FiatCurrency,
    ) -> Result<(), BullBitcoinError> {
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":\"bullnym\",\"method\":\"validateSellToBalance\",\"params\":{{\"fiatCurrency\":\"{}\"}}}}",
            currency.as_str(),
        );
        let result = self
            .post_rpc(key, body, RpcCallKind::EligibilityPreflight)
            .await?;
        match result.as_object() {
            Some(object)
                if object.len() == 1
                    && object.get("eligible").and_then(Value::as_bool) == Some(true) =>
            {
                Ok(())
            }
            _ => Err(BullBitcoinError::MalformedResponse),
        }
    }

    async fn create_sell_to_balance(
        &self,
        key: &ScopedApiKey,
        request: &CreateSellRequest,
    ) -> Result<CreatedSellOrder, BullBitcoinError> {
        if request.use_payjoin && request.network != BitcoinNetwork::Bitcoin {
            return Err(BullBitcoinError::Integrity);
        }
        let body = build_create_body(request);
        let result = self.post_rpc(key, body, RpcCallKind::CreateOrder).await?;
        parse_created_order(&result, request)
    }

    async fn get_created_order(
        &self,
        key: &ScopedApiKey,
        order_id: Uuid,
    ) -> Result<OrderObservation, BullBitcoinError> {
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":\"bullnym\",\"method\":\"getSellToFiatBalanceOrder\",\"params\":{{\"orderId\":\"{order_id}\"}}}}"
        );
        let result = self.post_rpc(key, body, RpcCallKind::ReadOrder).await?;
        let order = result.get("element").unwrap_or(&result);
        let observation = parse_order_observation(order)?;
        if observation.order_id != order_id {
            return Err(BullBitcoinError::Integrity);
        }
        Ok(observation)
    }
}

fn build_create_body(request: &CreateSellRequest) -> String {
    let payjoin = if request.use_payjoin {
        ",\"usePayjoin\":true"
    } else {
        ""
    };
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":\"bullnym\",\"method\":\"sellToBalance\",\"params\":{{\"bitcoinAmount\":{},\"bitcoinNetwork\":\"{}\",\"fiatCurrency\":\"{}\"{payjoin}}}}}",
        request.bitcoin_amount.btc_json_number(),
        request.network.as_str(),
        request.currency.as_str(),
    )
}

async fn bounded_response_body(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, BullBitcoinError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(BullBitcoinError::MalformedResponse);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(classify_transport_error)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(BullBitcoinError::MalformedResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn classify_transport_error(error: reqwest::Error) -> BullBitcoinError {
    if error.is_timeout() {
        BullBitcoinError::Timeout
    } else {
        BullBitcoinError::Transport
    }
}

fn classify_rpc_error(error: &Value, call_kind: RpcCallKind) -> BullBitcoinError {
    if call_kind == RpcCallKind::EligibilityPreflight
        && error.pointer("/data/apiError/code").and_then(Value::as_str)
            == Some("SELL_TO_BALANCE_KYC_REQUIRED")
    {
        return BullBitcoinError::BenchmarkEligibilityDenied;
    }
    // API-Orders intentionally hides a method when the authenticated key does
    // not carry its permission. This method is a required part of the pinned
    // Bullnym/API-Orders release contract, so MethodNotFound on the preflight
    // is a wrong-scope credential result. Reads retain their legacy mapping.
    if call_kind == RpcCallKind::EligibilityPreflight
        && error.get("code").and_then(Value::as_i64) == Some(-32601)
    {
        return BullBitcoinError::Authentication;
    }
    if let Some(operator) = error
        .pointer("/data/reason/limit/conditionalOperator")
        .and_then(Value::as_str)
    {
        return match operator {
            "GREATER_THAN" | "GREATER_THAN_OR_EQUAL" => BullBitcoinError::Minimum,
            "LESS_THAN" | "LESS_THAN_OR_EQUAL" => BullBitcoinError::Maximum,
            _ => BullBitcoinError::Policy,
        };
    }
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if message.contains("not found") || message.trim() == "404" {
        BullBitcoinError::NotFound
    } else if message.contains("api key")
        || message.contains("unauthorized")
        || message.contains("permission")
        || message.contains("forbidden")
    {
        BullBitcoinError::Authentication
    } else if call_kind == RpcCallKind::CreateOrder {
        BullBitcoinError::Policy
    } else {
        BullBitcoinError::Upstream
    }
}

fn parse_created_order(
    order: &Value,
    request: &CreateSellRequest,
) -> Result<CreatedSellOrder, BullBitcoinError> {
    let order_id = parse_uuid_field(order, "orderId")?;
    let currency = parse_currency_field(order, "payoutCurrency")?;
    if currency != request.currency {
        return Err(BullBitcoinError::Integrity);
    }
    let requested_bitcoin = parse_bitcoin_field(order, "payinAmount")?;
    if requested_bitcoin != request.bitcoin_amount {
        return Err(BullBitcoinError::Integrity);
    }
    let instruction = parse_instruction(order, request.network, request.bitcoin_amount)?;
    let deadline = required_string(order, "confirmationDeadline")?;
    let expires_at_unix = DateTime::parse_from_rfc3339(deadline)
        .map_err(|_| BullBitcoinError::MalformedResponse)?
        .timestamp();
    if expires_at_unix <= chrono::Utc::now().timestamp() {
        return Err(BullBitcoinError::Integrity);
    }
    Ok(CreatedSellOrder {
        order_id,
        currency,
        network: request.network,
        requested_bitcoin,
        instruction,
        expires_at_unix: Some(expires_at_unix),
    })
}

fn parse_order_observation(order: &Value) -> Result<OrderObservation, BullBitcoinError> {
    let order_id = parse_uuid_field(order, "orderId")?;
    let currency = parse_currency_field(order, "payoutCurrency")?;
    let order_status = safe_status(order, "orderStatus")?;
    let payin_status = safe_status(order, "payinStatus")?;
    let payout_status = safe_status(order, "payoutStatus")?;

    let changed_received = order
        .pointer("/payinAmountChanged/receivedAmount")
        .filter(|value| !value.is_null())
        .map(parse_bitcoin_value)
        .transpose()?;
    let payment_observed = matches!(
        payin_status.as_str(),
        "In progress" | "Under review" | "Awaiting confirmation" | "Completed"
    );
    let actual_received_sat = match changed_received {
        Some(amount) => Some(amount.as_sat()),
        None if payment_observed => Some(parse_bitcoin_field(order, "payinAmount")?.as_sat()),
        None => None,
    };
    let credited_fiat_minor = if payout_status == "Completed" {
        Some(parse_fiat_field(order, "payoutAmount")?)
    } else {
        None
    };
    let provider_final = order_status == "Completed"
        && payin_status == "Completed"
        && payout_status == "Completed"
        && credited_fiat_minor.is_some();

    Ok(OrderObservation {
        order_id,
        currency,
        order_status,
        payin_status,
        payout_status,
        actual_received_sat,
        credited_fiat_minor,
        provider_final,
    })
}

fn parse_instruction(
    order: &Value,
    network: BitcoinNetwork,
    amount: BitcoinAmountSat,
) -> Result<PayerInstruction, BullBitcoinError> {
    match network {
        BitcoinNetwork::Bitcoin => {
            let bip21 = order
                .get("bip21URI")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty());
            let instruction = bip21
                .or_else(|| order.get("bitcoinAddress").and_then(Value::as_str))
                .ok_or(BullBitcoinError::MalformedResponse)?;
            validate_text(instruction, 1, 2_048)?;
            let address = instruction
                .strip_prefix("bitcoin:")
                .unwrap_or(instruction)
                .split('?')
                .next()
                .ok_or(BullBitcoinError::MalformedResponse)?;
            bitcoin::Address::from_str(address)
                .map_err(|_| BullBitcoinError::MalformedResponse)?
                .require_network(bitcoin::Network::Bitcoin)
                .map_err(|_| BullBitcoinError::MalformedResponse)?;
            if let Some(bip21) = bip21 {
                validate_bip21_amount(bip21, amount)?;
            }
            Ok(PayerInstruction::Bitcoin {
                address_or_bip21: instruction.to_owned(),
            })
        }
        BitcoinNetwork::Lightning => {
            let bolt11 = required_string(order, "lightningInvoice")?;
            validate_text(bolt11, 1, 4_096)?;
            let invoice =
                Bolt11Invoice::from_str(bolt11).map_err(|_| BullBitcoinError::MalformedResponse)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| BullBitcoinError::Integrity)?;
            if invoice.currency() != Currency::Bitcoin
                || invoice.amount_milli_satoshis() != Some(amount.as_sat() as u64 * 1_000)
                || invoice
                    .expires_at()
                    .is_none_or(|expires_at| expires_at <= now)
            {
                return Err(BullBitcoinError::Integrity);
            }
            Ok(PayerInstruction::Lightning {
                bolt11: bolt11.to_owned(),
            })
        }
        BitcoinNetwork::Liquid => {
            let address = required_string(order, "liquidAddress")?;
            validate_text(address, 1, 256)?;
            let parsed = elements_miniscript::elements::Address::from_str(address)
                .map_err(|_| BullBitcoinError::MalformedResponse)?;
            if !parsed.is_blinded()
                || parsed.params != &elements_miniscript::elements::AddressParams::LIQUID
            {
                return Err(BullBitcoinError::Integrity);
            }
            Ok(PayerInstruction::Liquid {
                confidential_address: address.to_owned(),
            })
        }
    }
}

fn validate_bip21_amount(
    instruction: &str,
    expected: BitcoinAmountSat,
) -> Result<(), BullBitcoinError> {
    let uri = Url::parse(instruction).map_err(|_| BullBitcoinError::MalformedResponse)?;
    if uri.scheme() != "bitcoin" {
        return Err(BullBitcoinError::MalformedResponse);
    }
    let amounts: Vec<_> = uri
        .query_pairs()
        .filter_map(|(name, value)| (name == "amount").then_some(value))
        .collect();
    if amounts.len() != 1 {
        return Err(BullBitcoinError::Integrity);
    }
    let amount = BitcoinAmountSat::parse_json_decimal(&amounts[0])
        .map_err(|_| BullBitcoinError::Integrity)?;
    if amount != expected {
        return Err(BullBitcoinError::Integrity);
    }
    Ok(())
}

fn is_loopback_endpoint(endpoint: &Url) -> bool {
    endpoint.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

fn parse_uuid_field(value: &Value, field: &str) -> Result<Uuid, BullBitcoinError> {
    Uuid::parse_str(required_string(value, field)?).map_err(|_| BullBitcoinError::MalformedResponse)
}

fn parse_currency_field(value: &Value, field: &str) -> Result<FiatCurrency, BullBitcoinError> {
    FiatCurrency::from_str(required_string(value, field)?)
        .map_err(|_| BullBitcoinError::MalformedResponse)
}

fn parse_bitcoin_field(value: &Value, field: &str) -> Result<BitcoinAmountSat, BullBitcoinError> {
    let value = value
        .get(field)
        .ok_or(BullBitcoinError::MalformedResponse)?;
    parse_bitcoin_value(value)
}

fn parse_bitcoin_value(value: &Value) -> Result<BitcoinAmountSat, BullBitcoinError> {
    let number = value
        .as_number()
        .ok_or(BullBitcoinError::MalformedResponse)?;
    BitcoinAmountSat::parse_json_decimal(&number.to_string())
        .map_err(|_| BullBitcoinError::MalformedResponse)
}

fn parse_fiat_field(value: &Value, field: &str) -> Result<FiatAmountMinor, BullBitcoinError> {
    let number = value
        .get(field)
        .and_then(Value::as_number)
        .ok_or(BullBitcoinError::MalformedResponse)?;
    FiatAmountMinor::parse_json_decimal(&number.to_string())
        .map_err(|_| BullBitcoinError::MalformedResponse)
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, BullBitcoinError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(BullBitcoinError::MalformedResponse)
}

fn safe_status(value: &Value, field: &str) -> Result<String, BullBitcoinError> {
    let status = required_string(value, field)?;
    validate_text(status, 1, 64)?;
    Ok(status.to_owned())
}

fn validate_text(value: &str, minimum: usize, maximum: usize) -> Result<(), BullBitcoinError> {
    if value.len() < minimum || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(BullBitcoinError::MalformedResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    const BTC_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Option<(HeaderMap, Value)>>>);

    async fn fake_api(
        State(capture): State<Capture>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let is_validation =
            body.get("method").and_then(Value::as_str) == Some("validateSellToBalance");
        *capture.0.lock().await = Some((headers, body));
        let result = if is_validation {
            serde_json::json!({"eligible": true})
        } else {
            serde_json::json!({
                "orderId": "11111111-1111-4111-8111-111111111111",
                "payinAmount": 0.001,
                "payoutAmount": 50.25,
                "payoutCurrency": "CAD",
                "orderStatus": "In progress",
                "payinStatus": "Awaiting payment",
                "payoutStatus": "Not started",
                "bitcoinAddress": BTC_ADDRESS,
                "confirmationDeadline": "2099-07-19T12:00:00Z"
            })
        };
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "bullnym",
            "result": result
        }))
    }

    async fn client_for_app(
        app: Router,
        request_timeout_ms: u64,
    ) -> (HttpBullBitcoinApi, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = BullBitcoinConfig {
            api_url: format!("http://{address}/ak/api-orders"),
            request_timeout_ms,
            ..BullBitcoinConfig::default()
        };
        (HttpBullBitcoinApi::new(&config).unwrap(), task)
    }

    async fn test_client() -> (HttpBullBitcoinApi, Capture, tokio::task::JoinHandle<()>) {
        let capture = Capture::default();
        let app = Router::new()
            .route("/ak/api-orders", post(fake_api))
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = BullBitcoinConfig {
            api_url: format!("http://{address}/ak/api-orders"),
            ..BullBitcoinConfig::default()
        };
        (HttpBullBitcoinApi::new(&config).unwrap(), capture, task)
    }

    fn key() -> ScopedApiKey {
        ScopedApiKey::parse(format!("bbak-{}", "ab".repeat(32))).unwrap()
    }

    #[tokio::test]
    async fn create_call_is_exactly_scoped_and_uses_x_api_key() {
        let (client, capture, task) = test_client().await;
        let request = CreateSellRequest {
            currency: FiatCurrency::CAD,
            network: BitcoinNetwork::Bitcoin,
            bitcoin_amount: BitcoinAmountSat::new(100_000).unwrap(),
            use_payjoin: true,
        };
        let created = client
            .create_sell_to_balance(&key(), &request)
            .await
            .unwrap();
        assert_eq!(created.requested_bitcoin.as_sat(), 100_000);
        assert!(matches!(
            created.instruction,
            PayerInstruction::Bitcoin { .. }
        ));

        let (headers, body) = capture.0.lock().await.take().unwrap();
        assert_eq!(headers.get("x-api-key").unwrap(), key().expose());
        assert_eq!(body["method"], "sellToBalance");
        assert_eq!(body["params"]["bitcoinAmount"], 0.001);
        assert_eq!(body["params"]["bitcoinNetwork"], "bitcoin");
        assert_eq!(body["params"]["fiatCurrency"], "CAD");
        assert_eq!(body["params"]["usePayjoin"], true);
        assert!(body["params"].get("fiatAmount").is_none());
        task.abort();
    }

    #[tokio::test]
    async fn eligibility_call_is_minimal_and_uses_the_scoped_key() {
        let (client, capture, task) = test_client().await;
        for currency in FiatCurrency::ALL {
            client
                .validate_sell_to_balance(&key(), currency)
                .await
                .unwrap();

            let (headers, body) = capture.0.lock().await.take().unwrap();
            assert_eq!(headers.get("x-api-key").unwrap(), key().expose());
            assert_eq!(body["method"], "validateSellToBalance");
            assert_eq!(
                body["params"],
                serde_json::json!({"fiatCurrency": currency.as_str()})
            );
        }
        task.abort();
    }

    #[tokio::test]
    async fn eligibility_denial_auth_and_upstream_failures_remain_distinct() {
        async fn denied() -> Json<Value> {
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "bullnym",
                "error": {
                    "code": -32602,
                    "message": "eligibility denied",
                    "data": {"apiError": {"code": "SELL_TO_BALANCE_KYC_REQUIRED"}}
                }
            }))
        }
        let (client, task) =
            client_for_app(Router::new().route("/ak/api-orders", post(denied)), 1_000).await;
        assert_eq!(
            client
                .validate_sell_to_balance(&key(), FiatCurrency::CAD)
                .await,
            Err(BullBitcoinError::BenchmarkEligibilityDenied)
        );
        task.abort();

        async fn unauthorized() -> StatusCode {
            StatusCode::UNAUTHORIZED
        }
        let (client, task) = client_for_app(
            Router::new().route("/ak/api-orders", post(unauthorized)),
            1_000,
        )
        .await;
        assert_eq!(
            client
                .validate_sell_to_balance(&key(), FiatCurrency::CAD)
                .await,
            Err(BullBitcoinError::Authentication)
        );
        task.abort();

        async fn wrong_scope() -> Json<Value> {
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "bullnym",
                "error": {
                    "code": -32601,
                    "message": "The method does not exist / is not available.",
                    "data": {"method": "validateSellToBalance"}
                }
            }))
        }
        let (client, task) = client_for_app(
            Router::new().route("/ak/api-orders", post(wrong_scope)),
            1_000,
        )
        .await;
        assert_eq!(
            client
                .validate_sell_to_balance(&key(), FiatCurrency::CAD)
                .await,
            Err(BullBitcoinError::Authentication)
        );
        task.abort();

        async fn unavailable() -> StatusCode {
            StatusCode::SERVICE_UNAVAILABLE
        }
        let (client, task) = client_for_app(
            Router::new().route("/ak/api-orders", post(unavailable)),
            1_000,
        )
        .await;
        assert_eq!(
            client
                .validate_sell_to_balance(&key(), FiatCurrency::CAD)
                .await,
            Err(BullBitcoinError::Upstream)
        );
        task.abort();
    }

    #[tokio::test]
    async fn eligibility_rejects_nonminimal_success_and_times_out_safely() {
        async fn nonminimal() -> Json<Value> {
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "bullnym",
                "result": {"eligible": true, "kycTier": "must-not-be-consumed"}
            }))
        }
        let (client, task) = client_for_app(
            Router::new().route("/ak/api-orders", post(nonminimal)),
            1_000,
        )
        .await;
        assert_eq!(
            client
                .validate_sell_to_balance(&key(), FiatCurrency::USD)
                .await,
            Err(BullBitcoinError::MalformedResponse)
        );
        task.abort();

        async fn slow() -> Json<Value> {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "bullnym",
                "result": {"eligible": true}
            }))
        }
        let (client, task) =
            client_for_app(Router::new().route("/ak/api-orders", post(slow)), 5).await;
        assert_eq!(
            client
                .validate_sell_to_balance(&key(), FiatCurrency::USD)
                .await,
            Err(BullBitcoinError::Timeout)
        );
        task.abort();

        let config = BullBitcoinConfig {
            // No service can listen on TCP port zero; this deterministically
            // exercises connection failure without racing another test for a
            // recently released ephemeral port.
            api_url: "http://127.0.0.1:0/ak/api-orders".into(),
            connect_timeout_ms: 100,
            request_timeout_ms: 100,
            ..BullBitcoinConfig::default()
        };
        let client = HttpBullBitcoinApi::new(&config).unwrap();
        assert_eq!(
            client
                .validate_sell_to_balance(&key(), FiatCurrency::USD)
                .await,
            Err(BullBitcoinError::Transport)
        );
    }

    #[test]
    fn bearer_client_rejects_plain_http_off_loopback() {
        let config = BullBitcoinConfig {
            api_url: "http://example.com/ak/api-orders".into(),
            ..BullBitcoinConfig::default()
        };
        assert!(HttpBullBitcoinApi::new(&config).is_err());
    }

    #[test]
    fn bip21_amount_must_be_present_once_and_match() {
        let amount = BitcoinAmountSat::new(100_000).unwrap();
        assert!(validate_bip21_amount(
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.001&pj=https%3A%2F%2Fexample.com",
            amount,
        )
        .is_ok());
        for invalid in [
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.002",
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.001&amount=0.001",
        ] {
            assert!(validate_bip21_amount(invalid, amount).is_err());
        }
    }

    #[test]
    fn observation_uses_actual_received_and_exact_credited_minor_units() {
        let observation = parse_order_observation(&serde_json::json!({
            "orderId": "11111111-1111-4111-8111-111111111111",
            "payoutCurrency": "EUR",
            "orderStatus": "Completed",
            "payinStatus": "Completed",
            "payoutStatus": "Completed",
            "payinAmount": 0.001,
            "payinAmountChanged": {
                "requestedAmount": 0.001,
                "receivedAmount": 0.00100001
            },
            "payoutAmount": 61.23
        }))
        .unwrap();
        assert_eq!(observation.actual_received_sat, Some(100_001));
        assert_eq!(observation.credited_fiat_minor.unwrap().as_minor(), 6_123);
        assert!(observation.provider_final);
    }

    #[test]
    fn rpc_errors_are_classified_without_retaining_upstream_text() {
        let minimum = serde_json::json!({
            "data": {"reason": {"limit": {
                "conditionalOperator": "GREATER_THAN_OR_EQUAL"
            }}}
        });
        assert_eq!(
            classify_rpc_error(&minimum, RpcCallKind::CreateOrder),
            BullBitcoinError::Minimum
        );
        assert_eq!(
            classify_rpc_error(
                &serde_json::json!({
                    "data": {"apiError": {"code": "SELL_TO_BALANCE_KYC_REQUIRED"}}
                }),
                RpcCallKind::EligibilityPreflight
            ),
            BullBitcoinError::BenchmarkEligibilityDenied
        );
        assert_eq!(
            classify_rpc_error(
                &serde_json::json!({"message": "API key denied"}),
                RpcCallKind::ReadOrder
            ),
            BullBitcoinError::Authentication
        );
        assert_eq!(
            classify_rpc_error(
                &serde_json::json!({"message": "secret provider details"}),
                RpcCallKind::CreateOrder
            ),
            BullBitcoinError::Policy
        );
        let hidden_method = serde_json::json!({
            "code": -32601,
            "message": "The method does not exist / is not available."
        });
        assert_eq!(
            classify_rpc_error(&hidden_method, RpcCallKind::EligibilityPreflight),
            BullBitcoinError::Authentication
        );
        assert_eq!(
            classify_rpc_error(&hidden_method, RpcCallKind::ReadOrder),
            BullBitcoinError::Upstream
        );
    }
}

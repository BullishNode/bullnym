//! API-Pricer client: first Rust consumer of the bullbitcoin Pricer.
//!
//! Donation pages embed a fiat conversion rate at HTML render time so the
//! browser can show "5,432 sats" next to "$5". The rate is fetched per
//! `display_currency` and cached in-memory with a short TTL. On upstream
//! failure, the last-good rate is served (with `last_known_rate=true`)
//! rather than failing the page render.
//!
//! Wire shape mirrors the existing Dart consumer
//! (`bb-exchange/bb_flutter_core/lib/data/data_source/pricer_data_source.dart`):
//! JSON-RPC 2.0 POST with method `getRate`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::PricerConfig;

/// Currency rate result. `minor_per_btc` is in minor units of `currency`
/// (e.g. cents for USD/CAD/EUR). To convert sats → minor:
/// `minor = sats * minor_per_btc / 100_000_000`.
#[derive(Debug, Clone, Serialize)]
pub struct RateView {
    pub currency: String,
    pub minor_per_btc: i64,
    pub precision: u8,
    /// Unix epoch seconds when this rate was fetched from upstream. The
    /// donation-page template renders this as a small "rate updated …"
    /// line so users can sanity-check freshness.
    pub fetched_at_unix: u64,
    /// True when upstream is unreachable and we're returning a stale-but-
    /// known rate instead of failing. The page can show a "rate may be
    /// stale" badge.
    pub last_known_rate: bool,
}

#[derive(Debug, Clone, Copy)]
struct CachedRate {
    minor_per_btc: i64,
    precision: u8,
    fetched_at: Instant,
    fetched_at_unix: u64,
}

pub struct PricerClient {
    cfg: PricerConfig,
    http: reqwest::Client,
    cache: Arc<DashMap<String, CachedRate>>,
    supported_currencies: Arc<Vec<CurrencyView>>,
}

/// Sanity bounds on a freshly-fetched rate. Rejects garbage upstream
/// responses before they hit the cache and feed the donation-page JS.
/// Values outside this range cause the page to render with
/// `minor_per_btc=0` (Donate button disabled), which is preferable to
/// silently doing 0-sat-equivalent math.
const PRICER_MIN_MINOR_PER_BTC: i64 = 1;

impl PricerClient {
    pub fn new(cfg: PricerConfig) -> Result<Self, PricerInitError> {
        // Defense-in-depth: reject pricer URLs that aren't http(s).
        // A misconfigured `file://` or `gopher://` URL won't cause
        // surprises; an unknown scheme would also short-circuit reqwest
        // but we'd rather fail at startup than at first request.
        let lower = cfg.url.to_lowercase();
        if !lower.starts_with("http://") && !lower.starts_with("https://") {
            return Err(PricerInitError::BadScheme(cfg.url.clone()));
        }
        let supported_currencies = normalize_supported_currencies(&cfg.supported_currencies);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.request_timeout_ms))
            .build()
            .map_err(PricerInitError::Build)?;
        Ok(Self {
            cfg,
            http,
            cache: Arc::new(DashMap::new()),
            supported_currencies: Arc::new(supported_currencies),
        })
    }

    /// Server-authoritative currency list for mobile and public donation
    /// pages. The same list gates invoice creation before pricer calls.
    pub fn supported_currencies(&self) -> &[CurrencyView] {
        self.supported_currencies.as_slice()
    }

    pub fn is_supported_currency(&self, currency: &str) -> bool {
        let currency = normalize_currency_code(currency);
        self.supported_currencies.iter().any(|c| c.code == currency)
    }

    /// Fetch a fresh rate for `currency` (e.g. "USD"), or return the cached
    /// rate if it's within the configured TTL. On upstream error and a
    /// non-empty cache, returns the stale rate with `last_known_rate=true`.
    /// On upstream error and empty cache, returns `None`.
    pub async fn get_rate(&self, currency: &str) -> Option<RateView> {
        let currency = normalize_currency_code(currency);

        // Fast path: cached and within TTL.
        if let Some(entry) = self.cache.get(&currency) {
            if entry.fetched_at.elapsed() < Duration::from_secs(self.cfg.cache_ttl_secs) {
                return Some(RateView {
                    currency: currency.clone(),
                    minor_per_btc: entry.minor_per_btc,
                    precision: entry.precision,
                    fetched_at_unix: entry.fetched_at_unix,
                    last_known_rate: false,
                });
            }
        }

        // Slow path: refresh from upstream.
        match self.fetch_from_upstream(&currency).await {
            Ok(view) => {
                self.cache.insert(
                    currency.clone(),
                    CachedRate {
                        minor_per_btc: view.minor_per_btc,
                        precision: view.precision,
                        fetched_at: Instant::now(),
                        fetched_at_unix: view.fetched_at_unix,
                    },
                );
                Some(view)
            }
            Err(e) => {
                tracing::warn!(
                    currency = %currency,
                    error = %e,
                    "pricer fetch failed; serving last-known rate if cached"
                );
                self.cache.get(&currency).map(|entry| RateView {
                    currency: currency.clone(),
                    minor_per_btc: entry.minor_per_btc,
                    precision: entry.precision,
                    fetched_at_unix: entry.fetched_at_unix,
                    last_known_rate: true,
                })
            }
        }
    }

    async fn fetch_from_upstream(&self, currency: &str) -> Result<RateView, PricerError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getRate",
            "params": {
                "element": {
                    "fromCurrency": "BTC",
                    "toCurrency": currency,
                }
            }
        });

        let resp: JsonRpcResponse = self
            .http
            .post(&self.cfg.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| PricerError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| PricerError::Transport(e.to_string()))?
            .json()
            .await
            .map_err(|e| PricerError::Decode(e.to_string()))?;

        if let Some(err) = resp.error {
            return Err(PricerError::Rpc(err.message));
        }

        let element = resp
            .result
            .ok_or_else(|| PricerError::Decode("missing result".into()))?
            .element;

        if let Err(reason) = validate_rate_element(&element) {
            return Err(PricerError::Decode(format!(
                "indexPrice {} for {} rejected: {}",
                element.index_price, element.to_currency, reason
            )));
        }

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(RateView {
            currency: element.to_currency,
            minor_per_btc: element.index_price,
            precision: element.precision,
            fetched_at_unix: now_unix,
            last_known_rate: false,
        })
    }
}

fn validate_rate_element(element: &RateElement) -> Result<(), String> {
    if element.index_price < PRICER_MIN_MINOR_PER_BTC {
        return Err(format!("below minimum {PRICER_MIN_MINOR_PER_BTC}"));
    }

    let max = max_minor_per_btc(&element.to_currency)
        .ok_or_else(|| "currency has no configured ceiling".to_string())?;
    if element.index_price > max {
        return Err(format!("above currency ceiling {max}"));
    }

    Ok(())
}

fn max_minor_per_btc(currency: &str) -> Option<i64> {
    match normalize_currency_code(currency).as_str() {
        // Roughly a $10M/BTC equivalent ceiling per supported currency.
        // These are not market predictions; they catch unit/decimal/feed
        // failures while leaving a wide operational margin.
        "USD" | "CAD" | "EUR" => Some(1_000_000_000),
        "CRC" => Some(500_000_000_000),
        "MXN" => Some(20_000_000_000),
        "COP" => Some(50_000_000_000),
        "INR" => Some(100_000_000_000),
        "ARS" => Some(5_000_000_000_000),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CurrencyView {
    pub code: String,
    pub precision: u8,
}

#[derive(Debug, Serialize)]
pub struct SupportedCurrenciesResponse {
    pub currencies: Vec<CurrencyView>,
}

pub async fn supported_currencies(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
) -> axum::Json<SupportedCurrenciesResponse> {
    axum::Json(SupportedCurrenciesResponse {
        currencies: state.pricer.supported_currencies().to_vec(),
    })
}

pub fn normalize_currency_code(currency: &str) -> String {
    currency.trim().to_uppercase()
}

pub fn currency_precision(currency: &str) -> u8 {
    match normalize_currency_code(currency).as_str() {
        "COP" => 0,
        _ => 2,
    }
}

fn normalize_supported_currencies(currencies: &[String]) -> Vec<CurrencyView> {
    let mut codes: Vec<String> = currencies
        .iter()
        .map(|c| normalize_currency_code(c))
        .filter(|c| !c.is_empty())
        .collect();
    codes.sort();
    codes.dedup();
    codes
        .into_iter()
        .map(|code| CurrencyView {
            precision: currency_precision(&code),
            code,
        })
        .collect()
}

#[derive(Debug)]
pub enum PricerInitError {
    BadScheme(String),
    Build(reqwest::Error),
}

impl std::fmt::Display for PricerInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadScheme(url) => {
                write!(f, "pricer URL must be http:// or https://; got {url:?}")
            }
            Self::Build(e) => write!(f, "pricer client build failed: {e}"),
        }
    }
}

impl std::error::Error for PricerInitError {}

// --- JSON-RPC wire types ---

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    result: Option<JsonRpcResult>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResult {
    element: RateElement,
}

#[derive(Debug, Deserialize)]
struct RateElement {
    #[serde(rename = "fromCurrency")]
    #[allow(dead_code)]
    from_currency: String,
    #[serde(rename = "toCurrency")]
    to_currency: String,
    /// Index (reference) rate in minor units of `toCurrency` per 1 BTC.
    /// Distinct from `price`: `price` carries Bull's sell-side markup
    /// while `indexPrice` is the neutral reference rate. The donation
    /// page is unauthenticated public surface; we want the rate the
    /// donator would see in their own wallet, not Bull's quote price.
    #[serde(rename = "indexPrice")]
    index_price: i64,
    precision: u8,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    #[allow(dead_code)]
    code: i64,
    message: String,
}

#[derive(Debug)]
pub enum PricerError {
    Transport(String),
    Decode(String),
    Rpc(String),
}

impl std::fmt::Display for PricerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(m) => write!(f, "pricer transport: {m}"),
            Self::Decode(m) => write!(f, "pricer decode: {m}"),
            Self::Rpc(m) => write!(f, "pricer rpc: {m}"),
        }
    }
}

impl std::error::Error for PricerError {}

#[cfg(test)]
mod tests;

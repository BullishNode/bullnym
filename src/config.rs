use serde::Deserialize;
use std::fmt;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub domain: String,
    pub listen: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    pub boltz: BoltzConfig,
    #[serde(default)]
    pub pricer: PricerConfig,
    #[serde(default)]
    pub pwa: PwaConfig,
    #[serde(default)]
    pub donation: DonationConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub proof: ProofConfig,
    #[serde(default)]
    pub features: FeaturesConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub certification: CertificationConfig,
    #[serde(default)]
    pub electrum: ElectrumConfig,
    #[serde(default)]
    pub claim: ClaimConfig,
    #[serde(default)]
    pub reconciler: ReconcilerConfig,
    #[serde(default)]
    pub bitcoin_watcher: BitcoinWatcherConfig,
    #[serde(default)]
    pub liquid_watcher: LiquidWatcherConfig,
    #[serde(default)]
    pub fee_policy: FeePolicyConfig,
    #[serde(default)]
    pub workers: WorkersConfig,
    #[serde(default)]
    pub invoice_accounting: InvoiceAccountingConfig,
    #[serde(skip)]
    pub database_url: String,
    #[serde(skip)]
    pub swap_mnemonic: String,
    /// URL-path secret for Boltz webhook authentication. Boltz's backend
    /// (verified at `boltzr/src/webhook/caller.rs`) does NOT sign webhook
    /// deliveries — there is no HMAC header. The shared secret therefore
    /// has to live somewhere Boltz already echoes back, and the only
    /// such place is the webhook URL itself. We register
    /// `https://{domain}/webhook/boltz/{webhook_url_secret}` with Boltz
    /// at swap creation time; the handler matches the path segment in
    /// constant time.
    ///
    /// Sourced from `BOLTZ_WEBHOOK_URL_SECRET` env var. See
    /// docs/compatibility-ledger.md for fallback and rotation policy.
    #[serde(skip)]
    pub boltz_webhook_url_secret: String,
    /// Optional previous URL secret. Accepted in addition to
    /// `boltz_webhook_url_secret` for the duration of a rotation overlap
    /// window (so existing swaps' webhooks keep delivering while new
    /// swaps register the new URL). Empty = no overlap.
    #[serde(skip)]
    pub boltz_webhook_url_secret_previous: String,
}

// --- Construction-time fee discovery config ---

pub const MAX_FEE_SOURCES_PER_RAIL: usize = 4;
pub const MAX_FEE_SOURCE_ID_BYTES: usize = 64;

const DEFAULT_FEE_REFRESH_INTERVAL_SECS: u64 = 30;
const DEFAULT_FEE_LIVE_MAX_AGE_SECS: u64 = 120;
const DEFAULT_FEE_LAST_KNOWN_GOOD_MAX_AGE_SECS: u64 = 900;
const DEFAULT_BITCOIN_FEE_FLOOR_SAT_PER_VBYTE: f64 = 1.0;
const DEFAULT_BITCOIN_FEE_CAP_SAT_PER_VBYTE: f64 = 500.0;
const DEFAULT_LIQUID_FEE_FLOOR_SAT_PER_VBYTE: f64 = 0.1;
const DEFAULT_LIQUID_FEE_CAP_SAT_PER_VBYTE: f64 = 10.0;

/// One explicitly configured, API-compatible fee source.
///
/// The ID is a non-secret persistence key. Both fields are intentionally
/// redacted from Debug so a future operational diagnostic cannot disclose
/// operator-controlled source details.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FeeSourceConfig {
    pub id: String,
    pub endpoint: String,
}

impl fmt::Debug for FeeSourceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeeSourceConfig")
            .field("id", &"<redacted>")
            .field("endpoint", &"<redacted>")
            .finish()
    }
}

/// Bitcoin-specific live-fee discovery settings. Each configured API base is
/// queried only at `/v1/fees/precise`. These are validation, freshness, and
/// economic bounds only; there is deliberately no configured fee quote or
/// default construction rate.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BitcoinFeeConfig {
    #[serde(default = "default_bitcoin_fee_sources")]
    pub sources: Vec<FeeSourceConfig>,
    #[serde(default = "default_fee_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_fee_live_max_age_secs")]
    pub live_max_age_secs: u64,
    #[serde(default = "default_fee_last_known_good_max_age_secs")]
    pub last_known_good_max_age_secs: u64,
    #[serde(default = "default_bitcoin_fee_floor_sat_per_vbyte")]
    pub floor_sat_per_vbyte: f64,
    #[serde(default = "default_bitcoin_fee_cap_sat_per_vbyte")]
    pub cap_sat_per_vbyte: f64,
}

impl Default for BitcoinFeeConfig {
    fn default() -> Self {
        Self {
            sources: default_bitcoin_fee_sources(),
            refresh_interval_secs: default_fee_refresh_interval_secs(),
            live_max_age_secs: default_fee_live_max_age_secs(),
            last_known_good_max_age_secs: default_fee_last_known_good_max_age_secs(),
            floor_sat_per_vbyte: default_bitcoin_fee_floor_sat_per_vbyte(),
            cap_sat_per_vbyte: default_bitcoin_fee_cap_sat_per_vbyte(),
        }
    }
}

/// Liquid-specific live-fee discovery settings. The configured sources must
/// expose the Esplora fee-estimates shape; ordinary Liquid transaction-data
/// endpoints are not implicitly added here.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LiquidFeeConfig {
    #[serde(default = "default_liquid_fee_sources")]
    pub sources: Vec<FeeSourceConfig>,
    #[serde(default = "default_fee_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_fee_live_max_age_secs")]
    pub live_max_age_secs: u64,
    #[serde(default = "default_fee_last_known_good_max_age_secs")]
    pub last_known_good_max_age_secs: u64,
    #[serde(default = "default_liquid_fee_floor_sat_per_vbyte")]
    pub floor_sat_per_vbyte: f64,
    #[serde(default = "default_liquid_fee_cap_sat_per_vbyte")]
    pub cap_sat_per_vbyte: f64,
}

impl Default for LiquidFeeConfig {
    fn default() -> Self {
        Self {
            sources: default_liquid_fee_sources(),
            refresh_interval_secs: default_fee_refresh_interval_secs(),
            live_max_age_secs: default_fee_live_max_age_secs(),
            last_known_good_max_age_secs: default_fee_last_known_good_max_age_secs(),
            floor_sat_per_vbyte: default_liquid_fee_floor_sat_per_vbyte(),
            cap_sat_per_vbyte: default_liquid_fee_cap_sat_per_vbyte(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct FeePolicyConfig {
    #[serde(default)]
    pub bitcoin: BitcoinFeeConfig,
    #[serde(default)]
    pub liquid: LiquidFeeConfig,
}

/// Rail-local validation facts. They are observations about static config,
/// not readiness and not evidence that a source answered in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeRailConfigValidationFacts {
    pub sources_valid: bool,
    pub refresh_interval_valid: bool,
    pub live_freshness_window_valid: bool,
    pub last_known_good_freshness_window_valid: bool,
    pub bounds_valid: bool,
}

impl FeeRailConfigValidationFacts {
    pub const fn all_valid(self) -> bool {
        self.sources_valid
            && self.refresh_interval_valid
            && self.live_freshness_window_valid
            && self.last_known_good_freshness_window_valid
            && self.bounds_valid
    }
}

/// Static configuration facts for each rail. Future startup wiring may consume
/// these facts, but constructing them never opens admission or calls a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeePolicyConfigValidationFacts {
    pub bitcoin: FeeRailConfigValidationFacts,
    pub liquid: FeeRailConfigValidationFacts,
}

impl FeePolicyConfigValidationFacts {
    pub const fn all_valid(self) -> bool {
        self.bitcoin.all_valid() && self.liquid.all_valid()
    }
}

impl FeePolicyConfig {
    pub fn validation_facts(&self) -> FeePolicyConfigValidationFacts {
        FeePolicyConfigValidationFacts {
            bitcoin: fee_rail_config_validation_facts(
                &self.bitcoin.sources,
                self.bitcoin.refresh_interval_secs,
                self.bitcoin.live_max_age_secs,
                self.bitcoin.last_known_good_max_age_secs,
                self.bitcoin.floor_sat_per_vbyte,
                self.bitcoin.cap_sat_per_vbyte,
            ),
            liquid: fee_rail_config_validation_facts(
                &self.liquid.sources,
                self.liquid.refresh_interval_secs,
                self.liquid.live_max_age_secs,
                self.liquid.last_known_good_max_age_secs,
                self.liquid.floor_sat_per_vbyte,
                self.liquid.cap_sat_per_vbyte,
            ),
        }
    }
}

fn fee_rail_config_validation_facts(
    sources: &[FeeSourceConfig],
    refresh_interval_secs: u64,
    live_max_age_secs: u64,
    last_known_good_max_age_secs: u64,
    floor_sat_per_vbyte: f64,
    cap_sat_per_vbyte: f64,
) -> FeeRailConfigValidationFacts {
    FeeRailConfigValidationFacts {
        sources_valid: fee_sources_valid(sources),
        refresh_interval_valid: refresh_interval_secs > 0,
        live_freshness_window_valid: live_max_age_secs > 0,
        last_known_good_freshness_window_valid: last_known_good_max_age_secs > 0,
        bounds_valid: fee_bounds_valid(floor_sat_per_vbyte, cap_sat_per_vbyte),
    }
}

fn fee_sources_valid(sources: &[FeeSourceConfig]) -> bool {
    !sources.is_empty()
        && sources.len() <= MAX_FEE_SOURCES_PER_RAIL
        && sources.iter().enumerate().all(|(index, source)| {
            valid_fee_source_id(&source.id)
                && valid_fee_https_base_endpoint(&source.endpoint)
                && sources[..index].iter().all(|prior| prior.id != source.id)
        })
}

fn fee_bounds_valid(floor_sat_per_vbyte: f64, cap_sat_per_vbyte: f64) -> bool {
    floor_sat_per_vbyte.is_finite()
        && floor_sat_per_vbyte > 0.0
        && cap_sat_per_vbyte.is_finite()
        && cap_sat_per_vbyte > 0.0
        && floor_sat_per_vbyte <= cap_sat_per_vbyte
}

pub fn valid_fee_source_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FEE_SOURCE_ID_BYTES
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'-' | b'_' => index > 0,
            _ => false,
        })
}

pub fn valid_fee_https_base_endpoint(raw: &str) -> bool {
    reqwest::Url::parse(raw).is_ok_and(|url| {
        url.scheme() == "https"
            && !url.cannot_be_a_base()
            && url.host_str().is_some()
            && url.port() != Some(0)
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn default_bitcoin_fee_sources() -> Vec<FeeSourceConfig> {
    // The Bitcoin fee adapter appends `/v1/fees/precise` to each base. In
    // particular, the public fallback resolves to the operator-requested
    // `https://mempool.space/api/v1/fees/precise` endpoint.
    vec![
        FeeSourceConfig {
            id: "bull-bitcoin".to_string(),
            endpoint: "https://mempool.bullbitcoin.com/api".to_string(),
        },
        FeeSourceConfig {
            id: "mempool-space".to_string(),
            endpoint: "https://mempool.space/api".to_string(),
        },
    ]
}

fn default_liquid_fee_sources() -> Vec<FeeSourceConfig> {
    vec![FeeSourceConfig {
        id: "liquid-network".to_string(),
        endpoint: "https://liquid.network/api".to_string(),
    }]
}

fn default_fee_refresh_interval_secs() -> u64 {
    DEFAULT_FEE_REFRESH_INTERVAL_SECS
}

fn default_fee_live_max_age_secs() -> u64 {
    DEFAULT_FEE_LIVE_MAX_AGE_SECS
}

fn default_fee_last_known_good_max_age_secs() -> u64 {
    DEFAULT_FEE_LAST_KNOWN_GOOD_MAX_AGE_SECS
}

fn default_bitcoin_fee_floor_sat_per_vbyte() -> f64 {
    DEFAULT_BITCOIN_FEE_FLOOR_SAT_PER_VBYTE
}

fn default_bitcoin_fee_cap_sat_per_vbyte() -> f64 {
    DEFAULT_BITCOIN_FEE_CAP_SAT_PER_VBYTE
}

fn default_liquid_fee_floor_sat_per_vbyte() -> f64 {
    DEFAULT_LIQUID_FEE_FLOOR_SAT_PER_VBYTE
}

fn default_liquid_fee_cap_sat_per_vbyte() -> f64 {
    DEFAULT_LIQUID_FEE_CAP_SAT_PER_VBYTE
}

const DEFAULT_BTC_SHORTFALL_TOLERANCE_SAT: i64 = 300;
const DEFAULT_LIQUID_SHORTFALL_TOLERANCE_SAT: i64 = 60;
const DEFAULT_LIGHTNING_SHORTFALL_TOLERANCE_SAT: i64 = 1;
const DEFAULT_CHECKOUT_PARTIAL_TERMINAL_GRACE_SECS: u64 = 900;
const DEFAULT_PAYMENT_GRACE_SECS: u64 = 3600;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeaturesConfig {
    /// Lightning Address and registration APIs:
    /// `/.well-known/lnurlp`, `/.well-known/nostr.json`, `/lnurlp/callback`,
    /// `/register*`, and reservation inspection.
    #[serde(default = "default_feature_enabled")]
    pub lightning_address: bool,
    /// Wallet-origin invoice APIs and standalone invoice payment pages.
    #[serde(default = "default_feature_enabled")]
    pub invoices: bool,
    /// Donation/payment-page APIs and donation checkout invoice sessions.
    #[serde(default = "default_feature_enabled")]
    pub payment_pages: bool,
    /// NIP-05 resolution at `/.well-known/nostr.json`. OFF by default and
    /// independent of `lightning_address`: even with registration enabled,
    /// the server publishes no NIP-05 records unless an operator turns this
    /// on. Combined with opt-in `verification_npub` (ISS-S-01), this stops
    /// the server-auth key from ever doubling as a public NIP-05 identity.
    #[serde(default)]
    pub nip05: bool,
}

impl Default for FeaturesConfig {
    fn default() -> Self {
        Self {
            lightning_address: default_feature_enabled(),
            invoices: default_feature_enabled(),
            payment_pages: default_feature_enabled(),
            nip05: false,
        }
    }
}

fn default_feature_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkersConfig {
    /// When false, the HTTP server starts without background workers.
    /// Use this for standby/web-only instances so failover does not
    /// duplicate claim, watcher, reconciler, or GC loops.
    #[serde(default = "default_workers_enabled")]
    pub enabled: bool,
}

impl Default for WorkersConfig {
    fn default() -> Self {
        Self {
            enabled: default_workers_enabled(),
        }
    }
}

fn default_workers_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceAccountingConfig {
    #[serde(default = "default_btc_shortfall_tolerance_sat")]
    pub btc_shortfall_tolerance_sat: i64,
    #[serde(default = "default_liquid_shortfall_tolerance_sat")]
    pub liquid_shortfall_tolerance_sat: i64,
    #[serde(default = "default_lightning_shortfall_tolerance_sat")]
    pub lightning_shortfall_tolerance_sat: i64,
    #[serde(default = "default_checkout_partial_terminal_grace_secs")]
    pub checkout_partial_terminal_grace_secs: u64,
    /// Grace window (seconds) added AFTER `expires_at` during which the
    /// watchers keep polling an invoice and GC withholds expiry, so a payment
    /// broadcast just before expiry that confirms just after is still credited
    /// (the expiry-cliff fix). Must comfortably exceed one on-chain block
    /// interval. Default 3600 covers the vast majority of single-block waits.
    #[serde(default = "default_payment_grace_secs")]
    pub payment_grace_secs: u64,
}

impl Default for InvoiceAccountingConfig {
    fn default() -> Self {
        Self {
            btc_shortfall_tolerance_sat: DEFAULT_BTC_SHORTFALL_TOLERANCE_SAT,
            liquid_shortfall_tolerance_sat: DEFAULT_LIQUID_SHORTFALL_TOLERANCE_SAT,
            lightning_shortfall_tolerance_sat: DEFAULT_LIGHTNING_SHORTFALL_TOLERANCE_SAT,
            checkout_partial_terminal_grace_secs: DEFAULT_CHECKOUT_PARTIAL_TERMINAL_GRACE_SECS,
            payment_grace_secs: DEFAULT_PAYMENT_GRACE_SECS,
        }
    }
}

fn default_btc_shortfall_tolerance_sat() -> i64 {
    DEFAULT_BTC_SHORTFALL_TOLERANCE_SAT
}
fn default_liquid_shortfall_tolerance_sat() -> i64 {
    DEFAULT_LIQUID_SHORTFALL_TOLERANCE_SAT
}
fn default_lightning_shortfall_tolerance_sat() -> i64 {
    DEFAULT_LIGHTNING_SHORTFALL_TOLERANCE_SAT
}
fn default_checkout_partial_terminal_grace_secs() -> u64 {
    DEFAULT_CHECKOUT_PARTIAL_TERMINAL_GRACE_SECS
}
fn default_payment_grace_secs() -> u64 {
    DEFAULT_PAYMENT_GRACE_SECS
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoltzConfig {
    pub api_url: String,
    pub electrum_url: String,
    /// Operator-controlled generation of the swap-key root. Increment when
    /// intentionally rotating the master key; historical rows retain their
    /// persisted epoch. Must be positive.
    #[serde(default = "default_swap_key_epoch")]
    pub key_epoch: i32,
}

fn default_swap_key_epoch() -> i32 {
    1
}

// --- Claim retry policy ---

const DEFAULT_MAX_CLAIM_ATTEMPTS: i32 = 30;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimConfig {
    /// After this many failed claim attempts, the row transitions to
    /// `claim_stuck` and leaves the fast background sweep. The slow-recovery
    /// worker continues retrying funded rows on a longer capped backoff.
    ///
    /// Default 30 ≈ 24h of trying with the documented backoff
    /// (30s, 60s, 120s, 300s, 600s, 1800s, 3600s cap). Plenty for any
    /// transient outage; well past Boltz's `timeoutBlockHeight` for any
    /// realistic swap.
    #[serde(default = "default_max_claim_attempts")]
    pub max_claim_attempts: i32,
}

impl Default for ClaimConfig {
    fn default() -> Self {
        Self {
            max_claim_attempts: DEFAULT_MAX_CLAIM_ATTEMPTS,
        }
    }
}

fn default_max_claim_attempts() -> i32 {
    DEFAULT_MAX_CLAIM_ATTEMPTS
}

// --- Reconciler ---

const DEFAULT_RECONCILER_INTERVAL_SECS: u64 = 90;
const DEFAULT_RECONCILER_MIN_AGE_SECS: u64 = 60;
const DEFAULT_RECONCILER_MAX_PER_TICK: u32 = 200;
const DEFAULT_RECONCILER_INTER_CALL_DELAY_MS: u64 = 50;
// Slow-recovery sweep (issue #63): revives funded `claim_stuck` rows on a long,
// capped backoff so a post-retry-budget outage doesn't abandon claimable funds.
const DEFAULT_SLOW_RECOVERY_INTERVAL_SECS: u64 = 1800;
const DEFAULT_SLOW_RECOVERY_MAX_PER_TICK: u32 = 25;
const DEFAULT_SLOW_RECOVERY_BACKOFF_BASE_SECS: u64 = 3600;
const DEFAULT_SLOW_RECOVERY_BACKOFF_CAP_SECS: u64 = 86400;

/// Reconciler task config. The reconciler periodically polls Boltz's
/// `GET /swap/{id}` for every non-terminal `swap_records` row and
/// reconciles our DB state against Boltz's view. Catches dropped
/// webhooks (Boltz abandons after 5 retries × 60s = ~5 min) and
/// state-machine surprises.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcilerConfig {
    /// Tick cadence. 90s by default — chosen so a dropped webhook is
    /// caught within ~1.5 min of Boltz abandoning delivery, well inside
    /// any on-chain claim window.
    #[serde(default = "default_reconciler_interval_secs")]
    pub interval_secs: u64,
    /// Skip rows newer than this. Avoids racing the webhook handler on
    /// freshly-created swaps where the webhook is still in transit.
    #[serde(default = "default_reconciler_min_age_secs")]
    pub min_age_secs: u64,
    /// Cap per-tick scan size. Caps Boltz API RPM at backlog peak
    /// (e.g., the first tick after a long downtime). Drains over
    /// multiple ticks, oldest-first.
    #[serde(default = "default_reconciler_max_per_tick")]
    pub max_per_tick: u32,
    /// Defensive inter-call delay (ms) between Boltz API calls within a
    /// single tick. With max_per_tick=200 and 50ms, peak RPM is ~133 —
    /// well below any reasonable rate limit.
    #[serde(default = "default_reconciler_inter_call_delay_ms")]
    pub inter_call_delay_ms: u64,
    /// Slow-recovery sweep cadence (issue #63). Much slower than the main tick:
    /// this revives funded `claim_stuck` rows, which by definition already
    /// exhausted the fast retry budget.
    #[serde(default = "default_slow_recovery_interval_secs")]
    pub slow_recovery_interval_secs: u64,
    /// Cap per slow-recovery tick.
    #[serde(default = "default_slow_recovery_max_per_tick")]
    pub slow_recovery_max_per_tick: u32,
    /// Backoff base: the nth revival of a row waits ~base * 2^(n-1), jittered.
    #[serde(default = "default_slow_recovery_backoff_base_secs")]
    pub slow_recovery_backoff_base_secs: u64,
    /// Backoff ceiling so a long-outage row still gets retried ~daily.
    #[serde(default = "default_slow_recovery_backoff_cap_secs")]
    pub slow_recovery_backoff_cap_secs: u64,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_RECONCILER_INTERVAL_SECS,
            min_age_secs: DEFAULT_RECONCILER_MIN_AGE_SECS,
            max_per_tick: DEFAULT_RECONCILER_MAX_PER_TICK,
            inter_call_delay_ms: DEFAULT_RECONCILER_INTER_CALL_DELAY_MS,
            slow_recovery_interval_secs: DEFAULT_SLOW_RECOVERY_INTERVAL_SECS,
            slow_recovery_max_per_tick: DEFAULT_SLOW_RECOVERY_MAX_PER_TICK,
            slow_recovery_backoff_base_secs: DEFAULT_SLOW_RECOVERY_BACKOFF_BASE_SECS,
            slow_recovery_backoff_cap_secs: DEFAULT_SLOW_RECOVERY_BACKOFF_CAP_SECS,
        }
    }
}

fn default_reconciler_interval_secs() -> u64 {
    DEFAULT_RECONCILER_INTERVAL_SECS
}
fn default_reconciler_min_age_secs() -> u64 {
    DEFAULT_RECONCILER_MIN_AGE_SECS
}
fn default_reconciler_max_per_tick() -> u32 {
    DEFAULT_RECONCILER_MAX_PER_TICK
}
fn default_reconciler_inter_call_delay_ms() -> u64 {
    DEFAULT_RECONCILER_INTER_CALL_DELAY_MS
}
fn default_slow_recovery_interval_secs() -> u64 {
    DEFAULT_SLOW_RECOVERY_INTERVAL_SECS
}
fn default_slow_recovery_max_per_tick() -> u32 {
    DEFAULT_SLOW_RECOVERY_MAX_PER_TICK
}
fn default_slow_recovery_backoff_base_secs() -> u64 {
    DEFAULT_SLOW_RECOVERY_BACKOFF_BASE_SECS
}
fn default_slow_recovery_backoff_cap_secs() -> u64 {
    DEFAULT_SLOW_RECOVERY_BACKOFF_CAP_SECS
}

// --- Pricer config ---

const DEFAULT_PRICER_URL: &str = "https://api.bullbitcoin.com/public/price";
const DEFAULT_PRICER_CACHE_TTL_SECS: u64 = 60;
const DEFAULT_PRICER_REQUEST_TIMEOUT_MS: u64 = 2000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PricerConfig {
    /// JSON-RPC endpoint for the bullbitcoin API-Pricer. Donation pages
    /// fetch `getRate` per `display_currency` to embed a fiat conversion
    /// rate at HTML render time.
    #[serde(default = "default_pricer_url")]
    pub url: String,
    /// In-memory TTL (seconds) for cached rates. A thundering herd of
    /// donation-page views all share one upstream call within the TTL.
    #[serde(default = "default_pricer_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// HTTP request timeout (milliseconds) for the upstream call. On
    /// timeout / error, the donation render falls back to the last-good
    /// cached rate (if any).
    #[serde(default = "default_pricer_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Fiat currencies the server will expose to clients and accept for
    /// invoice creation. Keep this list aligned with the configured pricer
    /// backend; unsupported submitted currencies are rejected before any
    /// upstream pricing request is attempted.
    #[serde(default = "default_pricer_supported_currencies")]
    pub supported_currencies: Vec<String>,
}

impl Default for PricerConfig {
    fn default() -> Self {
        Self {
            url: DEFAULT_PRICER_URL.to_string(),
            cache_ttl_secs: DEFAULT_PRICER_CACHE_TTL_SECS,
            request_timeout_ms: DEFAULT_PRICER_REQUEST_TIMEOUT_MS,
            supported_currencies: default_pricer_supported_currencies(),
        }
    }
}

fn default_pricer_url() -> String {
    DEFAULT_PRICER_URL.to_string()
}
fn default_pricer_cache_ttl_secs() -> u64 {
    DEFAULT_PRICER_CACHE_TTL_SECS
}
fn default_pricer_request_timeout_ms() -> u64 {
    DEFAULT_PRICER_REQUEST_TIMEOUT_MS
}
fn default_pricer_supported_currencies() -> Vec<String> {
    ["USD", "CAD", "EUR", "CRC", "MXN", "ARS", "COP"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

// --- PWA shell/static serving ---

const DEFAULT_PWA_DIST_DIR: &str = "pwa/dist";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PwaConfig {
    #[serde(default = "default_pwa_dist_dir")]
    pub dist_dir: String,
}

impl Default for PwaConfig {
    fn default() -> Self {
        Self {
            dist_dir: default_pwa_dist_dir(),
        }
    }
}

fn default_pwa_dist_dir() -> String {
    DEFAULT_PWA_DIST_DIR.to_string()
}

// --- Donation page image pipeline ---

const DEFAULT_DONATION_IMAGE_ROOT: &str = "/opt/payservice/data/images";
const DEFAULT_DONATION_IMAGE_MAX_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const DEFAULT_DONATION_IMAGE_MAX_DIMENSION: u32 = 5_000;
const DEFAULT_DONATION_IMAGE_MAX_PIXELS: u64 = 12_000_000;
const DEFAULT_DONATION_AVATAR_SIZE: u32 = 256;
const DEFAULT_DONATION_OG_WIDTH: u32 = 1200;
const DEFAULT_DONATION_OG_HEIGHT: u32 = 630;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DonationConfig {
    /// Filesystem root for image storage. Generated social cards are written
    /// below `<image_root_path>/og/`; historical merchant media may also live
    /// below this root. nginx serves it directly at `location ^~ /img/`. The
    /// directory must be writable by pay-service and readable by nginx.
    #[serde(default = "default_donation_image_root")]
    pub image_root_path: String,
    /// Hard cap on incoming image bytes. Enforced via per-route
    /// `DefaultBodyLimit` BEFORE the multipart parser runs — bytes never
    /// enter memory beyond this.
    #[serde(default = "default_donation_image_max_bytes")]
    pub image_max_bytes: usize,
    /// Reject images whose decoded dimensions exceed this in either
    /// axis. Image-bomb defense: read the header dimensions first
    /// (cheap), reject before allocating the full pixel buffer. The
    /// default is intentionally below large-camera panoramas because decode
    /// memory grows with pixels, not upload bytes.
    #[serde(default = "default_donation_image_max_dimension")]
    pub image_max_dimension: u32,
    /// Reject images whose decoded pixel area exceeds this value before
    /// allocating the full pixel buffer.
    #[serde(default = "default_donation_image_max_pixels")]
    pub image_max_pixels: u64,
    /// Output size for resized avatar (square).
    #[serde(default = "default_donation_avatar_size")]
    pub avatar_size: u32,
    /// Output size for resized OG image (1200×630 is the Twitter/Facebook
    /// summary_large_image standard).
    #[serde(default = "default_donation_og_width")]
    pub og_width: u32,
    #[serde(default = "default_donation_og_height")]
    pub og_height: u32,
}

impl Default for DonationConfig {
    fn default() -> Self {
        Self {
            image_root_path: DEFAULT_DONATION_IMAGE_ROOT.to_string(),
            image_max_bytes: DEFAULT_DONATION_IMAGE_MAX_BYTES,
            image_max_dimension: DEFAULT_DONATION_IMAGE_MAX_DIMENSION,
            image_max_pixels: DEFAULT_DONATION_IMAGE_MAX_PIXELS,
            avatar_size: DEFAULT_DONATION_AVATAR_SIZE,
            og_width: DEFAULT_DONATION_OG_WIDTH,
            og_height: DEFAULT_DONATION_OG_HEIGHT,
        }
    }
}

fn default_donation_image_root() -> String {
    DEFAULT_DONATION_IMAGE_ROOT.to_string()
}
fn default_donation_image_max_bytes() -> usize {
    DEFAULT_DONATION_IMAGE_MAX_BYTES
}
fn default_donation_image_max_dimension() -> u32 {
    DEFAULT_DONATION_IMAGE_MAX_DIMENSION
}
fn default_donation_image_max_pixels() -> u64 {
    DEFAULT_DONATION_IMAGE_MAX_PIXELS
}
fn default_donation_avatar_size() -> u32 {
    DEFAULT_DONATION_AVATAR_SIZE
}
fn default_donation_og_width() -> u32 {
    DEFAULT_DONATION_OG_WIDTH
}
fn default_donation_og_height() -> u32 {
    DEFAULT_DONATION_OG_HEIGHT
}

const DEFAULT_POOL_SIZE: u32 = 10;
const DEFAULT_MIN_SENDABLE_MSAT: u64 = 100_000;
const DEFAULT_MAX_SENDABLE_MSAT: u64 = 25_000_000_000;
const DEFAULT_MAX_DESCRIPTOR_LEN: usize = 1000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_min_sendable")]
    pub min_sendable_msat: u64,
    #[serde(default = "default_max_sendable")]
    pub max_sendable_msat: u64,
    #[serde(default = "default_max_descriptor_len")]
    pub max_descriptor_len: usize,
    /// Hard cap on the number of distinct nyms a single npub can ever
    /// register. Inactive (deregistered) nyms still count — the row keeps
    /// its name reserved. Without this cap one key can squat the namespace
    /// by churning through dereg/rereg cycles.
    #[serde(default = "default_max_lifetime_nyms_per_npub")]
    pub max_lifetime_nyms_per_npub: i64,
}

const DEFAULT_MAX_LIFETIME_NYMS_PER_NPUB: i64 = 3;
fn default_max_lifetime_nyms_per_npub() -> i64 {
    DEFAULT_MAX_LIFETIME_NYMS_PER_NPUB
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            min_sendable_msat: DEFAULT_MIN_SENDABLE_MSAT,
            max_sendable_msat: DEFAULT_MAX_SENDABLE_MSAT,
            max_descriptor_len: DEFAULT_MAX_DESCRIPTOR_LEN,
            max_lifetime_nyms_per_npub: DEFAULT_MAX_LIFETIME_NYMS_PER_NPUB,
        }
    }
}

// --- Proof-of-funds config ---

const DEFAULT_MIN_PROOF_VALUE_SAT: u64 = 1000;
const DEFAULT_MESSAGE_TAG: &str = "bullpay-lnurlp-v1";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofConfig {
    /// Minimum L-BTC value the payer must prove for a LUD-22 proof UTXO. This
    /// is the economic cost floor for a single Liquid LNURL-pay callback and
    /// is ENFORCED: the callback unblinds the confidential proof output and
    /// rejects it unless the asset is L-BTC and the value is >= this floor
    /// (DG-7 / ISS-S-04). Not merely advisory.
    #[serde(default = "default_min_proof_value_sat")]
    pub min_proof_value_sat: u64,
    /// Domain separation tag for the signed ownership message.
    #[serde(default = "default_message_tag")]
    pub message_tag: String,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            min_proof_value_sat: DEFAULT_MIN_PROOF_VALUE_SAT,
            message_tag: DEFAULT_MESSAGE_TAG.to_string(),
        }
    }
}

fn default_min_proof_value_sat() -> u64 {
    DEFAULT_MIN_PROOF_VALUE_SAT
}
fn default_message_tag() -> String {
    DEFAULT_MESSAGE_TAG.to_string()
}

// --- Bitcoin watcher config ---
//
// Polls mempool.bullbitcoin.com for invoice on-chain BTC settlement.
// Active/idle tier split keeps load proportional to fresh-invoice
// activity; the token bucket bounds RPS against the upstream API.

const DEFAULT_BTC_WATCHER_ENDPOINT: &str = "https://mempool.bullbitcoin.com/api";
const DEFAULT_BTC_WATCHER_ACTIVE_TICK_SECS: u64 = 30;
const DEFAULT_BTC_WATCHER_IDLE_TICK_SECS: u64 = 300;
const DEFAULT_BTC_WATCHER_ACTIVE_WINDOW_SECS: i64 = 3600;
const DEFAULT_BTC_WATCHER_CONFIRMATIONS_REQUIRED: u32 = 3;
const DEFAULT_BTC_WATCHER_RATE_PER_SEC: u32 = 5;
const DEFAULT_BTC_WATCHER_REQUEST_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinWatcherConfig {
    /// When false, the watcher is not spawned at all. Useful in dev
    /// environments without outbound network or when the operator wants
    /// to drain the existing flow before flipping BTC support on.
    #[serde(default = "default_btc_watcher_enabled")]
    pub enabled: bool,
    /// mempool.space-shape API root (no trailing slash). Defaults to
    /// Bull's own instance to keep the watcher inside the trust
    /// boundary; rate limits there are ours to set.
    #[serde(default = "default_btc_watcher_endpoint")]
    pub endpoint: String,
    /// Extra esplora endpoints appended after `endpoint` as ordered failovers.
    /// The two hardcoded providers (Bull Bitcoin + Blockstream) are always
    /// appended after these, so leaving this empty still yields failover.
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// Active-tier poll period for "fresh" invoices (created within
    /// `active_window_secs`).
    #[serde(default = "default_btc_watcher_active_tick_secs")]
    pub active_tick_secs: u64,
    /// Idle-tier poll period for older invoices that stayed unpaid.
    #[serde(default = "default_btc_watcher_idle_tick_secs")]
    pub idle_tick_secs: u64,
    /// An invoice is "active" if `created_at > NOW() - active_window_secs`.
    #[serde(default = "default_btc_watcher_active_window_secs")]
    pub active_window_secs: i64,
    /// Confirmation depth at which an already-accounted transaction becomes
    /// final. Accounting always starts at exactly one confirmation; this
    /// deployment-tunable threshold controls settlement finality only.
    #[serde(default = "default_btc_watcher_confirmations_required")]
    pub confirmations_required: u32,
    /// Token-bucket refill rate against the mempool endpoint.
    #[serde(default = "default_btc_watcher_rate_per_sec")]
    pub rate_per_sec: u32,
    /// Per-request HTTP timeout. The watcher logs and skips a tick on
    /// timeout rather than blocking the loop.
    #[serde(default = "default_btc_watcher_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

/// Hardcoded Bitcoin esplora failover providers (Bull Bitcoin, Blockstream),
/// appended after the configured endpoint(s). mempool.space-shape REST; values
/// from the bullbitcoin-mobile wallet defaults.
pub const BUILTIN_BTC_ESPLORA_ENDPOINTS: [&str; 2] = [
    "https://mempool.bullbitcoin.com/api",
    "https://mempool.space/api",
];

impl BitcoinWatcherConfig {
    pub fn finality_valid(&self) -> bool {
        self.confirmations_required > 0
    }

    /// Validate only operator-visible settings. Built-in failovers remain
    /// available to existing observation/recovery work, but they must not hide
    /// malformed explicit configuration from money admission.
    pub fn explicit_endpoints_valid(&self) -> bool {
        valid_http_endpoint(&self.endpoint)
            && self
                .endpoints
                .iter()
                .all(|endpoint| valid_http_endpoint(endpoint))
    }

    /// Ordered, deduplicated esplora endpoint list: configured `endpoint`
    /// first (primary), then any extra `endpoints`, then the two hardcoded
    /// provider failovers. Trailing slashes trimmed. Never empty. Behaviour is
    /// unchanged while the primary is healthy — the rest are only tried on error.
    pub fn effective_endpoints(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let configured = std::iter::once(self.endpoint.as_str())
            .chain(self.endpoints.iter().map(String::as_str))
            .chain(BUILTIN_BTC_ESPLORA_ENDPOINTS);
        for u in configured {
            let n = u.trim_end_matches('/').to_string();
            if !n.is_empty() && !out.contains(&n) {
                out.push(n);
            }
        }
        out
    }
}

impl Default for BitcoinWatcherConfig {
    fn default() -> Self {
        Self {
            enabled: default_btc_watcher_enabled(),
            endpoint: default_btc_watcher_endpoint(),
            endpoints: Vec::new(),
            active_tick_secs: default_btc_watcher_active_tick_secs(),
            idle_tick_secs: default_btc_watcher_idle_tick_secs(),
            active_window_secs: default_btc_watcher_active_window_secs(),
            confirmations_required: default_btc_watcher_confirmations_required(),
            rate_per_sec: default_btc_watcher_rate_per_sec(),
            request_timeout_ms: default_btc_watcher_request_timeout_ms(),
        }
    }
}

fn default_btc_watcher_enabled() -> bool {
    true
}
fn default_btc_watcher_endpoint() -> String {
    DEFAULT_BTC_WATCHER_ENDPOINT.to_string()
}
fn default_btc_watcher_active_tick_secs() -> u64 {
    DEFAULT_BTC_WATCHER_ACTIVE_TICK_SECS
}
fn default_btc_watcher_idle_tick_secs() -> u64 {
    DEFAULT_BTC_WATCHER_IDLE_TICK_SECS
}
fn default_btc_watcher_active_window_secs() -> i64 {
    DEFAULT_BTC_WATCHER_ACTIVE_WINDOW_SECS
}
fn default_btc_watcher_confirmations_required() -> u32 {
    DEFAULT_BTC_WATCHER_CONFIRMATIONS_REQUIRED
}
fn default_btc_watcher_rate_per_sec() -> u32 {
    DEFAULT_BTC_WATCHER_RATE_PER_SEC
}
fn default_btc_watcher_request_timeout_ms() -> u64 {
    DEFAULT_BTC_WATCHER_REQUEST_TIMEOUT_MS
}

// --- Liquid direct-payment watcher config ---

const DEFAULT_LIQUID_WATCHER_FINALITY_CONFIRMATIONS: u32 = 2;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidWatcherConfig {
    /// Confirmation depth at which an already-accounted Liquid transaction
    /// becomes final. Accounting always starts at exactly one confirmation.
    #[serde(default = "default_liquid_watcher_finality_confirmations")]
    pub finality_confirmations: u32,
}

impl Default for LiquidWatcherConfig {
    fn default() -> Self {
        Self {
            finality_confirmations: default_liquid_watcher_finality_confirmations(),
        }
    }
}

impl LiquidWatcherConfig {
    pub fn finality_valid(&self) -> bool {
        self.finality_confirmations > 0
    }
}

fn default_liquid_watcher_finality_confirmations() -> u32 {
    DEFAULT_LIQUID_WATCHER_FINALITY_CONFIRMATIONS
}

// --- Rate limit config ---

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// IPs / CIDR ranges that bypass ALL rate limits and proof requirements.
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    /// Trust the X-Forwarded-For header for caller IP resolution.
    /// Set true only behind a known reverse proxy.
    #[serde(default)]
    pub trust_forwarded_for: bool,

    #[serde(default = "default_per_ip_limit")]
    pub per_ip_limit: u32,
    #[serde(default = "default_per_ip_window_secs")]
    pub per_ip_window_secs: u32,

    #[serde(default = "default_per_pubkey_limit")]
    pub per_pubkey_limit: u32,
    #[serde(default = "default_per_pubkey_window_secs")]
    pub per_pubkey_window_secs: u32,

    /// Max distinct nyms a single IPv4 source may probe per
    /// `distinct_nyms_window_secs`. 0 disables the check. Loosened
    /// vs `distinct_nyms_per_ipv6_56_limit` because IPv4 sources are
    /// often CGNAT / office NAT / family households (one /32 is many
    /// real users); IPv6 /56 is a single ISP customer allocation.
    #[serde(default = "default_distinct_nyms_per_ip")]
    pub distinct_nyms_per_ip_limit: u32,
    /// Max distinct nyms a single IPv6 /56 source may probe per
    /// `distinct_nyms_window_secs`. Tighter than the v4 cap because
    /// /56 is the canonical ISP-customer block and represents one
    /// real user / household, not many. 0 disables the check.
    #[serde(default = "default_distinct_nyms_per_ipv6_56")]
    pub distinct_nyms_per_ipv6_56_limit: u32,
    /// Max distinct nyms a single proof-of-funds outpoint may be reused
    /// against per `distinct_nyms_window_secs`. 0 disables the check.
    #[serde(default = "default_distinct_nyms_per_outpoint")]
    pub distinct_nyms_per_outpoint_limit: u32,
    /// Window for the distinct-nyms-per-source counters (seconds).
    #[serde(default = "default_distinct_nyms_window_secs")]
    pub distinct_nyms_window_secs: u32,

    #[serde(default = "default_max_pending_per_nym")]
    pub max_pending_reservations_per_nym: u32,
    #[serde(default = "default_recycle_days")]
    pub recycle_pending_older_than_days: u32,

    #[serde(default = "default_lightning_rate")]
    pub lightning_rate_per_minute: u32,

    #[serde(default = "default_global_electrum_rate")]
    pub global_electrum_rate_per_sec: u32,

    // --- Registration gates ---
    /// Per-IP rate-limit on `/register*` endpoints. 0 disables.
    #[serde(default = "default_register_rate_limit")]
    pub register_rate_limit: u32,
    #[serde(default = "default_register_rate_window_secs")]
    pub register_rate_window_secs: u32,

    /// Per-IP distinct-npubs cap on `POST /register` over the configured
    /// window. Stops one IP from registering many distinct identities even
    /// if it spaces them out under the per-IP rate. 0 disables.
    #[serde(default = "default_register_distinct_npubs_per_ip")]
    pub register_distinct_npubs_per_ip_limit: u32,
    #[serde(default = "default_register_distinct_npubs_per_ip_window_secs")]
    pub register_distinct_npubs_per_ip_window_secs: u32,

    /// Hard ceiling on total active users. New `POST /register` returns 503
    /// once `count(*) WHERE is_active = TRUE >= max_active_users`.
    /// 0 disables the check.
    #[serde(default = "default_max_active_users")]
    pub max_active_users: u32,

    // --- General API + metadata enumeration gates ---
    /// Cheap per-source gate used before signature verification or
    /// database-heavy reads. Covers public metadata, Payment Page management,
    /// and signed invoice management. 0 disables. The legacy `metadata_*`
    /// keys remain accepted so existing deployments do not need a flag day.
    #[serde(default = "default_api_rate_limit", alias = "metadata_rate_limit")]
    pub api_rate_limit: u32,
    #[serde(
        default = "default_api_rate_window_secs",
        alias = "metadata_rate_window_secs"
    )]
    pub api_rate_window_secs: u32,

    /// Distinct nyms a single IP can probe across the metadata endpoints
    /// per window. Bounds enumeration even when the per-IP rate is unhit
    /// (slow-drip nym discovery). 0 disables.
    #[serde(default = "default_metadata_distinct_nyms_per_ip")]
    pub metadata_distinct_nyms_per_ip_limit: u32,
    #[serde(default = "default_metadata_distinct_nyms_per_ip_window_secs")]
    pub metadata_distinct_nyms_per_ip_window_secs: u32,

    /// Distinct npubs a single IP can probe via `GET /register/lookup`
    /// per window. Same shape as `metadata_distinct_nyms_per_ip_limit`
    /// but on the npub-side enumeration vector. 0 disables.
    #[serde(default = "default_lookup_distinct_npubs_per_ip")]
    pub lookup_distinct_npubs_per_ip_limit: u32,
    #[serde(default = "default_lookup_distinct_npubs_per_ip_window_secs")]
    pub lookup_distinct_npubs_per_ip_window_secs: u32,

    // --- Chain watcher ---
    /// Dedicated Electrum token bucket carved out for the chain watcher,
    /// separate from the user-facing `global_electrum_rate_per_sec`. A
    /// callback storm against `/lnurlp/callback` cannot starve the watcher
    /// (and vice-versa) because they consume different buckets.
    #[serde(default = "default_chain_watcher_electrum_rate")]
    pub chain_watcher_electrum_rate_per_sec: u32,

    /// Watcher ticks on "active" users every `active_user_tick_secs`.
    /// Idle users (no callback within `active_window_secs`) only get
    /// scanned every `idle_user_tick_secs`. Bounds per-tick work to the
    /// active subset, which is typically <1% of the `users` table.
    #[serde(default = "default_chain_watcher_active_user_tick_secs")]
    pub chain_watcher_active_user_tick_secs: u32,
    #[serde(default = "default_chain_watcher_idle_user_tick_secs")]
    pub chain_watcher_idle_user_tick_secs: u32,
    #[serde(default = "default_chain_watcher_active_window_secs")]
    pub chain_watcher_active_window_secs: u32,

    /// Per-source rate-limit on `/webhook/boltz`. Bounds webhook-bomb
    /// blast radius even if the URL secret leaks. Real Boltz traffic
    /// hits one swap_id at a time with ~5 events end-to-end, well under
    /// 10/min.
    #[serde(default = "default_webhook_rate_limit")]
    pub webhook_rate_limit: u32,
    #[serde(default = "default_webhook_rate_window_secs")]
    pub webhook_rate_window_secs: u32,

    /// Per-source rate-limit on Lightning ops, covering both explicit
    /// `network=lightning` callbacks and Liquid-to-Lightning soft fallbacks.
    /// 0 disables the check.
    ///
    /// Per-source (not per-nym) is correct shape under the v2 principle:
    /// many payers paying one merchant via Lightning is normal; one
    /// source making many Lightning ops across many merchants is not.
    /// The cap also bounds Boltz API spend under a fallback storm.
    #[serde(default = "default_lightning_per_source_limit")]
    pub lightning_per_source_limit: u32,
    #[serde(default = "default_lightning_per_source_window_secs")]
    pub lightning_per_source_window_secs: u32,

    // --- Donation page render ---
    /// Per-source rate-limit on `GET /<nym>` donation-page HTML renders.
    /// Public, browser-facing, no auth — bounds volumetric scraping. 0
    /// disables the check.
    #[serde(default = "default_donation_html_rate_limit")]
    pub donation_html_rate_limit: u32,
    #[serde(default = "default_donation_html_rate_window_secs")]
    pub donation_html_rate_window_secs: u32,
    /// Per-source rate-limit on `GET /<nym>/manifest.webmanifest`.
    /// Kept separate from HTML so install metadata fetches don't double-bill
    /// normal page loads.
    #[serde(default = "default_donation_manifest_rate_limit")]
    pub donation_manifest_rate_limit: u32,
    #[serde(default = "default_donation_manifest_rate_window_secs")]
    pub donation_manifest_rate_window_secs: u32,

    // --- Donation page image upload ---
    /// Per-npub upload rate-limit on `POST /donation-page/image`. Tight
    /// because a real user uploads avatar + OG once per session, not
    /// many times per hour.
    #[serde(default = "default_donation_image_uploads_per_npub_per_hour")]
    pub donation_image_uploads_per_npub_per_hour: u32,
    /// Per-source upload rate-limit. Defense-in-depth against IP-rotated
    /// abuse — stops one IP from uploading to many npubs in quick
    /// succession.
    #[serde(default = "default_donation_image_uploads_per_source_per_min")]
    pub donation_image_uploads_per_source_per_min: u32,

    /// Per-source rate-limit on public invoice status polling.
    #[serde(
        default = "default_invoice_status_per_source_per_min",
        alias = "donation_status_per_source_per_min"
    )]
    pub invoice_status_per_source_per_min: u32,

    // --- Invoices ---
    /// Per-source rate-limit on anonymous `POST /<nym>/invoice`.
    /// Each invoice creation is a real DB write + eager Boltz reverse-swap
    /// allocation; refresh-driven retries should land on the existing
    /// invoice URL. 0 disables the check.
    #[serde(default = "default_invoice_create_per_source_per_min")]
    pub invoice_create_per_source_per_min: u32,
    /// Per-npub rate-limit on signed `POST /api/v1/<nym>/invoices`.
    /// Bounds runaway wallet-origin invoice creation (e.g., a stolen
    /// mobile credential). 100/h matches a heavy daily merchant
    /// without blocking a legitimate burst. 0 disables the check.
    #[serde(default = "default_invoice_create_per_npub_per_hour")]
    pub invoice_create_per_npub_per_hour: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            ip_whitelist: Vec::new(),
            trust_forwarded_for: false,
            per_ip_limit: default_per_ip_limit(),
            per_ip_window_secs: default_per_ip_window_secs(),
            per_pubkey_limit: default_per_pubkey_limit(),
            per_pubkey_window_secs: default_per_pubkey_window_secs(),
            distinct_nyms_per_ip_limit: default_distinct_nyms_per_ip(),
            distinct_nyms_per_ipv6_56_limit: default_distinct_nyms_per_ipv6_56(),
            distinct_nyms_per_outpoint_limit: default_distinct_nyms_per_outpoint(),
            distinct_nyms_window_secs: default_distinct_nyms_window_secs(),
            max_pending_reservations_per_nym: default_max_pending_per_nym(),
            recycle_pending_older_than_days: default_recycle_days(),
            lightning_rate_per_minute: default_lightning_rate(),
            global_electrum_rate_per_sec: default_global_electrum_rate(),
            register_rate_limit: default_register_rate_limit(),
            register_rate_window_secs: default_register_rate_window_secs(),
            register_distinct_npubs_per_ip_limit: default_register_distinct_npubs_per_ip(),
            register_distinct_npubs_per_ip_window_secs:
                default_register_distinct_npubs_per_ip_window_secs(),
            max_active_users: default_max_active_users(),
            api_rate_limit: default_api_rate_limit(),
            api_rate_window_secs: default_api_rate_window_secs(),
            metadata_distinct_nyms_per_ip_limit: default_metadata_distinct_nyms_per_ip(),
            metadata_distinct_nyms_per_ip_window_secs:
                default_metadata_distinct_nyms_per_ip_window_secs(),
            lookup_distinct_npubs_per_ip_limit: default_lookup_distinct_npubs_per_ip(),
            lookup_distinct_npubs_per_ip_window_secs:
                default_lookup_distinct_npubs_per_ip_window_secs(),
            chain_watcher_electrum_rate_per_sec: default_chain_watcher_electrum_rate(),
            chain_watcher_active_user_tick_secs: default_chain_watcher_active_user_tick_secs(),
            chain_watcher_idle_user_tick_secs: default_chain_watcher_idle_user_tick_secs(),
            chain_watcher_active_window_secs: default_chain_watcher_active_window_secs(),
            webhook_rate_limit: default_webhook_rate_limit(),
            webhook_rate_window_secs: default_webhook_rate_window_secs(),
            lightning_per_source_limit: default_lightning_per_source_limit(),
            lightning_per_source_window_secs: default_lightning_per_source_window_secs(),
            donation_html_rate_limit: default_donation_html_rate_limit(),
            donation_html_rate_window_secs: default_donation_html_rate_window_secs(),
            donation_manifest_rate_limit: default_donation_manifest_rate_limit(),
            donation_manifest_rate_window_secs: default_donation_manifest_rate_window_secs(),
            donation_image_uploads_per_npub_per_hour:
                default_donation_image_uploads_per_npub_per_hour(),
            donation_image_uploads_per_source_per_min:
                default_donation_image_uploads_per_source_per_min(),
            invoice_status_per_source_per_min: default_invoice_status_per_source_per_min(),
            invoice_create_per_source_per_min: default_invoice_create_per_source_per_min(),
            invoice_create_per_npub_per_hour: default_invoice_create_per_npub_per_hour(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CertificationConfig {
    /// Scoped certification mode for deterministic production/staging
    /// assessment. Separate from `rate_limit.ip_whitelist`: a certification
    /// bypass requires an allowed source, a token, and an explicit scope.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub source_allowlist: Vec<String>,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

fn default_per_ip_limit() -> u32 {
    60
}
fn default_per_ip_window_secs() -> u32 {
    60
}
/// Disabled by default (0). The per-pubkey sliding-window check is redundant
/// with the per-outpoint distinct-nym check; field is kept for backwards
/// compatibility with deployed configs that explicitly set a non-zero value.
fn default_per_pubkey_limit() -> u32 {
    0
}
fn default_per_pubkey_window_secs() -> u32 {
    3600
}
// --- Asymmetric-defense thresholds ---
// Real payers touch 0-2 distinct nyms per day. Real merchants get paid by
// many distinct payers per day. So per-source distinct-target caps are
// kept tight; per-target rate caps are removed.
fn default_distinct_nyms_per_ip() -> u32 {
    5
}
fn default_distinct_nyms_per_ipv6_56() -> u32 {
    3
}
fn default_distinct_nyms_per_outpoint() -> u32 {
    3
}
fn default_distinct_nyms_window_secs() -> u32 {
    3600
}
/// Memory bound only — the real defense against per-nym pollution is the
/// per-source distinct-outpoints cap + the GC recycler on
/// `outpoint_addresses` rows. This number should never fire under normal
/// operation. (was 500; punished popular merchants.)
fn default_max_pending_per_nym() -> u32 {
    50_000
}
fn default_recycle_days() -> u32 {
    30
}
/// Disabled by default: per-nym Lightning rate is wrong-shape. A popular
/// merchant being paid via Lightning Address can legitimately exceed any
/// per-nym rate — bursts during business hours are normal. Keep the field
/// for backwards compat with deployed configs that explicitly set it.
fn default_lightning_rate() -> u32 {
    0
}
fn default_global_electrum_rate() -> u32 {
    50
}
fn default_register_rate_limit() -> u32 {
    5
}
fn default_register_rate_window_secs() -> u32 {
    60
}
// Accommodates phone reset (new install regenerates the Nostr identity)
// and family device sharing from one IP.
fn default_register_distinct_npubs_per_ip() -> u32 {
    3
}
fn default_register_distinct_npubs_per_ip_window_secs() -> u32 {
    3600
}
// Meaningful operational capacity trigger: high enough for organic growth,
// low enough to fire before surprise scale changes become invisible.
fn default_max_active_users() -> u32 {
    10_000
}
fn default_api_rate_limit() -> u32 {
    30
}
fn default_api_rate_window_secs() -> u32 {
    60
}
// LUD-06 requires a metadata fetch per payment, so a small office paying
// multiple Lightning Addresses can exceed 5/h. Enumeration is still bounded
// by the distinct-target cap.
fn default_metadata_distinct_nyms_per_ip() -> u32 {
    10
}
fn default_metadata_distinct_nyms_per_ip_window_secs() -> u32 {
    3600
}
fn default_lookup_distinct_npubs_per_ip() -> u32 {
    5
}
fn default_lookup_distinct_npubs_per_ip_window_secs() -> u32 {
    3600
}
fn default_chain_watcher_electrum_rate() -> u32 {
    50
}
fn default_chain_watcher_active_user_tick_secs() -> u32 {
    30
}
fn default_chain_watcher_idle_user_tick_secs() -> u32 {
    600
}
/// 24h: a user who hasn't made a callback in a day is "idle" — payment
/// flows on Lightning addresses are bursty (one callback per pay event)
/// so 24h handles real-world traffic patterns comfortably.
fn default_chain_watcher_active_window_secs() -> u32 {
    86_400
}
fn default_webhook_rate_limit() -> u32 {
    10
}
fn default_webhook_rate_window_secs() -> u32 {
    60
}
/// 30 Lightning ops per source per hour. Lightning is the default rail
/// and doesn't leak Liquid addresses, so the cap is loose — only there
/// to bound Boltz API spend per source. (Replaces the wrong-shape
/// per-nym `lightning_rate_per_minute`, which is now a no-op kept for
/// backwards-compat with deployed configs.)
fn default_lightning_per_source_limit() -> u32 {
    30
}
fn default_lightning_per_source_window_secs() -> u32 {
    3600
}
/// 300/min: public social-preview crawlers may fetch many unrelated Pages
/// through a small shared IP pool. Nginx caching absorbs normal bursts; this
/// remains a generous per-source backstop against volumetric scraping.
fn default_donation_html_rate_limit() -> u32 {
    300
}
fn default_donation_html_rate_window_secs() -> u32 {
    60
}
fn default_donation_manifest_rate_limit() -> u32 {
    default_donation_html_rate_limit()
}
fn default_donation_manifest_rate_window_secs() -> u32 {
    default_donation_html_rate_window_secs()
}
/// 6/h per npub: a real user uploads avatar + OG once per setup; six is
/// generous headroom for retries and accidental re-uploads.
fn default_donation_image_uploads_per_npub_per_hour() -> u32 {
    6
}
/// 3/min per source: defense-in-depth against IP-rotated abuse.
fn default_donation_image_uploads_per_source_per_min() -> u32 {
    3
}
/// 60/min: invoice payment pages poll status during an active session.
fn default_invoice_status_per_source_per_min() -> u32 {
    60
}
/// 5/min per source: anonymous invoice creation is a write+swap-alloc.
/// Refresh hits the same invoice URL; new amounts mean new invoices,
/// which 5 per minute comfortably covers an indecisive sender.
fn default_invoice_create_per_source_per_min() -> u32 {
    5
}
/// 100/h per npub: signed wallet-origin invoice creation. Real-world
/// merchant volume is well under this; the cap bounds abuse via a
/// stolen mobile credential without throttling legitimate use.
fn default_invoice_create_per_npub_per_hour() -> u32 {
    100
}

// --- Electrum / tx cache config ---

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectrumConfig {
    /// Single Liquid Electrum server URL (deprecated; use `liquid_urls`).
    /// Kept for backwards-compat with existing deployed configs.
    #[serde(default)]
    pub liquid_url: Option<String>,
    /// Ordered list of Liquid Electrum server URLs. Tried in order on every
    /// reconnect; rotate on transport failure to survive single-server outages.
    #[serde(default)]
    pub liquid_urls: Vec<String>,
    #[serde(default = "default_electrum_cache_ttl")]
    pub cache_ttl_secs: u64,
    #[serde(default = "default_electrum_cache_max")]
    pub cache_max_entries: usize,
}

impl Default for ElectrumConfig {
    fn default() -> Self {
        Self {
            liquid_url: None,
            liquid_urls: vec![default_liquid_electrum_url()],
            cache_ttl_secs: default_electrum_cache_ttl(),
            cache_max_entries: default_electrum_cache_max(),
        }
    }
}

impl ElectrumConfig {
    /// Validate the configured values before built-in failovers are appended.
    /// An invalid explicit value is a rail-scoped admission failure even when
    /// a built-in endpoint can keep existing obligations recoverable.
    pub fn explicit_urls_valid(&self) -> bool {
        self.liquid_url
            .as_deref()
            .is_none_or(valid_electrum_endpoint)
            && self
                .liquid_urls
                .iter()
                .all(|url| valid_electrum_endpoint(url))
    }

    /// Resolve the configured URLs into a single ordered list, accepting
    /// either the legacy single-string field or the new list field (or both).
    /// URLs without an explicit `ssl://` or `tcp://` scheme are normalized to
    /// `ssl://` — every public Liquid Electrum server we know of uses TLS, so
    /// a bare `host:port` was the source of a long-standing PF outage where
    /// `electrum-client` defaulted to plain TCP against a TLS port.
    pub fn urls(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(u) = &self.liquid_url {
            if !u.is_empty() {
                out.push(normalize_electrum_url(u));
            }
        }
        for u in &self.liquid_urls {
            if u.is_empty() {
                continue;
            }
            let n = normalize_electrum_url(u);
            if !out.contains(&n) {
                out.push(n);
            }
        }
        if out.is_empty() {
            out.push(default_liquid_electrum_url());
        }
        out
    }

    /// `urls()` plus the two hardcoded provider failovers (Bull Bitcoin +
    /// Blockstream), deduplicated. This is what the Electrum pool is actually
    /// built from: configured URLs stay first (primary); the built-ins are pure
    /// additive redundancy, so a single-URL deployment gains failover with no
    /// behaviour change while its primary is healthy. `urls()` itself is left
    /// as the "what the operator configured" view (unchanged).
    pub fn urls_with_builtin_failover(&self) -> Vec<String> {
        let mut out = self.urls();
        for u in BUILTIN_LIQUID_ELECTRUM_URLS {
            let n = u.to_string();
            if !out.contains(&n) {
                out.push(n);
            }
        }
        out
    }
}

/// Hardcoded Liquid Electrum failover providers (Bull Bitcoin, Blockstream).
/// Values from the bullbitcoin-mobile wallet defaults (`les` first — it has
/// been the more reliable of the two).
pub const BUILTIN_LIQUID_ELECTRUM_URLS: [&str; 2] = [
    "ssl://les.bullbitcoin.com:995",
    "ssl://blockstream.info:995",
];

/// Add a default `ssl://` prefix to URLs that lack a scheme. Logs a warning
/// so operators can fix their configs.
pub fn normalize_electrum_url(raw: &str) -> String {
    if raw.starts_with("ssl://") || raw.starts_with("tcp://") {
        raw.to_string()
    } else {
        tracing::warn!(
            "electrum url '{}' has no ssl:// or tcp:// scheme; assuming ssl://. \
             Add an explicit prefix in config to silence this warning.",
            raw
        );
        format!("ssl://{}", raw)
    }
}

pub fn valid_electrum_endpoint(raw: &str) -> bool {
    let host_port = if let Some(endpoint) = raw.strip_prefix("ssl://") {
        endpoint
    } else if let Some(endpoint) = raw.strip_prefix("tcp://") {
        endpoint
    } else if raw.contains("://") {
        return false;
    } else {
        raw
    };
    let Some((_, port)) = host_port.rsplit_once(':') else {
        return false;
    };
    if !port.parse::<u16>().is_ok_and(|port| port != 0) {
        return false;
    }
    reqwest::Url::parse(&format!("http://{host_port}")).is_ok_and(|url| {
        url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

pub fn valid_http_endpoint(raw: &str) -> bool {
    reqwest::Url::parse(raw).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.port() != Some(0)
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn default_liquid_electrum_url() -> String {
    "ssl://blockstream.info:995".to_string()
}
fn default_electrum_cache_ttl() -> u64 {
    3600
}
fn default_electrum_cache_max() -> usize {
    10_000
}

fn default_pool_size() -> u32 {
    DEFAULT_POOL_SIZE
}
fn default_min_sendable() -> u64 {
    DEFAULT_MIN_SENDABLE_MSAT
}
fn default_max_sendable() -> u64 {
    DEFAULT_MAX_SENDABLE_MSAT
}
fn default_max_descriptor_len() -> usize {
    DEFAULT_MAX_DESCRIPTOR_LEN
}

impl Config {
    pub fn liquid_claim_settings_valid(&self) -> bool {
        valid_electrum_endpoint(&self.boltz.electrum_url) && self.electrum.explicit_urls_valid()
    }

    /// Ordered, deduplicated Liquid Electrum URL list for the CLAIM path
    /// (chain-swap + reverse-swap claim construction/broadcast). The legacy
    /// single `boltz.electrum_url` stays the primary; the `[electrum]` pool
    /// (which now ends with the hardcoded Bull Bitcoin + Blockstream failovers)
    /// follows. Deduped on the normalized `ssl://` form. Behaviour is unchanged
    /// while the primary is healthy — the rest are only tried on error.
    pub fn claim_liquid_electrum_urls(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let primary = normalize_electrum_url(&self.boltz.electrum_url);
        if !self.boltz.electrum_url.is_empty() {
            out.push(primary);
        }
        for u in self.electrum.urls_with_builtin_failover() {
            if !out.contains(&u) {
                out.push(u);
            }
        }
        if out.is_empty() {
            out.push(default_liquid_electrum_url());
        }
        out
    }

    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;

        config.database_url = std::env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL environment variable is required")?;
        config.swap_mnemonic = std::env::var("SWAP_MNEMONIC")
            .map_err(|_| "SWAP_MNEMONIC environment variable is required")?;
        // See docs/compatibility-ledger.md for the env-var fallback.
        config.boltz_webhook_url_secret = std::env::var("BOLTZ_WEBHOOK_URL_SECRET")
            .or_else(|_| std::env::var("BOLTZ_WEBHOOK_SECRET"))
            .unwrap_or_default();
        config.boltz_webhook_url_secret_previous =
            std::env::var("BOLTZ_WEBHOOK_URL_SECRET_PREVIOUS").unwrap_or_default();

        let runtime_mode =
            std::env::var("BULLNYM_RUNTIME_MODE").unwrap_or_else(|_| "unknown".into());
        let allow_public_listen = std::env::var("BULLNYM_ALLOW_PUBLIC_LISTEN")
            .map(|v| env_flag_enabled(&v))
            .unwrap_or(false);
        config.validate_for_runtime(&runtime_mode, allow_public_listen)?;
        Ok(config)
    }

    fn validate_for_runtime(
        &self,
        runtime_mode: &str,
        allow_public_listen: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.validate_common()?;
        if runtime_mode == "production" {
            self.validate_production(allow_public_listen)?;
        }
        Ok(())
    }

    fn validate_common(&self) -> Result<(), Box<dyn std::error::Error>> {
        validate_domain(&self.domain)?;
        listen_addr_is_non_loopback(&self.listen)?;
        if self.pool_size == 0 {
            return Err("pool_size must be > 0".into());
        }
        validate_http_endpoint("boltz.api_url", &self.boltz.api_url)?;
        validate_webhook_secret("BOLTZ_WEBHOOK_URL_SECRET", &self.boltz_webhook_url_secret)?;
        validate_webhook_secret(
            "BOLTZ_WEBHOOK_URL_SECRET_PREVIOUS",
            &self.boltz_webhook_url_secret_previous,
        )?;
        if self.boltz.key_epoch <= 0 {
            return Err("boltz.key_epoch must be > 0".into());
        }
        if self.limits.min_sendable_msat > self.limits.max_sendable_msat {
            return Err("min_sendable_msat must be <= max_sendable_msat".into());
        }
        if self.limits.min_sendable_msat == 0 {
            return Err("min_sendable_msat must be > 0".into());
        }
        if self.proof.message_tag.is_empty() {
            return Err("proof.message_tag must be non-empty".into());
        }
        if self.proof.min_proof_value_sat == 0 {
            return Err("proof.min_proof_value_sat must be > 0".into());
        }
        if self.limits.max_descriptor_len == 0 {
            return Err("limits.max_descriptor_len must be > 0".into());
        }
        if self.limits.max_lifetime_nyms_per_npub <= 0 {
            return Err("limits.max_lifetime_nyms_per_npub must be > 0".into());
        }
        if self.invoice_accounting.btc_shortfall_tolerance_sat < 0
            || self.invoice_accounting.liquid_shortfall_tolerance_sat < 0
            || self.invoice_accounting.lightning_shortfall_tolerance_sat < 0
        {
            return Err("invoice shortfall tolerances must be >= 0".into());
        }
        if self.claim.max_claim_attempts <= 0 {
            return Err("claim.max_claim_attempts must be > 0".into());
        }
        require_positive("reconciler.interval_secs", self.reconciler.interval_secs)?;
        require_positive_u32("reconciler.max_per_tick", self.reconciler.max_per_tick)?;
        require_positive(
            "reconciler.slow_recovery_interval_secs",
            self.reconciler.slow_recovery_interval_secs,
        )?;
        require_positive_u32(
            "reconciler.slow_recovery_max_per_tick",
            self.reconciler.slow_recovery_max_per_tick,
        )?;
        require_positive(
            "reconciler.slow_recovery_backoff_base_secs",
            self.reconciler.slow_recovery_backoff_base_secs,
        )?;
        require_positive(
            "reconciler.slow_recovery_backoff_cap_secs",
            self.reconciler.slow_recovery_backoff_cap_secs,
        )?;
        if self.reconciler.slow_recovery_backoff_base_secs
            > self.reconciler.slow_recovery_backoff_cap_secs
        {
            return Err("reconciler slow-recovery backoff base must be <= cap".into());
        }
        validate_http_endpoint("pricer.url", &self.pricer.url)?;
        require_positive("pricer.request_timeout_ms", self.pricer.request_timeout_ms)?;
        if self.pwa.dist_dir.trim().is_empty() {
            return Err("pwa.dist_dir must be non-empty".into());
        }
        if self.donation.image_max_dimension == 0 {
            return Err("donation.image_max_dimension must be > 0".into());
        }
        if self.donation.image_max_pixels == 0 {
            return Err("donation.image_max_pixels must be > 0".into());
        }
        require_positive(
            "bitcoin_watcher.active_tick_secs",
            self.bitcoin_watcher.active_tick_secs,
        )?;
        require_positive(
            "bitcoin_watcher.idle_tick_secs",
            self.bitcoin_watcher.idle_tick_secs,
        )?;
        if self.bitcoin_watcher.active_window_secs < 0 {
            return Err("bitcoin_watcher.active_window_secs must be >= 0".into());
        }
        require_positive_u32(
            "bitcoin_watcher.rate_per_sec",
            self.bitcoin_watcher.rate_per_sec,
        )?;
        require_positive(
            "bitcoin_watcher.request_timeout_ms",
            self.bitcoin_watcher.request_timeout_ms,
        )?;
        if self.electrum.cache_max_entries == 0 {
            return Err("electrum.cache_max_entries must be > 0".into());
        }
        require_positive_u32(
            "rate_limit.max_pending_reservations_per_nym",
            self.rate_limit.max_pending_reservations_per_nym,
        )?;
        require_positive_u32(
            "rate_limit.global_electrum_rate_per_sec",
            self.rate_limit.global_electrum_rate_per_sec,
        )?;
        require_positive_u32(
            "rate_limit.chain_watcher_electrum_rate_per_sec",
            self.rate_limit.chain_watcher_electrum_rate_per_sec,
        )?;
        require_positive_u32(
            "rate_limit.chain_watcher_active_user_tick_secs",
            self.rate_limit.chain_watcher_active_user_tick_secs,
        )?;
        require_positive_u32(
            "rate_limit.chain_watcher_idle_user_tick_secs",
            self.rate_limit.chain_watcher_idle_user_tick_secs,
        )?;
        validate_rate_limit_windows(&self.rate_limit)?;
        if self.certification.enabled {
            if self.certification.token.is_empty() {
                return Err("certification.token must be non-empty when enabled".into());
            }
            if self.certification.source_allowlist.is_empty() {
                return Err("certification.source_allowlist must be non-empty when enabled".into());
            }
            if self.certification.scopes.is_empty() {
                return Err("certification.scopes must be non-empty when enabled".into());
            }
        }
        Ok(())
    }

    fn validate_production(
        &self,
        allow_public_listen: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.boltz_webhook_url_secret.is_empty() {
            return Err(
                "BOLTZ_WEBHOOK_URL_SECRET must be set when BULLNYM_RUNTIME_MODE=production".into(),
            );
        }
        let host = domain_host(&self.domain)?;
        let loopback_ip = host
            .trim_matches(|character| matches!(character, '[' | ']'))
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
        if host.eq_ignore_ascii_case("localhost") || loopback_ip {
            return Err("domain must not be localhost or a loopback IP in production".into());
        }
        if !allow_public_listen && listen_addr_is_non_loopback(&self.listen)? {
            return Err(
                "listen must bind loopback in production; use 127.0.0.1 or set BULLNYM_ALLOW_PUBLIC_LISTEN=true".into(),
            );
        }
        Ok(())
    }
}

fn require_positive(name: &str, value: u64) -> Result<(), Box<dyn std::error::Error>> {
    if value == 0 {
        return Err(format!("{name} must be > 0").into());
    }
    Ok(())
}

fn require_positive_u32(name: &str, value: u32) -> Result<(), Box<dyn std::error::Error>> {
    require_positive(name, u64::from(value))
}

fn validate_http_endpoint(name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !valid_http_endpoint(value) {
        return Err(format!(
            "{name} must be an http(s) URL with a host and no credentials, query, fragment, or port 0"
        )
        .into());
    }
    Ok(())
}

fn domain_host(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = reqwest::Url::parse(&format!("https://{value}"))
        .map_err(|error| format!("domain is invalid: {error}"))?;
    parsed
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| "domain must contain a host".into())
}

fn validate_domain(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.is_empty() || value.trim() != value || value.contains("://") || value.contains('/') {
        return Err("domain must be a non-empty host[:port] without a scheme or path".into());
    }
    let parsed = reqwest::Url::parse(&format!("https://{value}"))
        .map_err(|error| format!("domain is invalid: {error}"))?;
    if parsed.host_str().is_none()
        || parsed.port() == Some(0)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err("domain must be a host[:port]".into());
    }
    Ok(())
}

fn validate_webhook_secret(name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.is_empty() {
        return Ok(());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'?' | b'#' | b'%'))
    {
        return Err(format!("{name} must be one URL path segment without escapes").into());
    }
    Ok(())
}

fn validate_limit_window(
    limit_name: &str,
    limit: u32,
    window_name: &str,
    window_secs: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    if limit > 0 && window_secs == 0 {
        return Err(format!("{window_name} must be > 0 when {limit_name} is enabled").into());
    }
    Ok(())
}

fn validate_rate_limit_windows(config: &RateLimitConfig) -> Result<(), Box<dyn std::error::Error>> {
    for (limit_name, limit, window_name, window_secs) in [
        (
            "rate_limit.per_ip_limit",
            config.per_ip_limit,
            "rate_limit.per_ip_window_secs",
            config.per_ip_window_secs,
        ),
        (
            "rate_limit.per_pubkey_limit",
            config.per_pubkey_limit,
            "rate_limit.per_pubkey_window_secs",
            config.per_pubkey_window_secs,
        ),
        (
            "rate_limit.distinct_nyms_per_ip_limit",
            config.distinct_nyms_per_ip_limit,
            "rate_limit.distinct_nyms_window_secs",
            config.distinct_nyms_window_secs,
        ),
        (
            "rate_limit.distinct_nyms_per_ipv6_56_limit",
            config.distinct_nyms_per_ipv6_56_limit,
            "rate_limit.distinct_nyms_window_secs",
            config.distinct_nyms_window_secs,
        ),
        (
            "rate_limit.distinct_nyms_per_outpoint_limit",
            config.distinct_nyms_per_outpoint_limit,
            "rate_limit.distinct_nyms_window_secs",
            config.distinct_nyms_window_secs,
        ),
        (
            "rate_limit.register_rate_limit",
            config.register_rate_limit,
            "rate_limit.register_rate_window_secs",
            config.register_rate_window_secs,
        ),
        (
            "rate_limit.register_distinct_npubs_per_ip_limit",
            config.register_distinct_npubs_per_ip_limit,
            "rate_limit.register_distinct_npubs_per_ip_window_secs",
            config.register_distinct_npubs_per_ip_window_secs,
        ),
        (
            "rate_limit.api_rate_limit",
            config.api_rate_limit,
            "rate_limit.api_rate_window_secs",
            config.api_rate_window_secs,
        ),
        (
            "rate_limit.metadata_distinct_nyms_per_ip_limit",
            config.metadata_distinct_nyms_per_ip_limit,
            "rate_limit.metadata_distinct_nyms_per_ip_window_secs",
            config.metadata_distinct_nyms_per_ip_window_secs,
        ),
        (
            "rate_limit.lookup_distinct_npubs_per_ip_limit",
            config.lookup_distinct_npubs_per_ip_limit,
            "rate_limit.lookup_distinct_npubs_per_ip_window_secs",
            config.lookup_distinct_npubs_per_ip_window_secs,
        ),
        (
            "rate_limit.webhook_rate_limit",
            config.webhook_rate_limit,
            "rate_limit.webhook_rate_window_secs",
            config.webhook_rate_window_secs,
        ),
        (
            "rate_limit.lightning_per_source_limit",
            config.lightning_per_source_limit,
            "rate_limit.lightning_per_source_window_secs",
            config.lightning_per_source_window_secs,
        ),
        (
            "rate_limit.donation_html_rate_limit",
            config.donation_html_rate_limit,
            "rate_limit.donation_html_rate_window_secs",
            config.donation_html_rate_window_secs,
        ),
        (
            "rate_limit.donation_manifest_rate_limit",
            config.donation_manifest_rate_limit,
            "rate_limit.donation_manifest_rate_window_secs",
            config.donation_manifest_rate_window_secs,
        ),
    ] {
        validate_limit_window(limit_name, limit, window_name, window_secs)?;
    }
    Ok(())
}

fn env_flag_enabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn listen_addr_is_non_loopback(listen: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let addr: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| format!("listen must be a socket address host:port: {e}"))?;
    Ok(!addr.ip().is_loopback())
}

#[cfg(test)]
mod tests;

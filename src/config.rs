use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub domain: String,
    pub listen: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    pub boltz: BoltzConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub proof: ProofConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub electrum: ElectrumConfig,
    #[serde(skip)]
    pub database_url: String,
    #[serde(skip)]
    pub swap_mnemonic: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BoltzConfig {
    pub api_url: String,
    pub electrum_url: String,
}

const DEFAULT_POOL_SIZE: u32 = 10;
const DEFAULT_MIN_SENDABLE_MSAT: u64 = 100_000;
const DEFAULT_MAX_SENDABLE_MSAT: u64 = 25_000_000_000;
const DEFAULT_MAX_DESCRIPTOR_LEN: usize = 1000;

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_min_sendable")]
    pub min_sendable_msat: u64,
    #[serde(default = "default_max_sendable")]
    pub max_sendable_msat: u64,
    #[serde(default = "default_max_descriptor_len")]
    pub max_descriptor_len: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            min_sendable_msat: DEFAULT_MIN_SENDABLE_MSAT,
            max_sendable_msat: DEFAULT_MAX_SENDABLE_MSAT,
            max_descriptor_len: DEFAULT_MAX_DESCRIPTOR_LEN,
        }
    }
}

// --- Proof-of-funds config ---

const DEFAULT_MIN_PROOF_VALUE_SAT: u64 = 1000;
const DEFAULT_MESSAGE_TAG: &str = "bullpay-lnurlp-v1";

#[derive(Debug, Clone, Deserialize)]
pub struct ProofConfig {
    /// Minimum UTXO value the payer must prove ownership of. Sets the economic
    /// cost floor for a single LNURL-pay callback.
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

fn default_min_proof_value_sat() -> u64 { DEFAULT_MIN_PROOF_VALUE_SAT }
fn default_message_tag() -> String { DEFAULT_MESSAGE_TAG.to_string() }

// --- Rate limit config ---

#[derive(Debug, Clone, Deserialize)]
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

    #[serde(default = "default_max_pending_per_nym")]
    pub max_pending_reservations_per_nym: u32,
    #[serde(default = "default_recycle_days")]
    pub recycle_pending_older_than_days: u32,

    #[serde(default = "default_lightning_rate")]
    pub lightning_rate_per_minute: u32,

    #[serde(default = "default_global_electrum_rate")]
    pub global_electrum_rate_per_sec: u32,
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
            max_pending_reservations_per_nym: default_max_pending_per_nym(),
            recycle_pending_older_than_days: default_recycle_days(),
            lightning_rate_per_minute: default_lightning_rate(),
            global_electrum_rate_per_sec: default_global_electrum_rate(),
        }
    }
}

fn default_per_ip_limit() -> u32 { 60 }
fn default_per_ip_window_secs() -> u32 { 60 }
fn default_per_pubkey_limit() -> u32 { 10 }
fn default_per_pubkey_window_secs() -> u32 { 3600 }
fn default_max_pending_per_nym() -> u32 { 500 }
fn default_recycle_days() -> u32 { 30 }
fn default_lightning_rate() -> u32 { 10 }
fn default_global_electrum_rate() -> u32 { 50 }

// --- Electrum / tx cache config ---

#[derive(Debug, Clone, Deserialize)]
pub struct ElectrumConfig {
    /// Liquid Electrum server URL (e.g. "blockstream.info:995" over SSL).
    #[serde(default = "default_liquid_electrum_url")]
    pub liquid_url: String,
    #[serde(default = "default_electrum_cache_ttl")]
    pub cache_ttl_secs: u64,
    #[serde(default = "default_electrum_cache_max")]
    pub cache_max_entries: usize,
}

impl Default for ElectrumConfig {
    fn default() -> Self {
        Self {
            liquid_url: default_liquid_electrum_url(),
            cache_ttl_secs: default_electrum_cache_ttl(),
            cache_max_entries: default_electrum_cache_max(),
        }
    }
}

fn default_liquid_electrum_url() -> String { "blockstream.info:995".to_string() }
fn default_electrum_cache_ttl() -> u64 { 3600 }
fn default_electrum_cache_max() -> usize { 10_000 }

fn default_pool_size() -> u32 { DEFAULT_POOL_SIZE }
fn default_min_sendable() -> u64 { DEFAULT_MIN_SENDABLE_MSAT }
fn default_max_sendable() -> u64 { DEFAULT_MAX_SENDABLE_MSAT }
fn default_max_descriptor_len() -> usize { DEFAULT_MAX_DESCRIPTOR_LEN }

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;

        config.database_url = std::env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL environment variable is required")?;
        config.swap_mnemonic = std::env::var("SWAP_MNEMONIC")
            .map_err(|_| "SWAP_MNEMONIC environment variable is required")?;

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.limits.min_sendable_msat > self.limits.max_sendable_msat {
            return Err("min_sendable_msat must be <= max_sendable_msat".into());
        }
        if self.limits.min_sendable_msat == 0 {
            return Err("min_sendable_msat must be > 0".into());
        }
        if self.proof.message_tag.is_empty() {
            return Err("proof.message_tag must be non-empty".into());
        }
        Ok(())
    }
}

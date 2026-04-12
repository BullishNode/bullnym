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
    pub dns: DnsConfig,
    // Loaded from environment, not TOML
    #[serde(skip)]
    pub database_url: String,
    #[serde(skip)]
    pub swap_mnemonic: String,
    #[serde(skip)]
    pub easydns_api_key: Option<String>,
    #[serde(skip)]
    pub easydns_api_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BoltzConfig {
    pub api_url: String,
    pub electrum_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_min_sendable")]
    pub min_sendable_msat: u64,
    #[serde(default = "default_max_sendable")]
    pub max_sendable_msat: u64,
    #[serde(default = "default_max_descriptor_len")]
    pub max_descriptor_len: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_easydns_url")]
    pub easydns_api_url: String,
    #[serde(default)]
    pub zone_domain: String,
}

const DEFAULT_POOL_SIZE: u32 = 10;
const DEFAULT_MIN_SENDABLE_MSAT: u64 = 100_000; // 100 sats
const DEFAULT_MAX_SENDABLE_MSAT: u64 = 25_000_000_000; // 25M sats
const DEFAULT_MAX_DESCRIPTOR_LEN: usize = 1000;
const DEFAULT_EASYDNS_URL: &str = "https://rest.easydns.net";

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            min_sendable_msat: DEFAULT_MIN_SENDABLE_MSAT,
            max_sendable_msat: DEFAULT_MAX_SENDABLE_MSAT,
            max_descriptor_len: DEFAULT_MAX_DESCRIPTOR_LEN,
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            easydns_api_url: DEFAULT_EASYDNS_URL.to_string(),
            zone_domain: String::new(),
        }
    }
}

fn default_pool_size() -> u32 { DEFAULT_POOL_SIZE }
fn default_min_sendable() -> u64 { DEFAULT_MIN_SENDABLE_MSAT }
fn default_max_sendable() -> u64 { DEFAULT_MAX_SENDABLE_MSAT }
fn default_max_descriptor_len() -> usize { DEFAULT_MAX_DESCRIPTOR_LEN }
fn default_easydns_url() -> String { DEFAULT_EASYDNS_URL.to_string() }

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;

        // Load secrets from environment
        config.database_url = std::env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL environment variable is required")?;
        config.swap_mnemonic = std::env::var("SWAP_MNEMONIC")
            .map_err(|_| "SWAP_MNEMONIC environment variable is required")?;
        config.easydns_api_key = std::env::var("EASYDNS_API_KEY").ok();
        config.easydns_api_token = std::env::var("EASYDNS_API_TOKEN").ok();

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
        if self.dns.zone_domain.is_empty() && self.easydns_api_key.is_some() {
            return Err("dns.zone_domain is required when EASYDNS_API_KEY is set".into());
        }
        Ok(())
    }

    pub fn dns_enabled(&self) -> bool {
        self.easydns_api_key.is_some()
            && self.easydns_api_token.is_some()
            && !self.dns.zone_domain.is_empty()
    }
}

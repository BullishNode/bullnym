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

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            min_sendable_msat: default_min_sendable(),
            max_sendable_msat: default_max_sendable(),
            max_descriptor_len: default_max_descriptor_len(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            easydns_api_url: default_easydns_url(),
            zone_domain: String::new(),
        }
    }
}

fn default_pool_size() -> u32 { 10 }
fn default_min_sendable() -> u64 { 10_000_000 }
fn default_max_sendable() -> u64 { 25_000_000_000 }
fn default_max_descriptor_len() -> usize { 1000 }
fn default_easydns_url() -> String { "https://rest.easydns.net".to_string() }

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

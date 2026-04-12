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
        Ok(())
    }
}

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
}

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

fn default_liquid_electrum_url() -> String { "ssl://blockstream.info:995".to_string() }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn electrum_urls_legacy_single_field_only() {
        let cfg = ElectrumConfig {
            liquid_url: Some("a.example:50001".to_string()),
            liquid_urls: vec![],
            cache_ttl_secs: 0,
            cache_max_entries: 0,
        };
        assert_eq!(cfg.urls(), vec!["ssl://a.example:50001".to_string()]);
    }

    #[test]
    fn electrum_urls_list_field_only() {
        let cfg = ElectrumConfig {
            liquid_url: None,
            liquid_urls: vec!["a:1".to_string(), "b:2".to_string()],
            cache_ttl_secs: 0,
            cache_max_entries: 0,
        };
        assert_eq!(
            cfg.urls(),
            vec!["ssl://a:1".to_string(), "ssl://b:2".to_string()]
        );
    }

    #[test]
    fn electrum_urls_both_fields_dedup_legacy_first() {
        let cfg = ElectrumConfig {
            liquid_url: Some("primary:1".to_string()),
            liquid_urls: vec!["primary:1".to_string(), "secondary:2".to_string()],
            cache_ttl_secs: 0,
            cache_max_entries: 0,
        };
        assert_eq!(
            cfg.urls(),
            vec!["ssl://primary:1".to_string(), "ssl://secondary:2".to_string()]
        );
    }

    #[test]
    fn electrum_urls_falls_back_to_default() {
        let cfg = ElectrumConfig {
            liquid_url: None,
            liquid_urls: vec![],
            cache_ttl_secs: 0,
            cache_max_entries: 0,
        };
        assert_eq!(cfg.urls(), vec![default_liquid_electrum_url()]);
        assert!(cfg.urls()[0].starts_with("ssl://"));
    }

    #[test]
    fn electrum_urls_skips_empty_strings() {
        let cfg = ElectrumConfig {
            liquid_url: Some(String::new()),
            liquid_urls: vec![String::new(), "a:1".to_string()],
            cache_ttl_secs: 0,
            cache_max_entries: 0,
        };
        assert_eq!(cfg.urls(), vec!["ssl://a:1".to_string()]);
    }

    #[test]
    fn electrum_urls_preserves_explicit_scheme() {
        let cfg = ElectrumConfig {
            liquid_url: None,
            liquid_urls: vec![
                "tcp://localhost:50001".to_string(),
                "ssl://example:995".to_string(),
            ],
            cache_ttl_secs: 0,
            cache_max_entries: 0,
        };
        assert_eq!(
            cfg.urls(),
            vec![
                "tcp://localhost:50001".to_string(),
                "ssl://example:995".to_string(),
            ]
        );
    }
}

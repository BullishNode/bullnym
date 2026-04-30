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
    /// HMAC-SHA256 shared secret for Boltz webhook authentication.
    /// Sourced from `BOLTZ_WEBHOOK_SECRET` env var. When empty, webhook
    /// HMAC verification is disabled — for legacy compat, but production
    /// MUST set this.
    #[serde(skip)]
    pub boltz_webhook_secret: String,
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

    // --- Registration gates (P1) ---
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

    // --- Metadata + lookup gates (P2) ---
    /// Per-IP rate-limit on `GET /.well-known/lnurlp/:nym` and
    /// `GET /.well-known/nostr.json`. 0 disables.
    #[serde(default = "default_metadata_rate_limit")]
    pub metadata_rate_limit: u32,
    #[serde(default = "default_metadata_rate_window_secs")]
    pub metadata_rate_window_secs: u32,

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

    // --- Chain watcher (P4) ---
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

    /// Per-source rate-limit on `/webhook/boltz` (D2). Bounds webhook-bomb
    /// blast radius even if the HMAC secret leaks. Real Boltz traffic
    /// hits one swap_id at a time with ~5 events end-to-end, well under
    /// 10/min.
    #[serde(default = "default_webhook_rate_limit")]
    pub webhook_rate_limit: u32,
    #[serde(default = "default_webhook_rate_window_secs")]
    pub webhook_rate_window_secs: u32,

    /// Per-source rate-limit on Lightning ops, covering BOTH explicit
    /// `network=lightning` callbacks AND Liquid→Lightning soft fallbacks
    /// (PR C). 0 disables the check.
    ///
    /// Per-source (not per-nym) is correct shape under the v2 principle:
    /// many payers paying one merchant via Lightning is normal; one
    /// source making many Lightning ops across many merchants is not.
    /// The cap also bounds Boltz API spend under a fallback storm.
    #[serde(default = "default_lightning_per_source_limit")]
    pub lightning_per_source_limit: u32,
    #[serde(default = "default_lightning_per_source_window_secs")]
    pub lightning_per_source_window_secs: u32,
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
            metadata_rate_limit: default_metadata_rate_limit(),
            metadata_rate_window_secs: default_metadata_rate_window_secs(),
            metadata_distinct_nyms_per_ip_limit:
                default_metadata_distinct_nyms_per_ip(),
            metadata_distinct_nyms_per_ip_window_secs:
                default_metadata_distinct_nyms_per_ip_window_secs(),
            lookup_distinct_npubs_per_ip_limit:
                default_lookup_distinct_npubs_per_ip(),
            lookup_distinct_npubs_per_ip_window_secs:
                default_lookup_distinct_npubs_per_ip_window_secs(),
            chain_watcher_electrum_rate_per_sec:
                default_chain_watcher_electrum_rate(),
            chain_watcher_active_user_tick_secs:
                default_chain_watcher_active_user_tick_secs(),
            chain_watcher_idle_user_tick_secs:
                default_chain_watcher_idle_user_tick_secs(),
            chain_watcher_active_window_secs:
                default_chain_watcher_active_window_secs(),
            webhook_rate_limit: default_webhook_rate_limit(),
            webhook_rate_window_secs: default_webhook_rate_window_secs(),
            lightning_per_source_limit: default_lightning_per_source_limit(),
            lightning_per_source_window_secs:
                default_lightning_per_source_window_secs(),
        }
    }
}

fn default_per_ip_limit() -> u32 { 60 }
fn default_per_ip_window_secs() -> u32 { 60 }
/// Disabled by default (0). The per-pubkey sliding-window check is redundant
/// with the per-outpoint distinct-nym check; field is kept for backwards
/// compatibility with deployed configs that explicitly set a non-zero value.
fn default_per_pubkey_limit() -> u32 { 0 }
fn default_per_pubkey_window_secs() -> u32 { 3600 }
// --- v2 thresholds (asymmetric-defense principle) ---
// Real payers touch 0-2 distinct nyms per day. Real merchants get paid by
// many distinct payers per day. So per-source distinct-target caps are
// kept tight; per-target rate caps are removed.
//
// PR D adjustment: IPv4 cap raised 3→5 to accommodate CGNAT / office /
// family-share IPs. IPv6 /56 cap stays at 3 (one real customer block).
fn default_distinct_nyms_per_ip() -> u32 { 5 }
fn default_distinct_nyms_per_ipv6_56() -> u32 { 3 }
fn default_distinct_nyms_per_outpoint() -> u32 { 3 }
fn default_distinct_nyms_window_secs() -> u32 { 3600 }
/// Memory bound only — the real defense against per-nym pollution is the
/// per-source distinct-outpoints cap + the GC recycler on
/// `outpoint_addresses` rows. This number should never fire under normal
/// operation. (was 500; punished popular merchants.)
fn default_max_pending_per_nym() -> u32 { 50_000 }
fn default_recycle_days() -> u32 { 30 }
/// Disabled by default: per-nym Lightning rate is wrong-shape. A popular
/// merchant being paid via Lightning Address can legitimately exceed any
/// per-nym rate — bursts during business hours are normal. Keep the field
/// for backwards compat with deployed configs that explicitly set it.
fn default_lightning_rate() -> u32 { 0 }
fn default_global_electrum_rate() -> u32 { 50 }
fn default_register_rate_limit() -> u32 { 5 }
fn default_register_rate_window_secs() -> u32 { 60 }
// PR D: 2→3 to accommodate phone-reset (new install regenerates Nostr
// identity → 2nd npub from same IP) and family device-sharing.
fn default_register_distinct_npubs_per_ip() -> u32 { 3 }
fn default_register_distinct_npubs_per_ip_window_secs() -> u32 { 3600 }
// PR D: 100_000 was ceremonial — at our user-base this would never fire
// under attack OR organic growth. 10_000 is a meaningful "we're growing,
// time to revisit capacity" trigger.
fn default_max_active_users() -> u32 { 10_000 }
fn default_metadata_rate_limit() -> u32 { 30 }
fn default_metadata_rate_window_secs() -> u32 { 60 }
// PR D: 5→10. LUD-06 requires a metadata fetch per payment, so a small
// office paying multiple Lightning Addresses easily exceeds 5/h.
// Enumeration attack still blocked: 10/h × 70 Mullvad cities = 700/h
// total, vs the 70K-candidate dictionary the attack needs.
fn default_metadata_distinct_nyms_per_ip() -> u32 { 10 }
fn default_metadata_distinct_nyms_per_ip_window_secs() -> u32 { 3600 }
fn default_lookup_distinct_npubs_per_ip() -> u32 { 5 }
fn default_lookup_distinct_npubs_per_ip_window_secs() -> u32 { 3600 }
fn default_chain_watcher_electrum_rate() -> u32 { 50 }
fn default_chain_watcher_active_user_tick_secs() -> u32 { 30 }
fn default_chain_watcher_idle_user_tick_secs() -> u32 { 600 }
/// 24h: a user who hasn't made a callback in a day is "idle" — payment
/// flows on Lightning addresses are bursty (one callback per pay event)
/// so 24h handles real-world traffic patterns comfortably.
fn default_chain_watcher_active_window_secs() -> u32 { 86_400 }
fn default_webhook_rate_limit() -> u32 { 10 }
fn default_webhook_rate_window_secs() -> u32 { 60 }
/// 30 Lightning ops per source per hour. Lightning is the default rail
/// and doesn't leak Liquid addresses, so the cap is loose — only there
/// to bound Boltz API spend per source. (Replaces the wrong-shape
/// per-nym `lightning_rate_per_minute`, which is now a no-op kept for
/// backwards-compat with deployed configs.)
fn default_lightning_per_source_limit() -> u32 { 30 }
fn default_lightning_per_source_window_secs() -> u32 { 3600 }

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
        // Optional in dev / required in prod. When empty, the webhook
        // handler logs a warning on every request and falls back to
        // unauthenticated mode (legacy behaviour).
        config.boltz_webhook_secret =
            std::env::var("BOLTZ_WEBHOOK_SECRET").unwrap_or_default();

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

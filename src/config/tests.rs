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
        vec![
            "ssl://primary:1".to_string(),
            "ssl://secondary:2".to_string()
        ]
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

#[test]
fn rate_limit_invoice_status_uses_current_key() {
    let cfg: RateLimitConfig = toml::from_str("invoice_status_per_source_per_min = 42").unwrap();

    assert_eq!(cfg.invoice_status_per_source_per_min, 42);
}

#[test]
fn rate_limit_invoice_status_accepts_legacy_key() {
    let cfg: RateLimitConfig = toml::from_str("donation_status_per_source_per_min = 43").unwrap();

    assert_eq!(cfg.invoice_status_per_source_per_min, 43);
}

fn production_base_config() -> Config {
    Config {
        domain: "pay.example.com".to_string(),
        listen: "127.0.0.1:8080".to_string(),
        pool_size: 10,
        boltz: BoltzConfig {
            api_url: "https://api.boltz.exchange/v2".to_string(),
            electrum_url: "ssl://liquid-electrum.example.com:50002".to_string(),
        },
        pricer: PricerConfig::default(),
        pwa: PwaConfig::default(),
        donation: DonationConfig::default(),
        limits: LimitsConfig::default(),
        proof: ProofConfig::default(),
        features: FeaturesConfig::default(),
        rate_limit: RateLimitConfig::default(),
        certification: CertificationConfig::default(),
        electrum: ElectrumConfig::default(),
        claim: ClaimConfig::default(),
        reconciler: ReconcilerConfig::default(),
        bitcoin_watcher: BitcoinWatcherConfig::default(),
        workers: WorkersConfig::default(),
        invoice_accounting: InvoiceAccountingConfig::default(),
        database_url: "postgres://payservice@example/payservice".to_string(),
        swap_mnemonic: "abandon abandon abandon".to_string(),
        boltz_webhook_url_secret: "webhook-secret".to_string(),
        boltz_webhook_url_secret_previous: String::new(),
    }
}

#[test]
fn production_requires_webhook_secret() {
    let mut cfg = production_base_config();
    cfg.boltz_webhook_url_secret.clear();

    let err = cfg.validate_for_runtime("production", false).unwrap_err();

    assert!(err.to_string().contains("BOLTZ_WEBHOOK_URL_SECRET"));
}

#[test]
fn production_rejects_public_listen_by_default() {
    let mut cfg = production_base_config();
    cfg.listen = "0.0.0.0:8080".to_string();

    let err = cfg.validate_for_runtime("production", false).unwrap_err();

    assert!(err.to_string().contains("listen must bind loopback"));
}

#[test]
fn production_public_listen_requires_explicit_override() {
    let mut cfg = production_base_config();
    cfg.listen = "0.0.0.0:8080".to_string();

    cfg.validate_for_runtime("production", true).unwrap();
}

#[test]
fn production_allows_loopback_listen_by_default() {
    let cfg = production_base_config();

    cfg.validate_for_runtime("production", false).unwrap();
}

#[test]
fn listen_guard_treats_unspecified_ipv6_as_non_loopback() {
    assert!(listen_addr_is_non_loopback("[::]:8080").unwrap());
}

#[test]
fn env_flag_enabled_accepts_common_truthy_values() {
    assert!(env_flag_enabled("1"));
    assert!(env_flag_enabled(" true "));
    assert!(env_flag_enabled("YES"));
    assert!(env_flag_enabled("on"));
    assert!(!env_flag_enabled("false"));
}

#[test]
fn production_rejects_localhost_domain() {
    let mut cfg = production_base_config();
    cfg.domain = "localhost:8080".to_string();

    let err = cfg.validate_for_runtime("production", false).unwrap_err();

    assert!(err.to_string().contains("domain must not be localhost"));
}

#[test]
fn non_production_allows_dev_webhook_and_public_listen() {
    let mut cfg = production_base_config();
    cfg.domain = "localhost:8080".to_string();
    cfg.listen = "0.0.0.0:8080".to_string();
    cfg.boltz_webhook_url_secret.clear();

    cfg.validate_for_runtime("development", false).unwrap();
}

#[test]
fn feature_flags_default_enabled() {
    let cfg = FeaturesConfig::default();

    assert!(cfg.lightning_address);
    assert!(cfg.invoices);
    assert!(cfg.payment_pages);
    assert!(!cfg.nip05);
}

#[test]
fn feature_flags_parse_independently() {
    let cfg: FeaturesConfig = toml::from_str(
        r#"
        lightning_address = true
        invoices = false
        payment_pages = true
        nip05 = true
        "#,
    )
    .unwrap();

    assert!(cfg.lightning_address);
    assert!(!cfg.invoices);
    assert!(cfg.payment_pages);
    assert!(cfg.nip05);
}

#[test]
fn workers_default_enabled() {
    let cfg = WorkersConfig::default();

    assert!(cfg.enabled);
}

#[test]
fn electrum_urls_with_builtin_failover_appends_and_dedups() {
    let cfg = ElectrumConfig {
        liquid_url: Some("ssl://les.bullbitcoin.com:995".to_string()),
        liquid_urls: vec![],
        cache_ttl_secs: 0,
        cache_max_entries: 0,
    };
    assert_eq!(
        cfg.urls_with_builtin_failover(),
        vec![
            "ssl://les.bullbitcoin.com:995".to_string(),
            "ssl://blockstream.info:995".to_string(),
        ]
    );
    let cfg2 = ElectrumConfig {
        liquid_url: Some("ssl://my-node:50002".to_string()),
        liquid_urls: vec![],
        cache_ttl_secs: 0,
        cache_max_entries: 0,
    };
    assert_eq!(
        cfg2.urls_with_builtin_failover(),
        vec![
            "ssl://my-node:50002".to_string(),
            "ssl://les.bullbitcoin.com:995".to_string(),
            "ssl://blockstream.info:995".to_string(),
        ]
    );
    assert_eq!(cfg2.urls(), vec!["ssl://my-node:50002".to_string()]);
}

#[test]
fn btc_effective_endpoints_primary_first_deduped() {
    let cfg = BitcoinWatcherConfig::default();
    assert_eq!(
        cfg.effective_endpoints(),
        vec![
            "https://mempool.bullbitcoin.com/api".to_string(),
            "https://mempool.space/api".to_string(),
        ]
    );
    let cfg2 = BitcoinWatcherConfig {
        endpoint: "http://172.16.0.8/api/".to_string(),
        ..BitcoinWatcherConfig::default()
    };
    assert_eq!(
        cfg2.effective_endpoints(),
        vec![
            "http://172.16.0.8/api".to_string(),
            "https://mempool.bullbitcoin.com/api".to_string(),
            "https://mempool.space/api".to_string(),
        ]
    );
}

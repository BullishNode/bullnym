use super::*;

#[test]
fn electrum_urls_list_field_only() {
    let cfg = ElectrumConfig {
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
fn electrum_rejects_legacy_single_url_key() {
    assert!(toml::from_str::<ElectrumConfig>("liquid_url = \"legacy.example:50001\"").is_err());
}

#[test]
fn electrum_urls_falls_back_to_default() {
    let cfg = ElectrumConfig {
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
        liquid_urls: vec![String::new(), "a:1".to_string()],
        cache_ttl_secs: 0,
        cache_max_entries: 0,
    };
    assert_eq!(cfg.urls(), vec!["ssl://a:1".to_string()]);
}

#[test]
fn electrum_urls_preserves_explicit_scheme() {
    let cfg = ElectrumConfig {
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
fn explicit_electrum_validation_does_not_let_failovers_hide_invalid_config() {
    let mut cfg = ElectrumConfig::default();
    assert!(cfg.explicit_urls_valid());

    cfg.liquid_urls = vec!["not-an-electrum-endpoint".to_string()];
    assert!(!cfg.explicit_urls_valid());
    assert!(!cfg.urls_with_builtin_failover().is_empty());

    cfg.liquid_urls = vec!["http://example.com:50002".to_string()];
    assert!(!cfg.explicit_urls_valid());

    cfg.liquid_urls = vec!["ssl://::1:50002".to_string()];
    assert!(!cfg.explicit_urls_valid());

    for invalid in [
        "ssl://[not-ipv6]:50002",
        "ssl://[::gg]:50002",
        "ssl://foo]:50002",
        "ssl://[::1:50002",
        "ssl://host:0",
        "ssl://user@host:50002",
        "ssl://host:50002/path",
        "ssl://host:50002?query=1",
    ] {
        cfg.liquid_urls = vec![invalid.to_string()];
        assert!(!cfg.explicit_urls_valid(), "accepted {invalid}");
    }

    cfg.liquid_urls = vec![
        "tcp://127.0.0.1:50001".to_string(),
        "ssl://[::1]:50002".to_string(),
    ];
    assert!(cfg.explicit_urls_valid());
}

#[test]
fn explicit_bitcoin_validation_does_not_let_builtins_hide_invalid_config() {
    let mut cfg = BitcoinWatcherConfig::default();
    assert!(cfg.explicit_endpoints_valid());

    cfg.endpoint = "not-an-http-endpoint".to_string();
    assert!(!cfg.explicit_endpoints_valid());
    assert!(!cfg.effective_endpoints().is_empty());

    cfg.endpoint = "https://mempool.bullbitcoin.com/api".to_string();
    for invalid in [
        "ftp://invalid.example/api",
        "https://example.com:0/api",
        "https://user@example.com/api",
        "https://example.com/api?query=1",
        "https://example.com/api#fragment",
    ] {
        cfg.endpoints = vec![invalid.to_string()];
        assert!(!cfg.explicit_endpoints_valid(), "accepted {invalid}");
    }
}

#[test]
fn rate_limit_invoice_status_uses_current_key() {
    let cfg: RateLimitConfig = toml::from_str("invoice_status_per_source_per_min = 42").unwrap();

    assert_eq!(cfg.invoice_status_per_source_per_min, 42);
}

#[test]
fn rate_limit_invoice_status_rejects_legacy_key() {
    assert!(toml::from_str::<RateLimitConfig>("donation_status_per_source_per_min = 43").is_err());
}

#[test]
fn api_rate_limit_accepts_only_current_keys() {
    let current: RateLimitConfig =
        toml::from_str("api_rate_limit = 41\napi_rate_window_secs = 71").unwrap();
    assert_eq!(current.api_rate_limit, 41);
    assert_eq!(current.api_rate_window_secs, 71);

    assert!(toml::from_str::<RateLimitConfig>(
        "metadata_rate_limit = 42\nmetadata_rate_window_secs = 72"
    )
    .is_err());
}

#[test]
fn public_rate_limit_has_a_separate_reasonable_default() {
    let defaults = RateLimitConfig::default();
    assert_eq!(defaults.public_rate_per_source_per_min, 120);

    let configured: RateLimitConfig =
        toml::from_str("public_rate_per_source_per_min = 75").unwrap();
    assert_eq!(configured.public_rate_per_source_per_min, 75);
    assert_eq!(configured.api_rate_limit, default_api_rate_limit());
}

#[test]
fn pricer_cache_must_be_positive_and_within_freshness_bound() {
    for (cache_ttl_secs, max_freshness_secs, expected) in [
        (0, 300, "pricer.cache_ttl_secs must be > 0"),
        (60, 0, "pricer.max_freshness_secs must be > 0"),
        (60, 301, "pricer.max_freshness_secs must be <= 300"),
        (
            301,
            300,
            "pricer.cache_ttl_secs must be <= pricer.max_freshness_secs",
        ),
    ] {
        let mut config = production_base_config();
        config.pricer.cache_ttl_secs = cache_ttl_secs;
        config.pricer.max_freshness_secs = max_freshness_secs;
        let error = config
            .validate_for_runtime("development", false)
            .unwrap_err();
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn pricer_request_timeout_must_be_positive() {
    let mut config = production_base_config();
    config.pricer.request_timeout_ms = 0;

    let error = config
        .validate_for_runtime("development", false)
        .unwrap_err();

    assert_eq!(error.to_string(), "pricer.request_timeout_ms must be > 0");
}

#[test]
fn donation_image_default_dimension_bounds_decode_memory() {
    let cfg = DonationConfig::default();

    assert_eq!(cfg.image_max_dimension, 5_000);
    assert_eq!(cfg.image_max_pixels, 12_000_000);
}

#[test]
fn donation_output_dimensions_must_be_positive() {
    for (avatar_size, og_width, og_height, expected) in [
        (
            0,
            DEFAULT_DONATION_OG_WIDTH,
            DEFAULT_DONATION_OG_HEIGHT,
            "donation.avatar_size must be > 0",
        ),
        (
            DEFAULT_DONATION_AVATAR_SIZE,
            0,
            DEFAULT_DONATION_OG_HEIGHT,
            "donation.og_width must be > 0",
        ),
        (
            DEFAULT_DONATION_AVATAR_SIZE,
            DEFAULT_DONATION_OG_WIDTH,
            0,
            "donation.og_height must be > 0",
        ),
    ] {
        let mut config = production_base_config();
        config.donation.avatar_size = avatar_size;
        config.donation.og_width = og_width;
        config.donation.og_height = og_height;

        let error = config
            .validate_for_runtime("development", false)
            .unwrap_err();

        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn donation_output_dimensions_must_fit_configured_memory_bounds() {
    let mut config = production_base_config();
    config.donation.avatar_size = config.donation.image_max_dimension + 1;
    assert_eq!(
        config
            .validate_for_runtime("development", false)
            .unwrap_err()
            .to_string(),
        "donation.avatar_size must be <= donation.image_max_dimension"
    );

    let mut config = production_base_config();
    config.donation.og_width = config.donation.image_max_dimension + 1;
    assert_eq!(
        config
            .validate_for_runtime("development", false)
            .unwrap_err()
            .to_string(),
        "donation.og_width must be <= donation.image_max_dimension"
    );

    let mut config = production_base_config();
    config.donation.avatar_size = 4_000;
    assert_eq!(
        config
            .validate_for_runtime("development", false)
            .unwrap_err()
            .to_string(),
        "donation.avatar_size squared must be <= donation.image_max_pixels"
    );

    let mut config = production_base_config();
    config.donation.og_width = 4_000;
    config.donation.og_height = 4_000;
    assert_eq!(
        config
            .validate_for_runtime("development", false)
            .unwrap_err()
            .to_string(),
        "donation.og_width * donation.og_height must be <= donation.image_max_pixels"
    );
}

fn production_base_config() -> Config {
    Config {
        domain: "pay.example.com".to_string(),
        listen: "127.0.0.1:8080".to_string(),
        pool_size: 10,
        boltz: BoltzConfig {
            api_url: "https://api.boltz.exchange/v2".to_string(),
            electrum_url: "ssl://liquid-electrum.example.com:50002".to_string(),
            key_epoch: 1,
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
        liquid_watcher: LiquidWatcherConfig::default(),
        fee_policy: FeePolicyConfig::default(),
        workers: WorkersConfig::default(),
        invoice_accounting: InvoiceAccountingConfig::default(),
        database_url: "postgres://payservice@example/payservice".to_string(),
        swap_mnemonic: "abandon abandon abandon".to_string(),
        boltz_webhook_url_secret: "webhook-secret".to_string(),
        boltz_webhook_url_secret_previous: String::new(),
    }
}

#[test]
fn config_rejects_unknown_root_and_nested_fields() {
    let unknown_root = r#"
domain = "pay.example.com"
listen = "127.0.0.1:8080"
pool_sze = 10

[boltz]
api_url = "https://api.boltz.exchange/v2"
electrum_url = "ssl://liquid-electrum.example.com:50002"
"#;
    assert!(toml::from_str::<Config>(unknown_root).is_err());

    let unknown_nested = r#"
domain = "pay.example.com"
listen = "127.0.0.1:8080"

[boltz]
api_url = "https://api.boltz.exchange/v2"
electrum_url = "ssl://liquid-electrum.example.com:50002"

[workers]
enable = true
"#;
    assert!(toml::from_str::<Config>(unknown_nested).is_err());
}

#[test]
fn permanent_nym_cap_is_not_operator_configurable() {
    for configured_cap in [1, 3] {
        let input = format!("max_lifetime_nyms_per_npub = {configured_cap}");
        let error = toml::from_str::<LimitsConfig>(&input)
            .expect_err("the permanent-name invariant must not be configurable")
            .to_string();

        assert!(
            error.contains("unknown field `max_lifetime_nyms_per_npub`"),
            "unexpected parse error for cap {configured_cap}: {error}"
        );
    }
}

#[test]
fn checked_in_config_uses_only_current_keys() {
    let parsed: Config = toml::from_str(include_str!("../../config.toml")).unwrap();

    assert_eq!(parsed.rate_limit.api_rate_limit, 30);
    assert_eq!(parsed.rate_limit.api_rate_window_secs, 60);
    parsed.validate_for_runtime("development", false).unwrap();
}

#[test]
fn common_validation_rejects_hot_loops_and_unsafe_values() {
    let mut config = production_base_config();
    config.reconciler.interval_secs = 0;
    assert!(config
        .validate_for_runtime("development", false)
        .unwrap_err()
        .to_string()
        .contains("reconciler.interval_secs"));

    let mut config = production_base_config();
    config.invoice_accounting.liquid_shortfall_tolerance_sat = -1;
    assert!(config
        .validate_for_runtime("development", false)
        .unwrap_err()
        .to_string()
        .contains("shortfall tolerances"));

    let mut config = production_base_config();
    config.rate_limit.global_electrum_rate_per_sec = 0;
    assert!(config
        .validate_for_runtime("development", false)
        .unwrap_err()
        .to_string()
        .contains("global_electrum_rate_per_sec"));

    let mut config = production_base_config();
    config.rate_limit.api_rate_limit = 1;
    config.rate_limit.api_rate_window_secs = 0;
    assert!(config
        .validate_for_runtime("development", false)
        .unwrap_err()
        .to_string()
        .contains("api_rate_window_secs"));
}

#[test]
fn common_validation_rejects_malformed_shared_endpoints_and_secrets() {
    let mut config = production_base_config();
    config.boltz.api_url = "https://user@example.com/v2".to_string();
    assert!(config
        .validate_for_runtime("development", false)
        .unwrap_err()
        .to_string()
        .contains("boltz.api_url"));

    let mut config = production_base_config();
    config.boltz_webhook_url_secret = "not/a/path-segment".to_string();
    assert!(config
        .validate_for_runtime("development", false)
        .unwrap_err()
        .to_string()
        .contains("BOLTZ_WEBHOOK_URL_SECRET"));
}

fn fee_source(id: &str, endpoint: &str) -> FeeSourceConfig {
    FeeSourceConfig {
        id: id.to_string(),
        endpoint: endpoint.to_string(),
    }
}

#[test]
fn fee_policy_defaults_are_complete_bounded_and_quote_free() {
    let parsed: FeePolicyConfig = toml::from_str("").unwrap();
    let defaults = FeePolicyConfig::default();

    assert_eq!(parsed, defaults);
    assert!(defaults.validation_facts().all_valid());
    assert_eq!(defaults.bitcoin.sources.len(), 2);
    assert_eq!(defaults.liquid.sources.len(), 1);
    assert!(defaults.bitcoin.sources.len() <= MAX_FEE_SOURCES_PER_RAIL);
    assert!(defaults.liquid.sources.len() <= MAX_FEE_SOURCES_PER_RAIL);
    assert_eq!(defaults.bitcoin.refresh_interval_secs, 30);
    assert_eq!(defaults.bitcoin.live_max_age_secs, 120);
    assert_eq!(defaults.bitcoin.last_known_good_max_age_secs, 900);
    assert_eq!(defaults.bitcoin.floor_sat_per_vbyte, 1.0);
    assert_eq!(defaults.bitcoin.cap_sat_per_vbyte, 500.0);
    assert_eq!(defaults.liquid.refresh_interval_secs, 30);
    assert_eq!(defaults.liquid.live_max_age_secs, 120);
    assert_eq!(defaults.liquid.last_known_good_max_age_secs, 900);
    assert_eq!(defaults.liquid.floor_sat_per_vbyte, 0.1);
    assert_eq!(defaults.liquid.cap_sat_per_vbyte, 10.0);

    for forbidden_quote_key in [
        "default_sat_per_vbyte",
        "fee_rate_sat_per_vbyte",
        "fallback_sat_per_vbyte",
        "configured_quote_sat_per_vbyte",
    ] {
        let input = format!("[bitcoin]\n{forbidden_quote_key} = 2.0\n");
        assert!(
            toml::from_str::<FeePolicyConfig>(&input).is_err(),
            "accepted forbidden quote authority {forbidden_quote_key}"
        );
    }
}

#[test]
fn fee_policy_toml_preserves_explicit_order_windows_and_bounds() {
    let config: FeePolicyConfig = toml::from_str(
        r#"
        [bitcoin]
        refresh_interval_secs = 15
        live_max_age_secs = 45
        last_known_good_max_age_secs = 600
        floor_sat_per_vbyte = 1.25
        cap_sat_per_vbyte = 250.5

        [[bitcoin.sources]]
        id = "bitcoin-primary"
        endpoint = "https://btc-primary.example/api"

        [[bitcoin.sources]]
        id = "bitcoin-secondary"
        endpoint = "https://btc-secondary.example/mempool"

        [liquid]
        refresh_interval_secs = 20
        live_max_age_secs = 70
        last_known_good_max_age_secs = 700
        floor_sat_per_vbyte = 0.15
        cap_sat_per_vbyte = 5.75

        [[liquid.sources]]
        id = "liquid-primary"
        endpoint = "https://liquid-primary.example/api"

        [[liquid.sources]]
        id = "liquid-secondary"
        endpoint = "https://liquid-secondary.example/esplora"
        "#,
    )
    .unwrap();

    assert!(config.validation_facts().all_valid());
    assert_eq!(config.bitcoin.refresh_interval_secs, 15);
    assert_eq!(config.bitcoin.live_max_age_secs, 45);
    assert_eq!(config.bitcoin.last_known_good_max_age_secs, 600);
    assert_eq!(config.bitcoin.floor_sat_per_vbyte, 1.25);
    assert_eq!(config.bitcoin.cap_sat_per_vbyte, 250.5);
    assert_eq!(config.bitcoin.sources[0].id, "bitcoin-primary");
    assert_eq!(config.bitcoin.sources[1].id, "bitcoin-secondary");
    assert_eq!(config.liquid.refresh_interval_secs, 20);
    assert_eq!(config.liquid.live_max_age_secs, 70);
    assert_eq!(config.liquid.last_known_good_max_age_secs, 700);
    assert_eq!(config.liquid.floor_sat_per_vbyte, 0.15);
    assert_eq!(config.liquid.cap_sat_per_vbyte, 5.75);
    assert_eq!(config.liquid.sources[0].id, "liquid-primary");
    assert_eq!(config.liquid.sources[1].id, "liquid-secondary");
}

#[test]
fn fee_source_lists_are_nonempty_max_four_and_uniquely_named_per_rail() {
    let mut config = FeePolicyConfig::default();
    config.bitcoin.sources.clear();
    let facts = config.validation_facts();
    assert!(!facts.bitcoin.sources_valid);
    assert!(facts.liquid.all_valid());

    config = FeePolicyConfig::default();
    config.liquid.sources = (0..=MAX_FEE_SOURCES_PER_RAIL)
        .map(|index| {
            fee_source(
                &format!("liquid-{index}"),
                &format!("https://liquid-{index}.example/api"),
            )
        })
        .collect();
    let facts = config.validation_facts();
    assert!(facts.bitcoin.all_valid());
    assert!(!facts.liquid.sources_valid);

    for rail in ["bitcoin", "liquid"] {
        let mut config = FeePolicyConfig::default();
        let duplicate = vec![
            fee_source("same-source", "https://one.example/api"),
            fee_source("same-source", "https://two.example/api"),
        ];
        if rail == "bitcoin" {
            config.bitcoin.sources = duplicate;
        } else {
            config.liquid.sources = duplicate;
        }
        let facts = config.validation_facts();
        assert_eq!(facts.bitcoin.sources_valid, rail != "bitcoin");
        assert_eq!(facts.liquid.sources_valid, rail != "liquid");
    }

    let mut config = FeePolicyConfig::default();
    config.bitcoin.sources = (0..MAX_FEE_SOURCES_PER_RAIL)
        .map(|index| {
            fee_source(
                &format!("bitcoin-{index}"),
                &format!("https://bitcoin-{index}.example/api"),
            )
        })
        .collect();
    config.liquid.sources = (0..MAX_FEE_SOURCES_PER_RAIL)
        .map(|index| {
            fee_source(
                &format!("liquid-{index}"),
                &format!("https://liquid-{index}.example/api"),
            )
        })
        .collect();
    assert!(config.validation_facts().all_valid());
}

#[test]
fn fee_source_ids_are_strictly_sanitized_and_bounded() {
    for invalid in [
        "",
        "UPPERCASE",
        "-leading",
        "_leading",
        "has.dot",
        "has/slash",
        "has space",
        "has\nnewline",
    ] {
        assert!(!valid_fee_source_id(invalid), "accepted {invalid:?}");
        let mut config = FeePolicyConfig::default();
        config.bitcoin.sources[0].id = invalid.to_string();
        assert!(!config.validation_facts().bitcoin.sources_valid);
    }

    let maximum = "x".repeat(MAX_FEE_SOURCE_ID_BYTES);
    assert!(valid_fee_source_id(&maximum));
    assert!(!valid_fee_source_id(&format!("{maximum}x")));
    for valid in ["source0", "source-1", "source_2", "source-", "source_"] {
        assert!(valid_fee_source_id(valid), "rejected {valid}");
        let mut config = FeePolicyConfig::default();
        config.bitcoin.sources[0].id = valid.to_string();
        assert!(config.validation_facts().bitcoin.sources_valid);
    }
}

#[test]
fn fee_endpoints_require_credential_free_https_bases() {
    for valid in [
        "https://fees.example",
        "https://fees.example/api",
        "https://fees.example:443/api/",
        "https://[2001:db8::1]/api",
    ] {
        assert!(valid_fee_https_base_endpoint(valid), "rejected {valid}");
    }

    for invalid in [
        "",
        "not-a-url",
        "http://fees.example/api",
        "ftp://fees.example/api",
        "https://user@fees.example/api",
        "https://user:secret@fees.example/api",
        "https://fees.example:0/api",
        "https://fees.example/api?token=secret",
        "https://fees.example/api#fragment",
        "data:text/plain,fees",
    ] {
        assert!(
            !valid_fee_https_base_endpoint(invalid),
            "accepted {invalid}"
        );
        let mut config = FeePolicyConfig::default();
        config.liquid.sources[0].endpoint = invalid.to_string();
        assert!(!config.validation_facts().liquid.sources_valid);
    }
}

#[test]
fn fee_refresh_and_freshness_windows_fail_closed_independently() {
    let mut config = FeePolicyConfig::default();
    config.bitcoin.refresh_interval_secs = 0;
    let facts = config.validation_facts();
    assert!(!facts.bitcoin.refresh_interval_valid);
    assert!(facts.bitcoin.live_freshness_window_valid);
    assert!(facts.bitcoin.last_known_good_freshness_window_valid);
    assert!(facts.liquid.all_valid());

    config = FeePolicyConfig::default();
    config.bitcoin.live_max_age_secs = 0;
    let facts = config.validation_facts();
    assert!(facts.bitcoin.refresh_interval_valid);
    assert!(!facts.bitcoin.live_freshness_window_valid);
    assert!(facts.bitcoin.last_known_good_freshness_window_valid);

    config = FeePolicyConfig::default();
    config.liquid.last_known_good_max_age_secs = 0;
    let facts = config.validation_facts();
    assert!(facts.liquid.refresh_interval_valid);
    assert!(facts.liquid.live_freshness_window_valid);
    assert!(!facts.liquid.last_known_good_freshness_window_valid);
    assert!(facts.bitcoin.all_valid());

    let parsed: FeePolicyConfig = toml::from_str(
        r#"
        [bitcoin]
        refresh_interval_secs = 1
        live_max_age_secs = 2
        last_known_good_max_age_secs = 3
        [liquid]
        refresh_interval_secs = 4
        live_max_age_secs = 5
        last_known_good_max_age_secs = 6
        "#,
    )
    .unwrap();
    assert!(parsed.validation_facts().all_valid());
}

#[test]
fn fee_bounds_require_finite_positive_ordered_values_per_rail() {
    for (floor, cap) in [
        (f64::NAN, 10.0),
        (1.0, f64::NAN),
        (f64::INFINITY, 10.0),
        (1.0, f64::INFINITY),
        (f64::NEG_INFINITY, 10.0),
        (1.0, f64::NEG_INFINITY),
        (0.0, 10.0),
        (-1.0, 10.0),
        (1.0, 0.0),
        (1.0, -10.0),
        (10.0, 1.0),
    ] {
        let mut config = FeePolicyConfig::default();
        config.bitcoin.floor_sat_per_vbyte = floor;
        config.bitcoin.cap_sat_per_vbyte = cap;
        let facts = config.validation_facts();
        assert!(!facts.bitcoin.bounds_valid, "accepted {floor}..={cap}");
        assert!(facts.liquid.bounds_valid);
    }

    let mut config = FeePolicyConfig::default();
    config.bitcoin.floor_sat_per_vbyte = 2.5;
    config.bitcoin.cap_sat_per_vbyte = 2.5;
    config.liquid.floor_sat_per_vbyte = 0.125;
    config.liquid.cap_sat_per_vbyte = 0.125;
    assert!(config.validation_facts().all_valid());

    for literal in ["nan", "inf", "-inf", "0.0", "-1.0"] {
        let input =
            format!("[liquid]\nfloor_sat_per_vbyte = {literal}\ncap_sat_per_vbyte = 10.0\n");
        let parsed: FeePolicyConfig = toml::from_str(&input).unwrap();
        assert!(!parsed.validation_facts().liquid.bounds_valid);
    }
}

#[test]
fn fee_config_debug_redacts_valid_and_invalid_endpoint_values() {
    let mut config = FeePolicyConfig::default();
    config.bitcoin.sources = vec![fee_source(
        "private-primary",
        "https://credential-like-value.example/api?token=private-token",
    )];
    config.liquid.sources = vec![fee_source(
        "invalid\nidentity",
        "https://other-private.example/api",
    )];

    let diagnostic = format!("{config:?}");
    assert!(diagnostic.contains("<redacted>"));
    for secret in [
        "private-primary",
        "credential-like-value.example",
        "private-token",
        "other-private.example",
        "invalid\nidentity",
    ] {
        assert!(!diagnostic.contains(secret));
    }

    let mut root = production_base_config();
    root.fee_policy = config;
    let root_diagnostic = format!("{root:?}");
    assert!(!root_diagnostic.contains("credential-like-value.example"));
    assert!(!root_diagnostic.contains("other-private.example"));
}

#[test]
fn invalid_fee_config_exposes_false_facts_without_changing_startup_validation() {
    let mut config = production_base_config();
    config.fee_policy.bitcoin.sources.clear();
    config.fee_policy.liquid.refresh_interval_secs = 0;

    config.validate_for_runtime("development", false).unwrap();
    let facts = config.fee_policy.validation_facts();
    assert!(!facts.bitcoin.sources_valid);
    assert!(!facts.liquid.refresh_interval_valid);
    assert!(!facts.all_valid());
}

#[test]
fn direct_payment_finality_defaults_and_overrides_are_explicit() {
    assert_eq!(BitcoinWatcherConfig::default().confirmations_required, 3);
    assert_eq!(LiquidWatcherConfig::default().finality_confirmations, 2);

    let bitcoin: BitcoinWatcherConfig = toml::from_str("confirmations_required = 4").unwrap();
    let liquid: LiquidWatcherConfig = toml::from_str("finality_confirmations = 5").unwrap();
    assert_eq!(bitcoin.confirmations_required, 4);
    assert_eq!(liquid.finality_confirmations, 5);
}

#[test]
fn swap_key_epoch_defaults_to_one_and_must_be_positive() {
    let boltz: BoltzConfig = toml::from_str(
        r#"
api_url = "https://api.boltz.exchange/v2"
electrum_url = "ssl://liquid-electrum.example.com:50002"
"#,
    )
    .unwrap();
    assert_eq!(boltz.key_epoch, 1);

    let mut cfg = production_base_config();
    cfg.boltz.key_epoch = 0;
    let error = cfg.validate_for_runtime("development", false).unwrap_err();
    assert!(error.to_string().contains("boltz.key_epoch"));
}

#[test]
fn direct_payment_finality_zero_is_rail_local_without_aborting_config() {
    let mut cfg = production_base_config();
    cfg.bitcoin_watcher.confirmations_required = 0;
    assert!(!cfg.bitcoin_watcher.finality_valid());
    cfg.validate_for_runtime("unknown", false).unwrap();

    cfg.bitcoin_watcher.confirmations_required = 1;
    cfg.liquid_watcher.finality_confirmations = 0;
    assert!(cfg.bitcoin_watcher.finality_valid());
    assert!(!cfg.liquid_watcher.finality_valid());
    cfg.validate_for_runtime("unknown", false).unwrap();

    cfg.liquid_watcher.finality_confirmations = 1;
    assert!(cfg.liquid_watcher.finality_valid());
    cfg.validate_for_runtime("unknown", false).unwrap();
}

#[test]
fn liquid_claim_validation_includes_boltz_and_shared_electrum_settings() {
    let mut cfg = production_base_config();
    assert!(cfg.liquid_claim_settings_valid());

    cfg.boltz.electrum_url = "invalid".to_string();
    assert!(!cfg.liquid_claim_settings_valid());

    cfg.boltz.electrum_url = "ssl://liquid-electrum.example.com:50002".to_string();
    cfg.electrum.liquid_urls = vec!["ssl://missing-port".to_string()];
    assert!(!cfg.liquid_claim_settings_valid());
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
fn production_rejects_loopback_ip_domain() {
    let mut cfg = production_base_config();
    cfg.domain = "127.0.0.1:8080".to_string();

    let err = cfg.validate_for_runtime("production", false).unwrap_err();

    assert!(err.to_string().contains("loopback IP"));
}

#[test]
fn production_rejects_ipv6_loopback_domain() {
    let mut cfg = production_base_config();
    cfg.domain = "[::1]:8080".to_string();

    let err = cfg.validate_for_runtime("production", false).unwrap_err();

    assert!(err.to_string().contains("loopback IP"));
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
fn image_pixel_cap_must_be_nonzero() {
    let mut cfg = production_base_config();
    cfg.donation.image_max_pixels = 0;

    let err = cfg.validate_for_runtime("development", false).unwrap_err();

    assert!(err
        .to_string()
        .contains("donation.image_max_pixels must be > 0"));
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
        liquid_urls: vec!["ssl://les.bullbitcoin.com:995".to_string()],
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
        liquid_urls: vec!["ssl://my-node:50002".to_string()],
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

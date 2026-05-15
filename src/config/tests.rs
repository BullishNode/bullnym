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

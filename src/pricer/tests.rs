use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{http::StatusCode, routing::post, Router};
use chrono::{SecondsFormat, Utc};
use tokio::net::TcpListener;

fn rate_element(currency: &str, index_price: i64, precision: u8) -> RateElement {
    RateElement {
        from_currency: BASE_CURRENCY.to_string(),
        to_currency: currency.to_string(),
        price_currency: currency.to_string(),
        index_price,
        precision,
        created_at: "2026-05-07T20:21:33.652Z".to_string(),
    }
}

fn rfc3339(unix: u64) -> String {
    DateTime::<Utc>::from_timestamp(unix as i64, 0)
        .expect("fixture timestamp must be representable")
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[test]
fn supported_currencies_are_normalized_deduped_and_explicit() {
    let currencies = vec![
        "usd".to_string(),
        " USD ".to_string(),
        "cop".to_string(),
        "crc".to_string(),
        "".to_string(),
    ];
    let normalized = normalize_supported_currencies(&currencies);
    assert_eq!(
        normalized,
        vec![
            CurrencyView {
                code: "COP".to_string(),
                precision: 0,
            },
            CurrencyView {
                code: "CRC".to_string(),
                precision: 0,
            },
            CurrencyView {
                code: "USD".to_string(),
                precision: 2,
            },
        ]
    );

    let client = PricerClient::new(PricerConfig {
        supported_currencies: currencies,
        ..PricerConfig::default()
    })
    .unwrap();
    assert!(client.is_supported_currency(" usd "));
    assert!(!client.is_supported_currency("EUR"));
}

#[test]
fn currency_code_normalization_is_ascii_uppercase() {
    assert_eq!(normalize_currency_code(" usd "), "USD");
    assert_eq!(normalize_currency_code("ß"), "ß");
}

#[test]
fn pricer_init_rejects_empty_or_unbounded_currency_sets() {
    let empty = PricerConfig {
        supported_currencies: vec![" ".to_string()],
        ..PricerConfig::default()
    };
    assert!(matches!(
        PricerClient::new(empty),
        Err(PricerInitError::EmptySupportedCurrencies)
    ));

    let unbounded = PricerConfig {
        supported_currencies: vec!["USD".to_string(), "XYZ".to_string()],
        ..PricerConfig::default()
    };
    match PricerClient::new(unbounded) {
        Err(PricerInitError::MissingRateCeiling(currency)) => assert_eq!(currency, "XYZ"),
        Err(error) => panic!("unexpected pricer init error: {error}"),
        Ok(_) => panic!("expected missing ceiling error"),
    }
}

#[test]
fn pricer_init_rejects_unbounded_freshness_policy() {
    for cfg in [
        PricerConfig {
            cache_ttl_secs: 0,
            ..PricerConfig::default()
        },
        PricerConfig {
            max_freshness_secs: 0,
            ..PricerConfig::default()
        },
        PricerConfig {
            max_freshness_secs: 301,
            ..PricerConfig::default()
        },
        PricerConfig {
            cache_ttl_secs: 301,
            max_freshness_secs: 300,
            ..PricerConfig::default()
        },
        PricerConfig {
            request_timeout_ms: 0,
            ..PricerConfig::default()
        },
    ] {
        assert!(matches!(
            PricerClient::new(cfg),
            Err(PricerInitError::InvalidFreshnessPolicy)
        ));
    }
}

#[test]
fn rate_view_serializes_provenance_and_freshness() {
    let view = RateView {
        currency: "USD".to_string(),
        minor_per_btc: 918_780_000,
        precision: 2,
        source: RATE_SOURCE.to_string(),
        observed_at_unix: 1_700_000_000,
        fetched_at_unix: 1_700_000_001,
        expires_at_unix: 1_700_000_300,
        last_known_rate: false,
    };
    let value = serde_json::to_value(view).unwrap();
    assert_eq!(value["currency"], "USD");
    assert_eq!(value["minor_per_btc"], 918_780_000);
    assert_eq!(value["precision"], 2);
    assert_eq!(value["source"], RATE_SOURCE);
    assert_eq!(value["observed_at_unix"], 1_700_000_000_u64);
    assert_eq!(value["fetched_at_unix"], 1_700_000_001_u64);
    assert_eq!(value["expires_at_unix"], 1_700_000_300_u64);
}

#[test]
fn json_rpc_response_decodes_exact_public_pricer_shape() {
    let raw = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "element": {
                "fromCurrency": "BTC",
                "toCurrency": "USD",
                "price": 7853523,
                "priceCurrency": "USD",
                "precision": 2,
                "indexPrice": 8009468,
                "createdAt": "2026-05-07T20:21:33.652Z"
            }
        }
    }"#;
    let parsed: JsonRpcResponse = serde_json::from_str(raw).unwrap();
    let element = parsed.result.unwrap().element;
    assert_eq!(element.index_price, 8_009_468);
    assert_eq!(element.from_currency, "BTC");
    assert_eq!(element.to_currency, "USD");
    assert_eq!(element.price_currency, "USD");
    assert_eq!(element.precision, 2);
    assert_eq!(element.created_at, "2026-05-07T20:21:33.652Z");
}

#[test]
fn upstream_pair_validation_rejects_base_quote_and_price_mismatch() {
    let valid = rate_element("USD", 90_000_000, 2);
    assert_eq!(validate_upstream_pair(&valid, "USD"), Ok(()));

    let wrong_base = RateElement {
        from_currency: "L-BTC".to_string(),
        ..rate_element("USD", 90_000_000, 2)
    };
    let wrong_quote = RateElement {
        to_currency: "CAD".to_string(),
        ..rate_element("USD", 90_000_000, 2)
    };
    let wrong_price_currency = RateElement {
        price_currency: "CAD".to_string(),
        ..rate_element("USD", 90_000_000, 2)
    };
    for mismatch in [&wrong_base, &wrong_quote, &wrong_price_currency] {
        assert_eq!(
            validate_upstream_pair(mismatch, "USD"),
            Err(PricerError::PairMismatch)
        );
    }
}

#[test]
fn upstream_observation_has_exclusive_age_and_future_bounds() {
    let fetched = 1_700_000_000;
    assert_eq!(
        validate_observation_time(&rfc3339(fetched - 299), fetched, 300),
        Ok((fetched - 299, fetched + 1))
    );
    assert_eq!(
        validate_observation_time(&rfc3339(fetched - 300), fetched, 300),
        Err(PricerError::StaleObservation)
    );
    assert_eq!(
        validate_observation_time(
            &rfc3339(fetched + MAX_UPSTREAM_FUTURE_SKEW_SECS + 1),
            fetched,
            300,
        ),
        Err(PricerError::FutureObservation)
    );
    assert_eq!(
        validate_observation_time(
            &rfc3339(fetched + MAX_UPSTREAM_FUTURE_SKEW_SECS),
            fetched,
            300,
        ),
        Ok((fetched + MAX_UPSTREAM_FUTURE_SKEW_SECS, fetched + 300,))
    );
    assert_eq!(
        validate_observation_time("not-a-time", fetched, 300),
        Err(PricerError::InvalidObservationTime)
    );
}

#[test]
fn non_integer_and_non_finite_wire_rates_do_not_decode() {
    for index_price in ["1.5", "NaN", "Infinity", "1e309"] {
        let raw = format!(
            r#"{{
                "result": {{"element": {{
                    "fromCurrency": "BTC",
                    "toCurrency": "USD",
                    "priceCurrency": "USD",
                    "precision": 2,
                    "indexPrice": {index_price},
                    "createdAt": "2026-05-07T20:21:33Z"
                }}}}
            }}"#
        );
        assert!(
            serde_json::from_str::<JsonRpcResponse>(&raw).is_err(),
            "wire rate {index_price} unexpectedly decoded"
        );
    }
}

#[test]
fn rate_guardrail_accepts_supported_currency_ranges() {
    let usd = rate_element("USD", 90_000_000, 2);
    let crc = rate_element("CRC", 5_000_000_000, 2);
    let cop = rate_element("COP", 450_000_000, 0);

    let usd_minor = minor_per_btc_from_element(&usd).unwrap();
    let crc_minor = minor_per_btc_from_element(&crc).unwrap();
    let cop_minor = minor_per_btc_from_element(&cop).unwrap();

    assert_eq!(usd_minor, 90_000_000);
    assert_eq!(crc_minor, 50_000_000);
    assert_eq!(cop_minor, 450_000_000);
    assert!(validate_rate(&usd.to_currency, usd_minor).is_ok());
    assert!(validate_rate(&crc.to_currency, crc_minor).is_ok());
    assert!(validate_rate(&cop.to_currency, cop_minor).is_ok());
}

#[test]
fn rate_guardrail_rejects_non_positive_rates() {
    for index_price in [0, -1] {
        let rate = rate_element("USD", index_price, 2);
        let minor = minor_per_btc_from_element(&rate).unwrap();
        assert!(validate_rate(&rate.to_currency, minor).is_err());
    }
}

#[test]
fn crc_rate_is_normalized_to_whole_colones() {
    let crc = rate_element("CRC", 5_000_000_049, 2);
    assert_eq!(minor_per_btc_from_element(&crc).unwrap(), 50_000_000);

    let rounded = RateElement {
        index_price: 5_000_000_050,
        ..crc
    };
    assert_eq!(minor_per_btc_from_element(&rounded).unwrap(), 50_000_001);
}

#[test]
fn rate_guardrail_rejects_absurd_or_unbounded_rates() {
    let rates = [
        rate_element("USD", 1_000_000_001, 2),
        rate_element("CRC", 500_000_000_050, 2),
        rate_element("CRC", 5_000_000_001, 0),
        rate_element("COP", 50_000_000_001, 0),
        rate_element("XYZ", 100, 2),
    ];

    for rate in rates {
        let minor = minor_per_btc_from_element(&rate).unwrap();
        assert!(validate_rate(&rate.to_currency, minor).is_err());
    }
}

#[test]
fn expired_cache_is_never_exposed() {
    let client = PricerClient::new(PricerConfig::default()).unwrap();
    let now = unix_now();
    client.cache.insert(
        "USD".to_string(),
        CachedRate {
            rate: RateView {
                currency: "USD".to_string(),
                minor_per_btc: 9_000_000,
                precision: 2,
                source: RATE_SOURCE.to_string(),
                observed_at_unix: now.saturating_sub(300),
                fetched_at_unix: now.saturating_sub(60),
                expires_at_unix: now,
                last_known_rate: false,
            },
            cached_at: Instant::now() - Duration::from_secs(60),
        },
    );

    assert!(client.cached_rate("USD").is_none());
    assert!(client.bounded_last_known_rate("USD").is_none());
}

#[test]
fn failed_refresh_may_reuse_only_a_still_unexpired_observation() {
    let client = PricerClient::new(PricerConfig::default()).unwrap();
    let now = unix_now();
    client.cache.insert(
        "USD".to_string(),
        CachedRate {
            rate: RateView {
                currency: "USD".to_string(),
                minor_per_btc: 9_000_000,
                precision: 2,
                source: RATE_SOURCE.to_string(),
                observed_at_unix: now.saturating_sub(120),
                fetched_at_unix: now.saturating_sub(61),
                expires_at_unix: now + 180,
                last_known_rate: false,
            },
            cached_at: Instant::now() - Duration::from_secs(61),
        },
    );

    assert!(client.current_cached_rate("USD").is_none());
    let fallback = client.bounded_last_known_rate("USD").unwrap();
    assert!(fallback.last_known_rate);
    assert_eq!(fallback.observed_at_unix, now.saturating_sub(120));
    assert_eq!(fallback.expires_at_unix, now + 180);
}

#[tokio::test]
async fn identical_concurrent_requests_share_one_upstream_fetch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let observed_at = rfc3339(unix_now());
    let app = Router::new().route(
        "/",
        post(move || {
            let handler_calls = Arc::clone(&handler_calls);
            let observed_at = observed_at.clone();
            async move {
                handler_calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(75)).await;
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"element": {
                        "fromCurrency": "BTC",
                        "toCurrency": "USD",
                        "price": 9_000_000,
                        "priceCurrency": "USD",
                        "precision": 2,
                        "indexPrice": 9_000_000,
                        "createdAt": observed_at,
                    }}
                }))
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = Arc::new(
        PricerClient::new(PricerConfig {
            url: format!("http://{address}/"),
            supported_currencies: vec!["USD".to_string()],
            ..PricerConfig::default()
        })
        .unwrap(),
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(17));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let client = Arc::clone(&client);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            client.get_rate(" usd ").await
        }));
    }
    barrier.wait().await;
    for task in tasks {
        let rate = task.await.unwrap().unwrap();
        assert_eq!(rate.currency, "USD");
        assert_eq!(rate.source, RATE_SOURCE);
        assert!(!rate.last_known_rate);
        assert!(rate.observed_at_unix <= rate.fetched_at_unix);
        assert!(rate.fetched_at_unix < rate.expires_at_unix);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    server.abort();
}

#[tokio::test]
async fn identical_concurrent_failures_share_one_upstream_fetch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let app = Router::new().route(
        "/",
        post(move || {
            let handler_calls = Arc::clone(&handler_calls);
            async move {
                handler_calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(75)).await;
                StatusCode::SERVICE_UNAVAILABLE
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = Arc::new(
        PricerClient::new(PricerConfig {
            url: format!("http://{address}/"),
            supported_currencies: vec!["USD".to_string()],
            ..PricerConfig::default()
        })
        .unwrap(),
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(17));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let client = Arc::clone(&client);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            client.get_rate("USD").await
        }));
    }
    barrier.wait().await;
    for task in tasks {
        assert!(task.await.unwrap().is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    server.abort();
}

#[test]
fn json_rpc_error_payload_is_not_retained_for_logging() {
    let raw = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "error": { "code": -32602, "message": "sensitive upstream payload" }
    }"#;
    let parsed: JsonRpcResponse = serde_json::from_str(raw).unwrap();
    assert!(parsed.result.is_none());
    assert!(parsed.error.is_some());
    assert_eq!(PricerError::Rpc.to_string(), "pricer rpc");
}

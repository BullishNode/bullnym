use super::*;

#[test]
fn supported_currencies_are_normalized_and_deduped() {
    let currencies = vec![
        "usd".to_string(),
        " USD ".to_string(),
        "cop".to_string(),
        "".to_string(),
    ];
    let normalized = normalize_supported_currencies(&currencies);
    assert_eq!(
        normalized
            .iter()
            .map(|c| c.code.as_str())
            .collect::<Vec<_>>(),
        vec!["COP", "USD"]
    );
    assert_eq!(normalized[0].precision, 0);
    assert_eq!(normalized[1].precision, 2);
}

#[test]
fn currency_code_normalization_trims_and_uppercases() {
    assert_eq!(normalize_currency_code(" usd "), "USD");
}

#[test]
fn pricer_init_rejects_supported_currency_without_ceiling() {
    let cfg = PricerConfig {
        supported_currencies: vec!["USD".to_string(), "XYZ".to_string()],
        ..PricerConfig::default()
    };

    match PricerClient::new(cfg) {
        Err(PricerInitError::MissingRateCeiling(currency)) => assert_eq!(currency, "XYZ"),
        Err(err) => panic!("unexpected pricer init error: {err}"),
        Ok(_) => panic!("expected missing ceiling error"),
    }
}

#[test]
fn rate_view_serializes_with_expected_fields() {
    let view = RateView {
        currency: "USD".to_string(),
        minor_per_btc: 918_780_000,
        precision: 2,
        fetched_at_unix: 1_700_000_000,
        last_known_rate: false,
    };
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains("\"currency\":\"USD\""));
    assert!(json.contains("\"minor_per_btc\":918780000"));
    assert!(json.contains("\"precision\":2"));
}

#[test]
fn json_rpc_response_decodes_pricer_shape() {
    // Real shape from api.bullbitcoin.com/public/price: no `marketPrice`,
    // only `price` + `indexPrice`. We use the neutral index rate.
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
    assert_eq!(element.to_currency, "USD");
    assert_eq!(element.precision, 2);
}

#[test]
fn rate_guardrail_accepts_supported_currency_ranges() {
    let usd = RateElement {
        from_currency: "BTC".to_string(),
        to_currency: "USD".to_string(),
        index_price: 90_000_000,
        precision: 2,
    };
    let crc = RateElement {
        from_currency: "BTC".to_string(),
        to_currency: "CRC".to_string(),
        index_price: 5_000_000_000,
        precision: 2,
    };
    let cop = RateElement {
        from_currency: "BTC".to_string(),
        to_currency: "COP".to_string(),
        index_price: 450_000_000,
        precision: 0,
    };

    assert!(validate_rate_element(&usd).is_ok());
    assert!(validate_rate_element(&crc).is_ok());
    assert!(validate_rate_element(&cop).is_ok());
}

#[test]
fn rate_guardrail_rejects_non_positive_rates() {
    let zero = RateElement {
        from_currency: "BTC".to_string(),
        to_currency: "USD".to_string(),
        index_price: 0,
        precision: 2,
    };

    assert!(validate_rate_element(&zero).is_err());
}

#[test]
fn rate_guardrail_rejects_absurd_currency_specific_rates() {
    let usd = RateElement {
        from_currency: "BTC".to_string(),
        to_currency: "USD".to_string(),
        index_price: 1_000_000_001,
        precision: 2,
    };
    let crc = RateElement {
        from_currency: "BTC".to_string(),
        to_currency: "CRC".to_string(),
        index_price: 500_000_000_001,
        precision: 2,
    };
    let cop = RateElement {
        from_currency: "BTC".to_string(),
        to_currency: "COP".to_string(),
        index_price: 50_000_000_001,
        precision: 0,
    };

    assert!(validate_rate_element(&usd).is_err());
    assert!(validate_rate_element(&crc).is_err());
    assert!(validate_rate_element(&cop).is_err());
}

#[test]
fn rate_guardrail_rejects_currencies_without_explicit_ceiling() {
    let unknown = RateElement {
        from_currency: "BTC".to_string(),
        to_currency: "XYZ".to_string(),
        index_price: 100,
        precision: 2,
    };

    assert!(validate_rate_element(&unknown).is_err());
}

#[test]
fn json_rpc_error_decodes() {
    let raw = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "error": { "code": -32602, "message": "Invalid params" }
    }"#;
    let parsed: JsonRpcResponse = serde_json::from_str(raw).unwrap();
    assert!(parsed.result.is_none());
    assert_eq!(parsed.error.unwrap().message, "Invalid params");
}

use super::*;

#[test]
fn callback_contract_rejects_retired_approach_a_fields() {
    for retired in ["blinding_key", "asset"] {
        let mut request = serde_json::json!({ "amount": 100_000 });
        request[retired] = serde_json::Value::String("00".repeat(32));

        let error = match serde_json::from_value::<CallbackParams>(request) {
            Ok(_) => panic!("retired LUD-22 fields must not be silently accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unknown field"));
        assert!(error.to_string().contains(retired));
    }
}

#[test]
fn callback_contract_accepts_only_current_approach_b_fields() {
    let request = serde_json::json!({
        "amount": 100_000,
        "payment_method": "L-BTC",
        "outpoint": format!("{}:0", "00".repeat(32)),
        "pubkey": format!("02{}", "11".repeat(32)),
        "sig": "3000",
        "value": 1_000,
        "value_bf": "22".repeat(32),
        "asset_bf": "33".repeat(32),
    });

    serde_json::from_value::<CallbackParams>(request)
        .expect("the current LUD-22 callback shape must remain accepted");
}

#[test]
fn metadata_is_valid_json() {
    let meta = build_metadata("francis", "bullpay.ca");
    let parsed: serde_json::Value = serde_json::from_str(&meta).unwrap();
    assert!(parsed.is_array());
}

#[test]
fn metadata_contains_identifier() {
    let meta = build_metadata("francis", "bullpay.ca");
    assert!(meta.contains("francis@bullpay.ca"));
    assert!(meta.contains("text/identifier"));
}

#[test]
fn metadata_contains_plain_text() {
    let meta = build_metadata("francis", "bullpay.ca");
    assert!(meta.contains("Sats for francis"));
    assert!(meta.contains("text/plain"));
}

#[test]
fn rl_gate_rate_limited_becomes_soft() {
    for variant in [
        AppError::RateLimitedSender,
        AppError::RateLimitedRecipient,
        AppError::RateLimitedNetwork,
        AppError::BackendThrottled,
    ] {
        let expected_code = variant.code();
        let r: Result<(), AppError> = Err(variant);
        match rl_gate(r) {
            Err(LiquidOutcome::SoftRateLimited(error)) => {
                assert_eq!(error.code(), expected_code)
            }
            _ => panic!("rate-limit variant should map to SoftRateLimited"),
        }
    }
}

#[test]
fn rl_gate_too_many_pending_becomes_soft() {
    // Pending caps protect server resources; Lightning fallback is the
    // graceful response when Liquid cannot reserve another address.
    let r: Result<(), AppError> = Err(AppError::TooManyPendingReservations);
    match rl_gate(r) {
        Err(LiquidOutcome::SoftRateLimited(AppError::TooManyPendingReservations)) => (),
        _ => panic!("TooManyPendingReservations should map to SoftRateLimited"),
    }
}

#[test]
fn rl_gate_proof_failure_is_hard() {
    let r: Result<(), AppError> = Err(AppError::UtxoSpent);
    match rl_gate(r) {
        Err(LiquidOutcome::Hard(AppError::UtxoSpent)) => (),
        _ => panic!("UtxoSpent should map to Hard(UtxoSpent)"),
    }
}

#[test]
fn rl_gate_db_error_is_hard() {
    let r: Result<(), AppError> = Err(AppError::DbError("test".into()));
    match rl_gate(r) {
        Err(LiquidOutcome::Hard(AppError::DbError(_))) => (),
        _ => panic!("DbError should map to Hard"),
    }
}

#[test]
fn rl_gate_ok_passes_through() {
    let r: Result<u32, AppError> = Ok(42);
    assert_eq!(rl_gate(r).ok(), Some(42));
}

#[test]
fn provider_snapshot_unavailability_uses_existing_temporary_service_error() {
    for unavailable in [
        LightningAddressUnavailable::SnapshotMissing,
        LightningAddressUnavailable::SnapshotInvalid(
            crate::provider_limits::ReversePairValidationError::WrongPair,
        ),
        LightningAddressUnavailable::SnapshotObservedInFuture,
        LightningAddressUnavailable::SnapshotStale,
        LightningAddressUnavailable::ZeroConfUnavailable,
        LightningAddressUnavailable::NoExecutableRange,
    ] {
        let error = lightning_address_unavailable(unavailable);
        assert!(matches!(&error, AppError::MoneyAdmissionUnavailable));
        assert_eq!(error.code(), "ServiceUnavailable");
    }
}

#[test]
fn creation_unavailability_uses_existing_temporary_service_error() {
    let error =
        lightning_address_creation_error(LightningAddressCreationError::TemporarilyUnavailable(
            LightningAddressUnavailable::SnapshotStale,
        ));
    assert!(matches!(&error, AppError::MoneyAdmissionUnavailable));
    assert_eq!(error.code(), "ServiceUnavailable");
}

#[test]
fn creation_amount_errors_keep_existing_lnurl_contract() {
    let cases = [
        (
            LightningAddressCreationError::AmountNotWholeSatoshi,
            "amount must be a multiple of 1000 msat",
        ),
        (
            LightningAddressCreationError::BelowCurrentMinimum {
                minimum_msat: 250_000,
            },
            "minimum is 250000 msat",
        ),
        (
            LightningAddressCreationError::AboveCurrentMaximum {
                maximum_msat: 500_000,
            },
            "maximum is 500000 msat",
        ),
    ];

    for (creation_error, expected_message) in cases {
        let error = lightning_address_creation_error(creation_error);
        match error {
            AppError::InvalidAmount(message) => assert_eq!(message, expected_message),
            other => panic!("expected InvalidAmount, got {}", other.code()),
        }
    }
}

#[test]
fn liquid_response_addr_index_uses_current_cursor_without_reservation() {
    assert_eq!(liquid_response_addr_index(7, None).unwrap(), 7);
}

#[test]
fn liquid_response_addr_index_uses_reserved_index_when_present() {
    assert_eq!(liquid_response_addr_index(7, Some(2)).unwrap(), 2);
}

#[test]
fn liquid_response_addr_index_rejects_negative_current_cursor() {
    let err = liquid_response_addr_index(-1, None).unwrap_err();
    assert_eq!(err.code(), "InternalError");
}

#[test]
fn liquid_response_addr_index_rejects_negative_reserved_index() {
    let err = liquid_response_addr_index(7, Some(-1)).unwrap_err();
    assert_eq!(err.code(), "InternalError");
}

#[test]
fn requests_method_single() {
    assert!(requests_method(Some("L-BTC"), "L-BTC"));
    assert!(!requests_method(Some("L-BTC"), "BTC-SP"));
    assert!(!requests_method(None, "L-BTC"));
}

#[test]
fn requests_method_comma_list() {
    assert!(requests_method(Some("L-BTC,BTC-SP"), "L-BTC"));
    assert!(requests_method(Some("L-BTC,BTC-SP"), "BTC-SP"));
    assert!(!requests_method(Some("L-BTC,BTC-SP"), "BTC"));
}

#[test]
fn requests_method_trims_whitespace() {
    assert!(requests_method(Some("L-BTC, BTC-SP"), "BTC-SP"));
    assert!(requests_method(Some(" L-BTC "), "L-BTC"));
}

#[test]
fn requests_method_case_sensitive() {
    assert!(!requests_method(Some("l-btc"), "L-BTC"));
}

#[test]
fn metadata_has_two_entries() {
    let meta = build_metadata("test", "example.com");
    let parsed: Vec<Vec<String>> = serde_json::from_str(&meta).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0][0], "text/identifier");
    assert_eq!(parsed[1][0], "text/plain");
}

#[test]
fn description_hash_is_deterministic() {
    let meta = build_metadata("francis", "bullpay.ca");
    let hash1 = hex::encode(Sha256::digest(meta.as_bytes()));
    let hash2 = hex::encode(Sha256::digest(
        build_metadata("francis", "bullpay.ca").as_bytes(),
    ));
    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 64);
}

#[test]
fn description_hash_differs_per_nym() {
    let h1 = hex::encode(Sha256::digest(
        build_metadata("alice", "bullpay.ca").as_bytes(),
    ));
    let h2 = hex::encode(Sha256::digest(
        build_metadata("bob", "bullpay.ca").as_bytes(),
    ));
    assert_ne!(h1, h2);
}

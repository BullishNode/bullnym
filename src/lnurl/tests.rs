use super::*;

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
        let r: Result<(), AppError> = Err(variant);
        match rl_gate(r) {
            Err(LiquidOutcome::SoftRateLimited) => (),
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
        Err(LiquidOutcome::SoftRateLimited) => (),
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

use super::*;

#[test]
fn save_payload_fields_fixed_order() {
    let fields = save_payload_fields(
        "Alice's Coffee",
        "Buy me a coffee!",
        "USD",
        "https://alice.example",
        "alice",
        "alice_ig",
        "1",
    );
    assert_eq!(fields.len(), 7);
    assert_eq!(fields[0], "Alice's Coffee");
    assert_eq!(fields[2], "USD");
    assert_eq!(fields[6], "1");
}

/// Byte-exact contract test for the v2 signing protocol.
///
/// Mobile builds this same message with
/// `core/nostr/bullpay_la_v2_signing.dart`. Any field order or separator
/// change here must ship with the matching mobile change.
#[test]
fn v2_save_message_byte_exact_contract() {
    let fields = save_payload_fields(
        "Alice's Coffee",
        "Buy me a coffee!",
        "USD",
        "https://alice.example",
        "alice",
        "alice_ig",
        "1",
    );
    let npub = "00".repeat(32);
    let timestamp: u64 = 1_700_000_000;
    let msg = crate::auth::build_la_v2_message(ACTION_SAVE, &npub, "alice", &fields, timestamp);

    let mut expected: Vec<u8> = Vec::new();
    expected.extend_from_slice(b"bullpay-la-v2");
    expected.push(0);
    expected.extend_from_slice(b"donation-page-save");
    expected.push(0);
    expected.extend_from_slice(npub.as_bytes());
    expected.push(0);
    expected.extend_from_slice(b"alice");
    expected.push(0);
    for f in &fields {
        expected.extend_from_slice(f.as_bytes());
        expected.push(0);
    }
    expected.extend_from_slice(b"1700000000");

    assert_eq!(msg, expected, "v2 byte order regression");
    assert_eq!(msg.iter().filter(|&&b| b == 0).count(), 11);
}

#[test]
fn v2_archive_message_byte_exact_contract() {
    let npub = "ab".repeat(32);
    let timestamp: u64 = 1_700_000_000;
    let msg = crate::auth::build_la_v2_message(ACTION_ARCHIVE, &npub, "alice", &[], timestamp);

    let mut expected: Vec<u8> = Vec::new();
    expected.extend_from_slice(b"bullpay-la-v2");
    expected.push(0);
    expected.extend_from_slice(b"donation-page-archive");
    expected.push(0);
    expected.extend_from_slice(npub.as_bytes());
    expected.push(0);
    expected.extend_from_slice(b"alice");
    expected.push(0);
    expected.extend_from_slice(b"1700000000");

    assert_eq!(msg, expected, "v2 archive byte order regression");
}

#[test]
fn v2_image_message_byte_exact_contract() {
    let npub = "cd".repeat(32);
    let timestamp: u64 = 1_700_000_000;
    let sha256_hex = "94ee059335e587e501cc4bf90613e0814f00a7b08bc7c648fd865a2af6a22cc2";
    let msg = crate::auth::build_la_v2_message(
        ACTION_IMAGE,
        &npub,
        "alice",
        &["avatar", sha256_hex],
        timestamp,
    );

    let mut expected: Vec<u8> = Vec::new();
    expected.extend_from_slice(b"bullpay-la-v2");
    expected.push(0);
    expected.extend_from_slice(b"donation-page-image");
    expected.push(0);
    expected.extend_from_slice(npub.as_bytes());
    expected.push(0);
    expected.extend_from_slice(b"alice");
    expected.push(0);
    expected.extend_from_slice(b"avatar");
    expected.push(0);
    expected.extend_from_slice(sha256_hex.as_bytes());
    expected.push(0);
    expected.extend_from_slice(b"1700000000");

    assert_eq!(msg, expected, "v2 image byte order regression");
}

fn make_req() -> SaveDonationPageRequest {
    SaveDonationPageRequest {
        nym: "alice".to_string(),
        npub: "00".repeat(32),
        header: "Title".to_string(),
        description: "Desc".to_string(),
        display_currency: "USD".to_string(),
        website: Some("https://example.com".to_string()),
        twitter: Some("alice".to_string()),
        instagram: Some("alice.ig".to_string()),
        enabled: true,
        timestamp: 0,
        signature: String::new(),
    }
}

fn test_pricer() -> PricerClient {
    PricerClient::new(Default::default()).unwrap()
}

#[test]
fn validates_minimal_request() {
    assert!(validate_lengths(&make_req(), &test_pricer()).is_ok());
}

#[test]
fn rejects_empty_header() {
    let mut req = make_req();
    req.header = String::new();
    assert!(validate_lengths(&req, &test_pricer()).is_err());
}

#[test]
fn rejects_long_header() {
    let mut req = make_req();
    req.header = "a".repeat(MAX_HEADER_LEN + 1);
    assert!(validate_lengths(&req, &test_pricer()).is_err());
}

#[test]
fn rejects_long_description() {
    let mut req = make_req();
    req.description = "a".repeat(MAX_DESCRIPTION_LEN + 1);
    assert!(validate_lengths(&req, &test_pricer()).is_err());
}

#[test]
fn rejects_unknown_currency() {
    let mut req = make_req();
    req.display_currency = "BTC".to_string();
    assert!(validate_lengths(&req, &test_pricer()).is_err());
}

#[test]
fn rejects_non_canonical_currency() {
    let mut req = make_req();
    req.display_currency = "usd".to_string();
    assert!(validate_lengths(&req, &test_pricer()).is_err());
}

#[test]
fn rejects_non_https_website() {
    let mut req = make_req();
    req.website = Some("http://insecure.example".to_string());
    assert!(validate_lengths(&req, &test_pricer()).is_err());
}

#[test]
fn accepts_empty_optional_fields() {
    let mut req = make_req();
    req.website = None;
    req.twitter = None;
    req.instagram = None;
    assert!(validate_lengths(&req, &test_pricer()).is_ok());
}

#[test]
fn rejects_bad_twitter_handle() {
    let mut req = make_req();
    req.twitter = Some("has space".to_string());
    assert!(validate_lengths(&req, &test_pricer()).is_err());
}

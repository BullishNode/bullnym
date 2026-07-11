use super::*;

const TEST_DESCRIPTOR: &str = "ct(slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023),elwpkh([73c5da0a/84h/1776h/0h]xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*))#y8jljyxl";

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
        Some("0"),
        Some(TEST_DESCRIPTOR),
        None,
        None,
    );
    assert_eq!(fields.len(), 9);
    assert_eq!(fields[0], "Alice's Coffee");
    assert_eq!(fields[2], "USD");
    assert_eq!(fields[6], "1");
    assert_eq!(fields[7], "0");
    assert_eq!(fields[8], TEST_DESCRIPTOR);
}

#[test]
fn save_payload_fields_omit_descriptor() {
    let fields = save_payload_fields(
        "Alice's Coffee",
        "Buy me a coffee!",
        "USD",
        "https://alice.example",
        "alice",
        "alice_ig",
        "1",
        Some("0"),
        None,
        None,
        None,
    );
    assert_eq!(fields.len(), 8);
    assert_eq!(fields[6], "1");
    assert_eq!(fields[7], "0");
}

#[test]
fn save_payload_fields_kind_is_trailing_after_descriptor() {
    // The POS surface sends kind='pos' AFTER ct_descriptor; kind is the last
    // signed field so legacy layouts stay a prefix of the new one.
    let fields = save_payload_fields(
        "Alice's Coffee",
        "Buy me a coffee!",
        "USD",
        "https://alice.example",
        "alice",
        "alice_ig",
        "1",
        Some("0"),
        Some(TEST_DESCRIPTOR),
        Some("pos"),
        None,
    );
    assert_eq!(fields.len(), 10);
    assert_eq!(fields[7], "0");
    assert_eq!(fields[8], TEST_DESCRIPTOR);
    assert_eq!(fields[9], "pos");
}

#[test]
fn save_payload_fields_legacy_omitting_kind_is_prefix() {
    // A legacy client omits kind entirely: the field list is byte-identical to
    // the pre-POS layout, so its old signature still verifies.
    let with_kind = save_payload_fields("h", "d", "USD", "", "", "", "1", None, None, None, None);
    assert_eq!(with_kind.len(), 7);
}

#[test]
fn save_payload_fields_legacy_without_pos_mode() {
    let fields = save_payload_fields(
        "Alice's Coffee",
        "Buy me a coffee!",
        "USD",
        "https://alice.example",
        "alice",
        "alice_ig",
        "1",
        None,
        Some(TEST_DESCRIPTOR),
        None,
        None,
    );
    assert_eq!(fields.len(), 8);
    assert_eq!(fields[6], "1");
    assert_eq!(fields[7], TEST_DESCRIPTOR);
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
        Some("0"),
        Some(TEST_DESCRIPTOR),
        None,
        None,
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
    assert_eq!(msg.iter().filter(|&&b| b == 0).count(), 13);
}

#[test]
fn v2_save_message_legacy_without_pos_mode_byte_exact_contract() {
    let fields = save_payload_fields(
        "Alice's Coffee",
        "Buy me a coffee!",
        "USD",
        "https://alice.example",
        "alice",
        "alice_ig",
        "1",
        None,
        Some(TEST_DESCRIPTOR),
        None,
        None,
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

    assert_eq!(msg, expected, "v2 legacy byte order regression");
    assert_eq!(msg.iter().filter(|&&b| b == 0).count(), 12);
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

fn make_req() -> SaveDonationPageRequest {
    SaveDonationPageRequest {
        nym: "alice".to_string(),
        npub: "00".repeat(32),
        ct_descriptor: Some(TEST_DESCRIPTOR.to_string()),
        header: "Title".to_string(),
        description: "Desc".to_string(),
        display_currency: "USD".to_string(),
        website: Some("https://example.com".to_string()),
        twitter: Some("alice".to_string()),
        instagram: Some("alice.ig".to_string()),
        pos_mode: Some(false),
        enabled: true,
        kind: None,
        alias: None,
        timestamp: 0,
        signature: String::new(),
    }
}

fn test_pricer() -> PricerClient {
    PricerClient::new(Default::default()).unwrap()
}

fn validate_req(req: &SaveDonationPageRequest) -> Result<(), AppError> {
    validate_lengths(req, &test_pricer(), TEST_DESCRIPTOR.len() + 1)
}

#[test]
fn validates_minimal_request() {
    assert!(validate_req(&make_req()).is_ok());
}

#[test]
fn validates_legacy_request_without_page_descriptor() {
    let mut req = make_req();
    req.ct_descriptor = None;
    assert!(validate_req(&req).is_ok());
}

#[test]
fn rejects_empty_header() {
    let mut req = make_req();
    req.header = String::new();
    assert!(validate_req(&req).is_err());
}

#[test]
fn rejects_long_header() {
    let mut req = make_req();
    req.header = "a".repeat(MAX_HEADER_LEN + 1);
    assert!(validate_req(&req).is_err());
}

#[test]
fn rejects_long_description() {
    let mut req = make_req();
    req.description = "a".repeat(MAX_DESCRIPTION_LEN + 1);
    assert!(validate_req(&req).is_err());
}

#[test]
fn rejects_unknown_currency() {
    let mut req = make_req();
    req.display_currency = "BTC".to_string();
    assert!(validate_req(&req).is_err());
}

#[test]
fn rejects_non_canonical_currency() {
    let mut req = make_req();
    req.display_currency = "usd".to_string();
    assert!(validate_req(&req).is_err());
}

#[test]
fn rejects_non_https_website() {
    let mut req = make_req();
    req.website = Some("http://insecure.example".to_string());
    assert!(validate_req(&req).is_err());
}

#[test]
fn accepts_empty_optional_fields() {
    let mut req = make_req();
    req.website = None;
    req.twitter = None;
    req.instagram = None;
    assert!(validate_req(&req).is_ok());
}

#[test]
fn rejects_bad_twitter_handle() {
    let mut req = make_req();
    req.twitter = Some("has space".to_string());
    assert!(validate_req(&req).is_err());
}

// --- Alias slug: signed-layout + validation ---

#[test]
fn save_payload_fields_alias_is_trailing_after_kind() {
    // All four optional trailing fields present: alias is the terminal field,
    // immediately after kind.
    let fields = save_payload_fields(
        "Alice's Coffee",
        "Buy me a coffee!",
        "USD",
        "https://alice.example",
        "alice",
        "alice_ig",
        "1",
        Some("0"),
        Some(TEST_DESCRIPTOR),
        Some("pos"),
        Some("alices-shop"),
    );
    assert_eq!(fields.len(), 11);
    assert_eq!(fields[9], "pos");
    assert_eq!(fields[10], "alices-shop");
}

#[test]
fn save_payload_fields_alias_without_kind_is_prefix_extension() {
    // A client may claim an alias without sending kind. The alias is still
    // appended last; every layout that omits it stays a byte-prefix.
    let with_alias = save_payload_fields(
        "h",
        "d",
        "USD",
        "",
        "",
        "",
        "1",
        None,
        None,
        None,
        Some("shop"),
    );
    assert_eq!(with_alias.len(), 8);
    assert_eq!(with_alias[7], "shop");
    let without = save_payload_fields("h", "d", "USD", "", "", "", "1", None, None, None, None);
    assert_eq!(without.len(), 7);
    assert_eq!(&with_alias[..7], &without[..]);
}

/// Byte-exact contract for a save message carrying an alias (10 trailing
/// fields → 14 NUL separators). Mobile's `buildSavePayloadFields` must append
/// alias in lockstep.
#[test]
fn v2_save_message_with_alias_byte_exact_contract() {
    let fields = save_payload_fields(
        "Alice's Coffee",
        "Buy me a coffee!",
        "USD",
        "https://alice.example",
        "alice",
        "alice_ig",
        "1",
        Some("0"),
        Some(TEST_DESCRIPTOR),
        None,
        Some("alices-shop"),
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

    assert_eq!(msg, expected, "v2 alias byte order regression");
    assert_eq!(msg.iter().filter(|&&b| b == 0).count(), 14);
}

#[test]
fn alias_regex_accepts_valid_slugs() {
    for s in ["a", "alices-shop", "shop2", "a-b-c", &"z".repeat(32)] {
        assert!(ALIAS_REGEX.is_match(s), "should accept {s:?}");
    }
}

#[test]
fn alias_regex_rejects_invalid_slugs() {
    for s in [
        "",              // empty
        "-shop",         // leading hyphen
        "shop-",         // trailing hyphen
        "Shop",          // uppercase
        "my_shop",       // underscore (also keeps `payment_page` invalid)
        "café",          // non-ascii
        "a b",           // space
        &"z".repeat(33), // too long
    ] {
        assert!(!ALIAS_REGEX.is_match(s), "should reject {s:?}");
    }
}

#[test]
fn alias_blocklist_rejects_confusion_and_brand_values() {
    // "0"/"1" are the pos_mode value domain (signed-field confusion guard);
    // "pos" is a kind value; brand names are impersonation risks.
    for s in [
        "0",
        "1",
        "pos",
        "bull",
        "bullbitcoin",
        "bull-bitcoin",
        "bullpay",
    ] {
        assert!(reserved_nyms::is_reserved_alias(s), "should reserve {s:?}");
    }
    // A normal merchant slug is allowed.
    assert!(!reserved_nyms::is_reserved_alias("alices-shop"));
}

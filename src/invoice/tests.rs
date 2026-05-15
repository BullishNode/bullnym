use super::*;

/// Field-order helpers are wire contracts. If you change one, the
/// mobile must change in lockstep. These tests document the byte
/// sequence so any silent change fails the test.
#[test]
fn create_payload_field_order() {
    let f = create_payload_fields(
        "5000",
        "",
        "",
        "coffee",
        "Alice",
        "INV-1",
        "false",
        "true",
        "true",
        "",
        "lq1qq...",
        "abcd",
        "1700000000",
    );
    assert_eq!(
        f,
        [
            "5000",
            "",
            "",
            "coffee",
            "Alice",
            "INV-1",
            "false",
            "true",
            "true",
            "",
            "lq1qq...",
            "abcd",
            "1700000000",
        ],
        "create field order changed — mobile MUST update in lockstep"
    );
}

#[test]
fn cancel_payload_field_order() {
    let f = cancel_payload_fields("00000000-0000-0000-0000-000000000001");
    assert_eq!(
        f,
        ["00000000-0000-0000-0000-000000000001"],
        "cancel field order changed — mobile MUST update in lockstep"
    );
}

#[test]
fn list_payload_field_order() {
    let f = list_payload_fields("1", "50", "unpaid");
    assert_eq!(
        f,
        ["1", "50", "unpaid"],
        "list field order changed — mobile MUST update in lockstep"
    );
}

#[test]
fn action_constants_distinct() {
    assert_ne!(ACTION_CREATE, ACTION_CANCEL);
    assert_ne!(ACTION_CREATE, ACTION_LIST);
    assert_ne!(ACTION_CANCEL, ACTION_LIST);
}

#[test]
fn checkout_outer_expiry_is_seven_days() {
    assert_eq!(CHECKOUT_DEFAULT_EXPIRES_SECS, 7 * 24 * 60 * 60);
}

#[test]
fn npub_log_tag_truncates() {
    assert_eq!(
        npub_log_tag("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        "89abcdef"
    );
    assert_eq!(npub_log_tag("short"), "short");
    assert_eq!(npub_log_tag(""), "");
}

#[test]
fn bolt11_reusable_check_uses_embedded_expiry() {
    // BOLT11 test vector timestamp is 1496314658 with default 3600s
    // expiry. The helper must reuse it before expiry and reject it
    // after expiry, independently of the merchant invoice lifetime.
    let pr = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";

    assert!(bolt11_is_reusable_at(pr, 1_496_314_658 + 3_479));
    assert!(!bolt11_is_reusable_at(pr, 1_496_314_658 + 3_481));
    assert!(!bolt11_is_reusable_at(pr, 1_496_314_658 + 3_601));
    assert!(!bolt11_is_reusable_at("not-a-bolt11", 1_496_314_658));
}

#[test]
fn invoice_public_url_builds_linked_and_unlinked_urls() {
    let id = Uuid::nil();

    assert_eq!(
        invoice_public_url("bullpay.ca", Some("alice"), id),
        "https://bullpay.ca/alice/i/00000000-0000-0000-0000-000000000000"
    );
    assert_eq!(
        invoice_public_url("bullpay.ca", None, id),
        "https://bullpay.ca/invoice/00000000-0000-0000-0000-000000000000"
    );
}

#[test]
fn boltz_invoice_description_uses_url_when_it_fits() {
    let url = "https://bullpay.ca/alice/i/00000000-0000-0000-0000-000000000000";

    let description = boltz_invoice_description_for_url(url);

    assert_eq!(description.description.as_deref(), Some(url));
    assert!(description.description_hash.is_none());
}

#[test]
fn max_bullpay_invoice_url_fits_boltz_description_limit() {
    let url = invoice_public_url(
        "bullpay.ca",
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Uuid::nil(),
    );

    assert_eq!(url.len(), 90);
    assert_eq!(
        boltz_invoice_description_for_url(&url)
            .description
            .as_deref(),
        Some(url.as_str())
    );
}

#[test]
fn boltz_invoice_description_hashes_url_when_too_long() {
    let url = format!(
        "https://really-long-bullpay-domain.example/{}/i/00000000-0000-0000-0000-000000000000",
        "a".repeat(32)
    );

    let description = boltz_invoice_description_for_url(&url);
    let expected_hash = hex::encode(Sha256::digest(url.as_bytes()));

    assert!(description.description.is_none());
    assert_eq!(
        description.description_hash.as_deref(),
        Some(expected_hash.as_str())
    );
}

#[test]
fn append_bip21_message_adds_encoded_invoice_url() {
    let bip21 = "bitcoin:bc1qboltzlockup?amount=0.00010000&label=Send%20to%20L-BTC%20address";
    let url = "https://bullpay.ca/alice/i/00000000-0000-0000-0000-000000000000";

    assert_eq!(
            append_bip21_message(bip21, url),
            "bitcoin:bc1qboltzlockup?amount=0.00010000&label=Send%20to%20L-BTC%20address&message=https%3A%2F%2Fbullpay.ca%2Falice%2Fi%2F00000000-0000-0000-0000-000000000000"
        );
}

#[test]
fn append_bip21_message_replaces_existing_message() {
    let bip21 = "bitcoin:bc1qboltzlockup?amount=0.00010000&message=old";
    let url = "https://bullpay.ca/invoice/00000000-0000-0000-0000-000000000000";

    assert_eq!(
            append_bip21_message(bip21, url),
            "bitcoin:bc1qboltzlockup?amount=0.00010000&message=https%3A%2F%2Fbullpay.ca%2Finvoice%2F00000000-0000-0000-0000-000000000000"
        );
}

#[test]
fn partially_paid_template_remains_payable_for_remaining_amount() {
    let tpl = InvoicePaymentTpl {
        nym: "alice",
        is_unlinked: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status: "partially_paid",
        settlement_status: "none",
        amount_sat: 10_000,
        remaining_amount_sat: 2_500,
        fiat_display: None,
        public_description: None,
        recipient_name: None,
        invoice_number: None,
        accept_btc: true,
        accept_ln: true,
        accept_liquid: true,
        bitcoin_chain_address: None,
        bitcoin_address_js: js_string_literal(Some("bc1qexample")).unwrap(),
        bitcoin_chain_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_bip21_js: js_string_literal(None).unwrap(),
        liquid_address_js: js_string_literal(Some("lq1qqexample")).unwrap(),
        liquid_btc_asset_id: LIQUID_BTC_ASSET_ID,
    };

    let html = tpl.render().expect("template renders");
    assert!(html.contains("Partially paid"));
    assert!(html.contains("2500 sat remaining"));
    assert!(html.contains("id=\"rail-lightning\""));
    assert!(html.contains("let currentAmountSat = 2500;"));
}

#[test]
fn template_refreshes_lightning_explicitly_when_status_has_no_reusable_pr() {
    let tpl = InvoicePaymentTpl {
        nym: "alice",
        is_unlinked: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status: "unpaid",
        settlement_status: "none",
        amount_sat: 10_000,
        remaining_amount_sat: 10_000,
        fiat_display: None,
        public_description: None,
        recipient_name: None,
        invoice_number: None,
        accept_btc: false,
        accept_ln: true,
        accept_liquid: true,
        bitcoin_chain_address: None,
        bitcoin_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_bip21_js: js_string_literal(None).unwrap(),
        liquid_address_js: js_string_literal(Some("lq1qqexample")).unwrap(),
        liquid_btc_asset_id: LIQUID_BTC_ASSET_ID,
    };

    let html = tpl.render().expect("template renders");
    assert!(html.contains("Refreshing Lightning offer"));
    assert!(html.contains("fetchLightning();"));
    assert!(html.contains("method: 'POST'"));
    assert!(html.contains("/lightning"));
}

#[test]
fn template_exposes_boltz_chain_bitcoin_without_direct_btc_address() {
    let tpl = InvoicePaymentTpl {
        nym: "alice",
        is_unlinked: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status: "unpaid",
        settlement_status: "none",
        amount_sat: 10_000,
        remaining_amount_sat: 10_000,
        fiat_display: None,
        public_description: None,
        recipient_name: None,
        invoice_number: None,
        accept_btc: false,
        accept_ln: true,
        accept_liquid: true,
        bitcoin_chain_address: Some("bc1qboltzlockup"),
        bitcoin_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_address_js: js_string_literal(Some("bc1qboltzlockup")).unwrap(),
        bitcoin_chain_bip21_js: js_string_literal(Some(
            "bitcoin:bc1qboltzlockup?amount=0.00010000&label=Send%20to%20L-BTC%20address",
        ))
        .unwrap(),
        liquid_address_js: js_string_literal(Some("lq1qqexample")).unwrap(),
        liquid_btc_asset_id: LIQUID_BTC_ASSET_ID,
    };

    let html = tpl.render().expect("template renders");
    assert!(html.contains("id=\"rail-btc\""));
    assert!(html.contains("INITIAL_BITCOIN_CHAIN_ADDRESS = \"bc1qboltzlockup\""));
    assert!(html.contains("INITIAL_BITCOIN_CHAIN_BIP21 = \"bitcoin:bc1qboltzlockup?amount=0.00010000\\u0026label=Send%20to%20L-BTC%20address\""));
    assert!(html.contains("return bip21 || btcUri(address, amountSat);"));
    assert!(html.contains("INITIAL_BITCOIN_CHAIN_ADDRESS || INITIAL_BITCOIN_ADDRESS"));
}

#[test]
fn template_liquid_uri_pins_lbtc_asset() {
    let tpl = InvoicePaymentTpl {
        nym: "alice",
        is_unlinked: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status: "unpaid",
        settlement_status: "none",
        amount_sat: 10_000,
        remaining_amount_sat: 10_000,
        fiat_display: None,
        public_description: None,
        recipient_name: None,
        invoice_number: None,
        accept_btc: false,
        accept_ln: false,
        accept_liquid: true,
        bitcoin_chain_address: None,
        bitcoin_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_bip21_js: js_string_literal(None).unwrap(),
        liquid_address_js: js_string_literal(Some("lq1qqexample")).unwrap(),
        liquid_btc_asset_id: LIQUID_BTC_ASSET_ID,
    };

    let html = tpl.render().expect("template renders");

    assert!(html.contains(
            "liquidnetwork:${address}?amount=${btc}&assetid=6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d"
        ));
}

#[test]
fn api_tolerance_uses_configured_values() {
    let mut inv = invoice_fixture();
    inv.accept_btc = false;
    inv.accept_liquid = true;
    inv.accept_ln = false;
    let tolerances = db::InvoiceAccountingTolerances {
        btc_sat: 900,
        liquid_sat: 42,
        lightning_sat: 3,
    };

    assert_eq!(payment_tolerance_sat(&inv, tolerances), 42);
}

fn invoice_fixture() -> db::Invoice {
    db::Invoice {
        id: Uuid::nil(),
        nym_owner: Some("alice".to_string()),
        npub_owner: "npub".to_string(),
        origin: "wallet".to_string(),
        fiat_amount_minor: None,
        fiat_currency: None,
        amount_sat: 10_000,
        rate_minor_per_btc: None,
        memo: None,
        recipient_label: None,
        bitcoin_address: None,
        accept_btc: false,
        accept_ln: true,
        accept_liquid: false,
        public_description: None,
        invoice_number: None,
        liquid_address: None,
        liquid_address_index: None,
        status: "unpaid".to_string(),
        paid_via: None,
        paid_amount_sat: None,
        pricing_mode: "sat_fixed".to_string(),
        settlement_status: "none".to_string(),
        liquid_blinding_key_hex: None,
        created_at_unix: 0,
        expires_at_unix: 0,
        rate_locked_at_unix: 0,
        rate_locks_until_unix: 0,
        paid_at_unix: None,
        cancelled_at_unix: None,
    }
}

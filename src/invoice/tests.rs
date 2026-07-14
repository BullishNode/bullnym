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
fn recovery_list_payload_field_order() {
    let f = recovery_list_payload_fields();
    assert_eq!(
        f.len(),
        0,
        "invoice-recovery-list is a ZERO-field signed payload — adding a field \
         is a wire-breaking change the mobile signer MUST match in lockstep"
    );
}

#[test]
fn action_constants_distinct() {
    assert_ne!(ACTION_CREATE, ACTION_CANCEL);
    assert_ne!(ACTION_CREATE, ACTION_LIST);
    assert_ne!(ACTION_CANCEL, ACTION_LIST);
    assert_ne!(ACTION_RECOVERY_LIST, ACTION_LIST);
    assert_ne!(ACTION_RECOVERY_LIST, ACTION_CREATE);
    assert_ne!(ACTION_RECOVERY_LIST, ACTION_CANCEL);
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
fn invoice_html_response_does_not_mark_pwa_shell() {
    let resp = html_response("<!doctype html><title>invoice</title>".to_string());

    assert!(!resp.headers().contains_key("x-bullnym-pwa-shell"));
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
        invoice_public_url("bullpay.ca", Some("alice"), None, id),
        "https://bullpay.ca/alice/i/00000000-0000-0000-0000-000000000000"
    );
    assert_eq!(
        invoice_public_url("bullpay.ca", None, None, id),
        "https://bullpay.ca/invoice/00000000-0000-0000-0000-000000000000"
    );
    // An alias slug wins over the nym, so the public URL is nym-free.
    assert_eq!(
        invoice_public_url("bullpay.ca", Some("alice"), Some("alices-shop"), id),
        "https://bullpay.ca/a/alices-shop/i/00000000-0000-0000-0000-000000000000"
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
        None,
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
fn chain_bip21_is_built_locally_with_exact_amount_and_encoded_invoice_url() {
    let address = "bc1qboltzlockup";
    let url = "https://bullpay.ca/alice/i/00000000-0000-0000-0000-000000000000";

    assert_eq!(
            build_bitcoin_chain_bip21(address, 10_000, url),
            "bitcoin:bc1qboltzlockup?amount=0.00010000&label=Send%20to%20L-BTC%20address&message=https%3A%2F%2Fbullpay.ca%2Falice%2Fi%2F00000000-0000-0000-0000-000000000000"
        );
}

#[test]
fn chain_bip21_formats_whole_bitcoin_without_rounding() {
    let address = "bc1qboltzlockup";
    let url = "https://bullpay.ca/invoice/00000000-0000-0000-0000-000000000000";

    assert_eq!(
            build_bitcoin_chain_bip21(address, 100_000_001, url),
            "bitcoin:bc1qboltzlockup?amount=1.00000001&label=Send%20to%20L-BTC%20address&message=https%3A%2F%2Fbullpay.ca%2Finvoice%2F00000000-0000-0000-0000-000000000000"
        );
}

#[test]
fn public_chain_amount_requires_a_positive_non_decreasing_gross_up() {
    assert_eq!(
        validated_payer_chain_amount_sat(10_431, 10_000),
        Some(10_431)
    );
    assert_eq!(
        validated_payer_chain_amount_sat(10_000, 10_000),
        Some(10_000)
    );
    for (user, server) in [(9_999, 10_000), (0, 0), (1, 0), (-1, 1)] {
        assert_eq!(
            validated_payer_chain_amount_sat(user, server),
            None,
            "invalid public amount pair {user}/{server} was exposed"
        );
    }
}

#[test]
fn permit_release_failure_keeps_the_persisted_chain_offer_visible() {
    let retained = retain_persisted_offer_after_permit_release(
        BitcoinChainOffer {
            lockup_address: "bc1qpersistedoffer".to_owned(),
            lockup_bip21: Some("bitcoin:bc1qpersistedoffer?amount=0.00001000".to_owned()),
            payer_amount_sat: 1_000,
        },
        Err(ChainSwapCreationPermitError::ReleaseFailed),
    );

    assert_eq!(retained.lockup_address, "bc1qpersistedoffer");
    assert_eq!(
        retained.lockup_bip21.as_deref(),
        Some("bitcoin:bc1qpersistedoffer?amount=0.00001000")
    );
}

#[test]
fn partially_paid_template_remains_payable_for_remaining_amount() {
    let mut tpl = InvoicePaymentTpl {
        nym: "alice",
        is_unlinked: false,
        hide_owner: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status: "partially_paid",
        presentation_status: "partial",
        presentation_known: true,
        settlement_status: "none",
        rails_payable: true,
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
        bitcoin_chain_amount_sat: None,
        lightning_pr_js: js_string_literal(None).unwrap(),
        lightning_amount_sat: None,
        liquid_amount_sat: Some(2_500),
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

    tpl.settlement_status = "settled";
    let settled_html = tpl.render().expect("settled partial template renders");
    assert!(settled_html.contains("id=\"rail-lightning\""));
    assert!(settled_html.contains("initialStatus === 'underpaid'"));
    assert!(settled_html
        .contains("return data.presentation_status !== 'partial' || data.status === 'underpaid';"));
    assert!(settled_html.contains("setRail(currentRail)"));

    tpl.status = "underpaid";
    tpl.rails_payable = false;
    let underpaid_html = tpl
        .render()
        .expect("settled terminal partial template renders");
    assert!(underpaid_html.contains(">Underpaid</div>"));
    assert!(!underpaid_html.contains("id=\"rail-lightning\""));
    assert!(underpaid_html.contains("initialStatus === 'underpaid'"));
}

#[test]
fn template_refreshes_lightning_explicitly_when_status_has_no_reusable_pr() {
    let tpl = InvoicePaymentTpl {
        nym: "alice",
        is_unlinked: false,
        hide_owner: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status: "unpaid",
        presentation_status: "unpaid",
        presentation_known: true,
        settlement_status: "none",
        rails_payable: true,
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
        bitcoin_chain_amount_sat: None,
        lightning_pr_js: js_string_literal(None).unwrap(),
        lightning_amount_sat: None,
        liquid_amount_sat: Some(10_000),
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
        hide_owner: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status: "unpaid",
        presentation_status: "unpaid",
        presentation_known: true,
        settlement_status: "none",
        rails_payable: true,
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
        bitcoin_chain_amount_sat: Some(10_100),
        lightning_pr_js: js_string_literal(None).unwrap(),
        lightning_amount_sat: None,
        liquid_amount_sat: Some(10_000),
        bitcoin_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_address_js: js_string_literal(Some("bc1qboltzlockup")).unwrap(),
        bitcoin_chain_bip21_js: js_string_literal(Some(
            "bitcoin:bc1qboltzlockup?amount=0.00010100&label=Send%20to%20L-BTC%20address",
        ))
        .unwrap(),
        liquid_address_js: js_string_literal(Some("lq1qqexample")).unwrap(),
        liquid_btc_asset_id: LIQUID_BTC_ASSET_ID,
    };

    let html = tpl.render().expect("template renders");
    assert!(html.contains("id=\"rail-btc\""));
    assert!(html.contains("INITIAL_BITCOIN_CHAIN_ADDRESS = \"bc1qboltzlockup\""));
    assert!(html.contains("INITIAL_BITCOIN_CHAIN_BIP21 = \"bitcoin:bc1qboltzlockup?amount=0.00010100\\u0026label=Send%20to%20L-BTC%20address\""));
    assert!(html.contains("INITIAL_BITCOIN_CHAIN_AMOUNT_SAT = 10100"));
    assert!(html.contains("return bip21 || btcUri(address, amountSat);"));
    assert!(html.contains("currentBitcoinChainAddress = INITIAL_BITCOIN_CHAIN_ADDRESS || null"));
    assert!(html.contains("return currentBitcoinChainAddress || currentBitcoinDirectAddress;"));
    assert!(html.contains("? currentBitcoinChainAmountSat\n                    : currentAmountSat"));
    assert!(
        html.contains("Includes ${new Intl.NumberFormat().format(swapCostSat)} sats in swap costs")
    );
    let lightning = html.find("id=\"rail-lightning\"").unwrap();
    let liquid = html.find("id=\"rail-liquid\"").unwrap();
    let bitcoin = html.find("id=\"rail-btc\"").unwrap();
    assert!(lightning < liquid && liquid < bitcoin);
}

#[test]
fn template_liquid_uri_pins_lbtc_asset() {
    let tpl = InvoicePaymentTpl {
        nym: "alice",
        is_unlinked: false,
        hide_owner: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status: "unpaid",
        presentation_status: "unpaid",
        presentation_known: true,
        settlement_status: "none",
        rails_payable: true,
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
        bitcoin_chain_amount_sat: None,
        lightning_pr_js: js_string_literal(None).unwrap(),
        lightning_amount_sat: None,
        liquid_amount_sat: Some(10_000),
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
fn invoice_template_escapes_user_text_and_js_literals() {
    let attack = r#"</script><img src=x onerror=alert(1)>&"#;
    let tpl = InvoicePaymentTpl {
        nym: "alice",
        is_unlinked: false,
        hide_owner: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status: "unpaid",
        presentation_status: "unpaid",
        presentation_known: true,
        settlement_status: "none",
        rails_payable: true,
        amount_sat: 10_000,
        remaining_amount_sat: 10_000,
        fiat_display: None,
        public_description: Some(attack),
        recipient_name: Some(attack),
        invoice_number: Some(attack),
        accept_btc: true,
        accept_ln: false,
        accept_liquid: false,
        bitcoin_chain_address: None,
        bitcoin_chain_amount_sat: None,
        lightning_pr_js: js_string_literal(None).unwrap(),
        lightning_amount_sat: None,
        liquid_amount_sat: None,
        bitcoin_address_js: js_string_literal(Some(attack)).unwrap(),
        bitcoin_chain_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_bip21_js: js_string_literal(None).unwrap(),
        liquid_address_js: js_string_literal(None).unwrap(),
        liquid_btc_asset_id: LIQUID_BTC_ASSET_ID,
    };

    let html = tpl.render().expect("template renders");
    assert!(!html.contains("</script><img"));
    assert!(!html.contains("<img src=x"));
    assert!(html.contains("&lt;/script&gt;"));
    assert!(html.contains("\\u003c/script\\u003e"));
    assert!(html.contains("\\u0026"));
}

#[test]
fn hide_owner_suppresses_nym_in_rendered_header() {
    let base = InvoicePaymentTpl {
        nym: "secretnym",
        is_unlinked: false,
        hide_owner: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status: "unpaid",
        presentation_status: "unpaid",
        presentation_known: true,
        settlement_status: "none",
        rails_payable: true,
        amount_sat: 10_000,
        remaining_amount_sat: 10_000,
        fiat_display: None,
        public_description: None,
        recipient_name: None,
        invoice_number: None,
        accept_btc: false,
        accept_ln: true,
        accept_liquid: false,
        bitcoin_chain_address: None,
        bitcoin_chain_amount_sat: None,
        lightning_pr_js: js_string_literal(None).unwrap(),
        lightning_amount_sat: None,
        liquid_amount_sat: None,
        bitcoin_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_bip21_js: js_string_literal(None).unwrap(),
        liquid_address_js: js_string_literal(None).unwrap(),
        liquid_btc_asset_id: LIQUID_BTC_ASSET_ID,
    };

    // Nym path: the header names the merchant.
    let shown = base.render().expect("template renders");
    assert!(shown.contains("secretnym"));
    assert!(shown.contains("Pay <span"));

    // Alias path (hide_owner): generic header, nym scrubbed everywhere.
    let hidden = InvoicePaymentTpl {
        nym: "",
        hide_owner: true,
        ..base
    }
    .render()
    .expect("template renders");
    assert!(hidden.contains("Pay invoice"));
    assert!(!hidden.contains("secretnym"));
}

#[test]
fn presentation_projection_controls_new_payment_instructions() {
    let mut inv = invoice_fixture();
    assert!(invoice_payment_rails_are_payable(&inv));

    inv.presentation_status = None;
    assert!(!invoice_payment_rails_are_payable(&inv));

    inv.status = "in_progress".to_string();
    inv.presentation_status = Some("partial".to_string());
    inv.settlement_status = "pending".to_string();
    assert!(invoice_payment_rails_are_payable(&inv));

    inv.status = "partially_paid".to_string();
    inv.presentation_status = Some("payment_received".to_string());
    assert!(!invoice_payment_rails_are_payable(&inv));

    inv.presentation_status = Some("partial".to_string());
    for incident in ["resolution_pending", "claim_stuck", "refunded", "failed"] {
        inv.settlement_status = incident.to_string();
        assert!(
            !invoice_payment_rails_are_payable(&inv),
            "{incident} must suppress payment instructions"
        );
    }
}

#[test]
fn public_direct_addresses_are_withheld_when_invoice_is_closed() {
    let mut inv = invoice_fixture();
    inv.bitcoin_address = Some("bc1qexample".to_string());
    inv.liquid_address = Some("lq1qqexample".to_string());
    inv.accept_btc = true;
    inv.accept_liquid = true;

    let payable = public_direct_payment_addresses(&inv);
    assert_eq!(payable.bitcoin, Some("bc1qexample"));
    assert_eq!(payable.liquid, Some("lq1qqexample"));

    inv.status = "cancelled".to_string();
    inv.presentation_status = Some("payment_received".to_string());
    inv.settlement_status = "settled".to_string();
    let closed = public_direct_payment_addresses(&inv);
    assert_eq!(closed.bitcoin, None);
    assert_eq!(closed.liquid, None);

    assert_eq!(inv.bitcoin_address.as_deref(), Some("bc1qexample"));
    assert_eq!(inv.liquid_address.as_deref(), Some("lq1qqexample"));
}

#[test]
fn public_direct_addresses_require_explicit_direct_rail_acceptance() {
    let mut inv = invoice_fixture();
    inv.liquid_address = Some("lq1internalclaimdestination".to_string());
    assert!(inv.accept_ln);
    assert!(!inv.accept_liquid);
    assert!(invoice_payment_rails_are_payable(&inv));

    let public = public_direct_payment_addresses(&inv);
    assert_eq!(public.bitcoin, None);
    assert_eq!(public.liquid, None);
    assert_eq!(
        inv.liquid_address.as_deref(),
        Some("lq1internalclaimdestination")
    );
}

#[test]
fn template_presentation_precedes_accounting_terminality() {
    let html = payment_template_fixture("paid", "payment_received", "pending", false)
        .render()
        .expect("template renders");
    assert!(html.contains(">Payment received</div>"));
    assert!(html.contains(">Settlement pending</div>"));

    let partial = payment_template_fixture("in_progress", "partial", "pending", true)
        .render()
        .expect("template renders");
    assert!(partial.contains("Partially paid — remaining amount due"));
    assert!(partial.contains("id=\"rail-lightning\""));
    assert!(partial.contains("id=\"settlement-support\">Settlement pending"));
}

#[test]
fn template_renders_resolution_and_existing_swap_incidents() {
    let resolution = payment_template_fixture(
        "in_progress",
        "payment_received",
        "resolution_pending",
        false,
    )
    .render()
    .expect("template renders");
    assert!(resolution.contains(">Payment issue</div>"));
    assert!(resolution.contains(">Settlement problem — being checked</div>"));

    for incident in ["refunded", "failed"] {
        let html = payment_template_fixture("in_progress", "payment_received", incident, false)
            .render()
            .expect("template renders");
        assert!(html.contains(">Settlement failed</div>"), "{incident}");
    }
    let stuck = payment_template_fixture("in_progress", "payment_received", "claim_stuck", false)
        .render()
        .expect("template renders");
    assert!(stuck.contains(">Payment needs review</div>"));
}

#[test]
fn template_status_poll_replaces_nullable_bitcoin_offer_state() {
    let html = payment_template_fixture("in_progress", "partial", "pending", true)
        .render()
        .expect("template renders");

    assert!(html.contains("currentBitcoinDirectAddress = data.bitcoin_address || null;"));
    assert!(html.contains("Number.isSafeInteger(data.bitcoin_chain_amount_sat)"));
    assert!(html.contains("nextBitcoinChainAddress && nextBitcoinChainAmountSat !== null"));
    assert!(html.contains("currentBitcoinChainAmountSat = currentBitcoinChainAddress"));
    assert!(html.contains("currentBitcoinChainBip21 = currentBitcoinChainAddress"));
    assert!(html
        .contains("const bip21 = currentBitcoinChainAddress ? currentBitcoinChainBip21 : null;"));
    assert!(!html.contains("const nextBitcoinAddress ="));
    let adopt = html
        .find("adoptStatusPayloads(data);")
        .expect("status payloads are adopted");
    let pending_branch = html
        .find("if (data.settlement_status === 'pending')")
        .expect("pending branch exists");
    assert!(
        adopt < pending_branch,
        "nullable offers must be replaced before partial+pending returns"
    );
    assert!(html.contains(
        "if (data.presentation_status === 'partial') {\n                            if (statusAllowsPaymentRails(data))"
    ));
    assert!(html.contains("renderUnknownState();"));
}

#[test]
fn template_never_maps_unknown_presentation_to_paid_or_unpaid() {
    let mut template = payment_template_fixture("paid", "", "none", false);
    template.presentation_known = false;
    let html = template.render().expect("template renders");
    assert!(html.contains(">Checking payment status</div>"));
    assert!(html.contains(">Payment status is being checked</div>"));
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
        payment_grace_secs: 3600,
    };

    assert_eq!(payment_tolerance_sat(&inv, tolerances), 42);
}

fn payment_template_fixture(
    status: &'static str,
    presentation_status: &'static str,
    settlement_status: &'static str,
    rails_payable: bool,
) -> InvoicePaymentTpl<'static> {
    InvoicePaymentTpl {
        nym: "alice",
        is_unlinked: false,
        hide_owner: false,
        invoice_id: Uuid::nil().to_string(),
        domain: "bullpay.ca",
        status,
        presentation_status,
        presentation_known: true,
        settlement_status,
        rails_payable,
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
        bitcoin_chain_amount_sat: None,
        lightning_pr_js: js_string_literal(None).unwrap(),
        lightning_amount_sat: None,
        liquid_amount_sat: Some(2_500),
        bitcoin_address_js: js_string_literal(Some("bc1qexample")).unwrap(),
        bitcoin_chain_address_js: js_string_literal(None).unwrap(),
        bitcoin_chain_bip21_js: js_string_literal(None).unwrap(),
        liquid_address_js: js_string_literal(Some("lq1qqexample")).unwrap(),
        liquid_btc_asset_id: LIQUID_BTC_ASSET_ID,
    }
}

#[test]
fn fiat_display_uses_zero_decimal_crc() {
    assert_eq!(format_fiat_major(12_345, "CRC"), "12345 CRC");
    assert_eq!(format_fiat_major(12_345, "COP"), "12345 COP");
    assert_eq!(format_fiat_major(12_345, "USD"), "123.45 USD");
}

fn invoice_fixture() -> db::Invoice {
    db::Invoice {
        id: Uuid::nil(),
        nym_owner: Some("alice".to_string()),
        public_slug: None,
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
        presentation_status: Some("unpaid".to_string()),
        direct_settlement_status: "none".to_string(),
        swap_settlement_status: "none".to_string(),
        direct_payment_projection_version: 0,
        liquid_blinding_key_hex: None,
        created_at_unix: 0,
        expires_at_unix: 0,
        rate_locked_at_unix: 0,
        rate_locks_until_unix: 0,
        paid_at_unix: None,
        cancelled_at_unix: None,
    }
}

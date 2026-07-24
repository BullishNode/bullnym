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
        "00000000-0000-0000-0000-000000000001",
        "AQAA",
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
            "00000000-0000-0000-0000-000000000001",
            "AQAA",
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
fn merchant_bull_bitcoin_projection_is_minimal_and_never_fabricates_fiat() {
    let invoice_id = Uuid::new_v4();
    let order_id = Uuid::new_v4();
    let rows = vec![
        db::InvoiceBullBitcoinSettlementProjection {
            invoice_id,
            purpose: "fiat_only".into(),
            bull_bitcoin_order_id: Some(order_id),
            fiat_currency: "CAD".into(),
            settlement_status: "pending".into(),
            credited_fiat_minor: None,
            quoted_fiat_minor: Some(5_000),
            fiat_percentage: Some(100),
            funding_route: Some("bull_bitcoin".into()),
            fallback_category: None,
            merchant_bitcoin_sat: None,
            merchant_bitcoin_settled: false,
        },
        db::InvoiceBullBitcoinSettlementProjection {
            invoice_id,
            purpose: "fiat_only".into(),
            bull_bitcoin_order_id: None,
            fiat_currency: "CAD".into(),
            settlement_status: "none".into(),
            credited_fiat_minor: None,
            quoted_fiat_minor: None,
            fiat_percentage: None,
            funding_route: Some("bitcoin_fallback".into()),
            fallback_category: Some("ambiguous_create".into()),
            merchant_bitcoin_sat: None,
            merchant_bitcoin_settled: false,
        },
    ];
    let mut projections = merchant_invoice_settlement_projections(rows);
    let projection = projections.remove(&invoice_id).unwrap();
    assert_eq!(
        projection.fiat_only,
        vec![MerchantFiatSettlementEntry {
            amount_minor: None,
            // The locked quote is exposed while the leg is still pending.
            quoted_amount_minor: Some(5_000),
            currency: "CAD".into(),
            order_id,
            status: "pending".into(),
        }]
    );
    // The captured split is surfaced from the settlement row.
    assert_eq!(projection.fiat_percentage, Some(100));
    assert_eq!(projection.fallback_reasons, vec!["conversion_unavailable"]);
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
fn wallet_and_checkout_outer_expiry_are_thirty_days() {
    let thirty_days = 30 * 24 * 60 * 60;
    assert_eq!(INVOICE_LIFETIME_SECS, thirty_days);
    assert_eq!(MAX_WALLET_EXPIRES_SECS, thirty_days);
    assert_eq!(CHECKOUT_DEFAULT_EXPIRES_SECS, thirty_days);
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
fn invoice_html_response_is_private_and_not_offline_cacheable() {
    let resp = html_response("<!doctype html><title>invoice</title>".to_string());

    assert!(!resp.headers().contains_key("x-bullnym-pwa-shell"));
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "private, no-store");
    assert_eq!(resp.headers()[header::REFERRER_POLICY], "no-referrer");
    assert!(resp.headers().contains_key(header::CONTENT_SECURITY_POLICY));
}

#[test]
fn invoice_pwa_shell_injection_is_exact_and_private() {
    let id = Uuid::new_v4();
    let config = InvoicePwaConfig {
        invoice_id: id,
        private_presentation: true,
    };
    let shell = "<html><!-- BULLNYM_INVOICE_CONFIG --><main></main></html>";
    let html = inject_invoice_pwa_shell(shell, &config).expect("single marker is valid");

    assert!(!html.contains("BULLNYM_INVOICE_CONFIG"));
    assert!(html.contains("id=\"bullnym-invoice-config\""));
    assert!(html.contains(&id.to_string()));
    assert!(html.contains("\"private_presentation\":true"));
    assert!(!html.contains("merchant_nym"));

    assert!(inject_invoice_pwa_shell("<html></html>", &config).is_none());
    assert!(inject_invoice_pwa_shell(
        "<!-- BULLNYM_INVOICE_CONFIG --><!-- BULLNYM_INVOICE_CONFIG -->",
        &config,
    )
    .is_none());
}

#[test]
fn missing_invoice_pwa_is_a_fixed_non_cacheable_503() {
    let resp = invoice_pwa_unavailable_response();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "private, no-store");
    assert!(!resp.headers().contains_key("x-bullnym-pwa-shell"));
}

#[test]
fn bolt11_reusable_check_uses_embedded_expiry() {
    // BOLT11 test vector timestamp is 1496314658 with default 3600s
    // expiry. The helper must reuse it before expiry and reject it
    // after expiry, independently of the merchant invoice lifetime.
    let pr = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";

    assert!(bolt11_is_fresh_at(pr, 1_496_314_658 + 3_479));
    assert!(!bolt11_is_fresh_at(pr, 1_496_314_658 + 3_481));
    assert!(!bolt11_is_fresh_at(pr, 1_496_314_658 + 3_601));
    assert!(!bolt11_is_fresh_at("not-a-bolt11", 1_496_314_658));

    // Pre-privacy invoices used a URL (or its hash) as their description.
    // Even while fresh, those offers must be replaced before being exposed.
    assert!(!bolt11_is_reusable_at(pr, 1_496_314_658 + 3_479));
}

#[test]
fn boltz_invoice_description_is_generic_and_contains_no_invoice_identifier() {
    assert_eq!(BOLTZ_INVOICE_DESCRIPTION, "Bullnym payment");
    assert!(!BOLTZ_INVOICE_DESCRIPTION.contains("http"));
}

#[test]
fn chain_bip21_is_built_locally_without_an_invoice_url_or_message() {
    let address = "bc1qboltzlockup";

    assert_eq!(
        build_bitcoin_chain_bip21(address, 10_000),
        "bitcoin:bc1qboltzlockup?amount=0.00010000&label=Send%20to%20L-BTC%20address"
    );
}

#[test]
fn public_chain_bip21_rebuild_ignores_legacy_persisted_messages() {
    let rebuilt = public_bitcoin_chain_bip21("bc1qlegacypersistedoffer", 10_000).unwrap();

    assert_eq!(
        rebuilt,
        "bitcoin:bc1qlegacypersistedoffer?amount=0.00010000&label=Send%20to%20L-BTC%20address"
    );
    assert!(!rebuilt.contains("message="));
    assert!(!rebuilt.contains("http"));
}

#[test]
fn chain_bip21_formats_whole_bitcoin_without_rounding() {
    let address = "bc1qboltzlockup";

    assert_eq!(
        build_bitcoin_chain_bip21(address, 100_000_001),
        "bitcoin:bc1qboltzlockup?amount=1.00000001&label=Send%20to%20L-BTC%20address"
    );
}

#[test]
fn direct_bitcoin_bip21_keeps_the_exact_merchant_output() {
    assert_eq!(
        build_direct_bitcoin_bip21("bc1qstable", 10_001),
        "bitcoin:bc1qstable?amount=0.00010001"
    );
    assert_eq!(
        build_direct_bitcoin_bip21("bc1qstable", 100_000_001),
        "bitcoin:bc1qstable?amount=1.00000001"
    );
}

#[test]
fn fiat_wallet_bitcoin_is_direct_while_checkout_bitcoin_remains_provider_backed() {
    let mut wallet = invoice_fixture();
    wallet.pricing_mode = "fiat_fixed".to_string();
    wallet.fiat_amount_minor = Some(1_000);
    wallet.fiat_currency = Some("USD".to_string());
    wallet.amount_sat = 0;
    wallet.accept_ln = false;
    wallet.accept_btc = true;
    wallet.bitcoin_address = Some("bc1qstable".to_string());
    assert_eq!(
        payer_quote_rail_availability(&wallet, None).map(|rails| rails.bitcoin),
        Some(true)
    );

    let mut checkout = invoice_fixture();
    checkout.pricing_mode = "fiat_fixed".to_string();
    checkout.fiat_amount_minor = Some(1_000);
    checkout.fiat_currency = Some("USD".to_string());
    checkout.amount_sat = 0;
    checkout.accept_ln = false;
    checkout.origin = "checkout".to_string();
    checkout.accept_btc = false;
    checkout.bitcoin_address = None;
    checkout.liquid_address = Some("lq1merchant".to_string());
    assert_eq!(
        payer_quote_rail_availability(&checkout, None).map(|rails| rails.bitcoin),
        Some(true)
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

// Legacy standalone invoice-template rendering tests were removed with the template.

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

// Payment-state rendering is covered by the shared PWA component tests.

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

    inv.accept_btc = true;
    inv.accept_liquid = true;
    inv.accept_ln = true;
    assert_eq!(
        payment_tolerance_sat(&inv, tolerances),
        3,
        "the API must advertise the strictest accepted-rail tolerance"
    );
}

#[test]
fn anonymous_checkout_create_accepts_only_the_current_wire_shapes() {
    let sat: CreateAnonymousRequest = serde_json::from_value(serde_json::json!({
        "amount_sat": 1_000
    }))
    .unwrap();
    assert_eq!(sat.amount_sat, Some(1_000));
    assert!(sat.fiat_amount_minor.is_none());
    assert!(sat.fiat_currency.is_none());
    assert!(sat.note.is_none());

    let fiat: CreateAnonymousRequest = serde_json::from_value(serde_json::json!({
        "fiat_amount_minor": 1_000,
        "fiat_currency": "USD",
        "note": "private checkout note"
    }))
    .unwrap();
    assert!(fiat.amount_sat.is_none());
    assert_eq!(fiat.fiat_amount_minor, Some(1_000));
    assert_eq!(fiat.fiat_currency.as_deref(), Some("USD"));
    assert_eq!(fiat.note.as_deref(), Some("private checkout note"));

    for unknown in [
        "recipient_label",
        "recipient_name",
        "public_description",
        "invoice_number",
        "unexpected",
    ] {
        let mut payload = serde_json::json!({ "amount_sat": 1_000 });
        payload
            .as_object_mut()
            .unwrap()
            .insert(unknown.to_string(), serde_json::json!("forbidden"));
        let error = serde_json::from_value::<CreateAnonymousRequest>(payload).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("unknown field `{unknown}`")),
            "unexpected error for {unknown}: {error}"
        );
    }
}

fn presentation_envelope_fixture() -> String {
    let mut envelope = vec![0_u8; PRIVATE_INVOICE_PRESENTATION_ENVELOPE_BYTES];
    envelope[0] = PRIVATE_INVOICE_PRESENTATION_VERSION;
    URL_SAFE_NO_PAD.encode(envelope)
}

#[test]
fn signed_invoice_create_requires_only_the_encrypted_presentation_contract() {
    let canonical = serde_json::json!({
        "npub": "11".repeat(32),
        "amount_sat": 1_000,
        "client_request_id": "00000000-0000-0000-0000-000000000001",
        "presentation_envelope": presentation_envelope_fixture(),
        "accept_ln": true,
        "liquid_address": "lq1qqexample",
        "timestamp": 1,
        "signature": "22".repeat(64)
    });
    let parsed: CreateSignedRequest = serde_json::from_value(canonical).unwrap();
    assert_eq!(
        parsed.client_request_id,
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    );
    assert_eq!(
        decode_private_invoice_presentation(&parsed.presentation_envelope)
            .unwrap()
            .len(),
        PRIVATE_INVOICE_PRESENTATION_ENVELOPE_BYTES
    );

    for plaintext_field in [
        "recipient_label",
        "recipient_name",
        "public_description",
        "invoice_number",
        "payer_name",
        "payee_name",
        "payment_deadline",
    ] {
        let mut legacy = serde_json::json!({
            "npub": "11".repeat(32),
            "amount_sat": 1_000,
            "client_request_id": "00000000-0000-0000-0000-000000000001",
            "presentation_envelope": presentation_envelope_fixture(),
            "timestamp": 1,
            "signature": "22".repeat(64)
        });
        legacy
            .as_object_mut()
            .unwrap()
            .insert(plaintext_field.to_string(), serde_json::json!("forbidden"));
        let error = serde_json::from_value::<CreateSignedRequest>(legacy).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("unknown field `{plaintext_field}`")),
            "unexpected error for {plaintext_field}: {error}"
        );
    }
}

#[test]
fn private_invoice_envelope_rejects_wrong_size_version_and_noncanonical_base64() {
    let valid = presentation_envelope_fixture();
    assert!(decode_private_invoice_presentation(&valid).is_ok());

    let mut wrong_version = vec![0_u8; PRIVATE_INVOICE_PRESENTATION_ENVELOPE_BYTES];
    wrong_version[0] = 2;
    assert!(decode_private_invoice_presentation(&URL_SAFE_NO_PAD.encode(wrong_version)).is_err());
    assert!(decode_private_invoice_presentation("AQAA").is_err());
    assert!(decode_private_invoice_presentation(&format!("{valid}=")).is_err());
}

#[test]
fn private_invoice_interoperability_fixture_matches_server_framing() {
    use sha2::{Digest, Sha256};

    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/private_invoice_v1.json")).unwrap();
    let encoded = fixture["presentation_envelope_base64url"].as_str().unwrap();
    let envelope = decode_private_invoice_presentation(encoded).unwrap();

    assert_eq!(
        envelope.len(),
        fixture["presentation_envelope_length"].as_u64().unwrap() as usize
    );
    assert_eq!(envelope[0], PRIVATE_INVOICE_PRESENTATION_VERSION);
    assert_eq!(
        hex::encode(Sha256::digest(&envelope)),
        fixture["presentation_envelope_sha256"].as_str().unwrap()
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(&envelope),
        fixture["presentation_envelope_base64url"].as_str().unwrap()
    );
}

fn invoice_fixture() -> db::Invoice {
    db::Invoice {
        id: Uuid::nil(),
        nym_owner: Some("alice".to_string()),
        public_slug: None,
        npub_owner: "npub".to_string(),
        origin: "wallet".to_string(),
        checkout_surface_kind: None,
        fiat_amount_minor: None,
        fiat_currency: None,
        amount_sat: 10_000,
        rate_minor_per_btc: None,
        memo: None,
        bitcoin_address: None,
        accept_btc: false,
        accept_ln: true,
        accept_liquid: false,
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
        fiat_settlement_status: "none".to_string(),
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

#[test]
fn mrh_is_scoped_to_payment_page_invoices_with_an_existing_liquid_address() {
    let mut invoice = invoice_fixture();
    invoice.origin = "checkout".into();
    invoice.accept_liquid = true;
    invoice.checkout_surface_kind = Some(db::KIND_PAYMENT_PAGE.into());
    invoice.liquid_address = Some("lq1paymentpage".into());
    assert_eq!(payment_page_mrh_address(&invoice), Some("lq1paymentpage"));

    invoice.accept_liquid = false;
    assert_eq!(payment_page_mrh_address(&invoice), None);
    invoice.accept_liquid = true;
    invoice.checkout_surface_kind = Some(db::KIND_POS.into());
    assert_eq!(payment_page_mrh_address(&invoice), None);
    invoice.origin = "wallet".into();
    invoice.checkout_surface_kind = None;
    assert_eq!(payment_page_mrh_address(&invoice), None);
}

//! Privacy invariant for the invoice `memo` (PoS description / donor message).
//!
//! The note captured at checkout is stored as the invoice's `memo` and must be
//! returned ONLY on the signed, npub-verified invoice list — never on any
//! public response. These are pure serialization tests (no DB) that pin the
//! wire shape so a future field addition to a public struct fails loudly.

use pay_service::invoice::{InvoiceListItem, InvoiceStatusResponse};
use uuid::Uuid;

/// The signed invoice list is the ONE place a merchant's private memo is
/// returned; it must serialize the field.
#[test]
fn signed_list_item_exposes_memo() {
    let mut item = InvoiceListItem {
        id: Uuid::nil(),
        nym_owner: Some("alice".to_string()),
        origin: "checkout".to_string(),
        status: "paid".to_string(),
        presentation_status: Some("payment_received".to_string()),
        pricing_mode: "sat_fixed".to_string(),
        settlement_status: "none".to_string(),
        amount_sat: 1000,
        remaining_amount_sat: 0,
        fiat_amount_minor: None,
        fiat_currency: None,
        memo: Some("table 5 — decaf".to_string()),
        accept_btc: false,
        accept_ln: true,
        accept_liquid: false,
        bitcoin_address: None,
        liquid_address: None,
        created_at_unix: 0,
        expires_at_unix: 0,
        paid_via: None,
        paid_at_unix: None,
        paid_amount_sat: None,
        settlement_details: None,
        fiat_conversion: None,
    };
    let json = serde_json::to_value(&item).unwrap();
    let obj = json.as_object().unwrap();
    assert!(
        obj.contains_key("memo"),
        "signed invoice list item must carry the private memo"
    );
    assert_eq!(obj["memo"], "table 5 — decaf");
    assert_eq!(obj["presentation_status"], "payment_received");

    item.presentation_status = None;
    let rollout_json = serde_json::to_value(&item).unwrap();
    assert!(
        rollout_json["presentation_status"].is_null(),
        "unresolved migrated presentation must remain an explicit nullable field"
    );
}

/// The public per-invoice status response drives the payer's page and any
/// unauthenticated poller. It must NEVER carry the memo. If someone adds a
/// `memo` field to `InvoiceStatusResponse`, this fails.
#[test]
fn public_status_response_hides_memo() {
    let mut status = InvoiceStatusResponse {
        status: "unpaid".to_string(),
        presentation_status: Some("unpaid".to_string()),
        pricing_mode: "sat_fixed".to_string(),
        settlement_status: "none".to_string(),
        amount_sat: 1000,
        fiat_amount_minor: None,
        fiat_currency: None,
        remaining_amount_sat: 1000,
        payment_tolerance_sat: 0,
        rate_minor_per_btc: None,
        rate_locks_until_unix: 0,
        expires_at_unix: 0,
        paid_via: None,
        paid_at_unix: None,
        paid_amount_sat: None,
        lightning_pr: None,
        lightning_amount_sat: None,
        liquid_address: None,
        liquid_amount_sat: None,
        bitcoin_address: None,
        bitcoin_direct_observations: vec![],
        bitcoin_chain_address: None,
        bitcoin_chain_bip21: None,
        bitcoin_chain_amount_sat: None,
        accept_btc: false,
        accept_ln: true,
        accept_liquid: false,
        quote_rail_availability: None,
    };
    let json = serde_json::to_value(&status).unwrap();
    let obj = json.as_object().unwrap();
    assert!(
        !obj.contains_key("memo"),
        "public invoice status must NOT expose the private memo"
    );
    assert_eq!(obj["presentation_status"], "unpaid");

    status.presentation_status = None;
    let rollout_json = serde_json::to_value(&status).unwrap();
    assert!(
        rollout_json["presentation_status"].is_null(),
        "public status must preserve the additive nullable rollout contract"
    );
}

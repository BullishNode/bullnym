// Over-the-wire probe for the signed recoverable-swaps detection endpoint.
// Seeds a `refund_due` chain swap for a deterministic merchant identity (reusing
// the real `db` inserts, so columns/migrations match production), then prints a
// freshly-signed `invoice-recovery-list` request the shell can curl against a
// running server. NOT a production tool — a manual E2E aid for SPEC-RECOVER.
//
//   DATABASE_URL=... PROBE_TS=<unix> cargo run --example recover_probe
use pay_service::{auth, db, recovery_address_registration};
use secp256k1::{Keypair, Message, Secp256k1};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;

const DESCRIPTOR: &str = "ct(slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023),elwpkh([73c5da0a/84h/1776h/0h]xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*))#y8jljyxl";
const RECOVERY_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

fn signed_recovery_address_registration(
    keypair: &Keypair,
    npub: &str,
    timestamp: u64,
) -> recovery_address_registration::RecoveryAddressRegistrationRequest {
    let version = recovery_address_registration::RECOVERY_ADDRESS_REGISTRATION_VERSION;
    let message = recovery_address_registration::build_recovery_address_registration_message(
        version,
        npub,
        RECOVERY_ADDRESS,
        timestamp,
    )
    .unwrap();
    let digest = Sha256::digest(message);
    let message = Message::from_digest(*digest.as_ref());
    let signature = Secp256k1::new().sign_schnorr_no_aux_rand(&message, keypair);

    recovery_address_registration::RecoveryAddressRegistrationRequest {
        version,
        npub: npub.to_string(),
        btc_address: RECOVERY_ADDRESS.to_string(),
        timestamp,
        signature: signature.to_string(),
    }
}

#[tokio::main]
async fn main() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let nym = std::env::var("PROBE_NYM").unwrap_or_else(|_| "recoverprobe".into());
    let ts: u64 = std::env::var("PROBE_TS")
        .ok()
        .and_then(|s| s.parse().ok())
        .expect("PROBE_TS (unix seconds) required");

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_slice(&secp, &[0x11u8; 32]).unwrap();
    let (xonly, _) = kp.x_only_public_key();
    let npub = xonly.to_string();

    // Seed: merchant + checkout invoice + funded refund_due chain swap.
    db::create_user(&pool, &nym, &npub, DESCRIPTOR).await.ok();
    let recovery_registration = signed_recovery_address_registration(&kp, &npub, ts);
    let verified_recovery =
        recovery_address_registration::verify_recovery_address_registration(&recovery_registration)
            .unwrap();
    let recovery_commitment = db::persist_recovery_address_commitment(&pool, &verified_recovery)
        .await
        .unwrap();
    let invoice = db::insert_invoice(
        &pool,
        &db::NewInvoice {
            nym_owner: Some(&nym),
            public_slug: None,
            npub_owner: &npub,
            origin: "checkout",
            checkout_surface_kind: Some(db::KIND_PAYMENT_PAGE),
            fiat_amount_minor: None,
            fiat_currency: None,
            amount_sat: 100_000,
            rate_minor_per_btc: None,
            rate_lock_secs: 3_600,
            memo: None,
            accept_btc: false,
            accept_ln: false,
            accept_liquid: true,
            bitcoin_address: None,
            liquid_address: Some("lq1probe"),
            liquid_blinding_key_hex: Some(&"11".repeat(32)),
            expires_in_secs: 3_600,
        },
    )
    .await
    .unwrap();
    let claim_index = db::next_swap_key_index(&pool).await.unwrap();
    let refund_index = db::next_swap_key_index(&pool).await.unwrap();
    let root_fingerprint = "70726f62656b6579";
    let claim_public_key = format!(
        "02{}",
        hex::encode(Sha256::digest(format!("recover-probe-claim-{claim_index}")))
    );
    let refund_public_key = format!(
        "03{}",
        hex::encode(Sha256::digest(format!(
            "recover-probe-refund-{refund_index}"
        )))
    );
    let preimage_hex = "11".repeat(32);
    let preimage_hash = hex::encode(Sha256::digest([0x11_u8; 32]));
    let claim_allocation_id = db::reserve_swap_key_allocation(
        &pool,
        &db::NewSwapKeyAllocation {
            root_fingerprint,
            key_epoch: 1,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            child_index: claim_index as i64,
            purpose: db::SwapKeyPurpose::ChainClaim,
            public_key_hex: &claim_public_key,
            preimage_hash_hex: Some(&preimage_hash),
        },
    )
    .await
    .unwrap();
    let refund_allocation_id = db::reserve_swap_key_allocation(
        &pool,
        &db::NewSwapKeyAllocation {
            root_fingerprint,
            key_epoch: 1,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            child_index: refund_index as i64,
            purpose: db::SwapKeyPurpose::ChainRefund,
            public_key_hex: &refund_public_key,
            preimage_hash_hex: None,
        },
    )
    .await
    .unwrap();
    let boltz_response_json = r#"{"id":"probe-swap-1"}"#;
    let pair_hash = "aa".repeat(32);
    let creation_response_sha256 = hex::encode(Sha256::digest(boltz_response_json.as_bytes()));
    let btc_claim_script_sha256 = hex::encode(Sha256::digest(b"probe-btc-claim-script"));
    let btc_refund_script_sha256 = hex::encode(Sha256::digest(b"probe-btc-refund-script"));
    let liquid_claim_script_sha256 = hex::encode(Sha256::digest(b"probe-liquid-claim-script"));
    let liquid_refund_script_sha256 = hex::encode(Sha256::digest(b"probe-liquid-refund-script"));
    let creation_terms = db::NewChainSwapCreationTerms {
        pinned_pair_hash: &pair_hash,
        canonical_pair_quote_json: r#"{"fees":{"minerFees":{"server":1},"percentage":0},"hash":"probe","limits":{"maximal":1000000,"minimal":1},"rate":1}"#,
        creation_response_sha256: &creation_response_sha256,
        btc_claim_script_sha256: &btc_claim_script_sha256,
        btc_refund_script_sha256: &btc_refund_script_sha256,
        liquid_claim_script_sha256: &liquid_claim_script_sha256,
        liquid_refund_script_sha256: &liquid_refund_script_sha256,
        btc_timeout_height: 1,
        liquid_timeout_height: 1,
        btc_network: "bitcoin",
        liquid_network: "liquid",
        liquid_asset_id: "6f0279e9ed041c3d710a9f57d0c02928416413f827c37bf6833e2407092ff84d",
        merchant_liquid_destination: "lq1probe",
        merchant_emergency_btc_address: Some(recovery_commitment.canonical_btc_address()),
    };
    let swap = db::record_chain_swap_with_lineage_and_creation_evidence(
        &pool,
        &db::NewChainSwapRecord {
            claim_key_index: Some(claim_index as i64),
            refund_key_index: Some(refund_index as i64),
            root_fingerprint: Some(root_fingerprint),
            invoice_id: invoice.id,
            nym: Some(&nym),
            boltz_swap_id: "probe-swap-1",
            lockup_address: "bc1qproberecoverylockup",
            lockup_bip21: None,
            user_lock_amount_sat: 105_000,
            server_lock_amount_sat: 100_000,
            preimage_hex: &preimage_hex,
            claim_key_hex: &"22".repeat(32),
            refund_key_hex: &"33".repeat(32),
            boltz_response_json,
        },
        &db::ChainSwapLineage {
            claim_allocation_id,
            refund_allocation_id,
            key_epoch: 1,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &claim_public_key,
            refund_public_key_hex: &refund_public_key,
            preimage_hash_hex: &preimage_hash,
        },
        &db::NewChainSwapCreationEvidence {
            creation_terms,
            recovery_address_commitment_id: Some(recovery_commitment.commitment_id),
        },
    )
    .await
    .unwrap();
    db::mark_chain_swap_refund_due(&pool, swap.id)
        .await
        .unwrap();

    // Sign invoice-recovery-list: empty nym, ZERO payload fields.
    let fields: [&str; 0] = [];
    let msg = auth::build_la_v2_message("invoice-recovery-list", &npub, "", &fields, ts);
    let digest = Sha256::digest(&msg);
    let m = Message::from_digest(*digest.as_ref());
    let sig = secp.sign_schnorr(&m, &kp);

    println!("NPUB={npub}");
    println!("INVOICE_ID={}", invoice.id);
    println!("TS={ts}");
    println!("SIG={sig}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_registration_signature_is_deterministic() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[0x11_u8; 32]).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        let npub = xonly.to_string();
        let timestamp = 1_700_000_000;

        let first = signed_recovery_address_registration(&keypair, &npub, timestamp);
        let second = signed_recovery_address_registration(&keypair, &npub, timestamp);

        assert!(first == second);
        assert_eq!(first.npub, npub);
        assert_eq!(first.btc_address, RECOVERY_ADDRESS);
        assert_eq!(first.timestamp, timestamp);
    }
}

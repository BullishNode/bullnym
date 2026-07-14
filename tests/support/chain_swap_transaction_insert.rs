use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

use pay_service::db::{
    ChainSwapCreationTerms, ChainSwapLineage, ChainSwapRecord, NewChainSwapCreationEvidence,
    NewChainSwapCreationTerms, NewChainSwapRecord, NewSwapKeyAllocation, SwapKeyPurpose,
    DERIVATION_SCHEME_VERSION,
};

use super::{
    assert_sqlstate, cleanup_db, create_test_user, insert_test_invoice,
    insert_test_recovery_commitment, test_pool,
};

const RECOVERY_ADDRESS: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

struct AllocationPair {
    root_fingerprint: String,
    claim_child_index: i64,
    refund_child_index: i64,
    claim_allocation_id: Uuid,
    refund_allocation_id: Uuid,
    claim_public_key_hex: String,
    refund_public_key_hex: String,
    preimage_hash_hex: String,
}

struct SwapFixture {
    preimage_hex: String,
    claim_key_hex: String,
    refund_key_hex: String,
    boltz_response_json: String,
    creation_response_sha256: String,
}

impl SwapFixture {
    fn new() -> Self {
        let boltz_response_json = r#"{"id":"CHAIN_TX_INSERT","status":"swap.created"}"#.to_owned();
        let creation_response_sha256 = hex::encode(Sha256::digest(boltz_response_json.as_bytes()));
        Self {
            preimage_hex: lower_hash(0xa1),
            claim_key_hex: lower_hash(0xa2),
            refund_key_hex: lower_hash(0xa3),
            boltz_response_json,
            creation_response_sha256,
        }
    }

    fn swap<'a>(
        &'a self,
        invoice_id: Uuid,
        boltz_swap_id: &'a str,
        pair: &'a AllocationPair,
    ) -> NewChainSwapRecord<'a> {
        NewChainSwapRecord {
            invoice_id,
            nym: Some("txinsert"),
            boltz_swap_id,
            lockup_address: "bc1qtransactionawareinsert",
            lockup_bip21: Some("bitcoin:bc1qtransactionawareinsert?amount=0.00025431"),
            user_lock_amount_sat: 25_431,
            server_lock_amount_sat: 25_000,
            preimage_hex: &self.preimage_hex,
            claim_key_hex: &self.claim_key_hex,
            refund_key_hex: &self.refund_key_hex,
            boltz_response_json: &self.boltz_response_json,
            claim_key_index: Some(pair.claim_child_index),
            refund_key_index: Some(pair.refund_child_index),
            root_fingerprint: Some(&pair.root_fingerprint),
        }
    }

    fn creation_terms(&self) -> NewChainSwapCreationTerms<'_> {
        NewChainSwapCreationTerms {
            pinned_pair_hash: "1111111111111111111111111111111111111111111111111111111111111111",
            canonical_pair_quote_json: r#"{"hash":"tx-insert","rate":1}"#,
            creation_response_sha256: &self.creation_response_sha256,
            btc_claim_script_sha256:
                "3333333333333333333333333333333333333333333333333333333333333333",
            btc_refund_script_sha256:
                "4444444444444444444444444444444444444444444444444444444444444444",
            liquid_claim_script_sha256:
                "5555555555555555555555555555555555555555555555555555555555555555",
            liquid_refund_script_sha256:
                "6666666666666666666666666666666666666666666666666666666666666666",
            btc_timeout_height: 958_033,
            liquid_timeout_height: 3_972_215,
            btc_network: "bitcoin",
            liquid_network: "liquid",
            liquid_asset_id: "6f0279e9ed041c3d710a9f57d0c02928416413f827c37bf6833e2407092ff84d",
            merchant_liquid_destination: "lq1qqtransactionawaremerchantdestination",
            merchant_emergency_btc_address: Some(RECOVERY_ADDRESS),
        }
    }

    fn creation_evidence(&self, commitment_id: Uuid) -> NewChainSwapCreationEvidence<'_> {
        NewChainSwapCreationEvidence {
            creation_terms: self.creation_terms(),
            recovery_address_commitment_id: Some(commitment_id),
        }
    }
}

fn lower_hash(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn public_key(scalar: u8) -> String {
    PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[scalar; 32]).unwrap(),
    )
    .to_string()
}

async fn reserve_pair(
    pool: &PgPool,
    root_fingerprint: &str,
    claim_child_index: i64,
    claim_scalar: u8,
    preimage_byte: u8,
) -> AllocationPair {
    let refund_child_index = claim_child_index + 1;
    let claim_public_key_hex = public_key(claim_scalar);
    let refund_public_key_hex = public_key(claim_scalar + 1);
    let preimage_hash_hex = lower_hash(preimage_byte);
    let claim_allocation_id = pay_service::db::reserve_swap_key_allocation(
        pool,
        &NewSwapKeyAllocation {
            root_fingerprint,
            key_epoch: 1,
            derivation_scheme_version: DERIVATION_SCHEME_VERSION,
            child_index: claim_child_index,
            purpose: SwapKeyPurpose::ChainClaim,
            public_key_hex: &claim_public_key_hex,
            preimage_hash_hex: Some(&preimage_hash_hex),
        },
    )
    .await
    .unwrap();
    let refund_allocation_id = pay_service::db::reserve_swap_key_allocation(
        pool,
        &NewSwapKeyAllocation {
            root_fingerprint,
            key_epoch: 1,
            derivation_scheme_version: DERIVATION_SCHEME_VERSION,
            child_index: refund_child_index,
            purpose: SwapKeyPurpose::ChainRefund,
            public_key_hex: &refund_public_key_hex,
            preimage_hash_hex: None,
        },
    )
    .await
    .unwrap();

    AllocationPair {
        root_fingerprint: root_fingerprint.to_owned(),
        claim_child_index,
        refund_child_index,
        claim_allocation_id,
        refund_allocation_id,
        claim_public_key_hex,
        refund_public_key_hex,
        preimage_hash_hex,
    }
}

fn lineage(pair: &AllocationPair) -> ChainSwapLineage<'_> {
    ChainSwapLineage {
        claim_allocation_id: pair.claim_allocation_id,
        refund_allocation_id: pair.refund_allocation_id,
        key_epoch: 1,
        derivation_scheme_version: DERIVATION_SCHEME_VERSION,
        claim_public_key_hex: &pair.claim_public_key_hex,
        refund_public_key_hex: &pair.refund_public_key_hex,
        preimage_hash_hex: &pair.preimage_hash_hex,
    }
}

fn assert_record_matches_input(
    record: &ChainSwapRecord,
    swap: &NewChainSwapRecord<'_>,
    creation_evidence: &NewChainSwapCreationEvidence<'_>,
) {
    assert_eq!(record.invoice_id, swap.invoice_id);
    assert_eq!(record.nym.as_deref(), swap.nym);
    assert_eq!(record.boltz_swap_id, swap.boltz_swap_id);
    assert_eq!(record.from_chain, "BTC");
    assert_eq!(record.to_chain, "L-BTC");
    assert_eq!(record.lockup_address, swap.lockup_address);
    assert_eq!(record.lockup_bip21.as_deref(), swap.lockup_bip21);
    assert_eq!(record.user_lock_amount_sat, swap.user_lock_amount_sat);
    assert_eq!(record.server_lock_amount_sat, swap.server_lock_amount_sat);
    assert_eq!(record.preimage_hex, swap.preimage_hex);
    assert_eq!(record.claim_key_hex, swap.claim_key_hex);
    assert_eq!(record.refund_key_hex, swap.refund_key_hex);
    assert_eq!(record.boltz_response_json, swap.boltz_response_json);
    assert_eq!(record.status, "pending");
    assert_eq!(record.claim_txid, None);
    assert_eq!(record.claim_tx_hex, None);
    assert_eq!(record.claim_attempts, 0);
    assert_eq!(record.last_claim_error, None);
    assert!(!record.cooperative_refused);
    assert_eq!(
        record.creation_terms.as_ref(),
        Some(&ChainSwapCreationTerms::from(creation_evidence))
    );
    assert_eq!(record.renegotiated_server_lock_amount_sat, None);
    assert_eq!(record.refund_address, None);
    assert_eq!(record.refund_txid, None);
    assert!(record.created_at_unix > 0);
    assert!(record.updated_at_unix >= record.created_at_unix);
    record.verify_creation_response_integrity().unwrap();
}

fn assert_records_exact(left: &ChainSwapRecord, right: &ChainSwapRecord) {
    assert_eq!(left.id, right.id);
    assert_eq!(left.invoice_id, right.invoice_id);
    assert_eq!(left.nym, right.nym);
    assert_eq!(left.boltz_swap_id, right.boltz_swap_id);
    assert_eq!(left.from_chain, right.from_chain);
    assert_eq!(left.to_chain, right.to_chain);
    assert_eq!(left.lockup_address, right.lockup_address);
    assert_eq!(left.lockup_bip21, right.lockup_bip21);
    assert_eq!(left.user_lock_amount_sat, right.user_lock_amount_sat);
    assert_eq!(left.server_lock_amount_sat, right.server_lock_amount_sat);
    assert_eq!(left.preimage_hex, right.preimage_hex);
    assert_eq!(left.claim_key_hex, right.claim_key_hex);
    assert_eq!(left.refund_key_hex, right.refund_key_hex);
    assert_eq!(left.boltz_response_json, right.boltz_response_json);
    assert_eq!(left.status, right.status);
    assert_eq!(left.claim_txid, right.claim_txid);
    assert_eq!(left.claim_tx_hex, right.claim_tx_hex);
    assert_eq!(left.claim_attempts, right.claim_attempts);
    assert_eq!(left.last_claim_error, right.last_claim_error);
    assert_eq!(left.cooperative_refused, right.cooperative_refused);
    assert_eq!(left.creation_terms, right.creation_terms);
    assert_eq!(
        left.renegotiated_server_lock_amount_sat,
        right.renegotiated_server_lock_amount_sat
    );
    assert_eq!(left.refund_address, right.refund_address);
    assert_eq!(left.refund_txid, right.refund_txid);
    assert_eq!(left.created_at_unix, right.created_at_unix);
    assert_eq!(left.updated_at_unix, right.updated_at_unix);
}

fn assert_insert_api_parity(left: &ChainSwapRecord, right: &ChainSwapRecord) {
    assert_ne!(left.id, right.id);
    assert_ne!(left.boltz_swap_id, right.boltz_swap_id);
    assert_eq!(left.invoice_id, right.invoice_id);
    assert_eq!(left.nym, right.nym);
    assert_eq!(left.from_chain, right.from_chain);
    assert_eq!(left.to_chain, right.to_chain);
    assert_eq!(left.lockup_address, right.lockup_address);
    assert_eq!(left.lockup_bip21, right.lockup_bip21);
    assert_eq!(left.user_lock_amount_sat, right.user_lock_amount_sat);
    assert_eq!(left.server_lock_amount_sat, right.server_lock_amount_sat);
    assert_eq!(left.preimage_hex, right.preimage_hex);
    assert_eq!(left.claim_key_hex, right.claim_key_hex);
    assert_eq!(left.refund_key_hex, right.refund_key_hex);
    assert_eq!(left.boltz_response_json, right.boltz_response_json);
    assert_eq!(left.status, right.status);
    assert_eq!(left.claim_txid, right.claim_txid);
    assert_eq!(left.claim_tx_hex, right.claim_tx_hex);
    assert_eq!(left.claim_attempts, right.claim_attempts);
    assert_eq!(left.last_claim_error, right.last_claim_error);
    assert_eq!(left.cooperative_refused, right.cooperative_refused);
    assert_eq!(left.creation_terms, right.creation_terms);
    assert_eq!(
        left.renegotiated_server_lock_amount_sat,
        right.renegotiated_server_lock_amount_sat
    );
    assert_eq!(left.refund_address, right.refund_address);
    assert_eq!(left.refund_txid, right.refund_txid);
}

async fn raw_chain_row<'e, E>(executor: E, id: Uuid) -> Option<Value>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar("SELECT to_jsonb(chain_swap_records) FROM chain_swap_records WHERE id = $1")
        .bind(id)
        .fetch_optional(executor)
        .await
        .unwrap()
}

fn normalize_insert_identity(mut row: Value) -> Value {
    let object = row.as_object_mut().unwrap();
    for key in [
        "id",
        "boltz_swap_id",
        "claim_key_index",
        "refund_key_index",
        "root_fingerprint",
        "claim_key_allocation_id",
        "refund_key_allocation_id",
        "claim_public_key_hex",
        "refund_public_key_hex",
        "preimage_hash_hex",
        "created_at",
        "updated_at",
    ] {
        object.remove(key);
    }
    row
}

#[tokio::test]
async fn fully_validated_chain_swap_insert_in_tx_has_pool_parity_and_commit_visibility() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "txinsert").await;
    let recovery_address_commitment_id =
        insert_test_recovery_commitment(&pool, &npub, RECOVERY_ADDRESS, 1, 0xa7).await;
    let invoice =
        insert_test_invoice(&pool, "txinsert", &npub, "lq1transactionawareinsert", 3_600).await;
    let fixture = SwapFixture::new();
    let tx_pair = reserve_pair(&pool, "1111111111111111", 9_100, 0x11, 0x21).await;
    let pool_pair = reserve_pair(&pool, "2222222222222222", 9_200, 0x31, 0x41).await;

    let mut tx = pool.begin().await.unwrap();
    let tx_swap = fixture.swap(invoice.id, "CHAIN_TX_INSERT_COMMIT", &tx_pair);
    let tx_lineage = lineage(&tx_pair);
    let creation_evidence = fixture.creation_evidence(recovery_address_commitment_id);
    let inserted = pay_service::db::record_chain_swap_with_lineage_and_creation_evidence_in_tx(
        &mut tx,
        &tx_swap,
        &tx_lineage,
        &creation_evidence,
    )
    .await
    .unwrap();
    assert_record_matches_input(&inserted, &tx_swap, &creation_evidence);
    let inside = pay_service::db::get_chain_swap_by_id(&mut *tx, inserted.id)
        .await
        .unwrap()
        .unwrap();
    assert_records_exact(&inside, &inserted);
    let inside_raw = raw_chain_row(&mut *tx, inserted.id).await.unwrap();
    assert!(
        pay_service::db::get_chain_swap_by_boltz_id(&pool, "CHAIN_TX_INSERT_COMMIT")
            .await
            .unwrap()
            .is_none(),
        "a second connection must not see an uncommitted chain swap"
    );

    tx.commit().await.unwrap();

    let committed = pay_service::db::get_chain_swap_by_boltz_id(&pool, "CHAIN_TX_INSERT_COMMIT")
        .await
        .unwrap()
        .unwrap();
    assert_records_exact(&committed, &inserted);
    assert_eq!(raw_chain_row(&pool, inserted.id).await.unwrap(), inside_raw);

    let pool_swap = fixture.swap(invoice.id, "CHAIN_POOL_INSERT_PARITY", &pool_pair);
    let pool_lineage = lineage(&pool_pair);
    let pool_inserted = pay_service::db::record_chain_swap_with_lineage_and_creation_evidence(
        &pool,
        &pool_swap,
        &pool_lineage,
        &creation_evidence,
    )
    .await
    .unwrap();
    assert_record_matches_input(&pool_inserted, &pool_swap, &creation_evidence);
    assert_insert_api_parity(&inserted, &pool_inserted);
    assert_eq!(
        normalize_insert_identity(raw_chain_row(&pool, inserted.id).await.unwrap()),
        normalize_insert_identity(raw_chain_row(&pool, pool_inserted.id).await.unwrap())
    );

    let immutable =
        sqlx::query("UPDATE chain_swap_records SET pinned_pair_hash = $2 WHERE id = $1")
            .bind(inserted.id)
            .bind(lower_hash(0x99))
            .execute(&pool)
            .await
            .unwrap_err();
    assert_sqlstate(&immutable, "55000");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn fully_validated_chain_swap_insert_in_tx_rolls_back_and_keeps_constraints() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "txinsert").await;
    let recovery_address_commitment_id =
        insert_test_recovery_commitment(&pool, &npub, RECOVERY_ADDRESS, 1, 0xa8).await;
    let invoice = insert_test_invoice(
        &pool,
        "txinsert",
        &npub,
        "lq1transactionawarerollback",
        3_600,
    )
    .await;
    let fixture = SwapFixture::new();
    let rollback_pair = reserve_pair(&pool, "3333333333333333", 9_300, 0x51, 0x61).await;
    let invalid_pair = reserve_pair(&pool, "4444444444444444", 9_400, 0x71, 0x81).await;

    let mut rollback_tx = pool.begin().await.unwrap();
    let rollback_swap = fixture.swap(invoice.id, "CHAIN_TX_INSERT_ROLLBACK", &rollback_pair);
    let rollback_lineage = lineage(&rollback_pair);
    let creation_evidence = fixture.creation_evidence(recovery_address_commitment_id);
    let rolled_back = pay_service::db::record_chain_swap_with_lineage_and_creation_evidence_in_tx(
        &mut rollback_tx,
        &rollback_swap,
        &rollback_lineage,
        &creation_evidence,
    )
    .await
    .unwrap();
    assert!(raw_chain_row(&mut *rollback_tx, rolled_back.id)
        .await
        .is_some());
    assert!(raw_chain_row(&pool, rolled_back.id).await.is_none());
    rollback_tx.rollback().await.unwrap();
    assert!(raw_chain_row(&pool, rolled_back.id).await.is_none());
    assert!(
        pay_service::db::get_chain_swap_by_boltz_id(&pool, "CHAIN_TX_INSERT_ROLLBACK")
            .await
            .unwrap()
            .is_none()
    );

    let mut invalid_tx = pool.begin().await.unwrap();
    let invalid_swap = fixture.swap(invoice.id, "CHAIN_TX_INSERT_INVALID", &invalid_pair);
    let invalid_lineage = lineage(&invalid_pair);
    let mut invalid_evidence = fixture.creation_evidence(recovery_address_commitment_id);
    invalid_evidence.creation_terms.pinned_pair_hash = "not-a-lowercase-sha256";
    let invalid = pay_service::db::record_chain_swap_with_lineage_and_creation_evidence_in_tx(
        &mut invalid_tx,
        &invalid_swap,
        &invalid_lineage,
        &invalid_evidence,
    )
    .await
    .unwrap_err();
    assert_sqlstate(&invalid, "23514");
    assert_eq!(
        invalid
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("chain_swap_records_pinned_pair_hash_check")
    );
    invalid_tx.rollback().await.unwrap();
    assert!(
        pay_service::db::get_chain_swap_by_boltz_id(&pool, "CHAIN_TX_INSERT_INVALID")
            .await
            .unwrap()
            .is_none()
    );

    cleanup_db(&pool).await;
}

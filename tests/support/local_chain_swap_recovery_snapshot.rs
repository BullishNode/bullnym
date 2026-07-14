use std::collections::BTreeMap;
use std::time::Duration;

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sqlx::PgPool;
use uuid::Uuid;

use pay_service::db::{
    load_local_chain_swap_recovery_snapshot_v1, ChainSwapLineage, ChainSwapRecord,
    LocalRecoverySnapshotReadErrorV1, NewChainSwapCreationEvidence, NewChainSwapCreationTerms,
    NewChainSwapRecord, NewSwapKeyAllocation, SwapKeyPurpose, DERIVATION_SCHEME_VERSION,
};
use pay_service::local_chain_swap_recovery_audit::LocalChainSwapRecoveryStructuralClassV1;

use super::{
    cleanup_db, create_test_user, insert_test_invoice, insert_test_recovery_commitment,
    record_pre_050_chain_fixture, test_pool, RECOVERY_COMMITMENT_P2WPKH,
};

#[derive(Clone)]
struct AllocationPair {
    root_fingerprint: String,
    key_epoch: i32,
    claim_child_index: i64,
    refund_child_index: i64,
    claim_allocation_id: Uuid,
    refund_allocation_id: Uuid,
    claim_public_key_hex: String,
    refund_public_key_hex: String,
    claim_preimage_sha256: String,
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
    key_epoch: i32,
    claim_child_index: i64,
    claim_scalar: u8,
    preimage_byte: u8,
) -> AllocationPair {
    let refund_child_index = claim_child_index + 1;
    let refund_scalar = claim_scalar + 1;
    let claim_public_key_hex = public_key(claim_scalar);
    let refund_public_key_hex = public_key(refund_scalar);
    let claim_preimage_sha256 = lower_hash(preimage_byte);
    let claim_allocation_id = pay_service::db::reserve_swap_key_allocation(
        pool,
        &NewSwapKeyAllocation {
            root_fingerprint,
            key_epoch,
            derivation_scheme_version: DERIVATION_SCHEME_VERSION,
            child_index: claim_child_index,
            purpose: SwapKeyPurpose::ChainClaim,
            public_key_hex: &claim_public_key_hex,
            preimage_hash_hex: Some(&claim_preimage_sha256),
        },
    )
    .await
    .unwrap();
    let refund_allocation_id = pay_service::db::reserve_swap_key_allocation(
        pool,
        &NewSwapKeyAllocation {
            root_fingerprint,
            key_epoch,
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
        key_epoch,
        claim_child_index,
        refund_child_index,
        claim_allocation_id,
        refund_allocation_id,
        claim_public_key_hex,
        refund_public_key_hex,
        claim_preimage_sha256,
    }
}

fn creation_terms(creation_response_sha256: &str) -> NewChainSwapCreationTerms<'_> {
    NewChainSwapCreationTerms {
        pinned_pair_hash: "1111111111111111111111111111111111111111111111111111111111111111",
        canonical_pair_quote_json: r#"{"hash":"snapshot-fixture","rate":1}"#,
        creation_response_sha256,
        btc_claim_script_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
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
        merchant_liquid_destination: "lq1qqsnapshotfixturemerchantdestination",
        merchant_emergency_btc_address: Some(RECOVERY_COMMITMENT_P2WPKH),
    }
}

async fn insert_modern_chain_swap(
    pool: &PgPool,
    invoice_id: Uuid,
    nym: &str,
    boltz_swap_id: &str,
    pair: &AllocationPair,
    creation_response_sha256: &str,
    recovery_address_commitment_id: Uuid,
) -> ChainSwapRecord {
    let preimage_hex = lower_hash(0xc1);
    let claim_key_hex = lower_hash(0xc2);
    let refund_key_hex = lower_hash(0xc3);
    let response = format!(r#"{{"id":"{boltz_swap_id}"}}"#);
    pay_service::db::record_chain_swap_with_lineage_and_creation_evidence(
        pool,
        &NewChainSwapRecord {
            invoice_id,
            nym: Some(nym),
            boltz_swap_id,
            lockup_address: "bc1qsnapshotfixture",
            lockup_bip21: None,
            user_lock_amount_sat: 25_431,
            server_lock_amount_sat: 25_000,
            preimage_hex: &preimage_hex,
            claim_key_hex: &claim_key_hex,
            refund_key_hex: &refund_key_hex,
            boltz_response_json: &response,
            claim_key_index: Some(pair.claim_child_index),
            refund_key_index: Some(pair.refund_child_index),
            root_fingerprint: Some(&pair.root_fingerprint),
        },
        &ChainSwapLineage {
            claim_allocation_id: pair.claim_allocation_id,
            refund_allocation_id: pair.refund_allocation_id,
            key_epoch: pair.key_epoch,
            derivation_scheme_version: DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &pair.claim_public_key_hex,
            refund_public_key_hex: &pair.refund_public_key_hex,
            preimage_hash_hex: &pair.claim_preimage_sha256,
        },
        &NewChainSwapCreationEvidence {
            creation_terms: creation_terms(creation_response_sha256),
            recovery_address_commitment_id: Some(recovery_address_commitment_id),
        },
    )
    .await
    .unwrap()
}

async fn reserve_reverse_or_orphan(
    pool: &PgPool,
    root_fingerprint: &str,
    key_epoch: i32,
    child_index: i64,
    scalar: u8,
    preimage_byte: u8,
) -> Uuid {
    let public_key_hex = public_key(scalar);
    let preimage_hash_hex = lower_hash(preimage_byte);
    pay_service::db::reserve_swap_key_allocation(
        pool,
        &NewSwapKeyAllocation {
            root_fingerprint,
            key_epoch,
            derivation_scheme_version: DERIVATION_SCHEME_VERSION,
            child_index,
            purpose: SwapKeyPurpose::ReverseClaim,
            public_key_hex: &public_key_hex,
            preimage_hash_hex: Some(&preimage_hash_hex),
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn local_chain_swap_recovery_snapshot_projects_complete_rows_and_allocator_truth() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let nym = "snapshotadapter";
    let npub = create_test_user(&pool, nym).await;
    let recovery_address_commitment_id =
        insert_test_recovery_commitment(&pool, &npub, RECOVERY_COMMITMENT_P2WPKH, 1, 0xa1).await;
    let first_invoice = insert_test_invoice(&pool, nym, &npub, "lq1snapshotfirst", 3_600).await;
    let second_invoice = insert_test_invoice(&pool, nym, &npub, "lq1snapshotsecond", 3_600).await;
    let legacy_invoice = insert_test_invoice(&pool, nym, &npub, "lq1snapshotlegacy", 3_600).await;

    // Insert in reverse lineage order; the adapter's output must not depend on
    // insertion order.
    let second_pair = reserve_pair(&pool, "2222222222222222", 2, 20, 21, 0xa2).await;
    let second = insert_modern_chain_swap(
        &pool,
        second_invoice.id,
        nym,
        "SNAPSHOTSECOND",
        &second_pair,
        &lower_hash(0xb2),
        recovery_address_commitment_id,
    )
    .await;
    let first_pair = reserve_pair(&pool, "1111111111111111", 1, 10, 11, 0xa1).await;
    let first = insert_modern_chain_swap(
        &pool,
        first_invoice.id,
        nym,
        "SNAPSHOTFIRST",
        &first_pair,
        &lower_hash(0xb1),
        recovery_address_commitment_id,
    )
    .await;

    // The allocator high-water is global: reverse and orphan reservations are
    // evidence even though neither has a chain-swap row.
    reserve_reverse_or_orphan(&pool, "1111111111111111", 1, 14, 13, 0xa3).await;
    reserve_reverse_or_orphan(&pool, "0000000000000001", 3, 7, 14, 0xa4).await;

    let legacy_preimage = lower_hash(0xd1);
    let legacy_claim_key = lower_hash(0xd2);
    let legacy_refund_key = lower_hash(0xd3);
    let legacy_response = r#"{"id":"SNAPSHOT-LEGACY"}"#;
    record_pre_050_chain_fixture(
        &pool,
        &NewChainSwapRecord {
            invoice_id: legacy_invoice.id,
            nym: Some(nym),
            boltz_swap_id: "SNAPSHOTLEGACY",
            lockup_address: "bc1qsnapshotlegacy",
            lockup_bip21: None,
            user_lock_amount_sat: 20_000,
            server_lock_amount_sat: 19_000,
            preimage_hex: &legacy_preimage,
            claim_key_hex: &legacy_claim_key,
            refund_key_hex: &legacy_refund_key,
            boltz_response_json: legacy_response,
            // Exact migration-044 legacy shape: the root and both indices are
            // present, while migration-050 allocation/epoch/public evidence
            // and migration-051 creation evidence are absent.
            claim_key_index: Some(90),
            refund_key_index: Some(91),
            root_fingerprint: Some("9999999999999999"),
        },
    )
    .await
    .unwrap();

    let snapshot = load_local_chain_swap_recovery_snapshot_v1(&pool, "1111111111111111")
        .await
        .unwrap();
    assert_eq!(snapshot.summary.record_count, 2);
    assert_eq!(snapshot.summary.chain_inventory_record_count, 3);
    assert_eq!(snapshot.summary.chain_inventory.len(), 3);
    assert_eq!(snapshot.summary.active_root_fingerprint, "1111111111111111");
    assert_eq!(
        snapshot
            .summary
            .chain_inventory
            .iter()
            .filter(|record| {
                record.structural_class == LocalChainSwapRecoveryStructuralClassV1::CurrentV1
            })
            .count(),
        2
    );
    let legacy_inventory = snapshot
        .summary
        .chain_inventory
        .iter()
        .find(|record| {
            record.structural_class == LocalChainSwapRecoveryStructuralClassV1::CompleteLegacy
        })
        .unwrap();
    let legacy_derivation = legacy_inventory.legacy_derivation.as_ref().unwrap();
    assert_eq!(legacy_derivation.root_fingerprint, "9999999999999999");
    assert_eq!(legacy_derivation.claim_child_index, 90);
    assert_eq!(legacy_derivation.refund_child_index, 91);
    assert_eq!(snapshot.records.len(), 2);
    assert!(snapshot
        .records
        .windows(2)
        .all(|records| records[0].chain_swap_id < records[1].chain_swap_id));

    let records = snapshot
        .records
        .iter()
        .map(|record| (record.chain_swap_id, record))
        .collect::<BTreeMap<_, _>>();
    let first_loaded = records.get(&first.id).unwrap();
    assert_eq!(first_loaded.boltz_swap_id, "SNAPSHOTFIRST");
    assert_eq!(
        first_loaded.claim.allocation_id,
        first_pair.claim_allocation_id
    );
    assert_eq!(
        first_loaded.refund.allocation_id,
        first_pair.refund_allocation_id
    );
    assert_eq!(
        first_loaded.claim_preimage_sha256,
        first_pair.claim_preimage_sha256
    );
    assert_eq!(
        first_loaded.canonical_creation_response_sha256,
        lower_hash(0xb1)
    );
    assert!(records.contains_key(&second.id));
    assert!(!snapshot
        .records
        .iter()
        .any(|record| record.boltz_swap_id == "SNAPSHOTLEGACY"));

    assert_eq!(
        snapshot
            .summary
            .lineage_high_waters
            .iter()
            .map(|lineage| (
                lineage.root_fingerprint.as_str(),
                lineage.key_epoch,
                lineage.child_index
            ))
            .collect::<Vec<_>>(),
        [
            ("0000000000000001", 3, 7),
            ("1111111111111111", 1, 14),
            ("2222222222222222", 2, 21),
        ]
    );

    cleanup_db(&pool).await;
}

async fn insert_replica_chain_swap(
    pool: &PgPool,
    invoice_id: Uuid,
    nym: &str,
    boltz_swap_id: &str,
    pair: &AllocationPair,
    creation_response_sha256: &str,
    recovery_address_commitment_id: Uuid,
) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO chain_swap_records ( \
             invoice_id, nym, boltz_swap_id, from_chain, to_chain, lockup_address, \
             user_lock_amount_sat, server_lock_amount_sat, preimage_hex, claim_key_hex, \
             refund_key_hex, boltz_response_json, claim_key_index, refund_key_index, \
             root_fingerprint, claim_key_allocation_id, refund_key_allocation_id, \
             key_epoch, derivation_scheme_version, claim_public_key_hex, \
             refund_public_key_hex, preimage_hash_hex, pinned_pair_hash, \
             canonical_pair_quote_json, creation_response_sha256, \
             btc_claim_script_sha256, btc_refund_script_sha256, \
             liquid_claim_script_sha256, liquid_refund_script_sha256, \
             btc_timeout_height, liquid_timeout_height, btc_network, liquid_network, \
             liquid_asset_id, merchant_liquid_destination, \
             merchant_emergency_btc_address, recovery_address_commitment_id \
         ) VALUES ( \
             $1, $2, $3, 'BTC', 'L-BTC', 'bc1qreplicasnapshot', 25431, 25000, \
             repeat('a', 64), repeat('b', 64), repeat('c', 64), '{}', \
             $4, $5, $6, $7, $8, $9, 1, $10, $11, $12, repeat('1', 64), '{}', \
             $13, repeat('3', 64), repeat('4', 64), repeat('5', 64), repeat('6', 64), \
             958033, 3972215, 'bitcoin', 'liquid', repeat('7', 64), \
             'lq1qqreplicasnapshotdestination', $14, $15 \
         )",
    )
    .bind(invoice_id)
    .bind(nym)
    .bind(boltz_swap_id)
    .bind(pair.claim_child_index)
    .bind(pair.refund_child_index)
    .bind(&pair.root_fingerprint)
    .bind(pair.claim_allocation_id)
    .bind(pair.refund_allocation_id)
    .bind(pair.key_epoch)
    .bind(&pair.claim_public_key_hex)
    .bind(&pair.refund_public_key_hex)
    .bind(&pair.claim_preimage_sha256)
    .bind(creation_response_sha256)
    .bind(RECOVERY_COMMITMENT_P2WPKH)
    .bind(recovery_address_commitment_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn local_chain_swap_recovery_snapshot_is_one_repeatable_read_view() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let nym = "snapshotcoherent";
    let npub = create_test_user(&pool, nym).await;
    let recovery_address_commitment_id =
        insert_test_recovery_commitment(&pool, &npub, RECOVERY_COMMITMENT_P2WPKH, 1, 0xa2).await;
    let first_invoice = insert_test_invoice(&pool, nym, &npub, "lq1coherentfirst", 3_600).await;
    let second_invoice = insert_test_invoice(&pool, nym, &npub, "lq1coherentsecond", 3_600).await;
    let first_pair = reserve_pair(&pool, "3333333333333333", 1, 100, 31, 0xe1).await;
    insert_modern_chain_swap(
        &pool,
        first_invoice.id,
        nym,
        "SNAPSHOTCOHERENTFIRST",
        &first_pair,
        &lower_hash(0xf1),
        recovery_address_commitment_id,
    )
    .await;
    let second_pair = reserve_pair(&pool, "3333333333333333", 1, 102, 33, 0xe2).await;

    // Hold the allocator table only. The loader can establish its snapshot by
    // counting chain rows, then deterministically blocks on its lineage count.
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE swap_key_allocations IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();

    let loader_pool = pool.clone();
    let loader = tokio::spawn(async move {
        load_local_chain_swap_recovery_snapshot_v1(&loader_pool, "3333333333333333").await
    });

    let mut observed_blocked_lineage_count = false;
    for _ in 0..100 {
        observed_blocked_lineage_count = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
                 SELECT 1 FROM pg_stat_activity \
                  WHERE datname = current_database() \
                    AND pid <> pg_backend_pid() \
                    AND wait_event_type = 'Lock' \
                    AND query LIKE '%recovery_lineages%' \
             )",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if observed_blocked_lineage_count {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if !observed_blocked_lineage_count {
        blocker.rollback().await.unwrap();
        let _ = loader.await;
        panic!("snapshot loader never reached the blocked lineage count");
    }

    // This row commits after the loader's first snapshot read. Replica mode is
    // confined to the disposable test transaction so the insert does not need
    // to inspect the allocation table held by the deterministic barrier.
    tokio::time::timeout(
        Duration::from_secs(2),
        insert_replica_chain_swap(
            &pool,
            second_invoice.id,
            nym,
            "SNAPSHOTCOHERENTSECOND",
            &second_pair,
            &lower_hash(0xf2),
            recovery_address_commitment_id,
        ),
    )
    .await
    .expect("replica fixture insert blocked unexpectedly");
    blocker.commit().await.unwrap();

    let snapshot = tokio::time::timeout(Duration::from_secs(5), loader)
        .await
        .expect("snapshot loader did not resume")
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.summary.record_count, 1);
    assert_eq!(snapshot.records.len(), 1);
    assert_eq!(
        snapshot.summary.lineage_high_waters[0].child_index, second_pair.refund_child_index,
        "allocations reserved before the snapshot remain visible"
    );

    let next_snapshot = load_local_chain_swap_recovery_snapshot_v1(&pool, "3333333333333333")
        .await
        .unwrap();
    assert_eq!(next_snapshot.summary.record_count, 2);
    assert_eq!(next_snapshot.records.len(), 2);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn local_chain_swap_recovery_snapshot_bounds_before_bulk_reads() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let mut records_tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *records_tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO chain_swap_records ( \
             invoice_id, boltz_swap_id, from_chain, to_chain, lockup_address, \
             user_lock_amount_sat, server_lock_amount_sat, preimage_hex, claim_key_hex, \
             refund_key_hex, boltz_response_json, claim_key_index, refund_key_index, \
             root_fingerprint, claim_key_allocation_id, refund_key_allocation_id, \
             key_epoch, derivation_scheme_version, claim_public_key_hex, \
             refund_public_key_hex, preimage_hash_hex, pinned_pair_hash, \
             canonical_pair_quote_json, creation_response_sha256, \
             btc_claim_script_sha256, btc_refund_script_sha256, \
             liquid_claim_script_sha256, liquid_refund_script_sha256, \
             btc_timeout_height, liquid_timeout_height, btc_network, liquid_network, \
             liquid_asset_id, merchant_liquid_destination \
         ) \
         SELECT gen_random_uuid(), 'SNAPSHOT-BOUND-' || item, 'BTC', 'L-BTC', \
                'bc1qboundsnapshot', 25431, 25000, repeat('a', 64), repeat('b', 64), \
                repeat('c', 64), '{}', item * 2, item * 2 + 1, '4444444444444444', \
                gen_random_uuid(), gen_random_uuid(), 1, 1, \
                '02' || lpad(to_hex(item * 2), 64, '0'), \
                '03' || lpad(to_hex(item * 2 + 1), 64, '0'), \
                lpad(to_hex(item), 64, '0'), repeat('1', 64), '{}', \
                lpad(to_hex(item), 64, '0'), repeat('3', 64), repeat('4', 64), \
                repeat('5', 64), repeat('6', 64), 958033, 3972215, 'bitcoin', 'liquid', \
                repeat('7', 64), 'lq1qqboundsnapshotdestination' \
           FROM generate_series(1, 10001) AS item",
    )
    .execute(&mut *records_tx)
    .await
    .unwrap();
    records_tx.commit().await.unwrap();

    assert_eq!(
        load_local_chain_swap_recovery_snapshot_v1(&pool, "4444444444444444")
            .await
            .unwrap_err(),
        LocalRecoverySnapshotReadErrorV1::TooManyRecords
    );

    cleanup_db(&pool).await;
    let mut lineages_tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *lineages_tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO swap_key_allocations ( \
             root_fingerprint, key_epoch, derivation_scheme_version, child_index, \
             purpose, public_key_hex, preimage_hash_hex \
         ) \
         SELECT lpad(to_hex(item), 16, '0'), 1, 1, 0, 'chain_refund', \
                '02' || lpad(to_hex(item), 64, '0'), NULL \
           FROM generate_series(1, 4097) AS item",
    )
    .execute(&mut *lineages_tx)
    .await
    .unwrap();
    lineages_tx.commit().await.unwrap();

    assert_eq!(
        load_local_chain_swap_recovery_snapshot_v1(&pool, "4444444444444444")
            .await
            .unwrap_err(),
        LocalRecoverySnapshotReadErrorV1::TooManyLineages
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn local_chain_swap_recovery_snapshot_rejects_corrupt_registry_without_leaking_values() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let nym = "snapshotcorrupt";
    let npub = create_test_user(&pool, nym).await;
    let recovery_address_commitment_id =
        insert_test_recovery_commitment(&pool, &npub, RECOVERY_COMMITMENT_P2WPKH, 1, 0xa3).await;
    let invoice = insert_test_invoice(&pool, nym, &npub, "lq1snapshotcorrupt", 3_600).await;
    let pair = reserve_pair(&pool, "5555555555555555", 1, 200, 41, 0xd1).await;
    const SENTINEL: &str = "OperationalProviderIdentifierMustNotEscape";
    let row = insert_modern_chain_swap(
        &pool,
        invoice.id,
        nym,
        "SNAPSHOT-CORRUPT",
        &pair,
        &lower_hash(0xd2),
        recovery_address_commitment_id,
    )
    .await;

    let overlong_provider_id = format!("{SENTINEL}{}", "X".repeat(128));
    let mut corrupt = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *corrupt)
        .await
        .unwrap();
    sqlx::query("UPDATE chain_swap_records SET boltz_swap_id = $2 WHERE id = $1")
        .bind(row.id)
        .bind(&overlong_provider_id)
        .execute(&mut *corrupt)
        .await
        .unwrap();
    corrupt.commit().await.unwrap();

    let overlong_error = load_local_chain_swap_recovery_snapshot_v1(&pool, "5555555555555555")
        .await
        .unwrap_err();
    assert_eq!(
        overlong_error,
        LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence
    );
    assert!(!overlong_error.to_string().contains(SENTINEL));
    assert!(!format!("{overlong_error:?}").contains(SENTINEL));

    let mut corrupt = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *corrupt)
        .await
        .unwrap();
    sqlx::query("UPDATE chain_swap_records SET boltz_swap_id = 'SNAPSHOTCORRUPT' WHERE id = $1")
        .bind(row.id)
        .execute(&mut *corrupt)
        .await
        .unwrap();
    sqlx::query("UPDATE swap_key_allocations SET purpose = 'reverse_claim' WHERE id = $1")
        .bind(pair.claim_allocation_id)
        .execute(&mut *corrupt)
        .await
        .unwrap();
    corrupt.commit().await.unwrap();

    let registry_error = load_local_chain_swap_recovery_snapshot_v1(&pool, "5555555555555555")
        .await
        .unwrap_err();
    assert_eq!(
        registry_error,
        LocalRecoverySnapshotReadErrorV1::InvalidStoredEvidence
    );
    assert!(!registry_error.to_string().contains(SENTINEL));
    assert!(!format!("{registry_error:?}").contains(SENTINEL));
    assert!(std::error::Error::source(&registry_error).is_none());

    cleanup_db(&pool).await;
}

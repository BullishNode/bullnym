use std::sync::Arc;
use std::time::Duration;

use object_store::memory::InMemory;
use object_store::path::Path as ObjectStorePath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use pay_service::chain_swap_creation_permit::{
    ChainSwapCreationPermit, ChainSwapCreationPermitError,
};
use pay_service::db::{self, ChainSwapManifestDelivery, NewChainSwapRecord, NewInvoice};
use pay_service::swap_manifest::EncryptedSwapManifestV1;
use pay_service::swap_manifest_runtime::RecoveryManifestRuntimeV1;
use pay_service::swap_manifest_store::{ManifestObjectId, RecoveryManifestStore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

static TEST_SERIAL: Mutex<()> = Mutex::const_new(());
const RECOVERY_ADDRESS: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

fn require_test_db() -> String {
    std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must be set for creation-permit integration tests")
}

async fn test_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(8)
        .connect(&require_test_db())
        .await
        .expect("connect creation-permit test database")
}

async fn cleanup(pool: &PgPool) {
    sqlx::query(
        "TRUNCATE chain_swap_manifest_deliveries, chain_swap_records, \
         recovery_address_commitments, invoices, users, public_names, \
         swap_key_allocations CASCADE",
    )
    .execute(pool)
    .await
    .expect("clean creation-permit fixtures");
}

fn memory_store(prefix: &str) -> (Arc<InMemory>, RecoveryManifestStore) {
    let backend = Arc::new(InMemory::new());
    let erased: Arc<dyn ObjectStore> = backend.clone();
    let store = RecoveryManifestStore::from_object_store_for_integration_tests(erased, prefix)
        .expect("valid in-memory manifest store");
    (backend, store)
}

fn memory_runtime(prefix: &str) -> (Arc<InMemory>, RecoveryManifestRuntimeV1) {
    let (backend, store) = memory_store(prefix);
    (
        backend,
        RecoveryManifestRuntimeV1::from_store_for_integration_tests(store),
    )
}

#[derive(Serialize)]
struct StructuralManifestEnvelope<'a> {
    ciphertext_hex: String,
    encryption_algorithm: &'a str,
    encryption_key_id: &'a str,
    format: &'a str,
    nonce_hex: String,
    signature_algorithm: &'a str,
    signer_xonly_public_key: &'a str,
    version: u16,
}

fn manifest_envelope(byte: u8) -> EncryptedSwapManifestV1 {
    let encoded = serde_json::to_string(&StructuralManifestEnvelope {
        ciphertext_hex: format!("{byte:02x}").repeat(16),
        encryption_algorithm: "xchacha20poly1305",
        encryption_key_id: "manifest-key-creation-permit-test",
        format: "bullnym-chain-swap-manifest",
        nonce_hex: format!("{:02x}", byte.wrapping_add(1)).repeat(24),
        signature_algorithm: "bip340-secp256k1-sha256",
        signer_xonly_public_key: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        version: 1,
    })
    .expect("serialize structural manifest envelope");
    EncryptedSwapManifestV1::parse(encoded).expect("parse structural manifest envelope")
}

async fn insert_invoice_fixture(pool: &PgPool, label: &str) -> (String, db::Invoice) {
    let suffix = Uuid::new_v4().simple().to_string();
    let nym = format!("{label}{}", &suffix[..10]);
    let npub = hex::encode(Sha256::digest(nym.as_bytes()));
    db::create_user(pool, &nym, &npub, "ct-permit-test")
        .await
        .expect("insert permit test user");

    let liquid_address = format!("lq1{nym}");
    let blinding_key = "12".repeat(32);
    let invoice = db::insert_invoice(
        pool,
        &NewInvoice {
            nym_owner: Some(&nym),
            public_slug: None,
            npub_owner: &npub,
            origin: "checkout",
            fiat_amount_minor: None,
            fiat_currency: None,
            amount_sat: 1_000,
            rate_minor_per_btc: None,
            rate_lock_secs: 3_600,
            memo: None,
            recipient_label: None,
            public_description: None,
            invoice_number: None,
            accept_btc: false,
            accept_ln: false,
            accept_liquid: true,
            bitcoin_address: None,
            liquid_address: Some(&liquid_address),
            liquid_blinding_key_hex: Some(&blinding_key),
            expires_in_secs: 3_600,
        },
    )
    .await
    .expect("insert permit test invoice");

    (nym, invoice)
}

async fn insert_legacy_manifestless_swap(pool: &PgPool) -> db::ChainSwapRecord {
    let (nym, invoice) = insert_invoice_fixture(pool, "legacypermit").await;
    let suffix = Uuid::new_v4().simple().to_string();

    let boltz_swap_id = format!("permit-{suffix}");
    let lockup_address = format!("bc1q{nym}");
    let preimage = "21".repeat(32);
    let claim_key = "22".repeat(32);
    let refund_key = "23".repeat(32);
    let mut tx = pool.begin().await.expect("begin legacy source fixture");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("isolate legacy source fixture from production triggers");
    let swap = db::record_chain_swap_in_tx(
        &mut tx,
        &NewChainSwapRecord {
            invoice_id: invoice.id,
            nym: Some(&nym),
            boltz_swap_id: &boltz_swap_id,
            lockup_address: &lockup_address,
            lockup_bip21: None,
            user_lock_amount_sat: 1_010,
            server_lock_amount_sat: 1_000,
            preimage_hex: &preimage,
            claim_key_hex: &claim_key,
            refund_key_hex: &refund_key,
            boltz_response_json: "{}",
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
        },
    )
    .await
    .expect("insert permit test chain swap");
    tx.commit().await.expect("commit permit source fixture");

    swap
}

fn fixture_sha256(label: &str, suffix: &str) -> String {
    hex::encode(Sha256::digest(format!("{label}:{suffix}").as_bytes()))
}

async fn insert_complete_manifestless_swap(pool: &PgPool) -> db::ChainSwapRecord {
    let (nym, invoice) = insert_invoice_fixture(pool, "completepermit").await;
    let npub = hex::encode(Sha256::digest(nym.as_bytes()));
    let recovery_address_commitment_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO recovery_address_commitments (\
             commitment_id, npub, contract_format_version, commitment_version, \
             canonical_btc_address, original_signature, signed_at_unix\
         ) VALUES ($1, $2, 1, 1, $3, $4, $5)",
    )
    .bind(recovery_address_commitment_id)
    .bind(&npub)
    .bind(RECOVERY_ADDRESS)
    .bind("84".repeat(64))
    .bind(1_700_100_084_i64)
    .execute(pool)
    .await
    .expect("insert complete permit recovery commitment");
    let suffix = Uuid::new_v4().simple().to_string();
    let root_fingerprint_hex = fixture_sha256("root", &suffix);
    let root_fingerprint = &root_fingerprint_hex[..16];
    let claim_public_key_hex = format!("02{}", fixture_sha256("claim-key", &suffix));
    let refund_public_key_hex = format!("03{}", fixture_sha256("refund-key", &suffix));
    let preimage_hash_hex = fixture_sha256("preimage", &suffix);
    let claim_allocation_id = db::reserve_swap_key_allocation(
        pool,
        &db::NewSwapKeyAllocation {
            root_fingerprint,
            key_epoch: 1,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            child_index: 100,
            purpose: db::SwapKeyPurpose::ChainClaim,
            public_key_hex: &claim_public_key_hex,
            preimage_hash_hex: Some(&preimage_hash_hex),
        },
    )
    .await
    .expect("reserve complete permit claim allocation");
    let refund_allocation_id = db::reserve_swap_key_allocation(
        pool,
        &db::NewSwapKeyAllocation {
            root_fingerprint,
            key_epoch: 1,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            child_index: 101,
            purpose: db::SwapKeyPurpose::ChainRefund,
            public_key_hex: &refund_public_key_hex,
            preimage_hash_hex: None,
        },
    )
    .await
    .expect("reserve complete permit refund allocation");

    let boltz_swap_id = format!("complete-permit-{suffix}");
    let lockup_address = format!("bc1qcompletepermit{suffix}");
    let lockup_bip21 = format!("bitcoin:{lockup_address}?amount=0.00001010");
    let canonical_response = format!(r#"{{"id":"{boltz_swap_id}"}}"#);
    let preimage = fixture_sha256("private-preimage", &suffix);
    let claim_key = fixture_sha256("private-claim", &suffix);
    let refund_key = fixture_sha256("private-refund", &suffix);
    let pinned_pair_hash = fixture_sha256("pair", &suffix);
    let canonical_pair_quote_json = format!(r#"{{"hash":"{pinned_pair_hash}"}}"#);
    let creation_response_sha256 = hex::encode(Sha256::digest(canonical_response.as_bytes()));
    let btc_claim_script_sha256 = fixture_sha256("btc-claim", &suffix);
    let btc_refund_script_sha256 = fixture_sha256("btc-refund", &suffix);
    let liquid_claim_script_sha256 = fixture_sha256("liquid-claim", &suffix);
    let liquid_refund_script_sha256 = fixture_sha256("liquid-refund", &suffix);
    let liquid_asset_id = fixture_sha256("asset", &suffix);
    let merchant_liquid_destination = format!("lq1completepermit{suffix}");

    db::record_chain_swap_with_lineage_and_creation_evidence(
        pool,
        &NewChainSwapRecord {
            invoice_id: invoice.id,
            nym: Some(&nym),
            boltz_swap_id: &boltz_swap_id,
            lockup_address: &lockup_address,
            lockup_bip21: Some(&lockup_bip21),
            user_lock_amount_sat: 1_010,
            server_lock_amount_sat: 1_000,
            preimage_hex: &preimage,
            claim_key_hex: &claim_key,
            refund_key_hex: &refund_key,
            boltz_response_json: &canonical_response,
            claim_key_index: Some(100),
            refund_key_index: Some(101),
            root_fingerprint: Some(root_fingerprint),
        },
        &db::ChainSwapLineage {
            claim_allocation_id,
            refund_allocation_id,
            key_epoch: 1,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &claim_public_key_hex,
            refund_public_key_hex: &refund_public_key_hex,
            preimage_hash_hex: &preimage_hash_hex,
        },
        &db::NewChainSwapCreationEvidence {
            creation_terms: db::NewChainSwapCreationTerms {
                pinned_pair_hash: &pinned_pair_hash,
                canonical_pair_quote_json: &canonical_pair_quote_json,
                creation_response_sha256: &creation_response_sha256,
                btc_claim_script_sha256: &btc_claim_script_sha256,
                btc_refund_script_sha256: &btc_refund_script_sha256,
                liquid_claim_script_sha256: &liquid_claim_script_sha256,
                liquid_refund_script_sha256: &liquid_refund_script_sha256,
                btc_timeout_height: 900_000,
                liquid_timeout_height: 3_000_000,
                btc_network: "bitcoin",
                liquid_network: "liquid",
                liquid_asset_id: &liquid_asset_id,
                merchant_liquid_destination: &merchant_liquid_destination,
                merchant_emergency_btc_address: Some(RECOVERY_ADDRESS),
            },
            recovery_address_commitment_id: Some(recovery_address_commitment_id),
        },
    )
    .await
    .expect("insert complete manifest-less chain swap")
}

async fn insert_pending_delivery_for_swap(
    pool: &PgPool,
    chain_swap_id: Uuid,
    byte: u8,
) -> ChainSwapManifestDelivery {
    let envelope = manifest_envelope(byte);
    let mut tx = pool.begin().await.expect("begin pending delivery fixture");
    let reservation = db::lock_manifest_delivery_tail(&mut tx)
        .await
        .expect("reserve manifest delivery tail");
    let identity = reservation
        .identity(Uuid::new_v4(), chain_swap_id)
        .expect("build manifest delivery identity");
    let delivery = db::insert_manifest_delivery(&mut tx, &identity, &envelope)
        .await
        .expect("insert pending manifest delivery");
    tx.commit().await.expect("commit pending delivery fixture");
    delivery
}

async fn insert_pending_delivery(pool: &PgPool, byte: u8) -> ChainSwapManifestDelivery {
    let swap = insert_legacy_manifestless_swap(pool).await;
    insert_pending_delivery_for_swap(pool, swap.id, byte).await
}

async fn pending_state(pool: &PgPool, manifest_id: Uuid) -> String {
    db::get_manifest_delivery(pool, manifest_id)
        .await
        .expect("read manifest delivery")
        .expect("manifest delivery exists")
        .delivery_state
}

async fn acquire_after_drop(
    pool: &PgPool,
    runtime: &RecoveryManifestRuntimeV1,
) -> ChainSwapCreationPermit {
    match acquire_after_session_release(pool, runtime).await {
        Ok(permit) => permit,
        Err(error) => panic!("unexpected permit acquisition failure: {error}"),
    }
}

async fn acquire_after_session_release(
    pool: &PgPool,
    runtime: &RecoveryManifestRuntimeV1,
) -> Result<ChainSwapCreationPermit, ChainSwapCreationPermitError> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match ChainSwapCreationPermit::acquire(pool, runtime).await {
                result @ Ok(_) => return result,
                Err(ChainSwapCreationPermitError::Busy) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                error @ Err(_) => return error,
            }
        }
    })
    .await
    .expect("dropped session lock was not released")
}

#[tokio::test]
#[ignore = "requires a disposable migrated PostgreSQL database"]
async fn creation_permit_is_globally_mutually_exclusive() {
    let _serial = TEST_SERIAL.lock().await;
    let pool = test_pool().await;
    cleanup(&pool).await;
    let (_, runtime) = memory_runtime(&format!("bullnym/permit/{}", Uuid::new_v4()));

    let first = ChainSwapCreationPermit::acquire(&pool, &runtime)
        .await
        .expect("first creation permit");
    assert_eq!(
        ChainSwapCreationPermit::acquire(&pool, &runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::Busy
    );
    first.release().await.expect("explicit permit release");

    let next = ChainSwapCreationPermit::acquire(&pool, &runtime)
        .await
        .expect("permit after explicit release");
    next.release().await.expect("release next permit");
    cleanup(&pool).await;
}

#[tokio::test]
#[ignore = "requires a disposable migrated PostgreSQL database"]
async fn dropping_permit_closes_session_and_releases_lock() {
    let _serial = TEST_SERIAL.lock().await;
    let pool = test_pool().await;
    cleanup(&pool).await;
    let (_, runtime) = memory_runtime(&format!("bullnym/permit/{}", Uuid::new_v4()));

    let permit = ChainSwapCreationPermit::acquire(&pool, &runtime)
        .await
        .expect("initial creation permit");
    drop(permit);
    let next = acquire_after_drop(&pool, &runtime).await;
    next.release().await.expect("release permit after drop");
    cleanup(&pool).await;
}

#[tokio::test]
#[ignore = "requires a disposable migrated PostgreSQL database"]
async fn complete_manifestless_swap_is_repaired_and_releases_session_lock() {
    let _serial = TEST_SERIAL.lock().await;
    let pool = test_pool().await;
    cleanup(&pool).await;
    let swap = insert_complete_manifestless_swap(&pool).await;
    let (_, runtime) = memory_runtime(&format!("bullnym/permit/{}", Uuid::new_v4()));

    assert!(db::has_manifestless_complete_chain_swap(&pool)
        .await
        .expect("probe complete manifest-less row"));
    assert_eq!(
        ChainSwapCreationPermit::acquire(&pool, &runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::ManifestRepairCompleted
    );
    assert_eq!(
        db::get_chain_swap_by_id(&pool, swap.id)
            .await
            .expect("read retained complete row")
            .expect("complete row remains")
            .status,
        "pending"
    );

    assert!(!db::has_manifestless_complete_chain_swap(&pool)
        .await
        .expect("probe repaired manifest obligation"));
    let permit = acquire_after_drop(&pool, &runtime).await;
    permit.release().await.expect("release post-repair permit");
    cleanup(&pool).await;
}

#[tokio::test]
#[ignore = "requires a disposable migrated PostgreSQL database"]
async fn legacy_manifestless_swap_is_structurally_nonblocking() {
    let _serial = TEST_SERIAL.lock().await;
    let pool = test_pool().await;
    cleanup(&pool).await;
    let legacy = insert_legacy_manifestless_swap(&pool).await;
    let (_, runtime) = memory_runtime(&format!("bullnym/permit/{}", Uuid::new_v4()));

    assert!(legacy.creation_terms.is_none());
    assert!(!db::has_manifestless_complete_chain_swap(&pool)
        .await
        .expect("probe legacy manifest-less row"));
    let permit = ChainSwapCreationPermit::acquire(&pool, &runtime)
        .await
        .expect("legacy row must not block new creation");
    permit.release().await.expect("release legacy-row permit");
    cleanup(&pool).await;
}

#[tokio::test]
#[ignore = "requires a disposable migrated PostgreSQL database"]
async fn complete_manifestless_repair_delivers_one_exact_ledger_obligation() {
    let _serial = TEST_SERIAL.lock().await;
    let pool = test_pool().await;
    cleanup(&pool).await;
    let swap = insert_complete_manifestless_swap(&pool).await;
    let (_, runtime) = memory_runtime(&format!("bullnym/permit/{}", Uuid::new_v4()));

    assert_eq!(
        ChainSwapCreationPermit::acquire(&pool, &runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::ManifestRepairCompleted
    );
    let deliveries = db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .expect("read repaired manifest delivery");
    assert_eq!(deliveries.len(), 1);
    let delivery = &deliveries[0];
    assert_eq!(delivery.chain_swap_id, swap.id);
    assert_eq!(delivery.delivery_state, "delivered");
    assert!(!db::has_manifestless_complete_chain_swap(&pool)
        .await
        .expect("probe resolved manifest obligation"));
    let object_id = ManifestObjectId::new(swap.id, delivery.manifest_id)
        .expect("valid recovered object identity");
    assert_eq!(
        runtime
            .store()
            .get_v1(object_id)
            .await
            .expect("read recovered manifest object")
            .encoded(),
        delivery.encrypted_envelope().encoded()
    );
    let permit = acquire_after_drop(&pool, &runtime).await;
    permit
        .release()
        .await
        .expect("release recovered creation permit");
    cleanup(&pool).await;
}

#[tokio::test]
#[ignore = "requires a disposable migrated PostgreSQL database"]
async fn pending_manifest_is_resumed_without_returning_a_same_attempt_permit() {
    let _serial = TEST_SERIAL.lock().await;
    let pool = test_pool().await;
    cleanup(&pool).await;
    let delivery = insert_pending_delivery(&pool, 0x41).await;
    assert_eq!(pending_state(&pool, delivery.manifest_id).await, "pending");
    let (_, runtime) = memory_runtime(&format!("bullnym/permit/{}", Uuid::new_v4()));

    assert_eq!(
        ChainSwapCreationPermit::acquire(&pool, &runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::ManifestRepairCompleted
    );
    assert_eq!(
        pending_state(&pool, delivery.manifest_id).await,
        "delivered"
    );
    let object_id = ManifestObjectId::new(delivery.chain_swap_id, delivery.manifest_id)
        .expect("valid delivery object identity");
    assert_eq!(
        runtime
            .store()
            .get_v1(object_id)
            .await
            .expect("read resumed manifest")
            .encoded(),
        delivery.encrypted_envelope().encoded()
    );
    let permit = acquire_after_drop(&pool, &runtime).await;
    permit.release().await.expect("release subsequent permit");
    cleanup(&pool).await;
}

#[tokio::test]
#[ignore = "requires a disposable migrated PostgreSQL database"]
async fn storage_failure_leaves_pending_and_refuses_permit() {
    let _serial = TEST_SERIAL.lock().await;
    let pool = test_pool().await;
    cleanup(&pool).await;
    let delivery = insert_pending_delivery(&pool, 0x51).await;
    let (backend, failing_runtime) = memory_runtime(&format!("bullnym/permit/{}", Uuid::new_v4()));
    let object_id = ManifestObjectId::new(delivery.chain_swap_id, delivery.manifest_id)
        .expect("valid delivery object identity");
    backend
        .put(
            &ObjectStorePath::from(failing_runtime.store().object_key_v1(object_id)),
            PutPayload::from("pre-existing-invalid-object"),
        )
        .await
        .expect("seed conflicting object");

    assert_eq!(
        ChainSwapCreationPermit::acquire(&pool, &failing_runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::PendingDeliveryFailed
    );
    assert_eq!(pending_state(&pool, delivery.manifest_id).await, "pending");

    // The failed acquisition must also close its lock-holding session.
    let (_, recovery_runtime) = memory_runtime(&format!("bullnym/permit/{}", Uuid::new_v4()));
    assert_eq!(
        acquire_after_session_release(&pool, &recovery_runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::ManifestRepairCompleted
    );
    assert_eq!(
        pending_state(&pool, delivery.manifest_id).await,
        "delivered"
    );
    let permit = acquire_after_drop(&pool, &recovery_runtime).await;
    permit.release().await.expect("release subsequent permit");
    cleanup(&pool).await;
}

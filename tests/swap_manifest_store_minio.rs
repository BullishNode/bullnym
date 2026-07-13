//! Opt-in contract test for the real S3 adapter against disposable MinIO.
//!
//! Run through `scripts/test-swap-manifest-store-minio.sh`; the ordinary test
//! suite compiles this target but never reaches an external endpoint.

use std::sync::Arc;

use pay_service::swap_manifest::EncryptedSwapManifestV1;
use pay_service::swap_manifest_store::{
    ManifestObjectId, ManifestStoreError, ManifestWriteOutcome, RecoveryManifestStore,
    S3ManifestCredentials, S3ManifestStoreConfig,
};
use serde::Serialize;
use tokio::sync::Barrier;
use uuid::Uuid;

const ENDPOINT_ENV: &str = "BULLNYM_MINIO_ENDPOINT";
const BUCKET_ENV: &str = "BULLNYM_MINIO_BUCKET";
const ACCESS_KEY_ENV: &str = "BULLNYM_MINIO_ACCESS_KEY";
const SECRET_KEY_ENV: &str = "BULLNYM_MINIO_SECRET_KEY";

#[derive(Serialize)]
struct StructuralEnvelope<'a> {
    ciphertext_hex: String,
    encryption_algorithm: &'a str,
    encryption_key_id: &'a str,
    format: &'a str,
    nonce_hex: String,
    signature_algorithm: &'a str,
    signer_xonly_public_key: &'a str,
    version: u16,
}

fn required_env(name: &'static str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} must be supplied by scripts/test-swap-manifest-store-minio.sh")
    })
}

fn id(number: u128) -> ManifestObjectId {
    ManifestObjectId::new(Uuid::from_u128(number), Uuid::from_u128(number + 10_000)).unwrap()
}

fn manifest(byte: u8) -> EncryptedSwapManifestV1 {
    let encoded = serde_json::to_string(&StructuralEnvelope {
        ciphertext_hex: format!("{byte:02x}").repeat(16),
        encryption_algorithm: "xchacha20poly1305",
        encryption_key_id: "manifest-key-minio-test",
        format: "bullnym-chain-swap-manifest",
        nonce_hex: format!("{:02x}", byte.wrapping_add(1)).repeat(24),
        signature_algorithm: "bip340-secp256k1-sha256",
        signer_xonly_public_key: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        version: 1,
    })
    .unwrap();
    EncryptedSwapManifestV1::parse(encoded).unwrap()
}

fn config(
    endpoint: &str,
    bucket: &str,
    prefix: &str,
    access_key: &str,
    secret_key: &str,
) -> S3ManifestStoreConfig {
    S3ManifestStoreConfig::new(
        endpoint,
        "us-east-1",
        bucket,
        prefix,
        true,
        true,
        S3ManifestCredentials::new(access_key, secret_key, None),
    )
}

async fn put_after_barrier(
    store: RecoveryManifestStore,
    start: Arc<Barrier>,
    object_id: ManifestObjectId,
    manifest: EncryptedSwapManifestV1,
) -> Result<ManifestWriteOutcome, ManifestStoreError> {
    start.wait().await;
    store.put_v1(object_id, &manifest).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the disposable MinIO harness"]
async fn minio_exercises_manifest_store_contract_and_redaction() {
    let endpoint = required_env(ENDPOINT_ENV);
    let bucket = required_env(BUCKET_ENV);
    let access_key = required_env(ACCESS_KEY_ENV);
    let secret_key = required_env(SECRET_KEY_ENV);
    let prefix = format!("bullnym/integration/{}", Uuid::new_v4());

    let store_config = config(&endpoint, &bucket, &prefix, &access_key, &secret_key);
    let config_debug = format!("{store_config:?}");
    for forbidden in [&endpoint, &access_key, &secret_key] {
        assert!(!config_debug.contains(forbidden));
    }
    let store = RecoveryManifestStore::from_s3(store_config).unwrap();

    let first_id = id(1);
    let first = manifest(0x11);
    let different = manifest(0x22);
    assert_eq!(
        store.put_v1(first_id, &first).await.unwrap(),
        ManifestWriteOutcome::Created
    );
    assert_eq!(
        store.get_v1(first_id).await.unwrap().encoded(),
        first.encoded()
    );
    assert_eq!(
        store.put_v1(first_id, &first).await.unwrap(),
        ManifestWriteOutcome::AlreadyPresent
    );
    assert!(matches!(
        store.put_v1(first_id, &different).await,
        Err(ManifestStoreError::Conflict { id, .. }) if id == first_id
    ));
    assert_eq!(
        store.get_v1(first_id).await.unwrap().encoded(),
        first.encoded()
    );

    let second_id = id(2);
    let third_id = id(3);
    store.put_v1(second_id, &manifest(0x33)).await.unwrap();
    store.put_v1(third_id, &manifest(0x44)).await.unwrap();

    let first_page = store.list_v1(2).await.unwrap();
    assert_eq!(
        first_page
            .objects
            .iter()
            .map(|object| object.id)
            .collect::<Vec<_>>(),
        vec![first_id, second_id]
    );
    assert!(first_page.truncated);
    assert_eq!(first_page.next_after, Some(second_id));

    let final_page = store.list_v1_after(first_page.next_after, 2).await.unwrap();
    assert_eq!(
        final_page
            .objects
            .iter()
            .map(|object| object.id)
            .collect::<Vec<_>>(),
        vec![third_id]
    );
    assert!(!final_page.truncated);
    assert_eq!(final_page.next_after, None);

    // Use a fresh sub-prefix so both races target objects that cannot exist
    // before these synchronized writes begin.
    let race_prefix = format!("{prefix}/races/{}", Uuid::new_v4());
    let race_store = RecoveryManifestStore::from_s3(config(
        &endpoint,
        &bucket,
        &race_prefix,
        &access_key,
        &secret_key,
    ))
    .unwrap();

    let identical_id = id(4);
    let identical = manifest(0x55);
    let identical_start = Arc::new(Barrier::new(2));
    let identical_left = tokio::spawn(put_after_barrier(
        race_store.clone(),
        Arc::clone(&identical_start),
        identical_id,
        identical.clone(),
    ));
    let identical_right = tokio::spawn(put_after_barrier(
        race_store.clone(),
        identical_start,
        identical_id,
        identical.clone(),
    ));
    let (identical_left, identical_right) = tokio::join!(identical_left, identical_right);
    let identical_results = [identical_left.unwrap(), identical_right.unwrap()];
    assert_eq!(
        identical_results
            .iter()
            .filter(|result| { matches!(result.as_ref(), Ok(ManifestWriteOutcome::Created)) })
            .count(),
        1,
        "identical MinIO race must create exactly once: {identical_results:?}"
    );
    assert_eq!(
        identical_results
            .iter()
            .filter(|result| {
                matches!(result.as_ref(), Ok(ManifestWriteOutcome::AlreadyPresent))
            })
            .count(),
        1,
        "identical MinIO race must make the retry idempotent: {identical_results:?}"
    );
    assert_eq!(
        race_store.get_v1(identical_id).await.unwrap().encoded(),
        identical.encoded()
    );

    let differing_id = id(5);
    let differing_left = manifest(0x66);
    let differing_right = manifest(0x77);
    let differing_start = Arc::new(Barrier::new(2));
    let left_task = tokio::spawn(put_after_barrier(
        race_store.clone(),
        Arc::clone(&differing_start),
        differing_id,
        differing_left.clone(),
    ));
    let right_task = tokio::spawn(put_after_barrier(
        race_store.clone(),
        differing_start,
        differing_id,
        differing_right.clone(),
    ));
    let (left_result, right_result) = tokio::join!(left_task, right_task);
    let left_result = left_result.unwrap();
    let right_result = right_result.unwrap();
    let (winner, loser) = match (&left_result, &right_result) {
        (Ok(ManifestWriteOutcome::Created), Err(ManifestStoreError::Conflict { id, .. }))
            if *id == differing_id =>
        {
            (&differing_left, &differing_right)
        }
        (Err(ManifestStoreError::Conflict { id, .. }), Ok(ManifestWriteOutcome::Created))
            if *id == differing_id =>
        {
            (&differing_right, &differing_left)
        }
        results => {
            panic!("differing MinIO race must yield exactly Created + Conflict: {results:?}")
        }
    };
    let stored_after_race = race_store.get_v1(differing_id).await.unwrap();
    assert_eq!(stored_after_race.encoded(), winner.encoded());
    assert_ne!(stored_after_race.encoded(), loser.encoded());
    let bytes_before_conflicting_retry = stored_after_race.into_encoded();
    assert!(matches!(
        race_store.put_v1(differing_id, loser).await,
        Err(ManifestStoreError::Conflict { id, .. }) if id == differing_id
    ));
    assert_eq!(
        race_store.get_v1(differing_id).await.unwrap().encoded(),
        bytes_before_conflicting_retry
    );

    let wrong_access_key = format!("{access_key}-wrong");
    let wrong_secret_key = format!("{secret_key}-wrong");
    let rejected_config = config(
        &endpoint,
        &bucket,
        &prefix,
        &wrong_access_key,
        &wrong_secret_key,
    );
    let rejected_debug = format!("{rejected_config:?}");
    for forbidden in [&endpoint, &wrong_access_key, &wrong_secret_key] {
        assert!(!rejected_debug.contains(forbidden));
    }
    let rejected_store = RecoveryManifestStore::from_s3(rejected_config).unwrap();
    let error = rejected_store.get_v1(first_id).await.unwrap_err();
    assert!(matches!(
        error,
        ManifestStoreError::Authentication { operation: "get" }
    ));
    let public_error = format!("{error:?} {error}");
    for forbidden in [
        &endpoint,
        &access_key,
        &secret_key,
        &wrong_access_key,
        &wrong_secret_key,
    ] {
        assert!(!public_error.contains(forbidden));
    }
}

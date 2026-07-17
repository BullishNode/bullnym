use super::*;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

#[test]
fn signing_message_is_fixed_nul_separated_bytes() {
    let npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let message = build_signing_message(
        STORE_ACTION,
        BackupStream::WalletMetadata,
        npub,
        1,
        None,
        Some("ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc"),
        4,
        1_700_000_000,
    );
    assert_eq!(message.iter().filter(|&&byte| byte == 0).count(), 8);
    let expected = concat!(
        "bullbitcoin-wallet-backup-v1\0backup-store\0wallet_metadata\0",
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\0",
        "1\0\0ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc\0",
        "4\01700000000"
    );
    assert_eq!(message, expected.as_bytes());
}

#[test]
fn etag_is_domain_separated_and_deterministic() {
    let npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let hash = "ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc";
    let first = compute_etag(BackupStream::WalletMetadata, npub, 1, Some(hash));
    let second = compute_etag(BackupStream::WalletMetadata, npub, 1, Some(hash));
    assert_eq!(first, second);
    assert_ne!(
        first,
        compute_etag(BackupStream::KeychainManifest, npub, 1, Some(hash))
    );
    assert_ne!(
        first,
        compute_etag(BackupStream::WalletMetadata, npub, 2, Some(hash))
    );
    assert_ne!(
        first,
        compute_etag(BackupStream::WalletMetadata, npub, 1, None)
    );
}

#[test]
fn canonical_hex_rejects_uppercase_and_wrong_lengths() {
    assert!(decode_canonical_hex::<32>(&"ab".repeat(32), "invalid").is_ok());
    assert!(decode_canonical_hex::<32>(&"AB".repeat(32), "invalid").is_err());
    assert!(decode_canonical_hex::<32>(&"ab".repeat(31), "invalid").is_err());
}

#[test]
fn stream_json_is_closed_and_stable() {
    assert_eq!(
        serde_json::to_string(&BackupStream::KeychainManifest).unwrap(),
        "\"keychain_manifest\""
    );
    assert_eq!(
        serde_json::from_str::<BackupStream>("\"wallet_metadata\"").unwrap(),
        BackupStream::WalletMetadata
    );
    assert!(serde_json::from_str::<BackupStream>("\"arbitrary\"").is_err());
}

#[test]
fn request_shapes_reject_unknown_fields() {
    let request = serde_json::json!({
        "version": 1,
        "stream": "wallet_metadata",
        "npub": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "timestamp": 1_700_000_000u64,
        "signature": "00".repeat(64),
        "unexpected": true
    });
    assert!(serde_json::from_value::<FetchRequest>(request).is_err());
}

#[test]
fn store_requires_explicit_nullable_expected_etag() {
    let mut request = serde_json::json!({
        "version": 1,
        "stream": "wallet_metadata",
        "npub": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "generation": 1,
        "expected_etag": null,
        "ciphertext": "AA==",
        "ciphertext_sha256": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "ciphertext_bytes": 1,
        "timestamp": 1_700_000_000u64,
        "signature": "00".repeat(64)
    });
    assert!(serde_json::from_value::<StoreRequest>(request.clone()).is_ok());
    request.as_object_mut().unwrap().remove("expected_etag");
    assert!(serde_json::from_value::<StoreRequest>(request).is_err());
}

#[test]
fn exact_decoded_limit_is_two_mebibytes() {
    assert_eq!(MAX_CIPHERTEXT_BYTES, 2_097_152);
    assert!(BASE64_STANDARD
        .decode(BASE64_STANDARD.encode(vec![0u8; MAX_CIPHERTEXT_BYTES]))
        .is_ok());
}

#[test]
fn router_combines_store_and_delete_methods() {
    let _router = router();
}

#[test]
fn success_and_error_responses_disable_caching() {
    let success = private_no_store(Json(json!({"status": "ok"})).into_response());
    assert_eq!(
        success.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store, max-age=0"
    );
    assert_eq!(success.headers().get(header::PRAGMA).unwrap(), "no-cache");

    let error = WalletBackupError::Authentication.into_response();
    assert_eq!(
        error.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store, max-age=0"
    );
    assert_eq!(error.headers().get(header::PRAGMA).unwrap(), "no-cache");
}

#[test]
fn shared_contract_fixture_matches_rust_codec_and_bip340() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/wallet-backup-v1.json")).unwrap();
    let npub = fixture["npub"].as_str().unwrap();
    let secret = SecretKey::from_slice(
        &hex::decode(fixture["test_only_secret_key"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    assert_eq!(keypair.x_only_public_key().0.to_string(), npub);

    for vector in fixture["vectors"].as_array().unwrap() {
        let stream = match vector["stream"].as_str().unwrap() {
            "keychain_manifest" => BackupStream::KeychainManifest,
            "wallet_metadata" => BackupStream::WalletMetadata,
            other => panic!("unexpected fixture stream: {other}"),
        };
        let generation = vector["generation"].as_u64().unwrap();
        let expected_etag = vector["expected_etag"].as_str();
        let ciphertext_hash = vector["ciphertext_sha256"].as_str();
        let ciphertext_bytes = vector["ciphertext_bytes"].as_u64().unwrap();
        let timestamp = vector["timestamp"].as_u64().unwrap();
        let message = build_signing_message(
            vector["action"].as_str().unwrap(),
            stream,
            npub,
            generation,
            expected_etag,
            ciphertext_hash,
            ciphertext_bytes,
            timestamp,
        );
        assert_eq!(hex::encode(&message), vector["signed_message_hex"]);
        let digest = Sha256::digest(&message);
        assert_eq!(hex::encode(digest), vector["signed_message_sha256"]);

        let signature = vector["signature"].as_str().unwrap();
        auth::verify_signature(npub, &message, signature).unwrap();
        let deterministic_signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest.into()), &keypair);
        assert_eq!(deterministic_signature.to_string(), signature);

        if generation > 0 {
            assert_eq!(
                hex::encode(compute_etag(stream, npub, generation, ciphertext_hash)),
                vector["result_etag"]
            );
        }
        if let Some(ciphertext) = vector["ciphertext"].as_str() {
            let decoded = BASE64_STANDARD.decode(ciphertext).unwrap();
            assert_eq!(decoded.len() as u64, ciphertext_bytes);
            assert_eq!(
                hex::encode(Sha256::digest(decoded)),
                ciphertext_hash.unwrap()
            );
        }
    }

    let initial = &fixture["vectors"][2];
    let tampered = build_signing_message(
        DELETE_ACTION,
        BackupStream::WalletMetadata,
        npub,
        initial["generation"].as_u64().unwrap(),
        None,
        initial["ciphertext_sha256"].as_str(),
        initial["ciphertext_bytes"].as_u64().unwrap(),
        initial["timestamp"].as_u64().unwrap(),
    );
    assert!(
        auth::verify_signature(npub, &tampered, initial["signature"].as_str().unwrap()).is_err()
    );
}

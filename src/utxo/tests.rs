use super::*;
use lwk_wollet::elements::hashes::Hash;
use secp256k1::SecretKey;
use serde_json::json;

fn test_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    (sk, pk)
}

fn sign(tag: &[u8], nym: &str, outpoint: &str, sk: &SecretKey) -> String {
    let secp = Secp256k1::signing_only();
    let digest = ownership_message_digest(tag, nym, outpoint);
    let msg = Message::from_digest(digest);
    hex::encode(secp.sign_ecdsa(&msg, sk).serialize_der())
}

#[test]
fn digest_is_deterministic() {
    let a = ownership_message_digest(b"tag", "alice", "ab:0");
    let b = ownership_message_digest(b"tag", "alice", "ab:0");
    assert_eq!(a, b);
}

#[test]
fn digest_differs_per_nym() {
    let a = ownership_message_digest(b"tag", "alice", "ab:0");
    let b = ownership_message_digest(b"tag", "bob", "ab:0");
    assert_ne!(a, b);
}

#[test]
fn digest_differs_per_outpoint() {
    let a = ownership_message_digest(b"tag", "alice", "ab:0");
    let b = ownership_message_digest(b"tag", "alice", "ab:1");
    assert_ne!(a, b);
}

#[test]
fn valid_sig_verifies() {
    let (sk, pk) = test_keypair();
    let sig = sign(b"bullpay-lnurlp-v1", "alice", "ab:0", &sk);
    let got = verify_ownership_sig(
        b"bullpay-lnurlp-v1",
        "alice",
        "ab:0",
        &hex::encode(pk.serialize()),
        &sig,
    );
    assert!(got.is_ok());
}

#[test]
fn sig_for_different_nym_fails() {
    let (sk, pk) = test_keypair();
    let sig = sign(b"tag", "alice", "ab:0", &sk);
    let got = verify_ownership_sig(b"tag", "bob", "ab:0", &hex::encode(pk.serialize()), &sig);
    assert!(matches!(got, Err(AppError::ProofOfFundsInvalid(_))));
}

#[test]
fn sig_for_different_outpoint_fails() {
    let (sk, pk) = test_keypair();
    let sig = sign(b"tag", "alice", "ab:0", &sk);
    let got = verify_ownership_sig(b"tag", "alice", "ab:1", &hex::encode(pk.serialize()), &sig);
    assert!(matches!(got, Err(AppError::ProofOfFundsInvalid(_))));
}

#[test]
fn sig_malformed_fails() {
    let (_, pk) = test_keypair();
    let got = verify_ownership_sig(
        b"tag",
        "alice",
        "ab:0",
        &hex::encode(pk.serialize()),
        "notahex",
    );
    assert!(matches!(got, Err(AppError::ProofOfFundsInvalid(_))));
}

#[test]
fn script_match_p2wpkh() {
    let (_, pk) = test_keypair();
    let hash = hash160::Hash::hash(&pk.serialize());
    let wpkh = elements::WPubkeyHash::from_raw_hash(hash);
    let script = elements::Script::new_v0_wpkh(&wpkh);
    assert!(script_matches_pubkey(&script, &pk));
}

#[test]
fn script_mismatch_different_pubkey() {
    let (_, pk_a) = test_keypair();
    let sk_b = SecretKey::from_slice(&[8u8; 32]).unwrap();
    let pk_b = PublicKey::from_secret_key(&Secp256k1::new(), &sk_b);
    let hash = hash160::Hash::hash(&pk_a.serialize());
    let wpkh = elements::WPubkeyHash::from_raw_hash(hash);
    let script = elements::Script::new_v0_wpkh(&wpkh);
    assert!(!script_matches_pubkey(&script, &pk_b));
}

#[test]
fn parse_outpoint_ok() {
    let o = ParsedOutpoint::parse(
        "0000000000000000000000000000000000000000000000000000000000000001:42",
    )
    .unwrap();
    assert_eq!(o.vout, 42);
}

#[test]
fn parse_outpoint_missing_colon() {
    assert!(ParsedOutpoint::parse("abcdef").is_err());
}

#[test]
fn parse_outpoint_bad_txid_len() {
    assert!(ParsedOutpoint::parse("ab:0").is_err());
}

#[test]
fn history_txids_extracts_hashes() {
    let value = json!([
        {"tx_hash": "a", "height": 0},
        {"tx_hash": "b", "height": 10}
    ]);
    assert_eq!(history_txids(&value).unwrap(), vec!["a", "b"]);
}

#[test]
fn history_txids_rejects_malformed_shape() {
    assert!(matches!(
        history_txids(&json!({"tx_hash": "a"})),
        Err(AppError::ElectrumError(_))
    ));
    assert!(matches!(
        history_txids(&json!([{"height": 1}])),
        Err(AppError::ElectrumError(_))
    ));
}

/// Build a confidential L-BTC output of `value` sat payable to a fresh
/// blinding keypair, returning the output and the blinding secret key hex the
/// payer would supply. Uses the same elements blinding primitives the wallet
/// uses to fund outputs.
fn confidential_lbtc_output(value: u64) -> (elements::TxOut, String) {
    use lwk_wollet::elements;
    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let mut rng = secp256k1::rand::thread_rng();

    // Receiver (payer) blinding keypair — its secret key unblinds the output.
    let bsk = secp256k1::SecretKey::new(&mut rng);
    let bpk = secp256k1::PublicKey::from_secret_key(&secp, &bsk);

    let spk = elements::Script::new_v0_wpkh(&elements::WPubkeyHash::from_raw_hash(
        hash160::Hash::hash(&[9u8; 33]),
    ));
    let lbtc = elements::AssetId::from_str(crate::invoice::LIQUID_BTC_ASSET_ID).unwrap();

    // A spent-input secret of the same asset so the surjection proof (asset
    // provenance) can be built; value matches so the last-output blinding
    // balances.
    let in_secrets = elements::TxOutSecrets::new(
        lbtc,
        elements::confidential::AssetBlindingFactor::new(&mut rng),
        value,
        elements::confidential::ValueBlindingFactor::new(&mut rng),
    );

    let (txout, _abf, _vbf, _eph) = elements::TxOut::new_last_confidential(
        &mut rng,
        &secp,
        value,
        lbtc,
        spk,
        bpk,
        &[in_secrets],
        &[],
    )
    .expect("build confidential output");

    (txout, hex::encode(bsk.secret_bytes()))
}

#[test]
fn proof_value_passes_when_at_or_above_floor() {
    let (txout, bk) = confidential_lbtc_output(5000);
    let got =
        assert_proof_utxo_value(&txout, &bk, crate::invoice::LIQUID_BTC_ASSET_ID, 1000).unwrap();
    assert_eq!(got, 5000, "unblind recovers the true value");
}

#[test]
fn proof_value_rejects_below_floor() {
    // A dust output must not satisfy the anti-enumeration floor (DG-7).
    let (txout, bk) = confidential_lbtc_output(500);
    assert!(matches!(
        assert_proof_utxo_value(&txout, &bk, crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_wrong_asset() {
    let (txout, bk) = confidential_lbtc_output(5000);
    let not_lbtc = "0000000000000000000000000000000000000000000000000000000000000001";
    assert!(matches!(
        assert_proof_utxo_value(&txout, &bk, not_lbtc, 1000),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_wrong_blinding_key() {
    // A blinding key that does not match the output cannot rewind the
    // rangeproof, so the value can never be forged past the floor.
    let (txout, _bk) = confidential_lbtc_output(5000);
    let mut rng = secp256k1::rand::thread_rng();
    let wrong = hex::encode(secp256k1::SecretKey::new(&mut rng).secret_bytes());
    assert!(matches!(
        assert_proof_utxo_value(&txout, &wrong, crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_malformed_blinding_key() {
    let (txout, _bk) = confidential_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(&txout, "notahex", crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn transaction_spends_exact_outpoint_only() {
    let target = elements::Txid::from_slice(&[1u8; 32]).unwrap();
    let other = elements::Txid::from_slice(&[2u8; 32]).unwrap();
    let tx = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: elements::OutPoint::new(target, 7),
            is_pegin: false,
            script_sig: elements::Script::new(),
            sequence: elements::Sequence::MAX,
            asset_issuance: elements::AssetIssuance::default(),
            witness: elements::TxInWitness::default(),
        }],
        output: vec![],
    };

    assert!(transaction_spends_outpoint(&tx, &target.to_string(), 7));
    assert!(!transaction_spends_outpoint(&tx, &target.to_string(), 8));
    assert!(!transaction_spends_outpoint(&tx, &other.to_string(), 7));
}

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

/// Build a confidential L-BTC output of `value` sat, returning the output plus
/// the elements value/asset blinding factors as display-order hex — exactly the
/// form an Approach-B payer supplies (`TxOutSecrets::to_string()`).
fn confidential_lbtc_output(value: u64) -> (elements::TxOut, String, String) {
    use lwk_wollet::elements;
    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let mut rng = secp256k1::rand::thread_rng();

    let bsk = secp256k1::SecretKey::new(&mut rng);
    let bpk = secp256k1::PublicKey::from_secret_key(&secp, &bsk);

    let spk = elements::Script::new_v0_wpkh(&elements::WPubkeyHash::from_raw_hash(
        hash160::Hash::hash(&[9u8; 33]),
    ));
    let lbtc = elements::AssetId::from_str(crate::invoice::LIQUID_BTC_ASSET_ID).unwrap();

    let in_secrets = elements::TxOutSecrets::new(
        lbtc,
        elements::confidential::AssetBlindingFactor::new(&mut rng),
        value,
        elements::confidential::ValueBlindingFactor::new(&mut rng),
    );

    let (txout, abf, vbf, _eph) = elements::TxOut::new_last_confidential(
        &mut rng, &secp, value, lbtc, spk, bpk, &[in_secrets], &[],
    )
    .expect("build confidential output");

    (txout, vbf.to_string(), abf.to_string())
}

/// Asset-masquerade output: on-chain generator commits to a worthless token, not
/// L-BTC. Returns the token's (value_bf, asset_bf) — a payer claiming L-BTC. The
/// asset rebind reconstructs an L-BTC generator from OUR asset id, which cannot
/// equal the token generator, so the proof is rejected (no unblinding needed).
fn asset_masquerade_output(value: u64) -> (elements::TxOut, String, String) {
    use lwk_wollet::elements;
    use lwk_wollet::elements::confidential::{Asset, AssetBlindingFactor, Value, ValueBlindingFactor};
    use lwk_wollet::elements::secp256k1_zkp::Generator;

    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let mut rng = secp256k1::rand::thread_rng();

    let spk = elements::Script::new_v0_wpkh(&elements::WPubkeyHash::from_raw_hash(
        hash160::Hash::hash(&[9u8; 33]),
    ));
    let token = elements::AssetId::from_str(
        "1111111111111111111111111111111111111111111111111111111111111111",
    )
    .unwrap();
    let token_abf = AssetBlindingFactor::new(&mut rng);
    let token_gen = Generator::new_blinded(&secp, token.into_tag(), token_abf.into_inner());
    let vbf = ValueBlindingFactor::new(&mut rng);
    let value_commit = Value::new_confidential(&secp, value, token_gen, vbf);

    let txout = elements::TxOut {
        asset: Asset::Confidential(token_gen),
        value: value_commit,
        nonce: elements::confidential::Nonce::Null,
        script_pubkey: spk,
        witness: elements::TxOutWitness::default(),
    };
    (txout, vbf.to_string(), token_abf.to_string())
}

/// Explicit (non-confidential) L-BTC output — a proof UTXO must be confidential.
fn explicit_lbtc_output(value: u64) -> elements::TxOut {
    use lwk_wollet::elements;
    use lwk_wollet::elements::confidential::{Asset, Nonce, Value};

    let spk = elements::Script::new_v0_wpkh(&elements::WPubkeyHash::from_raw_hash(
        hash160::Hash::hash(&[9u8; 33]),
    ));
    let lbtc = elements::AssetId::from_str(crate::invoice::LIQUID_BTC_ASSET_ID).unwrap();
    elements::TxOut {
        asset: Asset::Explicit(lbtc),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: spk,
        witness: elements::TxOutWitness::default(),
    }
}

fn rand_vbf() -> String {
    elements::confidential::ValueBlindingFactor::new(&mut secp256k1::rand::thread_rng()).to_string()
}
fn rand_abf() -> String {
    elements::confidential::AssetBlindingFactor::new(&mut secp256k1::rand::thread_rng()).to_string()
}

#[test]
fn proof_value_passes_when_at_or_above_floor() {
    let (txout, vbf, abf) = confidential_lbtc_output(5000);
    let got =
        assert_proof_utxo_value(&txout, 5000, &vbf, &abf, crate::invoice::LIQUID_BTC_ASSET_ID, 1000)
            .unwrap();
    assert_eq!(got, 5000, "rebind confirms the committed value");
}

#[test]
fn proof_value_rejects_below_floor() {
    let (txout, vbf, abf) = confidential_lbtc_output(500);
    assert!(matches!(
        assert_proof_utxo_value(&txout, 500, &vbf, &abf, crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_wrong_asset() {
    let (txout, vbf, abf) = confidential_lbtc_output(5000);
    let not_lbtc = "0000000000000000000000000000000000000000000000000000000000000001";
    assert!(matches!(
        assert_proof_utxo_value(&txout, 5000, &vbf, &abf, not_lbtc, 1000),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_asset_masquerade() {
    let (txout, vbf, abf) = asset_masquerade_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(&txout, 5000, &vbf, &abf, crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_)),
    ));
}

#[test]
fn proof_value_rejects_explicit_asset() {
    let txout = explicit_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(&txout, 5000, &rand_vbf(), &rand_abf(), crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_)),
    ));
}

#[test]
fn proof_value_rejects_forged_value() {
    // Correct output + factors, but a lied-about value cannot bind to the
    // on-chain Pedersen commitment.
    let (txout, vbf, abf) = confidential_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(&txout, 999_999, &vbf, &abf, crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_wrong_value_bf() {
    let (txout, _vbf, abf) = confidential_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(&txout, 5000, &rand_vbf(), &abf, crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_wrong_asset_bf() {
    let (txout, vbf, _abf) = confidential_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(&txout, 5000, &vbf, &rand_abf(), crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_malformed_factor() {
    let (txout, vbf, _abf) = confidential_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(&txout, 5000, &vbf, "notahex", crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
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

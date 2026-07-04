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

/// Build the Q2 asset-masquerade attack output: a confidential output whose
/// on-chain asset generator commits to a worthless token, but whose rangeproof
/// message CLAIMS asset = L-BTC. The value commitment and rangeproof are built
/// over the *token* generator, so `unblind`'s rewind (which rewinds against the
/// on-chain generator) succeeds and recovers the value — but it reports the
/// message-claimed L-BTC asset. This is the exact bypass the generator
/// rebinding closes: without it, the asset and value checks both pass at ~zero
/// L-BTC cost. Returns the output and the payer blinding key hex.
fn asset_masquerade_output(value: u64) -> (elements::TxOut, String) {
    use lwk_wollet::elements;
    use lwk_wollet::elements::confidential::{
        Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor,
    };
    use lwk_wollet::elements::secp256k1_zkp::{Generator, RangeProof};

    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let mut rng = secp256k1::rand::thread_rng();

    // Payer blinding keypair — its secret key unblinds the output.
    let bsk = secp256k1::SecretKey::new(&mut rng);
    let bpk = secp256k1::PublicKey::from_secret_key(&secp, &bsk);

    let spk = elements::Script::new_v0_wpkh(&elements::WPubkeyHash::from_raw_hash(
        hash160::Hash::hash(&[9u8; 33]),
    ));

    // On-chain asset generator: a worthless token, NOT L-BTC.
    let token = elements::AssetId::from_str(
        "1111111111111111111111111111111111111111111111111111111111111111",
    )
    .unwrap();
    let token_abf = AssetBlindingFactor::new(&mut rng);
    let token_gen = Generator::new_blinded(&secp, token.into_tag(), token_abf.into_inner());

    // Value commitment + rangeproof are built over the token generator, so the
    // output is internally consistent and `unblind`'s rewind succeeds.
    let vbf = ValueBlindingFactor::new(&mut rng);
    let value_commit = Value::new_confidential(&secp, value, token_gen, vbf);
    let commitment = value_commit.commitment().expect("confidential value");

    // The forgery: the rangeproof message claims L-BTC (with an arbitrary asset
    // blinding factor) even though the on-chain generator commits to the token.
    let lbtc = elements::AssetId::from_str(crate::invoice::LIQUID_BTC_ASSET_ID).unwrap();
    let forged_msg = elements::RangeProofMessage {
        asset: lbtc,
        bf: AssetBlindingFactor::new(&mut rng),
    };

    let ephemeral_sk = secp256k1::SecretKey::new(&mut rng);
    let (nonce, shared_secret) = Nonce::with_ephemeral_sk(&secp, ephemeral_sk, &bpk);

    let rangeproof = RangeProof::new(
        &secp,
        elements::TxOut::RANGEPROOF_MIN_VALUE,
        commitment,
        value,
        vbf.into_inner(),
        &forged_msg.to_bytes(),
        spk.as_bytes(),
        shared_secret,
        elements::TxOut::RANGEPROOF_EXP_SHIFT,
        elements::TxOut::RANGEPROOF_MIN_PRIV_BITS,
        token_gen,
    )
    .expect("build forged rangeproof");

    let txout = elements::TxOut {
        asset: Asset::Confidential(token_gen),
        value: value_commit,
        nonce,
        script_pubkey: spk,
        witness: elements::TxOutWitness {
            surjection_proof: None,
            rangeproof: Some(Box::new(rangeproof)),
        },
    };

    (txout, hex::encode(bsk.secret_bytes()))
}

/// Build an explicit (non-confidential) L-BTC output. A proof UTXO must be a
/// confidential output; explicit outputs must be rejected.
fn explicit_lbtc_output(value: u64) -> (elements::TxOut, String) {
    use lwk_wollet::elements;
    use lwk_wollet::elements::confidential::{Asset, Nonce, Value};

    let mut rng = secp256k1::rand::thread_rng();
    let bsk = secp256k1::SecretKey::new(&mut rng);

    let spk = elements::Script::new_v0_wpkh(&elements::WPubkeyHash::from_raw_hash(
        hash160::Hash::hash(&[9u8; 33]),
    ));
    let lbtc = elements::AssetId::from_str(crate::invoice::LIQUID_BTC_ASSET_ID).unwrap();

    let txout = elements::TxOut {
        asset: Asset::Explicit(lbtc),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: spk,
        witness: elements::TxOutWitness::default(),
    };

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
fn proof_value_rejects_asset_masquerade() {
    // The exact Q2 attack: on-chain generator commits to a worthless token,
    // but the rangeproof message claims L-BTC and the value clears the floor.
    // `unblind` reports asset = L-BTC and value >= floor, so without the
    // asset-generator rebinding both the asset and value assertions would pass.
    // The rebinding reconstructs the generator from the recovered (asset,
    // asset_bf) — an L-BTC generator — which does NOT equal the on-chain token
    // generator, so the proof is rejected.
    let (txout, bk) = asset_masquerade_output(5000);

    // Sanity: unblind itself succeeds and is fooled into reporting L-BTC — the
    // forgery is well-formed, so the rejection must come from the rebinding,
    // not from a failed rewind.
    let secp = elements::secp256k1_zkp::Secp256k1::verification_only();
    let sk = elements::secp256k1_zkp::SecretKey::from_str(&bk).unwrap();
    let secrets = txout.unblind(&secp, sk).expect("forged proof unblinds");
    assert_eq!(
        secrets.asset.to_string(),
        crate::invoice::LIQUID_BTC_ASSET_ID,
        "attack: unblind is fooled into reporting L-BTC"
    );
    assert_eq!(secrets.value, 5000, "attack: value clears the floor");

    // The gate must still reject it via the asset-generator binding check.
    assert!(matches!(
        assert_proof_utxo_value(&txout, &bk, crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_)),
    ));
}

#[test]
fn proof_value_rejects_explicit_asset() {
    // An explicit (non-confidential) asset output must not qualify: a proof
    // UTXO has to be a confidential output whose generator binds to L-BTC.
    let (txout, bk) = explicit_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(&txout, &bk, crate::invoice::LIQUID_BTC_ASSET_ID, 1000),
        Err(AppError::ProofOfFundsInvalid(_)),
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

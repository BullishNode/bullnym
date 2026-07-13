use super::*;
use lwk_wollet::elements::hashes::Hash;
use secp256k1::SecretKey;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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

#[test]
fn liquid_history_entries_preserve_signed_heights_and_normalize_txids() {
    let upper = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let confirmed = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let entries = liquid_history_entries(&json!([
        {"tx_hash": upper, "height": -1},
        {"tx_hash": confirmed, "height": 42}
    ]))
    .unwrap();

    assert_eq!(entries[0].txid, upper.to_ascii_lowercase());
    assert_eq!(entries[0].height, -1);
    assert_eq!(entries[0].block_hash, None);
    assert_eq!(entries[1].height, 42);
}

#[test]
fn liquid_history_entries_reject_incomplete_or_ambiguous_evidence() {
    let txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for malformed in [
        json!([{"tx_hash": txid}]),
        json!([{"tx_hash": "short", "height": 0}]),
        json!([
            {"tx_hash": txid, "height": 0},
            {"tx_hash": txid, "height": 1}
        ]),
    ] {
        assert!(matches!(
            liquid_history_entries(&malformed),
            Err(AppError::ElectrumError(_))
        ));
    }
}

#[test]
fn liquid_script_history_requires_a_positive_confirmation_height() {
    let txid_a = "a".repeat(64);
    let txid_b = "b".repeat(64);

    assert_eq!(
        liquid_script_history(&json!([])).unwrap(),
        LiquidScriptHistory::Empty
    );
    assert_eq!(
        liquid_script_history(&json!([
            {"tx_hash": txid_a, "height": 0},
            {"tx_hash": txid_b, "height": -1}
        ]))
        .unwrap(),
        LiquidScriptHistory::MempoolOnly
    );
    assert_eq!(
        liquid_script_history(&json!([
            {"tx_hash": "a".repeat(64), "height": 0},
            {"tx_hash": "b".repeat(64), "height": 42}
        ]))
        .unwrap(),
        LiquidScriptHistory::Confirmed
    );
}

#[test]
fn liquid_script_history_rejects_untyped_confirmation_evidence() {
    assert!(matches!(
        liquid_script_history(&json!([{
            "tx_hash": "a".repeat(64),
            "height": "1"
        }])),
        Err(AppError::ElectrumError(message))
            if message.contains("invalid signed height")
    ));
}

#[test]
fn liquid_snapshot_plan_bounds_history_before_header_fanout() {
    let entries = (0..3)
        .map(|index| LiquidHistoryEntry {
            txid: format!("{index:064x}"),
            height: 100 + index,
            block_hash: None,
        })
        .collect::<Vec<_>>();
    let plan = liquid_snapshot_plan(
        &entries,
        &[],
        200,
        LiquidHistorySnapshotLimits {
            max_history_entries: 2,
            max_block_heights: 10,
        },
    )
    .unwrap();

    assert_eq!(
        plan,
        LiquidSnapshotPlan::Incomplete(LiquidHistorySnapshotLimit::HistoryEntries {
            observed: 3,
            limit: 2,
        })
    );
}

#[test]
fn liquid_snapshot_plan_deduplicates_current_and_prior_anchor_heights() {
    let entries = vec![LiquidHistoryEntry {
        txid: "a".repeat(64),
        height: 100,
        block_hash: None,
    }];
    let plan = liquid_snapshot_plan(
        &entries,
        &[99, 100, 100, 250],
        200,
        LiquidHistorySnapshotLimits {
            max_history_entries: 10,
            max_block_heights: 2,
        },
    )
    .unwrap();

    assert_eq!(
        plan,
        LiquidSnapshotPlan::Ready([99, 100].into_iter().collect())
    );
}

#[test]
fn liquid_snapshot_plan_bounds_unique_current_and_prior_heights() {
    let entries = vec![LiquidHistoryEntry {
        txid: "a".repeat(64),
        height: 100,
        block_hash: None,
    }];
    let plan = liquid_snapshot_plan(
        &entries,
        &[99, 98],
        200,
        LiquidHistorySnapshotLimits {
            max_history_entries: 10,
            max_block_heights: 2,
        },
    )
    .unwrap();

    assert_eq!(
        plan,
        LiquidSnapshotPlan::Incomplete(LiquidHistorySnapshotLimit::BlockHeights {
            observed: 3,
            limit: 2,
        })
    );
}

#[test]
fn liquid_snapshot_plan_accepts_256_and_rejects_257() {
    let limits = LiquidHistorySnapshotLimits {
        max_history_entries: 256,
        max_block_heights: 256,
    };
    let entries = (1..=257)
        .map(|height| LiquidHistoryEntry {
            txid: format!("{height:064x}"),
            height,
            block_hash: None,
        })
        .collect::<Vec<_>>();
    let production_entries = (0..204)
        .map(|index| LiquidHistoryEntry {
            txid: format!("{:064x}", index + 1),
            height: index % 71 + 1,
            block_hash: None,
        })
        .collect::<Vec<_>>();

    let LiquidSnapshotPlan::Ready(production_heights) =
        liquid_snapshot_plan(&production_entries, &[], 300, limits).unwrap()
    else {
        panic!("observed production history and height counts must fit the bounded snapshot");
    };
    assert_eq!(production_entries.len(), 204);
    assert_eq!(production_heights.len(), 71);

    assert!(matches!(
        liquid_snapshot_plan(&entries[..256], &[], 300, limits).unwrap(),
        LiquidSnapshotPlan::Ready(_)
    ));
    assert_eq!(
        liquid_snapshot_plan(&entries, &[], 300, limits).unwrap(),
        LiquidSnapshotPlan::Incomplete(LiquidHistorySnapshotLimit::HistoryEntries {
            observed: 257,
            limit: 256,
        })
    );
    assert!(matches!(
        liquid_snapshot_plan(&[], &(1..=256).collect::<Vec<_>>(), 300, limits).unwrap(),
        LiquidSnapshotPlan::Ready(_)
    ));
    assert_eq!(
        liquid_snapshot_plan(&[], &(1..=257).collect::<Vec<_>>(), 300, limits).unwrap(),
        LiquidSnapshotPlan::Incomplete(LiquidHistorySnapshotLimit::BlockHeights {
            observed: 257,
            limit: 256,
        })
    );
}

#[test]
fn liquid_snapshot_plan_rejects_invalid_prior_height() {
    let error = liquid_snapshot_plan(
        &[],
        &[0],
        200,
        LiquidHistorySnapshotLimits {
            max_history_entries: 10,
            max_block_heights: 10,
        },
    )
    .unwrap_err();
    assert!(matches!(error, AppError::ElectrumError(_)));
}

#[test]
fn liquid_authority_identity_is_stable_and_does_not_expose_endpoint_credentials() {
    let endpoint = "ssl://operator:secret@example.com:50002";
    let authority = sanitized_liquid_authority(endpoint);

    assert_eq!(authority, sanitized_liquid_authority(endpoint));
    assert!(authority.starts_with("liquid-electrum:"));
    assert!(!authority.contains("operator"));
    assert!(!authority.contains("secret"));
    assert!(!authority.contains("example.com"));
    assert!(authority.len() <= 200);
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

    (txout, vbf.to_string(), abf.to_string())
}

/// Asset-masquerade output: on-chain generator commits to a worthless token, not
/// L-BTC. Returns the token's (value_bf, asset_bf) — a payer claiming L-BTC. The
/// asset rebind reconstructs an L-BTC generator from OUR asset id, which cannot
/// equal the token generator, so the proof is rejected (no unblinding needed).
fn asset_masquerade_output(value: u64) -> (elements::TxOut, String, String) {
    use lwk_wollet::elements;
    use lwk_wollet::elements::confidential::{
        Asset, AssetBlindingFactor, Value, ValueBlindingFactor,
    };
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
    let got = assert_proof_utxo_value(
        &txout,
        5000,
        &vbf,
        &abf,
        crate::invoice::LIQUID_BTC_ASSET_ID,
        1000,
    )
    .unwrap();
    assert_eq!(got, 5000, "rebind confirms the committed value");
}

#[test]
fn proof_value_rejects_below_floor() {
    let (txout, vbf, abf) = confidential_lbtc_output(500);
    assert!(matches!(
        assert_proof_utxo_value(
            &txout,
            500,
            &vbf,
            &abf,
            crate::invoice::LIQUID_BTC_ASSET_ID,
            1000
        ),
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
        assert_proof_utxo_value(
            &txout,
            5000,
            &vbf,
            &abf,
            crate::invoice::LIQUID_BTC_ASSET_ID,
            1000
        ),
        Err(AppError::ProofOfFundsInvalid(_)),
    ));
}

#[test]
fn proof_value_rejects_explicit_asset() {
    let txout = explicit_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(
            &txout,
            5000,
            &rand_vbf(),
            &rand_abf(),
            crate::invoice::LIQUID_BTC_ASSET_ID,
            1000
        ),
        Err(AppError::ProofOfFundsInvalid(_)),
    ));
}

#[test]
fn proof_value_rejects_forged_value() {
    // Correct output + factors, but a lied-about value cannot bind to the
    // on-chain Pedersen commitment.
    let (txout, vbf, abf) = confidential_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(
            &txout,
            999_999,
            &vbf,
            &abf,
            crate::invoice::LIQUID_BTC_ASSET_ID,
            1000
        ),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_wrong_value_bf() {
    let (txout, _vbf, abf) = confidential_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(
            &txout,
            5000,
            &rand_vbf(),
            &abf,
            crate::invoice::LIQUID_BTC_ASSET_ID,
            1000
        ),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_wrong_asset_bf() {
    let (txout, vbf, _abf) = confidential_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(
            &txout,
            5000,
            &vbf,
            &rand_abf(),
            crate::invoice::LIQUID_BTC_ASSET_ID,
            1000
        ),
        Err(AppError::ProofOfFundsInvalid(_))
    ));
}

#[test]
fn proof_value_rejects_malformed_factor() {
    let (txout, vbf, _abf) = confidential_lbtc_output(5000);
    assert!(matches!(
        assert_proof_utxo_value(
            &txout,
            5000,
            &vbf,
            "notahex",
            crate::invoice::LIQUID_BTC_ASSET_ID,
            1000
        ),
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

#[test]
fn verify_liquid_raw_tx_accepts_matching_and_rejects_mismatch_or_malformed() {
    // A minimal but valid Liquid transaction; serialize it and confirm the
    // verify helper accepts its own txid, rejects a different requested txid,
    // and rejects malformed bytes (#66).
    let tx = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: elements::OutPoint::new(
                elements::Txid::from_slice(&[9u8; 32]).unwrap(),
                0,
            ),
            is_pegin: false,
            script_sig: elements::Script::new(),
            sequence: elements::Sequence::MAX,
            asset_issuance: elements::AssetIssuance::default(),
            witness: elements::TxInWitness::default(),
        }],
        output: vec![],
    };
    let bytes = elements::encode::serialize(&tx);
    let txid = tx.txid().to_string();

    // Correct txid (and mixed case) verifies.
    assert!(super::verify_liquid_raw_tx(&txid, &bytes).is_ok());
    assert!(super::verify_liquid_raw_tx(&txid.to_uppercase(), &bytes).is_ok());

    // Valid bytes returned for a DIFFERENT requested txid is rejected.
    let other = elements::Txid::from_slice(&[7u8; 32]).unwrap().to_string();
    assert!(super::verify_liquid_raw_tx(&other, &bytes).is_err());

    // Malformed bytes are rejected before any downstream use.
    assert!(super::verify_liquid_raw_tx(&txid, &[0xde, 0xad, 0xbe, 0xef]).is_err());
    assert!(super::verify_liquid_raw_tx(&txid, &[]).is_err());
}

async fn spawn_raw_tx_electrum_fixture(
    bytes: Vec<u8>,
) -> (String, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Electrum raw-tx fixture");
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await.unwrap();
        let request: serde_json::Value = serde_json::from_str(&request_line).unwrap();
        let response = json!({
            "jsonrpc": "2.0",
            "id": request["id"].clone(),
            "result": hex::encode(bytes),
        });
        write_half
            .write_all(format!("{response}\n").as_bytes())
            .await
            .unwrap();
        request["method"].as_str().unwrap_or_default().to_string()
    });
    (format!("tcp://{address}"), task)
}

#[tokio::test]
async fn raw_tx_integrity_mismatch_fails_over_to_the_next_authority() {
    let requested_tx = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: elements::OutPoint::new(
                elements::Txid::from_slice(&[11u8; 32]).unwrap(),
                0,
            ),
            is_pegin: false,
            script_sig: elements::Script::new(),
            sequence: elements::Sequence::MAX,
            asset_issuance: elements::AssetIssuance::default(),
            witness: elements::TxInWitness::default(),
        }],
        output: vec![],
    };
    let wrong_tx = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: elements::OutPoint::new(
                elements::Txid::from_slice(&[12u8; 32]).unwrap(),
                0,
            ),
            is_pegin: false,
            script_sig: elements::Script::new(),
            sequence: elements::Sequence::MAX,
            asset_issuance: elements::AssetIssuance::default(),
            witness: elements::TxInWitness::default(),
        }],
        output: vec![],
    };
    let requested_bytes = elements::encode::serialize(&requested_tx);
    let (wrong_url, wrong_server) =
        spawn_raw_tx_electrum_fixture(elements::encode::serialize(&wrong_tx)).await;
    let (valid_url, valid_server) = spawn_raw_tx_electrum_fixture(requested_bytes.clone()).await;
    let client = ElectrumClient::connect(vec![wrong_url, valid_url], 60, 8).unwrap();

    let returned = tokio::time::timeout(
        Duration::from_secs(2),
        client.get_raw_tx(&requested_tx.txid().to_string()),
    )
    .await
    .expect("raw-tx integrity failover timed out")
    .expect("second Electrum authority should return the requested transaction");

    assert_eq!(returned, requested_bytes);
    assert_eq!(wrong_server.await.unwrap(), "blockchain.transaction.get");
    assert_eq!(valid_server.await.unwrap(), "blockchain.transaction.get");
}

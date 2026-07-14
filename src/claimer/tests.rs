use super::*;
use async_trait::async_trait;
use elements::encode::serialize;
use std::cell::Cell;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::fee_policy::{FeeProvenance, LiquidFeePolicy, LiveLiquid, SatPerVbyte};

fn liquid_builder_fee(rate: f64) -> LiquidBuilderFeeDecision {
    let observation = LiveLiquid::new(
        SatPerVbyte::try_from(rate).unwrap(),
        1_000,
        FeeProvenance::new("claimer-test").unwrap(),
    );
    let decision = LiquidFeePolicy::default()
        .decide_typed(Some(&observation), None, 1_000)
        .unwrap();
    LiquidBuilderFeeDecision::from(&decision)
}

fn short_lived_liquid_fee_record() -> FeeDecisionRecord {
    let policy = LiquidFeePolicy::with_freshness(
        SatPerVbyte::try_from(0.1).unwrap(),
        SatPerVbyte::try_from(10.0).unwrap(),
        1,
        1,
    )
    .unwrap();
    let observation = LiveLiquid::new(
        SatPerVbyte::try_from(1.0).unwrap(),
        1_000,
        FeeProvenance::new("claimer-final-commit-gate").unwrap(),
    );
    let decision = policy
        .decide_typed(Some(&observation), None, 1_000)
        .unwrap();
    FeeDecisionRecord::from_liquid(
        FeeConstructionPurpose::ReverseLiquidClaim,
        &decision,
        &policy,
        1_000,
    )
    .unwrap()
}

fn valid_chain_creation_terms() -> db::ChainSwapCreationTerms {
    db::ChainSwapCreationTerms {
        pinned_pair_hash: "11".repeat(32),
        canonical_pair_quote_json: "{}".into(),
        creation_response_sha256: "22".repeat(32),
        btc_claim_script_sha256: "33".repeat(32),
        btc_refund_script_sha256: "44".repeat(32),
        liquid_claim_script_sha256: "55".repeat(32),
        liquid_refund_script_sha256: "66".repeat(32),
        btc_timeout_height: 958_033,
        liquid_timeout_height: 3_972_215,
        btc_network: "bitcoin".into(),
        liquid_network: "liquid".into(),
        liquid_asset_id: elements::AssetId::LIQUID_BTC.to_string(),
        merchant_liquid_destination: "lq1pqv20pj0v3drz4xuzra5tgl4lylxaaglu6uamqryj06raeztexcyfquafnsttga69pezal4khvghxwkg65cqa9mrm9q4t9z0sk0a0gvsur6lrsu8hg8zg".into(),
        merchant_emergency_btc_address: None,
        recovery_address_commitment_id: None,
    }
}

fn relative_fee_rate(fee: Fee) -> f64 {
    match fee {
        Fee::Relative(rate) => rate,
        Fee::Absolute(_) => panic!("claim builder must use a sat/vByte decision"),
    }
}

#[test]
fn reverse_and_chain_claim_paths_preserve_upstream_min_midrange_and_max_rates() {
    // Representative policy boundary values. The policy package owns their
    // actual configuration; this builder test proves all four construction
    // paths receive the exact selected sat/vByte rate without reclamping it.
    for rate in [0.1, 2.0, 10.0] {
        let decision = liquid_builder_fee(rate);
        for cooperative in [true, false] {
            assert_eq!(
                relative_fee_rate(liquid_claim_fee(&decision, cooperative)),
                rate
            );
        }
    }
}

#[test]
fn changed_liquid_decision_changes_each_next_claim_construction_path() {
    let previous = liquid_builder_fee(0.1);
    let changed = liquid_builder_fee(5.0);

    for cooperative in [true, false] {
        assert_eq!(
            relative_fee_rate(liquid_claim_fee(&previous, cooperative)),
            0.1
        );
        assert_eq!(
            relative_fee_rate(liquid_claim_fee(&changed, cooperative)),
            5.0
        );
    }
}

#[test]
fn final_liquid_journal_gate_rechecks_fresh_bytes_but_not_replay() {
    let record = short_lived_liquid_fee_record();
    assert!(liquid_claim_journal_authorized(false, Some(&record)));

    // Model construction plus journal writes crossing the one-second
    // monotonic authority window. The same gate is called immediately before
    // COMMIT on both reverse- and chain-claim paths.
    std::thread::sleep(Duration::from_millis(1_100));
    assert!(!liquid_claim_journal_authorized(false, Some(&record)));
    assert!(!liquid_claim_journal_authorized(false, None));

    // Existing bytes retain their construction-time packet and are replayed
    // without requiring a new quote or process-local deadline.
    assert!(liquid_claim_journal_authorized(true, None));
    assert!(liquid_claim_journal_authorized(true, Some(&record)));
}

#[test]
fn liquid_actual_fee_uses_discounted_virtual_size_basis() {
    let secp = boltz_elements::secp256k1_zkp::Secp256k1::new();
    let confidential_value = boltz_elements::confidential::Value::new_confidential_from_assetid(
        &secp,
        50_000,
        boltz_elements::AssetId::LIQUID_BTC,
        boltz_elements::confidential::ValueBlindingFactor::zero(),
        boltz_elements::confidential::AssetBlindingFactor::zero(),
    );
    let transaction = boltz_elements::Transaction {
        version: 2,
        lock_time: boltz_elements::LockTime::ZERO,
        input: Vec::new(),
        output: vec![
            boltz_elements::TxOut {
                asset: boltz_elements::confidential::Asset::Explicit(
                    boltz_elements::AssetId::LIQUID_BTC,
                ),
                value: confidential_value,
                nonce: boltz_elements::confidential::Nonce::Null,
                script_pubkey: boltz_elements::Script::from(vec![0x51]),
                witness: boltz_elements::TxOutWitness::default(),
            },
            boltz_elements::TxOut {
                asset: boltz_elements::confidential::Asset::Explicit(
                    boltz_elements::AssetId::LIQUID_BTC,
                ),
                value: boltz_elements::confidential::Value::Explicit(1_000),
                nonce: boltz_elements::confidential::Nonce::Null,
                script_pubkey: boltz_elements::Script::new(),
                witness: boltz_elements::TxOutWitness::default(),
            },
        ],
    };
    assert_ne!(transaction.vsize(), transaction.discount_vsize());

    let (fee_sat, rate_sat_vb, discounted_vbytes) =
        liquid_actual_fee(&BtcLikeTransaction::Liquid(transaction.clone())).unwrap();

    assert_eq!(fee_sat, 1_000);
    assert_eq!(rate_sat_vb, 1_000.0 / transaction.discount_vsize() as f64);
    assert_eq!(discounted_vbytes, transaction.discount_vsize() as u64);
}

#[test]
fn liquid_fee_authority_rejects_one_sat_under_and_over_the_exact_size_fee() {
    let policy = LiquidFeePolicy::default();
    let observation = LiveLiquid::new(
        SatPerVbyte::try_from(0.5).unwrap(),
        1_000,
        FeeProvenance::new("claimer-exact-fee-test").unwrap(),
    );
    let decision = policy
        .decide_typed(Some(&observation), None, 1_000)
        .unwrap();
    let record = FeeDecisionRecord::from_liquid(
        FeeConstructionPurpose::ReverseLiquidClaim,
        &decision,
        &policy,
        1_000,
    )
    .unwrap();

    // ceil(0.5 sat/vB * 141 vB) = 71 sat.
    assert!(ensure_actual_fee_authorized("test claim", 71, 141, &record).is_ok());
    for unauthorized in [70, 72] {
        assert!(ensure_actual_fee_authorized("test claim", unauthorized, 141, &record).is_err());
    }
}

#[test]
fn chain_claim_journal_fee_must_match_exact_signed_transaction_tuple() {
    let rate = 1_000.0 / 141.0;
    assert!(ensure_chain_claim_journal_fee_matches_actual(1_000, rate, 1_000, rate).is_ok());

    assert!(ensure_chain_claim_journal_fee_matches_actual(1_000, rate, -1, rate).is_err());
    assert!(ensure_chain_claim_journal_fee_matches_actual(999, rate, 1_000, rate).is_err());
    assert!(ensure_chain_claim_journal_fee_matches_actual(
        1_000,
        f64::from_bits(rate.to_bits() + 1),
        1_000,
        rate,
    )
    .is_err());
}

#[test]
fn chain_claim_uses_validated_immutable_creation_destination() {
    let terms = valid_chain_creation_terms();
    assert_eq!(
        validated_chain_creation_destination(&terms).unwrap(),
        terms.merchant_liquid_destination
    );
}

#[test]
fn chain_claim_rejects_corrupt_creation_destination_policy() {
    let mut wrong_network = valid_chain_creation_terms();
    wrong_network.liquid_network = "liquidtestnet".into();
    assert!(validated_chain_creation_destination(&wrong_network).is_err());

    let mut wrong_asset = valid_chain_creation_terms();
    wrong_asset.liquid_asset_id = "00".repeat(32);
    assert!(validated_chain_creation_destination(&wrong_asset).is_err());

    let mut wrong_address = valid_chain_creation_terms();
    wrong_address.merchant_liquid_destination = "not-a-liquid-address".into();
    assert!(validated_chain_creation_destination(&wrong_address).is_err());
}

#[test]
fn chain_claim_journal_mode_rejects_orphan_parent_state() {
    assert_eq!(
        persisted_chain_claim_journal_mode(None, None).unwrap(),
        PersistedChainClaimJournalMode::ConstructAndInsert
    );
    assert_eq!(
        persisted_chain_claim_journal_mode(Some("00"), Some("11")).unwrap(),
        PersistedChainClaimJournalMode::DecodeAndLoadExact
    );
    assert!(persisted_chain_claim_journal_mode(Some("00"), None).is_err());
    assert!(persisted_chain_claim_journal_mode(None, Some("11")).is_err());
    assert!(require_terminal_chain_claim_journal(
        ChainSwapStatus::Claimed,
        PersistedChainClaimJournalMode::ConstructAndInsert,
    )
    .is_err());
    assert!(require_terminal_chain_claim_journal(
        ChainSwapStatus::Claimed,
        PersistedChainClaimJournalMode::DecodeAndLoadExact,
    )
    .is_ok());
    assert!(require_terminal_chain_claim_journal(
        ChainSwapStatus::Claiming,
        PersistedChainClaimJournalMode::ConstructAndInsert,
    )
    .is_ok());
}

#[test]
fn persisted_chain_claim_without_exact_journal_fails_before_broadcast() {
    let broadcast_calls = Cell::new(0usize);
    let result = (|| -> Result<(), AppError> {
        require_exact_persisted_chain_claim_journal::<()>(Err(
            db::MerchantSettlementRepositoryError::MissingJournal,
        ))?;
        broadcast_calls.set(broadcast_calls.get() + 1);
        Ok(())
    })();

    assert!(result.is_err());
    assert_eq!(broadcast_calls.get(), 0);
}

#[test]
fn url_secret_matches_current() {
    assert_eq!(
        match_url_secret_pair("s3cr3t-current", "s3cr3t-current", ""),
        UrlSecretMatch::Current
    );
    assert!(url_secret_matches_pair(
        "s3cr3t-current",
        "s3cr3t-current",
        ""
    ));
}

#[test]
fn url_secret_matches_previous_during_overlap() {
    assert_eq!(
        match_url_secret_pair("s3cr3t-previous", "s3cr3t-current", "s3cr3t-previous"),
        UrlSecretMatch::Previous
    );
    assert!(url_secret_matches_pair(
        "s3cr3t-previous",
        "s3cr3t-current",
        "s3cr3t-previous"
    ));
    assert!(url_secret_matches_pair(
        "s3cr3t-current",
        "s3cr3t-current",
        "s3cr3t-previous"
    ));
}

#[test]
fn url_secret_rejects_wrong() {
    assert_eq!(
        match_url_secret_pair("nope", "s3cr3t-current", "s3cr3t-previous"),
        UrlSecretMatch::None
    );
    assert!(!url_secret_matches_pair(
        "nope",
        "s3cr3t-current",
        "s3cr3t-previous"
    ));
    assert!(!url_secret_matches_pair(
        "",
        "s3cr3t-current",
        "s3cr3t-previous"
    ));
}

/// Empty configured secrets must never validate — even against an
/// empty presented secret. Otherwise a misconfigured deploy would
/// silently accept any presented value.
#[test]
fn url_secret_rejects_empty_when_unconfigured() {
    assert!(!url_secret_matches_pair("", "", ""));
    assert!(!url_secret_matches_pair("anything", "", ""));
}

#[test]
fn url_secret_rejects_length_mismatch() {
    assert!(!url_secret_matches_pair(
        "0123456789abcde",
        "0123456789abcdef",
        ""
    ));
    assert!(!url_secret_matches_pair(
        "0123456789abcdef0",
        "0123456789abcdef",
        ""
    ));
}

#[test]
fn issue30_webhook_dispatch_success_stops_provider_retries() {
    let response = webhook_dispatch_response(Ok("ok"));
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn issue30_webhook_dispatch_errors_are_http_retryable() {
    for error in [
        AppError::DbError("transition commit failed".to_string()),
        AppError::ClaimError("renegotiation failed".to_string()),
        AppError::RateLimitedNetwork,
    ] {
        let response = webhook_dispatch_response(Err(error));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    let response = webhook_dispatch_response(Err(AppError::ServiceUnavailable(
        "provider unavailable".to_string(),
    )));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn cooperative_refusal_recognises_known_phrases() {
    for phrase in [
        "construct_claim failed: serde error: swap expired at line 1",
        "construct_claim failed: invalid preimage",
        "construct_claim failed: cooperative claim disabled",
        "construct_claim failed: cooperative signing disabled",
        // Exact production wording observed from the pinned Boltz client.
        "construct_claim failed: swap not eligible for a cooperative claim",
        "construct_claim failed: not eligible for cooperative",
        // case-insensitive
        "construct_claim failed: SWAP EXPIRED",
    ] {
        let e = AppError::ClaimError(phrase.to_string());
        assert!(
            is_cooperative_refusal(&e),
            "expected refusal classification for: {phrase}"
        );
    }
}

#[test]
fn cooperative_refusal_rejects_unrelated_errors() {
    for phrase in [
        "broadcast failed: connection reset",
        "construct_claim failed: timeout",
        "construct_claim failed: 502 bad gateway",
        "swap script build failed: ...",
        "electrum connection failed: ...",
    ] {
        let e = AppError::ClaimError(phrase.to_string());
        assert!(
            !is_cooperative_refusal(&e),
            "did not expect refusal classification for: {phrase}"
        );
    }
}

#[test]
fn claim_cycle_is_unhealthy_when_systemic_operations_fail() {
    let errors = [
        AppError::DbError("database unavailable".to_string()),
        AppError::ElectrumError("all endpoints unavailable".to_string()),
        AppError::BoltzError("provider timeout".to_string()),
        AppError::ClaimError("electrum connection failed on all urls".to_string()),
        AppError::ClaimError("construct_claim failed: provider timeout".to_string()),
        AppError::ClaimError("broadcast failed: connection reset".to_string()),
    ];
    let mut health = ClaimCycleHealth::default();
    for error in &errors {
        assert_eq!(
            classify_claim_failure(error),
            ClaimFailureScope::Systemic,
            "expected systemic classification for {error}"
        );
        health.observe_error(error);
    }
    assert!(health.systemic_failure);
}

#[test]
fn claim_cycle_keeps_malformed_and_business_local_obligations_local() {
    let errors = [
        AppError::ClaimError("invalid boltz response json: expected value".to_string()),
        AppError::ClaimError("decode persisted claim_tx: invalid hex".to_string()),
        AppError::ClaimError("construct_claim failed: swap expired".to_string()),
    ];
    let mut health = ClaimCycleHealth::default();
    for error in &errors {
        assert_eq!(
            classify_claim_failure(error),
            ClaimFailureScope::Local,
            "expected local classification for {error}"
        );
        health.observe_error(error);
    }
    assert!(!health.systemic_failure);
}

#[test]
fn chain_swap_boltz_claimed_does_not_terminalize_local_status() {
    assert_eq!(
        chain_swap_provider_input("transaction.server.mempool"),
        Some(db::ChainSwapProviderStatusInput::ServerLockMempool)
    );
    assert_eq!(
        chain_swap_provider_input("transaction.claimed"),
        Some(db::ChainSwapProviderStatusInput::Observe)
    );
}

struct MockUtxoBackend {
    raw_txs: HashMap<String, Vec<u8>>,
    find_calls: Mutex<Vec<(String, u32)>>,
    spender: Option<String>,
}

#[async_trait]
impl UtxoBackend for MockUtxoBackend {
    async fn get_raw_tx(&self, txid_hex: &str) -> Result<Vec<u8>, AppError> {
        self.raw_txs
            .get(txid_hex)
            .cloned()
            .ok_or(AppError::UtxoNotFound)
    }

    async fn is_unspent(
        &self,
        _script_pubkey: &elements::Script,
        _txid_hex: &str,
        _vout: u32,
    ) -> Result<bool, AppError> {
        Ok(false)
    }

    async fn script_history(
        &self,
        _script_pubkey: &elements::Script,
    ) -> Result<crate::utxo::LiquidScriptHistory, AppError> {
        Ok(crate::utxo::LiquidScriptHistory::Empty)
    }

    async fn history_txids(
        &self,
        _script_pubkey: &elements::Script,
    ) -> Result<Vec<String>, AppError> {
        Ok(Vec::new())
    }

    async fn find_spending_txid(
        &self,
        _script_pubkey: &elements::Script,
        txid_hex: &str,
        vout: u32,
    ) -> Result<Option<String>, AppError> {
        self.find_calls
            .lock()
            .await
            .push((txid_hex.to_string(), vout));
        Ok(self.spender.clone())
    }
}

struct ChainClaimJournalFixture {
    claim_tx: BtcLikeTransaction,
    source_address: String,
    source_blinding_key_hex: String,
    merchant_address: String,
    merchant_blinding_key_hex: String,
    source_txid: String,
    backend: Arc<dyn UtxoBackend>,
}

fn chain_claim_journal_fixture() -> ChainClaimJournalFixture {
    let secp = boltz_elements::secp256k1_zkp::Secp256k1::new();
    let mut rng = boltz_elements::secp256k1_zkp::rand::thread_rng();
    let asset = boltz_elements::AssetId::LIQUID_BTC;
    let address_template = boltz_elements::Address::from_str(
        &valid_chain_creation_terms().merchant_liquid_destination,
    )
    .unwrap()
    .to_unconfidential();

    let source_blinding_key = boltz_elements::secp256k1_zkp::SecretKey::new(&mut rng);
    let source_blinding_pubkey =
        boltz_elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &source_blinding_key);
    let source_address = address_template
        .clone()
        .to_confidential(source_blinding_pubkey);
    let source_input_secrets = boltz_elements::TxOutSecrets::new(
        asset,
        boltz_elements::confidential::AssetBlindingFactor::new(&mut rng),
        91_000,
        boltz_elements::confidential::ValueBlindingFactor::new(&mut rng),
    );
    let (source_output, source_abf, source_vbf, _) = boltz_elements::TxOut::new_last_confidential(
        &mut rng,
        &secp,
        91_000,
        asset,
        source_address.script_pubkey(),
        source_blinding_pubkey,
        &[source_input_secrets],
        &[],
    )
    .unwrap();
    let source_secrets = boltz_elements::TxOutSecrets::new(asset, source_abf, 91_000, source_vbf);
    let source_transaction = boltz_elements::Transaction {
        version: 2,
        lock_time: boltz_elements::LockTime::ZERO,
        input: Vec::new(),
        output: vec![source_output],
    };
    let source_txid = source_transaction.txid();

    let merchant_blinding_key = boltz_elements::secp256k1_zkp::SecretKey::new(&mut rng);
    let merchant_blinding_pubkey =
        boltz_elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &merchant_blinding_key);
    let merchant_address = address_template.to_confidential(merchant_blinding_pubkey);
    let (merchant_output, _, _, _) = boltz_elements::TxOut::new_last_confidential(
        &mut rng,
        &secp,
        90_000,
        asset,
        merchant_address.script_pubkey(),
        merchant_blinding_pubkey,
        &[source_secrets],
        &[],
    )
    .unwrap();
    let claim_transaction = boltz_elements::Transaction {
        version: 2,
        lock_time: boltz_elements::LockTime::ZERO,
        input: vec![boltz_elements::TxIn {
            previous_output: boltz_elements::OutPoint::new(source_txid, 0),
            is_pegin: false,
            script_sig: boltz_elements::Script::new(),
            sequence: boltz_elements::Sequence::MAX,
            asset_issuance: boltz_elements::AssetIssuance::default(),
            witness: boltz_elements::TxInWitness::default(),
        }],
        output: vec![
            merchant_output,
            boltz_elements::TxOut::new_fee(1_000, asset),
        ],
    };
    let backend = Arc::new(MockUtxoBackend {
        raw_txs: HashMap::from([(
            source_txid.to_string(),
            boltz_elements::encode::serialize(&source_transaction),
        )]),
        find_calls: Mutex::new(vec![]),
        spender: None,
    });

    ChainClaimJournalFixture {
        claim_tx: BtcLikeTransaction::Liquid(claim_transaction),
        source_address: source_address.to_string(),
        source_blinding_key_hex: source_blinding_key.display_secret().to_string(),
        merchant_address: merchant_address.to_string(),
        merchant_blinding_key_hex: merchant_blinding_key.display_secret().to_string(),
        source_txid: source_txid.to_string(),
        backend,
    }
}

#[tokio::test]
async fn chain_claim_journal_preparation_binds_raw_sources_output_and_fee() {
    let fixture = chain_claim_journal_fixture();
    let prepared = prepare_chain_claim_settlement_journal(
        &fixture.claim_tx,
        &fixture.merchant_address,
        &boltz_elements::AssetId::LIQUID_BTC.to_string(),
        &fixture.merchant_blinding_key_hex,
        &fixture.source_address,
        &fixture.source_blinding_key_hex,
        &fixture.backend,
    )
    .await
    .unwrap();

    assert_eq!(prepared.journal.amount_sat, 90_000);
    assert_eq!(prepared.journal.vout, 0);
    assert_eq!(prepared.fee_amount_sat, 1_000);
    assert!(prepared.fee_rate_sat_vb.is_finite());
    assert!(prepared.fee_rate_sat_vb > 0.0);
    assert_eq!(prepared.journal.source_prevouts.len(), 1);
    assert_eq!(
        prepared.journal.source_prevouts[0].txid,
        fixture.source_txid
    );
    assert_eq!(prepared.journal.source_prevouts[0].vout, 0);
    assert_eq!(prepared.journal.source_prevouts[0].amount_sat, 91_000);
}

fn test_liquid_tx(
    input_outpoint: Option<elements::OutPoint>,
    script_pubkey: elements::Script,
) -> elements::Transaction {
    let input = input_outpoint.map(|previous_output| elements::TxIn {
        previous_output,
        is_pegin: false,
        script_sig: elements::Script::new(),
        sequence: elements::Sequence::MAX,
        asset_issuance: elements::AssetIssuance::default(),
        witness: elements::TxInWitness::default(),
    });

    elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: input.into_iter().collect(),
        output: vec![elements::TxOut {
            asset: elements::confidential::Asset::Explicit(elements::AssetId::LIQUID_BTC),
            value: elements::confidential::Value::Explicit(10_000),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey,
            witness: elements::TxOutWitness::default(),
        }],
    }
}

fn test_boltz_liquid_tx(
    input_outpoint: Option<boltz_elements::OutPoint>,
    script_pubkey: boltz_elements::Script,
) -> boltz_elements::Transaction {
    let input = input_outpoint.map(|previous_output| boltz_elements::TxIn {
        previous_output,
        is_pegin: false,
        script_sig: boltz_elements::Script::new(),
        sequence: boltz_elements::Sequence::MAX,
        asset_issuance: boltz_elements::AssetIssuance::default(),
        witness: boltz_elements::TxInWitness::default(),
    });

    boltz_elements::Transaction {
        version: 2,
        lock_time: boltz_elements::LockTime::ZERO,
        input: input.into_iter().collect(),
        output: vec![boltz_elements::TxOut {
            asset: boltz_elements::confidential::Asset::Explicit(
                boltz_elements::AssetId::LIQUID_BTC,
            ),
            value: boltz_elements::confidential::Value::Explicit(10_000),
            nonce: boltz_elements::confidential::Nonce::Null,
            script_pubkey,
            witness: boltz_elements::TxOutWitness::default(),
        }],
    }
}

#[test]
fn reloaded_liquid_claim_requires_exact_committed_bytes_and_txid() {
    let outpoint = boltz_elements::OutPoint::new("00".repeat(32).parse().expect("test txid"), 0);
    let transaction = BtcLikeTransaction::Liquid(test_boltz_liquid_tx(
        Some(outpoint),
        boltz_elements::Script::from(vec![0x51]),
    ));
    let txid = btc_like_txid(&transaction);
    let hex = serialize_claim_tx_hex(&transaction).unwrap();

    let reloaded = validate_reloaded_liquid_claim("test", &hex, Some(&txid), Some(&hex)).unwrap();
    assert_eq!(btc_like_txid(&reloaded), txid);

    let other_txid = "00".repeat(32);
    let mut witness_changed = match transaction {
        BtcLikeTransaction::Liquid(transaction) => transaction,
        BtcLikeTransaction::Bitcoin(_) => unreachable!("test transaction is Liquid"),
    };
    witness_changed.input[0].witness.script_witness = vec![vec![1]];
    assert_eq!(witness_changed.txid().to_string(), txid);
    let witness_changed_hex =
        serialize_claim_tx_hex(&BtcLikeTransaction::Liquid(witness_changed)).unwrap();

    for result in [
        validate_reloaded_liquid_claim("test", &hex, None, Some(&hex)),
        validate_reloaded_liquid_claim("test", &hex, Some(&txid), None),
        validate_reloaded_liquid_claim("test", &hex, Some(&other_txid), Some(&hex)),
        validate_reloaded_liquid_claim("test", &hex, Some(&txid), Some(&witness_changed_hex)),
        validate_reloaded_liquid_claim("test", "00", Some(&txid), Some("00")),
    ] {
        assert!(matches!(result, Err(AppError::ClaimError(_))));
    }
}

#[tokio::test]
async fn recover_claim_from_lockup_spend_returns_discovered_spender() {
    let claim_script = elements::Script::from(vec![0x51]);
    let boltz_claim_script = boltz_elements::Script::from(vec![0x51]);
    let lockup_tx = test_liquid_tx(None, elements::Script::new());
    let lockup_txid = lockup_tx.txid();
    let boltz_lockup_txid = lockup_txid
        .to_string()
        .parse()
        .expect("lockup txid parses as boltz elements txid");
    let claim_tx = test_boltz_liquid_tx(
        Some(boltz_elements::OutPoint::new(boltz_lockup_txid, 0)),
        boltz_claim_script,
    );
    let spending_tx = test_liquid_tx(Some(elements::OutPoint::new(lockup_txid, 0)), claim_script);
    let spender = spending_tx.txid().to_string();
    let backend = Arc::new(MockUtxoBackend {
        raw_txs: HashMap::from([
            (lockup_txid.to_string(), serialize(&lockup_tx)),
            (spender.clone(), serialize(&spending_tx)),
        ]),
        find_calls: Mutex::new(vec![]),
        spender: Some(spender.clone()),
    });

    let backend_dyn: Arc<dyn UtxoBackend> = backend.clone();
    let got = recover_claim_from_lockup_spend(&BtcLikeTransaction::Liquid(claim_tx), &backend_dyn)
        .await
        .unwrap();

    assert_eq!(got, Some(spender));
    assert_eq!(
        backend.find_calls.lock().await.as_slice(),
        &[(lockup_txid.to_string(), 0)]
    );
}

#[tokio::test]
async fn recover_claim_from_lockup_spend_returns_none_when_unspent() {
    let lockup_tx = test_liquid_tx(None, elements::Script::new());
    let lockup_txid = lockup_tx.txid();
    let boltz_lockup_txid = lockup_txid
        .to_string()
        .parse()
        .expect("lockup txid parses as boltz elements txid");
    let claim_tx = test_boltz_liquid_tx(
        Some(boltz_elements::OutPoint::new(boltz_lockup_txid, 0)),
        boltz_elements::Script::from(vec![0x51]),
    );
    let backend = Arc::new(MockUtxoBackend {
        raw_txs: HashMap::from([(lockup_txid.to_string(), serialize(&lockup_tx))]),
        find_calls: Mutex::new(vec![]),
        spender: None,
    });

    let backend_dyn: Arc<dyn UtxoBackend> = backend.clone();
    let got = recover_claim_from_lockup_spend(&BtcLikeTransaction::Liquid(claim_tx), &backend_dyn)
        .await
        .unwrap();

    assert_eq!(got, None);
}

#[tokio::test]
async fn recover_claim_from_lockup_spend_rejects_non_claim_destination() {
    let lockup_tx = test_liquid_tx(None, elements::Script::new());
    let lockup_txid = lockup_tx.txid();
    let boltz_lockup_txid = lockup_txid
        .to_string()
        .parse()
        .expect("lockup txid parses as boltz elements txid");
    let claim_tx = test_boltz_liquid_tx(
        Some(boltz_elements::OutPoint::new(boltz_lockup_txid, 0)),
        boltz_elements::Script::from(vec![0x51]),
    );
    let spending_tx = test_liquid_tx(
        Some(elements::OutPoint::new(lockup_txid, 0)),
        elements::Script::from(vec![0x52]),
    );
    let spender = spending_tx.txid().to_string();
    let backend = Arc::new(MockUtxoBackend {
        raw_txs: HashMap::from([
            (lockup_txid.to_string(), serialize(&lockup_tx)),
            (spender, serialize(&spending_tx)),
        ]),
        find_calls: Mutex::new(vec![]),
        spender: Some(spending_tx.txid().to_string()),
    });

    let backend_dyn: Arc<dyn UtxoBackend> = backend.clone();
    let got =
        recover_claim_from_lockup_spend(&BtcLikeTransaction::Liquid(claim_tx), &backend_dyn).await;

    assert!(matches!(got, Err(AppError::ClaimError(_))));
}

#[test]
fn chain_swap_expired_is_not_terminal() {
    // `swap.expired` is Boltz's wall-clock timer, not the on-chain lockup
    // timeout — the server lockup stays claimable until timeoutBlockHeight.
    // It must NOT map to terminal `Expired` (which abandoned claimable funds);
    // it is folded by the shared transition as a one-way script-claim hint.
    assert_eq!(
        chain_swap_provider_input("swap.expired"),
        Some(db::ChainSwapProviderStatusInput::SwapExpired)
    );
}

#[test]
fn chain_swap_status_mapping_feeds_the_shared_transition() {
    assert_eq!(
        chain_swap_provider_input("transaction.server.confirmed"),
        Some(db::ChainSwapProviderStatusInput::ServerLockConfirmed)
    );
    // 0-conf rejection is a "wait for confirmation" signal, not a failure —
    // it must re-sight the user lockup, never terminalize (was a live loss bug).
    assert_eq!(
        chain_swap_provider_input("transaction.zeroconf.rejected"),
        Some(db::ChainSwapProviderStatusInput::UserLockMempool)
    );
    assert_eq!(
        chain_swap_provider_input("transaction.refunded"),
        Some(db::ChainSwapProviderStatusInput::FundingFailed)
    );
    assert_eq!(
        chain_swap_provider_input("transaction.lockupFailed"),
        Some(db::ChainSwapProviderStatusInput::Observe)
    );
    assert_eq!(
        chain_swap_provider_input("transaction.failed"),
        Some(db::ChainSwapProviderStatusInput::FundingFailed)
    );
}

#[test]
fn electrum_host_port_strips_scheme_for_boltz_client() {
    // boltz-client re-adds ssl://; we must hand it a bare host:port.
    assert_eq!(
        electrum_host_port("ssl://les.bullbitcoin.com:50002"),
        "les.bullbitcoin.com:50002"
    );
    assert_eq!(
        electrum_host_port("ssl://172.16.0.15:50002"),
        "172.16.0.15:50002"
    );
    assert_eq!(electrum_host_port("tcp://host:50001"), "host:50001");
    // Already bare — unchanged.
    assert_eq!(electrum_host_port("host:50002"), "host:50002");
}

#[test]
fn liquid_claim_factory_requires_a_structurally_valid_endpoint() {
    assert!(LiquidClaimClientFactory::try_new(Vec::new()).is_err());
    assert!(LiquidClaimClientFactory::try_new(vec![
        "not-a-url".to_string(),
        "ssl://missing-port".to_string(),
        "tcp://host:0".to_string(),
    ])
    .is_err());
}

#[test]
fn liquid_claim_factory_retains_only_valid_failover_endpoints() {
    let factory = LiquidClaimClientFactory::try_new(vec![
        "invalid".to_string(),
        "ssl://les.bullbitcoin.com:995".to_string(),
        "tcp://127.0.0.1:50001".to_string(),
    ])
    .expect("at least one valid claim endpoint");

    assert_eq!(
        factory.urls(),
        [
            "ssl://les.bullbitcoin.com:995".to_string(),
            "tcp://127.0.0.1:50001".to_string(),
        ]
    );
}

#[tokio::test]
async fn claim_client_startup_retries_until_success_then_never_probes_again() {
    let calls = Cell::new(0usize);
    let mut startup = ClaimClientStartup::default();

    let first = startup
        .ensure_initialized(|| async {
            calls.set(calls.get() + 1);
            Err(AppError::ClaimError("scripted probe failure".to_string()))
        })
        .await;
    assert!(first.is_err());
    assert!(!startup.initialized);
    assert_eq!(calls.get(), 1);

    let initialized_now = startup
        .ensure_initialized(|| async {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .await
        .expect("second probe succeeds");
    assert!(initialized_now);
    assert!(startup.initialized);
    assert_eq!(calls.get(), 2);

    let initialized_now = startup
        .ensure_initialized(|| async {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .await
        .expect("latched startup remains healthy");
    assert!(!initialized_now);
    assert_eq!(calls.get(), 2, "latched startup must not probe again");
}

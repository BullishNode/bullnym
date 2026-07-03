use super::*;
use async_trait::async_trait;
use elements::encode::serialize;
use std::collections::HashMap;
use tokio::sync::Mutex;

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
fn cooperative_refusal_recognises_known_phrases() {
    for phrase in [
        "construct_claim failed: serde error: swap expired at line 1",
        "construct_claim failed: invalid preimage",
        "construct_claim failed: cooperative claim disabled",
        "construct_claim failed: cooperative signing disabled",
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
fn chain_swap_boltz_claimed_does_not_terminalize_local_status() {
    assert_eq!(
        chain_swap_status_from_boltz_status("transaction.server.mempool"),
        Some(ChainSwapStatus::ServerLockMempool)
    );
    assert_eq!(
        chain_swap_status_from_boltz_status("transaction.claimed"),
        None
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

    async fn has_history(&self, _script_pubkey: &elements::Script) -> Result<bool, AppError> {
        Ok(false)
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

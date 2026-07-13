use std::collections::{BTreeMap, VecDeque};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode, Uri};
use axum::routing::any;
use axum::Router;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde_json::{json, Value};

use super::manifest_set_fixture;
use crate::chain_lockup_witness_adapter::{
    BitcoinLockupWitnessAdapterError, BitcoinLockupWitnessAdapterV1,
    BITCOIN_LOCKUP_WITNESS_PAGE_SIZE_V1, MAX_BITCOIN_LOCKUP_WITNESS_PAGES_V1,
};
use crate::chain_lockup_witness_audit::{
    ChainLockupInclusionV1, ChainLockupSpendV1, ChainLockupWitnessChainV1,
};
use crate::swap_manifest::SwapManifestV1;

#[derive(Clone)]
struct Reply {
    status: StatusCode,
    body: String,
}

impl Reply {
    fn ok(body: impl Into<String>) -> Self {
        Self {
            status: StatusCode::OK,
            body: body.into(),
        }
    }

    fn failure() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: "backend-sensitive-body".into(),
        }
    }
}

type Routes = Arc<Mutex<BTreeMap<String, VecDeque<Reply>>>>;

struct MockEsplora {
    endpoint: String,
    routes: Routes,
    task: tokio::task::JoinHandle<()>,
}

impl MockEsplora {
    async fn start(entries: Vec<(String, Vec<Reply>)>) -> Self {
        async fn handler(State(routes): State<Routes>, uri: Uri) -> Response<Body> {
            let reply = routes
                .lock()
                .unwrap()
                .get_mut(uri.path())
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(Reply::failure);
            Response::builder()
                .status(reply.status)
                .header("content-type", "application/json")
                .body(Body::from(reply.body))
                .unwrap()
        }

        let routes = Arc::new(Mutex::new(
            entries
                .into_iter()
                .map(|(path, replies)| (path, VecDeque::from(replies)))
                .collect(),
        ));
        let app = Router::new()
            .fallback(any(handler))
            .with_state(routes.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            endpoint,
            routes,
            task,
        }
    }

    fn remaining(&self, path: &str) -> usize {
        self.routes
            .lock()
            .unwrap()
            .get(path)
            .map(VecDeque::len)
            .unwrap_or(0)
    }
}

impl Drop for MockEsplora {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn manifest() -> SwapManifestV1 {
    manifest_set_fixture(1, None, 1_901, 3_902, 3_903, 3_905, 0x31, 0x32, 0x33)
}

fn target_script(manifest: &SwapManifestV1) -> ScriptBuf {
    Address::from_str(&manifest.creation.lockup_address)
        .unwrap()
        .require_network(Network::Bitcoin)
        .unwrap()
        .script_pubkey()
}

fn transaction(
    previous_output: OutPoint,
    script_pubkey: ScriptBuf,
    amount_sat: u64,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey,
        }],
    }
}

fn raw_hex(transaction: &Transaction) -> String {
    hex::encode(serialize(transaction))
}

fn status(confirmed: bool, height: Option<u32>, hash: Option<&str>) -> Value {
    json!({
        "confirmed": confirmed,
        "block_height": height,
        "block_hash": hash,
    })
}

fn history(txid: &str, tx_status: Value) -> String {
    json!([{"txid": txid, "status": tx_status}]).to_string()
}

fn adapter(endpoint: String) -> BitcoinLockupWitnessAdapterV1 {
    BitcoinLockupWitnessAdapterV1::try_new(vec![endpoint], Duration::from_secs(2)).unwrap()
}

fn common_routes(
    manifest: &SwapManifestV1,
    funding: &Transaction,
    funding_status: Value,
    tip: u32,
    tip_hash: &str,
    block_routes: Vec<(u32, String, usize)>,
    outspend: Value,
) -> Vec<(String, Vec<Reply>)> {
    let txid = funding.compute_txid().to_string();
    let mut routes = vec![
        (
            "/blocks/tip/height".into(),
            vec![Reply::ok(tip.to_string()), Reply::ok(tip.to_string())],
        ),
        (
            format!("/address/{}/txs", manifest.creation.lockup_address),
            vec![Reply::ok(history(&txid, funding_status.clone()))],
        ),
        (
            format!("/tx/{txid}/status"),
            vec![Reply::ok(funding_status.to_string())],
        ),
        (format!("/tx/{txid}/hex"), vec![Reply::ok(raw_hex(funding))]),
        (
            format!("/tx/{txid}/outspend/0"),
            vec![Reply::ok(outspend.to_string())],
        ),
    ];
    let mut block_routes = block_routes;
    if !block_routes.iter().any(|(height, _, _)| *height == tip) {
        block_routes.push((tip, tip_hash.to_owned(), 3));
    }
    routes.extend(block_routes.into_iter().map(|(height, hash, calls)| {
        (
            format!("/block-height/{height}"),
            (0..calls).map(|_| Reply::ok(hash.clone())).collect(),
        )
    }));
    routes
}

#[tokio::test]
async fn adapter_returns_exact_unspent_mempool_output_and_redacts_debug() {
    let manifest = manifest();
    let funding = transaction(OutPoint::null(), target_script(&manifest), 25_431);
    let txid = funding.compute_txid().to_string();
    let tip_hash = "11".repeat(32);
    let server = MockEsplora::start(common_routes(
        &manifest,
        &funding,
        status(false, None, None),
        900_000,
        &tip_hash,
        vec![],
        json!({"spent": false}),
    ))
    .await;

    let snapshot = adapter(server.endpoint.clone())
        .load_snapshot(std::slice::from_ref(&manifest))
        .await
        .unwrap();
    assert_eq!(snapshot.authority(), server.endpoint);
    assert_eq!(snapshot.observations.len(), 1);
    let observed = &snapshot.observations[0];
    assert_eq!(observed.chain, ChainLockupWitnessChainV1::BitcoinMainnet);
    assert_eq!(observed.txid, txid);
    assert_eq!(observed.vout, 0);
    assert_eq!(observed.amount_sat, 25_431);
    assert_eq!(observed.inclusion, ChainLockupInclusionV1::Mempool);
    assert_eq!(observed.spend, ChainLockupSpendV1::Unspent);
    let debug = format!("{snapshot:?}");
    assert!(!debug.contains(&server.endpoint));
    assert!(!debug.contains(&observed.txid));
    assert!(!debug.contains(&snapshot.tip_hash));
    assert_eq!(server.remaining("/blocks/tip/height"), 0);
}

#[tokio::test]
async fn adapter_returns_exact_confirmed_output_from_canonical_tip_facts() {
    let manifest = manifest();
    let funding = transaction(OutPoint::null(), target_script(&manifest), 25_431);
    let block_hash = "22".repeat(32);
    let tip_hash = "33".repeat(32);
    let funding_status = status(true, Some(899_998), Some(&block_hash));
    let server = MockEsplora::start(common_routes(
        &manifest,
        &funding,
        funding_status,
        900_000,
        &tip_hash,
        vec![(899_998, block_hash.clone(), 2)],
        json!({"spent": false}),
    ))
    .await;

    let snapshot = adapter(server.endpoint.clone())
        .load_snapshot(&[manifest])
        .await
        .unwrap();
    assert_eq!(
        snapshot.observations[0].inclusion,
        ChainLockupInclusionV1::Confirmed {
            confirmations: 3,
            block_height: 899_998,
            block_hash,
        }
    );
}

#[tokio::test]
async fn adapter_validates_spender_raw_input_identity_and_inclusion() {
    let manifest = manifest();
    let funding = transaction(OutPoint::null(), target_script(&manifest), 25_431);
    let funding_txid = funding.compute_txid();
    let spending = transaction(
        OutPoint {
            txid: funding_txid,
            vout: 0,
        },
        ScriptBuf::new(),
        25_000,
    );
    let spending_txid = spending.compute_txid().to_string();
    let funding_hash = "44".repeat(32);
    let spending_hash = "55".repeat(32);
    let tip_hash = spending_hash.clone();
    let mut routes = common_routes(
        &manifest,
        &funding,
        status(true, Some(899_999), Some(&funding_hash)),
        900_000,
        &tip_hash,
        vec![
            (899_999, funding_hash, 2),
            (900_000, spending_hash.clone(), 3),
        ],
        json!({
            "spent": true,
            "txid": spending_txid,
            "vin": 0,
            "status": status(true, Some(900_000), Some(&spending_hash)),
        }),
    );
    routes.push((
        format!("/tx/{spending_txid}/hex"),
        vec![Reply::ok(raw_hex(&spending))],
    ));
    let server = MockEsplora::start(routes).await;

    let snapshot = adapter(server.endpoint.clone())
        .load_snapshot(&[manifest])
        .await
        .unwrap();
    assert_eq!(
        snapshot.observations[0].spend,
        ChainLockupSpendV1::Spent {
            spending_txid,
            inclusion: ChainLockupInclusionV1::Confirmed {
                confirmations: 1,
                block_height: 900_000,
                block_hash: spending_hash,
            },
        }
    );
}

#[tokio::test]
async fn adapter_rejects_raw_txid_mismatch_instead_of_returning_missing() {
    let manifest = manifest();
    let funding = transaction(OutPoint::null(), target_script(&manifest), 25_431);
    let txid = funding.compute_txid().to_string();
    let wrong = transaction(OutPoint::null(), target_script(&manifest), 25_432);
    let tip_hash = "66".repeat(32);
    let mut routes = common_routes(
        &manifest,
        &funding,
        status(false, None, None),
        900_000,
        &tip_hash,
        vec![],
        json!({"spent": false}),
    );
    routes
        .iter_mut()
        .find(|(path, _)| path == &format!("/tx/{txid}/hex"))
        .unwrap()
        .1 = vec![Reply::ok(raw_hex(&wrong))];
    let server = MockEsplora::start(routes).await;

    assert_eq!(
        adapter(server.endpoint.clone())
            .load_snapshot(&[manifest])
            .await
            .unwrap_err(),
        BitcoinLockupWitnessAdapterError::NoCompleteAuthority
    );
}

#[tokio::test]
async fn adapter_discards_partial_authority_before_safe_failover() {
    let manifest = manifest();
    let funding = transaction(OutPoint::null(), target_script(&manifest), 25_431);
    let tip_hash = "77".repeat(32);
    let failed = MockEsplora::start(vec![
        ("/blocks/tip/height".into(), vec![Reply::ok("900000")]),
        (
            "/block-height/900000".into(),
            vec![Reply::ok(tip_hash.clone())],
        ),
        (
            format!("/address/{}/txs", manifest.creation.lockup_address),
            vec![Reply::failure()],
        ),
    ])
    .await;
    let healthy = MockEsplora::start(common_routes(
        &manifest,
        &funding,
        status(false, None, None),
        900_000,
        &tip_hash,
        vec![],
        json!({"spent": false}),
    ))
    .await;
    let loader = BitcoinLockupWitnessAdapterV1::try_new(
        vec![failed.endpoint.clone(), healthy.endpoint.clone()],
        Duration::from_secs(2),
    )
    .unwrap();

    let snapshot = loader.load_snapshot(&[manifest]).await.unwrap();
    assert_eq!(snapshot.authority(), healthy.endpoint);
    assert_eq!(snapshot.observations.len(), 1);
    assert_eq!(
        failed.remaining(&format!(
            "/address/{}/txs",
            snapshot.observations[0].lockup_address
        )),
        0
    );
}

#[tokio::test]
async fn adapter_fails_closed_on_full_final_page_and_backend_failure() {
    let manifest = manifest();
    let height = 899_900;
    let block_hash = "88".repeat(32);
    let tip_hash = "99".repeat(32);
    let mut entries = Vec::new();
    let mut next_tx = 0usize;
    let mut first_path = format!("/address/{}/txs", manifest.creation.lockup_address);
    for page_index in 0..MAX_BITCOIN_LOCKUP_WITNESS_PAGES_V1 {
        let page = (0..BITCOIN_LOCKUP_WITNESS_PAGE_SIZE_V1)
            .map(|_| {
                let txid = format!("{next_tx:064x}");
                next_tx += 1;
                json!({
                    "txid": txid,
                    "status": status(true, Some(height), Some(&block_hash)),
                })
            })
            .collect::<Vec<_>>();
        let cursor = page.last().unwrap()["txid"].as_str().unwrap().to_owned();
        entries.push((first_path, vec![Reply::ok(Value::Array(page).to_string())]));
        first_path = format!(
            "/address/{}/txs/chain/{cursor}",
            manifest.creation.lockup_address
        );
        assert_eq!(page_index + 1, entries.len());
    }
    entries.extend([
        ("/blocks/tip/height".into(), vec![Reply::ok("900000")]),
        ("/block-height/900000".into(), vec![Reply::ok(tip_hash)]),
    ]);
    let truncated = MockEsplora::start(entries).await;
    assert_eq!(
        adapter(truncated.endpoint.clone())
            .load_snapshot(std::slice::from_ref(&manifest))
            .await
            .unwrap_err(),
        BitcoinLockupWitnessAdapterError::NoCompleteAuthority
    );

    let failed =
        MockEsplora::start(vec![("/blocks/tip/height".into(), vec![Reply::failure()])]).await;
    let error = adapter(failed.endpoint.clone())
        .load_snapshot(&[manifest])
        .await
        .unwrap_err();
    assert_eq!(error, BitcoinLockupWitnessAdapterError::NoCompleteAuthority);
    assert!(error.to_string().len() <= 80);
    assert!(std::error::Error::source(&error).is_none());
    assert!(!format!("{error:?}").contains("backend-sensitive-body"));
}

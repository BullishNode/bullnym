//! Crash-safe Bitcoin recovery execution for BTC->L-BTC chain swaps.
//!
//! The central invariant is deliberately mechanical: no broadcaster receives
//! transaction bytes until those exact bytes and their immutable intent have
//! committed to `chain_swap_tx_attempts`.  Restart reconciliation only ever
//! replays that committed transaction.

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, Signature as TaprootSignature};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxOut,
    XOnlyPublicKey,
};
use boltz_client::network::esplora::EsploraBitcoinClient;
use boltz_client::network::{BitcoinChain, Chain};
use boltz_client::swaps::bitcoin::BtcSwapScript;
use boltz_client::swaps::boltz::{BoltzApiClientV2, CreateChainResponse, PartialSig, Side};
use boltz_client::swaps::{
    BtcLikeTransaction, ChainClient, SwapScript, SwapTransactionParams, TransactionOptions,
};
use boltz_client::util::fees::Fee;
use boltz_client::{Keypair, PublicKey, Secp256k1};
use secp256k1_musig::musig;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::builder_fee::BitcoinBuilderFeeDecision;
use crate::chain_swap_action::{
    reduce_chain_swap_evidence, BitcoinSourceEvidence, BitcoinTimeoutEvidence, ChainSwapAction,
    CooperativeRecoveryEvidence, MerchantTransactionEvidence,
};
use crate::chain_swap_runtime_evidence::{
    collect_automatic_fallback_evidence_under_lock, AutomaticFallbackConstructionPath,
    CollectedAutomaticFallbackEvidence,
};
use crate::cooperative_bitcoin_refund::{
    complete_exact_cooperative_refund, exact_chain_lockup_script, prepare_exact_cooperative_refund,
    provider_partial_signature_for_integration_test, select_exact_source,
    DurableCooperativeRequest, PreparedCooperativeRefund,
};
use crate::db::{
    self, ChainSwapRecord, ChainSwapStatus, ChainSwapTxAttempt, NewBitcoinRecoveryAttempt,
    RecoverySourcePrevout,
};
use crate::error::AppError;
use crate::fee_decision_record::{FeeConstructionPurpose, FeeDecisionRecord};
use crate::fee_policy::{BitcoinFeeDecision, BitcoinFeePolicy, FeeFreshness};
use crate::fee_runtime::FeeRuntime;
use crate::swap_manifest_runtime::CooperativeSigningNonceEnvelopeV1;
use crate::AppState;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Stable, non-secret reason returned when a new recovery cannot be built
/// without accepted live or recent same-rail fee evidence.
#[doc(hidden)]
pub const BITCOIN_FEE_DECISION_PENDING_REASON: &str =
    "Bitcoin fee decision unavailable; retry after accepted live or recent same-rail evidence";

fn bitcoin_recovery_fee(decision: BitcoinBuilderFeeDecision) -> Fee {
    Fee::Relative(decision.rate().as_f64())
}

/// Deterministic failure points used by the first incremental #88 harness.
/// Production uses [`NoRecoveryFaults`]; integration tests stop a worker at
/// each point and invoke it again to prove exact resume behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryFaultPoint {
    BeforeConstruction,
    AfterConstructionBeforeJournal,
    AfterJournalWriteBeforeCommit,
    AfterJournalCommitBeforeBroadcast,
    AfterBroadcastAttemptCommit,
    AfterBroadcastCallBeforeOutcomeCommit,
    AfterCooperativeRequestedCommitBeforeProvider,
    AfterCooperativeProviderBeforeResponseCommit,
    AfterCooperativeResponseCommit,
    AfterCooperativeAttemptWriteBeforeCommit,
}

pub trait RecoveryFaultInjector: Send + Sync {
    fn check(&self, point: RecoveryFaultPoint) -> Result<(), AppError>;
}

#[derive(Debug, Default)]
pub struct NoRecoveryFaults;

impl RecoveryFaultInjector for NoRecoveryFaults {
    fn check(&self, _point: RecoveryFaultPoint) -> Result<(), AppError> {
        Ok(())
    }
}

#[async_trait]
pub trait BitcoinRecoveryBuilder: Send + Sync {
    /// Construct a new attempt with the caller's already-validated decision.
    /// The write-ahead executor never calls this method once an attempt exists.
    async fn construct(
        &self,
        swap: &ChainSwapRecord,
        destination_address: &str,
        fee_decision: BitcoinBuilderFeeDecision,
    ) -> Result<BtcLikeTransaction, AppError>;

    /// Automatic execution must choose the spend path from fresh under-lock
    /// evidence. Test builders retain the compatibility default; the live
    /// builder overrides it so a pre-timeout failure can never fall through to
    /// the unilateral script path.
    async fn construct_automatic(
        &self,
        swap: &ChainSwapRecord,
        destination_address: &str,
        fee_decision: BitcoinBuilderFeeDecision,
        _path: AutomaticFallbackConstructionPath,
    ) -> Result<BtcLikeTransaction, AppError> {
        self.construct(swap, destination_address, fee_decision)
            .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcoinOutspend {
    Unspent,
    Spent { txid: String },
}

/// Tx-specific Bitcoin chain position from one internally consistent Esplora
/// tip/status/block read. `Absent` is positive evidence only when every
/// configured endpoint returned a complete absent snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcoinRecoveryTransactionStatus {
    Absent,
    Mempool,
    Confirmed {
        block_height: u32,
        block_hash: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinRecoveryStatusSnapshot {
    pub tip_height: u32,
    pub status: BitcoinRecoveryTransactionStatus,
    /// Current canonical hash at the caller's prior positive height. `None`
    /// means that height is above this authority's current tip.
    pub prior_block_hash: Option<String>,
}

#[async_trait]
pub trait BitcoinRecoveryEvidence: Send + Sync {
    /// Return exact raw bytes, `None` only when all configured backends
    /// positively report the tx absent, and `Err` when presence is unknown.
    /// Cross-provider agreement policy is added by the #82 evidence reducer.
    async fn raw_transaction(&self, txid: &str) -> Result<Option<Vec<u8>>, AppError>;

    async fn outspend(&self, txid: &str, vout: u32) -> Result<BitcoinOutspend, AppError>;

    /// Fetch an internally consistent Esplora status/tip/block snapshot. The
    /// fail-closed default preserves deterministic recovery-executor mocks;
    /// merchant-settlement observation requires a backend that implements the
    /// anchored contract.
    async fn status_snapshot(
        &self,
        _txid: &str,
        _prior_block_height: Option<u32>,
    ) -> Result<BitcoinRecoveryStatusSnapshot, AppError> {
        Err(AppError::ElectrumError(
            "Bitcoin recovery backend does not provide anchored status snapshots".into(),
        ))
    }
}

#[async_trait]
pub trait BitcoinRecoveryBroadcaster: Send + Sync {
    async fn broadcast(&self, raw_tx_hex: &str, expected_txid: &str) -> Result<String, AppError>;
}

struct LiveRecoveryBuilder<'a> {
    state: &'a AppState,
}

#[async_trait]
impl BitcoinRecoveryBuilder for LiveRecoveryBuilder<'_> {
    async fn construct(
        &self,
        swap: &ChainSwapRecord,
        destination_address: &str,
        fee_decision: BitcoinBuilderFeeDecision,
    ) -> Result<BtcLikeTransaction, AppError> {
        construct_live_refund(
            self.state,
            swap,
            destination_address,
            fee_decision,
            AutomaticFallbackConstructionPath::Unilateral,
        )
        .await
    }

    async fn construct_automatic(
        &self,
        swap: &ChainSwapRecord,
        destination_address: &str,
        fee_decision: BitcoinBuilderFeeDecision,
        path: AutomaticFallbackConstructionPath,
    ) -> Result<BtcLikeTransaction, AppError> {
        construct_live_refund(self.state, swap, destination_address, fee_decision, path).await
    }
}

/// Initialized, reusable witness for the Bitcoin recovery evidence path.
/// Network reachability remains transient worker evidence; construction only
/// validates the immutable endpoint set and builds the shared HTTP client.
pub struct BitcoinRecoveryBackend {
    endpoints: Vec<String>,
    client: reqwest::Client,
}

impl BitcoinRecoveryBackend {
    pub fn try_new(endpoints: Vec<String>) -> Result<Self, AppError> {
        let endpoints: Vec<String> = endpoints
            .into_iter()
            .filter(|endpoint| crate::config::valid_http_endpoint(endpoint))
            .collect();
        if endpoints.is_empty() {
            return Err(AppError::ElectrumError(
                "Bitcoin recovery has no valid evidence backend".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| AppError::ElectrumError(format!("build Bitcoin evidence client: {e}")))?;
        Ok(Self { endpoints, client })
    }

    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }
}

#[derive(Deserialize)]
struct EsploraOutspend {
    spent: bool,
    txid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EsploraRecoveryTransactionStatus {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<String>,
}

#[async_trait]
impl BitcoinRecoveryEvidence for BitcoinRecoveryBackend {
    async fn raw_transaction(&self, txid: &str) -> Result<Option<Vec<u8>>, AppError> {
        let mut not_found = 0usize;
        let mut errors = Vec::new();
        for endpoint in &self.endpoints {
            let url = format!("{}/tx/{txid}/hex", endpoint.trim_end_matches('/'));
            match self.client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    let body = response.text().await.map_err(|e| {
                        AppError::ElectrumError(format!(
                            "read raw transaction from {endpoint}: {e}"
                        ))
                    })?;
                    let bytes = hex::decode(body.trim()).map_err(|e| {
                        AppError::ElectrumError(format!(
                            "Bitcoin backend {endpoint} returned invalid transaction hex: {e}"
                        ))
                    })?;
                    let tx: Transaction = deserialize(&bytes).map_err(|e| {
                        AppError::ElectrumError(format!(
                            "Bitcoin backend {endpoint} returned invalid transaction: {e}"
                        ))
                    })?;
                    if tx.compute_txid().to_string() != txid {
                        return Err(AppError::ElectrumError(format!(
                            "Bitcoin backend {endpoint} returned bytes with the wrong txid"
                        )));
                    }
                    return Ok(Some(bytes));
                }
                Ok(response) if response.status() == reqwest::StatusCode::NOT_FOUND => {
                    not_found += 1;
                }
                Ok(response) => errors.push(format!("{endpoint}: HTTP {}", response.status())),
                Err(e) => errors.push(format!("{endpoint}: {e}")),
            }
        }
        if not_found == self.endpoints.len() {
            Ok(None)
        } else {
            Err(AppError::ElectrumError(format!(
                "Bitcoin transaction presence is unknown for {txid}: {}",
                errors.join(" | ")
            )))
        }
    }

    async fn outspend(&self, txid: &str, vout: u32) -> Result<BitcoinOutspend, AppError> {
        let mut errors = Vec::new();
        for endpoint in &self.endpoints {
            let url = format!(
                "{}/tx/{txid}/outspend/{vout}",
                endpoint.trim_end_matches('/')
            );
            match self.client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    let value: EsploraOutspend = response.json().await.map_err(|e| {
                        AppError::ElectrumError(format!(
                            "decode Bitcoin outspend from {endpoint}: {e}"
                        ))
                    })?;
                    return if value.spent {
                        value
                            .txid
                            .filter(|id| {
                                id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
                            })
                            .map(|txid| BitcoinOutspend::Spent {
                                txid: txid.to_lowercase(),
                            })
                            .ok_or_else(|| {
                                AppError::ElectrumError(format!(
                                    "Bitcoin backend {endpoint} reported a spend without a valid txid"
                                ))
                            })
                    } else {
                        Ok(BitcoinOutspend::Unspent)
                    };
                }
                Ok(response) => errors.push(format!("{endpoint}: HTTP {}", response.status())),
                Err(e) => errors.push(format!("{endpoint}: {e}")),
            }
        }
        Err(AppError::ElectrumError(format!(
            "Bitcoin outspend state is unknown for {txid}:{vout}: {}",
            errors.join(" | ")
        )))
    }

    async fn status_snapshot(
        &self,
        txid: &str,
        prior_block_height: Option<u32>,
    ) -> Result<BitcoinRecoveryStatusSnapshot, AppError> {
        if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AppError::ElectrumError(
                "Bitcoin recovery status requested for an invalid txid".into(),
            ));
        }
        let mut absent = None;
        let mut absent_count = 0usize;
        let mut errors = Vec::new();
        for endpoint in &self.endpoints {
            match fetch_bitcoin_recovery_status_snapshot(
                &self.client,
                endpoint,
                txid,
                prior_block_height,
            )
            .await
            {
                Ok(snapshot)
                    if !matches!(snapshot.status, BitcoinRecoveryTransactionStatus::Absent) =>
                {
                    return Ok(snapshot);
                }
                Ok(snapshot) => {
                    if absent.as_ref().is_some_and(|prior| prior != &snapshot) {
                        errors.push(
                            "configured Bitcoin recovery backends disagreed on absent anchors"
                                .into(),
                        );
                        continue;
                    }
                    absent_count += 1;
                    absent.get_or_insert(snapshot);
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
        if absent_count == self.endpoints.len() {
            return absent.ok_or_else(|| {
                AppError::ElectrumError("Bitcoin recovery absent snapshot disappeared".into())
            });
        }
        Err(AppError::ElectrumError(format!(
            "Bitcoin transaction status is unknown for {txid}: {}",
            errors.join(" | ")
        )))
    }
}

async fn fetch_bitcoin_recovery_status_snapshot(
    client: &reqwest::Client,
    endpoint: &str,
    txid: &str,
    prior_block_height: Option<u32>,
) -> Result<BitcoinRecoveryStatusSnapshot, AppError> {
    let endpoint = endpoint.trim_end_matches('/');
    let first_tip = fetch_esplora_tip(client, endpoint).await?;
    let first_status = fetch_esplora_recovery_status(client, endpoint, txid).await?;
    let status = normalize_esplora_recovery_status(first_status)?;
    if let BitcoinRecoveryTransactionStatus::Confirmed {
        block_height,
        block_hash,
    } = &status
    {
        if *block_height == 0 || *block_height > first_tip {
            return Err(AppError::ElectrumError(
                "Bitcoin recovery confirmed height is outside the observed tip".into(),
            ));
        }
        let anchored = fetch_esplora_block_hash(client, endpoint, *block_height).await?;
        if anchored != *block_hash {
            return Err(AppError::ElectrumError(
                "Bitcoin recovery status block hash disagrees with its height anchor".into(),
            ));
        }
    }
    let prior_block_hash = match prior_block_height {
        Some(0) => {
            return Err(AppError::ElectrumError(
                "Bitcoin recovery prior block height must be positive".into(),
            ));
        }
        Some(height) if height <= first_tip => match &status {
            BitcoinRecoveryTransactionStatus::Confirmed {
                block_height,
                block_hash,
            } if *block_height == height => Some(block_hash.clone()),
            _ => Some(fetch_esplora_block_hash(client, endpoint, height).await?),
        },
        Some(_) | None => None,
    };

    let final_status = normalize_esplora_recovery_status(
        fetch_esplora_recovery_status(client, endpoint, txid).await?,
    )?;
    if final_status != status {
        return Err(AppError::ElectrumError(
            "Bitcoin recovery status changed during anchored observation".into(),
        ));
    }
    let final_tip = fetch_esplora_tip(client, endpoint).await?;
    if final_tip != first_tip {
        return Err(AppError::ElectrumError(
            "Bitcoin recovery tip changed during anchored observation".into(),
        ));
    }
    Ok(BitcoinRecoveryStatusSnapshot {
        tip_height: first_tip,
        status,
        prior_block_hash,
    })
}

async fn fetch_esplora_tip(client: &reqwest::Client, endpoint: &str) -> Result<u32, AppError> {
    let response = client
        .get(format!("{endpoint}/blocks/tip/height"))
        .send()
        .await
        .map_err(|error| AppError::ElectrumError(format!("Bitcoin recovery tip: {error}")))?;
    if !response.status().is_success() {
        return Err(AppError::ElectrumError(format!(
            "Bitcoin recovery tip returned HTTP {}",
            response.status()
        )));
    }
    let body = response
        .text()
        .await
        .map_err(|error| AppError::ElectrumError(format!("read Bitcoin recovery tip: {error}")))?;
    body.trim()
        .parse::<u32>()
        .map_err(|_| AppError::ElectrumError("Bitcoin recovery tip is not a u32".into()))
}

async fn fetch_esplora_recovery_status(
    client: &reqwest::Client,
    endpoint: &str,
    txid: &str,
) -> Result<Option<EsploraRecoveryTransactionStatus>, AppError> {
    let response = client
        .get(format!("{endpoint}/tx/{txid}/status"))
        .send()
        .await
        .map_err(|error| AppError::ElectrumError(format!("Bitcoin recovery status: {error}")))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(AppError::ElectrumError(format!(
            "Bitcoin recovery status returned HTTP {}",
            response.status()
        )));
    }
    response
        .json::<EsploraRecoveryTransactionStatus>()
        .await
        .map(Some)
        .map_err(|error| {
            AppError::ElectrumError(format!("decode Bitcoin recovery status: {error}"))
        })
}

fn normalize_esplora_recovery_status(
    status: Option<EsploraRecoveryTransactionStatus>,
) -> Result<BitcoinRecoveryTransactionStatus, AppError> {
    let Some(status) = status else {
        return Ok(BitcoinRecoveryTransactionStatus::Absent);
    };
    if !status.confirmed {
        if status.block_height.is_some() || status.block_hash.is_some() {
            return Err(AppError::ElectrumError(
                "unconfirmed Bitcoin recovery status carried block identity".into(),
            ));
        }
        return Ok(BitcoinRecoveryTransactionStatus::Mempool);
    }
    let block_height = status.block_height.ok_or_else(|| {
        AppError::ElectrumError("confirmed Bitcoin recovery status omitted block height".into())
    })?;
    let block_hash = status
        .block_hash
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(|hash| hash.to_ascii_lowercase())
        .ok_or_else(|| {
            AppError::ElectrumError("confirmed Bitcoin recovery status omitted block hash".into())
        })?;
    Ok(BitcoinRecoveryTransactionStatus::Confirmed {
        block_height,
        block_hash,
    })
}

async fn fetch_esplora_block_hash(
    client: &reqwest::Client,
    endpoint: &str,
    height: u32,
) -> Result<String, AppError> {
    let response = client
        .get(format!("{endpoint}/block-height/{height}"))
        .send()
        .await
        .map_err(|error| {
            AppError::ElectrumError(format!("Bitcoin recovery block anchor: {error}"))
        })?;
    if !response.status().is_success() {
        return Err(AppError::ElectrumError(format!(
            "Bitcoin recovery block anchor returned HTTP {}",
            response.status()
        )));
    }
    let hash = response
        .text()
        .await
        .map_err(|error| AppError::ElectrumError(format!("read Bitcoin block anchor: {error}")))?;
    let hash = hash.trim();
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::ElectrumError(
            "Bitcoin recovery block anchor is not a canonical hash".into(),
        ));
    }
    Ok(hash.to_ascii_lowercase())
}

struct EsploraRecoveryBroadcaster {
    endpoints: Vec<String>,
}

/// Narrow boundary around the single provider-mutating cooperative request.
/// The executor calls this only after the exact request transition commits;
/// tests inject a counter so source drift and CAS retries can prove zero POSTs.
#[async_trait]
trait CooperativeSigningProvider: Send + Sync {
    async fn request_partial_signature(
        &self,
        boltz_swap_id: &str,
        input_index: u32,
        client_public_nonce_hex: &str,
        transaction_hex: &str,
    ) -> Result<PartialSig, AppError>;
}

struct LiveCooperativeSigningProvider {
    api_url: String,
}

#[async_trait]
impl CooperativeSigningProvider for LiveCooperativeSigningProvider {
    async fn request_partial_signature(
        &self,
        boltz_swap_id: &str,
        input_index: u32,
        client_public_nonce_hex: &str,
        transaction_hex: &str,
    ) -> Result<PartialSig, AppError> {
        if input_index != 0 {
            return Err(AppError::ClaimError(
                "cooperative provider request input index is not canonical".into(),
            ));
        }
        let public_nonce = musig::PublicNonce::from_str(client_public_nonce_hex).map_err(|_| {
            AppError::ClaimError("cooperative provider request public nonce is invalid".into())
        })?;
        let provider = BoltzApiClientV2::new(self.api_url.clone(), Some(Duration::from_secs(15)));
        provider
            .get_chain_partial_sig(
                &boltz_swap_id.to_owned(),
                input_index as usize,
                &public_nonce,
                &transaction_hex.to_owned(),
            )
            .await
            .map_err(|_| {
                AppError::RecoveryNotAvailable(
                    "cooperative provider request outcome is unknown".into(),
                )
            })
    }
}

/// Every configured construction backend must expose exactly the one source
/// selected by the primary authority. This check happens before the durable
/// signing request is prepared, and the exact returned prevout is injected
/// directly into Bullnym's transaction template; no address-wide SDK fetch is
/// performed after this boundary.
async fn exact_cooperative_source_across_backends(
    script: &BtcSwapScript,
    expected: OutPoint,
    expected_txout: &TxOut,
    endpoints: &[String],
) -> Result<TxOut, AppError> {
    if endpoints.is_empty() {
        return Err(AppError::ElectrumError(
            "cooperative recovery has no construction backend".into(),
        ));
    }
    let mut agreed = None;
    for endpoint in endpoints {
        let client = EsploraBitcoinClient::new(BitcoinChain::Bitcoin, endpoint, 30);
        let sources = script.fetch_utxos(&client).await.map_err(|error| {
            AppError::ElectrumError(format!(
                "cooperative recovery source read failed on {endpoint}: {error}"
            ))
        })?;
        let candidate = select_exact_source(&expected, expected_txout, sources)?;
        if agreed.as_ref().is_some_and(|prior| prior != &candidate) {
            return Err(AppError::ElectrumError(
                "cooperative recovery construction backends disagree on the exact source".into(),
            ));
        }
        agreed.get_or_insert(candidate);
    }
    agreed.ok_or_else(|| {
        AppError::ElectrumError("cooperative recovery exact source disappeared".into())
    })
}

struct LiveCooperativePreparation {
    prepared: PreparedCooperativeRefund,
    source_outpoint: OutPoint,
    source_txout: TxOut,
    destination_address: String,
    fee_record: FeeDecisionRecord,
}

struct CooperativeOperationDigests {
    provider_request_sha256: String,
    session_sha256: String,
}

fn framed_sha256(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hex::encode(hasher.finalize())
}

fn cooperative_operation_digests(
    swap: &ChainSwapRecord,
    preparation: &LiveCooperativePreparation,
) -> Result<CooperativeOperationDigests, AppError> {
    let request = preparation.prepared.durable_request();
    let input_index = request.input_index.to_string();
    let provider_request_sha256 = framed_sha256(
        b"bullnym/boltz-chain-refund-signature-request/v1",
        &[
            swap.boltz_swap_id.as_bytes(),
            request.public_nonce_hex.as_bytes(),
            request.unsigned_tx_hex.as_bytes(),
            input_index.as_bytes(),
        ],
    );
    let source_txid = preparation.source_outpoint.txid.to_string();
    let source_vout = preparation.source_outpoint.vout.to_string();
    let source_amount = preparation.source_txout.value.to_sat().to_string();
    let fee = &preparation.fee_record;
    let fee_rate = fee.rate().as_f64().to_bits().to_string();
    let fee_quoted = fee.quoted_at_unix().to_string();
    let fee_evaluated = fee.evaluated_at_unix().to_string();
    let fee_age = fee.freshness_age_secs().to_string();
    let fee_max_age = fee.freshness_max_age_secs().to_string();
    let fee_floor = fee.policy_floor().as_f64().to_bits().to_string();
    let fee_cap = fee.policy_cap().as_f64().to_bits().to_string();
    let secret_commitment =
        hex::encode(Sha256::digest(preparation.prepared.secret_nonce().expose()));
    let session_sha256 = framed_sha256(
        b"bullnym/cooperative-signing-session/v1",
        &[
            swap.id.as_bytes(),
            swap.boltz_swap_id.as_bytes(),
            source_txid.as_bytes(),
            source_vout.as_bytes(),
            source_amount.as_bytes(),
            preparation.source_txout.script_pubkey.as_bytes(),
            request.unsigned_tx_hex.as_bytes(),
            request.sighash_hex.as_bytes(),
            request.tweaked_aggregate_key_hex.as_bytes(),
            request.public_nonce_hex.as_bytes(),
            fee.purpose().as_str().as_bytes(),
            fee.rail().as_str().as_bytes(),
            fee.target().as_str().as_bytes(),
            fee.source().as_str().as_bytes(),
            fee_rate.as_bytes(),
            fee_quoted.as_bytes(),
            fee_evaluated.as_bytes(),
            fee_age.as_bytes(),
            fee_max_age.as_bytes(),
            fee.provenance_for_persistence().as_bytes(),
            fee_floor.as_bytes(),
            fee_cap.as_bytes(),
            fee.policy_version().as_bytes(),
            provider_request_sha256.as_bytes(),
            secret_commitment.as_bytes(),
        ],
    );
    Ok(CooperativeOperationDigests {
        provider_request_sha256,
        session_sha256,
    })
}

fn cooperative_signing_material(
    swap: &ChainSwapRecord,
) -> Result<(CreateChainResponse, BtcSwapScript, Keypair), AppError> {
    swap.verify_creation_response_integrity()
        .map_err(AppError::ClaimError)?;
    let response: CreateChainResponse =
        serde_json::from_str(&swap.boltz_response_json).map_err(|_| {
            AppError::ClaimError("cooperative signing creation response is invalid".into())
        })?;
    let refund_key_bytes =
        Zeroizing::new(hex::decode(&swap.refund_key_hex).map_err(|_| {
            AppError::ClaimError("cooperative signing refund key is invalid".into())
        })?);
    let refund_secret_key = bitcoin::secp256k1::SecretKey::from_slice(refund_key_bytes.as_slice())
        .map_err(|_| AppError::ClaimError("cooperative signing refund key is invalid".into()))?;
    let refund_keypair = Keypair::from_secret_key(&Secp256k1::new(), &refund_secret_key);
    let refund_public_key = PublicKey::new(refund_keypair.public_key());
    let script = exact_chain_lockup_script(&response.lockup_details, refund_public_key)?;
    Ok((response, script, refund_keypair))
}

async fn prepare_live_cooperative_operation(
    state: &AppState,
    swap: &ChainSwapRecord,
    authority: &CollectedAutomaticFallbackEvidence,
) -> Result<LiveCooperativePreparation, AppError> {
    if authority.automatic_construction_path()
        != Some(AutomaticFallbackConstructionPath::Cooperative)
        || authority.exact_sources().len() != 1
    {
        return Err(AppError::RecoveryNotAvailable(
            "cooperative recovery lacks one exact current source".into(),
        ));
    }
    let destination = authority.committed_destination().ok_or_else(|| {
        AppError::ClaimError("cooperative recovery lacks its committed destination".into())
    })?;
    let source = &authority.exact_sources()[0];
    let source_outpoint = OutPoint {
        txid: source
            .txid()
            .parse()
            .map_err(|_| AppError::ClaimError("cooperative source txid is invalid".into()))?,
        vout: source.vout(),
    };
    let authoritative_script = hex::decode(source.script_pubkey_hex()).map_err(|_| {
        AppError::ClaimError("cooperative authoritative source script is invalid".into())
    })?;
    let authoritative_txout = TxOut {
        value: Amount::from_sat(source.amount_sat()),
        script_pubkey: ScriptBuf::from_bytes(authoritative_script),
    };
    let (response, script, refund_keypair) = cooperative_signing_material(swap)?;
    let evidence_backend = state.bitcoin_recovery_backend.as_deref().ok_or_else(|| {
        AppError::ElectrumError("Bitcoin recovery evidence client is unavailable".into())
    })?;
    let source_txout = exact_cooperative_source_across_backends(
        &script,
        source_outpoint,
        &authoritative_txout,
        evidence_backend.endpoints(),
    )
    .await?;
    let (decision, fee_record) = state
        .fee_runtime
        .bitcoin_construction_decision_now(FeeConstructionPurpose::BitcoinRecovery)
        .map_err(|_| AppError::RecoveryNotAvailable(BITCOIN_FEE_DECISION_PENDING_REASON.into()))?;
    let prepared = prepare_exact_cooperative_refund(
        &script,
        &response.lockup_details,
        &refund_keypair,
        source_outpoint,
        source_txout.clone(),
        destination,
        BitcoinBuilderFeeDecision::from(&decision),
    )?;
    if !fee_record.authorizes_construction_now() {
        return Err(AppError::RecoveryNotAvailable(
            BITCOIN_FEE_DECISION_PENDING_REASON.into(),
        ));
    }
    Ok(LiveCooperativePreparation {
        prepared,
        source_outpoint,
        source_txout,
        destination_address: destination.to_owned(),
        fee_record,
    })
}

fn build_cooperative_signing_identity(
    swap: &ChainSwapRecord,
    preparation: &LiveCooperativePreparation,
    runtime: &crate::swap_manifest_runtime::RecoveryManifestRuntimeV1,
) -> Result<db::ChainSwapCooperativeSigningIdentity, AppError> {
    let digests = cooperative_operation_digests(swap, preparation)?;
    let durable_request = preparation.prepared.durable_request();
    if durable_request.input_index != 0 {
        return Err(AppError::ClaimError(
            "cooperative signing request input index is not canonical".into(),
        ));
    }
    let raw_request = hex::decode(&durable_request.unsigned_tx_hex).map_err(|_| {
        AppError::ClaimError("cooperative signing request transaction hex is invalid".into())
    })?;
    let request_transaction: Transaction = deserialize(&raw_request).map_err(|_| {
        AppError::ClaimError("cooperative signing request transaction is invalid".into())
    })?;
    if request_transaction.input.len() != 1 || request_transaction.output.len() != 1 {
        return Err(AppError::ClaimError(
            "cooperative signing request transaction shape changed".into(),
        ));
    }
    let destination = &request_transaction.output[0];
    let fee_amount_sat = preparation
        .source_txout
        .value
        .to_sat()
        .checked_sub(destination.value.to_sat())
        .filter(|fee| *fee > 0)
        .ok_or_else(|| AppError::ClaimError("cooperative signing request fee is invalid".into()))?;
    let fee_vbytes = u64::try_from(request_transaction.vsize()).map_err(|_| {
        AppError::ClaimError("cooperative signing request virtual size is invalid".into())
    })?;
    let sealed = runtime
        .seal_cooperative_signing_nonce_v1(
            swap.id,
            &digests.session_sha256,
            preparation.prepared.secret_nonce().expose(),
        )
        .map_err(|error| AppError::RecoveryNotAvailable(error.to_string()))?;
    let encrypted_nonce = db::EncryptedCooperativeSecretNonce::new(
        sealed.key_id,
        sealed.encryption_nonce,
        sealed.ciphertext,
        sealed.plaintext_sha256,
    )
    .map_err(|error| AppError::ClaimError(error.to_string()))?;
    let request = db::CooperativeSigningRequest::new(
        durable_request.unsigned_tx_hex.clone(),
        durable_request.txid.clone(),
        durable_request.sighash_hex.clone(),
        durable_request.tweaked_aggregate_key_hex.clone(),
        durable_request.public_nonce_hex.clone(),
        digests.provider_request_sha256,
        digests.session_sha256,
        encrypted_nonce,
    )
    .map_err(|error| AppError::ClaimError(error.to_string()))?;
    let source = db::CooperativeSigningSource::new(
        preparation.source_outpoint.txid.to_string(),
        preparation.source_outpoint.vout,
        preparation.source_txout.value.to_sat(),
        hex::encode(preparation.source_txout.script_pubkey.as_bytes()),
    )
    .map_err(|error| AppError::ClaimError(error.to_string()))?;
    let destination = db::CooperativeSigningDestination::new(
        preparation.destination_address.clone(),
        hex::encode(destination.script_pubkey.as_bytes()),
        destination.value.to_sat(),
    )
    .map_err(|error| AppError::ClaimError(error.to_string()))?;
    let fee_authority = db::CooperativeSigningFeeAuthority::from_decision(&preparation.fee_record)
        .map_err(|error| AppError::ClaimError(error.to_string()))?;
    db::ChainSwapCooperativeSigningIdentity::new(
        swap.id,
        swap.boltz_swap_id.clone(),
        source,
        destination,
        fee_amount_sat,
        fee_vbytes,
        fee_authority,
        request,
    )
    .map_err(|error| AppError::ClaimError(error.to_string()))
}

/// Prepare one cryptographically valid selected-response fixture through the
/// same constructor, nonce sealing, digest, and MuSig code used in production.
/// The caller still persists each lifecycle transition through the real DB
/// adapter before exercising completion.
#[doc(hidden)]
// Keep every independent authority field visible at this test-only boundary;
// bundling them would make accidental fixture drift harder to review.
#[allow(clippy::too_many_arguments)]
pub fn prepare_cooperative_signing_completion_fixture_for_test(
    swap: &ChainSwapRecord,
    source_txid: &str,
    source_vout: u32,
    source_amount_sat: u64,
    destination_address: &str,
    fee_decision: &BitcoinFeeDecision,
    fee_record: FeeDecisionRecord,
    runtime: &crate::swap_manifest_runtime::RecoveryManifestRuntimeV1,
    provider_secret_key: [u8; 32],
) -> Result<(db::ChainSwapCooperativeSigningIdentity, PartialSig), AppError> {
    if fee_record.rate() != fee_decision.rate() {
        return Err(AppError::ClaimError(
            "cooperative fixture fee authority differs from construction".into(),
        ));
    }
    let source_outpoint = OutPoint {
        txid: source_txid
            .parse()
            .map_err(|_| AppError::ClaimError("cooperative fixture source txid invalid".into()))?,
        vout: source_vout,
    };
    let (response, script, refund_keypair) = cooperative_signing_material(swap)?;
    let source_txout = TxOut {
        value: Amount::from_sat(source_amount_sat),
        script_pubkey: script
            .to_address(BitcoinChain::Bitcoin)
            .map_err(|_| AppError::ClaimError("cooperative fixture lockup invalid".into()))?
            .script_pubkey(),
    };
    let prepared = prepare_exact_cooperative_refund(
        &script,
        &response.lockup_details,
        &refund_keypair,
        source_outpoint,
        source_txout.clone(),
        destination_address,
        BitcoinBuilderFeeDecision::from(fee_decision),
    )?;
    let provider_secret = bitcoin::secp256k1::SecretKey::from_slice(&provider_secret_key)
        .map_err(|_| AppError::ClaimError("cooperative fixture provider key invalid".into()))?;
    let provider_keypair = Keypair::from_secret_key(&Secp256k1::new(), &provider_secret);
    let provider_public_key = PublicKey::new(provider_keypair.public_key());
    if provider_public_key != response.lockup_details.server_public_key {
        return Err(AppError::ClaimError(
            "cooperative fixture provider key differs from creation response".into(),
        ));
    }
    let provider_response = provider_partial_signature_for_integration_test(
        &script,
        &response.lockup_details,
        &provider_keypair,
        prepared.durable_request(),
    )?;
    let preparation = LiveCooperativePreparation {
        prepared,
        source_outpoint,
        source_txout,
        destination_address: destination_address.to_owned(),
        fee_record,
    };
    let identity = build_cooperative_signing_identity(swap, &preparation, runtime)?;
    Ok((identity, provider_response))
}

fn validate_cooperative_operation_authority(
    operation: &db::ChainSwapCooperativeSigningOperation,
    authority: &CollectedAutomaticFallbackEvidence,
    swap: &ChainSwapRecord,
    require_pre_timeout_selection: bool,
) -> Result<(), AppError> {
    if !authority.dependencies_available() || authority.exact_sources().len() != 1 {
        return Err(AppError::RecoveryNotAvailable(
            "cooperative signing exact authority is unavailable".into(),
        ));
    }
    if require_pre_timeout_selection
        && authority.automatic_construction_path()
            != Some(AutomaticFallbackConstructionPath::Cooperative)
    {
        return Err(AppError::RecoveryNotAvailable(
            "cooperative signing is no longer the selected pre-timeout path".into(),
        ));
    }
    let identity = operation.identity();
    if identity.chain_swap_id() != swap.id || identity.boltz_swap_id() != swap.boltz_swap_id {
        return Err(AppError::ClaimError(
            "cooperative signing parent identity changed".into(),
        ));
    }
    let committed_destination = authority.committed_destination().ok_or_else(|| {
        AppError::ClaimError("cooperative signing destination authority is missing".into())
    })?;
    if identity.destination().address() != committed_destination
        || swap.refund_address.as_deref() != Some(committed_destination)
    {
        return Err(AppError::ClaimError(
            "cooperative signing destination differs from current authority".into(),
        ));
    }
    let address = Address::from_str(committed_destination)
        .map_err(|_| AppError::ClaimError("cooperative signing destination is invalid".into()))?
        .require_network(Network::Bitcoin)
        .map_err(|_| {
            AppError::ClaimError("cooperative signing destination is not mainnet".into())
        })?;
    if hex::encode(address.script_pubkey().as_bytes()) != identity.destination().script_pubkey_hex()
    {
        return Err(AppError::ClaimError(
            "cooperative signing destination script changed".into(),
        ));
    }
    let source = identity.source();
    let journaled_source = RecoverySourcePrevout {
        txid: source.txid().to_owned(),
        vout: source.vout(),
        amount_sat: source.amount_sat(),
        script_pubkey_hex: source.script_pubkey_hex().to_owned(),
    };
    let primary_source = &authority.exact_sources()[0];
    validate_exact_primary_source_tuple(
        primary_source.txid(),
        primary_source.vout(),
        primary_source.amount_sat(),
        primary_source.script_pubkey_hex(),
        &journaled_source,
    )?;
    if automatic_action_for_path_evidence(
        authority.evidence,
        AutomaticFallbackConstructionPath::Cooperative,
    ) != ChainSwapAction::RecoverBitcoin
    {
        return Err(AppError::RecoveryNotAvailable(
            "current authority no longer permits the selected cooperative transaction".into(),
        ));
    }
    Ok(())
}

fn prepared_attempt_from_completed_cooperative_signing(
    identity: &db::ChainSwapCooperativeSigningIdentity,
    transaction: &Transaction,
) -> Result<PreparedAttempt, AppError> {
    if transaction.input.len() != 1
        || transaction.output.len() != 1
        || transaction.input[0].previous_output.txid.to_string() != identity.source().txid()
        || transaction.input[0].previous_output.vout != identity.source().vout()
        || transaction.compute_txid().to_string() != identity.request().transaction_txid()
        || transaction.output[0].value.to_sat() != identity.destination().amount_sat()
        || hex::encode(transaction.output[0].script_pubkey.as_bytes())
            != identity.destination().script_pubkey_hex()
    {
        return Err(AppError::ClaimError(
            "completed cooperative transaction differs from its durable identity".into(),
        ));
    }
    let fee_amount_sat = identity
        .source()
        .amount_sat()
        .checked_sub(transaction.output[0].value.to_sat())
        .filter(|fee| *fee == identity.fee_amount_sat())
        .ok_or_else(|| {
            AppError::ClaimError("completed cooperative transaction fee changed".into())
        })?;
    let vbytes = u64::try_from(transaction.vsize()).map_err(|_| {
        AppError::ClaimError("completed cooperative transaction virtual size is invalid".into())
    })?;
    if vbytes != identity.fee_vbytes() {
        return Err(AppError::ClaimError(
            "completed cooperative transaction virtual size changed".into(),
        ));
    }
    Ok(PreparedAttempt {
        raw_tx_hex: hex::encode(serialize(transaction)),
        txid: transaction.compute_txid().to_string(),
        source_prevouts: vec![RecoverySourcePrevout {
            txid: identity.source().txid().to_owned(),
            vout: identity.source().vout(),
            amount_sat: identity.source().amount_sat(),
            script_pubkey_hex: identity.source().script_pubkey_hex().to_owned(),
        }],
        destination_address: identity.destination().address().to_owned(),
        destination_script_hex: identity.destination().script_pubkey_hex().to_owned(),
        destination_amount_sat: i64::try_from(identity.destination().amount_sat()).map_err(
            |_| {
                AppError::ClaimError("cooperative destination amount exceeds database range".into())
            },
        )?,
        fee_amount_sat: i64::try_from(fee_amount_sat).map_err(|_| {
            AppError::ClaimError("cooperative fee amount exceeds database range".into())
        })?,
        fee_rate_sat_vb: fee_amount_sat as f64 / vbytes as f64,
    })
}

/// Finish only the provider response already selected by the durable journal.
/// Opening the protected nonce before this boundary would make an uncommitted
/// or losing response capable of consuming signing material.
fn complete_selected_cooperative_signing(
    swap: &ChainSwapRecord,
    operation: &db::ChainSwapCooperativeSigningOperation,
    runtime: &crate::swap_manifest_runtime::RecoveryManifestRuntimeV1,
) -> Result<
    (
        PreparedAttempt,
        db::CooperativeSigningCompletion,
        FeeDecisionRecord,
    ),
    AppError,
> {
    if operation.state() != db::CooperativeSigningState::ResponseReceived {
        return Err(AppError::ClaimError(
            "cooperative signing response is not durably selected".into(),
        ));
    }
    let identity = operation.identity();
    if identity.chain_swap_id() != swap.id || identity.boltz_swap_id() != swap.boltz_swap_id {
        return Err(AppError::ClaimError(
            "cooperative signing response belongs to a different swap".into(),
        ));
    }
    let request = identity.request();
    let encrypted_nonce = request.secret_nonce();
    let envelope = CooperativeSigningNonceEnvelopeV1::from_persisted(
        encrypted_nonce.key_id().to_owned(),
        encrypted_nonce.encryption_nonce_for_decryption().to_vec(),
        encrypted_nonce.ciphertext_for_decryption().to_vec(),
        encrypted_nonce.plaintext_sha256().to_owned(),
    )
    .map_err(|_| AppError::ClaimError("cooperative signing nonce envelope is invalid".into()))?;
    let secret_nonce = runtime
        .open_cooperative_signing_nonce_v1(swap.id, request.session_sha256(), &envelope)
        .map_err(|_| {
            AppError::ClaimError("cooperative signing nonce could not be opened".into())
        })?;
    let (response, script, refund_keypair) = cooperative_signing_material(swap)?;

    let source_script = hex::decode(identity.source().script_pubkey_hex())
        .map_err(|_| AppError::ClaimError("cooperative signing source script is invalid".into()))?;
    if hex::encode(&source_script) != identity.source().script_pubkey_hex() {
        return Err(AppError::ClaimError(
            "cooperative signing source script is not canonical".into(),
        ));
    }
    let source_txout = TxOut {
        value: Amount::from_sat(identity.source().amount_sat()),
        script_pubkey: ScriptBuf::from_bytes(source_script),
    };
    let durable_request = DurableCooperativeRequest {
        unsigned_tx_hex: request.transaction_hex().to_owned(),
        txid: request.transaction_txid().to_owned(),
        public_nonce_hex: request.client_public_nonce_hex().to_owned(),
        sighash_hex: request.sighash_hex().to_owned(),
        tweaked_aggregate_key_hex: request.aggregate_key_xonly_hex().to_owned(),
        input_index: 0,
    };
    let selected_response = operation.provider_response().ok_or_else(|| {
        AppError::ClaimError("cooperative signing selected response is missing".into())
    })?;
    let provider_response = PartialSig {
        pub_nonce: selected_response.public_nonce_hex().to_owned(),
        partial_signature: selected_response.partial_signature_hex().to_owned(),
    };
    let completed = complete_exact_cooperative_refund(
        &script,
        &response.lockup_details,
        &refund_keypair,
        &source_txout,
        &durable_request,
        secret_nonce.expose(),
        &provider_response,
    )?;
    let prepared =
        prepared_attempt_from_completed_cooperative_signing(identity, &completed.transaction)?;
    let completion = db::CooperativeSigningCompletion::new(
        prepared.raw_tx_hex.clone(),
        completed.local_partial_signature_sha256,
    )
    .map_err(|_| AppError::ClaimError("cooperative signing completion is invalid".into()))?;
    let fee_record = identity
        .fee_authority()
        .to_fee_decision_record_for_committed_bytes()
        .map_err(|_| AppError::ClaimError("cooperative signing fee authority is invalid".into()))?;
    Ok((prepared, completion, fee_record))
}

fn cooperative_store_error(error: db::ChainSwapCooperativeSigningStoreError) -> AppError {
    match error {
        db::ChainSwapCooperativeSigningStoreError::Database(_) => {
            AppError::DbError("cooperative signing database request failed".into())
        }
        error => AppError::ClaimError(error.to_string()),
    }
}

async fn persist_cooperative_integrity_hold_in_transaction(
    conn: &mut sqlx::PgConnection,
    chain_swap_id: Uuid,
    expected_version: u64,
    reason_domain: &[u8],
) -> Result<(), AppError> {
    let reason_sha256 = framed_sha256(reason_domain, &[chain_swap_id.as_bytes()]);
    let outcome = db::mark_chain_swap_cooperative_signing_integrity_hold_in_transaction(
        conn,
        chain_swap_id,
        expected_version,
        &reason_sha256,
    )
    .await
    .map_err(cooperative_store_error)?;
    if outcome.operation.state() != db::CooperativeSigningState::IntegrityHold {
        return Err(AppError::ClaimError(
            "cooperative signing integrity hold did not become durable".into(),
        ));
    }
    Ok(())
}

fn validate_durable_cooperative_provider_request(
    identity: &db::ChainSwapCooperativeSigningIdentity,
) -> Result<(), AppError> {
    let request = identity.request();
    let input_index = 0_u32.to_string();
    let digest = framed_sha256(
        b"bullnym/boltz-chain-refund-signature-request/v1",
        &[
            identity.boltz_swap_id().as_bytes(),
            request.client_public_nonce_hex().as_bytes(),
            request.transaction_hex().as_bytes(),
            input_index.as_bytes(),
        ],
    );
    if digest != request.provider_request_sha256() {
        return Err(AppError::ClaimError(
            "cooperative provider request digest changed".into(),
        ));
    }
    Ok(())
}

/// Execute the one permitted provider mutation and immediately persist its
/// response. This function is reachable only from an `Applied` requested CAS.
async fn request_and_record_cooperative_response(
    pool: &sqlx::PgPool,
    operation: &db::ChainSwapCooperativeSigningOperation,
    provider: &dyn CooperativeSigningProvider,
    faults: &dyn RecoveryFaultInjector,
) -> Result<(), AppError> {
    if operation.state() != db::CooperativeSigningState::Requested
        || operation.request_attempt_count() != 1
    {
        return Err(AppError::ClaimError(
            "cooperative provider call lacks one committed request intent".into(),
        ));
    }
    let identity = operation.identity();
    validate_durable_cooperative_provider_request(identity)?;
    let request = identity.request();
    let response = match provider
        .request_partial_signature(
            identity.boltz_swap_id(),
            0,
            request.client_public_nonce_hex(),
            request.transaction_hex(),
        )
        .await
    {
        Ok(response) => response,
        Err(_) => {
            let outcome = db::mark_chain_swap_cooperative_signing_ambiguous(
                pool,
                identity.chain_swap_id(),
                operation.version(),
                db::CooperativeSigningErrorClass::UnknownProviderOutcome,
            )
            .await
            .map_err(cooperative_store_error)?;
            if outcome.operation.state() != db::CooperativeSigningState::Ambiguous {
                return Err(AppError::ClaimError(
                    "cooperative provider uncertainty was not preserved".into(),
                ));
            }
            // Return progress so the caller reacquires the chain lock once.
            // A parent/Liquid transition that won while the POST was in
            // flight must terminally hold this ambiguous evidence now.
            return Ok(());
        }
    };

    // A crash here deliberately leaves `requested`. Restart reconciliation
    // never POSTs that intent again because the remote outcome is unknowable.
    faults.check(RecoveryFaultPoint::AfterCooperativeProviderBeforeResponseCommit)?;
    let durable_response = match db::CooperativeSigningProviderResponse::new(
        response.pub_nonce.to_ascii_lowercase(),
        response.partial_signature.to_ascii_lowercase(),
    ) {
        Ok(response) => response,
        Err(_) => {
            let outcome = db::mark_chain_swap_cooperative_signing_ambiguous(
                pool,
                identity.chain_swap_id(),
                operation.version(),
                db::CooperativeSigningErrorClass::MalformedResponse,
            )
            .await
            .map_err(cooperative_store_error)?;
            if outcome.operation.state() != db::CooperativeSigningState::Ambiguous {
                return Err(AppError::ClaimError(
                    "malformed cooperative response was not preserved".into(),
                ));
            }
            // Re-lock once after the response is durably quarantined; this
            // closes the parent-transition window around the remote call.
            return Ok(());
        }
    };
    let outcome = db::record_chain_swap_cooperative_signing_response(
        pool,
        identity.chain_swap_id(),
        operation.version(),
        &durable_response,
    )
    .await
    .map_err(cooperative_store_error)?;
    match outcome.operation.state() {
        db::CooperativeSigningState::ResponseReceived => {}
        db::CooperativeSigningState::IntegrityHold => {
            return Err(AppError::ClaimError(
                "cooperative provider returned conflicting signing evidence".into(),
            ));
        }
        _ => {
            return Err(AppError::ClaimError(
                "cooperative provider response did not become durable".into(),
            ));
        }
    }
    faults.check(RecoveryFaultPoint::AfterCooperativeResponseCommit)?;
    Ok(())
}

struct CooperativeProviderHarness<'a> {
    calls: &'a std::sync::atomic::AtomicUsize,
    response: Option<PartialSig>,
}

#[async_trait]
impl CooperativeSigningProvider for CooperativeProviderHarness<'_> {
    async fn request_partial_signature(
        &self,
        _boltz_swap_id: &str,
        _input_index: u32,
        _client_public_nonce_hex: &str,
        _transaction_hex: &str,
    ) -> Result<PartialSig, AppError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.response.clone().ok_or_else(|| {
            AppError::RecoveryNotAvailable(
                "cooperative provider harness returned an unknown outcome".into(),
            )
        })
    }
}

/// DB-backed crash seam for the one irreversible provider boundary.
///
/// This deliberately omits construction and chain authority; those belong to
/// the live state machine. It exercises the production atomic
/// `prepared -> requested` CAS and the exact production response persistence
/// helper so integration tests can prove that only `Applied` calls the
/// provider and every restart `ExactRetry` performs zero POSTs.
#[doc(hidden)]
pub async fn exercise_cooperative_provider_transition_for_test(
    pool: &sqlx::PgPool,
    identity: &db::ChainSwapCooperativeSigningIdentity,
    response: Option<PartialSig>,
    calls: &std::sync::atomic::AtomicUsize,
    faults: &dyn RecoveryFaultInjector,
) -> Result<db::CooperativeSigningState, AppError> {
    if let Some(existing) = db::get_chain_swap_cooperative_signing(pool, identity.chain_swap_id())
        .await
        .map_err(cooperative_store_error)?
    {
        if existing.identity() != identity {
            return Err(AppError::ClaimError(
                "cooperative provider harness identity changed".into(),
            ));
        }
        if !matches!(
            existing.state(),
            db::CooperativeSigningState::Prepared | db::CooperativeSigningState::Requested
        ) {
            // The provider boundary has already been resolved or terminally
            // quarantined. A worker restart observes it without reopening the
            // one-shot request path.
            return Ok(existing.state());
        }
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| AppError::DbError("cooperative provider harness transaction failed".into()))?;
    let outcome = db::prepare_and_mark_chain_swap_cooperative_signing_requested_in_transaction(
        &mut tx, identity,
    )
    .await
    .map_err(cooperative_store_error)?;
    tx.commit().await.map_err(|_| {
        AppError::DbError("cooperative provider harness request commit failed".into())
    })?;
    if outcome.disposition == db::CooperativeSigningCasDisposition::Applied {
        faults.check(RecoveryFaultPoint::AfterCooperativeRequestedCommitBeforeProvider)?;
        let provider = CooperativeProviderHarness { calls, response };
        request_and_record_cooperative_response(pool, &outcome.operation, &provider, faults)
            .await?;
    }
    let operation = db::get_chain_swap_cooperative_signing(pool, identity.chain_swap_id())
        .await
        .map_err(cooperative_store_error)?
        .ok_or_else(|| {
            AppError::ClaimError("cooperative provider harness operation disappeared".into())
        })?;
    Ok(operation.state())
}

/// Drive the exact live cooperative state machine with a counted provider.
/// This is used for database-backed preflight and crash-boundary regressions;
/// production continues to inject its real Boltz provider.
#[doc(hidden)]
pub async fn exercise_cooperative_signing_advance_for_test(
    state: &AppState,
    chain_swap_id: Uuid,
    response: Option<PartialSig>,
    calls: &std::sync::atomic::AtomicUsize,
    faults: &dyn RecoveryFaultInjector,
) -> Result<(), AppError> {
    let provider = CooperativeProviderHarness { calls, response };
    advance_cooperative_signing_operation(state, chain_swap_id, &provider, faults).await
}

async fn cooperative_requested_intent_is_stale(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    chain_swap_id: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT COALESCE(\
             requested_at <= clock_timestamp() - INTERVAL '30 seconds', FALSE\
           ) \
           FROM chain_swap_cooperative_signing_operations \
          WHERE chain_swap_id = $1",
    )
    .bind(chain_swap_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| AppError::DbError("cooperative signing request age read failed".into()))
}

#[derive(Clone, Copy)]
struct CooperativeParentConflict {
    reason_domain: &'static [u8],
    commit_error: &'static str,
    claim_error: &'static str,
}

fn cooperative_nonterminal_parent_conflict(
    swap: &ChainSwapRecord,
    status: ChainSwapStatus,
    operation: Option<&db::ChainSwapCooperativeSigningOperation>,
) -> Option<CooperativeParentConflict> {
    if operation.is_none_or(|operation| operation.state().is_terminal()) {
        return None;
    }
    if status != ChainSwapStatus::RefundDue {
        return Some(CooperativeParentConflict {
            reason_domain: b"bullnym/cooperative-signing/parent-status-integrity/v1",
            commit_error: "cooperative signing parent-conflict commit failed",
            claim_error: "cooperative signing intent conflicts with the parent lifecycle",
        });
    }
    if swap.claim_txid.is_some() || swap.claim_tx_hex.is_some() {
        return Some(CooperativeParentConflict {
            reason_domain: b"bullnym/cooperative-signing/liquid-claim-integrity/v1",
            commit_error: "cooperative signing Liquid-conflict commit failed",
            claim_error: "cooperative signing intent conflicts with a persisted Liquid claim",
        });
    }
    None
}

async fn persist_cooperative_parent_conflict(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    chain_swap_id: Uuid,
    operation: &db::ChainSwapCooperativeSigningOperation,
    conflict: CooperativeParentConflict,
) -> Result<(), AppError> {
    persist_cooperative_integrity_hold_in_transaction(
        tx,
        chain_swap_id,
        operation.version(),
        conflict.reason_domain,
    )
    .await
}

enum CooperativeCompletionAuthority<'a> {
    Live(&'a CollectedAutomaticFallbackEvidence),
    IntegrationFixture,
}

// This is the single atomic production boundary. Its explicit arguments make
// the attempt, selected response, fee authority, live evidence, and fault seam
// independently auditable rather than hidden in a permissive context bag.
#[allow(clippy::too_many_arguments)]
async fn persist_selected_cooperative_completion_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    swap: &ChainSwapRecord,
    operation: &db::ChainSwapCooperativeSigningOperation,
    prepared: &PreparedAttempt,
    completion: &db::CooperativeSigningCompletion,
    fee_record: &FeeDecisionRecord,
    authority: CooperativeCompletionAuthority<'_>,
    faults: &dyn RecoveryFaultInjector,
) -> Result<ChainSwapTxAttempt, AppError> {
    let attempt = db::insert_bitcoin_recovery_attempt(tx, &prepared.as_new(swap.id, fee_record))
        .await
        .map_err(|_| AppError::DbError("cooperative recovery attempt insert failed".into()))?;
    validate_reloaded_attempt(&attempt)?;
    match authority {
        CooperativeCompletionAuthority::Live(authority) => {
            validate_automatic_attempt_authority(
                &attempt,
                authority,
                swap,
                Some(AutomaticFallbackConstructionPath::Cooperative),
            )?;
        }
        CooperativeCompletionAuthority::IntegrationFixture => {}
    }
    let rows = db::mark_chain_swap_refunding(&mut **tx, swap.id)
        .await
        .map_err(|_| AppError::DbError("cooperative recovery parent transition failed".into()))?;
    if rows != 1 {
        return Err(AppError::ClaimError(
            "cooperative recovery race lost before commit".into(),
        ));
    }
    let completed = db::complete_chain_swap_cooperative_signing_in_transaction(
        tx,
        swap.id,
        operation.version(),
        completion,
    )
    .await
    .map_err(cooperative_store_error)?;
    if completed.operation.state() != db::CooperativeSigningState::Completed {
        return Err(AppError::ClaimError(
            "cooperative signing completion did not become durable".into(),
        ));
    }
    faults.check(RecoveryFaultPoint::AfterCooperativeAttemptWriteBeforeCommit)?;
    Ok(attempt)
}

/// Exercise valid selected-response completion through the production signer
/// and the exact atomic attempt/parent/journal commit helper. External chain
/// authority is deliberately omitted because the fixture's immutable identity
/// already supplies the transaction tuple; the live caller validates fresh
/// authority immediately before entering this same helper.
#[doc(hidden)]
pub async fn preview_cooperative_signing_completion_for_test(
    state: &AppState,
    chain_swap_id: Uuid,
) -> Result<String, AppError> {
    let swap = db::get_chain_swap_by_id(&state.db, chain_swap_id)
        .await
        .map_err(|_| AppError::DbError("cooperative completion preview parent read failed".into()))?
        .ok_or_else(|| {
            AppError::ClaimError("cooperative completion preview parent missing".into())
        })?;
    let operation = db::get_chain_swap_cooperative_signing(&state.db, chain_swap_id)
        .await
        .map_err(cooperative_store_error)?
        .ok_or_else(|| {
            AppError::ClaimError("cooperative completion preview intent missing".into())
        })?;
    let runtime = state.recovery_manifest_runtime_v1().ok_or_else(|| {
        AppError::RecoveryNotAvailable("cooperative completion preview runtime missing".into())
    })?;
    let (prepared, _, _) = complete_selected_cooperative_signing(&swap, &operation, runtime)?;
    Ok(prepared.raw_tx_hex)
}

#[doc(hidden)]
pub async fn exercise_cooperative_signing_completion_for_test(
    state: &AppState,
    chain_swap_id: Uuid,
    faults: &dyn RecoveryFaultInjector,
) -> Result<String, AppError> {
    let mut tx = state.db.begin().await.map_err(|_| {
        AppError::DbError("cooperative completion harness transaction failed".into())
    })?;
    let lock_key = format!("chain-claim:{chain_swap_id}");
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| AppError::DbError("cooperative completion harness lock failed".into()))?;
    if !got_lock {
        return Err(AppError::RecoveryNotAvailable(
            "cooperative completion harness lock is busy".into(),
        ));
    }
    let swap = db::get_chain_swap_by_id_for_update(&mut *tx, chain_swap_id)
        .await
        .map_err(|_| AppError::DbError("cooperative completion harness parent read failed".into()))?
        .ok_or_else(|| {
            AppError::ClaimError("cooperative completion harness parent missing".into())
        })?;
    let operation = db::get_chain_swap_cooperative_signing_for_update(&mut tx, chain_swap_id)
        .await
        .map_err(cooperative_store_error)?
        .ok_or_else(|| {
            AppError::ClaimError("cooperative completion harness intent missing".into())
        })?;
    if let Some(attempt) = db::get_bitcoin_recovery_attempt_for_update(&mut tx, chain_swap_id)
        .await
        .map_err(|_| {
            AppError::DbError("cooperative completion harness attempt read failed".into())
        })?
    {
        validate_reloaded_attempt(&attempt)?;
        let exact_completed_replay = swap.parsed_status().map_err(AppError::DbError)?
            == ChainSwapStatus::Refunding
            && operation.state() == db::CooperativeSigningState::Completed
            && operation
                .completion()
                .is_some_and(|completion| completion.final_transaction_hex() == attempt.raw_tx_hex);
        if !exact_completed_replay {
            if !operation.state().is_terminal() {
                persist_cooperative_integrity_hold_in_transaction(
                    &mut tx,
                    chain_swap_id,
                    operation.version(),
                    b"bullnym/cooperative-signing/completion-replay-integrity/v1",
                )
                .await?;
                tx.commit().await.map_err(|_| {
                    AppError::DbError(
                        "cooperative completion harness replay hold commit failed".into(),
                    )
                })?;
            }
            return Err(AppError::ClaimError(
                "cooperative completion harness replay state is inconsistent".into(),
            ));
        }
        tx.commit().await.map_err(|_| {
            AppError::DbError("cooperative completion harness replay commit failed".into())
        })?;
        return Ok(attempt.raw_tx_hex);
    }
    if swap.parsed_status().map_err(AppError::DbError)? != ChainSwapStatus::RefundDue {
        return Err(AppError::ClaimError(
            "cooperative completion harness parent is not refund due".into(),
        ));
    }
    let runtime = state.recovery_manifest_runtime_v1().ok_or_else(|| {
        AppError::RecoveryNotAvailable("cooperative completion harness runtime missing".into())
    })?;
    let (prepared, completion, fee_record) =
        complete_selected_cooperative_signing(&swap, &operation, runtime)?;
    let raw_tx_hex = prepared.raw_tx_hex.clone();
    persist_selected_cooperative_completion_in_transaction(
        &mut tx,
        &swap,
        &operation,
        &prepared,
        &completion,
        &fee_record,
        CooperativeCompletionAuthority::IntegrationFixture,
        faults,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| AppError::DbError("cooperative completion harness commit failed".into()))?;
    Ok(raw_tx_hex)
}

/// Advance the provider-assisted branch until either an immutable Bitcoin
/// attempt exists or current evidence selects the unilateral executor. Every
/// loop iteration reacquires the shared lock and fresh #82 authority.
async fn advance_cooperative_signing_operation(
    state: &AppState,
    chain_swap_id: Uuid,
    provider: &dyn CooperativeSigningProvider,
    faults: &dyn RecoveryFaultInjector,
) -> Result<(), AppError> {
    for _ in 0..8 {
        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|_| AppError::DbError("cooperative signing transaction failed".into()))?;
        let lock_key = format!("chain-claim:{chain_swap_id}");
        let got_lock: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
                .bind(&lock_key)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| {
                    AppError::DbError("cooperative signing execution lock failed".into())
                })?;
        if !got_lock {
            return Err(AppError::RecoveryNotAvailable(
                "cooperative signing execution lock is busy".into(),
            ));
        }
        let swap = db::get_chain_swap_by_id_for_update(&mut *tx, chain_swap_id)
            .await
            .map_err(|_| AppError::DbError("cooperative signing parent read failed".into()))?
            .ok_or_else(|| AppError::ClaimError("cooperative signing parent is missing".into()))?;
        let status = swap.parsed_status().map_err(AppError::DbError)?;
        if db::get_bitcoin_recovery_attempt_for_update(&mut tx, chain_swap_id)
            .await
            .map_err(|_| AppError::DbError("cooperative signing attempt read failed".into()))?
            .is_some()
        {
            tx.commit()
                .await
                .map_err(|_| AppError::DbError("cooperative signing commit failed".into()))?;
            return Ok(());
        }
        let operation = db::get_chain_swap_cooperative_signing_for_update(&mut tx, chain_swap_id)
            .await
            .map_err(cooperative_store_error)?;
        if let Some(conflict) =
            cooperative_nonterminal_parent_conflict(&swap, status, operation.as_ref())
        {
            let operation = operation.as_ref().ok_or_else(|| {
                AppError::ClaimError("cooperative signing conflict lost its intent".into())
            })?;
            persist_cooperative_parent_conflict(&mut tx, chain_swap_id, operation, conflict)
                .await?;
            tx.commit()
                .await
                .map_err(|_| AppError::DbError(conflict.commit_error.into()))?;
            return Err(AppError::ClaimError(conflict.claim_error.into()));
        }
        if status != ChainSwapStatus::RefundDue {
            if status == ChainSwapStatus::Refunding {
                // Preserve the core executor's legacy-ambiguity refusal when
                // no cooperative intent remains capable of local signing.
                tx.commit()
                    .await
                    .map_err(|_| AppError::DbError("cooperative signing commit failed".into()))?;
                return Ok(());
            }
            return Err(AppError::ClaimError(format!(
                "chain swap not recoverable (status {status})"
            )));
        }
        if swap.claim_txid.is_some() || swap.claim_tx_hex.is_some() {
            return Err(AppError::ClaimError(
                "recovery blocked: a Liquid claim is already in progress for this payment".into(),
            ));
        }

        let authority =
            collect_automatic_fallback_evidence_under_lock(state, &mut tx, &swap, None).await?;
        if !authority.dependencies_available() {
            return Err(AppError::ElectrumError(
                "cooperative signing evidence dependencies are unavailable".into(),
            ));
        }
        let path = authority.automatic_construction_path();

        let Some(operation) = operation else {
            match path {
                Some(AutomaticFallbackConstructionPath::Unilateral) => {
                    tx.commit().await.map_err(|_| {
                        AppError::DbError("cooperative signing commit failed".into())
                    })?;
                    return Ok(());
                }
                Some(AutomaticFallbackConstructionPath::Cooperative) => {
                    let runtime = state.recovery_manifest_runtime_v1().ok_or_else(|| {
                        AppError::RecoveryNotAvailable(
                            "protected cooperative signing runtime is unavailable".into(),
                        )
                    })?;
                    let preparation =
                        prepare_live_cooperative_operation(state, &swap, &authority).await?;
                    let identity =
                        build_cooperative_signing_identity(&swap, &preparation, runtime)?;
                    let outcome = db::prepare_and_mark_chain_swap_cooperative_signing_requested_in_transaction(
                        &mut tx,
                        &identity,
                    )
                    .await
                    .map_err(cooperative_store_error)?;
                    if outcome.operation.state() != db::CooperativeSigningState::Requested
                        || outcome.operation.identity() != &identity
                    {
                        return Err(AppError::ClaimError(
                            "cooperative signing request intent did not become immutable".into(),
                        ));
                    }
                    if !preparation.fee_record.authorizes_construction_now() {
                        return Err(AppError::RecoveryNotAvailable(
                            BITCOIN_FEE_DECISION_PENDING_REASON.into(),
                        ));
                    }
                    tx.commit().await.map_err(|_| {
                        AppError::DbError("cooperative signing request commit failed".into())
                    })?;
                    if outcome.disposition == db::CooperativeSigningCasDisposition::Applied {
                        faults.check(
                            RecoveryFaultPoint::AfterCooperativeRequestedCommitBeforeProvider,
                        )?;
                        request_and_record_cooperative_response(
                            &state.db,
                            &outcome.operation,
                            provider,
                            faults,
                        )
                        .await?;
                    }
                    // ExactRetry proves the request already committed and may
                    // never authorize a second provider POST.
                    continue;
                }
                None => {
                    return Err(AppError::RecoveryNotAvailable(
                        "automatic fallback evidence does not select a signing path".into(),
                    ));
                }
            }
        };

        match operation.state() {
            db::CooperativeSigningState::Prepared => match path {
                Some(AutomaticFallbackConstructionPath::Cooperative) => {
                    validate_cooperative_operation_authority(&operation, &authority, &swap, true)?;
                    return Err(AppError::RecoveryNotAvailable(
                        "legacy prepared cooperative intent cannot authorize a provider call"
                            .into(),
                    ));
                }
                Some(AutomaticFallbackConstructionPath::Unilateral) => {
                    validate_cooperative_operation_authority(&operation, &authority, &swap, false)?;
                    db::supersede_chain_swap_cooperative_signing_at_unilateral_timeout_in_transaction(
                        &mut tx,
                        chain_swap_id,
                        operation.version(),
                    )
                    .await
                    .map_err(cooperative_store_error)?;
                    tx.commit().await.map_err(|_| {
                        AppError::DbError("cooperative signing supersede commit failed".into())
                    })?;
                    return Ok(());
                }
                None => {
                    return Err(AppError::RecoveryNotAvailable(
                        "prepared cooperative signing intent lacks current authority".into(),
                    ));
                }
            },
            db::CooperativeSigningState::Requested => {
                if path == Some(AutomaticFallbackConstructionPath::Unilateral) {
                    validate_cooperative_operation_authority(&operation, &authority, &swap, false)?;
                    db::supersede_chain_swap_cooperative_signing_at_unilateral_timeout_in_transaction(
                        &mut tx,
                        chain_swap_id,
                        operation.version(),
                    )
                    .await
                    .map_err(cooperative_store_error)?;
                    tx.commit().await.map_err(|_| {
                        AppError::DbError("cooperative signing supersede commit failed".into())
                    })?;
                    return Ok(());
                }
                let stale = cooperative_requested_intent_is_stale(&mut tx, chain_swap_id).await?;
                let version = operation.version();
                tx.commit().await.map_err(|_| {
                    AppError::DbError("cooperative signing request check commit failed".into())
                })?;
                if stale {
                    let outcome = db::mark_chain_swap_cooperative_signing_ambiguous(
                        &state.db,
                        chain_swap_id,
                        version,
                        db::CooperativeSigningErrorClass::LocalCommitUncertainty,
                    )
                    .await
                    .map_err(cooperative_store_error)?;
                    if outcome.operation.state() != db::CooperativeSigningState::Ambiguous {
                        return Err(AppError::ClaimError(
                            "stale cooperative request was not quarantined".into(),
                        ));
                    }
                }
                return Err(AppError::RecoveryNotAvailable(
                    "cooperative signing request has an unknown remote outcome; no retry permitted"
                        .into(),
                ));
            }
            db::CooperativeSigningState::Ambiguous => {
                if path == Some(AutomaticFallbackConstructionPath::Unilateral) {
                    validate_cooperative_operation_authority(&operation, &authority, &swap, false)?;
                    db::supersede_chain_swap_cooperative_signing_at_unilateral_timeout_in_transaction(
                        &mut tx,
                        chain_swap_id,
                        operation.version(),
                    )
                    .await
                    .map_err(cooperative_store_error)?;
                    tx.commit().await.map_err(|_| {
                        AppError::DbError("cooperative signing supersede commit failed".into())
                    })?;
                    return Ok(());
                }
                return Err(AppError::RecoveryNotAvailable(
                    "cooperative signing outcome is ambiguous; waiting for unilateral timeout"
                        .into(),
                ));
            }
            db::CooperativeSigningState::ResponseReceived => {
                let action = automatic_action_for_path_evidence(
                    authority.evidence,
                    AutomaticFallbackConstructionPath::Cooperative,
                );
                let authority_integrity_failure = match action {
                    ChainSwapAction::Observe => {
                        return Err(AppError::RecoveryNotAvailable(
                            "cooperative signing response awaits complete current authority".into(),
                        ));
                    }
                    ChainSwapAction::RecoverBitcoin => validate_cooperative_operation_authority(
                        &operation, &authority, &swap, false,
                    )
                    .is_err(),
                    // A selected response cannot be completed after the
                    // Liquid path, an unknown outspend, or another terminal
                    // reducer decision wins. Preserve that conflict instead
                    // of leaving a response in an infinite retry loop.
                    _ => true,
                };
                if authority_integrity_failure {
                    let version = operation.version();
                    persist_cooperative_integrity_hold_in_transaction(
                        &mut tx,
                        chain_swap_id,
                        version,
                        b"bullnym/cooperative-signing/authority-integrity/v1",
                    )
                    .await?;
                    tx.commit().await.map_err(|_| {
                        AppError::DbError("cooperative signing authority hold commit failed".into())
                    })?;
                    return Err(AppError::ClaimError(
                        "cooperative signing response conflicts with current authority".into(),
                    ));
                }
                let runtime = state.recovery_manifest_runtime_v1().ok_or_else(|| {
                    AppError::RecoveryNotAvailable(
                        "protected cooperative signing runtime is unavailable".into(),
                    )
                })?;
                let (prepared, completion, fee_record) =
                    match complete_selected_cooperative_signing(&swap, &operation, runtime) {
                        Ok(completed) => completed,
                        Err(AppError::ClaimError(_)) => {
                            let version = operation.version();
                            persist_cooperative_integrity_hold_in_transaction(
                                &mut tx,
                                chain_swap_id,
                                version,
                                b"bullnym/cooperative-signing/completion-integrity/v1",
                            )
                            .await?;
                            tx.commit().await.map_err(|_| {
                                AppError::DbError(
                                    "cooperative signing integrity hold commit failed".into(),
                                )
                            })?;
                            return Err(AppError::ClaimError(
                                "cooperative signing completion failed integrity validation".into(),
                            ));
                        }
                        Err(error) => return Err(error),
                    };
                persist_selected_cooperative_completion_in_transaction(
                    &mut tx,
                    &swap,
                    &operation,
                    &prepared,
                    &completion,
                    &fee_record,
                    CooperativeCompletionAuthority::Live(&authority),
                    faults,
                )
                .await?;
                tx.commit().await.map_err(|_| {
                    AppError::DbError("cooperative signing completion commit failed".into())
                })?;
                return Ok(());
            }
            db::CooperativeSigningState::Completed => {
                return Err(AppError::ClaimError(
                    "completed cooperative signing has no immutable recovery attempt".into(),
                ));
            }
            db::CooperativeSigningState::IntegrityHold => {
                return Err(AppError::ClaimError(
                    "cooperative signing operation is on integrity hold".into(),
                ));
            }
            db::CooperativeSigningState::Superseded => {
                if path == Some(AutomaticFallbackConstructionPath::Unilateral) {
                    tx.commit().await.map_err(|_| {
                        AppError::DbError("cooperative signing commit failed".into())
                    })?;
                    return Ok(());
                }
                return Err(AppError::RecoveryNotAvailable(
                    "cooperative signing was superseded; waiting for unilateral authority".into(),
                ));
            }
        }
    }
    Err(AppError::RecoveryNotAvailable(
        "cooperative signing state machine did not converge".into(),
    ))
}

#[async_trait]
impl BitcoinRecoveryBroadcaster for EsploraRecoveryBroadcaster {
    async fn broadcast(&self, raw_tx_hex: &str, expected_txid: &str) -> Result<String, AppError> {
        crate::esplora::broadcast(&self.endpoints, raw_tx_hex, expected_txid).await
    }
}

/// Existing-obligation #85 entry. This never selects an address from a request.
/// The complete independent #82 packet is rebuilt under the shared lock before
/// construction and again immediately before broadcast.
pub(crate) async fn execute_journaled_recovery_automatically(
    state: &AppState,
    chain_swap_id: Uuid,
) -> Result<String, AppError> {
    let evidence = state.bitcoin_recovery_backend.as_deref().ok_or_else(|| {
        AppError::ElectrumError("Bitcoin recovery evidence client is unavailable".into())
    })?;
    let endpoints = evidence.endpoints().to_vec();
    let cooperative_provider = LiveCooperativeSigningProvider {
        api_url: state.config.boltz.api_url.clone(),
    };
    advance_cooperative_signing_operation(
        state,
        chain_swap_id,
        &cooperative_provider,
        &NoRecoveryFaults,
    )
    .await?;

    // The cooperative state machine either committed the exact final attempt
    // or positively yielded to the timeout-safe unilateral builder. The core
    // executor below remains the only broadcast boundary for both paths.
    let builder = LiveRecoveryBuilder { state };
    let broadcaster = EsploraRecoveryBroadcaster { endpoints };
    execute_journaled_recovery_with_builder_fee(
        &state.db,
        chain_swap_id,
        &builder,
        RecoveryConstructionFee::runtime(&state.fee_runtime),
        RecoveryExecutionServices {
            evidence,
            broadcaster: &broadcaster,
            faults: &NoRecoveryFaults,
        },
        RecoveryExecutionMode::Automatic(state),
    )
    .await
}

/// Testable write-ahead executor.  This is public only to let the external DB
/// integration target supply deterministic boundary fakes. `fee_decision`
/// applies only when no journaled attempt exists; retries always reuse the
/// committed bytes and their immutable actual-fee evidence.
#[doc(hidden)]
pub async fn execute_journaled_recovery_with_services(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    builder: &dyn BitcoinRecoveryBuilder,
    fee_decision: &BitcoinFeeDecision,
    evidence: &dyn BitcoinRecoveryEvidence,
    broadcaster: &dyn BitcoinRecoveryBroadcaster,
    faults: &dyn RecoveryFaultInjector,
) -> Result<String, AppError> {
    execute_journaled_recovery_with_optional_fee_services(
        pool,
        chain_swap_id,
        builder,
        Some(fee_decision),
        evidence,
        broadcaster,
        faults,
    )
    .await
}

/// Optional-fee integration seam used to prove that committed bytes can be
/// resumed without a fresh quote while new construction remains pending.
#[doc(hidden)]
pub async fn execute_journaled_recovery_with_optional_fee_services(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    builder: &dyn BitcoinRecoveryBuilder,
    fee_decision: Option<&BitcoinFeeDecision>,
    evidence: &dyn BitcoinRecoveryEvidence,
    broadcaster: &dyn BitcoinRecoveryBroadcaster,
    faults: &dyn RecoveryFaultInjector,
) -> Result<String, AppError> {
    let construction_fee = RecoveryConstructionFee::compatibility(fee_decision);
    execute_journaled_recovery_with_builder_fee(
        pool,
        chain_swap_id,
        builder,
        construction_fee,
        RecoveryExecutionServices {
            evidence,
            broadcaster,
            faults,
        },
        RecoveryExecutionMode::InjectedHarness,
    )
    .await
}

struct RecoveryConstructionFee<'a> {
    builder_decision: Option<BitcoinBuilderFeeDecision>,
    record: Option<&'a FeeDecisionRecord>,
    compatibility_record: Option<Result<FeeDecisionRecord, AppError>>,
    runtime: Option<&'a FeeRuntime>,
}

impl<'a> RecoveryConstructionFee<'a> {
    fn compatibility(decision: Option<&BitcoinFeeDecision>) -> Self {
        Self {
            builder_decision: decision.map(BitcoinBuilderFeeDecision::from),
            record: None,
            // Capture the monotonic authority before any pool/lock wait, but
            // defer an unusable-record error until the core proves that no
            // committed bytes exist to replay.
            compatibility_record: decision.map(bitcoin_fee_record_for_compatibility_seam),
            runtime: None,
        }
    }

    const fn runtime(runtime: &'a FeeRuntime) -> Self {
        Self {
            builder_decision: None,
            record: None,
            compatibility_record: None,
            runtime: Some(runtime),
        }
    }
}

#[derive(Clone, Copy)]
enum RecoveryExecutionMode<'a> {
    InjectedHarness,
    Automatic(&'a AppState),
}

struct RecoveryExecutionServices<'a> {
    evidence: &'a dyn BitcoinRecoveryEvidence,
    broadcaster: &'a dyn BitcoinRecoveryBroadcaster,
    faults: &'a dyn RecoveryFaultInjector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthoritativeAutomaticAttemptDecision {
    Broadcast,
    ExpectedObserved,
    IntegrityHold,
    Deferred,
}

/// Classify only the final primary-authority packet. The generic recovery
/// backend has ordered public failovers and therefore cannot authorize an
/// automatic state transition before this boundary.
fn classify_authoritative_automatic_attempt(
    action: ChainSwapAction,
    bitcoin_source: BitcoinSourceEvidence,
    recovery_transaction: MerchantTransactionEvidence,
) -> AuthoritativeAutomaticAttemptDecision {
    if action == ChainSwapAction::IntegrityHold {
        return AuthoritativeAutomaticAttemptDecision::IntegrityHold;
    }
    if bitcoin_source == BitcoinSourceEvidence::SpentByRecoveryTransaction
        && matches!(
            recovery_transaction,
            MerchantTransactionEvidence::Mempool
                | MerchantTransactionEvidence::Confirmed
                | MerchantTransactionEvidence::Finalized
        )
        && matches!(
            action,
            ChainSwapAction::WatchTransaction | ChainSwapAction::Finalize
        )
    {
        return AuthoritativeAutomaticAttemptDecision::ExpectedObserved;
    }
    if action == ChainSwapAction::RecoverBitcoin {
        AuthoritativeAutomaticAttemptDecision::Broadcast
    } else {
        AuthoritativeAutomaticAttemptDecision::Deferred
    }
}

fn automatic_existing_attempt_may_reconcile(
    decision: AuthoritativeAutomaticAttemptDecision,
) -> bool {
    matches!(
        decision,
        AuthoritativeAutomaticAttemptDecision::Broadcast
            | AuthoritativeAutomaticAttemptDecision::ExpectedObserved
            | AuthoritativeAutomaticAttemptDecision::IntegrityHold
    )
}

enum RecoveryBroadcastDispatch {
    Network {
        attempt: ChainSwapTxAttempt,
        result: Result<String, AppError>,
        generic_error_reconciliation: bool,
    },
    ExpectedObserved {
        attempt: ChainSwapTxAttempt,
    },
    IntegrityHold {
        attempt: ChainSwapTxAttempt,
        reason: String,
    },
}

enum AutomaticAttemptPreflight {
    BroadcastReady,
    ExpectedObserved(ChainSwapTxAttempt),
    IntegrityHold {
        attempt: ChainSwapTxAttempt,
        reason: String,
    },
}

async fn execute_journaled_recovery_with_builder_fee(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    builder: &dyn BitcoinRecoveryBuilder,
    construction_fee: RecoveryConstructionFee<'_>,
    services: RecoveryExecutionServices<'_>,
    mode: RecoveryExecutionMode<'_>,
) -> Result<String, AppError> {
    let RecoveryExecutionServices {
        evidence,
        broadcaster,
        faults,
    } = services;
    prepare_or_reload_attempt(
        pool,
        chain_swap_id,
        builder,
        construction_fee,
        evidence,
        faults,
        mode,
    )
    .await?;

    faults.check(RecoveryFaultPoint::AfterJournalCommitBeforeBroadcast)?;

    // Broadcast only bytes reloaded after the journal transaction committed.
    // Automatic execution takes the shared execution lock again around its
    // final independent evidence snapshot and the irreversible call below.
    let attempt = db::get_bitcoin_recovery_attempt(pool, chain_swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| {
            AppError::ClaimError(
                "committed Bitcoin recovery attempt disappeared before broadcast".into(),
            )
        })?;
    validate_reloaded_attempt(&attempt)?;

    let current_swap = db::get_chain_swap_by_id(pool, chain_swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("chain swap not found: {chain_swap_id}")))?;
    if current_swap.parsed_status().map_err(AppError::DbError)? == ChainSwapStatus::Refunded
        && current_swap.refund_txid.as_deref() == Some(attempt.txid.as_str())
        && matches!(
            attempt.status.as_str(),
            "broadcast" | "confirmed" | "finalized"
        )
    {
        return Ok(attempt.txid);
    }

    if matches!(mode, RecoveryExecutionMode::InjectedHarness) {
        let observed_token = attempt.observed_state_token();
        match reconcile_attempt_evidence(&attempt, evidence).await? {
            EvidenceDecision::ExpectedObserved(reason) => {
                complete_expected_attempt(pool, &attempt, &reason).await?;
                return Ok(attempt.txid);
            }
            EvidenceDecision::Unspent => {}
            EvidenceDecision::UnknownOutspend { source, spender } => {
                let reason = format!(
                    "source {}:{} spent by unexpected transaction {}",
                    source.txid, source.vout, spender
                );
                let held = db::mark_recovery_integrity_hold(
                    pool,
                    attempt.chain_swap_id,
                    attempt.id,
                    &attempt.purpose,
                    &attempt.txid,
                    &observed_token,
                    &reason,
                )
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
                if held != 1 {
                    return Err(AppError::DbError(
                        "could not persist Bitcoin recovery integrity hold".into(),
                    ));
                }
                tracing::error!(
                    event = "chain_swap_recovery_integrity_hold",
                    chain_swap_id = %attempt.chain_swap_id,
                    expected_txid = %attempt.txid,
                    source_txid = %source.txid,
                    source_vout = source.vout,
                    unexpected_spender = %spender,
                    "Bitcoin recovery source has an unknown outspend; injected harness stopped"
                );
                return Err(AppError::ClaimError(reason));
            }
        }
    }

    if let RecoveryExecutionMode::Automatic(state) = mode {
        match preflight_automatic_attempt_under_lock(state, chain_swap_id).await? {
            AutomaticAttemptPreflight::BroadcastReady => {}
            AutomaticAttemptPreflight::ExpectedObserved(attempt) => {
                complete_expected_attempt(
                    pool,
                    &attempt,
                    "expected transaction observed by the authoritative primary snapshot",
                )
                .await?;
                return Ok(attempt.txid);
            }
            AutomaticAttemptPreflight::IntegrityHold { attempt, reason } => {
                let observed_token = attempt.observed_state_token();
                let held = db::mark_recovery_integrity_hold(
                    pool,
                    attempt.chain_swap_id,
                    attempt.id,
                    &attempt.purpose,
                    &attempt.txid,
                    &observed_token,
                    &reason,
                )
                .await
                .map_err(|error| AppError::DbError(error.to_string()))?;
                if held != 1 {
                    return Err(AppError::DbError(
                        "could not persist authoritative Bitcoin recovery integrity hold".into(),
                    ));
                }
                return Err(AppError::ClaimError(reason));
            }
        }
    }

    let started_token = db::mark_recovery_broadcast_started(pool, attempt.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| {
            AppError::ClaimError(format!(
                "recovery attempt {} is not broadcastable (status {})",
                attempt.id, attempt.status
            ))
        })?;
    faults.check(RecoveryFaultPoint::AfterBroadcastAttemptCommit)?;

    let dispatch = match mode {
        RecoveryExecutionMode::InjectedHarness => RecoveryBroadcastDispatch::Network {
            result: broadcaster
                .broadcast(&attempt.raw_tx_hex, &attempt.txid)
                .await,
            attempt,
            generic_error_reconciliation: true,
        },
        RecoveryExecutionMode::Automatic(state) => {
            broadcast_automatic_attempt_under_lock(state, chain_swap_id, broadcaster).await?
        }
    };

    let (attempt, broadcast_result, generic_error_reconciliation) = match dispatch {
        RecoveryBroadcastDispatch::ExpectedObserved { attempt } => {
            complete_expected_attempt(
                pool,
                &attempt,
                "expected transaction observed by the authoritative primary snapshot",
            )
            .await?;
            return Ok(attempt.txid);
        }
        RecoveryBroadcastDispatch::IntegrityHold { attempt, reason } => {
            let held = db::mark_recovery_integrity_hold(
                pool,
                attempt.chain_swap_id,
                attempt.id,
                &attempt.purpose,
                &attempt.txid,
                &started_token,
                &reason,
            )
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
            if held != 1 {
                return Err(AppError::DbError(
                    "could not persist authoritative Bitcoin recovery integrity hold".into(),
                ));
            }
            tracing::error!(
                event = "chain_swap_recovery_integrity_hold",
                chain_swap_id = %attempt.chain_swap_id,
                expected_txid = %attempt.txid,
                "authoritative automatic-recovery evidence entered an integrity hold"
            );
            return Err(AppError::ClaimError(reason));
        }
        RecoveryBroadcastDispatch::Network {
            attempt,
            result,
            generic_error_reconciliation,
        } => (attempt, result, generic_error_reconciliation),
    };
    faults.check(RecoveryFaultPoint::AfterBroadcastCallBeforeOutcomeCommit)?;

    match broadcast_result {
        Ok(returned_txid) if returned_txid.eq_ignore_ascii_case(&attempt.txid) => {
            complete_expected_attempt(pool, &attempt, "broadcast accepted").await?;
            Ok(attempt.txid)
        }
        Ok(returned_txid) => {
            let error = format!(
                "broadcaster returned txid {returned_txid}, expected {}",
                attempt.txid
            );
            let error = AppError::ClaimError(error);
            if generic_error_reconciliation {
                reconcile_after_broadcast_error(pool, &attempt, &started_token, evidence, error)
                    .await
            } else {
                preserve_authoritative_broadcast_ambiguity(pool, &attempt, &started_token, error)
                    .await
            }
        }
        Err(error) => {
            if generic_error_reconciliation {
                reconcile_after_broadcast_error(pool, &attempt, &started_token, evidence, error)
                    .await
            } else {
                preserve_authoritative_broadcast_ambiguity(pool, &attempt, &started_token, error)
                    .await
            }
        }
    }
}

async fn prepare_or_reload_attempt(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    builder: &dyn BitcoinRecoveryBuilder,
    construction_fee: RecoveryConstructionFee<'_>,
    evidence: &dyn BitcoinRecoveryEvidence,
    faults: &dyn RecoveryFaultInjector,
    mode: RecoveryExecutionMode<'_>,
) -> Result<ChainSwapTxAttempt, AppError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    let lock_key = format!("chain-claim:{chain_swap_id}");
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
    if !got_lock {
        return Err(AppError::ClaimError(
            "chain swap is busy (claim/recovery in progress); retry shortly".into(),
        ));
    }

    let swap = db::get_chain_swap_by_id_for_update(&mut *tx, chain_swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("chain swap not found: {chain_swap_id}")))?;
    let status = swap.parsed_status().map_err(AppError::DbError)?;
    let existing = db::get_bitcoin_recovery_attempt_for_update(&mut tx, chain_swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    let (automatic_authority, automatic_construction_path) = match mode {
        RecoveryExecutionMode::InjectedHarness => (None, None),
        RecoveryExecutionMode::Automatic(state) => {
            let collected = collect_automatic_fallback_evidence_under_lock(
                state,
                &mut tx,
                &swap,
                existing.as_ref(),
            )
            .await?;
            if !collected.dependencies_available() {
                return Err(AppError::ElectrumError(
                    "automatic fallback evidence dependencies are unavailable".into(),
                ));
            }
            if existing.is_some() {
                (Some(collected), None)
            } else if let Some(path) = collected.automatic_construction_path() {
                (Some(collected), Some(path))
            } else {
                let decision = classify_authoritative_automatic_attempt(
                    reduce_chain_swap_evidence(&collected.evidence),
                    collected.evidence.bitcoin_source,
                    collected.evidence.bitcoin_recovery_transaction,
                );
                if decision == AuthoritativeAutomaticAttemptDecision::IntegrityHold {
                    return Err(AppError::ClaimError(
                        "automatic fallback evidence requires an integrity hold".into(),
                    ));
                }
                return Err(AppError::RecoveryNotAvailable(
                    "automatic fallback evidence no longer authorizes recovery".into(),
                ));
            }
        }
    };

    if let Some(attempt) = existing {
        // Validate the immutable bytes and their construction-time authority
        // before repairing any parent lifecycle state.
        validate_reloaded_attempt(&attempt)?;
        if let Some(authority) = automatic_authority.as_ref() {
            let path = classify_automatic_attempt_path(&attempt, &swap)?;
            let decision = classify_authoritative_automatic_attempt(
                automatic_action_for_attempt(authority, path),
                authority.evidence.bitcoin_source,
                authority.evidence.bitcoin_recovery_transaction,
            );
            if !automatic_existing_attempt_may_reconcile(decision) {
                return Err(AppError::RecoveryNotAvailable(
                    "automatic fallback evidence no longer permits attempt reconciliation".into(),
                ));
            }
            if decision != AuthoritativeAutomaticAttemptDecision::IntegrityHold {
                validate_automatic_attempt_authority(&attempt, authority, &swap, Some(path))?;
            }
        }
        if attempt.status == "integrity_hold" {
            return Err(AppError::ClaimError(format!(
                "recovery attempt is on integrity hold: {}",
                attempt
                    .integrity_reason
                    .as_deref()
                    .unwrap_or("unknown reason")
            )));
        }
        match status {
            ChainSwapStatus::Refunded if swap.refund_txid.as_deref() == Some(&attempt.txid) => {
                tx.commit()
                    .await
                    .map_err(|e| AppError::DbError(e.to_string()))?;
                return Ok(attempt);
            }
            ChainSwapStatus::Refunding => {}
            ChainSwapStatus::RefundDue => {
                // Defensive repair for a row reverted by the pre-journal
                // implementation: retain and resume the committed bytes.
                let rows = db::mark_chain_swap_refunding(&mut *tx, chain_swap_id)
                    .await
                    .map_err(|e| AppError::DbError(e.to_string()))?;
                if rows != 1 {
                    return Err(AppError::ClaimError(
                        "could not resume the committed recovery attempt".into(),
                    ));
                }
            }
            _ => {
                return Err(AppError::ClaimError(format!(
                    "committed recovery attempt conflicts with chain-swap status {status}"
                )));
            }
        }
        tx.commit()
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        return Ok(attempt);
    }

    if status == ChainSwapStatus::Refunding {
        tracing::error!(
            event = "chain_swap_legacy_recovery_ambiguity",
            chain_swap_id = %chain_swap_id,
            "legacy `refunding` row has no write-ahead transaction; refusing to reconstruct"
        );
        return Err(AppError::ClaimError(
            "legacy in-flight recovery has no committed transaction bytes; integrity review required"
                .into(),
        ));
    }
    if status != ChainSwapStatus::RefundDue {
        return Err(AppError::ClaimError(format!(
            "chain swap not recoverable (status {status})"
        )));
    }
    if swap.claim_txid.is_some() || swap.claim_tx_hex.is_some() {
        return Err(AppError::ClaimError(
            "recovery blocked: a Liquid claim is already in progress for this payment".into(),
        ));
    }
    let destination = match automatic_authority.as_ref() {
        Some(authority) => authority
            .committed_destination()
            .map(str::to_owned)
            .ok_or_else(|| {
                AppError::ClaimError("automatic fallback has no committed destination".into())
            })?,
        None => swap.refund_address.clone().ok_or_else(|| {
            AppError::ClaimError("chain swap recovery has no committed destination".into())
        })?,
    };
    // Compatibility authority was captured before the pool/lock wait, but its
    // result is deliberately inspected only after the existing-journal branch:
    // replay never consults new-construction authority.
    let runtime_fee = construction_fee
        .runtime
        .map(|runtime| {
            runtime
                .bitcoin_construction_decision_now(FeeConstructionPurpose::BitcoinRecovery)
                .map_err(|_| {
                    AppError::RecoveryNotAvailable(BITCOIN_FEE_DECISION_PENDING_REASON.into())
                })
        })
        .transpose()?;
    let compatibility_record = construction_fee.compatibility_record.transpose()?;
    let fee_decision = runtime_fee
        .as_ref()
        .map(|(decision, _)| BitcoinBuilderFeeDecision::from(decision))
        .or(construction_fee.builder_decision)
        .ok_or_else(|| {
            AppError::RecoveryNotAvailable(BITCOIN_FEE_DECISION_PENDING_REASON.into())
        })?;
    let fee_record = construction_fee
        .record
        .or_else(|| runtime_fee.as_ref().map(|(_, record)| record))
        .or(compatibility_record.as_ref())
        .ok_or_else(|| {
            AppError::RecoveryNotAvailable(BITCOIN_FEE_DECISION_PENDING_REASON.into())
        })?;
    if !fee_record.authorizes_construction_now() {
        return Err(AppError::RecoveryNotAvailable(
            BITCOIN_FEE_DECISION_PENDING_REASON.into(),
        ));
    }

    faults.check(RecoveryFaultPoint::BeforeConstruction)?;
    let transaction = match mode {
        RecoveryExecutionMode::InjectedHarness => {
            builder.construct(&swap, &destination, fee_decision).await?
        }
        RecoveryExecutionMode::Automatic(_) => {
            let path = automatic_construction_path.ok_or_else(|| {
                AppError::RecoveryNotAvailable(
                    "automatic fallback has no current construction path".into(),
                )
            })?;
            builder
                .construct_automatic(&swap, &destination, fee_decision, path)
                .await?
        }
    };
    let prepared = validate_constructed_attempt(
        &swap,
        &destination,
        &transaction,
        fee_record,
        evidence,
        automatic_authority.as_ref(),
        automatic_construction_path,
    )
    .await?;
    faults.check(RecoveryFaultPoint::AfterConstructionBeforeJournal)?;
    if !fee_record.authorizes_construction_now() {
        return Err(AppError::RecoveryNotAvailable(
            BITCOIN_FEE_DECISION_PENDING_REASON.into(),
        ));
    }

    let new_attempt = prepared.as_new(swap.id, fee_record);
    let attempt = db::insert_bitcoin_recovery_attempt(&mut tx, &new_attempt)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    // A faulty builder or inconsistent decision must roll back with the
    // journal instead of committing an unreplayable immutable attempt.
    validate_reloaded_attempt(&attempt)?;
    if let Some(authority) = automatic_authority.as_ref() {
        validate_automatic_attempt_authority(
            &attempt,
            authority,
            &swap,
            automatic_construction_path,
        )?;
    }
    let rows = db::mark_chain_swap_refunding(&mut *tx, chain_swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if rows != 1 {
        return Err(AppError::ClaimError(
            "recovery race lost before the journal committed".into(),
        ));
    }

    faults.check(RecoveryFaultPoint::AfterJournalWriteBeforeCommit)?;
    // The journal insert and parent transition are asynchronous database
    // boundaries too.  A decision that expired while either was blocked must
    // roll back with the transaction instead of becoming immutable replay
    // authority merely because it was still fresh before the first write.
    if !fee_record.authorizes_construction_now() {
        return Err(AppError::RecoveryNotAvailable(
            BITCOIN_FEE_DECISION_PENDING_REASON.into(),
        ));
    }
    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    Ok(attempt)
}

/// Reconcile a restarted attempt before incrementing its durable broadcast
/// counter. This replaces the legacy first-success backend read with a fresh,
/// coherent primary packet and lets an already-observed transaction complete
/// without recording a broadcast call that never happened.
async fn preflight_automatic_attempt_under_lock(
    state: &AppState,
    chain_swap_id: Uuid,
) -> Result<AutomaticAttemptPreflight, AppError> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    let lock_key = format!("chain-claim:{chain_swap_id}");
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
    if !got_lock {
        return Err(AppError::RecoveryNotAvailable(
            "automatic fallback preflight lock is busy".into(),
        ));
    }
    let swap = db::get_chain_swap_by_id_for_update(&mut *tx, chain_swap_id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("chain swap not found: {chain_swap_id}")))?;
    if swap.parsed_status().map_err(AppError::DbError)? != ChainSwapStatus::Refunding {
        return Err(AppError::RecoveryNotAvailable(
            "automatic fallback is no longer the owned preflight branch".into(),
        ));
    }
    let attempt = db::get_bitcoin_recovery_attempt_for_update(&mut tx, chain_swap_id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?
        .ok_or_else(|| {
            AppError::ClaimError(
                "committed Bitcoin recovery attempt disappeared before preflight".into(),
            )
        })?;
    validate_reloaded_attempt(&attempt)?;
    let collected =
        collect_automatic_fallback_evidence_under_lock(state, &mut tx, &swap, Some(&attempt))
            .await?;
    if !collected.dependencies_available() {
        return Err(AppError::ElectrumError(
            "automatic fallback evidence dependencies changed during preflight".into(),
        ));
    }
    let path = classify_automatic_attempt_path(&attempt, &swap)?;
    let decision = classify_authoritative_automatic_attempt(
        automatic_action_for_attempt(&collected, path),
        collected.evidence.bitcoin_source,
        collected.evidence.bitcoin_recovery_transaction,
    );
    let result = match decision {
        AuthoritativeAutomaticAttemptDecision::ExpectedObserved => {
            validate_automatic_attempt_authority(&attempt, &collected, &swap, Some(path))?;
            AutomaticAttemptPreflight::ExpectedObserved(attempt)
        }
        AuthoritativeAutomaticAttemptDecision::IntegrityHold => {
            AutomaticAttemptPreflight::IntegrityHold {
                attempt,
                reason: "authoritative automatic fallback preflight requires integrity review"
                    .into(),
            }
        }
        AuthoritativeAutomaticAttemptDecision::Broadcast => {
            validate_automatic_attempt_authority(&attempt, &collected, &swap, Some(path))?;
            AutomaticAttemptPreflight::BroadcastReady
        }
        AuthoritativeAutomaticAttemptDecision::Deferred => {
            return Err(AppError::RecoveryNotAvailable(
                "automatic fallback evidence changed during preflight".into(),
            ));
        }
    };
    tx.commit()
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    Ok(result)
}

async fn broadcast_automatic_attempt_under_lock(
    state: &AppState,
    chain_swap_id: Uuid,
    broadcaster: &dyn BitcoinRecoveryBroadcaster,
) -> Result<RecoveryBroadcastDispatch, AppError> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    let lock_key = format!("chain-claim:{chain_swap_id}");
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
    if !got_lock {
        return Err(AppError::RecoveryNotAvailable(
            "automatic fallback execution lock is busy".into(),
        ));
    }
    let swap = db::get_chain_swap_by_id_for_update(&mut *tx, chain_swap_id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("chain swap not found: {chain_swap_id}")))?;
    if swap.parsed_status().map_err(AppError::DbError)? != ChainSwapStatus::Refunding {
        return Err(AppError::RecoveryNotAvailable(
            "automatic fallback is no longer the owned execution branch".into(),
        ));
    }
    let attempt = db::get_bitcoin_recovery_attempt_for_update(&mut tx, chain_swap_id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?
        .ok_or_else(|| {
            AppError::ClaimError(
                "committed Bitcoin recovery attempt disappeared before broadcast".into(),
            )
        })?;
    validate_reloaded_attempt(&attempt)?;
    let collected =
        collect_automatic_fallback_evidence_under_lock(state, &mut tx, &swap, Some(&attempt))
            .await?;
    if !collected.dependencies_available() {
        return Err(AppError::ElectrumError(
            "automatic fallback evidence dependencies changed before broadcast".into(),
        ));
    }
    let path = classify_automatic_attempt_path(&attempt, &swap)?;
    let action = automatic_action_for_attempt(&collected, path);
    match classify_authoritative_automatic_attempt(
        action,
        collected.evidence.bitcoin_source,
        collected.evidence.bitcoin_recovery_transaction,
    ) {
        AuthoritativeAutomaticAttemptDecision::ExpectedObserved => {
            validate_automatic_attempt_authority(&attempt, &collected, &swap, Some(path))?;
            tx.commit()
                .await
                .map_err(|error| AppError::DbError(error.to_string()))?;
            return Ok(RecoveryBroadcastDispatch::ExpectedObserved { attempt });
        }
        AuthoritativeAutomaticAttemptDecision::IntegrityHold => {
            tx.commit()
                .await
                .map_err(|error| AppError::DbError(error.to_string()))?;
            return Ok(RecoveryBroadcastDispatch::IntegrityHold {
                attempt,
                reason: "authoritative automatic fallback evidence requires integrity review"
                    .into(),
            });
        }
        AuthoritativeAutomaticAttemptDecision::Deferred => {
            return Err(AppError::RecoveryNotAvailable(
                "automatic fallback evidence changed before broadcast".into(),
            ));
        }
        AuthoritativeAutomaticAttemptDecision::Broadcast => {
            validate_automatic_attempt_authority(&attempt, &collected, &swap, Some(path))?;
        }
    }
    // Keep the transaction-scoped `chain-claim` lock through the exact-byte
    // broadcast. External chain reads above may take time, but no claim,
    // scheduler, or competing recovery can change the owned execution branch
    // between the final #82 decision and the irreversible call.
    let broadcast_result = broadcaster
        .broadcast(&attempt.raw_tx_hex, &attempt.txid)
        .await;
    if !matches!(
        &broadcast_result,
        Ok(returned_txid) if returned_txid.eq_ignore_ascii_case(&attempt.txid)
    ) {
        // A broadcaster error or mismatched response is ambiguous. Automatic
        // execution must reconcile it from another coherent primary packet,
        // never from the generic first-success public-failover backend.
        let reconciled =
            collect_automatic_fallback_evidence_under_lock(state, &mut tx, &swap, Some(&attempt))
                .await?;
        if reconciled.dependencies_available() {
            let reconciled_path = classify_automatic_attempt_path(&attempt, &swap)?;
            let reconciled_action = automatic_action_for_attempt(&reconciled, reconciled_path);
            match classify_authoritative_automatic_attempt(
                reconciled_action,
                reconciled.evidence.bitcoin_source,
                reconciled.evidence.bitcoin_recovery_transaction,
            ) {
                AuthoritativeAutomaticAttemptDecision::ExpectedObserved => {
                    validate_automatic_attempt_authority(
                        &attempt,
                        &reconciled,
                        &swap,
                        Some(reconciled_path),
                    )?;
                    tx.commit()
                        .await
                        .map_err(|error| AppError::DbError(error.to_string()))?;
                    return Ok(RecoveryBroadcastDispatch::ExpectedObserved { attempt });
                }
                AuthoritativeAutomaticAttemptDecision::IntegrityHold => {
                    tx.commit()
                        .await
                        .map_err(|error| AppError::DbError(error.to_string()))?;
                    return Ok(RecoveryBroadcastDispatch::IntegrityHold {
                        attempt,
                        reason: "authoritative post-broadcast evidence requires integrity review"
                            .into(),
                    });
                }
                AuthoritativeAutomaticAttemptDecision::Broadcast => {
                    // Revalidate all immutable attempt authority even though
                    // this call remains ambiguous and will not rebroadcast in
                    // the current invocation.
                    validate_automatic_attempt_authority(
                        &attempt,
                        &reconciled,
                        &swap,
                        Some(reconciled_path),
                    )?;
                }
                AuthoritativeAutomaticAttemptDecision::Deferred => {}
            }
        }
    }
    tx.commit()
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    Ok(RecoveryBroadcastDispatch::Network {
        attempt,
        result: broadcast_result,
        generic_error_reconciliation: false,
    })
}

fn automatic_action_for_attempt(
    authority: &CollectedAutomaticFallbackEvidence,
    path: AutomaticFallbackConstructionPath,
) -> ChainSwapAction {
    automatic_action_for_path_evidence(authority.evidence, path)
}

fn automatic_action_for_path_evidence(
    mut evidence: crate::chain_swap_action::ChainSwapEvidence,
    path: AutomaticFallbackConstructionPath,
) -> ChainSwapAction {
    if path == AutomaticFallbackConstructionPath::Cooperative {
        // A locally verified key-path witness is stronger than a transient
        // provider probe: it proves that cooperative recovery was available
        // for these exact bytes. This fact exists only in memory; the durable
        // authority remains the immutable transaction journal itself.
        evidence.cooperative_recovery = CooperativeRecoveryEvidence::Available;
    }
    reduce_chain_swap_evidence(&evidence)
}

fn validate_automatic_path_position(
    authority: &CollectedAutomaticFallbackEvidence,
    path: AutomaticFallbackConstructionPath,
    transaction: &Transaction,
) -> Result<(), AppError> {
    match path {
        AutomaticFallbackConstructionPath::Cooperative => {
            if authority.evidence.bitcoin_timeout == BitcoinTimeoutEvidence::Unknown {
                return Err(AppError::ClaimError(
                    "cooperative automatic recovery lacks a stable timeout position".into(),
                ));
            }
        }
        AutomaticFallbackConstructionPath::Unilateral => {
            if authority.evidence.bitcoin_timeout != BitcoinTimeoutEvidence::Reached {
                return Err(AppError::RecoveryNotAvailable(
                    "unilateral automatic recovery is not yet script-path spendable".into(),
                ));
            }
            let timeout_height = authority.bitcoin_timeout_height().ok_or_else(|| {
                AppError::ClaimError("automatic recovery lacks its immutable timeout".into())
            })?;
            if transaction.lock_time.to_consensus_u32() != timeout_height {
                return Err(AppError::ClaimError(
                    "automatic recovery journal does not enforce the immutable script timeout"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

fn classify_automatic_attempt_path(
    attempt: &ChainSwapTxAttempt,
    swap: &ChainSwapRecord,
) -> Result<AutomaticFallbackConstructionPath, AppError> {
    let raw = hex::decode(&attempt.raw_tx_hex)
        .map_err(|_| AppError::ClaimError("automatic recovery journal hex is invalid".into()))?;
    let transaction: Transaction = deserialize(&raw)
        .map_err(|_| AppError::ClaimError("automatic recovery journal is invalid".into()))?;
    let source_txouts = journaled_source_txouts(&attempt.source_prevouts.0)?;
    validate_automatic_recovery_witness(swap, &transaction, &source_txouts)
}

fn validate_automatic_attempt_authority(
    attempt: &ChainSwapTxAttempt,
    authority: &CollectedAutomaticFallbackEvidence,
    swap: &ChainSwapRecord,
    expected_path: Option<AutomaticFallbackConstructionPath>,
) -> Result<AutomaticFallbackConstructionPath, AppError> {
    let destination = authority.committed_destination().ok_or_else(|| {
        AppError::ClaimError("automatic fallback lacks its immutable destination".into())
    })?;
    if attempt.destination_address != destination
        || swap.refund_address.as_deref() != Some(destination)
    {
        return Err(AppError::ClaimError(
            "automatic recovery journal destination differs from the immutable commitment".into(),
        ));
    }
    let address = Address::from_str(destination)
        .map_err(|_| AppError::ClaimError("automatic recovery destination is invalid".into()))?
        .require_network(Network::Bitcoin)
        .map_err(|_| {
            AppError::ClaimError("automatic recovery destination is not mainnet".into())
        })?;
    if hex::encode(address.script_pubkey().as_bytes()) != attempt.destination_script_hex {
        return Err(AppError::ClaimError(
            "automatic recovery journal script differs from the immutable commitment".into(),
        ));
    }

    if authority.exact_sources().len() != 1 || attempt.source_prevouts.0.len() != 1 {
        return Err(AppError::ClaimError(
            "automatic recovery requires exactly one source outpoint per journal attempt".into(),
        ));
    }
    let primary_source = &authority.exact_sources()[0];
    validate_exact_primary_source_tuple(
        primary_source.txid(),
        primary_source.vout(),
        primary_source.amount_sat(),
        primary_source.script_pubkey_hex(),
        &attempt.source_prevouts.0[0],
    )?;
    let raw = hex::decode(&attempt.raw_tx_hex)
        .map_err(|_| AppError::ClaimError("automatic recovery journal hex is invalid".into()))?;
    let transaction: Transaction = deserialize(&raw)
        .map_err(|_| AppError::ClaimError("automatic recovery journal is invalid".into()))?;
    let source_txouts = journaled_source_txouts(&attempt.source_prevouts.0)?;
    let path = validate_automatic_recovery_witness(swap, &transaction, &source_txouts)?;
    if expected_path.is_some_and(|expected| expected != path) {
        return Err(AppError::ClaimError(
            "automatic recovery builder returned a different spend path than authorized".into(),
        ));
    }
    validate_automatic_path_position(authority, path, &transaction)?;
    Ok(path)
}

fn validate_exact_primary_source_tuple(
    primary_txid: &str,
    primary_vout: u32,
    primary_amount_sat: u64,
    primary_script_pubkey_hex: &str,
    journaled: &RecoverySourcePrevout,
) -> Result<(), AppError> {
    let primary_script = hex::decode(primary_script_pubkey_hex)
        .map_err(|_| AppError::ClaimError("fresh primary source script is invalid hex".into()))?;
    let journaled_script = hex::decode(&journaled.script_pubkey_hex).map_err(|_| {
        AppError::ClaimError("automatic recovery journal source script is invalid hex".into())
    })?;
    if hex::encode(&primary_script) != primary_script_pubkey_hex
        || hex::encode(&journaled_script) != journaled.script_pubkey_hex
    {
        return Err(AppError::ClaimError(
            "automatic recovery source script is not canonical".into(),
        ));
    }
    if journaled.txid != primary_txid
        || journaled.vout != primary_vout
        || journaled.amount_sat != primary_amount_sat
        || journaled.script_pubkey_hex != primary_script_pubkey_hex
    {
        return Err(AppError::ClaimError(
            "automatic recovery journal source tuple differs from fresh primary authority".into(),
        ));
    }
    Ok(())
}

fn journaled_source_txouts(sources: &[RecoverySourcePrevout]) -> Result<Vec<TxOut>, AppError> {
    sources
        .iter()
        .map(|source| {
            let script_bytes = hex::decode(&source.script_pubkey_hex).map_err(|_| {
                AppError::ClaimError(
                    "automatic recovery journal source script is invalid hex".into(),
                )
            })?;
            if hex::encode(&script_bytes) != source.script_pubkey_hex {
                return Err(AppError::ClaimError(
                    "automatic recovery journal source script is not canonical".into(),
                ));
            }
            Ok(TxOut {
                value: Amount::from_sat(source.amount_sat),
                script_pubkey: ScriptBuf::from_bytes(script_bytes),
            })
        })
        .collect()
}

fn validate_automatic_recovery_witness(
    swap: &ChainSwapRecord,
    transaction: &Transaction,
    source_txouts: &[TxOut],
) -> Result<AutomaticFallbackConstructionPath, AppError> {
    if transaction.input.len() != 1 || source_txouts.len() != 1 {
        return Err(AppError::ClaimError(
            "automatic recovery requires exactly one source outpoint per transaction".into(),
        ));
    }
    let cooperative_shape = transaction.lock_time == bitcoin::absolute::LockTime::ZERO
        && transaction.input.iter().all(|input| {
            input.sequence == bitcoin::Sequence::MAX
                && input.witness.len() == 1
                && input.witness[0].len() == 64
        });
    if cooperative_shape {
        validate_automatic_cooperative_refund_witness(swap, transaction, source_txouts)?;
        return Ok(AutomaticFallbackConstructionPath::Cooperative);
    }

    let timeout_height = swap
        .creation_terms
        .as_ref()
        .and_then(|terms| u32::try_from(terms.btc_timeout_height).ok())
        .filter(|height| *height > 0)
        .ok_or_else(|| {
            AppError::ClaimError("automatic recovery lacks its immutable timeout".into())
        })?;
    if transaction.lock_time.to_consensus_u32() != timeout_height
        || transaction
            .input
            .iter()
            .any(|input| input.sequence != bitcoin::Sequence::ZERO)
    {
        return Err(AppError::ClaimError(
            "automatic recovery transaction is neither an exact cooperative key-path spend nor the immutable unilateral refund path".into(),
        ));
    }
    validate_automatic_unilateral_refund_witness(swap, transaction, source_txouts)?;
    Ok(AutomaticFallbackConstructionPath::Unilateral)
}

/// Prove that the returned transaction is a Taproot key-path refund of the
/// exact committed source. A valid signature for the tweaked output key proves
/// successful provider cooperation; transport errors never reach this helper.
fn validate_automatic_cooperative_refund_witness(
    swap: &ChainSwapRecord,
    transaction: &Transaction,
    source_txouts: &[TxOut],
) -> Result<(), AppError> {
    swap.verify_creation_response_integrity()
        .map_err(AppError::ClaimError)?;
    let lockup_script = Address::from_str(&swap.lockup_address)
        .map_err(|_| AppError::ClaimError("automatic recovery lockup address is invalid".into()))?
        .require_network(Network::Bitcoin)
        .map_err(|_| AppError::ClaimError("automatic recovery lockup is not mainnet".into()))?
        .script_pubkey();
    if source_txouts[0].script_pubkey != lockup_script {
        return Err(AppError::ClaimError(
            "automatic cooperative source differs from the immutable lockup".into(),
        ));
    }
    validate_automatic_cooperative_keypath_signature(transaction, source_txouts)
}

fn validate_automatic_cooperative_keypath_signature(
    transaction: &Transaction,
    source_txouts: &[TxOut],
) -> Result<(), AppError> {
    if transaction.input.len() != 1 || source_txouts.len() != 1 {
        return Err(AppError::ClaimError(
            "automatic cooperative recovery requires exactly one source".into(),
        ));
    }
    let input = &transaction.input[0];
    if transaction.lock_time != bitcoin::absolute::LockTime::ZERO
        || input.sequence != bitcoin::Sequence::MAX
        || input.witness.len() != 1
    {
        return Err(AppError::ClaimError(
            "automatic cooperative recovery does not use the exact key-path shape".into(),
        ));
    }
    let signature = TaprootSignature::from_slice(&input.witness[0]).map_err(|_| {
        AppError::ClaimError("automatic cooperative recovery signature is invalid".into())
    })?;
    if signature.sighash_type != TapSighashType::Default {
        return Err(AppError::ClaimError(
            "automatic cooperative recovery does not use the pinned sighash mode".into(),
        ));
    }
    let sighash = SighashCache::new(transaction.clone())
        .taproot_key_spend_signature_hash(0, &Prevouts::All(source_txouts), TapSighashType::Default)
        .map_err(|_| {
            AppError::ClaimError("automatic cooperative recovery sighash is invalid".into())
        })?;
    let message = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    let output_key = p2tr_output_key(&source_txouts[0].script_pubkey)?;
    bitcoin::secp256k1::Secp256k1::verification_only()
        .verify_schnorr(&signature.signature, &message, &output_key)
        .map_err(|_| {
            AppError::ClaimError(
                "automatic cooperative recovery is not signed by the committed Taproot output key"
                    .into(),
            )
        })
}

/// Prove that every automatic input is the exact unilateral Boltz refund
/// script path. Source/destination/fee validation alone is insufficient: a
/// cooperative key-path transaction or a different tapleaf could otherwise be
/// journaled and replayed after the immutable timeout.
fn validate_automatic_unilateral_refund_witness(
    swap: &ChainSwapRecord,
    transaction: &Transaction,
    source_txouts: &[TxOut],
) -> Result<(), AppError> {
    if transaction.input.len() != source_txouts.len() || transaction.input.is_empty() {
        return Err(AppError::ClaimError(
            "automatic recovery witness source set is incomplete".into(),
        ));
    }
    swap.verify_creation_response_integrity()
        .map_err(AppError::ClaimError)?;
    let terms = swap.creation_terms.as_ref().ok_or_else(|| {
        AppError::ClaimError("automatic recovery lacks immutable creation terms".into())
    })?;
    let response: CreateChainResponse =
        serde_json::from_str(&swap.boltz_response_json).map_err(|_| {
            AppError::ClaimError("automatic recovery creation response is invalid".into())
        })?;
    let refund_leaf_bytes = hex::decode(&response.lockup_details.swap_tree.refund_leaf.output)
        .map_err(|_| AppError::ClaimError("automatic recovery refund leaf is invalid".into()))?;
    if hex::encode(Sha256::digest(&refund_leaf_bytes)) != terms.btc_refund_script_sha256 {
        return Err(AppError::ClaimError(
            "automatic recovery refund leaf differs from immutable creation terms".into(),
        ));
    }
    let refund_leaf = ScriptBuf::from_bytes(refund_leaf_bytes);
    let leaf_hash = TapLeafHash::from_script(&refund_leaf, LeafVersion::TapScript);

    let key_bytes =
        Zeroizing::new(hex::decode(&swap.refund_key_hex).map_err(|_| {
            AppError::ClaimError("automatic recovery refund key is invalid".into())
        })?);
    let secret_key = bitcoin::secp256k1::SecretKey::from_slice(key_bytes.as_slice())
        .map_err(|_| AppError::ClaimError("automatic recovery refund key is invalid".into()))?;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let refund_keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let (refund_xonly, _) = refund_keypair.x_only_public_key();

    let lockup_script = Address::from_str(&swap.lockup_address)
        .map_err(|_| AppError::ClaimError("automatic recovery lockup address is invalid".into()))?
        .require_network(Network::Bitcoin)
        .map_err(|_| AppError::ClaimError("automatic recovery lockup is not mainnet".into()))?
        .script_pubkey();
    if source_txouts
        .iter()
        .any(|source| source.script_pubkey != lockup_script)
    {
        return Err(AppError::ClaimError(
            "automatic recovery source script differs from the immutable lockup".into(),
        ));
    }

    for (input_index, input) in transaction.input.iter().enumerate() {
        if input.sequence != bitcoin::Sequence::ZERO
            || input.witness.len() != 3
            || input.witness[0].len() != 64
        {
            return Err(AppError::ClaimError(
                "automatic recovery input is not an exact unilateral refund witness".into(),
            ));
        }
        if &input.witness[1] != refund_leaf.as_bytes() {
            return Err(AppError::ClaimError(
                "automatic recovery witness uses a different refund leaf".into(),
            ));
        }
        let signature = TaprootSignature::from_slice(&input.witness[0]).map_err(|_| {
            AppError::ClaimError("automatic recovery witness signature is invalid".into())
        })?;
        if signature.sighash_type != TapSighashType::Default {
            return Err(AppError::ClaimError(
                "automatic recovery witness does not use the pinned sighash mode".into(),
            ));
        }
        let control_block = ControlBlock::decode(&input.witness[2]).map_err(|_| {
            AppError::ClaimError("automatic recovery witness control block is invalid".into())
        })?;
        if control_block.leaf_version != LeafVersion::TapScript {
            return Err(AppError::ClaimError(
                "automatic recovery witness control block uses a different leaf version".into(),
            ));
        }
        let output_key = p2tr_output_key(&source_txouts[input_index].script_pubkey)?;
        if !control_block.verify_taproot_commitment(&secp, output_key, &refund_leaf) {
            return Err(AppError::ClaimError(
                "automatic recovery witness does not commit to the source taproot output".into(),
            ));
        }
        let sighash = SighashCache::new(transaction.clone())
            .taproot_script_spend_signature_hash(
                input_index,
                &Prevouts::All(source_txouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|_| {
                AppError::ClaimError("automatic recovery witness sighash is invalid".into())
            })?;
        let message = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
        secp.verify_schnorr(&signature.signature, &message, &refund_xonly)
            .map_err(|_| {
                AppError::ClaimError(
                    "automatic recovery witness is not signed by the immutable refund key".into(),
                )
            })?;
    }
    Ok(())
}

fn p2tr_output_key(script: &ScriptBuf) -> Result<XOnlyPublicKey, AppError> {
    let bytes = script.as_bytes();
    if bytes.len() != 34 || bytes[0] != 0x51 || bytes[1] != 0x20 {
        return Err(AppError::ClaimError(
            "automatic recovery source is not a canonical taproot output".into(),
        ));
    }
    XOnlyPublicKey::from_slice(&bytes[2..]).map_err(|_| {
        AppError::ClaimError("automatic recovery source taproot key is invalid".into())
    })
}

async fn validate_constructed_attempt(
    swap: &ChainSwapRecord,
    destination: &str,
    transaction: &BtcLikeTransaction,
    fee_record: &FeeDecisionRecord,
    evidence: &dyn BitcoinRecoveryEvidence,
    automatic_authority: Option<&CollectedAutomaticFallbackEvidence>,
    automatic_path: Option<AutomaticFallbackConstructionPath>,
) -> Result<PreparedAttempt, AppError> {
    let BtcLikeTransaction::Bitcoin(tx) = transaction else {
        return Err(AppError::ClaimError(
            "Bitcoin recovery builder returned a non-Bitcoin transaction".into(),
        ));
    };
    if tx.input.is_empty() {
        return Err(AppError::ClaimError(
            "Bitcoin recovery transaction has no inputs".into(),
        ));
    }
    if tx.output.len() != 1 {
        return Err(AppError::ClaimError(format!(
            "Bitcoin recovery transaction must have exactly one merchant output, got {}",
            tx.output.len()
        )));
    }

    let destination_address = Address::from_str(destination)
        .map_err(|e| AppError::ClaimError(format!("invalid committed recovery address: {e}")))?
        .require_network(Network::Bitcoin)
        .map_err(|_| AppError::ClaimError("recovery destination is not Bitcoin mainnet".into()))?;
    let destination_script = destination_address.script_pubkey();
    if tx.output[0].script_pubkey != destination_script {
        return Err(AppError::ClaimError(
            "constructed recovery transaction does not pay the committed destination".into(),
        ));
    }

    let lockup_script = Address::from_str(&swap.lockup_address)
        .map_err(|e| AppError::ClaimError(format!("invalid chain-swap lockup address: {e}")))?
        .require_network(Network::Bitcoin)
        .map_err(|_| AppError::ClaimError("chain-swap lockup is not Bitcoin mainnet".into()))?
        .script_pubkey();

    let mut seen = HashSet::new();
    let mut source_prevouts = Vec::with_capacity(tx.input.len());
    let mut source_txouts = Vec::with_capacity(tx.input.len());
    let mut total_input_sat = 0u64;
    for input in &tx.input {
        let source_txid = input.previous_output.txid.to_string();
        let source_vout = input.previous_output.vout;
        if !seen.insert((source_txid.clone(), source_vout)) {
            return Err(AppError::ClaimError(
                "Bitcoin recovery transaction repeats a source outpoint".into(),
            ));
        }
        let raw_source = evidence
            .raw_transaction(&source_txid)
            .await?
            .ok_or_else(|| {
                AppError::ClaimError(format!(
                    "Bitcoin recovery source transaction {source_txid} is absent"
                ))
            })?;
        let source_tx: Transaction = deserialize(&raw_source).map_err(|e| {
            AppError::ClaimError(format!("decode Bitcoin recovery source transaction: {e}"))
        })?;
        if source_tx.compute_txid().to_string() != source_txid {
            return Err(AppError::ClaimError(
                "Bitcoin recovery source bytes do not match their txid".into(),
            ));
        }
        let prevout = source_tx.output.get(source_vout as usize).ok_or_else(|| {
            AppError::ClaimError(format!(
                "Bitcoin recovery source {source_txid}:{source_vout} has no such output"
            ))
        })?;
        if prevout.script_pubkey != lockup_script {
            return Err(AppError::ClaimError(format!(
                "Bitcoin recovery source {source_txid}:{source_vout} is not the committed lockup script"
            )));
        }
        let amount_sat = prevout.value.to_sat();
        total_input_sat = total_input_sat
            .checked_add(amount_sat)
            .ok_or_else(|| AppError::ClaimError("Bitcoin recovery input amount overflow".into()))?;
        source_prevouts.push(RecoverySourcePrevout {
            txid: source_txid,
            vout: source_vout,
            amount_sat,
            script_pubkey_hex: hex::encode(prevout.script_pubkey.as_bytes()),
        });
        source_txouts.push(prevout.clone());
    }

    if let Some(authority) = automatic_authority {
        if tx.input.len() != 1 || authority.exact_sources().len() != 1 {
            return Err(AppError::ClaimError(
                "automatic recovery requires exactly one source outpoint per journal attempt"
                    .into(),
            ));
        }
        let primary_source = &authority.exact_sources()[0];
        validate_exact_primary_source_tuple(
            primary_source.txid(),
            primary_source.vout(),
            primary_source.amount_sat(),
            primary_source.script_pubkey_hex(),
            &source_prevouts[0],
        )?;
        let expected_path = automatic_path.ok_or_else(|| {
            AppError::ClaimError("automatic recovery lacks its selected spend path".into())
        })?;
        let actual_path = validate_automatic_recovery_witness(swap, tx, &source_txouts)?;
        if actual_path != expected_path {
            return Err(AppError::ClaimError(
                "automatic recovery builder returned a different spend path than authorized".into(),
            ));
        }
        validate_automatic_path_position(authority, actual_path, tx)?;
        if automatic_action_for_attempt(authority, actual_path) != ChainSwapAction::RecoverBitcoin {
            return Err(AppError::RecoveryNotAvailable(
                "automatic recovery evidence changed before exact bytes were journaled".into(),
            ));
        }
    }

    let total_output_sat = tx.output.iter().try_fold(0u64, |sum, output| {
        sum.checked_add(output.value.to_sat())
            .ok_or_else(|| AppError::ClaimError("Bitcoin recovery output amount overflow".into()))
    })?;
    let fee_amount_sat = total_input_sat
        .checked_sub(total_output_sat)
        .ok_or_else(|| {
            AppError::ClaimError("Bitcoin recovery transaction spends more than its inputs".into())
        })?;
    if fee_amount_sat == 0 {
        return Err(AppError::ClaimError(
            "Bitcoin recovery transaction has a zero miner fee".into(),
        ));
    }
    let vsize = tx.vsize();
    if vsize == 0 {
        return Err(AppError::ClaimError(
            "Bitcoin recovery transaction has zero virtual size".into(),
        ));
    }
    let vbytes = u64::try_from(vsize).map_err(|_| {
        AppError::ClaimError("Bitcoin recovery virtual size exceeds fee-policy range".into())
    })?;
    let exact_fee_sat = fee_record
        .exact_authorized_fee_sat(vbytes)
        .map_err(|error| {
            AppError::ClaimError(format!(
                "Bitcoin recovery fee bound cannot be represented for {vbytes} vbytes: {error}"
            ))
        })?;
    if fee_amount_sat != exact_fee_sat {
        return Err(AppError::ClaimError(format!(
            "Bitcoin recovery fee {fee_amount_sat} sat does not match exact accepted decision fee {exact_fee_sat} sat for {vbytes} vbytes"
        )));
    }
    let raw_tx_hex = hex::encode(serialize(tx));
    let txid = tx.compute_txid().to_string();
    let destination_amount_sat = i64::try_from(tx.output[0].value.to_sat()).map_err(|_| {
        AppError::ClaimError("Bitcoin recovery destination amount exceeds database range".into())
    })?;
    let fee_amount_sat_i64 = i64::try_from(fee_amount_sat)
        .map_err(|_| AppError::ClaimError("Bitcoin recovery fee exceeds database range".into()))?;

    Ok(PreparedAttempt {
        raw_tx_hex,
        txid,
        source_prevouts,
        destination_address: destination.to_string(),
        destination_script_hex: hex::encode(destination_script.as_bytes()),
        destination_amount_sat,
        fee_amount_sat: fee_amount_sat_i64,
        fee_rate_sat_vb: fee_amount_sat as f64 / vsize as f64,
    })
}

struct PreparedAttempt {
    raw_tx_hex: String,
    txid: String,
    source_prevouts: Vec<RecoverySourcePrevout>,
    destination_address: String,
    destination_script_hex: String,
    destination_amount_sat: i64,
    fee_amount_sat: i64,
    fee_rate_sat_vb: f64,
}

impl PreparedAttempt {
    fn as_new<'a>(
        &'a self,
        chain_swap_id: Uuid,
        fee_decision: &'a FeeDecisionRecord,
    ) -> NewBitcoinRecoveryAttempt<'a> {
        NewBitcoinRecoveryAttempt {
            chain_swap_id,
            raw_tx_hex: &self.raw_tx_hex,
            txid: &self.txid,
            source_prevouts: &self.source_prevouts,
            destination_address: &self.destination_address,
            destination_script_hex: &self.destination_script_hex,
            destination_vout: 0,
            destination_amount_sat: self.destination_amount_sat,
            fee_amount_sat: self.fee_amount_sat,
            fee_rate_sat_vb: self.fee_rate_sat_vb,
            fee_decision,
        }
    }
}

fn bitcoin_fee_record_for_compatibility_seam(
    decision: &BitcoinFeeDecision,
) -> Result<FeeDecisionRecord, AppError> {
    let evaluated_at_unix =
        match decision.freshness() {
            FeeFreshness::Fresh { age_secs, .. } => decision
                .observed_at_unix()
                .checked_add(age_secs)
                .ok_or_else(|| AppError::ClaimError("fee decision clock overflow".into()))?,
            _ => {
                return Err(AppError::RecoveryNotAvailable(
                    BITCOIN_FEE_DECISION_PENDING_REASON.into(),
                ))
            }
        };
    FeeDecisionRecord::from_bitcoin(
        FeeConstructionPurpose::BitcoinRecovery,
        decision,
        &BitcoinFeePolicy::default(),
        evaluated_at_unix,
    )
    .map_err(|error| AppError::ClaimError(format!("invalid Bitcoin fee decision record: {error}")))
}

fn validate_reloaded_attempt(attempt: &ChainSwapTxAttempt) -> Result<(), AppError> {
    let raw = hex::decode(&attempt.raw_tx_hex)
        .map_err(|e| AppError::ClaimError(format!("decode journaled recovery hex: {e}")))?;
    let tx: Transaction = deserialize(&raw)
        .map_err(|e| AppError::ClaimError(format!("decode journaled recovery tx: {e}")))?;
    if tx.compute_txid().to_string() != attempt.txid {
        return Err(AppError::ClaimError(
            "journaled recovery bytes do not match the journaled txid".into(),
        ));
    }
    let destination_vout = usize::try_from(attempt.destination_vout).map_err(|_| {
        AppError::ClaimError("journaled recovery destination vout is negative".into())
    })?;
    let output = tx
        .output
        .get(destination_vout)
        .ok_or_else(|| AppError::ClaimError("journaled recovery output is missing".into()))?;
    let destination_amount_sat = i64::try_from(output.value.to_sat()).map_err(|_| {
        AppError::ClaimError("journaled recovery destination amount exceeds database range".into())
    })?;
    if hex::encode(output.script_pubkey.as_bytes()) != attempt.destination_script_hex
        || destination_amount_sat != attempt.destination_amount_sat
    {
        return Err(AppError::ClaimError(
            "journaled recovery bytes do not match the committed merchant output".into(),
        ));
    }
    if tx.input.len() != attempt.source_prevouts.0.len()
        || tx
            .input
            .iter()
            .zip(attempt.source_prevouts.0.iter())
            .any(|(input, source)| {
                input.previous_output.txid.to_string() != source.txid
                    || input.previous_output.vout != source.vout
            })
    {
        return Err(AppError::ClaimError(
            "journaled recovery bytes do not match the committed source outpoints".into(),
        ));
    }
    validate_reloaded_fee_intent(
        &attempt.source_prevouts.0,
        &tx,
        attempt.fee_amount_sat,
        attempt.fee_rate_sat_vb,
        &attempt.fee_authority,
    )?;
    Ok(())
}

fn validate_reloaded_fee_intent(
    source_prevouts: &[RecoverySourcePrevout],
    tx: &Transaction,
    stored_fee_amount_sat: i64,
    stored_fee_rate_sat_vb: f64,
    fee_authority: &db::BitcoinRecoveryFeeAuthority,
) -> Result<(), AppError> {
    let total_input_sat = source_prevouts.iter().try_fold(0u64, |sum, source| {
        sum.checked_add(source.amount_sat)
            .ok_or_else(|| AppError::ClaimError("journaled recovery input amount overflow".into()))
    })?;
    let total_output_sat = tx.output.iter().try_fold(0u64, |sum, output| {
        sum.checked_add(output.value.to_sat())
            .ok_or_else(|| AppError::ClaimError("journaled recovery output amount overflow".into()))
    })?;
    let derived_fee_amount_sat =
        total_input_sat
            .checked_sub(total_output_sat)
            .ok_or_else(|| {
                AppError::ClaimError(
                    "journaled recovery transaction spends more than its recorded inputs".into(),
                )
            })?;
    if derived_fee_amount_sat == 0 {
        return Err(AppError::ClaimError(
            "journaled recovery transaction has a zero miner fee".into(),
        ));
    }
    let stored_fee_amount_sat = u64::try_from(stored_fee_amount_sat).map_err(|_| {
        AppError::ClaimError("journaled recovery fee amount is outside database range".into())
    })?;
    if stored_fee_amount_sat != derived_fee_amount_sat {
        return Err(AppError::ClaimError(
            "journaled recovery bytes do not match the committed fee amount".into(),
        ));
    }
    let final_vsize = tx.vsize();
    if final_vsize == 0 {
        return Err(AppError::ClaimError(
            "journaled recovery transaction has zero virtual size".into(),
        ));
    }
    let derived_fee_rate_sat_vb = derived_fee_amount_sat as f64 / final_vsize as f64;
    if stored_fee_rate_sat_vb.to_bits() != derived_fee_rate_sat_vb.to_bits() {
        return Err(AppError::ClaimError(
            "journaled recovery bytes do not match the committed fee rate".into(),
        ));
    }
    let final_vbytes = u64::try_from(final_vsize)
        .map_err(|_| AppError::ClaimError("journaled recovery virtual size exceeds u64".into()))?;
    fee_authority
        .validate_replayed_fee(derived_fee_amount_sat, final_vbytes)
        .map_err(|error| {
            AppError::ClaimError(format!(
                "invalid journaled Bitcoin recovery fee authority: {error}"
            ))
        })
}

enum EvidenceDecision {
    ExpectedObserved(String),
    Unspent,
    UnknownOutspend {
        source: RecoverySourcePrevout,
        spender: String,
    },
}

async fn reconcile_attempt_evidence(
    attempt: &ChainSwapTxAttempt,
    evidence: &dyn BitcoinRecoveryEvidence,
) -> Result<EvidenceDecision, AppError> {
    if evidence.raw_transaction(&attempt.txid).await?.is_some() {
        return Ok(EvidenceDecision::ExpectedObserved(
            "expected transaction observed by Bitcoin backend".into(),
        ));
    }

    for source in attempt.source_prevouts.0.iter() {
        match evidence.outspend(&source.txid, source.vout).await? {
            BitcoinOutspend::Unspent => {}
            BitcoinOutspend::Spent { txid } if txid.eq_ignore_ascii_case(&attempt.txid) => {
                return Ok(EvidenceDecision::ExpectedObserved(format!(
                    "source {}:{} spent by expected transaction",
                    source.txid, source.vout
                )));
            }
            BitcoinOutspend::Spent { txid } => {
                return Ok(EvidenceDecision::UnknownOutspend {
                    source: source.clone(),
                    spender: txid,
                });
            }
        }
    }
    Ok(EvidenceDecision::Unspent)
}

async fn reconcile_after_broadcast_error(
    pool: &sqlx::PgPool,
    attempt: &ChainSwapTxAttempt,
    started_token: &db::RecoveryAttemptStateToken,
    evidence: &dyn BitcoinRecoveryEvidence,
    error: AppError,
) -> Result<String, AppError> {
    let error_text = error.to_string();
    match reconcile_attempt_evidence(attempt, evidence).await {
        Ok(EvidenceDecision::ExpectedObserved(reason)) => {
            complete_expected_attempt(
                pool,
                attempt,
                &format!("{reason}; broadcaster: {error_text}"),
            )
            .await?;
            Ok(attempt.txid.clone())
        }
        Ok(EvidenceDecision::UnknownOutspend { source, spender }) => {
            let reason = format!(
                "source {}:{} spent by unexpected transaction {} after broadcast ambiguity",
                source.txid, source.vout, spender
            );
            let held = db::mark_recovery_integrity_hold(
                pool,
                attempt.chain_swap_id,
                attempt.id,
                &attempt.purpose,
                &attempt.txid,
                started_token,
                &reason,
            )
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
            if held != 1 {
                return Err(AppError::DbError(
                    "could not persist Bitcoin recovery integrity hold".into(),
                ));
            }
            tracing::error!(
                event = "chain_swap_recovery_integrity_hold",
                chain_swap_id = %attempt.chain_swap_id,
                expected_txid = %attempt.txid,
                source_txid = %source.txid,
                source_vout = source.vout,
                unexpected_spender = %spender,
                "Bitcoin recovery broadcast became ambiguous and the source has an unknown outspend; automation stopped"
            );
            Err(AppError::ClaimError(reason))
        }
        Ok(EvidenceDecision::Unspent) => {
            let result = format!("broadcast outcome ambiguous: {error_text}");
            db::mark_recovery_broadcast_ambiguous(pool, attempt.id, started_token, &result)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
            // Preserve the broadcaster's typed failure scope after the
            // ambiguity is durably recorded. Re-wrapping a backend outage as
            // ClaimError would let reconciler health report a false success.
            Err(error)
        }
        Err(evidence_error) => {
            let result = format!(
                "broadcast outcome ambiguous: {error_text}; evidence unavailable: {evidence_error}"
            );
            db::mark_recovery_broadcast_ambiguous(pool, attempt.id, started_token, &result)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
            // Evidence is now the strongest reason the outcome cannot be
            // resolved, so retain its typed backend failure for worker health.
            Err(evidence_error)
        }
    }
}

/// Automatic execution already performed its authoritative post-call recheck
/// while holding the shared swap lock. If that packet did not positively
/// explain the outcome, preserve the write-ahead ambiguity and propagate the
/// original typed error without consulting a public failover backend.
async fn preserve_authoritative_broadcast_ambiguity(
    pool: &sqlx::PgPool,
    attempt: &ChainSwapTxAttempt,
    started_token: &db::RecoveryAttemptStateToken,
    error: AppError,
) -> Result<String, AppError> {
    let result =
        format!("broadcast outcome ambiguous after authoritative primary recheck: {error}");
    let updated = db::mark_recovery_broadcast_ambiguous(pool, attempt.id, started_token, &result)
        .await
        .map_err(|database_error| AppError::DbError(database_error.to_string()))?;
    if updated != 1 {
        return Err(AppError::DbError(
            "could not preserve authoritative Bitcoin recovery ambiguity".into(),
        ));
    }
    Err(error)
}

async fn complete_expected_attempt(
    pool: &sqlx::PgPool,
    attempt: &ChainSwapTxAttempt,
    result: &str,
) -> Result<(), AppError> {
    db::complete_recovery_broadcast(
        pool,
        attempt.id,
        attempt.chain_swap_id,
        &attempt.txid,
        result,
    )
    .await
    .map_err(|e| AppError::DbError(e.to_string()))
}

/// Construct the signed Bitcoin recovery transaction.  No broadcast happens
/// here; the caller validates and commits the result before execution.
async fn construct_live_refund(
    state: &AppState,
    swap: &ChainSwapRecord,
    refund_address: &str,
    fee_decision: BitcoinBuilderFeeDecision,
    path: AutomaticFallbackConstructionPath,
) -> Result<BtcLikeTransaction, AppError> {
    if path == AutomaticFallbackConstructionPath::Cooperative {
        // Cooperative construction is a provider-mutating operation. It must
        // use the dedicated exact-source prepare/request/response journal and
        // may never enter boltz-client's address-wide one-shot helper.
        return Err(AppError::RecoveryNotAvailable(
            "cooperative recovery requires its durable signing operation".into(),
        ));
    }
    swap.verify_creation_response_integrity()
        .map_err(AppError::ClaimError)?;
    let refund_key_bytes = Zeroizing::new(
        hex::decode(&swap.refund_key_hex)
            .map_err(|e| AppError::ClaimError(format!("invalid chain refund key hex: {e}")))?,
    );
    let secp = Secp256k1::new();
    let refund_secret_key = bitcoin::secp256k1::SecretKey::from_slice(refund_key_bytes.as_slice())
        .map_err(|e| AppError::ClaimError(format!("invalid chain refund secret key: {e}")))?;
    let refund_keypair = Keypair::from_secret_key(&secp, &refund_secret_key);
    let refund_public_key = PublicKey::new(refund_keypair.public_key());

    let boltz_response: CreateChainResponse = serde_json::from_str(&swap.boltz_response_json)
        .map_err(|e| AppError::ClaimError(format!("invalid chain boltz response json: {e}")))?;
    let lockup_script = SwapScript::chain_from_swap_resp(
        Chain::Bitcoin(BitcoinChain::Bitcoin),
        Side::Lockup,
        boltz_response.lockup_details.clone(),
        refund_public_key,
    )
    .map_err(|e| AppError::ClaimError(format!("chain lockup script build failed: {e}")))?;

    let boltz_api = BoltzApiClientV2::new(
        state.config.boltz.api_url.clone(),
        Some(Duration::from_secs(15)),
    );
    let endpoints = state
        .bitcoin_recovery_backend
        .as_deref()
        .ok_or_else(|| {
            AppError::ElectrumError("Bitcoin recovery evidence client is unavailable".into())
        })?
        .endpoints();
    let mut errors = Vec::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        let bitcoin_client = EsploraBitcoinClient::new(BitcoinChain::Bitcoin, endpoint, 30);
        let chain_client = ChainClient::new().with_bitcoin(bitcoin_client);
        let params = SwapTransactionParams {
            keys: refund_keypair,
            output_address: refund_address.to_string(),
            fee: bitcoin_recovery_fee(fee_decision),
            swap_id: swap.boltz_swap_id.clone(),
            chain_client: &chain_client,
            boltz_client: &boltz_api,
            options: Some(TransactionOptions::default().with_cooperative(false)),
        };
        match lockup_script.construct_refund(params).await {
            Ok(tx) => return Ok(tx),
            Err(script_error) => {
                if index + 1 < endpoints.len() {
                    tracing::warn!(
                        event = "chain_swap_refund_construct_failover",
                        swap_id = %swap.boltz_swap_id,
                        endpoint = %endpoint,
                        "recovery construction failed; rotating Bitcoin backend without changing spend path"
                    );
                }
                errors.push(format!("{endpoint}: script={script_error}"));
            }
        }
    }
    Err(AppError::ElectrumError(format!(
        "construct chain recovery failed on all {} Bitcoin backend(s): {}",
        endpoints.len(),
        errors.join(" | ")
    )))
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use boltz_client::util::fees::Fee;

    use super::{
        automatic_action_for_path_evidence, automatic_existing_attempt_may_reconcile,
        bitcoin_recovery_fee, classify_authoritative_automatic_attempt,
        validate_automatic_cooperative_keypath_signature, validate_exact_primary_source_tuple,
        validate_reloaded_fee_intent, AuthoritativeAutomaticAttemptDecision,
        BitcoinRecoveryBackend, BitcoinRecoveryEvidence, BitcoinRecoveryTransactionStatus,
    };
    use crate::builder_fee::BitcoinBuilderFeeDecision;
    use crate::chain_swap_action::{
        BitcoinSourceEvidence, BitcoinTimeoutEvidence, ChainSwapAction, ChainSwapEvidence,
        CooperativeRecoveryEvidence, EvidenceQuality, LiquidLockEvidence, LiquidPathEvidence,
        MerchantTransactionEvidence, ProviderStatusEvidence, RecoveryDestinationEvidence,
        RenegotiationEvidence,
    };
    use crate::chain_swap_runtime_evidence::AutomaticFallbackConstructionPath;
    use crate::db::{BitcoinRecoveryFeeAuthority, RecoverySourcePrevout};
    use crate::fee_policy::{BitcoinFeePolicy, FeeProvenance, LiveBitcoin, SatPerVbyte};
    use axum::{
        extract::{Path, State},
        http::StatusCode,
        routing::get,
        Router,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    fn bitcoin_builder_fee(rate: f64) -> BitcoinBuilderFeeDecision {
        let observation = LiveBitcoin::new(
            SatPerVbyte::try_from(rate).unwrap(),
            1_000,
            FeeProvenance::new("recovery-test").unwrap(),
        );
        let decision = BitcoinFeePolicy::default()
            .decide_typed(Some(&observation), None, 1_000)
            .unwrap();
        BitcoinBuilderFeeDecision::from(&decision)
    }

    fn relative_fee_rate(fee: Fee) -> f64 {
        match fee {
            Fee::Relative(rate) => rate,
            Fee::Absolute(_) => panic!("recovery builder must use a sat/vByte decision"),
        }
    }

    fn replay_fee_fixture() -> (Transaction, Vec<RecoverySourcePrevout>, i64, f64) {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let fee_amount_sat = 1_000;
        let fee_rate_sat_vb = fee_amount_sat as f64 / tx.vsize() as f64;
        let sources = vec![RecoverySourcePrevout {
            txid: OutPoint::null().txid.to_string(),
            vout: 0,
            amount_sat: 10_000,
            script_pubkey_hex: String::new(),
        }];
        (tx, sources, fee_amount_sat, fee_rate_sat_vb)
    }

    fn cooperative_keypath_fixture() -> (Transaction, Vec<TxOut>) {
        use bitcoin::hashes::Hash as _;
        use bitcoin::sighash::{Prevouts, SighashCache};

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[42; 32]).unwrap();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        let (output_key, _) = keypair.x_only_public_key();
        let mut source_script = vec![0x51, 0x20];
        source_script.extend_from_slice(&output_key.serialize());
        let sources = vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(source_script),
        }];
        let mut transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let sighash = SighashCache::new(transaction.clone())
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&sources),
                bitcoin::TapSighashType::Default,
            )
            .unwrap();
        let message = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_schnorr(&message, &keypair);
        transaction.input[0].witness.push(signature.as_ref());
        (transaction, sources)
    }

    #[test]
    fn cooperative_keypath_witness_is_exact_and_rejects_path_drift() {
        let (transaction, sources) = cooperative_keypath_fixture();
        validate_automatic_cooperative_keypath_signature(&transaction, &sources).unwrap();

        let mut changed_signature = transaction.clone();
        let mut bytes = changed_signature.input[0].witness[0].to_vec();
        bytes[0] ^= 1;
        changed_signature.input[0].witness.clear();
        changed_signature.input[0].witness.push(bytes);
        assert!(
            validate_automatic_cooperative_keypath_signature(&changed_signature, &sources).is_err()
        );

        let mut unilateral_shape = transaction.clone();
        unilateral_shape.input[0].sequence = Sequence::ZERO;
        assert!(
            validate_automatic_cooperative_keypath_signature(&unilateral_shape, &sources).is_err()
        );

        let mut aggregated = transaction;
        aggregated.input.push(aggregated.input[0].clone());
        assert!(validate_automatic_cooperative_keypath_signature(&aggregated, &sources).is_err());
    }

    #[test]
    fn automatic_replay_rejects_same_outpoint_with_primary_amount_drift() {
        let script = format!("5120{}", "11".repeat(32));
        let journaled = RecoverySourcePrevout {
            txid: "22".repeat(32),
            vout: 3,
            amount_sat: 100_000,
            script_pubkey_hex: script.clone(),
        };
        validate_exact_primary_source_tuple(
            &journaled.txid,
            journaled.vout,
            journaled.amount_sat,
            &script,
            &journaled,
        )
        .unwrap();
        assert!(validate_exact_primary_source_tuple(
            &journaled.txid,
            journaled.vout,
            journaled.amount_sat - 1,
            &script,
            &journaled,
        )
        .is_err());
    }

    #[test]
    fn automatic_prebroadcast_rejects_same_outpoint_with_primary_script_drift() {
        let script = format!("5120{}", "ab".repeat(32));
        let journaled = RecoverySourcePrevout {
            txid: "22".repeat(32),
            vout: 3,
            amount_sat: 100_000,
            script_pubkey_hex: script.clone(),
        };
        let different_script = format!("5120{}", "33".repeat(32));
        assert!(validate_exact_primary_source_tuple(
            &journaled.txid,
            journaled.vout,
            journaled.amount_sat,
            &different_script,
            &journaled,
        )
        .is_err());
        assert!(validate_exact_primary_source_tuple(
            &journaled.txid,
            journaled.vout,
            journaled.amount_sat,
            &script.to_ascii_uppercase(),
            &journaled,
        )
        .is_err());
    }

    #[test]
    fn journaled_cooperative_bytes_survive_signer_loss_and_timeout() {
        let (transaction, sources) = cooperative_keypath_fixture();
        let raw = bitcoin::consensus::serialize(&transaction);
        let reloaded: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        assert_eq!(bitcoin::consensus::serialize(&reloaded), raw);
        validate_automatic_cooperative_keypath_signature(&reloaded, &sources).unwrap();

        let mut evidence = ChainSwapEvidence {
            quality: EvidenceQuality::CompleteAndAgreed,
            provider_status: ProviderStatusEvidence::Unknown,
            bitcoin_source: BitcoinSourceEvidence::ConfirmedUnspent,
            liquid_lock: LiquidLockEvidence::NotObserved,
            liquid_path: LiquidPathEvidence::Unavailable,
            renegotiation: RenegotiationEvidence::NotRequired,
            recovery_destination: RecoveryDestinationEvidence::Committed,
            // Model the signing endpoint becoming unavailable after the exact
            // cooperative transaction was journaled. Replay derives the
            // positive cooperative fact from the verified witness, not from a
            // second signing request.
            cooperative_recovery: CooperativeRecoveryEvidence::Unavailable,
            bitcoin_timeout: BitcoinTimeoutEvidence::BeforeTimeout,
            liquid_claim_transaction: MerchantTransactionEvidence::None,
            bitcoin_recovery_transaction: MerchantTransactionEvidence::Prepared,
        };
        assert_eq!(
            automatic_action_for_path_evidence(
                evidence,
                AutomaticFallbackConstructionPath::Cooperative,
            ),
            ChainSwapAction::RecoverBitcoin
        );

        // Reaching the unilateral timeout must not replace or reconstruct an
        // already-journaled cooperative transaction. The same exact bytes
        // remain the single authorized recovery intent.
        evidence.bitcoin_timeout = BitcoinTimeoutEvidence::Reached;
        assert_eq!(
            automatic_action_for_path_evidence(
                evidence,
                AutomaticFallbackConstructionPath::Cooperative,
            ),
            ChainSwapAction::RecoverBitcoin
        );
    }

    #[test]
    fn bitcoin_recovery_preserves_upstream_min_midrange_and_max_rates() {
        // Representative upstream policy boundary values. This construction
        // seam must not clamp or reinterpret the policy's selected rate.
        for rate in [1.0, 2.0, 500.0] {
            let decision = bitcoin_builder_fee(rate);
            assert_eq!(relative_fee_rate(bitcoin_recovery_fee(decision)), rate);
        }
    }

    #[test]
    fn automatic_restart_reconciles_only_an_exact_primary_observation() {
        assert!(automatic_existing_attempt_may_reconcile(
            AuthoritativeAutomaticAttemptDecision::ExpectedObserved
        ));
        assert!(automatic_existing_attempt_may_reconcile(
            AuthoritativeAutomaticAttemptDecision::IntegrityHold
        ));
        assert!(!automatic_existing_attempt_may_reconcile(
            AuthoritativeAutomaticAttemptDecision::Deferred
        ));
        assert_eq!(
            classify_authoritative_automatic_attempt(
                ChainSwapAction::WatchTransaction,
                BitcoinSourceEvidence::SpentByRecoveryTransaction,
                MerchantTransactionEvidence::Mempool,
            ),
            AuthoritativeAutomaticAttemptDecision::ExpectedObserved
        );
        assert_eq!(
            classify_authoritative_automatic_attempt(
                ChainSwapAction::Finalize,
                BitcoinSourceEvidence::SpentByRecoveryTransaction,
                MerchantTransactionEvidence::Finalized,
            ),
            AuthoritativeAutomaticAttemptDecision::ExpectedObserved
        );

        // A transaction status without the exact primary-source spend cannot
        // complete a restarted attempt, even if a public backend reported it.
        assert_eq!(
            classify_authoritative_automatic_attempt(
                ChainSwapAction::WatchTransaction,
                BitcoinSourceEvidence::ConfirmedUnspent,
                MerchantTransactionEvidence::Mempool,
            ),
            AuthoritativeAutomaticAttemptDecision::Deferred
        );
    }

    #[test]
    fn automatic_primary_decision_separates_broadcast_hold_and_defer() {
        assert_eq!(
            classify_authoritative_automatic_attempt(
                ChainSwapAction::RecoverBitcoin,
                BitcoinSourceEvidence::ConfirmedUnspent,
                MerchantTransactionEvidence::Prepared,
            ),
            AuthoritativeAutomaticAttemptDecision::Broadcast
        );
        assert_eq!(
            classify_authoritative_automatic_attempt(
                ChainSwapAction::IntegrityHold,
                BitcoinSourceEvidence::UnknownOutspend,
                MerchantTransactionEvidence::Disputed,
            ),
            AuthoritativeAutomaticAttemptDecision::IntegrityHold
        );
        assert_eq!(
            classify_authoritative_automatic_attempt(
                ChainSwapAction::Observe,
                BitcoinSourceEvidence::Unknown,
                MerchantTransactionEvidence::Prepared,
            ),
            AuthoritativeAutomaticAttemptDecision::Deferred
        );
    }

    #[derive(Clone)]
    struct MockEsploraState {
        tip: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
        status: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
        block: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl MockEsploraState {
        fn new(
            tip: impl IntoIterator<Item = (StatusCode, String)>,
            status: impl IntoIterator<Item = (StatusCode, String)>,
            block: impl IntoIterator<Item = (StatusCode, String)>,
        ) -> Self {
            Self {
                tip: Arc::new(Mutex::new(tip.into_iter().collect())),
                status: Arc::new(Mutex::new(status.into_iter().collect())),
                block: Arc::new(Mutex::new(block.into_iter().collect())),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    fn next_response(queue: &Mutex<VecDeque<(StatusCode, String)>>) -> (StatusCode, String) {
        queue
            .lock()
            .unwrap()
            .pop_front()
            .expect("mock Esplora response queue is complete")
    }

    async fn mock_tip(State(state): State<MockEsploraState>) -> (StatusCode, String) {
        state.calls.lock().unwrap().push("tip".into());
        next_response(&state.tip)
    }

    async fn mock_status(
        State(state): State<MockEsploraState>,
        Path(_txid): Path<String>,
    ) -> (StatusCode, String) {
        state.calls.lock().unwrap().push("status".into());
        next_response(&state.status)
    }

    async fn mock_block(
        State(state): State<MockEsploraState>,
        Path(height): Path<u32>,
    ) -> (StatusCode, String) {
        state.calls.lock().unwrap().push(format!("block:{height}"));
        next_response(&state.block)
    }

    async fn spawn_mock_esplora(state: MockEsploraState) -> String {
        let app = Router::new()
            .route("/blocks/tip/height", get(mock_tip))
            .route("/tx/:txid/status", get(mock_status))
            .route("/block-height/:height", get(mock_block))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Esplora");
        let address = listener.local_addr().expect("mock Esplora address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock Esplora");
        });
        format!("http://{address}")
    }

    fn confirmed_status(height: u32, hash: &str) -> String {
        format!(r#"{{"confirmed":true,"block_height":{height},"block_hash":"{hash}"}}"#)
    }

    #[test]
    fn legacy_replay_still_binds_raw_fee_amount_and_exact_rate() {
        let (tx, sources, fee_amount_sat, fee_rate_sat_vb) = replay_fee_fixture();
        validate_reloaded_fee_intent(
            &sources,
            &tx,
            fee_amount_sat,
            fee_rate_sat_vb,
            &BitcoinRecoveryFeeAuthority::Legacy,
        )
        .unwrap();

        assert!(validate_reloaded_fee_intent(
            &sources,
            &tx,
            fee_amount_sat - 1,
            fee_rate_sat_vb,
            &BitcoinRecoveryFeeAuthority::Legacy,
        )
        .is_err());
        assert!(validate_reloaded_fee_intent(
            &sources,
            &tx,
            fee_amount_sat,
            f64::from_bits(fee_rate_sat_vb.to_bits() + 1),
            &BitcoinRecoveryFeeAuthority::Legacy,
        )
        .is_err());
    }

    #[test]
    fn replay_fee_derivation_subtracts_every_output() {
        let (mut tx, sources, fee_amount_sat, _) = replay_fee_fixture();
        tx.output.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        });
        // Match the enlarged transaction's vsize while retaining the old fee
        // amount. An implementation that ignored the extra output would now
        // pass both stored fee checks; the correct all-output sum rejects it.
        let rate_if_extra_output_were_ignored = fee_amount_sat as f64 / tx.vsize() as f64;
        assert!(validate_reloaded_fee_intent(
            &sources,
            &tx,
            fee_amount_sat,
            rate_if_extra_output_were_ignored,
            &BitcoinRecoveryFeeAuthority::Legacy,
        )
        .is_err());
    }

    #[test]
    fn recovery_backend_requires_a_valid_http_endpoint() {
        assert!(BitcoinRecoveryBackend::try_new(Vec::new()).is_err());
        assert!(BitcoinRecoveryBackend::try_new(vec![
            "not-a-url".to_string(),
            "ftp://example.com/api".to_string(),
        ])
        .is_err());
    }

    #[test]
    fn recovery_backend_reuses_the_validated_endpoint_set() {
        let backend = BitcoinRecoveryBackend::try_new(vec![
            "invalid".to_string(),
            "https://mempool.bullbitcoin.com/api".to_string(),
            "http://127.0.0.1:3000".to_string(),
        ])
        .expect("valid recovery endpoints");

        assert_eq!(
            backend.endpoints(),
            [
                "https://mempool.bullbitcoin.com/api".to_string(),
                "http://127.0.0.1:3000".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn recovery_status_snapshot_anchors_one_endpoint_and_rechecks_status_and_tip() {
        let block_hash = "aa".repeat(32);
        let state = MockEsploraState::new(
            [
                (StatusCode::OK, "100".into()),
                (StatusCode::OK, "100".into()),
            ],
            [
                (StatusCode::OK, confirmed_status(99, &block_hash)),
                (StatusCode::OK, confirmed_status(99, &block_hash)),
            ],
            [(StatusCode::OK, block_hash.clone())],
        );
        let endpoint = spawn_mock_esplora(state.clone()).await;
        let backend = BitcoinRecoveryBackend::try_new(vec![endpoint]).unwrap();
        let txid = "11".repeat(32);

        let snapshot = backend.status_snapshot(&txid, Some(99)).await.unwrap();

        assert_eq!(snapshot.tip_height, 100);
        assert_eq!(snapshot.prior_block_hash, Some(block_hash.clone()));
        assert_eq!(
            snapshot.status,
            BitcoinRecoveryTransactionStatus::Confirmed {
                block_height: 99,
                block_hash,
            }
        );
        assert_eq!(
            state.calls.lock().unwrap().as_slice(),
            ["tip", "status", "block:99", "status", "tip"]
        );
    }

    #[tokio::test]
    async fn recovery_status_snapshot_rejects_block_mismatch_and_toctou() {
        let claimed_hash = "aa".repeat(32);
        let anchored_hash = "bb".repeat(32);
        let mismatch = MockEsploraState::new(
            [(StatusCode::OK, "100".into())],
            [(StatusCode::OK, confirmed_status(99, &claimed_hash))],
            [(StatusCode::OK, anchored_hash)],
        );
        let mismatch_backend =
            BitcoinRecoveryBackend::try_new(vec![spawn_mock_esplora(mismatch.clone()).await])
                .unwrap();
        assert!(mismatch_backend
            .status_snapshot(&"22".repeat(32), None)
            .await
            .is_err());
        assert_eq!(
            mismatch.calls.lock().unwrap().as_slice(),
            ["tip", "status", "block:99"]
        );

        let toctou = MockEsploraState::new(
            [(StatusCode::OK, "100".into())],
            [
                (StatusCode::OK, r#"{"confirmed":false}"#.into()),
                (StatusCode::OK, confirmed_status(100, &claimed_hash)),
            ],
            [],
        );
        let toctou_backend =
            BitcoinRecoveryBackend::try_new(vec![spawn_mock_esplora(toctou.clone()).await])
                .unwrap();
        assert!(toctou_backend
            .status_snapshot(&"33".repeat(32), None)
            .await
            .is_err());
        assert_eq!(
            toctou.calls.lock().unwrap().as_slice(),
            ["tip", "status", "status"]
        );
    }

    #[tokio::test]
    async fn recovery_status_snapshot_requires_all_endpoints_for_positive_absence() {
        let absent_a = MockEsploraState::new(
            [
                (StatusCode::OK, "100".into()),
                (StatusCode::OK, "100".into()),
            ],
            [
                (StatusCode::NOT_FOUND, String::new()),
                (StatusCode::NOT_FOUND, String::new()),
            ],
            [],
        );
        let absent_b = MockEsploraState::new(
            [
                (StatusCode::OK, "100".into()),
                (StatusCode::OK, "100".into()),
            ],
            [
                (StatusCode::NOT_FOUND, String::new()),
                (StatusCode::NOT_FOUND, String::new()),
            ],
            [],
        );
        let endpoints = vec![
            spawn_mock_esplora(absent_a).await,
            spawn_mock_esplora(absent_b).await,
        ];
        let backend = BitcoinRecoveryBackend::try_new(endpoints).unwrap();
        let snapshot = backend
            .status_snapshot(&"44".repeat(32), None)
            .await
            .unwrap();
        assert_eq!(snapshot.status, BitcoinRecoveryTransactionStatus::Absent);

        let absent = MockEsploraState::new(
            [
                (StatusCode::OK, "100".into()),
                (StatusCode::OK, "100".into()),
            ],
            [
                (StatusCode::NOT_FOUND, String::new()),
                (StatusCode::NOT_FOUND, String::new()),
            ],
            [],
        );
        let uncertain = MockEsploraState::new(
            [(StatusCode::OK, "100".into())],
            [(StatusCode::SERVICE_UNAVAILABLE, "unavailable".into())],
            [],
        );
        let backend = BitcoinRecoveryBackend::try_new(vec![
            spawn_mock_esplora(absent).await,
            spawn_mock_esplora(uncertain).await,
        ])
        .unwrap();
        assert!(backend
            .status_snapshot(&"55".repeat(32), None)
            .await
            .is_err());
    }
}

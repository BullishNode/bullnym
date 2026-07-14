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
use bitcoin::{Address, Network, Transaction};
use boltz_client::network::esplora::EsploraBitcoinClient;
use boltz_client::network::{BitcoinChain, Chain};
use boltz_client::swaps::boltz::{BoltzApiClientV2, CreateChainResponse, Side};
use boltz_client::swaps::{
    BtcLikeTransaction, ChainClient, SwapScript, SwapTransactionParams, TransactionOptions,
};
use boltz_client::util::fees::Fee;
use boltz_client::{Keypair, PublicKey, Secp256k1};
use serde::Deserialize;
use uuid::Uuid;

use crate::builder_fee::BitcoinBuilderFeeDecision;
use crate::db::{
    self, ChainSwapRecord, ChainSwapStatus, ChainSwapTxAttempt, NewBitcoinRecoveryAttempt,
    RecoverySourcePrevout,
};
use crate::error::AppError;
use crate::fee_decision_record::{FeeConstructionPurpose, FeeDecisionRecord};
use crate::fee_policy::{BitcoinFeeDecision, BitcoinFeePolicy, FeeFreshness};
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
        construct_live_refund(self.state, swap, destination_address, fee_decision).await
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

#[async_trait]
impl BitcoinRecoveryBroadcaster for EsploraRecoveryBroadcaster {
    async fn broadcast(&self, raw_tx_hex: &str, expected_txid: &str) -> Result<String, AppError> {
        crate::esplora::broadcast(&self.endpoints, raw_tx_hex, expected_txid).await
    }
}

/// Production entry after the caller's Boltz-status and lockup-confirmation
/// gates.  The public dependency-taking variant below is intentionally narrow
/// so DB integration tests can deterministically model crash and response-loss
/// boundaries without a live Boltz or Bitcoin node.
pub(crate) async fn execute_journaled_recovery(
    state: &AppState,
    chain_swap_id: Uuid,
) -> Result<String, AppError> {
    let evidence = state.bitcoin_recovery_backend.as_deref().ok_or_else(|| {
        AppError::ElectrumError("Bitcoin recovery evidence client is unavailable".into())
    })?;
    let endpoints = evidence.endpoints().to_vec();
    let builder = LiveRecoveryBuilder { state };
    let broadcaster = EsploraRecoveryBroadcaster { endpoints };
    // A missing current decision is passed through deliberately: an existing
    // journal replays without it, while a new attempt remains pending.
    let fee_decision = state
        .fee_runtime
        .bitcoin_construction_decision_now(FeeConstructionPurpose::BitcoinRecovery)
        .ok();
    let construction_fee = match fee_decision.as_ref() {
        Some((decision, record)) => RecoveryConstructionFee::new(decision, record),
        None => RecoveryConstructionFee::unavailable(),
    };
    execute_journaled_recovery_with_builder_fee(
        &state.db,
        chain_swap_id,
        &builder,
        construction_fee,
        evidence,
        &broadcaster,
        &NoRecoveryFaults,
    )
    .await
}

/// Testable write-ahead executor.  This is public only to let the external DB
/// integration target supply deterministic boundary fakes; normal application
/// code calls [`execute_journaled_recovery`]. `fee_decision` applies only when
/// no journaled attempt exists; retries always reuse the committed bytes and
/// their immutable actual-fee evidence.
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
        evidence,
        broadcaster,
        faults,
    )
    .await
}

struct RecoveryConstructionFee<'a> {
    builder_decision: Option<BitcoinBuilderFeeDecision>,
    record: Option<&'a FeeDecisionRecord>,
    compatibility_record: Option<Result<FeeDecisionRecord, AppError>>,
}

impl<'a> RecoveryConstructionFee<'a> {
    fn new(decision: &BitcoinFeeDecision, record: &'a FeeDecisionRecord) -> Self {
        Self {
            builder_decision: Some(BitcoinBuilderFeeDecision::from(decision)),
            record: Some(record),
            compatibility_record: None,
        }
    }

    fn compatibility(decision: Option<&BitcoinFeeDecision>) -> Self {
        Self {
            builder_decision: decision.map(BitcoinBuilderFeeDecision::from),
            record: None,
            // Capture the monotonic authority before any pool/lock wait, but
            // defer an unusable-record error until the core proves that no
            // committed bytes exist to replay.
            compatibility_record: decision.map(bitcoin_fee_record_for_compatibility_seam),
        }
    }

    const fn unavailable() -> Self {
        Self {
            builder_decision: None,
            record: None,
            compatibility_record: None,
        }
    }
}

async fn execute_journaled_recovery_with_builder_fee(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    builder: &dyn BitcoinRecoveryBuilder,
    construction_fee: RecoveryConstructionFee<'_>,
    evidence: &dyn BitcoinRecoveryEvidence,
    broadcaster: &dyn BitcoinRecoveryBroadcaster,
    faults: &dyn RecoveryFaultInjector,
) -> Result<String, AppError> {
    prepare_or_reload_attempt(
        pool,
        chain_swap_id,
        builder,
        construction_fee,
        evidence,
        faults,
    )
    .await?;

    faults.check(RecoveryFaultPoint::AfterJournalCommitBeforeBroadcast)?;

    // Broadcast only bytes reloaded after the journal transaction committed.
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
                "Bitcoin recovery source has an unknown outspend; automation stopped"
            );
            return Err(AppError::ClaimError(reason));
        }
    }

    let started_token = attempt
        .state_token_after_broadcast_started()
        .ok_or_else(|| {
            AppError::DbError(
                "recovery attempt cannot produce a durable broadcast-start token".into(),
            )
        })?;
    let started = db::mark_recovery_broadcast_started(pool, attempt.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if started != 1 {
        return Err(AppError::ClaimError(format!(
            "recovery attempt {} is not broadcastable (status {})",
            attempt.id, attempt.status
        )));
    }
    faults.check(RecoveryFaultPoint::AfterBroadcastAttemptCommit)?;

    let broadcast_result = broadcaster
        .broadcast(&attempt.raw_tx_hex, &attempt.txid)
        .await;
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
            reconcile_after_broadcast_error(
                pool,
                &attempt,
                &started_token,
                evidence,
                AppError::ClaimError(error),
            )
            .await
        }
        Err(error) => {
            reconcile_after_broadcast_error(pool, &attempt, &started_token, evidence, error).await
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

    if let Some(attempt) = existing {
        // Validate the immutable bytes and their construction-time authority
        // before repairing any parent lifecycle state.
        validate_reloaded_attempt(&attempt)?;
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
    let destination = swap.refund_address.clone().ok_or_else(|| {
        AppError::ClaimError("chain swap recovery has no committed destination".into())
    })?;
    // Compatibility authority was captured before the pool/lock wait, but its
    // result is deliberately inspected only after the existing-journal branch:
    // replay never consults new-construction authority.
    let compatibility_record = construction_fee.compatibility_record.transpose()?;
    let fee_decision = construction_fee.builder_decision.ok_or_else(|| {
        AppError::RecoveryNotAvailable(BITCOIN_FEE_DECISION_PENDING_REASON.into())
    })?;
    let fee_record = construction_fee
        .record
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
    let transaction = builder.construct(&swap, &destination, fee_decision).await?;
    let prepared =
        validate_constructed_attempt(&swap, &destination, &transaction, fee_record, evidence)
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

async fn validate_constructed_attempt(
    swap: &ChainSwapRecord,
    destination: &str,
    transaction: &BtcLikeTransaction,
    fee_record: &FeeDecisionRecord,
    evidence: &dyn BitcoinRecoveryEvidence,
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
            db::mark_recovery_broadcast_ambiguous(pool, attempt.id, &result)
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
            db::mark_recovery_broadcast_ambiguous(pool, attempt.id, &result)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
            // Evidence is now the strongest reason the outcome cannot be
            // resolved, so retain its typed backend failure for worker health.
            Err(evidence_error)
        }
    }
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
) -> Result<BtcLikeTransaction, AppError> {
    swap.verify_creation_response_integrity()
        .map_err(AppError::ClaimError)?;
    let refund_key_bytes = hex::decode(&swap.refund_key_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid chain refund key hex: {e}")))?;
    let secp = Secp256k1::new();
    let refund_secret_key = bitcoin::secp256k1::SecretKey::from_slice(&refund_key_bytes)
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
        let build = |cooperative: bool| {
            let params = SwapTransactionParams {
                keys: refund_keypair,
                output_address: refund_address.to_string(),
                fee: bitcoin_recovery_fee(fee_decision),
                swap_id: swap.boltz_swap_id.clone(),
                chain_client: &chain_client,
                boltz_client: &boltz_api,
                options: Some(TransactionOptions::default().with_cooperative(cooperative)),
            };
            lockup_script.construct_refund(params)
        };

        match build(true).await {
            Ok(tx) => return Ok(tx),
            Err(cooperative_error) => {
                tracing::warn!(
                    event = "chain_swap_refund_cooperative_failed",
                    swap_id = %swap.boltz_swap_id,
                    endpoint = %endpoint,
                    error = %cooperative_error,
                    "cooperative recovery construction failed; trying script path"
                );
                match build(false).await {
                    Ok(tx) => return Ok(tx),
                    Err(script_error) => {
                        if index + 1 < endpoints.len() {
                            tracing::warn!(
                                event = "chain_swap_refund_construct_failover",
                                swap_id = %swap.boltz_swap_id,
                                endpoint = %endpoint,
                                "recovery construction failed; rotating Bitcoin backend"
                            );
                        }
                        errors.push(format!(
                            "{endpoint}: cooperative={cooperative_error}; script={script_error}"
                        ));
                    }
                }
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
        bitcoin_recovery_fee, validate_reloaded_fee_intent, BitcoinRecoveryBackend,
        BitcoinRecoveryEvidence, BitcoinRecoveryTransactionStatus,
    };
    use crate::builder_fee::BitcoinBuilderFeeDecision;
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

    #[test]
    fn bitcoin_recovery_preserves_upstream_min_midrange_and_max_rates() {
        // Representative upstream policy boundary values. This construction
        // seam must not clamp or reinterpret the policy's selected rate.
        for rate in [1.0, 2.0, 500.0] {
            let decision = bitcoin_builder_fee(rate);
            assert_eq!(relative_fee_rate(bitcoin_recovery_fee(decision)), rate);
        }
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

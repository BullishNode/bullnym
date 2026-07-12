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

use crate::db::{
    self, ChainSwapRecord, ChainSwapStatus, ChainSwapTxAttempt, NewBitcoinRecoveryAttempt,
    RecoverySourcePrevout,
};
use crate::error::AppError;
use crate::AppState;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

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
    async fn construct(
        &self,
        swap: &ChainSwapRecord,
        destination_address: &str,
    ) -> Result<BtcLikeTransaction, AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcoinOutspend {
    Unspent,
    Spent { txid: String },
}

#[async_trait]
pub trait BitcoinRecoveryEvidence: Send + Sync {
    /// Return exact raw bytes, `None` only when all configured backends
    /// positively report the tx absent, and `Err` when presence is unknown.
    /// Cross-provider agreement policy is added by the #82 evidence reducer.
    async fn raw_transaction(&self, txid: &str) -> Result<Option<Vec<u8>>, AppError>;

    async fn outspend(&self, txid: &str, vout: u32) -> Result<BitcoinOutspend, AppError>;
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
    ) -> Result<BtcLikeTransaction, AppError> {
        construct_live_refund(self.state, swap, destination_address).await
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
    execute_journaled_recovery_with_services(
        &state.db,
        chain_swap_id,
        &builder,
        evidence,
        &broadcaster,
        &NoRecoveryFaults,
    )
    .await
}

/// Testable write-ahead executor.  This is public only to let the external DB
/// integration target supply deterministic boundary fakes; normal application
/// code calls [`execute_journaled_recovery`].
#[doc(hidden)]
pub async fn execute_journaled_recovery_with_services(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    builder: &dyn BitcoinRecoveryBuilder,
    evidence: &dyn BitcoinRecoveryEvidence,
    broadcaster: &dyn BitcoinRecoveryBroadcaster,
    faults: &dyn RecoveryFaultInjector,
) -> Result<String, AppError> {
    prepare_or_reload_attempt(pool, chain_swap_id, builder, evidence, faults).await?;

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
            let held = db::mark_recovery_integrity_hold(pool, attempt.id, &reason)
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
            reconcile_after_broadcast_error(pool, &attempt, evidence, AppError::ClaimError(error))
                .await
        }
        Err(error) => reconcile_after_broadcast_error(pool, &attempt, evidence, error).await,
    }
}

async fn prepare_or_reload_attempt(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    builder: &dyn BitcoinRecoveryBuilder,
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

    faults.check(RecoveryFaultPoint::BeforeConstruction)?;
    let transaction = builder.construct(&swap, &destination).await?;
    let prepared =
        validate_constructed_attempt(&swap, &destination, &transaction, evidence).await?;
    faults.check(RecoveryFaultPoint::AfterConstructionBeforeJournal)?;

    let new_attempt = prepared.as_new(swap.id);
    let attempt = db::insert_bitcoin_recovery_attempt(&mut tx, &new_attempt)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    let rows = db::mark_chain_swap_refunding(&mut *tx, chain_swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if rows != 1 {
        return Err(AppError::ClaimError(
            "recovery race lost before the journal committed".into(),
        ));
    }

    faults.check(RecoveryFaultPoint::AfterJournalWriteBeforeCommit)?;
    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    Ok(attempt)
}

async fn validate_constructed_attempt(
    swap: &ChainSwapRecord,
    destination: &str,
    transaction: &BtcLikeTransaction,
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
    fn as_new(&self, chain_swap_id: Uuid) -> NewBitcoinRecoveryAttempt<'_> {
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
        }
    }
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
    let output = tx
        .output
        .get(attempt.destination_vout as usize)
        .ok_or_else(|| AppError::ClaimError("journaled recovery output is missing".into()))?;
    if hex::encode(output.script_pubkey.as_bytes()) != attempt.destination_script_hex
        || output.value.to_sat() as i64 != attempt.destination_amount_sat
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
    Ok(())
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
            let held = db::mark_recovery_integrity_hold(pool, attempt.id, &reason)
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
) -> Result<BtcLikeTransaction, AppError> {
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
                // Issue #64 replaces this legacy value with the persisted live
                // priority quote.  #62 records the actual resulting fee and
                // never rebuilds already-journaled bytes when policy changes.
                fee: Fee::Relative(2.0),
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
    use super::BitcoinRecoveryBackend;

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
}

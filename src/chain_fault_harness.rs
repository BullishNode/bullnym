//! Deterministic chain-boundary fakes for crash and convergence tests.
//!
//! These types implement the same narrow interfaces as the live Bitcoin and
//! Liquid backends. They are deliberately not a chain simulator: each call
//! either consumes one explicit step or reads the small Bitcoin observation
//! set installed by the test. Production never constructs these types.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use async_trait::async_trait;
use bitcoin::consensus::deserialize;
use lwk_wollet::elements;
use sha2::{Digest, Sha256};

use crate::chain_recovery::{
    BitcoinOutspend, BitcoinRecoveryBroadcaster, BitcoinRecoveryEvidence,
    BitcoinRecoveryStatusSnapshot,
};
use crate::error::AppError;
use crate::utxo::{
    LiquidHistorySnapshotLimits, LiquidHistorySnapshotOutcome, LiquidScriptHistory, UtxoBackend,
};

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Finite errors for chain scripts. No endpoint, credential, or arbitrary
/// provider text can be smuggled into logs through a fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptedChainError {
    BackendUnavailable,
    NotFound,
    InvalidEvidence,
}

impl ScriptedChainError {
    fn into_app_error(self, boundary: &'static str) -> AppError {
        match self {
            Self::BackendUnavailable => {
                AppError::ElectrumError(format!("scripted {boundary} backend unavailable"))
            }
            Self::NotFound => AppError::UtxoNotFound,
            Self::InvalidEvidence => {
                AppError::ElectrumError(format!("scripted {boundary} evidence is invalid"))
            }
        }
    }
}

/// Optional ordered overrides for the Bitcoin recovery evidence boundary.
/// When the queue is empty, raw-transaction and outspend reads use the small
/// state installed through [`ScriptedBitcoinRecoveryBackend::insert_raw_transaction`]
/// and [`ScriptedBitcoinRecoveryBackend::set_outspend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedBitcoinEvidenceStep {
    RawTransaction {
        txid: String,
        result: Result<Option<Vec<u8>>, ScriptedChainError>,
    },
    Outspend {
        txid: String,
        vout: u32,
        result: Result<BitcoinOutspend, ScriptedChainError>,
    },
    StatusSnapshot {
        txid: String,
        prior_block_height: Option<u32>,
        result: Result<BitcoinRecoveryStatusSnapshot, ScriptedChainError>,
    },
}

impl ScriptedBitcoinEvidenceStep {
    fn kind(&self) -> &'static str {
        match self {
            Self::RawTransaction { .. } => "raw_transaction",
            Self::Outspend { .. } => "outspend",
            Self::StatusSnapshot { .. } => "status_snapshot",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedBitcoinEvidenceCall {
    RawTransaction {
        txid: String,
    },
    Outspend {
        txid: String,
        vout: u32,
    },
    StatusSnapshot {
        txid: String,
        prior_block_height: Option<u32>,
    },
}

/// Shared Bitcoin evidence fake. A scripted broadcaster can publish accepted
/// bytes into the same instance before returning a lost-response error, so the
/// real executor must recover solely from its ordinary evidence probes.
#[derive(Default)]
pub struct ScriptedBitcoinRecoveryBackend {
    steps: Mutex<VecDeque<ScriptedBitcoinEvidenceStep>>,
    calls: Mutex<Vec<ScriptedBitcoinEvidenceCall>>,
    transactions: Mutex<HashMap<String, Vec<u8>>>,
    outspends: Mutex<HashMap<(String, u32), BitcoinOutspend>>,
    statuses: Mutex<HashMap<String, BitcoinRecoveryStatusSnapshot>>,
}

impl ScriptedBitcoinRecoveryBackend {
    pub fn new(steps: impl IntoIterator<Item = ScriptedBitcoinEvidenceStep>) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
            ..Self::default()
        }
    }

    pub fn calls(&self) -> Vec<ScriptedBitcoinEvidenceCall> {
        lock(&self.calls).clone()
    }

    pub fn remaining_steps(&self) -> usize {
        lock(&self.steps).len()
    }

    pub fn insert_raw_transaction(
        &self,
        txid: impl Into<String>,
        raw_transaction: Vec<u8>,
    ) -> Result<(), AppError> {
        let txid = txid.into();
        let transaction: bitcoin::Transaction = deserialize(&raw_transaction).map_err(|_| {
            AppError::ClaimError("scripted Bitcoin transaction bytes are invalid".into())
        })?;
        if transaction.compute_txid().to_string() != txid {
            return Err(AppError::ClaimError(
                "scripted Bitcoin transaction bytes do not match their txid".into(),
            ));
        }
        lock(&self.transactions).insert(txid, raw_transaction);
        Ok(())
    }

    pub fn remove_raw_transaction(&self, txid: &str) {
        lock(&self.transactions).remove(txid);
    }

    pub fn set_outspend(&self, txid: impl Into<String>, vout: u32, outspend: BitcoinOutspend) {
        lock(&self.outspends).insert((txid.into(), vout), outspend);
    }

    pub fn set_status_snapshot(
        &self,
        txid: impl Into<String>,
        status: BitcoinRecoveryStatusSnapshot,
    ) {
        lock(&self.statuses).insert(txid.into(), status);
    }

    fn record(&self, call: ScriptedBitcoinEvidenceCall) {
        lock(&self.calls).push(call);
    }

    fn next_override(
        &self,
        expected: &'static str,
    ) -> Result<Option<ScriptedBitcoinEvidenceStep>, AppError> {
        let Some(step) = lock(&self.steps).pop_front() else {
            return Ok(None);
        };
        if step.kind() != expected {
            return Err(AppError::ElectrumError(format!(
                "scripted Bitcoin evidence expected {expected}, found {}",
                step.kind()
            )));
        }
        Ok(Some(step))
    }
}

#[async_trait]
impl BitcoinRecoveryEvidence for ScriptedBitcoinRecoveryBackend {
    async fn raw_transaction(&self, txid: &str) -> Result<Option<Vec<u8>>, AppError> {
        self.record(ScriptedBitcoinEvidenceCall::RawTransaction {
            txid: txid.to_owned(),
        });
        if let Some(ScriptedBitcoinEvidenceStep::RawTransaction {
            txid: expected,
            result,
        }) = self.next_override("raw_transaction")?
        {
            if expected != txid {
                return Err(AppError::ElectrumError(
                    "scripted Bitcoin raw-transaction request mismatch".into(),
                ));
            }
            return result.map_err(|error| error.into_app_error("Bitcoin raw transaction"));
        }
        Ok(lock(&self.transactions).get(txid).cloned())
    }

    async fn outspend(&self, txid: &str, vout: u32) -> Result<BitcoinOutspend, AppError> {
        self.record(ScriptedBitcoinEvidenceCall::Outspend {
            txid: txid.to_owned(),
            vout,
        });
        if let Some(ScriptedBitcoinEvidenceStep::Outspend {
            txid: expected,
            vout: expected_vout,
            result,
        }) = self.next_override("outspend")?
        {
            if expected != txid || expected_vout != vout {
                return Err(AppError::ElectrumError(
                    "scripted Bitcoin outspend request mismatch".into(),
                ));
            }
            return result.map_err(|error| error.into_app_error("Bitcoin outspend"));
        }
        Ok(lock(&self.outspends)
            .get(&(txid.to_owned(), vout))
            .cloned()
            .unwrap_or(BitcoinOutspend::Unspent))
    }

    async fn status_snapshot(
        &self,
        txid: &str,
        prior_block_height: Option<u32>,
    ) -> Result<BitcoinRecoveryStatusSnapshot, AppError> {
        self.record(ScriptedBitcoinEvidenceCall::StatusSnapshot {
            txid: txid.to_owned(),
            prior_block_height,
        });
        if let Some(ScriptedBitcoinEvidenceStep::StatusSnapshot {
            txid: expected,
            prior_block_height: expected_height,
            result,
        }) = self.next_override("status_snapshot")?
        {
            if expected != txid || expected_height != prior_block_height {
                return Err(AppError::ElectrumError(
                    "scripted Bitcoin status-snapshot request mismatch".into(),
                ));
            }
            return result.map_err(|error| error.into_app_error("Bitcoin status snapshot"));
        }
        lock(&self.statuses).get(txid).cloned().ok_or_else(|| {
            AppError::ElectrumError("scripted Bitcoin status snapshot is unavailable".into())
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptedBitcoinBroadcastOutcome {
    Accept,
    AcceptResponseLost,
    BackendUnavailable,
    Reject,
    WrongTxid,
}

/// Exact-byte Bitcoin broadcaster script. Accepted outcomes update the shared
/// evidence backend before returning, including the response-loss outcome.
pub struct ScriptedBitcoinRecoveryBroadcaster {
    chain: std::sync::Arc<ScriptedBitcoinRecoveryBackend>,
    source: (String, u32),
    outcomes: Mutex<VecDeque<ScriptedBitcoinBroadcastOutcome>>,
    calls: Mutex<Vec<String>>,
}

impl ScriptedBitcoinRecoveryBroadcaster {
    pub fn new(
        chain: std::sync::Arc<ScriptedBitcoinRecoveryBackend>,
        source: (String, u32),
        outcomes: impl IntoIterator<Item = ScriptedBitcoinBroadcastOutcome>,
    ) -> Self {
        Self {
            chain,
            source,
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<String> {
        lock(&self.calls).clone()
    }

    pub fn remaining_outcomes(&self) -> usize {
        lock(&self.outcomes).len()
    }

    fn accept(&self, raw_tx_hex: &str, expected_txid: &str) -> Result<(), AppError> {
        let raw_transaction = hex::decode(raw_tx_hex).map_err(|_| {
            AppError::ClaimError("scripted Bitcoin broadcaster received invalid hex".into())
        })?;
        self.chain
            .insert_raw_transaction(expected_txid, raw_transaction)?;
        self.chain.set_outspend(
            self.source.0.clone(),
            self.source.1,
            BitcoinOutspend::Spent {
                txid: expected_txid.to_owned(),
            },
        );
        Ok(())
    }
}

#[async_trait]
impl BitcoinRecoveryBroadcaster for ScriptedBitcoinRecoveryBroadcaster {
    async fn broadcast(&self, raw_tx_hex: &str, expected_txid: &str) -> Result<String, AppError> {
        lock(&self.calls).push(raw_tx_hex.to_owned());
        let outcome = lock(&self.outcomes).pop_front().ok_or_else(|| {
            AppError::ClaimError("scripted Bitcoin broadcast outcomes exhausted".into())
        })?;
        match outcome {
            ScriptedBitcoinBroadcastOutcome::Accept => {
                self.accept(raw_tx_hex, expected_txid)?;
                Ok(expected_txid.to_owned())
            }
            ScriptedBitcoinBroadcastOutcome::AcceptResponseLost => {
                self.accept(raw_tx_hex, expected_txid)?;
                Err(AppError::ClaimError(
                    "scripted broadcaster accepted the transaction but lost the response".into(),
                ))
            }
            ScriptedBitcoinBroadcastOutcome::BackendUnavailable => Err(AppError::ElectrumError(
                "scripted Bitcoin broadcast backend unavailable".into(),
            )),
            ScriptedBitcoinBroadcastOutcome::Reject => Err(AppError::ClaimError(
                "scripted broadcaster rejected the transaction".into(),
            )),
            ScriptedBitcoinBroadcastOutcome::WrongTxid => Ok("ab".repeat(32)),
        }
    }
}

/// Ordered calls supported by the real [`UtxoBackend`] boundary. Successive
/// snapshots can describe mempool admission, eviction, confirmation, and
/// reorgs; separate instances represent independent authorities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedLiquidBackendStep {
    HealthCheck(Result<(), ScriptedChainError>),
    RawTransaction {
        txid: String,
        result: Result<Vec<u8>, ScriptedChainError>,
    },
    IsUnspent {
        txid: String,
        vout: u32,
        result: Result<bool, ScriptedChainError>,
    },
    ScriptHistory(Result<LiquidScriptHistory, ScriptedChainError>),
    HistoryTxids(Result<Vec<String>, ScriptedChainError>),
    LiquidHistorySnapshot(Box<Result<LiquidHistorySnapshotOutcome, ScriptedChainError>>),
    AutomaticFallbackLiquidHistorySnapshot(
        Box<Result<LiquidHistorySnapshotOutcome, ScriptedChainError>>,
    ),
    FindSpendingTxid {
        txid: String,
        vout: u32,
        result: Result<Option<String>, ScriptedChainError>,
    },
    TxExists {
        txid: String,
        result: Result<bool, ScriptedChainError>,
    },
}

impl ScriptedLiquidBackendStep {
    fn kind(&self) -> &'static str {
        match self {
            Self::HealthCheck(_) => "health_check",
            Self::RawTransaction { .. } => "get_raw_tx",
            Self::IsUnspent { .. } => "is_unspent",
            Self::ScriptHistory(_) => "script_history",
            Self::HistoryTxids(_) => "history_txids",
            Self::LiquidHistorySnapshot(_) => "liquid_history_snapshot",
            Self::AutomaticFallbackLiquidHistorySnapshot(_) => {
                "automatic_fallback_liquid_history_snapshot"
            }
            Self::FindSpendingTxid { .. } => "find_spending_txid",
            Self::TxExists { .. } => "tx_exists",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedLiquidBackendCall {
    HealthCheck,
    RawTransaction {
        txid: String,
    },
    IsUnspent {
        script_sha256: String,
        txid: String,
        vout: u32,
    },
    ScriptHistory {
        script_sha256: String,
    },
    HistoryTxids {
        script_sha256: String,
    },
    LiquidHistorySnapshot {
        script_sha256: String,
        prior_block_heights: Vec<i32>,
        limits: LiquidHistorySnapshotLimits,
    },
    AutomaticFallbackLiquidHistorySnapshot {
        script_sha256: String,
        prior_block_heights: Vec<i32>,
        limits: LiquidHistorySnapshotLimits,
    },
    FindSpendingTxid {
        script_sha256: String,
        txid: String,
        vout: u32,
    },
    TxExists {
        txid: String,
    },
}

pub struct ScriptedLiquidBackend {
    steps: Mutex<VecDeque<ScriptedLiquidBackendStep>>,
    calls: Mutex<Vec<ScriptedLiquidBackendCall>>,
}

impl ScriptedLiquidBackend {
    pub fn new(steps: impl IntoIterator<Item = ScriptedLiquidBackendStep>) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<ScriptedLiquidBackendCall> {
        lock(&self.calls).clone()
    }

    pub fn remaining_steps(&self) -> usize {
        lock(&self.steps).len()
    }

    fn record(&self, call: ScriptedLiquidBackendCall) {
        lock(&self.calls).push(call);
    }

    fn next(&self, expected: &'static str) -> Result<ScriptedLiquidBackendStep, AppError> {
        let step = lock(&self.steps).pop_front().ok_or_else(|| {
            AppError::ElectrumError(format!(
                "scripted Liquid backend exhausted before {expected}"
            ))
        })?;
        if step.kind() != expected {
            return Err(AppError::ElectrumError(format!(
                "scripted Liquid backend expected {expected}, found {}",
                step.kind()
            )));
        }
        Ok(step)
    }
}

fn script_sha256(script: &elements::Script) -> String {
    hex::encode(Sha256::digest(script.as_bytes()))
}

#[async_trait]
impl UtxoBackend for ScriptedLiquidBackend {
    async fn health_check(&self) -> Result<(), AppError> {
        self.record(ScriptedLiquidBackendCall::HealthCheck);
        let ScriptedLiquidBackendStep::HealthCheck(result) = self.next("health_check")? else {
            unreachable!("step kind checked")
        };
        result.map_err(|error| error.into_app_error("Liquid health check"))
    }

    async fn get_raw_tx(&self, txid_hex: &str) -> Result<Vec<u8>, AppError> {
        self.record(ScriptedLiquidBackendCall::RawTransaction {
            txid: txid_hex.to_owned(),
        });
        let ScriptedLiquidBackendStep::RawTransaction { txid, result } = self.next("get_raw_tx")?
        else {
            unreachable!("step kind checked")
        };
        if txid != txid_hex {
            return Err(AppError::ElectrumError(
                "scripted Liquid raw-transaction request mismatch".into(),
            ));
        }
        result.map_err(|error| error.into_app_error("Liquid raw transaction"))
    }

    async fn is_unspent(
        &self,
        script_pubkey: &elements::Script,
        txid_hex: &str,
        vout: u32,
    ) -> Result<bool, AppError> {
        self.record(ScriptedLiquidBackendCall::IsUnspent {
            script_sha256: script_sha256(script_pubkey),
            txid: txid_hex.to_owned(),
            vout,
        });
        let ScriptedLiquidBackendStep::IsUnspent {
            txid,
            vout: expected_vout,
            result,
        } = self.next("is_unspent")?
        else {
            unreachable!("step kind checked")
        };
        if txid != txid_hex || expected_vout != vout {
            return Err(AppError::ElectrumError(
                "scripted Liquid unspent request mismatch".into(),
            ));
        }
        result.map_err(|error| error.into_app_error("Liquid unspent"))
    }

    async fn script_history(
        &self,
        script_pubkey: &elements::Script,
    ) -> Result<LiquidScriptHistory, AppError> {
        self.record(ScriptedLiquidBackendCall::ScriptHistory {
            script_sha256: script_sha256(script_pubkey),
        });
        let ScriptedLiquidBackendStep::ScriptHistory(result) = self.next("script_history")? else {
            unreachable!("step kind checked")
        };
        result.map_err(|error| error.into_app_error("Liquid script history"))
    }

    async fn history_txids(
        &self,
        script_pubkey: &elements::Script,
    ) -> Result<Vec<String>, AppError> {
        self.record(ScriptedLiquidBackendCall::HistoryTxids {
            script_sha256: script_sha256(script_pubkey),
        });
        let ScriptedLiquidBackendStep::HistoryTxids(result) = self.next("history_txids")? else {
            unreachable!("step kind checked")
        };
        result.map_err(|error| error.into_app_error("Liquid history txids"))
    }

    async fn liquid_history_snapshot(
        &self,
        script_pubkey: &elements::Script,
        prior_block_heights: &[i32],
        limits: LiquidHistorySnapshotLimits,
    ) -> Result<LiquidHistorySnapshotOutcome, AppError> {
        self.record(ScriptedLiquidBackendCall::LiquidHistorySnapshot {
            script_sha256: script_sha256(script_pubkey),
            prior_block_heights: prior_block_heights.to_vec(),
            limits,
        });
        let ScriptedLiquidBackendStep::LiquidHistorySnapshot(result) =
            self.next("liquid_history_snapshot")?
        else {
            unreachable!("step kind checked")
        };
        (*result).map_err(|error| error.into_app_error("Liquid history snapshot"))
    }

    async fn automatic_fallback_liquid_history_snapshot(
        &self,
        script_pubkey: &elements::Script,
        prior_block_heights: &[i32],
        limits: LiquidHistorySnapshotLimits,
    ) -> Result<LiquidHistorySnapshotOutcome, AppError> {
        self.record(
            ScriptedLiquidBackendCall::AutomaticFallbackLiquidHistorySnapshot {
                script_sha256: script_sha256(script_pubkey),
                prior_block_heights: prior_block_heights.to_vec(),
                limits,
            },
        );
        let ScriptedLiquidBackendStep::AutomaticFallbackLiquidHistorySnapshot(result) =
            self.next("automatic_fallback_liquid_history_snapshot")?
        else {
            unreachable!("step kind checked")
        };
        (*result).map_err(|error| error.into_app_error("agreed Liquid history snapshot"))
    }

    async fn find_spending_txid(
        &self,
        script_pubkey: &elements::Script,
        txid_hex: &str,
        vout: u32,
    ) -> Result<Option<String>, AppError> {
        self.record(ScriptedLiquidBackendCall::FindSpendingTxid {
            script_sha256: script_sha256(script_pubkey),
            txid: txid_hex.to_owned(),
            vout,
        });
        let ScriptedLiquidBackendStep::FindSpendingTxid {
            txid,
            vout: expected_vout,
            result,
        } = self.next("find_spending_txid")?
        else {
            unreachable!("step kind checked")
        };
        if txid != txid_hex || expected_vout != vout {
            return Err(AppError::ElectrumError(
                "scripted Liquid spending request mismatch".into(),
            ));
        }
        result.map_err(|error| error.into_app_error("Liquid spending transaction"))
    }

    async fn tx_exists(&self, txid_hex: &str) -> Result<bool, AppError> {
        self.record(ScriptedLiquidBackendCall::TxExists {
            txid: txid_hex.to_owned(),
        });
        let ScriptedLiquidBackendStep::TxExists { txid, result } = self.next("tx_exists")? else {
            unreachable!("step kind checked")
        };
        if txid != txid_hex {
            return Err(AppError::ElectrumError(
                "scripted Liquid transaction-existence request mismatch".into(),
            ));
        }
        result.map_err(|error| error.into_app_error("Liquid transaction existence"))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::utxo::{LiquidHistoryEntry, LiquidHistorySnapshot};

    fn snapshot(
        authority: &str,
        tip_height: i32,
        tip_hash: &str,
        entries: Vec<LiquidHistoryEntry>,
        anchors: impl IntoIterator<Item = (i32, String)>,
    ) -> LiquidHistorySnapshotOutcome {
        LiquidHistorySnapshotOutcome::Complete(LiquidHistorySnapshot {
            authority: authority.to_owned(),
            tip_height,
            tip_hash: tip_hash.to_owned(),
            entries,
            anchored_block_hashes: anchors.into_iter().collect::<BTreeMap<_, _>>(),
        })
    }

    #[tokio::test]
    async fn liquid_script_replays_eviction_confirmation_and_reorg_snapshots() {
        let txid = "11".repeat(32);
        let mempool = snapshot(
            "authority-a",
            100,
            "aa",
            vec![LiquidHistoryEntry {
                txid: txid.clone(),
                height: 0,
                block_hash: None,
            }],
            [],
        );
        let confirmed = snapshot(
            "authority-a",
            101,
            "bb",
            vec![LiquidHistoryEntry {
                txid: txid.clone(),
                height: 101,
                block_hash: Some("bb".into()),
            }],
            [(101, "bb".into())],
        );
        let evicted = snapshot("authority-a", 101, "bb", vec![], [(101, "bb".into())]);
        let reorged = snapshot("authority-a", 102, "cc", vec![], [(101, "dd".into())]);
        let backend = ScriptedLiquidBackend::new([
            ScriptedLiquidBackendStep::LiquidHistorySnapshot(Box::new(Ok(mempool.clone()))),
            ScriptedLiquidBackendStep::LiquidHistorySnapshot(Box::new(Ok(confirmed.clone()))),
            ScriptedLiquidBackendStep::LiquidHistorySnapshot(Box::new(Ok(evicted.clone()))),
            ScriptedLiquidBackendStep::LiquidHistorySnapshot(Box::new(Ok(reorged.clone()))),
        ]);
        let script = elements::Script::new();
        let limits = LiquidHistorySnapshotLimits {
            max_history_entries: 10,
            max_block_heights: 10,
        };

        assert_eq!(
            backend
                .liquid_history_snapshot(&script, &[], limits)
                .await
                .unwrap(),
            mempool
        );
        assert_eq!(
            backend
                .liquid_history_snapshot(&script, &[], limits)
                .await
                .unwrap(),
            confirmed
        );
        assert_eq!(
            backend
                .liquid_history_snapshot(&script, &[101], limits)
                .await
                .unwrap(),
            evicted
        );
        assert_eq!(
            backend
                .liquid_history_snapshot(&script, &[101], limits)
                .await
                .unwrap(),
            reorged
        );
        assert_eq!(backend.remaining_steps(), 0);
    }

    #[tokio::test]
    async fn independent_liquid_scripts_preserve_backend_disagreement() {
        let left_snapshot = snapshot("authority-a", 50, "aa", vec![], []);
        let right_snapshot = snapshot("authority-b", 50, "bb", vec![], []);
        let left = ScriptedLiquidBackend::new([
            ScriptedLiquidBackendStep::AutomaticFallbackLiquidHistorySnapshot(Box::new(Ok(
                left_snapshot.clone(),
            ))),
        ]);
        let right = ScriptedLiquidBackend::new([
            ScriptedLiquidBackendStep::AutomaticFallbackLiquidHistorySnapshot(Box::new(Ok(
                right_snapshot.clone(),
            ))),
        ]);
        let script = elements::Script::new();
        let limits = LiquidHistorySnapshotLimits {
            max_history_entries: 1,
            max_block_heights: 1,
        };

        let left_observed = left
            .automatic_fallback_liquid_history_snapshot(&script, &[], limits)
            .await
            .unwrap();
        let right_observed = right
            .automatic_fallback_liquid_history_snapshot(&script, &[], limits)
            .await
            .unwrap();
        assert_ne!(left_observed, right_observed);
        assert_eq!(left.remaining_steps(), 0);
        assert_eq!(right.remaining_steps(), 0);
    }
}

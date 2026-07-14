//! Fresh, schema-free evidence assembly for the pending provider-expiry path.
//!
//! This module reads only one immutable chain-swap target. It neither scans a
//! wallet/address range nor persists funding allocations. Provider status and
//! transaction ids remain outside the source facts assembled here.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;

use boltz_client::elements;
use boltz_client::network::LiquidChain;
use boltz_client::swaps::boltz::{CreateChainResponse, Side};
use boltz_client::swaps::liquid::LBtcSwapScript;
use boltz_client::Keypair;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;

use crate::chain_lockup_witness_audit::{ChainLockupInclusionV1, ChainLockupSpendV1};
use crate::chain_swap_action::{
    recheck_recovery_under_lock, BitcoinSourceEvidence, BitcoinTimeoutEvidence, ChainSwapEvidence,
    CooperativeRecoveryEvidence, EvidenceQuality, LiquidLockEvidence, LiquidPathEvidence,
    MerchantTransactionEvidence, ProviderStatusEvidence, RecoveryDestinationEvidence,
    RecoveryExecutionGate, RenegotiationEvidence,
};
use crate::chain_swap_primary_source::{
    project_primary_bitcoin_source_snapshot_v1, PrimaryBitcoinAmountRelationV1,
    PrimaryBitcoinSourceAuthorityV1, PrimaryBitcoinSourceProjectionV1,
    PrimaryBitcoinSourceTargetV1,
};
use crate::db::{self, ChainSwapRecord, ChainSwapTxAttempt};
use crate::error::AppError;
use crate::merchant_settlement_lifecycle::SettlementFinalityPolicy;
use crate::utxo::{
    LiquidHistorySnapshot, LiquidHistorySnapshotLimits, LiquidHistorySnapshotOutcome,
    LiquidScriptHistory, UtxoBackend,
};
use crate::AppState;

const AUTOMATIC_FALLBACK_LIQUID_HISTORY_LIMIT: usize = 64;
const REDACTED: &str = "<redacted>";

/// Owned snapshot handoff for the runtime reducer.
pub struct CollectedPendingExpiryEvidence {
    /// Fresh provider status, or `None` when either provider read failed.
    /// This selects a reducer branch but is never chain authority.
    pub provider_status: Option<String>,
    pub evidence: ChainSwapEvidence,
    pub primary_bitcoin: Option<PrimaryBitcoinSourceProjectionV1>,
    /// Swap identity used to construct the primary projection.
    pub primary_chain_swap_id: Option<uuid::Uuid>,
    /// Stable tip bound to the independently loaded primary observation.
    pub primary_tip_height: Option<u32>,
    /// Canonical digest of the complete authority/tip/primary projection.
    /// Raw endpoint, transaction, address, and amount data are not exposed.
    pub primary_evidence_sha256: Option<String>,
}

/// One complete production snapshot for an irreversible Liquid claim check.
/// All database facts were loaded after the caller acquired the shared
/// advisory lock and reloaded the parent row with `FOR UPDATE`.
#[derive(Debug)]
pub struct CollectedChainClaimExecutionEvidence {
    pub evidence: ChainSwapEvidence,
    pub primary_bitcoin: Option<PrimaryBitcoinSourceProjectionV1>,
}

#[derive(Debug, Clone, Copy)]
struct LiquidLockProjection {
    quality: EvidenceQuality,
    lock: LiquidLockEvidence,
}

struct LiquidServerLockTarget {
    script: lwk_wollet::elements::Script,
    blinding_key: elements::secp256k1_zkp::SecretKey,
    expected_amount_sat: u64,
}

const CHAIN_CLAIM_LIQUID_SNAPSHOT_LIMITS: LiquidHistorySnapshotLimits =
    LiquidHistorySnapshotLimits {
        max_history_entries: 128,
        max_block_heights: 128,
    };

/// Assemble the exact ClaimLiquid reducer input from one locked database
/// boundary and fresh, independently verified chain snapshots.
///
/// Transport absence is expressed as incomplete evidence so the caller can
/// return a non-mutating reducer decision. Persisted database corruption still
/// returns an error because it is not a chain observation that may be retried
/// as if nothing happened.
pub async fn collect_chain_claim_execution_evidence_under_lock(
    state: &AppState,
    conn: &mut PgConnection,
    swap: &ChainSwapRecord,
) -> Result<CollectedChainClaimExecutionEvidence, AppError> {
    let recovery_attempt = db::get_bitcoin_recovery_attempt_for_update(&mut *conn, swap.id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    let delivery = db::get_delivered_manifest_for_chain_swap(&mut *conn, swap.id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    let finality_policy = SettlementFinalityPolicy::new(
        state.config.liquid_watcher.finality_confirmations,
        state.config.bitcoin_watcher.confirmations_required,
    )
    .map_err(|error| {
        AppError::ClaimError(format!(
            "merchant settlement finality configuration is invalid: {error}"
        ))
    })?;
    let settlement = db::load_liquid_claim_execution_facts_for_update(
        &mut *conn,
        swap.id,
        swap.invoice_id,
        &swap.boltz_swap_id,
        finality_policy,
    )
    .await
    .map_err(|error| {
        AppError::DbError(format!("load locked Liquid claim execution facts: {error}"))
    })?;

    let mut evidence = ChainSwapEvidence {
        quality: EvidenceQuality::CompleteAndAgreed,
        provider_status: ProviderStatusEvidence::Unknown,
        bitcoin_source: BitcoinSourceEvidence::Unknown,
        liquid_lock: LiquidLockEvidence::Unknown,
        liquid_path: LiquidPathEvidence::Unknown,
        renegotiation: RenegotiationEvidence::Ambiguous,
        recovery_destination: RecoveryDestinationEvidence::Missing,
        cooperative_recovery: CooperativeRecoveryEvidence::Unknown,
        bitcoin_timeout: BitcoinTimeoutEvidence::Unknown,
        liquid_claim_transaction: liquid_claim_transaction_evidence(swap, &settlement),
        bitcoin_recovery_transaction: recovery_transaction_evidence(recovery_attempt.as_ref()),
    };
    if swap
        .creation_terms
        .as_ref()
        .is_some_and(|terms| terms.recovery_address_commitment_id.is_some())
    {
        evidence.recovery_destination = RecoveryDestinationEvidence::Committed;
    }

    let primary_target = delivery.and_then(|delivery| {
        let expected_amount_sat = u64::try_from(swap.user_lock_amount_sat).ok()?;
        PrimaryBitcoinSourceTargetV1::try_new(
            delivery.manifest_sequence,
            delivery.manifest_id,
            delivery.chain_swap_id,
            swap.lockup_address.clone(),
            expected_amount_sat,
        )
        .ok()
    });
    let liquid_target = liquid_server_lock_target(swap).ok();

    let provider_read = state
        .boltz
        .fresh_chain_swap_provider_hint(&swap.boltz_swap_id);
    let bitcoin_read = async {
        let adapter = state.bitcoin_lockup_witness_adapter.as_deref()?;
        let target = primary_target.as_ref()?;
        let snapshot = adapter
            .load_chain_swap_snapshot(
                target.manifest_id(),
                target.chain_swap_id(),
                target.lockup_address(),
            )
            .await
            .ok()?;
        let authority = if adapter.is_primary_authority(&snapshot) {
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode
        } else {
            PrimaryBitcoinSourceAuthorityV1::UntrustedSingleBackend
        };
        Some((snapshot, authority))
    };
    let liquid_read = async {
        let backend = state.utxo_backend.as_deref()?;
        let target = liquid_target.as_ref()?;
        collect_liquid_lock_projection(
            backend,
            target,
            settlement
                .journal_txid
                .as_deref()
                .zip(settlement.journal_raw_transaction.as_deref())
                .zip(settlement.journal_source_prevouts.as_deref())
                .map(|((txid, raw), sources)| (txid, raw, sources)),
        )
        .await
        .ok()
    };
    let (provider_hint, bitcoin_snapshot, liquid_projection) =
        tokio::join!(provider_read, bitcoin_read, liquid_read);
    let provider_hint = provider_hint.ok();
    evidence.provider_status = provider_hint
        .as_ref()
        .map(|hint| provider_status_evidence(hint.status()))
        .unwrap_or(ProviderStatusEvidence::Unknown);

    let primary_bitcoin = match (primary_target.as_ref(), bitcoin_snapshot) {
        (Some(target), Some((snapshot, authority))) => project_primary_bitcoin_source_snapshot_v1(
            target,
            &snapshot,
            provider_hint
                .as_ref()
                .and_then(|hint| hint.transaction_txid()),
            authority,
        )
        .ok(),
        _ => None,
    };
    match primary_bitcoin.as_ref() {
        Some(primary) => primary.apply_to_reducer_evidence(&mut evidence),
        None => evidence.quality = EvidenceQuality::Incomplete,
    }
    match liquid_projection {
        Some(projection) => {
            evidence.quality = merge_evidence_quality(evidence.quality, projection.quality);
            evidence.liquid_lock = projection.lock;
        }
        None => {
            evidence.quality =
                merge_evidence_quality(evidence.quality, EvidenceQuality::Incomplete);
            evidence.liquid_lock = LiquidLockEvidence::Unknown;
        }
    }
    if matches!(
        evidence.liquid_lock,
        LiquidLockEvidence::MempoolUnspent | LiquidLockEvidence::ConfirmedUnspent
    ) {
        evidence.liquid_path = LiquidPathEvidence::Viable;
        evidence.renegotiation = RenegotiationEvidence::NotRequired;
    }

    Ok(CollectedChainClaimExecutionEvidence {
        evidence,
        primary_bitcoin,
    })
}

fn liquid_claim_transaction_evidence(
    swap: &ChainSwapRecord,
    facts: &db::LiquidClaimExecutionFacts,
) -> MerchantTransactionEvidence {
    if facts.replacement_present {
        return MerchantTransactionEvidence::Disputed;
    }
    let journal = match (
        facts.journal_txid.as_deref(),
        facts.journal_status.as_deref(),
    ) {
        (None, None) if swap.claim_txid.is_none() && swap.claim_tx_hex.is_none() => {
            MerchantTransactionEvidence::None
        }
        (None, None) => MerchantTransactionEvidence::Disputed,
        (Some(txid), Some(status))
            if swap.claim_txid.as_deref() == Some(txid) && swap.claim_tx_hex.is_some() =>
        {
            match status {
                "constructed" | "broadcast_ambiguous" => MerchantTransactionEvidence::Prepared,
                "broadcast" => MerchantTransactionEvidence::Broadcast,
                "confirmed" => MerchantTransactionEvidence::Confirmed,
                "finalized" => MerchantTransactionEvidence::Finalized,
                _ => MerchantTransactionEvidence::Disputed,
            }
        }
        _ => MerchantTransactionEvidence::Disputed,
    };
    let Some(lifecycle) = facts.lifecycle.as_ref() else {
        return journal;
    };
    let lifecycle = MerchantTransactionEvidence::from_settlement_lifecycle(lifecycle);
    if journal == lifecycle {
        lifecycle
    } else if facts.journal_status.as_deref() == Some("broadcast_ambiguous")
        && journal == MerchantTransactionEvidence::Prepared
        && lifecycle == MerchantTransactionEvidence::Disputed
    {
        // #83 writes `broadcast_ambiguous` atomically with an eviction/reorg
        // checkpoint specifically to request same-byte redrive. Treat that
        // exact durable pairing as prepared replay intent; every other
        // lifecycle/journal disagreement remains disputed.
        MerchantTransactionEvidence::Prepared
    } else {
        MerchantTransactionEvidence::Disputed
    }
}

async fn collect_liquid_lock_projection(
    backend: &dyn UtxoBackend,
    target: &LiquidServerLockTarget,
    journal: Option<(&str, &[u8], &[db::MerchantSettlementSourcePrevout])>,
) -> Result<LiquidLockProjection, AppError> {
    let snapshot = match backend
        .liquid_history_snapshot(&target.script, &[], CHAIN_CLAIM_LIQUID_SNAPSHOT_LIMITS)
        .await?
    {
        LiquidHistorySnapshotOutcome::Complete(snapshot) => snapshot,
        LiquidHistorySnapshotOutcome::Incomplete(_) => {
            return Ok(LiquidLockProjection {
                quality: EvidenceQuality::Incomplete,
                lock: LiquidLockEvidence::Unknown,
            })
        }
    };
    if snapshot.authority.is_empty() {
        return Ok(LiquidLockProjection {
            quality: EvidenceQuality::Incomplete,
            lock: LiquidLockEvidence::Unknown,
        });
    }

    let mut heights = BTreeMap::new();
    let mut transactions = Vec::with_capacity(snapshot.entries.len());
    let mut raw_transactions = HashMap::new();
    let mut spends = HashMap::<(String, u32), String>::new();
    for entry in &snapshot.entries {
        if heights
            .insert(entry.txid.to_ascii_lowercase(), entry.height)
            .is_some()
        {
            return Ok(LiquidLockProjection {
                quality: EvidenceQuality::BackendDisagreement,
                lock: LiquidLockEvidence::Unknown,
            });
        }
        let raw = backend.get_raw_tx(&entry.txid).await?;
        let transaction: elements::Transaction =
            elements::encode::deserialize(&raw).map_err(|error| {
                AppError::ElectrumError(format!("decode Liquid lock history: {error}"))
            })?;
        let actual_txid = transaction.txid().to_string();
        if !actual_txid.eq_ignore_ascii_case(&entry.txid) {
            return Ok(LiquidLockProjection {
                quality: EvidenceQuality::BackendDisagreement,
                lock: LiquidLockEvidence::Unknown,
            });
        }
        raw_transactions.insert(actual_txid.to_ascii_lowercase(), raw);
        for input in &transaction.input {
            if input.previous_output.is_null() {
                continue;
            }
            let outpoint = (
                input.previous_output.txid.to_string().to_ascii_lowercase(),
                input.previous_output.vout,
            );
            if spends.insert(outpoint, actual_txid.clone()).is_some() {
                return Ok(LiquidLockProjection {
                    quality: EvidenceQuality::BackendDisagreement,
                    lock: LiquidLockEvidence::UnknownOutspend,
                });
            }
        }
        transactions.push((entry.txid.to_ascii_lowercase(), transaction));
    }

    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let mut funding = Vec::new();
    let mut total_amount_sat = 0u64;
    for (txid, transaction) in &transactions {
        for (vout, output) in transaction.output.iter().enumerate() {
            if output.script_pubkey.as_bytes() != target.script.as_bytes() {
                continue;
            }
            let opened = match output.unblind(&secp, target.blinding_key) {
                Ok(opened) if opened.asset == elements::AssetId::LIQUID_BTC && opened.value > 0 => {
                    opened
                }
                _ => {
                    return Ok(LiquidLockProjection {
                        quality: EvidenceQuality::BackendDisagreement,
                        lock: LiquidLockEvidence::Unknown,
                    })
                }
            };
            total_amount_sat = match total_amount_sat.checked_add(opened.value) {
                Some(total) => total,
                None => {
                    return Ok(LiquidLockProjection {
                        quality: EvidenceQuality::BackendDisagreement,
                        lock: LiquidLockEvidence::Unknown,
                    })
                }
            };
            funding.push((txid.as_str(), u32::try_from(vout).ok(), opened.value));
        }
    }
    if funding.is_empty() {
        if !snapshot.entries.is_empty() {
            return Ok(LiquidLockProjection {
                quality: EvidenceQuality::BackendDisagreement,
                lock: LiquidLockEvidence::Unknown,
            });
        }
        return Ok(LiquidLockProjection {
            quality: EvidenceQuality::CompleteAndAgreed,
            lock: LiquidLockEvidence::NotObserved,
        });
    }
    if total_amount_sat != target.expected_amount_sat
        || funding.iter().any(|(_, vout, _)| vout.is_none())
    {
        return Ok(LiquidLockProjection {
            quality: EvidenceQuality::ProviderDisagreement,
            lock: LiquidLockEvidence::Unknown,
        });
    }
    if let Some((_, _, sources)) = journal {
        let target_script_hex = hex::encode(target.script.as_bytes());
        let exact_sources = funding.iter().all(|(txid, vout, amount_sat)| {
            sources.iter().any(|source| {
                source.txid.eq_ignore_ascii_case(txid)
                    && Some(source.vout) == *vout
                    && source.amount_sat == *amount_sat
                    && source
                        .script_pubkey_hex
                        .eq_ignore_ascii_case(&target_script_hex)
            })
        }) && sources.len() == funding.len();
        if !exact_sources {
            return Ok(LiquidLockProjection {
                quality: EvidenceQuality::BackendDisagreement,
                lock: LiquidLockEvidence::Unknown,
            });
        }
    }

    let mut unspent = 0usize;
    let mut merchant_spent = 0usize;
    let mut unknown_spent = 0usize;
    let mut all_confirmed = true;
    for (funding_txid, vout, _) in funding {
        all_confirmed &= heights.get(funding_txid).is_some_and(|height| *height > 0);
        match spends.get(&(funding_txid.to_owned(), vout.expect("validated above"))) {
            None => unspent += 1,
            Some(spender) => match journal {
                Some((txid, expected_raw, _))
                    if spender.eq_ignore_ascii_case(txid)
                        && raw_transactions
                            .get(&spender.to_ascii_lowercase())
                            .is_some_and(|observed| observed.as_slice() == expected_raw) =>
                {
                    merchant_spent += 1
                }
                _ => unknown_spent += 1,
            },
        }
    }
    let lock = if unknown_spent > 0 || (unspent > 0 && merchant_spent > 0) {
        LiquidLockEvidence::UnknownOutspend
    } else if merchant_spent > 0 {
        LiquidLockEvidence::SpentByMerchantClaim
    } else if all_confirmed {
        LiquidLockEvidence::ConfirmedUnspent
    } else {
        LiquidLockEvidence::MempoolUnspent
    };
    Ok(LiquidLockProjection {
        quality: EvidenceQuality::CompleteAndAgreed,
        lock,
    })
}

fn liquid_server_lock_target(swap: &ChainSwapRecord) -> Result<LiquidServerLockTarget, AppError> {
    swap.verify_creation_response_integrity()
        .map_err(AppError::ClaimError)?;
    let response: CreateChainResponse =
        serde_json::from_str(&swap.boltz_response_json).map_err(|error| {
            AppError::ClaimError(format!("invalid chain creation response: {error}"))
        })?;
    let address = elements::Address::from_str(&response.claim_details.lockup_address)
        .map_err(|error| AppError::ClaimError(format!("invalid Liquid server lock: {error}")))?;
    if address.params != &elements::AddressParams::LIQUID || address.blinding_pubkey.is_none() {
        return Err(AppError::ClaimError(
            "Liquid server lock is not confidential mainnet".into(),
        ));
    }
    let script = exact_liquid_server_lock_script(swap)?;
    if script.as_bytes() != address.script_pubkey().as_bytes() {
        return Err(AppError::ClaimError(
            "derived Liquid server lock disagrees with committed address".into(),
        ));
    }
    let blinding_key = response
        .claim_details
        .blinding_key
        .as_deref()
        .ok_or_else(|| AppError::ClaimError("Liquid server lock blinding key is missing".into()))?
        .parse()
        .map_err(|error| {
            AppError::ClaimError(format!("invalid Liquid server lock blinding key: {error}"))
        })?;
    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let blinding_pubkey = elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &blinding_key);
    if address.blinding_pubkey != Some(blinding_pubkey) {
        return Err(AppError::ClaimError(
            "Liquid server lock blinding key disagrees with committed address".into(),
        ));
    }
    let expected_amount_sat = u64::try_from(swap.effective_server_lock_amount_sat())
        .map_err(|_| AppError::ClaimError("invalid Liquid server lock amount".into()))?;
    if expected_amount_sat == 0 {
        return Err(AppError::ClaimError(
            "invalid Liquid server lock amount".into(),
        ));
    }
    Ok(LiquidServerLockTarget {
        script,
        blinding_key,
        expected_amount_sat,
    })
}

fn provider_status_evidence(status: &str) -> ProviderStatusEvidence {
    match status {
        "swap.expired"
        | "transaction.lockupFailed"
        | "transaction.failed"
        | "transaction.refunded" => ProviderStatusEvidence::Expired,
        "transaction.claimed" => ProviderStatusEvidence::SettlementHint,
        "swap.created"
        | "transaction.mempool"
        | "transaction.confirmed"
        | "transaction.server.mempool"
        | "transaction.server.confirmed"
        | "transaction.zeroconf.rejected" => ProviderStatusEvidence::Active,
        _ => ProviderStatusEvidence::Unknown,
    }
}

const fn merge_evidence_quality(left: EvidenceQuality, right: EvidenceQuality) -> EvidenceQuality {
    use EvidenceQuality as Quality;
    match (left, right) {
        (Quality::BackendDisagreement, _) | (_, Quality::BackendDisagreement) => {
            Quality::BackendDisagreement
        }
        (Quality::ProviderDisagreement, _) | (_, Quality::ProviderDisagreement) => {
            Quality::ProviderDisagreement
        }
        (Quality::Incomplete, _) | (_, Quality::Incomplete) => Quality::Incomplete,
        (Quality::CompleteAndAgreed, Quality::CompleteAndAgreed) => Quality::CompleteAndAgreed,
    }
}

/// One exact Bitcoin source outpoint selected by the independently audited
/// primary transaction. It remains an in-memory construction constraint; #85
/// does not introduce an allocation ledger or aggregate unrelated swaps.
#[derive(Clone, PartialEq, Eq)]
pub struct AutomaticFallbackSource {
    txid: String,
    vout: u32,
}

impl AutomaticFallbackSource {
    pub fn txid(&self) -> &str {
        &self.txid
    }

    pub fn vout(&self) -> u32 {
        self.vout
    }
}

impl fmt::Debug for AutomaticFallbackSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AutomaticFallbackSource")
            .field("txid", &REDACTED)
            .field("vout", &self.vout)
            .finish()
    }
}

/// Complete automatic-fallback packet assembled inside the shared per-swap
/// lock. Secret/address material has explicit accessors and redacted Debug.
#[derive(Clone)]
pub struct CollectedAutomaticFallbackEvidence {
    pub evidence: ChainSwapEvidence,
    committed_destination: Option<String>,
    exact_sources: Vec<AutomaticFallbackSource>,
    bitcoin_timeout_height: Option<u32>,
    dependencies_available: bool,
}

impl CollectedAutomaticFallbackEvidence {
    pub fn committed_destination(&self) -> Option<&str> {
        self.committed_destination.as_deref()
    }

    pub fn exact_sources(&self) -> &[AutomaticFallbackSource] {
        &self.exact_sources
    }

    pub fn bitcoin_timeout_height(&self) -> Option<u32> {
        self.bitcoin_timeout_height
    }

    pub fn dependencies_available(&self) -> bool {
        self.dependencies_available
    }

    /// Mechanical shape check in addition to the shared #82 reducer gate.
    /// The reducer chooses the rail; this check proves the executor also has
    /// one concrete immutable destination, timeout, and exact primary input
    /// set before construction can be called.
    pub fn authorizes_automatic_recovery(&self) -> bool {
        matches!(
            recheck_recovery_under_lock(&self.evidence),
            RecoveryExecutionGate::Authorized
        ) && self.dependencies_available
            && self.evidence.bitcoin_timeout == BitcoinTimeoutEvidence::Reached
            && self.committed_destination.is_some()
            && self.bitcoin_timeout_height.is_some()
            && !self.exact_sources.is_empty()
    }
}

impl fmt::Debug for CollectedAutomaticFallbackEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectedAutomaticFallbackEvidence")
            .field("evidence", &self.evidence)
            .field(
                "committed_destination",
                &self.committed_destination.as_ref().map(|_| REDACTED),
            )
            .field("exact_source_count", &self.exact_sources.len())
            .field("bitcoin_timeout_height", &self.bitcoin_timeout_height)
            .field("dependencies_available", &self.dependencies_available)
            .finish()
    }
}

/// Assemble the independent #82 packet used by #85 scheduling and execution.
///
/// Provider lifecycle/status is deliberately absent. Before the immutable
/// Bitcoin timeout, a missing Liquid lock is still a viable/unknown normal
/// path. At and after the timeout, one self-hosted primary Bitcoin snapshot,
/// one stable exact Liquid snapshot, the historical #84 commitment, and all
/// transaction intents must agree before the reducer can authorize unilateral
/// recovery.
pub async fn collect_automatic_fallback_evidence_under_lock(
    state: &AppState,
    conn: &mut PgConnection,
    swap: &ChainSwapRecord,
    recovery_attempt: Option<&ChainSwapTxAttempt>,
) -> Result<CollectedAutomaticFallbackEvidence, AppError> {
    let delivery = db::get_delivered_manifest_for_chain_swap(&mut *conn, swap.id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    let liquid_intent_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM chain_swap_tx_attempts \
              WHERE chain_swap_id = $1 \
                AND purpose IN ('liquid_claim', 'liquid_claim_replacement') \
             UNION ALL \
             SELECT 1 FROM merchant_settlement_checkpoints \
              WHERE chain_swap_id = $1 AND settlement_path = 'liquid_claim' \
         )",
    )
    .bind(swap.id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|error| AppError::DbError(error.to_string()))?;

    let mut evidence = ChainSwapEvidence {
        quality: EvidenceQuality::CompleteAndAgreed,
        provider_status: ProviderStatusEvidence::Unknown,
        bitcoin_source: BitcoinSourceEvidence::Unknown,
        liquid_lock: LiquidLockEvidence::Unknown,
        liquid_path: LiquidPathEvidence::Unknown,
        renegotiation: RenegotiationEvidence::Ambiguous,
        recovery_destination: RecoveryDestinationEvidence::Missing,
        cooperative_recovery: CooperativeRecoveryEvidence::Unknown,
        bitcoin_timeout: BitcoinTimeoutEvidence::Unknown,
        liquid_claim_transaction: liquid_claim_transaction_evidence(swap, liquid_intent_exists),
        bitcoin_recovery_transaction: MerchantTransactionEvidence::None,
    };

    let committed_destination =
        collect_exact_recovery_destination(conn, swap, recovery_attempt, &mut evidence).await?;

    let primary_target = delivery.and_then(|delivery| {
        let expected_amount_sat = u64::try_from(swap.user_lock_amount_sat).ok()?;
        PrimaryBitcoinSourceTargetV1::try_new(
            delivery.manifest_sequence,
            delivery.manifest_id,
            delivery.chain_swap_id,
            swap.lockup_address.clone(),
            expected_amount_sat,
        )
        .ok()
    });
    let liquid_target = exact_liquid_server_lock_target(swap).ok();

    let bitcoin_read = async {
        let adapter = state.bitcoin_lockup_witness_adapter.as_deref().ok_or(())?;
        let target = primary_target.as_ref().ok_or(())?;
        let snapshot = adapter
            .load_chain_swap_snapshot(
                target.manifest_id(),
                target.chain_swap_id(),
                target.lockup_address(),
            )
            .await
            .map_err(|_| ())?;
        let authority = if adapter.is_primary_authority(&snapshot) {
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode
        } else {
            PrimaryBitcoinSourceAuthorityV1::UntrustedSingleBackend
        };
        Ok::<_, ()>((snapshot, authority))
    };
    let liquid_read = async {
        let backend = state.utxo_backend.as_deref().ok_or(())?;
        let target = liquid_target.as_ref().ok_or(())?;
        let outcome = backend
            .automatic_fallback_liquid_history_snapshot(
                &target.script,
                &[],
                LiquidHistorySnapshotLimits {
                    max_history_entries: AUTOMATIC_FALLBACK_LIQUID_HISTORY_LIMIT,
                    max_block_heights: AUTOMATIC_FALLBACK_LIQUID_HISTORY_LIMIT,
                },
            )
            .await
            .map_err(|_| ())?;
        match outcome {
            LiquidHistorySnapshotOutcome::Complete(snapshot) => Ok(snapshot),
            LiquidHistorySnapshotOutcome::Incomplete(_) => Err(()),
        }
    };
    let (bitcoin_snapshot, liquid_snapshot) = tokio::join!(bitcoin_read, liquid_read);
    let dependencies_available =
        committed_destination.is_some() && bitcoin_snapshot.is_ok() && liquid_snapshot.is_ok();

    let mut exact_sources = Vec::new();
    let mut bitcoin_timeout_height = None;
    let mut amount_relation = PrimaryBitcoinAmountRelationV1::Unknown;
    match (primary_target.as_ref(), bitcoin_snapshot.as_ref().ok()) {
        (Some(target), Some((snapshot, authority))) => {
            let projection =
                project_primary_bitcoin_source_snapshot_v1(target, snapshot, None, *authority)
                    .map_err(|_| {
                        AppError::ClaimError(
                            "automatic fallback rejected the primary Bitcoin evidence".into(),
                        )
                    })?;
            projection.apply_to_reducer_evidence(&mut evidence);
            amount_relation = projection.amount_relation();
            let projected =
                classify_automatic_bitcoin_source(&projection, snapshot, recovery_attempt);
            evidence.bitcoin_source = projected.bitcoin_source;
            evidence.bitcoin_recovery_transaction = projected.transaction;
            evidence.quality = merge_quality(evidence.quality, projected.quality);
            exact_sources = projected.exact_sources;

            let timeout = swap
                .creation_terms
                .as_ref()
                .and_then(|terms| u32::try_from(terms.btc_timeout_height).ok());
            match timeout {
                Some(timeout) if timeout > 0 => {
                    bitcoin_timeout_height = Some(timeout);
                    evidence.bitcoin_timeout = if snapshot.tip_height >= timeout {
                        BitcoinTimeoutEvidence::Reached
                    } else {
                        BitcoinTimeoutEvidence::BeforeTimeout
                    };
                }
                _ => evidence.quality = EvidenceQuality::Incomplete,
            }
        }
        _ => evidence.quality = EvidenceQuality::Incomplete,
    }

    match (
        state.utxo_backend.as_deref(),
        liquid_target.as_ref(),
        liquid_snapshot.as_ref().ok(),
    ) {
        (Some(backend), Some(target), Some(snapshot)) => {
            let projected =
                classify_liquid_server_lock(backend, target, snapshot, swap, liquid_intent_exists)
                    .await?;
            evidence.quality = merge_quality(evidence.quality, projected.quality);
            evidence.liquid_lock = projected.lock;
            evidence.liquid_claim_transaction = projected.transaction;
            if projected.path_unavailable
                && evidence.bitcoin_timeout == BitcoinTimeoutEvidence::Reached
            {
                evidence.liquid_path = LiquidPathEvidence::Unavailable;
            }
        }
        _ => evidence.quality = EvidenceQuality::Incomplete,
    }

    if evidence.liquid_path != LiquidPathEvidence::Unavailable {
        evidence.liquid_path = match evidence.liquid_lock {
            LiquidLockEvidence::NotObserved
            | LiquidLockEvidence::MempoolUnspent
            | LiquidLockEvidence::ConfirmedUnspent => LiquidPathEvidence::Viable,
            LiquidLockEvidence::SpentByProviderRefund => LiquidPathEvidence::Unavailable,
            LiquidLockEvidence::Unknown
            | LiquidLockEvidence::SpentByMerchantClaim
            | LiquidLockEvidence::UnknownOutspend => LiquidPathEvidence::Unknown,
        };
    }
    evidence.renegotiation = classify_renegotiation(swap, amount_relation);

    Ok(CollectedAutomaticFallbackEvidence {
        evidence,
        committed_destination,
        exact_sources,
        bitcoin_timeout_height,
        dependencies_available,
    })
}

async fn collect_exact_recovery_destination(
    conn: &mut PgConnection,
    swap: &ChainSwapRecord,
    recovery_attempt: Option<&ChainSwapTxAttempt>,
    evidence: &mut ChainSwapEvidence,
) -> Result<Option<String>, AppError> {
    let Some(terms) = swap.creation_terms.as_ref() else {
        return Ok(None);
    };
    let (Some(commitment_id), Some(destination)) = (
        terms.recovery_address_commitment_id,
        terms.merchant_emergency_btc_address.as_ref(),
    ) else {
        return Ok(None);
    };
    let commitment = db::select_recovery_address_commitment_by_id(&mut *conn, commitment_id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    let invoice_owner = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT npub_owner, nym_owner FROM invoices WHERE id = $1",
    )
    .bind(swap.invoice_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|error| AppError::DbError(error.to_string()))?;
    let exact = commitment.as_ref().is_some_and(|commitment| {
        commitment.commitment_id == commitment_id
            && commitment.canonical_btc_address() == destination
            && recovery_owner_matches_invoice(
                &commitment.npub,
                swap.nym.as_deref(),
                invoice_owner.as_ref(),
            )
    });
    if !exact {
        evidence.recovery_destination = RecoveryDestinationEvidence::Disputed;
        return Ok(None);
    }
    if swap
        .refund_address
        .as_deref()
        .is_some_and(|address| address != destination)
        || recovery_attempt
            .is_some_and(|attempt| attempt.destination_address.as_str() != destination)
    {
        evidence.recovery_destination = RecoveryDestinationEvidence::Disputed;
        return Ok(None);
    }
    evidence.recovery_destination = RecoveryDestinationEvidence::Committed;
    Ok(Some(destination.clone()))
}

fn recovery_owner_matches_invoice(
    commitment_npub: &str,
    swap_nym: Option<&str>,
    invoice_owner: Option<&(String, Option<String>)>,
) -> bool {
    invoice_owner.is_some_and(|(npub, nym)| npub == commitment_npub && nym.as_deref() == swap_nym)
}

struct AutomaticBitcoinProjection {
    quality: EvidenceQuality,
    bitcoin_source: BitcoinSourceEvidence,
    transaction: MerchantTransactionEvidence,
    exact_sources: Vec<AutomaticFallbackSource>,
}

fn classify_automatic_bitcoin_source(
    projection: &PrimaryBitcoinSourceProjectionV1,
    snapshot: &crate::chain_lockup_witness_adapter::BitcoinMainnetLockupWitnessSnapshotV1,
    attempt: Option<&ChainSwapTxAttempt>,
) -> AutomaticBitcoinProjection {
    let mut result = AutomaticBitcoinProjection {
        quality: projection.quality(),
        bitcoin_source: projection.bitcoin_source(),
        transaction: recovery_transaction_evidence(attempt),
        exact_sources: Vec::new(),
    };
    let Some(primary_txid) = projection.primary_txid() else {
        return result;
    };
    let primary = snapshot
        .observations
        .iter()
        .filter(|observation| observation.txid == primary_txid)
        .collect::<Vec<_>>();
    if primary.is_empty() {
        result.quality = EvidenceQuality::Incomplete;
        result.bitcoin_source = BitcoinSourceEvidence::Unknown;
        return result;
    }

    if projection.bitcoin_source() == BitcoinSourceEvidence::ConfirmedUnspent {
        if primary.iter().all(|observation| {
            matches!(
                observation.inclusion,
                ChainLockupInclusionV1::Confirmed { .. }
            ) && observation.spend == ChainLockupSpendV1::Unspent
        }) {
            result.exact_sources = primary
                .iter()
                .map(|observation| AutomaticFallbackSource {
                    txid: observation.txid.clone(),
                    vout: observation.vout,
                })
                .collect();
            if let Some(attempt) = attempt {
                result.transaction = match attempt.status.as_str() {
                    "integrity_hold" => MerchantTransactionEvidence::Disputed,
                    "confirmed" | "finalized" => MerchantTransactionEvidence::Disputed,
                    _ => MerchantTransactionEvidence::Prepared,
                };
            }
        } else {
            result.quality = EvidenceQuality::BackendDisagreement;
            result.bitcoin_source = BitcoinSourceEvidence::Unknown;
        }
        return result;
    }

    if projection.bitcoin_source() == BitcoinSourceEvidence::UnknownOutspend {
        let Some(attempt) = attempt else {
            return result;
        };
        let mut inclusion = None;
        let expected = primary.iter().all(|observation| match &observation.spend {
            ChainLockupSpendV1::Spent {
                spending_txid,
                inclusion: candidate,
            } if spending_txid.eq_ignore_ascii_case(&attempt.txid) => {
                inclusion = Some(candidate);
                true
            }
            _ => false,
        });
        if expected {
            result.bitcoin_source = BitcoinSourceEvidence::SpentByRecoveryTransaction;
            result.transaction = match attempt.status.as_str() {
                "finalized" => MerchantTransactionEvidence::Finalized,
                "integrity_hold" => MerchantTransactionEvidence::Disputed,
                _ => match inclusion {
                    Some(ChainLockupInclusionV1::Mempool) => MerchantTransactionEvidence::Mempool,
                    Some(ChainLockupInclusionV1::Confirmed { .. }) => {
                        MerchantTransactionEvidence::Confirmed
                    }
                    None => MerchantTransactionEvidence::Disputed,
                },
            };
        }
    }
    result
}

struct LiquidServerLockTarget {
    script: elements::Script,
    blinding_key: elements::secp256k1_zkp::SecretKey,
    asset_id: elements::AssetId,
    amount_sat: u64,
    timeout_height: i32,
}

fn exact_liquid_server_lock_target(
    swap: &ChainSwapRecord,
) -> Result<LiquidServerLockTarget, AppError> {
    let script = exact_liquid_server_lock_script(swap)?;
    let response: CreateChainResponse =
        serde_json::from_str(&swap.boltz_response_json).map_err(|error| {
            AppError::ClaimError(format!("invalid chain creation response: {error}"))
        })?;
    let blinding_key = response
        .claim_details
        .blinding_key
        .as_deref()
        .ok_or_else(|| AppError::ClaimError("Liquid server lock lacks its blinding key".into()))?
        .parse()
        .map_err(|_| {
            AppError::ClaimError("Liquid server lock has an invalid blinding key".into())
        })?;
    let asset_id = swap
        .creation_terms
        .as_ref()
        .ok_or_else(|| AppError::ClaimError("chain swap lacks immutable creation terms".into()))?
        .liquid_asset_id
        .parse()
        .map_err(|_| AppError::ClaimError("chain swap has an invalid Liquid asset".into()))?;
    let amount_sat = u64::try_from(swap.effective_server_lock_amount_sat())
        .ok()
        .filter(|amount| *amount > 0)
        .ok_or_else(|| AppError::ClaimError("chain swap has an invalid Liquid amount".into()))?;
    let timeout_height = i32::try_from(
        swap.creation_terms
            .as_ref()
            .ok_or_else(|| {
                AppError::ClaimError("chain swap lacks immutable creation terms".into())
            })?
            .liquid_timeout_height,
    )
    .ok()
    .filter(|height| *height > 0)
    .ok_or_else(|| AppError::ClaimError("chain swap has an invalid Liquid timeout".into()))?;
    Ok(LiquidServerLockTarget {
        script,
        blinding_key,
        asset_id,
        amount_sat,
        timeout_height,
    })
}

struct LiquidLockProjection {
    quality: EvidenceQuality,
    lock: LiquidLockEvidence,
    transaction: MerchantTransactionEvidence,
    path_unavailable: bool,
}

async fn classify_liquid_server_lock(
    backend: &dyn UtxoBackend,
    target: &LiquidServerLockTarget,
    snapshot: &LiquidHistorySnapshot,
    swap: &ChainSwapRecord,
    liquid_intent_exists: bool,
) -> Result<LiquidLockProjection, AppError> {
    let claim_intent = liquid_claim_transaction_evidence(swap, liquid_intent_exists);
    if snapshot.entries.is_empty() {
        return Ok(LiquidLockProjection {
            quality: EvidenceQuality::CompleteAndAgreed,
            lock: LiquidLockEvidence::NotObserved,
            transaction: claim_intent,
            path_unavailable: snapshot.tip_height >= target.timeout_height,
        });
    }

    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let mut candidates = Vec::new();
    let mut invalid_candidate = false;
    for entry in &snapshot.entries {
        let raw = backend.get_raw_tx(&entry.txid).await?;
        let transaction: elements::Transaction = elements::encode::deserialize(&raw)
            .map_err(|_| AppError::ElectrumError("decode Liquid server-lock evidence".into()))?;
        if !transaction
            .txid()
            .to_string()
            .eq_ignore_ascii_case(&entry.txid)
        {
            return Ok(LiquidLockProjection {
                quality: EvidenceQuality::BackendDisagreement,
                lock: LiquidLockEvidence::Unknown,
                transaction: claim_intent,
                path_unavailable: false,
            });
        }
        for (vout, output) in transaction.output.iter().enumerate() {
            if output.script_pubkey != target.script {
                continue;
            }
            let opened = match output.unblind(&secp, target.blinding_key) {
                Ok(opened) => opened,
                Err(_) => {
                    invalid_candidate = true;
                    continue;
                }
            };
            if opened.asset != target.asset_id || opened.value != target.amount_sat {
                invalid_candidate = true;
                continue;
            }
            let Ok(vout) = u32::try_from(vout) else {
                invalid_candidate = true;
                continue;
            };
            candidates.push((entry, vout));
        }
    }
    if invalid_candidate || candidates.len() != 1 {
        return Ok(LiquidLockProjection {
            quality: if invalid_candidate {
                EvidenceQuality::BackendDisagreement
            } else {
                EvidenceQuality::Incomplete
            },
            lock: LiquidLockEvidence::Unknown,
            transaction: claim_intent,
            path_unavailable: false,
        });
    }

    let (funding, vout) = candidates[0];
    let mut spenders = Vec::new();
    for entry in &snapshot.entries {
        let raw = backend.get_raw_tx(&entry.txid).await?;
        let transaction: elements::Transaction = elements::encode::deserialize(&raw)
            .map_err(|_| AppError::ElectrumError("decode Liquid outspend evidence".into()))?;
        if transaction.input.iter().any(|input| {
            input
                .previous_output
                .txid
                .to_string()
                .eq_ignore_ascii_case(&funding.txid)
                && input.previous_output.vout == vout
        }) {
            spenders.push(entry);
        }
    }
    if spenders.is_empty() {
        return Ok(LiquidLockProjection {
            quality: EvidenceQuality::CompleteAndAgreed,
            lock: if funding.height > 0 {
                LiquidLockEvidence::ConfirmedUnspent
            } else {
                LiquidLockEvidence::MempoolUnspent
            },
            transaction: claim_intent,
            path_unavailable: false,
        });
    }
    if spenders.len() != 1 {
        return Ok(LiquidLockProjection {
            quality: EvidenceQuality::BackendDisagreement,
            lock: LiquidLockEvidence::UnknownOutspend,
            transaction: claim_intent,
            path_unavailable: false,
        });
    }
    // A parent txid/hex is not #83 merchant-output authority. Until the exact
    // settlement journal/lifecycle is restored here, every observed Liquid
    // outspend remains a positive integrity stop rather than guessed claim or
    // provider-refund evidence.
    Ok(LiquidLockProjection {
        quality: EvidenceQuality::CompleteAndAgreed,
        lock: LiquidLockEvidence::UnknownOutspend,
        transaction: claim_intent,
        path_unavailable: false,
    })
}

fn classify_renegotiation(
    swap: &ChainSwapRecord,
    amount_relation: PrimaryBitcoinAmountRelationV1,
) -> RenegotiationEvidence {
    if swap.renegotiated_server_lock_amount_sat.is_some() {
        return RenegotiationEvidence::AcceptedAwaitingLock;
    }
    match amount_relation {
        PrimaryBitcoinAmountRelationV1::NotFunded | PrimaryBitcoinAmountRelationV1::Exact => {
            RenegotiationEvidence::NotRequired
        }
        PrimaryBitcoinAmountRelationV1::Unknown
        | PrimaryBitcoinAmountRelationV1::Underfunded
        | PrimaryBitcoinAmountRelationV1::Overfunded => RenegotiationEvidence::Ambiguous,
    }
}

fn liquid_claim_transaction_evidence(
    swap: &ChainSwapRecord,
    persisted_intent_exists: bool,
) -> MerchantTransactionEvidence {
    match (swap.claim_txid.as_deref(), swap.claim_tx_hex.as_deref()) {
        (None, None) if !persisted_intent_exists => MerchantTransactionEvidence::None,
        _ => MerchantTransactionEvidence::Disputed,
    }
}

fn merge_quality(left: EvidenceQuality, right: EvidenceQuality) -> EvidenceQuality {
    use EvidenceQuality::{
        BackendDisagreement, CompleteAndAgreed, Incomplete, ProviderDisagreement,
    };
    match (left, right) {
        (BackendDisagreement, _) | (_, BackendDisagreement) => BackendDisagreement,
        (ProviderDisagreement, _) | (_, ProviderDisagreement) => ProviderDisagreement,
        (Incomplete, _) | (_, Incomplete) => Incomplete,
        (CompleteAndAgreed, CompleteAndAgreed) => CompleteAndAgreed,
    }
}

/// Assemble fresh evidence while the caller holds the existing per-swap
/// advisory transaction lock and has reloaded `swap` with `FOR UPDATE`.
///
/// Missing or transient chain dependencies are represented as incomplete
/// evidence, not errors or negative facts. Database failures still return an
/// error because the caller cannot safely finalize without its locked row.
pub async fn collect_pending_expiry_evidence_under_lock(
    state: &AppState,
    conn: &mut PgConnection,
    swap: &ChainSwapRecord,
) -> Result<CollectedPendingExpiryEvidence, AppError> {
    let recovery_attempt = db::get_bitcoin_recovery_attempt_for_update(&mut *conn, swap.id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    let delivery = db::get_delivered_manifest_for_chain_swap(&mut *conn, swap.id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;

    let mut evidence = ChainSwapEvidence {
        quality: EvidenceQuality::CompleteAndAgreed,
        provider_status: ProviderStatusEvidence::Unknown,
        bitcoin_source: BitcoinSourceEvidence::Unknown,
        liquid_lock: LiquidLockEvidence::Unknown,
        liquid_path: LiquidPathEvidence::Unknown,
        renegotiation: RenegotiationEvidence::Ambiguous,
        recovery_destination: RecoveryDestinationEvidence::Missing,
        cooperative_recovery: CooperativeRecoveryEvidence::Unknown,
        bitcoin_timeout: BitcoinTimeoutEvidence::Unknown,
        liquid_claim_transaction: if swap.claim_tx_hex.is_some() {
            MerchantTransactionEvidence::Prepared
        } else {
            MerchantTransactionEvidence::None
        },
        bitcoin_recovery_transaction: recovery_transaction_evidence(recovery_attempt.as_ref()),
    };

    let primary_target = delivery.and_then(|delivery| {
        let expected_amount_sat = u64::try_from(swap.user_lock_amount_sat).ok()?;
        PrimaryBitcoinSourceTargetV1::try_new(
            delivery.manifest_sequence,
            delivery.manifest_id,
            delivery.chain_swap_id,
            swap.lockup_address.clone(),
            expected_amount_sat,
        )
        .ok()
    });
    let liquid_script = exact_liquid_server_lock_script(swap).ok();

    let provider_read = state
        .boltz
        .fresh_chain_swap_provider_hint(&swap.boltz_swap_id);
    let bitcoin_read = async {
        let adapter = state.bitcoin_lockup_witness_adapter.as_deref()?;
        let target = primary_target.as_ref()?;
        let snapshot = adapter
            .load_chain_swap_snapshot(
                target.manifest_id(),
                target.chain_swap_id(),
                target.lockup_address(),
            )
            .await
            .ok()?;
        let authority = if adapter.is_primary_authority(&snapshot) {
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode
        } else {
            PrimaryBitcoinSourceAuthorityV1::UntrustedSingleBackend
        };
        Some((snapshot, authority))
    };
    let liquid_read = async {
        let backend = state.utxo_backend.as_deref()?;
        let script = liquid_script.as_ref()?;
        backend.script_history(script).await.ok()
    };
    let (provider_hint, bitcoin_snapshot, liquid_history) =
        tokio::join!(provider_read, bitcoin_read, liquid_read);
    let provider_hint = provider_hint.ok();
    let primary_bitcoin = match (primary_target.as_ref(), bitcoin_snapshot.as_ref()) {
        (Some(target), Some((snapshot, authority))) => project_primary_bitcoin_source_snapshot_v1(
            target,
            snapshot,
            provider_hint
                .as_ref()
                .and_then(|hint| hint.transaction_txid()),
            *authority,
        )
        .ok(),
        _ => None,
    };
    let primary_tip_height = bitcoin_snapshot
        .as_ref()
        .map(|(snapshot, _)| snapshot.tip_height);
    let primary_evidence_sha256 = match (
        primary_target.as_ref(),
        bitcoin_snapshot.as_ref(),
        primary_bitcoin.as_ref(),
    ) {
        (Some(target), Some((snapshot, _)), Some(primary)) => {
            primary_runtime_evidence_sha256(target, snapshot, primary).ok()
        }
        _ => None,
    };

    if provider_hint.is_none() || primary_bitcoin.is_none() {
        evidence.quality = EvidenceQuality::Incomplete;
    }
    match liquid_history {
        Some(LiquidScriptHistory::Empty) => {
            evidence.liquid_lock = LiquidLockEvidence::NotObserved;
        }
        Some(LiquidScriptHistory::MempoolOnly | LiquidScriptHistory::Confirmed) | None => {
            // This narrow source can prove absence but does not guess an
            // outspend classification from a non-empty history summary. The
            // full #83 lifecycle source will supply that evidence.
            evidence.quality = EvidenceQuality::Incomplete;
            evidence.liquid_lock = LiquidLockEvidence::Unknown;
        }
    }

    if let Some(primary) = primary_bitcoin.as_ref() {
        if primary.bitcoin_source() == BitcoinSourceEvidence::Unfunded
            && evidence.liquid_lock == LiquidLockEvidence::NotObserved
        {
            evidence.liquid_path = LiquidPathEvidence::Unavailable;
            evidence.renegotiation = RenegotiationEvidence::NotRequired;
        }
    }

    Ok(CollectedPendingExpiryEvidence {
        provider_status: provider_hint.map(|hint| hint.status().to_owned()),
        evidence,
        primary_chain_swap_id: primary_bitcoin.as_ref().and_then(|_| {
            primary_target
                .as_ref()
                .map(PrimaryBitcoinSourceTargetV1::chain_swap_id)
        }),
        primary_bitcoin,
        primary_tip_height,
        primary_evidence_sha256,
    })
}

fn primary_runtime_evidence_sha256(
    target: &PrimaryBitcoinSourceTargetV1,
    snapshot: &crate::chain_lockup_witness_adapter::BitcoinMainnetLockupWitnessSnapshotV1,
    primary: &PrimaryBitcoinSourceProjectionV1,
) -> Result<String, AppError> {
    let authority_sha256 = hex::encode(Sha256::digest(snapshot.authority().as_bytes()));
    let value = serde_json::json!({
        "formatVersion": 1,
        "manifestId": target.manifest_id(),
        "chainSwapId": target.chain_swap_id(),
        "tipHeight": snapshot.tip_height,
        "tipHash": snapshot.tip_hash,
        "authoritySha256": authority_sha256,
        "quality": format!("{:?}", primary.quality()),
        "bitcoinSource": format!("{:?}", primary.bitcoin_source()),
        "primaryTxid": primary.primary_txid(),
        "expectedAmountSat": primary.expected_amount_sat(),
        "observedAmountSat": primary.observed_amount_sat(),
        "amountRelation": format!("{:?}", primary.amount_relation()),
        "nonPrimaryTransactionCount": primary.non_primary_transaction_count(),
    });
    crate::canonical_json::canonical_json_and_sha256(&value)
        .map(|(_, digest)| digest)
        .map_err(|error| {
            AppError::ClaimError(format!(
                "primary runtime evidence is not canonical: {error}"
            ))
        })
}

fn recovery_transaction_evidence(
    attempt: Option<&ChainSwapTxAttempt>,
) -> MerchantTransactionEvidence {
    let Some(attempt) = attempt else {
        return MerchantTransactionEvidence::None;
    };
    match attempt.status.as_str() {
        "constructed" => MerchantTransactionEvidence::Prepared,
        "broadcast" => MerchantTransactionEvidence::Broadcast,
        "confirmed" => MerchantTransactionEvidence::Confirmed,
        "finalized" => MerchantTransactionEvidence::Finalized,
        "broadcast_ambiguous" | "integrity_hold" => MerchantTransactionEvidence::Disputed,
        _ => MerchantTransactionEvidence::Disputed,
    }
}

fn exact_liquid_server_lock_script(
    swap: &ChainSwapRecord,
) -> Result<lwk_wollet::elements::Script, AppError> {
    swap.verify_creation_response_integrity()
        .map_err(AppError::ClaimError)?;
    let response: CreateChainResponse =
        serde_json::from_str(&swap.boltz_response_json).map_err(|error| {
            AppError::ClaimError(format!("invalid chain creation response: {error}"))
        })?;
    let claim_key_bytes = hex::decode(&swap.claim_key_hex)
        .map_err(|error| AppError::ClaimError(format!("invalid chain claim key: {error}")))?;
    let secret = boltz_client::bitcoin::secp256k1::SecretKey::from_slice(&claim_key_bytes)
        .map_err(|error| AppError::ClaimError(format!("invalid chain claim key: {error}")))?;
    let keypair = Keypair::from_secret_key(&boltz_client::Secp256k1::new(), &secret);
    let claim_public_key = boltz_client::PublicKey::new(keypair.public_key());
    let script =
        LBtcSwapScript::chain_from_swap_resp(Side::Claim, response.claim_details, claim_public_key)
            .map_err(|error| {
                AppError::ClaimError(format!("invalid Liquid server lock: {error}"))
            })?;
    let address = script
        .to_address(LiquidChain::Liquid)
        .map_err(|error| AppError::ClaimError(format!("invalid Liquid server lock: {error}")))?;
    Ok(lwk_wollet::elements::Script::from(
        address.script_pubkey().to_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_swap_action::{
        recheck_chain_swap_execution_under_lock, ChainSwapAction, ChainSwapExecutionAction,
        ChainSwapExecutionGate,
    };

    #[derive(Debug, Default, PartialEq, Eq)]
    struct ClaimMutationCounts {
        constructed: usize,
        journaled: usize,
        broadcast: usize,
    }

    fn claimable_evidence() -> ChainSwapEvidence {
        ChainSwapEvidence {
            quality: EvidenceQuality::CompleteAndAgreed,
            provider_status: ProviderStatusEvidence::Active,
            bitcoin_source: BitcoinSourceEvidence::ConfirmedUnspent,
            liquid_lock: LiquidLockEvidence::ConfirmedUnspent,
            liquid_path: LiquidPathEvidence::Viable,
            renegotiation: RenegotiationEvidence::NotRequired,
            recovery_destination: RecoveryDestinationEvidence::Committed,
            cooperative_recovery: CooperativeRecoveryEvidence::Unknown,
            bitcoin_timeout: BitcoinTimeoutEvidence::BeforeTimeout,
            liquid_claim_transaction: MerchantTransactionEvidence::None,
            bitcoin_recovery_transaction: MerchantTransactionEvidence::None,
        }
    }

    fn simulate_two_gate_claim(
        first: &ChainSwapEvidence,
        second: &ChainSwapEvidence,
        exact_prepared_replay: bool,
    ) -> (ChainSwapExecutionGate, ClaimMutationCounts) {
        let mut mutations = ClaimMutationCounts::default();
        let first_gate =
            recheck_chain_swap_execution_under_lock(ChainSwapExecutionAction::ClaimLiquid, first);
        if first_gate != ChainSwapExecutionGate::Authorized {
            return (first_gate, mutations);
        }
        if !exact_prepared_replay {
            mutations.constructed += 1;
            mutations.journaled += 1;
        }
        let second_gate =
            recheck_chain_swap_execution_under_lock(ChainSwapExecutionAction::ClaimLiquid, second);
        if second_gate == ChainSwapExecutionGate::Authorized {
            mutations.broadcast += 1;
        }
        (second_gate, mutations)
    }

    fn automatic_candidate() -> ChainSwapEvidence {
        ChainSwapEvidence {
            quality: EvidenceQuality::CompleteAndAgreed,
            provider_status: ProviderStatusEvidence::Unknown,
            bitcoin_source: BitcoinSourceEvidence::ConfirmedUnspent,
            liquid_lock: LiquidLockEvidence::NotObserved,
            liquid_path: LiquidPathEvidence::Unavailable,
            renegotiation: RenegotiationEvidence::NotRequired,
            recovery_destination: RecoveryDestinationEvidence::Committed,
            cooperative_recovery: CooperativeRecoveryEvidence::Unknown,
            bitcoin_timeout: BitcoinTimeoutEvidence::Reached,
            liquid_claim_transaction: MerchantTransactionEvidence::None,
            bitcoin_recovery_transaction: MerchantTransactionEvidence::None,
        }
    }

    #[test]
    fn recovery_attempt_ambiguity_never_looks_absent_or_final() {
        assert_eq!(
            recovery_transaction_evidence(None),
            MerchantTransactionEvidence::None
        );
    }

    #[test]
    fn evidence_change_while_second_lock_is_awaited_blocks_broadcast() {
        let first = claimable_evidence();
        let mut after_wait = first;
        after_wait.liquid_claim_transaction = MerchantTransactionEvidence::Prepared;
        after_wait.quality = EvidenceQuality::Incomplete;

        let (gate, mutations) = simulate_two_gate_claim(&first, &after_wait, false);
        assert_eq!(
            gate,
            ChainSwapExecutionGate::Blocked(ChainSwapAction::Observe)
        );
        assert_eq!(mutations.constructed, 1);
        assert_eq!(mutations.journaled, 1);
        assert_eq!(mutations.broadcast, 0);
    }

    #[test]
    fn newly_committed_recovery_intent_blocks_competing_claim_broadcast() {
        let first = claimable_evidence();
        let mut after_wait = first;
        after_wait.liquid_claim_transaction = MerchantTransactionEvidence::Prepared;
        after_wait.bitcoin_recovery_transaction = MerchantTransactionEvidence::Prepared;

        let (gate, mutations) = simulate_two_gate_claim(&first, &after_wait, false);
        assert_eq!(
            gate,
            ChainSwapExecutionGate::Blocked(ChainSwapAction::IntegrityHold)
        );
        assert_eq!(mutations.broadcast, 0);
    }

    #[test]
    fn unknown_or_disagreed_backend_facts_mutate_nothing() {
        for quality in [
            EvidenceQuality::Incomplete,
            EvidenceQuality::BackendDisagreement,
            EvidenceQuality::ProviderDisagreement,
        ] {
            let mut blocked = claimable_evidence();
            blocked.quality = quality;
            let (gate, mutations) = simulate_two_gate_claim(&blocked, &blocked, false);
            assert_eq!(
                gate,
                ChainSwapExecutionGate::Blocked(ChainSwapAction::Observe)
            );
            assert_eq!(mutations, ClaimMutationCounts::default());
        }
    }

    #[test]
    fn unknown_liquid_outspend_mutates_nothing_and_never_broadcasts() {
        let mut blocked = claimable_evidence();
        blocked.liquid_lock = LiquidLockEvidence::UnknownOutspend;
        let (gate, mutations) = simulate_two_gate_claim(&blocked, &blocked, false);
        assert_eq!(
            gate,
            ChainSwapExecutionGate::Blocked(ChainSwapAction::IntegrityHold)
        );
        assert_eq!(mutations, ClaimMutationCounts::default());
    }

    #[test]
    fn duplicate_restart_replays_only_exact_prepared_claim() {
        let mut prepared = claimable_evidence();
        prepared.liquid_claim_transaction = MerchantTransactionEvidence::Prepared;

        for _duplicate in 0..2 {
            let (gate, mutations) = simulate_two_gate_claim(&prepared, &prepared, true);
            assert_eq!(gate, ChainSwapExecutionGate::Authorized);
            assert_eq!(mutations.constructed, 0);
            assert_eq!(mutations.journaled, 0);
            assert_eq!(mutations.broadcast, 1);
        }
    }

    #[test]
    fn commitment_npub_is_bound_to_invoice_owner_not_the_nym_alias() {
        let owner = ("02merchant".to_owned(), Some("merchant-name".to_owned()));
        assert!(recovery_owner_matches_invoice(
            "02merchant",
            Some("merchant-name"),
            Some(&owner),
        ));
        assert!(!recovery_owner_matches_invoice(
            "merchant-name",
            Some("merchant-name"),
            Some(&owner),
        ));
        assert!(!recovery_owner_matches_invoice(
            "02merchant",
            Some("other-name"),
            Some(&owner),
        ));
    }

    #[test]
    fn automatic_packet_requires_the_complete_execution_shape() {
        let mut packet = CollectedAutomaticFallbackEvidence {
            evidence: automatic_candidate(),
            committed_destination: Some(
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0".into(),
            ),
            exact_sources: vec![AutomaticFallbackSource {
                txid: "11".repeat(32),
                vout: 0,
            }],
            bitcoin_timeout_height: Some(840_000),
            dependencies_available: true,
        };
        assert!(packet.authorizes_automatic_recovery());

        packet.exact_sources.clear();
        assert!(!packet.authorizes_automatic_recovery());
        packet.exact_sources.push(AutomaticFallbackSource {
            txid: "11".repeat(32),
            vout: 0,
        });
        packet.evidence.renegotiation = RenegotiationEvidence::Ambiguous;
        assert!(!packet.authorizes_automatic_recovery());
        packet.evidence.renegotiation = RenegotiationEvidence::NotRequired;
        packet.dependencies_available = false;
        assert!(!packet.authorizes_automatic_recovery());
    }
}

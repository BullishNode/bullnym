//! Fresh, schema-free evidence assembly for the pending provider-expiry path.
//!
//! This module reads only one immutable chain-swap target. It neither scans a
//! wallet/address range nor persists funding allocations. Provider status and
//! transaction ids remain outside the source facts assembled here.

use boltz_client::network::LiquidChain;
use boltz_client::swaps::boltz::{CreateChainResponse, Side};
use boltz_client::swaps::liquid::LBtcSwapScript;
use boltz_client::Keypair;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;

use crate::chain_swap_action::{
    BitcoinSourceEvidence, BitcoinTimeoutEvidence, ChainSwapEvidence, CooperativeRecoveryEvidence,
    EvidenceQuality, LiquidLockEvidence, LiquidPathEvidence, MerchantTransactionEvidence,
    ProviderStatusEvidence, RecoveryDestinationEvidence, RenegotiationEvidence,
};
use crate::chain_swap_primary_source::{
    project_primary_bitcoin_source_snapshot_v1, PrimaryBitcoinSourceAuthorityV1,
    PrimaryBitcoinSourceProjectionV1, PrimaryBitcoinSourceTargetV1,
};
use crate::db::{self, ChainSwapRecord, ChainSwapTxAttempt};
use crate::error::AppError;
use crate::utxo::LiquidScriptHistory;
use crate::AppState;

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

    #[test]
    fn recovery_attempt_ambiguity_never_looks_absent_or_final() {
        assert_eq!(
            recovery_transaction_evidence(None),
            MerchantTransactionEvidence::None
        );
    }
}

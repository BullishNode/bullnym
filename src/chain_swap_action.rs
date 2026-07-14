//! Pure chain-swap evidence reduction.
//!
//! This module deliberately performs no I/O and owns no persistence. Webhook,
//! reconciliation, chain-watcher, and execution code can translate their
//! independently verified facts into [`ChainSwapEvidence`] and receive one
//! action. In particular, provider status is only a hint: it cannot settle a
//! funded swap, and an action is never authorized from evidence that is
//! ambiguous or disagreeing at the facts that action depends on.

use crate::merchant_settlement_lifecycle::{
    MerchantSettlementLifecycle, SettlementAccountingState, SettlementState,
};

/// The only actions the chain-swap evidence reducer can authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapAction {
    Observe,
    ClaimLiquid,
    Renegotiate,
    WaitForBitcoinTimeout,
    RecoverBitcoin,
    WatchTransaction,
    Finalize,
    IntegrityHold,
}

/// Whether every fact needed by this reduction came from a complete,
/// internally consistent evidence snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceQuality {
    CompleteAndAgreed,
    Incomplete,
    BackendDisagreement,
    ProviderDisagreement,
}

/// Provider lifecycle evidence. This remains a hint rather than settlement
/// authority. `Expired` is useful only to retire a swap whose source-chain
/// scan independently proves that it was never funded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderStatusEvidence {
    Unknown,
    Active,
    Expired,
    SettlementHint,
}

/// Authoritative Bitcoin user-lock evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinSourceEvidence {
    Unknown,
    Unfunded,
    MempoolUnspent,
    ConfirmedUnspent,
    SpentByProviderWithPreimage,
    SpentByRecoveryTransaction,
    UnknownOutspend,
}

/// Authoritative Liquid server-lock evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidLockEvidence {
    Unknown,
    NotObserved,
    MempoolUnspent,
    ConfirmedUnspent,
    SpentByMerchantClaim,
    SpentByProviderRefund,
    UnknownOutspend,
}

/// Whether the original Liquid path can still safely produce a server lock.
/// A temporarily absent lock is `Viable` or `Unknown`, never `Unavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidPathEvidence {
    Unknown,
    Viable,
    Unavailable,
}

/// Durable renegotiation evidence. Transport errors and timeouts are
/// `Ambiguous`, not `Unavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenegotiationEvidence {
    /// Positive protocol facts prove renegotiation does not apply to this
    /// failure. This is distinct from a missing quote or transport error.
    NotRequired,
    Available,
    Requested,
    AcceptedAwaitingLock,
    ExplicitlyUnavailable,
    Ambiguous,
}

/// Evidence that the immutable Bitcoin fallback destination is safe to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDestinationEvidence {
    Committed,
    Missing,
    Disputed,
}

/// Whether cooperative Bitcoin recovery is positively known to be available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooperativeRecoveryEvidence {
    Unknown,
    Available,
    Unavailable,
}

/// Evidence relative to the immutable Bitcoin script timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinTimeoutEvidence {
    Unknown,
    BeforeTimeout,
    Reached,
}

/// Lifecycle of a transaction that pays the immutable merchant destination.
///
/// Confirmation/finality and exact-output validation belong to the chain
/// evidence producer. The reducer consumes their conclusions without
/// reinterpreting transaction bytes or confirmation counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerchantTransactionEvidence {
    None,
    Prepared,
    Broadcast,
    Mempool,
    Confirmed,
    Finalized,
    Disputed,
    MerchantOutputMismatch,
}

impl MerchantTransactionEvidence {
    /// Translate the validated merchant-settlement lifecycle into reducer
    /// evidence. A demoted lifecycle remains disputed until independently
    /// verified confirmation reactivates its accounting state; merely seeing
    /// it broadcast or in mempool again cannot authorize settlement or a
    /// competing fallback.
    pub fn from_settlement_lifecycle(lifecycle: &MerchantSettlementLifecycle) -> Self {
        if lifecycle.accounting_state() == SettlementAccountingState::Demoted {
            return Self::Disputed;
        }

        match lifecycle.state() {
            SettlementState::Constructed => Self::Prepared,
            SettlementState::Broadcast => Self::Broadcast,
            SettlementState::Mempool => Self::Mempool,
            SettlementState::Confirmed { .. } => Self::Confirmed,
            SettlementState::Finalized { .. } => Self::Finalized,
            SettlementState::Replaced { .. }
            | SettlementState::Evicted
            | SettlementState::Reorged { .. } => Self::Disputed,
        }
    }

    const fn is_present(self) -> bool {
        !matches!(self, Self::None)
    }

    const fn observed_action(self) -> Option<ChainSwapAction> {
        match self {
            Self::Broadcast | Self::Mempool | Self::Confirmed => {
                Some(ChainSwapAction::WatchTransaction)
            }
            Self::Finalized => Some(ChainSwapAction::Finalize),
            Self::None | Self::Prepared | Self::Disputed | Self::MerchantOutputMismatch => None,
        }
    }
}

/// One coherent, per-swap evidence snapshot.
///
/// Callers must build this from one reduction boundary. Mixing a stale
/// provider read with a newer chain read is `Incomplete` or a disagreement,
/// not `CompleteAndAgreed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSwapEvidence {
    pub quality: EvidenceQuality,
    pub provider_status: ProviderStatusEvidence,
    pub bitcoin_source: BitcoinSourceEvidence,
    pub liquid_lock: LiquidLockEvidence,
    pub liquid_path: LiquidPathEvidence,
    pub renegotiation: RenegotiationEvidence,
    pub recovery_destination: RecoveryDestinationEvidence,
    pub cooperative_recovery: CooperativeRecoveryEvidence,
    pub bitcoin_timeout: BitcoinTimeoutEvidence,
    pub liquid_claim_transaction: MerchantTransactionEvidence,
    pub bitcoin_recovery_transaction: MerchantTransactionEvidence,
}

/// Irreversible action a runtime path intends to execute after acquiring the
/// shared per-swap advisory lock.
///
/// Keeping this narrower than [`ChainSwapAction`] prevents observation,
/// renegotiation, and transaction-watching decisions from being mistaken for
/// execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapExecutionAction {
    ClaimLiquid,
    RecoverBitcoin,
    Finalize,
}

impl ChainSwapExecutionAction {
    /// Reducer action that must still be current at the under-lock recheck.
    pub const fn reducer_action(self) -> ChainSwapAction {
        match self {
            Self::ClaimLiquid => ChainSwapAction::ClaimLiquid,
            Self::RecoverBitcoin => ChainSwapAction::RecoverBitcoin,
            Self::Finalize => ChainSwapAction::Finalize,
        }
    }
}

/// Result of the mandatory complete-evidence recheck while the shared
/// per-swap execution lock is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapExecutionGate {
    Authorized,
    Blocked(ChainSwapAction),
}

/// Backwards-compatible name for the original recovery-only gate result.
pub type RecoveryExecutionGate = ChainSwapExecutionGate;

/// Reduce independently verified evidence to one forward-safe action.
pub fn reduce_chain_swap_evidence(evidence: &ChainSwapEvidence) -> ChainSwapAction {
    use BitcoinSourceEvidence as BitcoinSource;
    use ChainSwapAction as Action;
    use LiquidLockEvidence as LiquidLock;
    use MerchantTransactionEvidence as Transaction;

    // An unknown spend or a transaction paying the wrong output is a positive
    // integrity hazard even if the rest of the snapshot is incomplete.
    if matches!(evidence.bitcoin_source, BitcoinSource::UnknownOutspend)
        || matches!(evidence.liquid_lock, LiquidLock::UnknownOutspend)
        || matches!(
            evidence.liquid_claim_transaction,
            Transaction::MerchantOutputMismatch
        )
        || matches!(
            evidence.bitcoin_recovery_transaction,
            Transaction::MerchantOutputMismatch
        )
    {
        return Action::IntegrityHold;
    }

    // Once both mutually exclusive merchant-payment paths have transaction
    // intent, guessing which one can still execute risks a double settlement.
    if evidence.liquid_claim_transaction.is_present()
        && evidence.bitcoin_recovery_transaction.is_present()
    {
        return Action::IntegrityHold;
    }

    if evidence.quality != EvidenceQuality::CompleteAndAgreed
        || matches!(evidence.liquid_claim_transaction, Transaction::Disputed)
        || matches!(evidence.bitcoin_recovery_transaction, Transaction::Disputed)
    {
        return Action::Observe;
    }

    // `CompleteAndAgreed` is not allowed to paper over an unknown chain
    // field. A caller must supply an actual classification for both swap
    // outputs before the reducer can authorize or finalize an action.
    if matches!(evidence.bitcoin_source, BitcoinSource::Unknown)
        || matches!(evidence.liquid_lock, LiquidLock::Unknown)
    {
        return Action::Observe;
    }

    // Mempool/confirmed/finalized transaction evidence must agree with the
    // relevant outspend classification in the same snapshot. Broadcast alone
    // may legitimately precede an observed outspend.
    if transaction_requires_observed_spend(evidence.liquid_claim_transaction)
        && evidence.liquid_lock != LiquidLock::SpentByMerchantClaim
    {
        return Action::IntegrityHold;
    }
    if transaction_requires_observed_spend(evidence.bitcoin_recovery_transaction)
        && evidence.bitcoin_source != BitcoinSource::SpentByRecoveryTransaction
    {
        return Action::IntegrityHold;
    }

    // A classified spend must have its matching, validated transaction
    // evidence in the same complete snapshot. Otherwise the classification is
    // not safe authority for settlement.
    if matches!(
        evidence.bitcoin_source,
        BitcoinSource::SpentByRecoveryTransaction
    ) && matches!(evidence.bitcoin_recovery_transaction, Transaction::None)
    {
        return Action::IntegrityHold;
    }
    if matches!(evidence.liquid_lock, LiquidLock::SpentByMerchantClaim)
        && matches!(evidence.liquid_claim_transaction, Transaction::None)
    {
        return Action::IntegrityHold;
    }

    // A transaction on either merchant path wins over provider status and
    // ordinary path selection. Broadcast is never final: keep watching until
    // the chain-evidence producer reports configured finality.
    if let Some(action) = evidence.liquid_claim_transaction.observed_action() {
        if matches!(
            evidence.bitcoin_source,
            BitcoinSource::SpentByRecoveryTransaction
        ) || matches!(evidence.liquid_lock, LiquidLock::SpentByProviderRefund)
        {
            return Action::IntegrityHold;
        }
        return action;
    }
    if let Some(action) = evidence.bitcoin_recovery_transaction.observed_action() {
        if matches!(
            evidence.bitcoin_source,
            BitcoinSource::SpentByProviderWithPreimage
        ) || matches!(evidence.liquid_lock, LiquidLock::SpentByMerchantClaim)
        {
            return Action::IntegrityHold;
        }
        return action;
    }

    // A prepared Liquid claim is safe to re-drive only while its server lock
    // is still positively observed unspent.
    if matches!(evidence.liquid_claim_transaction, Transaction::Prepared) {
        return if liquid_lock_is_unspent(evidence.liquid_lock)
            && !matches!(
                evidence.bitcoin_source,
                BitcoinSource::SpentByRecoveryTransaction
            ) {
            Action::ClaimLiquid
        } else if matches!(
            evidence.liquid_lock,
            LiquidLock::Unknown | LiquidLock::NotObserved
        ) {
            Action::Observe
        } else {
            Action::IntegrityHold
        };
    }

    // Persisted recovery bytes are still live intent even before broadcast.
    // If fresh under-lock evidence makes the normal Liquid path viable, stop
    // instead of broadcasting the recovery or starting a competing claim.
    if matches!(evidence.bitcoin_recovery_transaction, Transaction::Prepared) {
        if evidence.bitcoin_source != BitcoinSource::ConfirmedUnspent
            || liquid_lock_is_unspent(evidence.liquid_lock)
            || matches!(evidence.liquid_lock, LiquidLock::SpentByMerchantClaim)
        {
            return Action::IntegrityHold;
        }
        return reduce_confirmed_unspent(evidence);
    }

    // A server lock remains claimable regardless of provider expiry.
    if liquid_lock_is_unspent(evidence.liquid_lock) {
        if matches!(
            evidence.bitcoin_source,
            BitcoinSource::SpentByRecoveryTransaction
        ) {
            return Action::IntegrityHold;
        }
        return Action::ClaimLiquid;
    }

    // Spending the Bitcoin source with the preimage is not merchant success.
    // With no known/claimable Liquid settlement remaining in a complete
    // snapshot, the obligation must stop on an integrity hold.
    if matches!(
        evidence.bitcoin_source,
        BitcoinSource::SpentByProviderWithPreimage
    ) {
        return Action::IntegrityHold;
    }

    if matches!(
        evidence.bitcoin_source,
        BitcoinSource::SpentByRecoveryTransaction
    ) {
        // The matching transaction was required above and would already have
        // returned WatchTransaction/Finalize. Reaching here means its lifecycle
        // was only Prepared and cannot explain the observed spend.
        return Action::IntegrityHold;
    }

    match evidence.bitcoin_source {
        BitcoinSource::Unknown | BitcoinSource::MempoolUnspent => Action::Observe,
        BitcoinSource::Unfunded => reduce_unfunded(evidence),
        BitcoinSource::ConfirmedUnspent => reduce_confirmed_unspent(evidence),
        BitcoinSource::SpentByProviderWithPreimage
        | BitcoinSource::SpentByRecoveryTransaction
        | BitcoinSource::UnknownOutspend => {
            unreachable!("spent Bitcoin source evidence returned above")
        }
    }
}

/// Re-run the reducer on a complete evidence snapshot assembled after the
/// caller acquired the shared per-swap advisory lock.
///
/// Only the exact irreversible action requested by the caller is authorized.
/// Every other current decision is returned to the dispatcher without
/// executing stale work. In particular, unknown outspends remain the
/// reducer's [`ChainSwapAction::IntegrityHold`] and close this gate.
pub fn recheck_chain_swap_execution_under_lock(
    requested: ChainSwapExecutionAction,
    evidence: &ChainSwapEvidence,
) -> ChainSwapExecutionGate {
    let action = reduce_chain_swap_evidence(evidence);
    if action == requested.reducer_action() {
        ChainSwapExecutionGate::Authorized
    } else {
        ChainSwapExecutionGate::Blocked(action)
    }
}

/// Recovery-specific compatibility wrapper for callers that have not yet
/// adopted the shared irreversible-action gate.
pub fn recheck_recovery_under_lock(evidence: &ChainSwapEvidence) -> RecoveryExecutionGate {
    recheck_chain_swap_execution_under_lock(ChainSwapExecutionAction::RecoverBitcoin, evidence)
}

const fn liquid_lock_is_unspent(lock: LiquidLockEvidence) -> bool {
    matches!(
        lock,
        LiquidLockEvidence::MempoolUnspent | LiquidLockEvidence::ConfirmedUnspent
    )
}

const fn transaction_requires_observed_spend(transaction: MerchantTransactionEvidence) -> bool {
    matches!(
        transaction,
        MerchantTransactionEvidence::Mempool
            | MerchantTransactionEvidence::Confirmed
            | MerchantTransactionEvidence::Finalized
    )
}

fn reduce_unfunded(evidence: &ChainSwapEvidence) -> ChainSwapAction {
    use ChainSwapAction as Action;
    use LiquidLockEvidence as LiquidLock;

    // Provider expiry alone is insufficient. A complete source-chain scan must
    // also prove no user lock, and no merchant settlement may be in flight.
    if evidence.provider_status == ProviderStatusEvidence::Expired
        && matches!(
            evidence.liquid_lock,
            LiquidLock::NotObserved | LiquidLock::SpentByProviderRefund
        )
    {
        Action::Finalize
    } else {
        Action::Observe
    }
}

fn reduce_confirmed_unspent(evidence: &ChainSwapEvidence) -> ChainSwapAction {
    use ChainSwapAction as Action;
    use LiquidLockEvidence as LiquidLock;
    use MerchantTransactionEvidence as Transaction;
    use RenegotiationEvidence as Renegotiation;

    match evidence.liquid_lock {
        LiquidLock::SpentByProviderRefund => {}
        LiquidLock::NotObserved => match evidence.liquid_path {
            LiquidPathEvidence::Unavailable => {}
            LiquidPathEvidence::Unknown | LiquidPathEvidence::Viable => return Action::Observe,
        },
        LiquidLock::Unknown => return Action::Observe,
        LiquidLock::MempoolUnspent | LiquidLock::ConfirmedUnspent => {
            unreachable!("unspent Liquid locks returned before fallback reduction")
        }
        LiquidLock::SpentByMerchantClaim | LiquidLock::UnknownOutspend => {
            unreachable!("Liquid outspends returned before fallback reduction")
        }
    }

    if evidence.provider_status == ProviderStatusEvidence::SettlementHint {
        return Action::Observe;
    }

    match evidence.renegotiation {
        Renegotiation::Available => return Action::Renegotiate,
        Renegotiation::Requested
        | Renegotiation::AcceptedAwaitingLock
        | Renegotiation::Ambiguous => return Action::Observe,
        Renegotiation::NotRequired | Renegotiation::ExplicitlyUnavailable => {}
    }

    // An active/settled provider hint cannot prove merchant settlement, but it
    // does make immediate fallback unsafe until the disagreement is resolved.
    if matches!(evidence.provider_status, ProviderStatusEvidence::Active) {
        return Action::Observe;
    }

    if evidence.recovery_destination != RecoveryDestinationEvidence::Committed {
        return Action::IntegrityHold;
    }

    let recovery_action = match evidence.cooperative_recovery {
        CooperativeRecoveryEvidence::Available => Action::RecoverBitcoin,
        CooperativeRecoveryEvidence::Unknown => Action::Observe,
        CooperativeRecoveryEvidence::Unavailable => match evidence.bitcoin_timeout {
            BitcoinTimeoutEvidence::BeforeTimeout => Action::WaitForBitcoinTimeout,
            BitcoinTimeoutEvidence::Reached => Action::RecoverBitcoin,
            BitcoinTimeoutEvidence::Unknown => Action::Observe,
        },
    };

    if matches!(evidence.bitcoin_recovery_transaction, Transaction::Prepared)
        && recovery_action != Action::RecoverBitcoin
    {
        // A now-stale prepared recovery must be reconciled explicitly before
        // another path can execute. Never silently repurpose or ignore it.
        return if recovery_action == Action::Observe {
            Action::Observe
        } else {
            Action::IntegrityHold
        };
    }

    recovery_action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merchant_settlement_lifecycle::{
        apply_settlement_evidence, SettlementBlock, SettlementChain, SettlementEvidence,
        SettlementFinalityPolicy, SettlementTxid,
    };

    fn txid(character: char) -> SettlementTxid {
        SettlementTxid::parse(&character.to_string().repeat(64)).unwrap()
    }

    fn block(height: u32, character: char) -> SettlementBlock {
        SettlementBlock::new(height, &character.to_string().repeat(64)).unwrap()
    }

    fn advance(
        lifecycle: &MerchantSettlementLifecycle,
        evidence: SettlementEvidence,
    ) -> MerchantSettlementLifecycle {
        apply_settlement_evidence(lifecycle, &evidence, SettlementFinalityPolicy::default())
            .unwrap()
            .lifecycle
    }

    fn recovery_candidate() -> ChainSwapEvidence {
        ChainSwapEvidence {
            quality: EvidenceQuality::CompleteAndAgreed,
            provider_status: ProviderStatusEvidence::Expired,
            bitcoin_source: BitcoinSourceEvidence::ConfirmedUnspent,
            liquid_lock: LiquidLockEvidence::NotObserved,
            liquid_path: LiquidPathEvidence::Unavailable,
            renegotiation: RenegotiationEvidence::ExplicitlyUnavailable,
            recovery_destination: RecoveryDestinationEvidence::Committed,
            cooperative_recovery: CooperativeRecoveryEvidence::Available,
            bitcoin_timeout: BitcoinTimeoutEvidence::BeforeTimeout,
            liquid_claim_transaction: MerchantTransactionEvidence::None,
            bitcoin_recovery_transaction: MerchantTransactionEvidence::None,
        }
    }

    fn finalized_liquid_lifecycle() -> MerchantSettlementLifecycle {
        let lifecycle = MerchantSettlementLifecycle::new(SettlementChain::Liquid, txid('1'));
        let confirmed = advance(
            &lifecycle,
            SettlementEvidence::Confirmed {
                txid: txid('1'),
                block: block(100, 'a'),
                confirmations: 1,
            },
        );
        advance(
            &confirmed,
            SettlementEvidence::Finalized {
                txid: txid('1'),
                block: block(100, 'a'),
                confirmations: 2,
            },
        )
    }

    #[test]
    fn lifecycle_mapping_drives_broadcast_confirmed_and_finalized_actions() {
        let lifecycle = MerchantSettlementLifecycle::new(SettlementChain::Liquid, txid('1'));
        assert_eq!(
            MerchantTransactionEvidence::from_settlement_lifecycle(&lifecycle),
            MerchantTransactionEvidence::Prepared
        );

        let broadcast = advance(
            &lifecycle,
            SettlementEvidence::Broadcast { txid: txid('1') },
        );
        let mut evidence = recovery_candidate();
        evidence.liquid_lock = LiquidLockEvidence::ConfirmedUnspent;
        evidence.liquid_claim_transaction =
            MerchantTransactionEvidence::from_settlement_lifecycle(&broadcast);
        assert_eq!(
            evidence.liquid_claim_transaction,
            MerchantTransactionEvidence::Broadcast
        );
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            ChainSwapAction::WatchTransaction
        );

        let confirmed = advance(
            &broadcast,
            SettlementEvidence::Confirmed {
                txid: txid('1'),
                block: block(100, 'a'),
                confirmations: 1,
            },
        );
        evidence.liquid_lock = LiquidLockEvidence::SpentByMerchantClaim;
        evidence.liquid_claim_transaction =
            MerchantTransactionEvidence::from_settlement_lifecycle(&confirmed);
        assert_eq!(
            evidence.liquid_claim_transaction,
            MerchantTransactionEvidence::Confirmed
        );
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            ChainSwapAction::WatchTransaction
        );

        let finalized = advance(
            &confirmed,
            SettlementEvidence::Finalized {
                txid: txid('1'),
                block: block(100, 'a'),
                confirmations: 2,
            },
        );
        evidence.liquid_claim_transaction =
            MerchantTransactionEvidence::from_settlement_lifecycle(&finalized);
        assert_eq!(
            evidence.liquid_claim_transaction,
            MerchantTransactionEvidence::Finalized
        );
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            ChainSwapAction::Finalize
        );
    }

    #[test]
    fn replacement_eviction_and_reorg_demotion_block_finality_and_fallback() {
        let finalized = finalized_liquid_lifecycle();
        let replaced = advance(
            &finalized,
            SettlementEvidence::Replaced {
                replaced_txid: txid('1'),
                replacement_txid: txid('2'),
            },
        );
        let evicted = advance(&finalized, SettlementEvidence::Evicted { txid: txid('1') });
        let reorged = advance(
            &finalized,
            SettlementEvidence::Reorged {
                txid: txid('1'),
                previous_block: block(100, 'a'),
            },
        );
        let rebroadcast_after_reorg =
            advance(&reorged, SettlementEvidence::Broadcast { txid: txid('1') });
        let mempool_after_eviction =
            advance(&evicted, SettlementEvidence::Mempool { txid: txid('1') });

        for (name, lifecycle) in [
            ("replaced", replaced),
            ("evicted", evicted),
            ("reorged", reorged),
            ("rebroadcast after reorg", rebroadcast_after_reorg),
            ("mempool after eviction", mempool_after_eviction),
        ] {
            assert_eq!(
                lifecycle.accounting_state(),
                SettlementAccountingState::Demoted,
                "{name}"
            );
            let mapped = MerchantTransactionEvidence::from_settlement_lifecycle(&lifecycle);
            assert_eq!(mapped, MerchantTransactionEvidence::Disputed, "{name}");

            let mut evidence = recovery_candidate();
            evidence.liquid_claim_transaction = mapped;
            assert_eq!(
                reduce_chain_swap_evidence(&evidence),
                ChainSwapAction::Observe,
                "{name}"
            );
            assert_eq!(
                recheck_recovery_under_lock(&evidence),
                RecoveryExecutionGate::Blocked(ChainSwapAction::Observe),
                "{name}"
            );
        }
    }
}

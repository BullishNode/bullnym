//! Pure chain-swap evidence reduction.
//!
//! This module deliberately performs no I/O and owns no persistence. Webhook,
//! reconciliation, chain-watcher, and execution code can translate their
//! independently verified facts into [`ChainSwapEvidence`] and receive one
//! action. In particular, provider status is only a hint: it cannot settle a
//! funded swap, and an action is never authorized from evidence that is
//! ambiguous or disagreeing at the facts that action depends on.

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

/// Result of the mandatory fallback recheck while the per-swap execution lock
/// is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryExecutionGate {
    Authorized,
    Blocked(ChainSwapAction),
}

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

/// Re-run the reducer on evidence read while the per-swap execution lock is
/// held. Only an unchanged `RecoverBitcoin` decision authorizes construction
/// or broadcast; every other action sends the caller back through normal
/// planning without executing fallback.
pub fn recheck_recovery_under_lock(evidence: &ChainSwapEvidence) -> RecoveryExecutionGate {
    let action = reduce_chain_swap_evidence(evidence);
    if action == ChainSwapAction::RecoverBitcoin {
        RecoveryExecutionGate::Authorized
    } else {
        RecoveryExecutionGate::Blocked(action)
    }
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

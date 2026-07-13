//! Pure merchant-output settlement lifecycle reduction.
//!
//! Chain adapters persist the returned state and effects atomically. This
//! module performs no I/O and deliberately cannot create an accounting amount:
//! `activate_accounting` authorizes a caller to consume the already verified
//! merchant output's actual value exactly once.

use std::{fmt, num::NonZeroU32};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementChain {
    Liquid,
    Bitcoin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementFinalityPolicyError {
    LiquidMustBeNonzero,
    BitcoinMustBeNonzero,
}

impl fmt::Display for SettlementFinalityPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LiquidMustBeNonzero => "Liquid finality must be nonzero",
            Self::BitcoinMustBeNonzero => "Bitcoin finality must be nonzero",
        })
    }
}

impl std::error::Error for SettlementFinalityPolicyError {}

/// Validated finality configuration. Accounting activates at one confirmation;
/// these thresholds control the later operational-finality promotion only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementFinalityPolicy {
    liquid: NonZeroU32,
    bitcoin: NonZeroU32,
}

impl SettlementFinalityPolicy {
    pub fn new(liquid: u32, bitcoin: u32) -> Result<Self, SettlementFinalityPolicyError> {
        let liquid =
            NonZeroU32::new(liquid).ok_or(SettlementFinalityPolicyError::LiquidMustBeNonzero)?;
        let bitcoin =
            NonZeroU32::new(bitcoin).ok_or(SettlementFinalityPolicyError::BitcoinMustBeNonzero)?;
        Ok(Self { liquid, bitcoin })
    }

    pub const fn required(self, chain: SettlementChain) -> u32 {
        match chain {
            SettlementChain::Liquid => self.liquid.get(),
            SettlementChain::Bitcoin => self.bitcoin.get(),
        }
    }

    pub const fn liquid_confirmations(self) -> u32 {
        self.liquid.get()
    }

    pub const fn bitcoin_confirmations(self) -> u32 {
        self.bitcoin.get()
    }
}

impl Default for SettlementFinalityPolicy {
    fn default() -> Self {
        Self {
            liquid: NonZeroU32::new(2).expect("two is nonzero"),
            bitcoin: NonZeroU32::new(3).expect("three is nonzero"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SettlementTxid(String);

impl SettlementTxid {
    pub fn parse(value: &str) -> Result<Self, SettlementLifecycleError> {
        canonical_hash(value)
            .map(Self)
            .ok_or(SettlementLifecycleError::InvalidTransactionId)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementBlock {
    height: u32,
    hash: String,
}

impl SettlementBlock {
    pub fn new(height: u32, hash: &str) -> Result<Self, SettlementLifecycleError> {
        if height == 0 {
            return Err(SettlementLifecycleError::InvalidBlockHeight);
        }
        Ok(Self {
            height,
            hash: canonical_hash(hash).ok_or(SettlementLifecycleError::InvalidBlockHash)?,
        })
    }

    pub const fn height(&self) -> u32 {
        self.height
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementState {
    Constructed,
    Broadcast,
    Mempool,
    Confirmed {
        block: SettlementBlock,
        confirmations: u32,
        required_confirmations: u32,
    },
    Finalized {
        block: SettlementBlock,
        confirmations: u32,
        required_confirmations: u32,
    },
    Replaced {
        replaced_txid: SettlementTxid,
        replacement_txid: SettlementTxid,
    },
    Evicted,
    Reorged {
        previous_block: SettlementBlock,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementAccountingState {
    Unrecorded,
    Confirmed,
    Finalized,
    Demoted,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettlementEvidenceHistory {
    pub constructed: bool,
    pub broadcast: bool,
    pub mempool: bool,
    pub confirmed: bool,
    pub finalized: bool,
    pub replaced: bool,
    pub evicted: bool,
    pub reorged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerchantSettlementLifecycle {
    chain: SettlementChain,
    journal_txid: SettlementTxid,
    active_txid: SettlementTxid,
    state: SettlementState,
    accounting: SettlementAccountingState,
    history: SettlementEvidenceHistory,
    linked_replacement: Option<(SettlementTxid, SettlementTxid)>,
    last_confirmed_block: Option<SettlementBlock>,
    last_reorged_block: Option<SettlementBlock>,
}

impl MerchantSettlementLifecycle {
    pub fn new(chain: SettlementChain, journal_txid: SettlementTxid) -> Self {
        Self {
            chain,
            active_txid: journal_txid.clone(),
            journal_txid,
            state: SettlementState::Constructed,
            accounting: SettlementAccountingState::Unrecorded,
            history: SettlementEvidenceHistory {
                constructed: true,
                ..SettlementEvidenceHistory::default()
            },
            linked_replacement: None,
            last_confirmed_block: None,
            last_reorged_block: None,
        }
    }

    pub const fn chain(&self) -> SettlementChain {
        self.chain
    }

    pub fn journal_txid(&self) -> &SettlementTxid {
        &self.journal_txid
    }

    pub fn active_txid(&self) -> &SettlementTxid {
        &self.active_txid
    }

    pub fn state(&self) -> &SettlementState {
        &self.state
    }

    pub const fn accounting_state(&self) -> SettlementAccountingState {
        self.accounting
    }

    pub const fn history(&self) -> SettlementEvidenceHistory {
        self.history
    }

    pub fn linked_replacement(&self) -> Option<(&SettlementTxid, &SettlementTxid)> {
        self.linked_replacement
            .as_ref()
            .map(|(parent, child)| (parent, child))
    }

    pub fn last_confirmed_block(&self) -> Option<&SettlementBlock> {
        self.last_confirmed_block.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementEvidence {
    Constructed {
        txid: SettlementTxid,
    },
    Broadcast {
        txid: SettlementTxid,
    },
    Mempool {
        txid: SettlementTxid,
    },
    Confirmed {
        txid: SettlementTxid,
        block: SettlementBlock,
        confirmations: u32,
    },
    Finalized {
        txid: SettlementTxid,
        block: SettlementBlock,
        confirmations: u32,
    },
    Replaced {
        replaced_txid: SettlementTxid,
        replacement_txid: SettlementTxid,
    },
    Evicted {
        txid: SettlementTxid,
    },
    Reorged {
        txid: SettlementTxid,
        previous_block: SettlementBlock,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettlementTransitionEffects {
    /// Insert the active transaction's verified actual-value output for the
    /// first confirmed member of this lifecycle.
    pub activate_accounting: bool,
    /// Re-activate confirmed accounting after demotion. Persistence keys this
    /// by the active `(txid, vout)`: after a linked replacement this therefore
    /// creates/activates the replacement's distinct output event rather than
    /// mutating the original transaction identity.
    pub reactivate_accounting: bool,
    pub finalize_accounting: bool,
    pub demote_accounting: bool,
    pub redrive_observation: bool,
    pub rebroadcast_journaled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementTransition {
    pub lifecycle: MerchantSettlementLifecycle,
    pub effects: SettlementTransitionEffects,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementLifecycleError {
    InvalidTransactionId,
    InvalidBlockHeight,
    InvalidBlockHash,
    WrongTransaction {
        expected: SettlementTxid,
        observed: SettlementTxid,
    },
    ReplacementUsesSameTransaction,
    ConflictingReplacement,
    ZeroConfirmations,
    PrematureFinality {
        confirmations: u32,
        required_confirmations: u32,
    },
    ConflictingConfirmationBlock,
    ReorgRequiresConfirmedEvidence,
    ReorgBlockMismatch,
    ReconfirmationUsesReorgedBlock,
}

impl fmt::Display for SettlementLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("merchant settlement lifecycle evidence rejected")
    }
}

impl std::error::Error for SettlementLifecycleError {}

/// Apply one independently verified observation. Duplicate and stale forward
/// observations are safe no-ops. Only explicit eviction/reorg evidence may
/// demote accounting, and both return an observation-redrive effect.
pub fn apply_settlement_evidence(
    current: &MerchantSettlementLifecycle,
    evidence: &SettlementEvidence,
    policy: SettlementFinalityPolicy,
) -> Result<SettlementTransition, SettlementLifecycleError> {
    let mut next = current.clone();
    let mut effects = SettlementTransitionEffects::default();

    match evidence {
        SettlementEvidence::Constructed { txid } => {
            require_active(&next, txid)?;
            next.history.constructed = true;
        }
        SettlementEvidence::Broadcast { txid } => {
            require_active(&next, txid)?;
            next.history.broadcast = true;
            if matches!(
                next.state,
                SettlementState::Constructed
                    | SettlementState::Evicted
                    | SettlementState::Reorged { .. }
            ) {
                next.state = SettlementState::Broadcast;
            }
        }
        SettlementEvidence::Mempool { txid } => {
            require_active(&next, txid)?;
            next.history.mempool = true;
            if !matches!(
                next.state,
                SettlementState::Confirmed { .. } | SettlementState::Finalized { .. }
            ) {
                next.state = SettlementState::Mempool;
            }
        }
        SettlementEvidence::Confirmed {
            txid,
            block,
            confirmations,
        } => apply_confirmation(
            &mut next,
            txid,
            block,
            *confirmations,
            false,
            policy,
            &mut effects,
        )?,
        SettlementEvidence::Finalized {
            txid,
            block,
            confirmations,
        } => apply_confirmation(
            &mut next,
            txid,
            block,
            *confirmations,
            true,
            policy,
            &mut effects,
        )?,
        SettlementEvidence::Replaced {
            replaced_txid,
            replacement_txid,
        } => {
            if replaced_txid == replacement_txid {
                return Err(SettlementLifecycleError::ReplacementUsesSameTransaction);
            }
            if let Some((parent, child)) = &next.linked_replacement {
                if parent != replaced_txid || child != replacement_txid {
                    return Err(SettlementLifecycleError::ConflictingReplacement);
                }
                return Ok(SettlementTransition {
                    lifecycle: next,
                    effects,
                });
            }
            require_active(&next, replaced_txid)?;
            next.history.replaced = true;
            next.linked_replacement = Some((replaced_txid.clone(), replacement_txid.clone()));
            if matches!(
                next.accounting,
                SettlementAccountingState::Confirmed | SettlementAccountingState::Finalized
            ) {
                next.accounting = SettlementAccountingState::Demoted;
                effects.demote_accounting = true;
            }
            next.active_txid = replacement_txid.clone();
            next.state = SettlementState::Replaced {
                replaced_txid: replaced_txid.clone(),
                replacement_txid: replacement_txid.clone(),
            };
            effects.redrive_observation = true;
        }
        SettlementEvidence::Evicted { txid } => {
            require_active(&next, txid)?;
            next.history.evicted = true;
            if !matches!(next.state, SettlementState::Evicted) {
                if matches!(
                    next.accounting,
                    SettlementAccountingState::Confirmed | SettlementAccountingState::Finalized
                ) {
                    next.accounting = SettlementAccountingState::Demoted;
                    effects.demote_accounting = true;
                }
                next.state = SettlementState::Evicted;
                effects.redrive_observation = true;
                effects.rebroadcast_journaled = true;
            }
        }
        SettlementEvidence::Reorged {
            txid,
            previous_block,
        } => {
            require_active(&next, txid)?;
            if matches!(
                &next.state,
                SettlementState::Reorged { previous_block: existing }
                    if existing == previous_block
            ) {
                return Ok(SettlementTransition {
                    lifecycle: next,
                    effects,
                });
            }
            let Some(confirmed_block) = next.last_confirmed_block.as_ref() else {
                return Err(SettlementLifecycleError::ReorgRequiresConfirmedEvidence);
            };
            if confirmed_block != previous_block {
                return Err(SettlementLifecycleError::ReorgBlockMismatch);
            }
            next.history.reorged = true;
            next.last_reorged_block = Some(previous_block.clone());
            next.state = SettlementState::Reorged {
                previous_block: previous_block.clone(),
            };
            if matches!(
                next.accounting,
                SettlementAccountingState::Confirmed | SettlementAccountingState::Finalized
            ) {
                next.accounting = SettlementAccountingState::Demoted;
                effects.demote_accounting = true;
            }
            effects.redrive_observation = true;
        }
    }

    Ok(SettlementTransition {
        lifecycle: next,
        effects,
    })
}

fn apply_confirmation(
    next: &mut MerchantSettlementLifecycle,
    txid: &SettlementTxid,
    block: &SettlementBlock,
    confirmations: u32,
    explicitly_finalized: bool,
    policy: SettlementFinalityPolicy,
    effects: &mut SettlementTransitionEffects,
) -> Result<(), SettlementLifecycleError> {
    require_active(next, txid)?;
    if confirmations == 0 {
        return Err(SettlementLifecycleError::ZeroConfirmations);
    }
    let required = policy.required(next.chain);
    if explicitly_finalized && confirmations < required {
        return Err(SettlementLifecycleError::PrematureFinality {
            confirmations,
            required_confirmations: required,
        });
    }
    if next.last_reorged_block.as_ref() == Some(block) {
        return Err(SettlementLifecycleError::ReconfirmationUsesReorgedBlock);
    }

    let effective_confirmations = match &next.state {
        SettlementState::Confirmed {
            block: existing,
            confirmations: existing_confirmations,
            ..
        }
        | SettlementState::Finalized {
            block: existing,
            confirmations: existing_confirmations,
            ..
        } => {
            if existing != block {
                return Err(SettlementLifecycleError::ConflictingConfirmationBlock);
            }
            confirmations.max(*existing_confirmations)
        }
        _ => confirmations,
    };
    let finalized = effective_confirmations >= required;
    let accounting_before = next.accounting;

    next.history.confirmed = true;
    next.history.finalized |= finalized;
    next.last_confirmed_block = Some(block.clone());
    next.state = if finalized {
        SettlementState::Finalized {
            block: block.clone(),
            confirmations: effective_confirmations,
            required_confirmations: required,
        }
    } else {
        SettlementState::Confirmed {
            block: block.clone(),
            confirmations: effective_confirmations,
            required_confirmations: required,
        }
    };

    match accounting_before {
        SettlementAccountingState::Unrecorded => {
            effects.activate_accounting = true;
            next.accounting = if finalized {
                SettlementAccountingState::Finalized
            } else {
                SettlementAccountingState::Confirmed
            };
            effects.finalize_accounting = finalized;
        }
        SettlementAccountingState::Demoted => {
            effects.reactivate_accounting = true;
            next.accounting = if finalized {
                SettlementAccountingState::Finalized
            } else {
                SettlementAccountingState::Confirmed
            };
            effects.finalize_accounting = finalized;
        }
        SettlementAccountingState::Confirmed if finalized => {
            next.accounting = SettlementAccountingState::Finalized;
            effects.finalize_accounting = true;
        }
        SettlementAccountingState::Confirmed | SettlementAccountingState::Finalized => {}
    }
    Ok(())
}

fn require_active(
    lifecycle: &MerchantSettlementLifecycle,
    observed: &SettlementTxid,
) -> Result<(), SettlementLifecycleError> {
    if &lifecycle.active_txid == observed {
        Ok(())
    } else {
        Err(SettlementLifecycleError::WrongTransaction {
            expected: lifecycle.active_txid.clone(),
            observed: observed.clone(),
        })
    }
}

fn canonical_hash(value: &str) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txid(byte: char) -> SettlementTxid {
        SettlementTxid::parse(&byte.to_string().repeat(64)).unwrap()
    }

    fn block(height: u32, byte: char) -> SettlementBlock {
        SettlementBlock::new(height, &byte.to_string().repeat(64)).unwrap()
    }

    fn lifecycle(chain: SettlementChain) -> MerchantSettlementLifecycle {
        MerchantSettlementLifecycle::new(chain, txid('1'))
    }

    fn apply(
        current: &MerchantSettlementLifecycle,
        evidence: SettlementEvidence,
    ) -> SettlementTransition {
        apply_settlement_evidence(current, &evidence, SettlementFinalityPolicy::default()).unwrap()
    }

    #[test]
    fn finality_defaults_are_liquid_two_bitcoin_three_and_zero_is_rejected() {
        let policy = SettlementFinalityPolicy::default();
        assert_eq!(policy.liquid_confirmations(), 2);
        assert_eq!(policy.bitcoin_confirmations(), 3);
        assert_eq!(policy.required(SettlementChain::Liquid), 2);
        assert_eq!(policy.required(SettlementChain::Bitcoin), 3);
        assert_eq!(
            SettlementFinalityPolicy::new(0, 3),
            Err(SettlementFinalityPolicyError::LiquidMustBeNonzero)
        );
        assert_eq!(
            SettlementFinalityPolicy::new(2, 0),
            Err(SettlementFinalityPolicyError::BitcoinMustBeNonzero)
        );
        assert_eq!(
            SettlementFinalityPolicy::new(1, 1)
                .unwrap()
                .required(SettlementChain::Bitcoin),
            1
        );
    }

    #[test]
    fn transaction_and_block_identities_are_bounded_and_canonical() {
        assert_eq!(
            SettlementTxid::parse("not-a-txid"),
            Err(SettlementLifecycleError::InvalidTransactionId)
        );
        assert_eq!(
            SettlementBlock::new(0, &"a".repeat(64)),
            Err(SettlementLifecycleError::InvalidBlockHeight)
        );
        assert_eq!(
            SettlementBlock::new(1, "not-a-hash"),
            Err(SettlementLifecycleError::InvalidBlockHash)
        );
        assert_eq!(txid('A').as_str(), "a".repeat(64));
    }

    #[test]
    fn first_confirmation_activates_actual_value_once_and_duplicates_are_idempotent() {
        let initial = lifecycle(SettlementChain::Liquid);
        let evidence = SettlementEvidence::Confirmed {
            txid: txid('1'),
            block: block(100, 'a'),
            confirmations: 1,
        };
        let first = apply(&initial, evidence.clone());
        assert!(matches!(
            first.lifecycle.state(),
            SettlementState::Confirmed { .. }
        ));
        assert!(first.effects.activate_accounting);
        assert!(!first.effects.finalize_accounting);
        assert_eq!(
            first.lifecycle.accounting_state(),
            SettlementAccountingState::Confirmed
        );

        let duplicate = apply(&first.lifecycle, evidence);
        assert_eq!(duplicate.lifecycle, first.lifecycle);
        assert_eq!(duplicate.effects, SettlementTransitionEffects::default());
    }

    #[test]
    fn liquid_and_bitcoin_promote_only_at_their_configured_boundaries() {
        let liquid_one = apply(
            &lifecycle(SettlementChain::Liquid),
            SettlementEvidence::Confirmed {
                txid: txid('1'),
                block: block(100, 'a'),
                confirmations: 1,
            },
        );
        let liquid_two = apply(
            &liquid_one.lifecycle,
            SettlementEvidence::Confirmed {
                txid: txid('1'),
                block: block(100, 'a'),
                confirmations: 2,
            },
        );
        assert!(matches!(
            liquid_two.lifecycle.state(),
            SettlementState::Finalized { .. }
        ));
        assert!(liquid_two.effects.finalize_accounting);
        assert!(!liquid_two.effects.activate_accounting);

        let bitcoin_two = apply(
            &lifecycle(SettlementChain::Bitcoin),
            SettlementEvidence::Confirmed {
                txid: txid('1'),
                block: block(200, 'b'),
                confirmations: 2,
            },
        );
        assert!(matches!(
            bitcoin_two.lifecycle.state(),
            SettlementState::Confirmed { .. }
        ));
        let bitcoin_three = apply(
            &bitcoin_two.lifecycle,
            SettlementEvidence::Finalized {
                txid: txid('1'),
                block: block(200, 'b'),
                confirmations: 3,
            },
        );
        assert!(matches!(
            bitcoin_three.lifecycle.state(),
            SettlementState::Finalized { .. }
        ));
        assert!(bitcoin_three.effects.finalize_accounting);
    }

    #[test]
    fn explicit_finality_below_policy_fails_closed() {
        let error = apply_settlement_evidence(
            &lifecycle(SettlementChain::Bitcoin),
            &SettlementEvidence::Finalized {
                txid: txid('1'),
                block: block(200, 'b'),
                confirmations: 2,
            },
            SettlementFinalityPolicy::default(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            SettlementLifecycleError::PrematureFinality {
                confirmations: 2,
                required_confirmations: 3
            }
        );
    }

    #[test]
    fn linked_replacement_demotes_original_and_reactivates_child_exactly_once() {
        let confirmed = apply(
            &lifecycle(SettlementChain::Liquid),
            SettlementEvidence::Confirmed {
                txid: txid('1'),
                block: block(100, 'a'),
                confirmations: 1,
            },
        );
        let replacement_evidence = SettlementEvidence::Replaced {
            replaced_txid: txid('1'),
            replacement_txid: txid('2'),
        };
        let replaced = apply(&confirmed.lifecycle, replacement_evidence.clone());
        assert!(replaced.effects.demote_accounting);
        assert!(replaced.effects.redrive_observation);
        assert_eq!(replaced.lifecycle.journal_txid(), &txid('1'));
        assert_eq!(replaced.lifecycle.active_txid(), &txid('2'));
        assert_eq!(
            replaced.lifecycle.accounting_state(),
            SettlementAccountingState::Demoted
        );

        let duplicate_link = apply(&replaced.lifecycle, replacement_evidence);
        assert_eq!(duplicate_link.lifecycle, replaced.lifecycle);
        assert_eq!(
            duplicate_link.effects,
            SettlementTransitionEffects::default()
        );

        let replacement_evicted = apply(
            &replaced.lifecycle,
            SettlementEvidence::Evicted { txid: txid('2') },
        );
        assert!(replacement_evicted.effects.redrive_observation);
        assert!(replacement_evicted.effects.rebroadcast_journaled);

        let replacement_confirmed = apply(
            &replacement_evicted.lifecycle,
            SettlementEvidence::Confirmed {
                txid: txid('2'),
                block: block(101, 'b'),
                confirmations: 1,
            },
        );
        assert!(replacement_confirmed.effects.reactivate_accounting);
        assert!(!replacement_confirmed.effects.activate_accounting);
        assert_eq!(replacement_confirmed.lifecycle.journal_txid(), &txid('1'));
        assert_eq!(replacement_confirmed.lifecycle.active_txid(), &txid('2'));
    }

    #[test]
    fn eviction_demotes_and_redrives_without_erasing_inclusion_identity() {
        let confirmed = apply(
            &lifecycle(SettlementChain::Liquid),
            SettlementEvidence::Confirmed {
                txid: txid('1'),
                block: block(100, 'a'),
                confirmations: 1,
            },
        );
        let evicted = apply(
            &confirmed.lifecycle,
            SettlementEvidence::Evicted { txid: txid('1') },
        );
        assert_eq!(evicted.lifecycle.state(), &SettlementState::Evicted);
        assert!(evicted.effects.demote_accounting);
        assert!(evicted.effects.redrive_observation);
        assert!(evicted.effects.rebroadcast_journaled);
        assert_eq!(
            evicted.lifecycle.last_confirmed_block(),
            Some(&block(100, 'a'))
        );

        let duplicate = apply(
            &evicted.lifecycle,
            SettlementEvidence::Evicted { txid: txid('1') },
        );
        assert_eq!(duplicate.lifecycle, evicted.lifecycle);
        assert_eq!(duplicate.effects, SettlementTransitionEffects::default());
    }

    #[test]
    fn reorg_demotes_then_different_block_reconfirmation_reactivates() {
        let finalized = apply(
            &lifecycle(SettlementChain::Liquid),
            SettlementEvidence::Finalized {
                txid: txid('1'),
                block: block(100, 'a'),
                confirmations: 2,
            },
        );
        let reorg = apply(
            &finalized.lifecycle,
            SettlementEvidence::Reorged {
                txid: txid('1'),
                previous_block: block(100, 'a'),
            },
        );
        assert!(matches!(
            reorg.lifecycle.state(),
            SettlementState::Reorged { .. }
        ));
        assert!(reorg.effects.demote_accounting);
        assert!(reorg.effects.redrive_observation);

        let duplicate = apply(
            &reorg.lifecycle,
            SettlementEvidence::Reorged {
                txid: txid('1'),
                previous_block: block(100, 'a'),
            },
        );
        assert_eq!(duplicate.lifecycle, reorg.lifecycle);
        assert_eq!(duplicate.effects, SettlementTransitionEffects::default());

        assert_eq!(
            apply_settlement_evidence(
                &reorg.lifecycle,
                &SettlementEvidence::Confirmed {
                    txid: txid('1'),
                    block: block(100, 'a'),
                    confirmations: 1,
                },
                SettlementFinalityPolicy::default(),
            ),
            Err(SettlementLifecycleError::ReconfirmationUsesReorgedBlock)
        );

        let reconfirmed = apply(
            &reorg.lifecycle,
            SettlementEvidence::Confirmed {
                txid: txid('1'),
                block: block(101, 'b'),
                confirmations: 1,
            },
        );
        assert!(reconfirmed.effects.reactivate_accounting);
        assert!(matches!(
            reconfirmed.lifecycle.state(),
            SettlementState::Confirmed { .. }
        ));
        assert!(reconfirmed.lifecycle.history().reorged);
        assert!(reconfirmed.lifecycle.history().finalized);
    }

    #[test]
    fn conflicting_block_requires_explicit_reorg_and_stale_progress_cannot_regress() {
        let finalized = apply(
            &lifecycle(SettlementChain::Liquid),
            SettlementEvidence::Finalized {
                txid: txid('1'),
                block: block(100, 'a'),
                confirmations: 2,
            },
        );
        assert_eq!(
            apply_settlement_evidence(
                &finalized.lifecycle,
                &SettlementEvidence::Confirmed {
                    txid: txid('1'),
                    block: block(101, 'b'),
                    confirmations: 1,
                },
                SettlementFinalityPolicy::default(),
            ),
            Err(SettlementLifecycleError::ConflictingConfirmationBlock)
        );

        let stale_mempool = apply(
            &finalized.lifecycle,
            SettlementEvidence::Mempool { txid: txid('1') },
        );
        assert_eq!(stale_mempool.lifecycle.state(), finalized.lifecycle.state());
        assert_eq!(
            stale_mempool.lifecycle.accounting_state(),
            SettlementAccountingState::Finalized
        );
    }

    #[test]
    fn history_retains_every_observed_lifecycle_fact() {
        let initial = lifecycle(SettlementChain::Bitcoin);
        let broadcast = apply(&initial, SettlementEvidence::Broadcast { txid: txid('1') });
        let mempool = apply(
            &broadcast.lifecycle,
            SettlementEvidence::Mempool { txid: txid('1') },
        );
        let confirmed = apply(
            &mempool.lifecycle,
            SettlementEvidence::Confirmed {
                txid: txid('1'),
                block: block(200, 'b'),
                confirmations: 1,
            },
        );
        let evicted = apply(
            &confirmed.lifecycle,
            SettlementEvidence::Evicted { txid: txid('1') },
        );
        let history = evicted.lifecycle.history();
        assert!(history.constructed);
        assert!(history.broadcast);
        assert!(history.mempool);
        assert!(history.confirmed);
        assert!(history.evicted);
    }
}

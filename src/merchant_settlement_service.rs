//! Schema-independent composition of verified merchant outputs with the
//! settlement lifecycle reducer.
//!
//! This service deliberately returns persistence commands rather than writing
//! a repository. A later migration-owned adapter must commit the lifecycle
//! checkpoint, retained verifier evidence, and these commands atomically.

use std::{collections::BTreeMap, fmt};

use crate::{
    merchant_output_verifier::{
        AdaptedMerchantOutputEvidence, ApprovedMerchantDestination,
        BitcoinMerchantOutputObservation, LiquidMerchantOutputObservation,
        MerchantOutputVerificationError, VerifiedMerchantOutput,
    },
    merchant_settlement_adoption::{
        ConfirmedMerchantOutputEvidence, MerchantOutputAccountingIdentity,
        MerchantOutputAccountingIntent, MerchantSettlementAdoptionError, MerchantSettlementContext,
        MerchantSettlementPath,
    },
    merchant_settlement_lifecycle::{
        apply_settlement_evidence, MerchantSettlementLifecycle, SettlementAccountingState,
        SettlementBlock, SettlementChain, SettlementEvidence, SettlementFinalityPolicy,
        SettlementLifecycleError, SettlementLifecycleSnapshot, SettlementTransition,
        SettlementTxid,
    },
};

/// One immutable repository action. A repository applies every action in an
/// outcome together with the returned lifecycle checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerchantSettlementPersistenceCommand {
    /// Idempotently insert the exact verified output under its event key.
    Record(MerchantOutputAccountingIntent),
    /// Make this already-recorded event the family's active payment.
    Activate(MerchantOutputAccountingIdentity),
    /// Retain the event but remove it from active invoice value.
    Deactivate(MerchantOutputAccountingIdentity),
    /// Mark the active event operationally final without adding its value.
    Finalize(MerchantOutputAccountingIdentity),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MerchantSettlementProcessingOutcome {
    pub commands: Vec<MerchantSettlementPersistenceCommand>,
    pub redrive_observation: bool,
    pub rebroadcast_journaled: bool,
}

impl MerchantSettlementProcessingOutcome {
    fn extend(&mut self, other: Self) {
        self.commands.extend(other.commands);
        self.redrive_observation |= other.redrive_observation;
        self.rebroadcast_journaled |= other.rebroadcast_journaled;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetainedMerchantOutput {
    evidence: ConfirmedMerchantOutputEvidence,
    intent: MerchantOutputAccountingIntent,
    recorded: bool,
    active: bool,
    finalized: bool,
}

/// Durable service-owned verifier evidence. The repository representation may
/// map this to columns later; only [`MerchantSettlementAdoptionService::restore`]
/// turns it back into runtime authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedMerchantOutputSnapshot {
    pub evidence: ConfirmedMerchantOutputEvidence,
    pub intent: MerchantOutputAccountingIntent,
    pub recorded: bool,
    pub active: bool,
    pub finalized: bool,
}

/// Complete restart checkpoint for the reducer plus the evidence needed to
/// repair exact-value accounting without consulting a provider amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerchantSettlementAdoptionSnapshot {
    pub context: MerchantSettlementContext,
    pub lifecycle: SettlementLifecycleSnapshot,
    pub retained: Vec<RetainedMerchantOutputSnapshot>,
    pub active_event_key: Option<String>,
}

/// Restart-safe, pure service state. Only a validated typed checkpoint may
/// rehydrate it after a process restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerchantSettlementAdoptionService {
    context: MerchantSettlementContext,
    policy: SettlementFinalityPolicy,
    lifecycle: MerchantSettlementLifecycle,
    retained: BTreeMap<String, RetainedMerchantOutput>,
    active_event_key: Option<String>,
}

impl MerchantSettlementAdoptionService {
    pub fn new(
        context: MerchantSettlementContext,
        original_journal_txid: &str,
        policy: SettlementFinalityPolicy,
    ) -> Result<Self, MerchantSettlementProcessingError> {
        let journal_txid = SettlementTxid::parse(original_journal_txid)?;
        let chain = match context.path() {
            MerchantSettlementPath::LiquidClaim => SettlementChain::Liquid,
            MerchantSettlementPath::BitcoinRecovery => SettlementChain::Bitcoin,
        };
        Ok(Self {
            context,
            policy,
            lifecycle: MerchantSettlementLifecycle::new(chain, journal_txid),
            retained: BTreeMap::new(),
            active_event_key: None,
        })
    }

    pub fn lifecycle(&self) -> &MerchantSettlementLifecycle {
        &self.lifecycle
    }

    pub fn context(&self) -> &MerchantSettlementContext {
        &self.context
    }

    pub fn snapshot(&self) -> MerchantSettlementAdoptionSnapshot {
        MerchantSettlementAdoptionSnapshot {
            context: self.context.clone(),
            lifecycle: self.lifecycle.snapshot(),
            retained: self
                .retained
                .values()
                .map(|retained| RetainedMerchantOutputSnapshot {
                    evidence: retained.evidence.clone(),
                    intent: retained.intent.clone(),
                    recorded: retained.recorded,
                    active: retained.active,
                    finalized: retained.finalized,
                })
                .collect(),
            active_event_key: self.active_event_key.clone(),
        }
    }

    pub fn restore(
        snapshot: MerchantSettlementAdoptionSnapshot,
        policy: SettlementFinalityPolicy,
    ) -> Result<Self, MerchantSettlementProcessingError> {
        let lifecycle = MerchantSettlementLifecycle::restore(snapshot.lifecycle, policy)?;
        let expected_chain = match snapshot.context.path() {
            MerchantSettlementPath::LiquidClaim => SettlementChain::Liquid,
            MerchantSettlementPath::BitcoinRecovery => SettlementChain::Bitcoin,
        };
        if lifecycle.chain() != expected_chain || snapshot.retained.len() > 2 {
            return Err(MerchantSettlementProcessingError::InvalidCheckpoint);
        }

        let mut retained = BTreeMap::new();
        for record in snapshot.retained {
            if !record.recorded
                || record.finalized && !record.active
                || record.evidence.journal_txid() != lifecycle.journal_txid().as_str()
                || record
                    .evidence
                    .accounting_intent(&snapshot.context)
                    .as_ref()
                    != Ok(&record.intent)
            {
                return Err(MerchantSettlementProcessingError::InvalidCheckpoint);
            }
            let event_key = record.intent.identity.event_key().to_owned();
            if retained
                .insert(
                    event_key,
                    RetainedMerchantOutput {
                        evidence: record.evidence,
                        intent: record.intent,
                        recorded: record.recorded,
                        active: record.active,
                        finalized: record.finalized,
                    },
                )
                .is_some()
            {
                return Err(MerchantSettlementProcessingError::InvalidCheckpoint);
            }
        }

        let active_records: Vec<_> = retained
            .iter()
            .filter(|(_, record)| record.active)
            .collect();
        match lifecycle.accounting_state() {
            SettlementAccountingState::Unrecorded
                if !retained.is_empty()
                    || !active_records.is_empty()
                    || snapshot.active_event_key.is_some() =>
            {
                return Err(MerchantSettlementProcessingError::InvalidCheckpoint);
            }
            SettlementAccountingState::Demoted
                if retained.is_empty()
                    || !active_records.is_empty()
                    || snapshot.active_event_key.is_some() =>
            {
                return Err(MerchantSettlementProcessingError::InvalidCheckpoint);
            }
            SettlementAccountingState::Confirmed | SettlementAccountingState::Finalized
                if active_records.len() != 1
                    || snapshot.active_event_key.as_deref()
                        != Some(active_records[0].0.as_str())
                    || active_records[0].1.evidence.txid() != lifecycle.active_txid().as_str()
                    || active_records[0].1.finalized
                        != matches!(
                            lifecycle.accounting_state(),
                            SettlementAccountingState::Finalized
                        ) =>
            {
                return Err(MerchantSettlementProcessingError::InvalidCheckpoint);
            }
            SettlementAccountingState::Unrecorded
            | SettlementAccountingState::Confirmed
            | SettlementAccountingState::Finalized
            | SettlementAccountingState::Demoted => {}
        }

        Ok(Self {
            context: snapshot.context,
            policy,
            lifecycle,
            retained,
            active_event_key: snapshot.active_event_key,
        })
    }

    /// Consume the production Liquid observation directly. Adapter-validated
    /// mempool evidence can advance transaction identity but cannot create an
    /// amount; confirmed evidence must still pass the verifier at one
    /// confirmation before accounting is touched.
    pub fn apply_liquid_observation(
        &mut self,
        observation: &LiquidMerchantOutputObservation,
        approved_destination: &ApprovedMerchantDestination,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        if self.context.path() != MerchantSettlementPath::LiquidClaim {
            return Err(MerchantSettlementProcessingError::WrongSettlementPath);
        }
        match observation {
            LiquidMerchantOutputObservation::Observed(adapted)
                if adapted.observed().confirmations() == 0 =>
            {
                self.apply_adapted_mempool(adapted)
            }
            LiquidMerchantOutputObservation::Observed(adapted) => {
                let verified = adapted.verify(approved_destination, 1)?;
                self.apply_verified_confirmation(&verified)
            }
            LiquidMerchantOutputObservation::Evicted { txid } => {
                self.require_active_observation(txid)?;
                self.apply_eviction()
            }
            LiquidMerchantOutputObservation::ReorgDemoted {
                txid,
                previous_block_height,
                previous_block_hash,
            } => {
                self.require_active_observation(txid)?;
                self.apply_reorg(*previous_block_height, previous_block_hash)
            }
        }
    }

    /// Symmetric Bitcoin recovery boundary. The source independently anchors
    /// the observation; accounting still begins at one confirmation while the
    /// lifecycle preserves the Bitcoin three-confirmation finality policy.
    pub fn apply_bitcoin_recovery_observation(
        &mut self,
        observation: &BitcoinMerchantOutputObservation,
        approved_destination: &ApprovedMerchantDestination,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        if self.context.path() != MerchantSettlementPath::BitcoinRecovery {
            return Err(MerchantSettlementProcessingError::WrongSettlementPath);
        }
        match observation {
            BitcoinMerchantOutputObservation::Observed(adapted)
                if adapted.observed().confirmations() == 0 =>
            {
                self.apply_adapted_mempool(adapted)
            }
            BitcoinMerchantOutputObservation::Observed(adapted) => {
                let verified = adapted.verify(approved_destination, 1)?;
                self.apply_verified_confirmation(&verified)
            }
            BitcoinMerchantOutputObservation::Evicted { txid } => {
                self.require_active_observation(txid)?;
                self.apply_eviction()
            }
            BitcoinMerchantOutputObservation::ReorgDemoted {
                txid,
                previous_block_height,
                previous_block_hash,
            } => {
                self.require_active_observation(txid)?;
                self.apply_reorg(*previous_block_height, previous_block_hash)
            }
        }
    }

    fn apply_adapted_mempool(
        &mut self,
        adapted: &AdaptedMerchantOutputEvidence,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        if adapted.original_journal_txid() != self.lifecycle.journal_txid().as_str() {
            return Err(MerchantSettlementProcessingError::JournalMismatch);
        }
        let observed_txid = SettlementTxid::parse(adapted.candidate_txid())?;
        let mut next = self.clone();
        let mut outcome = MerchantSettlementProcessingOutcome::default();
        if adapted.is_linked_replacement() {
            let original_txid = SettlementTxid::parse(adapted.original_journal_txid())?;
            if next.lifecycle.active_txid() == &original_txid {
                let transition = apply_settlement_evidence(
                    &next.lifecycle,
                    &SettlementEvidence::Replaced {
                        replaced_txid: original_txid,
                        replacement_txid: observed_txid.clone(),
                    },
                    next.policy,
                )?;
                outcome.extend(next.adopt_transition(transition, None)?);
            } else if next.lifecycle.active_txid() != &observed_txid {
                return Err(MerchantSettlementProcessingError::ObservationTransactionMismatch);
            }
        } else if next.lifecycle.active_txid() != &observed_txid
            || observed_txid.as_str() != adapted.original_journal_txid()
        {
            return Err(MerchantSettlementProcessingError::ObservationTransactionMismatch);
        }
        let transition = apply_settlement_evidence(
            &next.lifecycle,
            &SettlementEvidence::Mempool {
                txid: observed_txid,
            },
            next.policy,
        )?;
        outcome.extend(next.adopt_transition(transition, None)?);
        *self = next;
        Ok(outcome)
    }

    fn require_active_observation(
        &self,
        txid: &str,
    ) -> Result<(), MerchantSettlementProcessingError> {
        let observed = SettlementTxid::parse(txid)?;
        if &observed == self.lifecycle.active_txid() {
            Ok(())
        } else {
            Err(MerchantSettlementProcessingError::ObservationTransactionMismatch)
        }
    }

    /// Accept a confirmed output only after the fail-closed verifier has
    /// produced it. The verifier's actual amount is the sole accounting value.
    pub fn apply_verified_confirmation(
        &mut self,
        output: &VerifiedMerchantOutput,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        let mut next = self.clone();
        let outcome = next.apply_verified_confirmation_inner(output)?;
        *self = next;
        Ok(outcome)
    }

    fn apply_verified_confirmation_inner(
        &mut self,
        output: &VerifiedMerchantOutput,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        let evidence = ConfirmedMerchantOutputEvidence::from_verified(&self.context, output)?;
        if evidence.journal_txid() != self.lifecycle.journal_txid().as_str() {
            return Err(MerchantSettlementProcessingError::JournalMismatch);
        }
        let observed_txid = SettlementTxid::parse(evidence.txid())?;
        let mut outcome = MerchantSettlementProcessingOutcome::default();

        if evidence.is_linked_replacement() {
            let original_txid = SettlementTxid::parse(evidence.journal_txid())?;
            if self.lifecycle.active_txid() == &original_txid {
                let transition = apply_settlement_evidence(
                    &self.lifecycle,
                    &SettlementEvidence::Replaced {
                        replaced_txid: original_txid,
                        replacement_txid: observed_txid.clone(),
                    },
                    self.policy,
                )?;
                outcome.extend(self.adopt_transition(transition, None)?);
            } else if self.lifecycle.active_txid() != &observed_txid {
                return Err(MerchantSettlementProcessingError::JournalMismatch);
            }
        } else if self.lifecycle.active_txid() != &observed_txid {
            return Err(MerchantSettlementProcessingError::UnlinkedReplacement);
        }

        let block = SettlementBlock::new(evidence.block_height(), evidence.block_hash())?;
        let transition = apply_settlement_evidence(
            &self.lifecycle,
            &SettlementEvidence::Confirmed {
                txid: observed_txid,
                block,
                confirmations: evidence.confirmations(),
            },
            self.policy,
        )?;
        outcome.extend(self.adopt_transition(transition, Some(evidence))?);
        Ok(outcome)
    }

    pub fn mark_broadcast(
        &mut self,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        self.apply_non_accounting(SettlementEvidence::Broadcast {
            txid: self.lifecycle.active_txid().clone(),
        })
    }

    pub fn mark_mempool(
        &mut self,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        self.apply_non_accounting(SettlementEvidence::Mempool {
            txid: self.lifecycle.active_txid().clone(),
        })
    }

    pub fn apply_eviction(
        &mut self,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        self.apply_non_accounting(SettlementEvidence::Evicted {
            txid: self.lifecycle.active_txid().clone(),
        })
    }

    pub fn apply_reorg(
        &mut self,
        previous_block_height: u32,
        previous_block_hash: &str,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        self.apply_non_accounting(SettlementEvidence::Reorged {
            txid: self.lifecycle.active_txid().clone(),
            previous_block: SettlementBlock::new(previous_block_height, previous_block_hash)?,
        })
    }

    fn apply_non_accounting(
        &mut self,
        evidence: SettlementEvidence,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        let mut next = self.clone();
        let transition = apply_settlement_evidence(&next.lifecycle, &evidence, next.policy)?;
        let outcome = next.adopt_transition(transition, None)?;
        *self = next;
        Ok(outcome)
    }

    fn adopt_transition(
        &mut self,
        transition: SettlementTransition,
        evidence: Option<ConfirmedMerchantOutputEvidence>,
    ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError> {
        let mut outcome = MerchantSettlementProcessingOutcome {
            redrive_observation: transition.effects.redrive_observation,
            rebroadcast_journaled: transition.effects.rebroadcast_journaled,
            ..MerchantSettlementProcessingOutcome::default()
        };

        if transition.effects.demote_accounting {
            let active_key = self
                .active_event_key
                .take()
                .ok_or(MerchantSettlementProcessingError::MissingRetainedEvidence)?;
            let retained = self
                .retained
                .get_mut(&active_key)
                .ok_or(MerchantSettlementProcessingError::MissingRetainedEvidence)?;
            retained.active = false;
            retained.finalized = false;
            outcome
                .commands
                .push(MerchantSettlementPersistenceCommand::Deactivate(
                    retained.intent.identity.clone(),
                ));
        }

        if let Some(evidence) = evidence {
            let intent = evidence.accounting_intent(&self.context)?;
            let event_key = intent.identity.event_key().to_owned();
            let needs_activation =
                transition.effects.activate_accounting || transition.effects.reactivate_accounting;

            match self.retained.get_mut(&event_key) {
                Some(retained) => {
                    if retained.intent != intent {
                        return Err(MerchantSettlementProcessingError::ImmutableEvidenceConflict);
                    }
                    retained.evidence = evidence;
                }
                None if needs_activation => {
                    self.retained.insert(
                        event_key.clone(),
                        RetainedMerchantOutput {
                            evidence,
                            intent: intent.clone(),
                            recorded: false,
                            active: false,
                            finalized: false,
                        },
                    );
                }
                None => {
                    return Err(MerchantSettlementProcessingError::MissingRetainedEvidence);
                }
            }

            if needs_activation {
                if let Some(other_key) = self.active_event_key.as_deref() {
                    if other_key != event_key {
                        return Err(MerchantSettlementProcessingError::ActiveFamilyConflict);
                    }
                }
                let retained = self
                    .retained
                    .get_mut(&event_key)
                    .expect("retained evidence inserted above");
                if !retained.recorded {
                    outcome
                        .commands
                        .push(MerchantSettlementPersistenceCommand::Record(
                            retained.intent.clone(),
                        ));
                    retained.recorded = true;
                }
                retained.active = true;
                self.active_event_key = Some(event_key.clone());
                outcome
                    .commands
                    .push(MerchantSettlementPersistenceCommand::Activate(
                        retained.intent.identity.clone(),
                    ));
            }

            if transition.effects.finalize_accounting {
                let retained = self
                    .retained
                    .get_mut(&event_key)
                    .ok_or(MerchantSettlementProcessingError::MissingRetainedEvidence)?;
                if !retained.active {
                    return Err(MerchantSettlementProcessingError::MissingRetainedEvidence);
                }
                retained.finalized = true;
                outcome
                    .commands
                    .push(MerchantSettlementPersistenceCommand::Finalize(
                        retained.intent.identity.clone(),
                    ));
            }
        } else if transition.effects.activate_accounting
            || transition.effects.reactivate_accounting
            || transition.effects.finalize_accounting
        {
            return Err(MerchantSettlementProcessingError::MissingRetainedEvidence);
        }

        self.lifecycle = transition.lifecycle;
        Ok(outcome)
    }

    /// Exact repair candidate. Unconfirmed, evicted, and reorg-demoted state
    /// cannot synthesize an accounting value.
    pub fn repair_accounting_intent(&self) -> Option<&MerchantOutputAccountingIntent> {
        if !matches!(
            self.lifecycle.accounting_state(),
            SettlementAccountingState::Confirmed | SettlementAccountingState::Finalized
        ) {
            return None;
        }
        self.active_event_key
            .as_deref()
            .and_then(|key| self.retained.get(key))
            .filter(|retained| retained.recorded && retained.active)
            .map(|retained| &retained.intent)
    }

    /// Construction of this service proves an immutable settlement journal is
    /// still owned. Eviction/reorg request redrive; they never authorize a
    /// value-changing fallback.
    pub const fn blocks_value_changing_fallback(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerchantSettlementProcessingError {
    Adoption(MerchantSettlementAdoptionError),
    Lifecycle(SettlementLifecycleError),
    Verification(MerchantOutputVerificationError),
    JournalMismatch,
    UnlinkedReplacement,
    WrongSettlementPath,
    ObservationTransactionMismatch,
    MissingRetainedEvidence,
    ImmutableEvidenceConflict,
    ActiveFamilyConflict,
    InvalidCheckpoint,
}

impl From<MerchantSettlementAdoptionError> for MerchantSettlementProcessingError {
    fn from(error: MerchantSettlementAdoptionError) -> Self {
        Self::Adoption(error)
    }
}

impl From<SettlementLifecycleError> for MerchantSettlementProcessingError {
    fn from(error: SettlementLifecycleError) -> Self {
        Self::Lifecycle(error)
    }
}

impl From<MerchantOutputVerificationError> for MerchantSettlementProcessingError {
    fn from(error: MerchantOutputVerificationError) -> Self {
        Self::Verification(error)
    }
}

impl fmt::Display for MerchantSettlementProcessingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Adoption(_) => "verified merchant output cannot be adopted",
            Self::Lifecycle(_) => "merchant settlement lifecycle rejected evidence",
            Self::Verification(_) => "merchant settlement observation did not verify",
            Self::JournalMismatch => "verified merchant output belongs to another journal",
            Self::UnlinkedReplacement => "merchant replacement is not explicitly linked",
            Self::WrongSettlementPath => "merchant observation uses the wrong settlement path",
            Self::ObservationTransactionMismatch => {
                "merchant observation does not name the active transaction"
            }
            Self::MissingRetainedEvidence => "lifecycle accounting lacks verifier evidence",
            Self::ImmutableEvidenceConflict => "merchant accounting event is immutable",
            Self::ActiveFamilyConflict => "merchant accounting family already has an active event",
            Self::InvalidCheckpoint => "merchant settlement checkpoint is invalid",
        })
    }
}

impl std::error::Error for MerchantSettlementProcessingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::btree_map::Entry, str::FromStr};

    use crate::merchant_output_verifier::{
        adapt_bitcoin_merchant_output, adapt_liquid_merchant_output, verify_merchant_output,
        ApprovedMerchantDestination, BitcoinMerchantOutputObservation,
        JournaledMerchantTransaction, LinkedReplacementJournalEvidence, MerchantAsset,
        MerchantConfirmationEvidence, MerchantOutputCommitment, MerchantOutputEvidence,
        MerchantOutputVerificationError, MerchantSourcePrevout, MerchantTransactionJournalEvidence,
        MerchantTransactionObservation, ObservedMerchantOutput,
    };
    use crate::merchant_settlement_lifecycle::SettlementState;
    use bitcoin::{
        absolute, consensus::serialize, transaction, Amount, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Txid, Witness,
    };
    use lwk_wollet::elements::{self, Address as LiquidAddress};
    use uuid::Uuid;

    const BITCOIN_ADDRESS: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    const BITCOIN_SCRIPT: &str =
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const LIQUID_ASSET: &str = "6f0279e9ed041c3d710a9f57d0c02928416453c0e87cbbe43c8ca792a3b6e499";
    const LIQUID_ADDRESS: &str =
        "lq1qqvxk052kf3qtkxmrakx50a9gc3smqad2ync54hzntjt980kfej9kkfe0247rp5h4yzmdftsahhw64uy8pzfe7cpg4fgykm7cv";
    const ORIGINAL_TXID: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const REPLACEMENT_TXID: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const BLOCK_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BLOCK_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[derive(Debug, Clone)]
    struct FixtureDestination {
        address: String,
        script: String,
        asset: MerchantAsset,
    }

    fn destination(path: MerchantSettlementPath) -> FixtureDestination {
        match path {
            MerchantSettlementPath::BitcoinRecovery => FixtureDestination {
                address: BITCOIN_ADDRESS.to_owned(),
                script: BITCOIN_SCRIPT.to_owned(),
                asset: MerchantAsset::Bitcoin,
            },
            MerchantSettlementPath::LiquidClaim => {
                let address = LiquidAddress::from_str(LIQUID_ADDRESS).unwrap();
                FixtureDestination {
                    address: LIQUID_ADDRESS.to_owned(),
                    script: hex::encode(address.script_pubkey().as_bytes()),
                    asset: MerchantAsset::Liquid(LIQUID_ASSET.to_owned()),
                }
            }
        }
    }

    fn context(path: MerchantSettlementPath) -> MerchantSettlementContext {
        MerchantSettlementContext::new(
            Uuid::from_u128(10),
            Uuid::from_u128(20),
            "issue83-runtime-journey",
            path,
        )
        .unwrap()
    }

    fn service(path: MerchantSettlementPath) -> MerchantSettlementAdoptionService {
        MerchantSettlementAdoptionService::new(
            context(path),
            ORIGINAL_TXID,
            SettlementFinalityPolicy::new(2, 3).unwrap(),
        )
        .unwrap()
    }

    struct LiquidSourceFixture {
        original_raw: Vec<u8>,
        original_txid: String,
        replacement_raw: Vec<u8>,
        replacement_txid: String,
        source_txid: String,
        address: String,
        script_hex: String,
        asset: MerchantAsset,
        blinding_key: elements::secp256k1_zkp::SecretKey,
    }

    impl LiquidSourceFixture {
        fn new(original_amount_sat: u64, replacement_amount_sat: u64) -> Self {
            let secp = elements::secp256k1_zkp::Secp256k1::new();
            let blinding_key = elements::secp256k1_zkp::SecretKey::from_slice(&[7; 32]).unwrap();
            let blinding_pubkey =
                elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &blinding_key);
            let address = LiquidAddress::from_str(LIQUID_ADDRESS)
                .unwrap()
                .to_unconfidential()
                .to_confidential(blinding_pubkey);
            let script = address.script_pubkey();
            let source_txid = elements::Txid::from_str(ORIGINAL_TXID).unwrap();
            let asset_id = elements::AssetId::from_str(LIQUID_ASSET).unwrap();
            let transaction = |amount_sat| elements::Transaction {
                version: 2,
                lock_time: elements::LockTime::ZERO,
                input: vec![elements::TxIn {
                    previous_output: elements::OutPoint::new(source_txid, 3),
                    is_pegin: false,
                    script_sig: elements::Script::new(),
                    sequence: elements::Sequence::MAX,
                    asset_issuance: elements::AssetIssuance::default(),
                    witness: elements::TxInWitness::default(),
                }],
                output: vec![elements::TxOut {
                    asset: elements::confidential::Asset::Explicit(asset_id),
                    value: elements::confidential::Value::Explicit(amount_sat),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: script.clone(),
                    witness: elements::TxOutWitness::default(),
                }],
            };
            let original = transaction(original_amount_sat);
            let replacement = transaction(replacement_amount_sat);
            Self {
                original_raw: elements::encode::serialize(&original),
                original_txid: original.txid().to_string(),
                replacement_raw: elements::encode::serialize(&replacement),
                replacement_txid: replacement.txid().to_string(),
                source_txid: source_txid.to_string(),
                address: address.to_string(),
                script_hex: hex::encode(script.as_bytes()),
                asset: MerchantAsset::Liquid(LIQUID_ASSET.to_owned()),
                blinding_key,
            }
        }

        fn approved(&self) -> ApprovedMerchantDestination {
            ApprovedMerchantDestination::liquid(
                self.address.clone(),
                self.script_hex.clone(),
                LIQUID_ASSET,
            )
        }

        fn service(&self) -> MerchantSettlementAdoptionService {
            MerchantSettlementAdoptionService::new(
                context(MerchantSettlementPath::LiquidClaim),
                &self.original_txid,
                SettlementFinalityPolicy::new(2, 3).unwrap(),
            )
            .unwrap()
        }

        fn observation(
            &self,
            replacement: bool,
            confirmation: MerchantConfirmationEvidence<'_>,
        ) -> LiquidMerchantOutputObservation {
            let sources = [MerchantSourcePrevout {
                txid: &self.source_txid,
                vout: 3,
                amount_sat: 91_000,
                script_pubkey_hex: "51",
            }];
            let original = MerchantTransactionJournalEvidence {
                raw_transaction: &self.original_raw,
                txid: &self.original_txid,
                source_prevouts: &sources,
                merchant: MerchantOutputCommitment {
                    destination_address: &self.address,
                    destination_script_hex: &self.script_hex,
                    asset: &self.asset,
                    amount_sat: 88_000,
                    vout: 0,
                },
            };
            let replacement_journal = MerchantTransactionJournalEvidence {
                raw_transaction: &self.replacement_raw,
                txid: &self.replacement_txid,
                source_prevouts: &sources,
                merchant: MerchantOutputCommitment {
                    destination_address: &self.address,
                    destination_script_hex: &self.script_hex,
                    asset: &self.asset,
                    amount_sat: 87_000,
                    vout: 0,
                },
            };
            let linked = LinkedReplacementJournalEvidence {
                replaces_txid: &self.original_txid,
                replacement: replacement_journal,
            };
            let (raw_transaction, txid) = if replacement {
                (&self.replacement_raw, &self.replacement_txid)
            } else {
                (&self.original_raw, &self.original_txid)
            };
            let observation = MerchantTransactionObservation {
                raw_transaction,
                txid,
                confirmation,
            };
            LiquidMerchantOutputObservation::Observed(Box::new(
                adapt_liquid_merchant_output(
                    &original,
                    replacement.then_some(&linked),
                    &observation,
                    &self.blinding_key,
                )
                .unwrap(),
            ))
        }
    }

    struct BitcoinSourceFixture {
        original_raw: Vec<u8>,
        original_txid: String,
        replacement_raw: Vec<u8>,
        replacement_txid: String,
        source_txid: String,
        asset: MerchantAsset,
    }

    impl BitcoinSourceFixture {
        fn new() -> Self {
            let source_txid = Txid::from_str(ORIGINAL_TXID).unwrap();
            let script = ScriptBuf::from_bytes(hex::decode(BITCOIN_SCRIPT).unwrap());
            let transaction = |amount_sat, sequence| Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(source_txid, 3),
                    script_sig: ScriptBuf::new(),
                    sequence,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(amount_sat),
                    script_pubkey: script.clone(),
                }],
            };
            let original = transaction(89_000, Sequence::MAX);
            let replacement = transaction(88_000, Sequence::ZERO);
            Self {
                original_raw: serialize(&original),
                original_txid: original.compute_txid().to_string(),
                replacement_raw: serialize(&replacement),
                replacement_txid: replacement.compute_txid().to_string(),
                source_txid: source_txid.to_string(),
                asset: MerchantAsset::Bitcoin,
            }
        }

        fn approved(&self) -> ApprovedMerchantDestination {
            ApprovedMerchantDestination::bitcoin(BITCOIN_ADDRESS, BITCOIN_SCRIPT)
        }

        fn service(&self) -> MerchantSettlementAdoptionService {
            MerchantSettlementAdoptionService::new(
                context(MerchantSettlementPath::BitcoinRecovery),
                &self.original_txid,
                SettlementFinalityPolicy::new(2, 3).unwrap(),
            )
            .unwrap()
        }

        fn observation(
            &self,
            replacement: bool,
            confirmation: MerchantConfirmationEvidence<'_>,
        ) -> BitcoinMerchantOutputObservation {
            let sources = [MerchantSourcePrevout {
                txid: &self.source_txid,
                vout: 3,
                amount_sat: 91_000,
                script_pubkey_hex: "51",
            }];
            let original = MerchantTransactionJournalEvidence {
                raw_transaction: &self.original_raw,
                txid: &self.original_txid,
                source_prevouts: &sources,
                merchant: MerchantOutputCommitment {
                    destination_address: BITCOIN_ADDRESS,
                    destination_script_hex: BITCOIN_SCRIPT,
                    asset: &self.asset,
                    amount_sat: 89_000,
                    vout: 0,
                },
            };
            let replacement_journal = MerchantTransactionJournalEvidence {
                raw_transaction: &self.replacement_raw,
                txid: &self.replacement_txid,
                source_prevouts: &sources,
                merchant: MerchantOutputCommitment {
                    destination_address: BITCOIN_ADDRESS,
                    destination_script_hex: BITCOIN_SCRIPT,
                    asset: &self.asset,
                    amount_sat: 88_000,
                    vout: 0,
                },
            };
            let linked = LinkedReplacementJournalEvidence {
                replaces_txid: &self.original_txid,
                replacement: replacement_journal,
            };
            let (raw_transaction, txid) = if replacement {
                (&self.replacement_raw, &self.replacement_txid)
            } else {
                (&self.original_raw, &self.original_txid)
            };
            let observation = MerchantTransactionObservation {
                raw_transaction,
                txid,
                confirmation,
            };
            BitcoinMerchantOutputObservation::Observed(Box::new(
                adapt_bitcoin_merchant_output(
                    &original,
                    replacement.then_some(&linked),
                    &observation,
                )
                .unwrap(),
            ))
        }
    }

    fn verified(
        path: MerchantSettlementPath,
        txid: &str,
        replacement: bool,
        amount_sat: u64,
        confirmations: u32,
        block_height: u32,
        block_hash: &str,
    ) -> VerifiedMerchantOutput {
        let destination = destination(path);
        let approved = match &destination.asset {
            MerchantAsset::Bitcoin => ApprovedMerchantDestination::bitcoin(
                destination.address.clone(),
                destination.script.clone(),
            ),
            MerchantAsset::Liquid(asset_id) => ApprovedMerchantDestination::liquid(
                destination.address.clone(),
                destination.script.clone(),
                asset_id.clone(),
            ),
        };
        let candidate = if replacement {
            JournaledMerchantTransaction::linked_replacement(
                txid,
                ORIGINAL_TXID,
                destination.address.clone(),
                destination.script.clone(),
                destination.asset.clone(),
                i64::try_from(amount_sat).unwrap(),
                0,
            )
        } else {
            JournaledMerchantTransaction::original(
                txid,
                destination.address.clone(),
                destination.script.clone(),
                destination.asset.clone(),
                i64::try_from(amount_sat).unwrap(),
                0,
            )
        };
        verify_merchant_output(
            ORIGINAL_TXID,
            &candidate,
            &approved,
            &MerchantOutputEvidence::Authoritative(ObservedMerchantOutput::new(
                txid,
                destination.script,
                destination.asset,
                amount_sat,
                0,
                confirmations,
                Some(block_height),
                Some(block_hash.to_owned()),
            )),
            1,
        )
        .unwrap()
    }

    #[derive(Debug, Clone)]
    struct SinkEvent {
        intent: MerchantOutputAccountingIntent,
        record_count: usize,
        active: bool,
        finalized: bool,
    }

    #[derive(Debug, Default)]
    struct DeterministicAccountingSink {
        events: BTreeMap<String, SinkEvent>,
        active_by_family: BTreeMap<String, String>,
    }

    impl DeterministicAccountingSink {
        fn apply(&mut self, outcome: &MerchantSettlementProcessingOutcome) {
            for command in &outcome.commands {
                match command {
                    MerchantSettlementPersistenceCommand::Record(intent) => {
                        let key = intent.identity.event_key().to_owned();
                        match self.events.entry(key) {
                            Entry::Vacant(entry) => {
                                entry.insert(SinkEvent {
                                    intent: intent.clone(),
                                    record_count: 1,
                                    active: false,
                                    finalized: false,
                                });
                            }
                            Entry::Occupied(entry) => {
                                assert_eq!(&entry.get().intent, intent);
                                panic!("service emitted a duplicate accounting insertion");
                            }
                        }
                    }
                    MerchantSettlementPersistenceCommand::Activate(identity) => {
                        let key = identity.event_key().to_owned();
                        let prior = self
                            .active_by_family
                            .insert(identity.family_key().to_owned(), key.clone());
                        assert!(prior.as_deref().is_none_or(|prior| prior == key));
                        self.events.get_mut(&key).unwrap().active = true;
                    }
                    MerchantSettlementPersistenceCommand::Deactivate(identity) => {
                        assert_eq!(
                            self.active_by_family
                                .remove(identity.family_key())
                                .as_deref(),
                            Some(identity.event_key())
                        );
                        let event = self.events.get_mut(identity.event_key()).unwrap();
                        event.active = false;
                        event.finalized = false;
                    }
                    MerchantSettlementPersistenceCommand::Finalize(identity) => {
                        let event = self.events.get_mut(identity.event_key()).unwrap();
                        assert!(event.active);
                        event.finalized = true;
                    }
                }
            }
        }

        fn active_value_sat(&self) -> i64 {
            self.events
                .values()
                .filter(|event| event.active)
                .map(|event| event.intent.actual_amount_sat)
                .sum()
        }

        fn total_records(&self) -> usize {
            self.events.values().map(|event| event.record_count).sum()
        }
    }

    /// Models the real worker transaction boundary: every tick restores the
    /// last durable checkpoint, applies one typed source outcome, applies the
    /// returned commands, then persists the next checkpoint.
    struct DeterministicRestoringWorker {
        checkpoint: MerchantSettlementAdoptionSnapshot,
        policy: SettlementFinalityPolicy,
        sink: DeterministicAccountingSink,
    }

    impl DeterministicRestoringWorker {
        fn new(service: MerchantSettlementAdoptionService) -> Self {
            Self {
                checkpoint: service.snapshot(),
                policy: SettlementFinalityPolicy::new(2, 3).unwrap(),
                sink: DeterministicAccountingSink::default(),
            }
        }

        fn liquid_tick(
            &mut self,
            observation: &LiquidMerchantOutputObservation,
            approved: &ApprovedMerchantDestination,
        ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError>
        {
            let mut service =
                MerchantSettlementAdoptionService::restore(self.checkpoint.clone(), self.policy)?;
            let outcome = service.apply_liquid_observation(observation, approved)?;
            self.sink.apply(&outcome);
            self.checkpoint = service.snapshot();
            Ok(outcome)
        }

        fn bitcoin_tick(
            &mut self,
            observation: &BitcoinMerchantOutputObservation,
            approved: &ApprovedMerchantDestination,
        ) -> Result<MerchantSettlementProcessingOutcome, MerchantSettlementProcessingError>
        {
            let mut service =
                MerchantSettlementAdoptionService::restore(self.checkpoint.clone(), self.policy)?;
            let outcome = service.apply_bitcoin_recovery_observation(observation, approved)?;
            self.sink.apply(&outcome);
            self.checkpoint = service.snapshot();
            Ok(outcome)
        }
    }

    #[test]
    fn liquid_one_confirmation_records_actual_value_once_then_finalizes() {
        let mut service = service(MerchantSettlementPath::LiquidClaim);
        let mut sink = DeterministicAccountingSink::default();
        assert!(service.repair_accounting_intent().is_none());

        let one_confirmation = verified(
            MerchantSettlementPath::LiquidClaim,
            ORIGINAL_TXID,
            false,
            73_219,
            1,
            900_000,
            BLOCK_A,
        );
        let outcome = service
            .apply_verified_confirmation(&one_confirmation)
            .unwrap();
        sink.apply(&outcome);
        assert_eq!(sink.active_value_sat(), 73_219);
        assert_eq!(sink.total_records(), 1);
        assert_eq!(
            service
                .repair_accounting_intent()
                .unwrap()
                .actual_amount_sat,
            73_219
        );

        let final_confirmation = verified(
            MerchantSettlementPath::LiquidClaim,
            ORIGINAL_TXID,
            false,
            73_219,
            2,
            900_000,
            BLOCK_A,
        );
        let outcome = service
            .apply_verified_confirmation(&final_confirmation)
            .unwrap();
        assert_eq!(outcome.commands.len(), 1);
        sink.apply(&outcome);
        assert_eq!(sink.active_value_sat(), 73_219);
        assert_eq!(sink.total_records(), 1);
        assert!(sink.events.values().next().unwrap().finalized);

        let duplicate = service
            .apply_verified_confirmation(&final_confirmation)
            .unwrap();
        assert!(duplicate.commands.is_empty());
    }

    #[test]
    fn linked_bitcoin_replacement_demotes_original_and_records_distinct_output() {
        let mut service = service(MerchantSettlementPath::BitcoinRecovery);
        let mut sink = DeterministicAccountingSink::default();
        let original = verified(
            MerchantSettlementPath::BitcoinRecovery,
            ORIGINAL_TXID,
            false,
            97_000,
            1,
            840_000,
            BLOCK_A,
        );
        sink.apply(&service.apply_verified_confirmation(&original).unwrap());

        let replacement = verified(
            MerchantSettlementPath::BitcoinRecovery,
            REPLACEMENT_TXID,
            true,
            96_000,
            1,
            840_001,
            BLOCK_B,
        );
        let outcome = service.apply_verified_confirmation(&replacement).unwrap();
        sink.apply(&outcome);
        assert_eq!(sink.events.len(), 2);
        assert_eq!(sink.total_records(), 2);
        assert_eq!(sink.active_value_sat(), 96_000);
        let mut families = sink
            .events
            .values()
            .map(|event| event.intent.identity.family_key());
        assert_eq!(families.next(), families.next());

        let replacement_final = verified(
            MerchantSettlementPath::BitcoinRecovery,
            REPLACEMENT_TXID,
            true,
            96_000,
            3,
            840_001,
            BLOCK_B,
        );
        sink.apply(
            &service
                .apply_verified_confirmation(&replacement_final)
                .unwrap(),
        );
        assert_eq!(sink.active_value_sat(), 96_000);
        assert_eq!(sink.total_records(), 2);
    }

    #[test]
    fn eviction_and_reconfirmation_reactivate_same_event_without_reinsertion() {
        let mut service = service(MerchantSettlementPath::BitcoinRecovery);
        let mut sink = DeterministicAccountingSink::default();
        let confirmed = verified(
            MerchantSettlementPath::BitcoinRecovery,
            ORIGINAL_TXID,
            false,
            51_000,
            1,
            840_000,
            BLOCK_A,
        );
        sink.apply(&service.apply_verified_confirmation(&confirmed).unwrap());

        let evicted = service.apply_eviction().unwrap();
        assert!(evicted.redrive_observation);
        assert!(evicted.rebroadcast_journaled);
        sink.apply(&evicted);
        assert_eq!(sink.active_value_sat(), 0);
        assert!(service.repair_accounting_intent().is_none());

        sink.apply(&service.apply_verified_confirmation(&confirmed).unwrap());
        assert_eq!(sink.active_value_sat(), 51_000);
        assert_eq!(sink.total_records(), 1);
    }

    #[test]
    fn reorg_and_new_block_reconfirmation_reactivate_same_event() {
        let mut service = service(MerchantSettlementPath::LiquidClaim);
        let mut sink = DeterministicAccountingSink::default();
        let first_block = verified(
            MerchantSettlementPath::LiquidClaim,
            ORIGINAL_TXID,
            false,
            62_000,
            1,
            900_000,
            BLOCK_A,
        );
        sink.apply(&service.apply_verified_confirmation(&first_block).unwrap());
        let reorg = service.apply_reorg(900_000, BLOCK_A).unwrap();
        assert!(reorg.redrive_observation);
        sink.apply(&reorg);
        assert_eq!(sink.active_value_sat(), 0);

        let new_block = verified(
            MerchantSettlementPath::LiquidClaim,
            ORIGINAL_TXID,
            false,
            62_000,
            1,
            900_001,
            BLOCK_B,
        );
        sink.apply(&service.apply_verified_confirmation(&new_block).unwrap());
        assert_eq!(sink.active_value_sat(), 62_000);
        assert_eq!(sink.total_records(), 1);
    }

    #[test]
    fn restart_redrive_and_confirmed_repair_reuse_the_same_event() {
        let mut service = service(MerchantSettlementPath::BitcoinRecovery);
        let confirmed = verified(
            MerchantSettlementPath::BitcoinRecovery,
            ORIGINAL_TXID,
            false,
            88_000,
            1,
            840_000,
            BLOCK_A,
        );
        let first = service.apply_verified_confirmation(&confirmed).unwrap();
        let first_intent = match &first.commands[0] {
            MerchantSettlementPersistenceCommand::Record(intent) => intent.clone(),
            command => panic!("unexpected first command: {command:?}"),
        };

        let mut restarted = MerchantSettlementAdoptionService::restore(
            service.snapshot(),
            SettlementFinalityPolicy::new(2, 3).unwrap(),
        )
        .unwrap();
        let duplicate = restarted.apply_verified_confirmation(&confirmed).unwrap();
        assert!(duplicate.commands.is_empty());
        assert_eq!(restarted.repair_accounting_intent(), Some(&first_intent));
        assert!(restarted.blocks_value_changing_fallback());
    }

    #[test]
    fn liquid_source_mempool_then_confirmation_records_exact_output() {
        let fixture = LiquidSourceFixture::new(88_000, 87_000);
        let approved = fixture.approved();
        let mut service = fixture.service();
        let mempool = fixture.observation(false, MerchantConfirmationEvidence::Mempool);
        let mempool_outcome = service
            .apply_liquid_observation(&mempool, &approved)
            .unwrap();
        assert!(mempool_outcome.commands.is_empty());
        assert!(matches!(
            service.lifecycle().state(),
            SettlementState::Mempool
        ));
        assert!(service.repair_accounting_intent().is_none());

        let confirmed = fixture.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 700_000,
                block_hash: BLOCK_A,
            },
        );
        let outcome = service
            .apply_liquid_observation(&confirmed, &approved)
            .unwrap();
        let MerchantSettlementPersistenceCommand::Record(intent) = &outcome.commands[0] else {
            panic!("first confirmation must record exact output")
        };
        assert_eq!(intent.actual_amount_sat, 88_000);
        assert_eq!(intent.txid, fixture.original_txid);
    }

    #[test]
    fn liquid_source_linked_replacement_mempool_then_confirmation_is_distinct() {
        let fixture = LiquidSourceFixture::new(88_000, 87_000);
        let approved = fixture.approved();
        let mut service = fixture.service();
        service
            .apply_liquid_observation(
                &fixture.observation(false, MerchantConfirmationEvidence::Mempool),
                &approved,
            )
            .unwrap();
        let replacement_mempool = fixture.observation(true, MerchantConfirmationEvidence::Mempool);
        let mempool_outcome = service
            .apply_liquid_observation(&replacement_mempool, &approved)
            .unwrap();
        assert!(mempool_outcome.commands.is_empty());
        assert!(mempool_outcome.redrive_observation);
        assert_eq!(
            service.lifecycle().active_txid().as_str(),
            fixture.replacement_txid
        );

        let confirmed = fixture.observation(
            true,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 700_001,
                block_hash: BLOCK_B,
            },
        );
        let outcome = service
            .apply_liquid_observation(&confirmed, &approved)
            .unwrap();
        let MerchantSettlementPersistenceCommand::Record(intent) = &outcome.commands[0] else {
            panic!("replacement confirmation must record its own output")
        };
        assert_eq!(intent.actual_amount_sat, 87_000);
        assert_eq!(intent.txid, fixture.replacement_txid);
        assert!(intent
            .identity
            .event_key()
            .contains(&fixture.replacement_txid));
    }

    #[test]
    fn liquid_source_eviction_and_reorg_redrive_on_separate_ticks() {
        let fixture = LiquidSourceFixture::new(88_000, 87_000);
        let approved = fixture.approved();
        let mut service = fixture.service();
        let confirmed_a = fixture.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 700_000,
                block_hash: BLOCK_A,
            },
        );
        service
            .apply_liquid_observation(&confirmed_a, &approved)
            .unwrap();
        let eviction = LiquidMerchantOutputObservation::Evicted {
            txid: fixture.original_txid.clone(),
        };
        let first_tick = service
            .apply_liquid_observation(&eviction, &approved)
            .unwrap();
        assert!(first_tick.redrive_observation);
        assert!(matches!(
            first_tick.commands.as_slice(),
            [MerchantSettlementPersistenceCommand::Deactivate(_)]
        ));
        let second_tick = service
            .apply_liquid_observation(&confirmed_a, &approved)
            .unwrap();
        assert!(matches!(
            second_tick.commands.as_slice(),
            [MerchantSettlementPersistenceCommand::Activate(_)]
        ));

        let reorg = LiquidMerchantOutputObservation::ReorgDemoted {
            txid: fixture.original_txid.clone(),
            previous_block_height: 700_000,
            previous_block_hash: BLOCK_A.to_owned(),
        };
        let first_tick = service.apply_liquid_observation(&reorg, &approved).unwrap();
        assert!(first_tick.redrive_observation);
        let confirmed_b = fixture.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 700_001,
                block_hash: BLOCK_B,
            },
        );
        let second_tick = service
            .apply_liquid_observation(&confirmed_b, &approved)
            .unwrap();
        assert!(matches!(
            second_tick.commands.as_slice(),
            [MerchantSettlementPersistenceCommand::Activate(_)]
        ));
    }

    #[test]
    fn liquid_source_checkpoint_restore_repairs_and_rejects_mismatched_demotion() {
        let fixture = LiquidSourceFixture::new(88_000, 87_000);
        let approved = fixture.approved();
        let mut service = fixture.service();
        let confirmed = fixture.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 700_000,
                block_hash: BLOCK_A,
            },
        );
        service
            .apply_liquid_observation(&confirmed, &approved)
            .unwrap();
        let snapshot = service.snapshot();
        let mut restored = MerchantSettlementAdoptionService::restore(
            snapshot.clone(),
            SettlementFinalityPolicy::new(2, 3).unwrap(),
        )
        .unwrap();
        assert_eq!(
            restored
                .repair_accounting_intent()
                .unwrap()
                .actual_amount_sat,
            88_000
        );

        let before = restored.snapshot();
        let mismatched = LiquidMerchantOutputObservation::Evicted {
            txid: REPLACEMENT_TXID.to_owned(),
        };
        assert_eq!(
            restored.apply_liquid_observation(&mismatched, &approved),
            Err(MerchantSettlementProcessingError::ObservationTransactionMismatch)
        );
        assert_eq!(restored.snapshot(), before);

        let mut malformed = snapshot;
        malformed.active_event_key = Some("wrong-event".to_owned());
        assert_eq!(
            MerchantSettlementAdoptionService::restore(
                malformed,
                SettlementFinalityPolicy::new(2, 3).unwrap(),
            ),
            Err(MerchantSettlementProcessingError::InvalidCheckpoint)
        );
    }

    #[test]
    fn bitcoin_source_accounts_at_one_and_finalizes_only_at_three_confirmations() {
        let fixture = BitcoinSourceFixture::new();
        let approved = fixture.approved();
        let mut service = fixture.service();
        let mempool = fixture.observation(false, MerchantConfirmationEvidence::Mempool);
        assert!(service
            .apply_bitcoin_recovery_observation(&mempool, &approved)
            .unwrap()
            .commands
            .is_empty());

        let confirmed_one = fixture.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 840_000,
                block_hash: BLOCK_A,
            },
        );
        let one = service
            .apply_bitcoin_recovery_observation(&confirmed_one, &approved)
            .unwrap();
        let MerchantSettlementPersistenceCommand::Record(intent) = &one.commands[0] else {
            panic!("one confirmation must record the exact Bitcoin output")
        };
        assert_eq!(intent.actual_amount_sat, 89_000);
        assert_eq!(intent.txid, fixture.original_txid);
        assert!(matches!(
            service.lifecycle().state(),
            SettlementState::Confirmed {
                required_confirmations: 3,
                ..
            }
        ));

        let confirmed_two = fixture.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 2,
                block_height: 840_000,
                block_hash: BLOCK_A,
            },
        );
        assert!(service
            .apply_bitcoin_recovery_observation(&confirmed_two, &approved)
            .unwrap()
            .commands
            .is_empty());

        let confirmed_three = fixture.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 3,
                block_height: 840_000,
                block_hash: BLOCK_A,
            },
        );
        assert!(matches!(
            service
                .apply_bitcoin_recovery_observation(&confirmed_three, &approved)
                .unwrap()
                .commands
                .as_slice(),
            [MerchantSettlementPersistenceCommand::Finalize(_)]
        ));
    }

    #[test]
    fn bitcoin_source_demotion_is_active_tx_bound_and_redrives() {
        let fixture = BitcoinSourceFixture::new();
        let approved = fixture.approved();
        let mut service = fixture.service();
        let confirmed_a = fixture.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 840_000,
                block_hash: BLOCK_A,
            },
        );
        service
            .apply_bitcoin_recovery_observation(&confirmed_a, &approved)
            .unwrap();

        let before = service.snapshot();
        let wrong_eviction = BitcoinMerchantOutputObservation::Evicted {
            txid: fixture.replacement_txid.clone(),
        };
        assert_eq!(
            service.apply_bitcoin_recovery_observation(&wrong_eviction, &approved),
            Err(MerchantSettlementProcessingError::ObservationTransactionMismatch)
        );
        assert_eq!(service.snapshot(), before);

        let eviction = BitcoinMerchantOutputObservation::Evicted {
            txid: fixture.original_txid.clone(),
        };
        let evicted = service
            .apply_bitcoin_recovery_observation(&eviction, &approved)
            .unwrap();
        assert!(evicted.redrive_observation);
        assert!(matches!(
            evicted.commands.as_slice(),
            [MerchantSettlementPersistenceCommand::Deactivate(_)]
        ));
        assert!(matches!(
            service
                .apply_bitcoin_recovery_observation(&confirmed_a, &approved)
                .unwrap()
                .commands
                .as_slice(),
            [MerchantSettlementPersistenceCommand::Activate(_)]
        ));

        let reorg = BitcoinMerchantOutputObservation::ReorgDemoted {
            txid: fixture.original_txid.clone(),
            previous_block_height: 840_000,
            previous_block_hash: BLOCK_A.to_owned(),
        };
        let reorged = service
            .apply_bitcoin_recovery_observation(&reorg, &approved)
            .unwrap();
        assert!(reorged.redrive_observation);
        let confirmed_b = fixture.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 840_001,
                block_hash: BLOCK_B,
            },
        );
        assert!(matches!(
            service
                .apply_bitcoin_recovery_observation(&confirmed_b, &approved)
                .unwrap()
                .commands
                .as_slice(),
            [MerchantSettlementPersistenceCommand::Activate(_)]
        ));
    }

    #[test]
    fn bitcoin_source_linked_replacement_restores_and_refuses_parent_demotion() {
        let fixture = BitcoinSourceFixture::new();
        let approved = fixture.approved();
        let mut service = fixture.service();
        service
            .apply_bitcoin_recovery_observation(
                &fixture.observation(false, MerchantConfirmationEvidence::Mempool),
                &approved,
            )
            .unwrap();
        service
            .apply_bitcoin_recovery_observation(
                &fixture.observation(true, MerchantConfirmationEvidence::Mempool),
                &approved,
            )
            .unwrap();
        let replacement = fixture.observation(
            true,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 840_001,
                block_hash: BLOCK_B,
            },
        );
        let outcome = service
            .apply_bitcoin_recovery_observation(&replacement, &approved)
            .unwrap();
        let MerchantSettlementPersistenceCommand::Record(intent) = &outcome.commands[0] else {
            panic!("replacement confirmation must record its exact output")
        };
        assert_eq!(intent.actual_amount_sat, 88_000);
        assert_eq!(intent.txid, fixture.replacement_txid);
        assert!(intent
            .identity
            .event_key()
            .contains(&fixture.replacement_txid));

        let mut restored = MerchantSettlementAdoptionService::restore(
            service.snapshot(),
            SettlementFinalityPolicy::new(2, 3).unwrap(),
        )
        .unwrap();
        assert!(restored
            .apply_bitcoin_recovery_observation(&replacement, &approved)
            .unwrap()
            .commands
            .is_empty());
        assert_eq!(
            restored.repair_accounting_intent().unwrap().txid,
            fixture.replacement_txid
        );

        let before = restored.snapshot();
        let stale_parent_reorg = BitcoinMerchantOutputObservation::ReorgDemoted {
            txid: fixture.original_txid,
            previous_block_height: 840_001,
            previous_block_hash: BLOCK_B.to_owned(),
        };
        assert_eq!(
            restored.apply_bitcoin_recovery_observation(&stale_parent_reorg, &approved),
            Err(MerchantSettlementProcessingError::ObservationTransactionMismatch)
        );
        assert_eq!(restored.snapshot(), before);
    }

    #[test]
    fn restoring_worker_two_tick_redrive_is_exact_across_both_rails() {
        let liquid = LiquidSourceFixture::new(88_000, 87_000);
        let liquid_approved = liquid.approved();
        let mut liquid_worker = DeterministicRestoringWorker::new(liquid.service());
        liquid_worker
            .liquid_tick(
                &liquid.observation(false, MerchantConfirmationEvidence::Mempool),
                &liquid_approved,
            )
            .unwrap();
        let liquid_confirmed = liquid.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 700_000,
                block_hash: BLOCK_A,
            },
        );
        liquid_worker
            .liquid_tick(&liquid_confirmed, &liquid_approved)
            .unwrap();
        assert_eq!(liquid_worker.sink.active_value_sat(), 88_000);

        let liquid_evicted = LiquidMerchantOutputObservation::Evicted {
            txid: liquid.original_txid.clone(),
        };
        let first_tick = liquid_worker
            .liquid_tick(&liquid_evicted, &liquid_approved)
            .unwrap();
        assert!(first_tick.redrive_observation);
        assert!(first_tick.rebroadcast_journaled);
        assert!(matches!(
            first_tick.commands.as_slice(),
            [MerchantSettlementPersistenceCommand::Deactivate(_)]
        ));
        assert_eq!(liquid_worker.sink.active_value_sat(), 0);
        let second_tick = liquid_worker
            .liquid_tick(&liquid_confirmed, &liquid_approved)
            .unwrap();
        assert!(matches!(
            second_tick.commands.as_slice(),
            [MerchantSettlementPersistenceCommand::Activate(_)]
        ));
        assert_eq!(liquid_worker.sink.active_value_sat(), 88_000);
        assert_eq!(liquid_worker.sink.total_records(), 1);

        let bitcoin = BitcoinSourceFixture::new();
        let bitcoin_approved = bitcoin.approved();
        let mut bitcoin_worker = DeterministicRestoringWorker::new(bitcoin.service());
        bitcoin_worker
            .bitcoin_tick(
                &bitcoin.observation(false, MerchantConfirmationEvidence::Mempool),
                &bitcoin_approved,
            )
            .unwrap();
        let bitcoin_confirmed_a = bitcoin.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 840_000,
                block_hash: BLOCK_A,
            },
        );
        bitcoin_worker
            .bitcoin_tick(&bitcoin_confirmed_a, &bitcoin_approved)
            .unwrap();
        assert_eq!(bitcoin_worker.sink.active_value_sat(), 89_000);

        let bitcoin_reorged = BitcoinMerchantOutputObservation::ReorgDemoted {
            txid: bitcoin.original_txid.clone(),
            previous_block_height: 840_000,
            previous_block_hash: BLOCK_A.to_owned(),
        };
        let first_tick = bitcoin_worker
            .bitcoin_tick(&bitcoin_reorged, &bitcoin_approved)
            .unwrap();
        assert!(first_tick.redrive_observation);
        assert!(!first_tick.rebroadcast_journaled);
        assert_eq!(bitcoin_worker.sink.active_value_sat(), 0);

        let bitcoin_confirmed_b = bitcoin.observation(
            false,
            MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 840_001,
                block_hash: BLOCK_B,
            },
        );
        let second_tick = bitcoin_worker
            .bitcoin_tick(&bitcoin_confirmed_b, &bitcoin_approved)
            .unwrap();
        assert!(matches!(
            second_tick.commands.as_slice(),
            [MerchantSettlementPersistenceCommand::Activate(_)]
        ));
        assert_eq!(bitcoin_worker.sink.active_value_sat(), 89_000);
        assert_eq!(bitcoin_worker.sink.total_records(), 1);

        let checkpoint_before_mismatch = bitcoin_worker.checkpoint.clone();
        let value_before_mismatch = bitcoin_worker.sink.active_value_sat();
        let mismatched = BitcoinMerchantOutputObservation::Evicted {
            txid: bitcoin.replacement_txid,
        };
        assert_eq!(
            bitcoin_worker.bitcoin_tick(&mismatched, &bitcoin_approved),
            Err(MerchantSettlementProcessingError::ObservationTransactionMismatch)
        );
        assert_eq!(bitcoin_worker.checkpoint, checkpoint_before_mismatch);
        assert_eq!(
            bitcoin_worker.sink.active_value_sat(),
            value_before_mismatch
        );
    }

    #[test]
    fn verifier_mismatch_and_unlinked_candidate_leave_service_unchanged() {
        let service = service(MerchantSettlementPath::BitcoinRecovery);
        let before = service.clone();
        let destination = destination(MerchantSettlementPath::BitcoinRecovery);
        let approved = ApprovedMerchantDestination::bitcoin(
            destination.address.clone(),
            destination.script.clone(),
        );
        let candidate = JournaledMerchantTransaction::original(
            ORIGINAL_TXID,
            destination.address.clone(),
            destination.script.clone(),
            MerchantAsset::Bitcoin,
            10_000,
            0,
        );
        let mismatch = verify_merchant_output(
            ORIGINAL_TXID,
            &candidate,
            &approved,
            &MerchantOutputEvidence::Authoritative(ObservedMerchantOutput::new(
                ORIGINAL_TXID,
                destination.script.clone(),
                MerchantAsset::Bitcoin,
                9_999,
                0,
                1,
                Some(840_000),
                Some(BLOCK_A.to_owned()),
            )),
            1,
        );
        assert_eq!(
            mismatch,
            Err(MerchantOutputVerificationError::AmountMismatch)
        );
        assert_eq!(service, before);

        let unlinked_candidate = JournaledMerchantTransaction::original(
            REPLACEMENT_TXID,
            destination.address,
            destination.script,
            MerchantAsset::Bitcoin,
            10_000,
            0,
        );
        assert_eq!(
            verify_merchant_output(
                ORIGINAL_TXID,
                &unlinked_candidate,
                &approved,
                &MerchantOutputEvidence::Unknown,
                1,
            ),
            Err(MerchantOutputVerificationError::UnlinkedTransaction)
        );
        assert_eq!(service, before);
    }
}

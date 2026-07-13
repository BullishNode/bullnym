//! Schema-independent composition of verified merchant outputs with the
//! settlement lifecycle reducer.
//!
//! This service deliberately returns persistence commands rather than writing
//! a repository. A later migration-owned adapter must commit the lifecycle
//! checkpoint, retained verifier evidence, and these commands atomically.

use std::{collections::BTreeMap, fmt};

use crate::{
    merchant_output_verifier::VerifiedMerchantOutput,
    merchant_settlement_adoption::{
        ConfirmedMerchantOutputEvidence, MerchantOutputAccountingIdentity,
        MerchantOutputAccountingIntent, MerchantSettlementAdoptionError, MerchantSettlementContext,
        MerchantSettlementPath,
    },
    merchant_settlement_lifecycle::{
        apply_settlement_evidence, MerchantSettlementLifecycle, SettlementAccountingState,
        SettlementBlock, SettlementChain, SettlementEvidence, SettlementFinalityPolicy,
        SettlementLifecycleError, SettlementTransition, SettlementTxid,
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

/// Restart-safe, pure service state. Cloning this value models loading an
/// atomic repository checkpoint after a process restart.
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
    JournalMismatch,
    UnlinkedReplacement,
    MissingRetainedEvidence,
    ImmutableEvidenceConflict,
    ActiveFamilyConflict,
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

impl fmt::Display for MerchantSettlementProcessingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Adoption(_) => "verified merchant output cannot be adopted",
            Self::Lifecycle(_) => "merchant settlement lifecycle rejected evidence",
            Self::JournalMismatch => "verified merchant output belongs to another journal",
            Self::UnlinkedReplacement => "merchant replacement is not explicitly linked",
            Self::MissingRetainedEvidence => "lifecycle accounting lacks verifier evidence",
            Self::ImmutableEvidenceConflict => "merchant accounting event is immutable",
            Self::ActiveFamilyConflict => "merchant accounting family already has an active event",
        })
    }
}

impl std::error::Error for MerchantSettlementProcessingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::btree_map::Entry, str::FromStr};

    use crate::merchant_output_verifier::{
        verify_merchant_output, ApprovedMerchantDestination, JournaledMerchantTransaction,
        MerchantAsset, MerchantOutputEvidence, MerchantOutputVerificationError,
        ObservedMerchantOutput,
    };
    use lwk_wollet::elements::Address as LiquidAddress;
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

        let mut restarted = service.clone();
        let duplicate = restarted.apply_verified_confirmation(&confirmed).unwrap();
        assert!(duplicate.commands.is_empty());
        assert_eq!(restarted.repair_accounting_intent(), Some(&first_intent));
        assert!(restarted.blocks_value_changing_fallback());
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

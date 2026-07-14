//! Schema-free projection of independently audited Bitcoin user-lock facts.
//!
//! Boltz assigns one primary funding transaction to a chain swap. A provider
//! transaction id may identify that transaction only after the configured
//! Bitcoin authority independently found and validated it. Other transactions
//! to the same old address are not additional Liquid settlements. Exact
//! recovery inputs remain a later #62 construction concern.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::chain_lockup_witness_audit::{
    ChainLockupConflictFieldV1, ChainLockupFindingClassificationV1, ChainLockupInclusionV1,
    ChainLockupManifestWitnessAuditV1, ChainLockupSpendV1,
    MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_PER_MANIFEST_V1,
};
use crate::chain_swap_action::{BitcoinSourceEvidence, ChainSwapEvidence, EvidenceQuality};

const HASH_HEX_CHARS: usize = 64;
const MAX_BITCOIN_MONEY_SAT: u64 = 2_100_000_000_000_000;
const REDACTED: &str = "<redacted>";

/// Authority attached by the configured Bitcoin evidence collector.
///
/// A single third-party response is useful for retrying but cannot prove an
/// empty address history or authorize an irreversible spend classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryBitcoinSourceAuthorityV1 {
    SelfHostedNode,
    BackendAgreement,
    UntrustedSingleBackend,
    BackendDisagreement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryBitcoinAmountRelationV1 {
    Unknown,
    NotFunded,
    Exact,
    Underfunded,
    Overfunded,
}

/// One primary-transaction projection for the existing #82 reducer.
///
/// No outpoint collection is exposed or persisted here. The selected txid and
/// verified aggregate amount are retained only to let the evidence assembler
/// reconcile a provider hint and decide whether renegotiation applies.
#[derive(Clone, PartialEq, Eq)]
pub struct PrimaryBitcoinSourceProjectionV1 {
    quality: EvidenceQuality,
    bitcoin_source: BitcoinSourceEvidence,
    primary_txid: Option<String>,
    expected_amount_sat: u64,
    observed_amount_sat: Option<u64>,
    amount_relation: PrimaryBitcoinAmountRelationV1,
    non_primary_transaction_count: usize,
}

impl fmt::Debug for PrimaryBitcoinSourceProjectionV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrimaryBitcoinSourceProjectionV1")
            .field("quality", &self.quality)
            .field("bitcoin_source", &self.bitcoin_source)
            .field(
                "primary_txid",
                &self.primary_txid.as_ref().map(|_| REDACTED),
            )
            .field("expected_amount_sat", &REDACTED)
            .field(
                "observed_amount_sat",
                &self.observed_amount_sat.map(|_| REDACTED),
            )
            .field("amount_relation", &self.amount_relation)
            .field(
                "non_primary_transaction_count",
                &self.non_primary_transaction_count,
            )
            .finish()
    }
}

impl PrimaryBitcoinSourceProjectionV1 {
    pub fn quality(&self) -> EvidenceQuality {
        self.quality
    }

    pub fn bitcoin_source(&self) -> BitcoinSourceEvidence {
        self.bitcoin_source
    }

    pub fn primary_txid(&self) -> Option<&str> {
        self.primary_txid.as_deref()
    }

    pub fn expected_amount_sat(&self) -> u64 {
        self.expected_amount_sat
    }

    pub fn observed_amount_sat(&self) -> Option<u64> {
        self.observed_amount_sat
    }

    pub fn amount_relation(&self) -> PrimaryBitcoinAmountRelationV1 {
        self.amount_relation
    }

    pub fn non_primary_transaction_count(&self) -> usize {
        self.non_primary_transaction_count
    }

    /// Install this independently assembled source fact into the existing
    /// pure #82 snapshot. Other evidence-quality failures remain sticky.
    pub fn apply_to_reducer_evidence(&self, evidence: &mut ChainSwapEvidence) {
        evidence.quality = merge_quality(evidence.quality, self.quality);
        evidence.bitcoin_source = self.bitcoin_source;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryBitcoinSourceProjectionErrorV1 {
    InvalidAuditedEvidence,
    AmountOverflow,
}

impl fmt::Display for PrimaryBitcoinSourceProjectionErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidAuditedEvidence => "primary Bitcoin source evidence is invalid",
            Self::AmountOverflow => "primary Bitcoin source amount is out of range",
        })
    }
}

impl std::error::Error for PrimaryBitcoinSourceProjectionErrorV1 {}

#[derive(Debug)]
struct TransactionCandidate {
    inclusion: ChainLockupInclusionV1,
    observed_amount_sat: u64,
    has_spent_output: bool,
}

/// Select the one Boltz primary user-lock transaction from an independently
/// audited, complete script history.
///
/// If more than one transaction exists, a provider txid is only a selector: it
/// must name a transaction already present in the independently validated
/// history. Without that hint the result stays incomplete instead of choosing
/// by txid, amount, or whichever backend answered first.
pub fn project_primary_bitcoin_source_v1(
    audit: &ChainLockupManifestWitnessAuditV1,
    provider_txid_hint: Option<&str>,
    authority: PrimaryBitcoinSourceAuthorityV1,
) -> Result<PrimaryBitcoinSourceProjectionV1, PrimaryBitcoinSourceProjectionErrorV1> {
    validate_expected_amount(audit.expected_amount_sat)?;
    let candidates = collect_candidates(audit)?;

    match authority {
        PrimaryBitcoinSourceAuthorityV1::UntrustedSingleBackend => {
            return Ok(unknown_projection(
                audit.expected_amount_sat,
                EvidenceQuality::Incomplete,
            ));
        }
        PrimaryBitcoinSourceAuthorityV1::BackendDisagreement => {
            return Ok(unknown_projection(
                audit.expected_amount_sat,
                EvidenceQuality::BackendDisagreement,
            ));
        }
        PrimaryBitcoinSourceAuthorityV1::SelfHostedNode
        | PrimaryBitcoinSourceAuthorityV1::BackendAgreement => {}
    }

    let hinted_txid = match provider_txid_hint {
        Some(txid) if valid_hash(txid) => Some(txid),
        Some(_) => {
            return Ok(unknown_projection(
                audit.expected_amount_sat,
                EvidenceQuality::ProviderDisagreement,
            ));
        }
        None => None,
    };

    if candidates.is_empty() {
        if hinted_txid.is_some() {
            return Ok(unknown_projection(
                audit.expected_amount_sat,
                EvidenceQuality::ProviderDisagreement,
            ));
        }
        return Ok(PrimaryBitcoinSourceProjectionV1 {
            quality: EvidenceQuality::CompleteAndAgreed,
            bitcoin_source: BitcoinSourceEvidence::Unfunded,
            primary_txid: None,
            expected_amount_sat: audit.expected_amount_sat,
            observed_amount_sat: None,
            amount_relation: PrimaryBitcoinAmountRelationV1::NotFunded,
            non_primary_transaction_count: 0,
        });
    }

    let (primary_txid, candidate) = if let Some(hint) = hinted_txid {
        let Some(candidate) = candidates.get(hint) else {
            return Ok(unknown_projection(
                audit.expected_amount_sat,
                EvidenceQuality::ProviderDisagreement,
            ));
        };
        (hint, candidate)
    } else if candidates.len() == 1 {
        candidates
            .first_key_value()
            .map(|(txid, candidate)| (txid.as_str(), candidate))
            .ok_or(PrimaryBitcoinSourceProjectionErrorV1::InvalidAuditedEvidence)?
    } else {
        return Ok(unknown_projection(
            audit.expected_amount_sat,
            EvidenceQuality::Incomplete,
        ));
    };

    let amount_relation = match candidate
        .observed_amount_sat
        .cmp(&audit.expected_amount_sat)
    {
        std::cmp::Ordering::Less => PrimaryBitcoinAmountRelationV1::Underfunded,
        std::cmp::Ordering::Equal => PrimaryBitcoinAmountRelationV1::Exact,
        std::cmp::Ordering::Greater => PrimaryBitcoinAmountRelationV1::Overfunded,
    };
    let bitcoin_source = if candidate.has_spent_output {
        // Linking this independently verified spend to a journaled recovery or
        // a preimage-bearing provider claim belongs to the evidence assembler.
        // Until then it is a positive unknown outspend, never "unfunded".
        BitcoinSourceEvidence::UnknownOutspend
    } else {
        match &candidate.inclusion {
            ChainLockupInclusionV1::Mempool => BitcoinSourceEvidence::MempoolUnspent,
            ChainLockupInclusionV1::Confirmed { .. } => BitcoinSourceEvidence::ConfirmedUnspent,
        }
    };

    Ok(PrimaryBitcoinSourceProjectionV1 {
        quality: EvidenceQuality::CompleteAndAgreed,
        bitcoin_source,
        primary_txid: Some(primary_txid.to_owned()),
        expected_amount_sat: audit.expected_amount_sat,
        observed_amount_sat: Some(candidate.observed_amount_sat),
        amount_relation,
        non_primary_transaction_count: candidates.len().saturating_sub(1),
    })
}

fn collect_candidates(
    audit: &ChainLockupManifestWitnessAuditV1,
) -> Result<BTreeMap<String, TransactionCandidate>, PrimaryBitcoinSourceProjectionErrorV1> {
    if audit.findings.len() > MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_PER_MANIFEST_V1 {
        return Err(PrimaryBitcoinSourceProjectionErrorV1::InvalidAuditedEvidence);
    }

    let mut candidates = BTreeMap::<String, TransactionCandidate>::new();
    let mut seen_outpoints = BTreeSet::new();
    for finding in &audit.findings {
        if !valid_hash(&finding.txid)
            || finding.observed_amount_sat == 0
            || finding.observed_amount_sat > MAX_BITCOIN_MONEY_SAT
            || !seen_outpoints.insert((finding.txid.as_str(), finding.vout))
            || !classification_matches_finding(finding, audit.expected_amount_sat)
        {
            return Err(PrimaryBitcoinSourceProjectionErrorV1::InvalidAuditedEvidence);
        }

        let has_spent_output = matches!(&finding.spend, ChainLockupSpendV1::Spent { .. });
        match candidates.get_mut(&finding.txid) {
            Some(candidate) => {
                if candidate.inclusion != finding.inclusion {
                    return Err(PrimaryBitcoinSourceProjectionErrorV1::InvalidAuditedEvidence);
                }
                candidate.observed_amount_sat = candidate
                    .observed_amount_sat
                    .checked_add(finding.observed_amount_sat)
                    .filter(|amount| *amount <= MAX_BITCOIN_MONEY_SAT)
                    .ok_or(PrimaryBitcoinSourceProjectionErrorV1::AmountOverflow)?;
                candidate.has_spent_output |= has_spent_output;
            }
            None => {
                candidates.insert(
                    finding.txid.clone(),
                    TransactionCandidate {
                        inclusion: finding.inclusion.clone(),
                        observed_amount_sat: finding.observed_amount_sat,
                        has_spent_output,
                    },
                );
            }
        }
    }
    Ok(candidates)
}

fn classification_matches_finding(
    finding: &crate::chain_lockup_witness_audit::ChainLockupWitnessFindingV1,
    expected_amount_sat: u64,
) -> bool {
    match &finding.classification {
        ChainLockupFindingClassificationV1::Unconfirmed => {
            finding.observed_amount_sat == expected_amount_sat
                && matches!(&finding.inclusion, ChainLockupInclusionV1::Mempool)
                && matches!(&finding.spend, ChainLockupSpendV1::Unspent)
        }
        ChainLockupFindingClassificationV1::Confirmed => {
            finding.observed_amount_sat == expected_amount_sat
                && matches!(&finding.inclusion, ChainLockupInclusionV1::Confirmed { .. })
                && matches!(&finding.spend, ChainLockupSpendV1::Unspent)
        }
        ChainLockupFindingClassificationV1::Spent => {
            finding.observed_amount_sat == expected_amount_sat
                && matches!(&finding.spend, ChainLockupSpendV1::Spent { .. })
        }
        ChainLockupFindingClassificationV1::Conflicting { fields } => {
            finding.observed_amount_sat != expected_amount_sat
                && fields.len() == 1
                && fields[0] == ChainLockupConflictFieldV1::ExpectedAmount
        }
    }
}

fn unknown_projection(
    expected_amount_sat: u64,
    quality: EvidenceQuality,
) -> PrimaryBitcoinSourceProjectionV1 {
    PrimaryBitcoinSourceProjectionV1 {
        quality,
        bitcoin_source: BitcoinSourceEvidence::Unknown,
        primary_txid: None,
        expected_amount_sat,
        observed_amount_sat: None,
        amount_relation: PrimaryBitcoinAmountRelationV1::Unknown,
        non_primary_transaction_count: 0,
    }
}

fn validate_expected_amount(amount_sat: u64) -> Result<(), PrimaryBitcoinSourceProjectionErrorV1> {
    if amount_sat == 0 || amount_sat > MAX_BITCOIN_MONEY_SAT {
        return Err(PrimaryBitcoinSourceProjectionErrorV1::InvalidAuditedEvidence);
    }
    Ok(())
}

const fn merge_quality(left: EvidenceQuality, right: EvidenceQuality) -> EvidenceQuality {
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

fn valid_hash(value: &str) -> bool {
    value.len() == HASH_HEX_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::chain_lockup_witness_audit::{
        ChainLockupFindingClassificationV1 as Classification, ChainLockupManifestClassificationV1,
        ChainLockupWitnessFindingV1,
    };
    use crate::chain_swap_action::{
        reduce_chain_swap_evidence, BitcoinTimeoutEvidence, ChainSwapAction,
        CooperativeRecoveryEvidence, LiquidLockEvidence, LiquidPathEvidence,
        MerchantTransactionEvidence, ProviderStatusEvidence, RecoveryDestinationEvidence,
        RenegotiationEvidence,
    };

    const EXPECTED_SAT: u64 = 42_000;

    fn hash(byte: char) -> String {
        byte.to_string().repeat(HASH_HEX_CHARS)
    }

    fn confirmed() -> ChainLockupInclusionV1 {
        ChainLockupInclusionV1::Confirmed {
            confirmations: 3,
            block_height: 900_000,
            block_hash: hash('b'),
        }
    }

    fn finding(tx_byte: char, vout: u32, amount_sat: u64) -> ChainLockupWitnessFindingV1 {
        let classification = if amount_sat == EXPECTED_SAT {
            Classification::Confirmed
        } else {
            Classification::Conflicting {
                fields: vec![ChainLockupConflictFieldV1::ExpectedAmount],
            }
        };
        ChainLockupWitnessFindingV1 {
            txid: hash(tx_byte),
            vout,
            observed_amount_sat: amount_sat,
            inclusion: confirmed(),
            spend: ChainLockupSpendV1::Unspent,
            classification,
        }
    }

    fn audit(findings: Vec<ChainLockupWitnessFindingV1>) -> ChainLockupManifestWitnessAuditV1 {
        ChainLockupManifestWitnessAuditV1 {
            manifest_sequence: 1,
            manifest_id: Uuid::from_u128(1),
            chain_swap_id: Uuid::from_u128(2),
            expected_amount_sat: EXPECTED_SAT,
            classification: if findings.is_empty() {
                ChainLockupManifestClassificationV1::Missing
            } else {
                ChainLockupManifestClassificationV1::Confirmed
            },
            findings,
        }
    }

    fn reducer_fixture() -> ChainSwapEvidence {
        ChainSwapEvidence {
            quality: EvidenceQuality::CompleteAndAgreed,
            provider_status: ProviderStatusEvidence::Expired,
            bitcoin_source: BitcoinSourceEvidence::Unknown,
            liquid_lock: LiquidLockEvidence::NotObserved,
            liquid_path: LiquidPathEvidence::Unavailable,
            renegotiation: RenegotiationEvidence::ExplicitlyUnavailable,
            recovery_destination: RecoveryDestinationEvidence::Committed,
            cooperative_recovery: CooperativeRecoveryEvidence::Unavailable,
            bitcoin_timeout: BitcoinTimeoutEvidence::BeforeTimeout,
            liquid_claim_transaction: MerchantTransactionEvidence::None,
            bitcoin_recovery_transaction: MerchantTransactionEvidence::None,
        }
    }

    #[test]
    fn only_authoritative_empty_history_proves_unfunded_and_can_finalize_expiry() {
        for authority in [
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
            PrimaryBitcoinSourceAuthorityV1::BackendAgreement,
        ] {
            let projection =
                project_primary_bitcoin_source_v1(&audit(vec![]), None, authority).unwrap();
            assert_eq!(projection.quality(), EvidenceQuality::CompleteAndAgreed);
            assert_eq!(projection.bitcoin_source(), BitcoinSourceEvidence::Unfunded);
            assert_eq!(
                projection.amount_relation(),
                PrimaryBitcoinAmountRelationV1::NotFunded
            );

            let mut evidence = reducer_fixture();
            projection.apply_to_reducer_evidence(&mut evidence);
            assert_eq!(
                reduce_chain_swap_evidence(&evidence),
                ChainSwapAction::Finalize
            );
        }
    }

    #[test]
    fn single_backend_empty_history_never_terminalizes_provider_expiry() {
        let projection = project_primary_bitcoin_source_v1(
            &audit(vec![]),
            None,
            PrimaryBitcoinSourceAuthorityV1::UntrustedSingleBackend,
        )
        .unwrap();
        assert_eq!(projection.quality(), EvidenceQuality::Incomplete);
        assert_eq!(projection.bitcoin_source(), BitcoinSourceEvidence::Unknown);

        let mut evidence = reducer_fixture();
        projection.apply_to_reducer_evidence(&mut evidence);
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            ChainSwapAction::Observe
        );
    }

    #[test]
    fn provider_hint_must_exist_in_the_independent_history() {
        let projection = project_primary_bitcoin_source_v1(
            &audit(vec![finding('a', 0, EXPECTED_SAT)]),
            Some(&hash('c')),
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
        )
        .unwrap();
        assert_eq!(projection.quality(), EvidenceQuality::ProviderDisagreement);
        assert_eq!(projection.bitcoin_source(), BitcoinSourceEvidence::Unknown);

        let mut evidence = reducer_fixture();
        projection.apply_to_reducer_evidence(&mut evidence);
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            ChainSwapAction::Observe
        );
    }

    #[test]
    fn exact_primary_transaction_maps_to_confirmed_unspent() {
        let projection = project_primary_bitcoin_source_v1(
            &audit(vec![finding('a', 0, EXPECTED_SAT)]),
            Some(&hash('a')),
            PrimaryBitcoinSourceAuthorityV1::BackendAgreement,
        )
        .unwrap();
        assert_eq!(
            projection.bitcoin_source(),
            BitcoinSourceEvidence::ConfirmedUnspent
        );
        assert_eq!(projection.primary_txid(), Some(hash('a').as_str()));
        assert_eq!(projection.observed_amount_sat(), Some(EXPECTED_SAT));
        assert_eq!(
            projection.amount_relation(),
            PrimaryBitcoinAmountRelationV1::Exact
        );
        assert_eq!(projection.non_primary_transaction_count(), 0);
    }

    #[test]
    fn mempool_primary_stays_observed_even_when_the_provider_says_expired() {
        let mut mempool = finding('a', 0, EXPECTED_SAT);
        mempool.inclusion = ChainLockupInclusionV1::Mempool;
        mempool.classification = Classification::Unconfirmed;
        let projection = project_primary_bitcoin_source_v1(
            &audit(vec![mempool]),
            None,
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
        )
        .unwrap();
        assert_eq!(
            projection.bitcoin_source(),
            BitcoinSourceEvidence::MempoolUnspent
        );

        let mut evidence = reducer_fixture();
        projection.apply_to_reducer_evidence(&mut evidence);
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            ChainSwapAction::Observe
        );
    }

    #[test]
    fn verified_wrong_amount_is_retained_for_renegotiation() {
        for (observed, relation) in [
            (
                EXPECTED_SAT - 1,
                PrimaryBitcoinAmountRelationV1::Underfunded,
            ),
            (EXPECTED_SAT + 1, PrimaryBitcoinAmountRelationV1::Overfunded),
        ] {
            let projection = project_primary_bitcoin_source_v1(
                &audit(vec![finding('a', 0, observed)]),
                None,
                PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
            )
            .unwrap();
            assert_eq!(
                projection.bitcoin_source(),
                BitcoinSourceEvidence::ConfirmedUnspent
            );
            assert_eq!(projection.observed_amount_sat(), Some(observed));
            assert_eq!(projection.amount_relation(), relation);
        }

        let underfunded = project_primary_bitcoin_source_v1(
            &audit(vec![finding('a', 0, EXPECTED_SAT - 1)]),
            None,
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
        )
        .unwrap();

        let mut evidence = reducer_fixture();
        evidence.provider_status = ProviderStatusEvidence::Expired;
        evidence.renegotiation = RenegotiationEvidence::Available;
        underfunded.apply_to_reducer_evidence(&mut evidence);
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            ChainSwapAction::Renegotiate
        );
    }

    #[test]
    fn multiple_transactions_never_become_multiple_settlements() {
        let history = audit(vec![
            finding('a', 0, EXPECTED_SAT),
            finding('c', 0, EXPECTED_SAT),
        ]);
        let no_hint = project_primary_bitcoin_source_v1(
            &history,
            None,
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
        )
        .unwrap();
        assert_eq!(no_hint.quality(), EvidenceQuality::Incomplete);
        assert_eq!(no_hint.bitcoin_source(), BitcoinSourceEvidence::Unknown);

        let selected = project_primary_bitcoin_source_v1(
            &history,
            Some(&hash('a')),
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
        )
        .unwrap();
        assert_eq!(selected.primary_txid(), Some(hash('a').as_str()));
        assert_eq!(selected.non_primary_transaction_count(), 1);
        assert_eq!(selected.observed_amount_sat(), Some(EXPECTED_SAT));
        assert_eq!(
            selected.bitcoin_source(),
            BitcoinSourceEvidence::ConfirmedUnspent
        );
    }

    #[test]
    fn multiple_outputs_in_the_primary_transaction_are_one_aggregate_amount() {
        let projection = project_primary_bitcoin_source_v1(
            &audit(vec![finding('a', 0, 20_000), finding('a', 1, 22_000)]),
            Some(&hash('a')),
            PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
        )
        .unwrap();
        assert_eq!(projection.observed_amount_sat(), Some(EXPECTED_SAT));
        assert_eq!(
            projection.amount_relation(),
            PrimaryBitcoinAmountRelationV1::Exact
        );
        assert_eq!(projection.non_primary_transaction_count(), 0);
    }

    #[test]
    fn independently_observed_unlinked_spend_enters_integrity_hold() {
        let mut spent = finding('a', 0, EXPECTED_SAT);
        spent.spend = ChainLockupSpendV1::Spent {
            spending_txid: hash('d'),
            inclusion: confirmed(),
        };
        spent.classification = Classification::Spent;
        let projection = project_primary_bitcoin_source_v1(
            &audit(vec![spent]),
            Some(&hash('a')),
            PrimaryBitcoinSourceAuthorityV1::BackendAgreement,
        )
        .unwrap();
        assert_eq!(
            projection.bitcoin_source(),
            BitcoinSourceEvidence::UnknownOutspend
        );

        let mut evidence = reducer_fixture();
        projection.apply_to_reducer_evidence(&mut evidence);
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            ChainSwapAction::IntegrityHold
        );
    }

    #[test]
    fn backend_disagreement_stays_observe_even_with_a_candidate() {
        let projection = project_primary_bitcoin_source_v1(
            &audit(vec![finding('a', 0, EXPECTED_SAT)]),
            Some(&hash('a')),
            PrimaryBitcoinSourceAuthorityV1::BackendDisagreement,
        )
        .unwrap();
        assert_eq!(projection.quality(), EvidenceQuality::BackendDisagreement);
        assert_eq!(projection.bitcoin_source(), BitcoinSourceEvidence::Unknown);
        let mut evidence = reducer_fixture();
        projection.apply_to_reducer_evidence(&mut evidence);
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            ChainSwapAction::Observe
        );
    }

    #[test]
    fn structural_target_conflicts_are_not_projected_as_amount_mismatches() {
        let mut invalid = finding('a', 0, EXPECTED_SAT - 1);
        invalid.classification = Classification::Conflicting {
            fields: vec![
                ChainLockupConflictFieldV1::ExpectedAmount,
                ChainLockupConflictFieldV1::LockupScriptPubkey,
            ],
        };
        assert_eq!(
            project_primary_bitcoin_source_v1(
                &audit(vec![invalid]),
                Some(&hash('a')),
                PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
            ),
            Err(PrimaryBitcoinSourceProjectionErrorV1::InvalidAuditedEvidence)
        );
    }
}

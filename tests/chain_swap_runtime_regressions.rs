use pay_service::chain_lockup_witness_audit::{
    ChainLockupFindingClassificationV1, ChainLockupInclusionV1,
    ChainLockupManifestClassificationV1, ChainLockupManifestWitnessAuditV1, ChainLockupSpendV1,
    ChainLockupWitnessFindingV1,
};
use pay_service::chain_swap_action::{
    recheck_chain_swap_execution_under_lock, reduce_chain_swap_evidence, BitcoinSourceEvidence,
    BitcoinTimeoutEvidence, ChainSwapAction, ChainSwapEvidence, ChainSwapExecutionAction,
    ChainSwapExecutionGate, CooperativeRecoveryEvidence, EvidenceQuality, LiquidLockEvidence,
    LiquidPathEvidence, MerchantTransactionEvidence, ProviderStatusEvidence,
    RecoveryDestinationEvidence, RenegotiationEvidence,
};
use pay_service::chain_swap_primary_source::{
    project_primary_bitcoin_source_v1, PrimaryBitcoinSourceAuthorityV1,
};
use pay_service::chain_swap_runtime::{
    decide_chain_swap_provider_effect, ChainSwapProviderEffect, ChainSwapProviderEvidence,
};
use uuid::Uuid;

const EXPECTED_AMOUNT_SAT: u64 = 42_000;

fn hash(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn confirmed() -> ChainLockupInclusionV1 {
    ChainLockupInclusionV1::Confirmed {
        confirmations: 3,
        block_height: 840_000,
        block_hash: hash('b'),
    }
}

fn finding(tx_byte: char, spend: ChainLockupSpendV1) -> ChainLockupWitnessFindingV1 {
    let classification = if matches!(spend, ChainLockupSpendV1::Unspent) {
        ChainLockupFindingClassificationV1::Confirmed
    } else {
        ChainLockupFindingClassificationV1::Spent
    };
    ChainLockupWitnessFindingV1 {
        txid: hash(tx_byte),
        vout: 0,
        observed_amount_sat: EXPECTED_AMOUNT_SAT,
        inclusion: confirmed(),
        spend,
        classification,
    }
}

fn audit(findings: Vec<ChainLockupWitnessFindingV1>) -> ChainLockupManifestWitnessAuditV1 {
    ChainLockupManifestWitnessAuditV1 {
        manifest_sequence: 1,
        manifest_id: Uuid::from_u128(1),
        chain_swap_id: Uuid::from_u128(2),
        expected_amount_sat: EXPECTED_AMOUNT_SAT,
        classification: match findings
            .iter()
            .map(|finding| &finding.classification)
            .max_by_key(|classification| match classification {
                ChainLockupFindingClassificationV1::Unconfirmed => 1,
                ChainLockupFindingClassificationV1::Confirmed => 2,
                ChainLockupFindingClassificationV1::Spent => 3,
                ChainLockupFindingClassificationV1::Conflicting { .. } => 4,
            }) {
            None => ChainLockupManifestClassificationV1::Missing,
            Some(ChainLockupFindingClassificationV1::Unconfirmed) => {
                ChainLockupManifestClassificationV1::Unconfirmed
            }
            Some(ChainLockupFindingClassificationV1::Confirmed) => {
                ChainLockupManifestClassificationV1::Confirmed
            }
            Some(ChainLockupFindingClassificationV1::Spent) => {
                ChainLockupManifestClassificationV1::Spent
            }
            Some(ChainLockupFindingClassificationV1::Conflicting { .. }) => {
                ChainLockupManifestClassificationV1::Conflicting
            }
        },
        findings,
    }
}

fn evidence() -> ChainSwapEvidence {
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

fn assert_every_irreversible_action_is_blocked(
    evidence: &ChainSwapEvidence,
    expected: ChainSwapAction,
) {
    for requested in [
        ChainSwapExecutionAction::ClaimLiquid,
        ChainSwapExecutionAction::RecoverBitcoin,
        ChainSwapExecutionAction::Finalize,
    ] {
        assert_eq!(
            recheck_chain_swap_execution_under_lock(requested, evidence),
            ChainSwapExecutionGate::Blocked(expected),
            "requested={requested:?}, evidence={evidence:#?}"
        );
    }
}

#[test]
fn authoritative_unfunded_and_inconclusive_primary_never_share_a_terminal_decision() {
    let empty_history = audit(vec![]);

    let authoritative = project_primary_bitcoin_source_v1(
        &empty_history,
        None,
        PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
    )
    .unwrap();
    let mut authoritative_evidence = evidence();
    authoritative.apply_to_reducer_evidence(&mut authoritative_evidence);
    assert_eq!(
        authoritative_evidence.bitcoin_source,
        BitcoinSourceEvidence::Unfunded
    );
    assert_eq!(
        reduce_chain_swap_evidence(&authoritative_evidence),
        ChainSwapAction::Finalize
    );
    assert_eq!(
        recheck_chain_swap_execution_under_lock(
            ChainSwapExecutionAction::Finalize,
            &authoritative_evidence,
        ),
        ChainSwapExecutionGate::Authorized
    );
    assert_eq!(
        decide_chain_swap_provider_effect(
            "swap.expired",
            ChainSwapProviderEvidence {
                evidence: authoritative_evidence,
                primary_bitcoin: Some(&authoritative),
            },
        ),
        ChainSwapProviderEffect::FinalizeUnfunded
    );

    for authority in [
        PrimaryBitcoinSourceAuthorityV1::UntrustedSingleBackend,
        PrimaryBitcoinSourceAuthorityV1::BackendDisagreement,
    ] {
        let inconclusive =
            project_primary_bitcoin_source_v1(&empty_history, None, authority).unwrap();
        let mut inconclusive_evidence = evidence();
        inconclusive.apply_to_reducer_evidence(&mut inconclusive_evidence);
        assert_eq!(
            inconclusive_evidence.bitcoin_source,
            BitcoinSourceEvidence::Unknown,
            "authority={authority:?}"
        );
        assert_eq!(
            reduce_chain_swap_evidence(&inconclusive_evidence),
            ChainSwapAction::Observe,
            "authority={authority:?}"
        );
        assert_every_irreversible_action_is_blocked(
            &inconclusive_evidence,
            ChainSwapAction::Observe,
        );
        assert_eq!(
            decide_chain_swap_provider_effect(
                "swap.expired",
                ChainSwapProviderEvidence {
                    evidence: inconclusive_evidence,
                    primary_bitcoin: Some(&inconclusive),
                },
            ),
            ChainSwapProviderEffect::Observe,
            "authority={authority:?}"
        );
    }
}

#[test]
fn provider_txid_disagreement_observes_unless_positive_chain_evidence_requires_a_hold() {
    let independent_history = audit(vec![finding('a', ChainLockupSpendV1::Unspent)]);
    let disagreement = project_primary_bitcoin_source_v1(
        &independent_history,
        Some(&hash('c')),
        PrimaryBitcoinSourceAuthorityV1::BackendAgreement,
    )
    .unwrap();
    let mut disagreement_evidence = evidence();
    disagreement.apply_to_reducer_evidence(&mut disagreement_evidence);
    assert_eq!(
        disagreement_evidence.quality,
        EvidenceQuality::ProviderDisagreement
    );
    assert_eq!(
        reduce_chain_swap_evidence(&disagreement_evidence),
        ChainSwapAction::Observe
    );
    assert_every_irreversible_action_is_blocked(&disagreement_evidence, ChainSwapAction::Observe);
    assert_eq!(
        decide_chain_swap_provider_effect(
            "swap.expired",
            ChainSwapProviderEvidence {
                evidence: disagreement_evidence,
                primary_bitcoin: Some(&disagreement),
            },
        ),
        ChainSwapProviderEffect::Observe
    );

    // A txid disagreement does not suppress a separately verified positive
    // integrity hazard on the other chain.
    disagreement_evidence.liquid_lock = LiquidLockEvidence::UnknownOutspend;
    assert_eq!(
        reduce_chain_swap_evidence(&disagreement_evidence),
        ChainSwapAction::IntegrityHold
    );
    assert_every_irreversible_action_is_blocked(
        &disagreement_evidence,
        ChainSwapAction::IntegrityHold,
    );
    assert_eq!(
        decide_chain_swap_provider_effect(
            "swap.expired",
            ChainSwapProviderEvidence {
                evidence: disagreement_evidence,
                primary_bitcoin: Some(&disagreement),
            },
        ),
        ChainSwapProviderEffect::IntegrityHold
    );
}

#[test]
fn independently_funded_server_lock_claims_while_an_unknown_source_spend_holds() {
    let unspent_projection = project_primary_bitcoin_source_v1(
        &audit(vec![finding('a', ChainLockupSpendV1::Unspent)]),
        Some(&hash('a')),
        PrimaryBitcoinSourceAuthorityV1::BackendAgreement,
    )
    .unwrap();
    let mut claim_evidence = evidence();
    claim_evidence.liquid_lock = LiquidLockEvidence::ConfirmedUnspent;
    unspent_projection.apply_to_reducer_evidence(&mut claim_evidence);
    assert_eq!(
        reduce_chain_swap_evidence(&claim_evidence),
        ChainSwapAction::ClaimLiquid
    );
    assert_eq!(
        recheck_chain_swap_execution_under_lock(
            ChainSwapExecutionAction::ClaimLiquid,
            &claim_evidence,
        ),
        ChainSwapExecutionGate::Authorized
    );
    assert_eq!(
        recheck_chain_swap_execution_under_lock(
            ChainSwapExecutionAction::Finalize,
            &claim_evidence,
        ),
        ChainSwapExecutionGate::Blocked(ChainSwapAction::ClaimLiquid),
        "a newly observed server lock must revoke a stale finalize plan"
    );
    assert_eq!(
        decide_chain_swap_provider_effect(
            "swap.expired",
            ChainSwapProviderEvidence {
                evidence: claim_evidence,
                primary_bitcoin: Some(&unspent_projection),
            },
        ),
        ChainSwapProviderEffect::Reconcile(ChainSwapAction::ClaimLiquid)
    );

    let unknown_spend = ChainLockupSpendV1::Spent {
        spending_txid: hash('d'),
        inclusion: confirmed(),
    };
    let spent_projection = project_primary_bitcoin_source_v1(
        &audit(vec![finding('a', unknown_spend)]),
        Some(&hash('a')),
        PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
    )
    .unwrap();
    let mut hold_evidence = evidence();
    spent_projection.apply_to_reducer_evidence(&mut hold_evidence);
    assert_eq!(
        hold_evidence.bitcoin_source,
        BitcoinSourceEvidence::UnknownOutspend
    );
    assert_eq!(
        reduce_chain_swap_evidence(&hold_evidence),
        ChainSwapAction::IntegrityHold
    );
    assert_every_irreversible_action_is_blocked(&hold_evidence, ChainSwapAction::IntegrityHold);
    assert_eq!(
        decide_chain_swap_provider_effect(
            "swap.expired",
            ChainSwapProviderEvidence {
                evidence: hold_evidence,
                primary_bitcoin: Some(&spent_projection),
            },
        ),
        ChainSwapProviderEffect::IntegrityHold
    );
}

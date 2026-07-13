use pay_service::chain_swap_action::{
    recheck_recovery_under_lock, reduce_chain_swap_evidence, BitcoinSourceEvidence,
    BitcoinTimeoutEvidence, ChainSwapAction, ChainSwapEvidence, CooperativeRecoveryEvidence,
    EvidenceQuality, LiquidLockEvidence, LiquidPathEvidence, MerchantTransactionEvidence,
    ProviderStatusEvidence, RecoveryDestinationEvidence, RecoveryExecutionGate,
    RenegotiationEvidence,
};

#[derive(Debug)]
struct Fixture {
    name: &'static str,
    evidence: ChainSwapEvidence,
    expected: ChainSwapAction,
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

fn fixture(
    name: &'static str,
    expected: ChainSwapAction,
    configure: impl FnOnce(&mut ChainSwapEvidence),
) -> Fixture {
    let mut evidence = recovery_candidate();
    configure(&mut evidence);
    Fixture {
        name,
        evidence,
        expected,
    }
}

fn assert_fixtures(fixtures: impl IntoIterator<Item = Fixture>) {
    for fixture in fixtures {
        assert_eq!(
            reduce_chain_swap_evidence(&fixture.evidence),
            fixture.expected,
            "fixture: {}\nevidence: {:#?}",
            fixture.name,
            fixture.evidence
        );
    }
}

#[test]
fn decision_fixtures_cover_every_action_and_locked_edge_case() {
    use BitcoinSourceEvidence as BitcoinSource;
    use BitcoinTimeoutEvidence as Timeout;
    use ChainSwapAction as Action;
    use CooperativeRecoveryEvidence as Cooperative;
    use EvidenceQuality as Quality;
    use LiquidLockEvidence as LiquidLock;
    use LiquidPathEvidence as LiquidPath;
    use MerchantTransactionEvidence as Transaction;
    use ProviderStatusEvidence as Provider;
    use RecoveryDestinationEvidence as Destination;
    use RenegotiationEvidence as Renegotiation;

    assert_fixtures([
        fixture(
            "complete cooperative fallback",
            Action::RecoverBitcoin,
            |_| {},
        ),
        fixture("incomplete evidence", Action::Observe, |e| {
            e.quality = Quality::Incomplete;
        }),
        fixture("chain backend disagreement", Action::Observe, |e| {
            e.quality = Quality::BackendDisagreement;
        }),
        fixture("provider disagreement", Action::Observe, |e| {
            e.quality = Quality::ProviderDisagreement;
        }),
        fixture(
            "provider API unavailable after durable path closure",
            Action::RecoverBitcoin,
            |e| {
                e.provider_status = Provider::Unknown;
            },
        ),
        fixture(
            "provider settlement hint is not success",
            Action::Observe,
            |e| {
                e.provider_status = Provider::SettlementHint;
            },
        ),
        fixture(
            "provider settlement hint prevents renegotiation",
            Action::Observe,
            |e| {
                e.provider_status = Provider::SettlementHint;
                e.renegotiation = Renegotiation::Available;
            },
        ),
        fixture(
            "active provider hint prevents fallback",
            Action::Observe,
            |e| {
                e.provider_status = Provider::Active;
            },
        ),
        fixture("unknown Bitcoin outspend", Action::IntegrityHold, |e| {
            e.bitcoin_source = BitcoinSource::UnknownOutspend;
        }),
        fixture("unknown Liquid outspend", Action::IntegrityHold, |e| {
            e.liquid_lock = LiquidLock::UnknownOutspend;
        }),
        fixture(
            "confirmed server lock despite provider expiry",
            Action::ClaimLiquid,
            |e| {
                e.liquid_lock = LiquidLock::ConfirmedUnspent;
            },
        ),
        fixture(
            "mempool server lock remains claimable",
            Action::ClaimLiquid,
            |e| {
                e.liquid_lock = LiquidLock::MempoolUnspent;
            },
        ),
        fixture(
            "prepared claim reuses the Liquid path",
            Action::ClaimLiquid,
            |e| {
                e.liquid_lock = LiquidLock::ConfirmedUnspent;
                e.liquid_claim_transaction = Transaction::Prepared;
            },
        ),
        fixture(
            "temporarily absent viable Liquid path",
            Action::Observe,
            |e| {
                e.liquid_path = LiquidPath::Viable;
            },
        ),
        fixture("unknown Liquid path", Action::Observe, |e| {
            e.liquid_path = LiquidPath::Unknown;
        }),
        fixture(
            "unknown Liquid chain field blocks finalization",
            Action::Observe,
            |e| {
                e.liquid_lock = LiquidLock::Unknown;
                e.bitcoin_source = BitcoinSource::SpentByRecoveryTransaction;
                e.bitcoin_recovery_transaction = Transaction::Finalized;
            },
        ),
        fixture(
            "incomplete finality evidence cannot finalize",
            Action::Observe,
            |e| {
                e.quality = Quality::Incomplete;
                e.liquid_lock = LiquidLock::SpentByMerchantClaim;
                e.liquid_claim_transaction = Transaction::Finalized;
            },
        ),
        fixture(
            "safe renegotiation is preferred",
            Action::Renegotiate,
            |e| {
                e.renegotiation = Renegotiation::Available;
            },
        ),
        fixture(
            "journaled renegotiation is re-observed",
            Action::Observe,
            |e| {
                e.renegotiation = Renegotiation::Requested;
            },
        ),
        fixture("accepted quote waits for its lock", Action::Observe, |e| {
            e.renegotiation = Renegotiation::AcceptedAwaitingLock;
        }),
        fixture(
            "renegotiation ambiguity never falls through",
            Action::Observe,
            |e| {
                e.renegotiation = Renegotiation::Ambiguous;
            },
        ),
        fixture(
            "positive non-applicability permits fallback",
            Action::RecoverBitcoin,
            |e| {
                e.renegotiation = Renegotiation::NotRequired;
            },
        ),
        fixture("unknown cooperative recovery", Action::Observe, |e| {
            e.cooperative_recovery = Cooperative::Unknown;
        }),
        fixture(
            "known refusal waits before timeout",
            Action::WaitForBitcoinTimeout,
            |e| {
                e.cooperative_recovery = Cooperative::Unavailable;
                e.bitcoin_timeout = Timeout::BeforeTimeout;
            },
        ),
        fixture(
            "known refusal recovers at timeout",
            Action::RecoverBitcoin,
            |e| {
                e.cooperative_recovery = Cooperative::Unavailable;
                e.bitcoin_timeout = Timeout::Reached;
            },
        ),
        fixture(
            "unknown timeout cannot authorize recovery",
            Action::Observe,
            |e| {
                e.cooperative_recovery = Cooperative::Unavailable;
                e.bitcoin_timeout = Timeout::Unknown;
            },
        ),
        fixture(
            "missing fallback commitment holds",
            Action::IntegrityHold,
            |e| {
                e.recovery_destination = Destination::Missing;
            },
        ),
        fixture(
            "disputed fallback commitment holds",
            Action::IntegrityHold,
            |e| {
                e.recovery_destination = Destination::Disputed;
            },
        ),
        fixture(
            "Liquid broadcast is watched",
            Action::WatchTransaction,
            |e| {
                e.liquid_claim_transaction = Transaction::Broadcast;
            },
        ),
        fixture(
            "Liquid confirmation awaits finality",
            Action::WatchTransaction,
            |e| {
                e.liquid_lock = LiquidLock::SpentByMerchantClaim;
                e.liquid_claim_transaction = Transaction::Confirmed;
            },
        ),
        fixture("Liquid finality can finalize", Action::Finalize, |e| {
            e.liquid_lock = LiquidLock::SpentByMerchantClaim;
            e.liquid_claim_transaction = Transaction::Finalized;
        }),
        fixture(
            "Bitcoin recovery broadcast is watched",
            Action::WatchTransaction,
            |e| {
                e.bitcoin_recovery_transaction = Transaction::Broadcast;
            },
        ),
        fixture(
            "Bitcoin recovery confirmation awaits finality",
            Action::WatchTransaction,
            |e| {
                e.bitcoin_source = BitcoinSource::SpentByRecoveryTransaction;
                e.bitcoin_recovery_transaction = Transaction::Confirmed;
            },
        ),
        fixture(
            "Bitcoin recovery finality can finalize",
            Action::Finalize,
            |e| {
                e.bitcoin_source = BitcoinSource::SpentByRecoveryTransaction;
                e.bitcoin_recovery_transaction = Transaction::Finalized;
            },
        ),
        fixture(
            "recovery finality with an unspent source is incoherent",
            Action::IntegrityHold,
            |e| {
                e.bitcoin_source = BitcoinSource::ConfirmedUnspent;
                e.bitcoin_recovery_transaction = Transaction::Finalized;
            },
        ),
        fixture(
            "claim finality with an unspent lock is incoherent",
            Action::IntegrityHold,
            |e| {
                e.liquid_lock = LiquidLock::ConfirmedUnspent;
                e.liquid_claim_transaction = Transaction::Finalized;
            },
        ),
        fixture(
            "claim finality with an absent lock is incoherent",
            Action::IntegrityHold,
            |e| {
                e.liquid_lock = LiquidLock::NotObserved;
                e.liquid_claim_transaction = Transaction::Finalized;
            },
        ),
        fixture(
            "disputed transaction evidence observes",
            Action::Observe,
            |e| {
                e.liquid_claim_transaction = Transaction::Disputed;
            },
        ),
        fixture(
            "wrong Liquid merchant output holds",
            Action::IntegrityHold,
            |e| {
                e.liquid_claim_transaction = Transaction::MerchantOutputMismatch;
            },
        ),
        fixture(
            "wrong Bitcoin merchant output holds",
            Action::IntegrityHold,
            |e| {
                e.bitcoin_recovery_transaction = Transaction::MerchantOutputMismatch;
            },
        ),
        fixture(
            "prepared claim and recovery race holds",
            Action::IntegrityHold,
            |e| {
                e.liquid_claim_transaction = Transaction::Prepared;
                e.bitcoin_recovery_transaction = Transaction::Prepared;
            },
        ),
        fixture(
            "broadcast claim and recovery race holds",
            Action::IntegrityHold,
            |e| {
                e.liquid_claim_transaction = Transaction::Broadcast;
                e.bitcoin_recovery_transaction = Transaction::Broadcast;
            },
        ),
        fixture(
            "prepared recovery plus new server lock holds",
            Action::IntegrityHold,
            |e| {
                e.bitcoin_recovery_transaction = Transaction::Prepared;
                e.liquid_lock = LiquidLock::ConfirmedUnspent;
            },
        ),
        fixture(
            "broadcast recovery plus late server lock stays watched",
            Action::WatchTransaction,
            |e| {
                e.bitcoin_recovery_transaction = Transaction::Broadcast;
                e.liquid_lock = LiquidLock::ConfirmedUnspent;
            },
        ),
        fixture(
            "provider preimage spend with claimable lock",
            Action::ClaimLiquid,
            |e| {
                e.bitcoin_source = BitcoinSource::SpentByProviderWithPreimage;
                e.liquid_lock = LiquidLock::ConfirmedUnspent;
            },
        ),
        fixture(
            "provider preimage spend is not success",
            Action::IntegrityHold,
            |e| {
                e.bitcoin_source = BitcoinSource::SpentByProviderWithPreimage;
            },
        ),
        fixture(
            "provider spend cannot coexist with recovery",
            Action::IntegrityHold,
            |e| {
                e.bitcoin_source = BitcoinSource::SpentByProviderWithPreimage;
                e.bitcoin_recovery_transaction = Transaction::Broadcast;
            },
        ),
        fixture(
            "recovery spend cannot coexist with claim",
            Action::IntegrityHold,
            |e| {
                e.bitcoin_source = BitcoinSource::SpentByRecoveryTransaction;
                e.liquid_claim_transaction = Transaction::Broadcast;
            },
        ),
        fixture(
            "merchant Liquid spend cannot coexist with recovery",
            Action::IntegrityHold,
            |e| {
                e.liquid_lock = LiquidLock::SpentByMerchantClaim;
                e.bitcoin_recovery_transaction = Transaction::Broadcast;
            },
        ),
        fixture(
            "unlinked classified recovery spend holds",
            Action::IntegrityHold,
            |e| {
                e.bitcoin_source = BitcoinSource::SpentByRecoveryTransaction;
            },
        ),
        fixture(
            "unlinked classified merchant claim holds",
            Action::IntegrityHold,
            |e| {
                e.liquid_lock = LiquidLock::SpentByMerchantClaim;
            },
        ),
        fixture(
            "known recovery spend is watched",
            Action::WatchTransaction,
            |e| {
                e.bitcoin_source = BitcoinSource::SpentByRecoveryTransaction;
                e.bitcoin_recovery_transaction = Transaction::Mempool;
            },
        ),
        fixture(
            "known merchant Liquid spend is watched",
            Action::WatchTransaction,
            |e| {
                e.liquid_lock = LiquidLock::SpentByMerchantClaim;
                e.liquid_claim_transaction = Transaction::Mempool;
            },
        ),
        fixture(
            "expired plus proven unfunded can finalize",
            Action::Finalize,
            |e| {
                e.bitcoin_source = BitcoinSource::Unfunded;
                e.provider_status = Provider::Expired;
            },
        ),
        fixture(
            "provider expiry cannot terminalize mempool funding",
            Action::Observe,
            |e| {
                e.bitcoin_source = BitcoinSource::MempoolUnspent;
                e.provider_status = Provider::Expired;
            },
        ),
        fixture(
            "provider expiry cannot terminalize unknown funding",
            Action::Observe,
            |e| {
                e.bitcoin_source = BitcoinSource::Unknown;
                e.provider_status = Provider::Expired;
            },
        ),
        fixture(
            "unfunded active provider remains observed",
            Action::Observe,
            |e| {
                e.bitcoin_source = BitcoinSource::Unfunded;
                e.provider_status = Provider::Active;
            },
        ),
        fixture(
            "provider-refunded Liquid lock still renegotiates first",
            Action::Renegotiate,
            |e| {
                e.liquid_lock = LiquidLock::SpentByProviderRefund;
                e.renegotiation = Renegotiation::Available;
            },
        ),
    ]);
}

#[test]
fn every_incomplete_or_disagreeing_snapshot_observes_or_holds() {
    use BitcoinSourceEvidence as BitcoinSource;
    use ChainSwapAction as Action;
    use EvidenceQuality as Quality;
    use LiquidLockEvidence as LiquidLock;

    let qualities = [
        Quality::Incomplete,
        Quality::BackendDisagreement,
        Quality::ProviderDisagreement,
    ];
    let sources = [
        BitcoinSource::Unknown,
        BitcoinSource::Unfunded,
        BitcoinSource::MempoolUnspent,
        BitcoinSource::ConfirmedUnspent,
        BitcoinSource::SpentByProviderWithPreimage,
        BitcoinSource::SpentByRecoveryTransaction,
        BitcoinSource::UnknownOutspend,
    ];
    let locks = [
        LiquidLock::Unknown,
        LiquidLock::NotObserved,
        LiquidLock::MempoolUnspent,
        LiquidLock::ConfirmedUnspent,
        LiquidLock::SpentByMerchantClaim,
        LiquidLock::SpentByProviderRefund,
        LiquidLock::UnknownOutspend,
    ];

    for quality in qualities {
        for bitcoin_source in sources {
            for liquid_lock in locks {
                let mut evidence = recovery_candidate();
                evidence.quality = quality;
                evidence.bitcoin_source = bitcoin_source;
                evidence.liquid_lock = liquid_lock;
                let action = reduce_chain_swap_evidence(&evidence);
                assert!(
                    matches!(action, Action::Observe | Action::IntegrityHold),
                    "quality={quality:?}, source={bitcoin_source:?}, lock={liquid_lock:?}, action={action:?}"
                );
                if bitcoin_source == BitcoinSource::UnknownOutspend
                    || liquid_lock == LiquidLock::UnknownOutspend
                {
                    assert_eq!(action, Action::IntegrityHold);
                }
            }
        }
    }
}

#[test]
fn transaction_lifecycle_matrix_is_exhaustive_for_both_paths() {
    use ChainSwapAction as Action;
    use LiquidLockEvidence as LiquidLock;
    use MerchantTransactionEvidence as Transaction;

    let lifecycle = [
        Transaction::None,
        Transaction::Prepared,
        Transaction::Broadcast,
        Transaction::Mempool,
        Transaction::Confirmed,
        Transaction::Finalized,
        Transaction::Disputed,
        Transaction::MerchantOutputMismatch,
    ];
    let expected_single_path = [
        Action::RecoverBitcoin,
        Action::RecoverBitcoin,
        Action::WatchTransaction,
        Action::WatchTransaction,
        Action::WatchTransaction,
        Action::Finalize,
        Action::Observe,
        Action::IntegrityHold,
    ];

    for (state, expected) in lifecycle.into_iter().zip(expected_single_path) {
        let mut evidence = recovery_candidate();
        if matches!(
            state,
            Transaction::Mempool | Transaction::Confirmed | Transaction::Finalized
        ) {
            evidence.bitcoin_source = BitcoinSourceEvidence::SpentByRecoveryTransaction;
        }
        evidence.bitcoin_recovery_transaction = state;
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            expected,
            "Bitcoin transaction state {state:?}"
        );
    }

    let expected_liquid_path = [
        Action::ClaimLiquid,
        Action::ClaimLiquid,
        Action::WatchTransaction,
        Action::WatchTransaction,
        Action::WatchTransaction,
        Action::Finalize,
        Action::Observe,
        Action::IntegrityHold,
    ];
    for (state, expected) in lifecycle.into_iter().zip(expected_liquid_path) {
        let mut evidence = recovery_candidate();
        evidence.liquid_lock = if matches!(
            state,
            Transaction::Mempool | Transaction::Confirmed | Transaction::Finalized
        ) {
            LiquidLock::SpentByMerchantClaim
        } else {
            LiquidLock::ConfirmedUnspent
        };
        evidence.liquid_claim_transaction = state;
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            expected,
            "Liquid transaction state {state:?}"
        );
    }

    for liquid_state in lifecycle
        .into_iter()
        .filter(|state| *state != Transaction::None)
    {
        for recovery_state in lifecycle
            .into_iter()
            .filter(|state| *state != Transaction::None)
        {
            let mut evidence = recovery_candidate();
            evidence.liquid_claim_transaction = liquid_state;
            evidence.bitcoin_recovery_transaction = recovery_state;
            assert_eq!(
                reduce_chain_swap_evidence(&evidence),
                Action::IntegrityHold,
                "claim/recovery race: liquid={liquid_state:?}, recovery={recovery_state:?}"
            );
        }
    }
}

#[test]
fn renegotiation_and_recovery_boundaries_are_exhaustive() {
    use BitcoinTimeoutEvidence as Timeout;
    use ChainSwapAction as Action;
    use CooperativeRecoveryEvidence as Cooperative;
    use RenegotiationEvidence as Renegotiation;

    let renegotiation_cases = [
        (Renegotiation::NotRequired, Action::RecoverBitcoin),
        (Renegotiation::Available, Action::Renegotiate),
        (Renegotiation::Requested, Action::Observe),
        (Renegotiation::AcceptedAwaitingLock, Action::Observe),
        (Renegotiation::ExplicitlyUnavailable, Action::RecoverBitcoin),
        (Renegotiation::Ambiguous, Action::Observe),
    ];
    for (renegotiation, expected) in renegotiation_cases {
        let mut evidence = recovery_candidate();
        evidence.renegotiation = renegotiation;
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            expected,
            "renegotiation={renegotiation:?}"
        );
    }

    let cooperative_cases = [
        (Cooperative::Unknown, Timeout::Unknown, Action::Observe),
        (
            Cooperative::Unknown,
            Timeout::BeforeTimeout,
            Action::Observe,
        ),
        (Cooperative::Unknown, Timeout::Reached, Action::Observe),
        (
            Cooperative::Available,
            Timeout::Unknown,
            Action::RecoverBitcoin,
        ),
        (
            Cooperative::Available,
            Timeout::BeforeTimeout,
            Action::RecoverBitcoin,
        ),
        (
            Cooperative::Available,
            Timeout::Reached,
            Action::RecoverBitcoin,
        ),
        (Cooperative::Unavailable, Timeout::Unknown, Action::Observe),
        (
            Cooperative::Unavailable,
            Timeout::BeforeTimeout,
            Action::WaitForBitcoinTimeout,
        ),
        (
            Cooperative::Unavailable,
            Timeout::Reached,
            Action::RecoverBitcoin,
        ),
    ];
    for (cooperative_recovery, bitcoin_timeout, expected) in cooperative_cases {
        let mut evidence = recovery_candidate();
        evidence.cooperative_recovery = cooperative_recovery;
        evidence.bitcoin_timeout = bitcoin_timeout;
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            expected,
            "cooperative={cooperative_recovery:?}, timeout={bitcoin_timeout:?}"
        );
    }
}

#[test]
fn provider_expiry_only_finalizes_independently_proven_unfunded_swaps() {
    use BitcoinSourceEvidence as BitcoinSource;
    use ChainSwapAction as Action;
    use ProviderStatusEvidence as Provider;

    let provider_cases = [
        (Provider::Unknown, Action::Observe),
        (Provider::Active, Action::Observe),
        (Provider::Expired, Action::Finalize),
        (Provider::SettlementHint, Action::Observe),
    ];
    for (provider_status, expected) in provider_cases {
        let mut evidence = recovery_candidate();
        evidence.bitcoin_source = BitcoinSource::Unfunded;
        evidence.provider_status = provider_status;
        assert_eq!(
            reduce_chain_swap_evidence(&evidence),
            expected,
            "provider={provider_status:?}"
        );
    }

    for source in [
        BitcoinSource::Unknown,
        BitcoinSource::MempoolUnspent,
        BitcoinSource::ConfirmedUnspent,
    ] {
        let mut evidence = recovery_candidate();
        evidence.bitcoin_source = source;
        evidence.provider_status = Provider::Expired;
        assert_ne!(
            reduce_chain_swap_evidence(&evidence),
            Action::Finalize,
            "provider expiry terminalized source evidence {source:?}"
        );
    }
}

#[test]
fn under_lock_recheck_authorizes_only_a_still_current_recovery_decision() {
    use BitcoinTimeoutEvidence as Timeout;
    use ChainSwapAction as Action;
    use CooperativeRecoveryEvidence as Cooperative;
    use EvidenceQuality as Quality;
    use LiquidLockEvidence as LiquidLock;
    use MerchantTransactionEvidence as Transaction;
    use RecoveryDestinationEvidence as Destination;
    use RenegotiationEvidence as Renegotiation;

    let unchanged = recovery_candidate();
    assert_eq!(
        recheck_recovery_under_lock(&unchanged),
        RecoveryExecutionGate::Authorized
    );

    let prepared = fixture("prepared exact recovery", Action::RecoverBitcoin, |e| {
        e.bitcoin_recovery_transaction = Transaction::Prepared;
    });
    assert_eq!(
        recheck_recovery_under_lock(&prepared.evidence),
        RecoveryExecutionGate::Authorized
    );

    let blocked = [
        fixture("new Liquid lock", Action::ClaimLiquid, |e| {
            e.liquid_lock = LiquidLock::ConfirmedUnspent;
        }),
        fixture("renegotiation became safe", Action::Renegotiate, |e| {
            e.renegotiation = Renegotiation::Available;
        }),
        fixture("backend disagreement", Action::Observe, |e| {
            e.quality = Quality::BackendDisagreement;
        }),
        fixture("provider became active", Action::Observe, |e| {
            e.provider_status = ProviderStatusEvidence::Active;
        }),
        fixture("unknown outspend", Action::IntegrityHold, |e| {
            e.bitcoin_source = BitcoinSourceEvidence::UnknownOutspend;
        }),
        fixture(
            "fallback commitment disappeared",
            Action::IntegrityHold,
            |e| {
                e.recovery_destination = Destination::Missing;
            },
        ),
        fixture(
            "known refusal before timeout",
            Action::WaitForBitcoinTimeout,
            |e| {
                e.cooperative_recovery = Cooperative::Unavailable;
                e.bitcoin_timeout = Timeout::BeforeTimeout;
            },
        ),
        fixture(
            "settlement finalized while waiting",
            Action::Finalize,
            |e| {
                e.liquid_lock = LiquidLock::SpentByMerchantClaim;
                e.liquid_claim_transaction = Transaction::Finalized;
            },
        ),
        fixture(
            "prepared recovery races with new Liquid lock",
            Action::IntegrityHold,
            |e| {
                e.bitcoin_recovery_transaction = Transaction::Prepared;
                e.liquid_lock = LiquidLock::ConfirmedUnspent;
            },
        ),
    ];

    for fixture in blocked {
        assert_eq!(
            recheck_recovery_under_lock(&fixture.evidence),
            RecoveryExecutionGate::Blocked(fixture.expected),
            "under-lock fixture: {}",
            fixture.name
        );
    }
}

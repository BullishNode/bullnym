use super::*;
use uuid::Uuid;

fn fixture(our_status: &str) -> ReconcilerSwap {
    ReconcilerSwap {
        id: Uuid::nil(),
        boltz_swap_id: "test-swap".to_string(),
        status: our_status.to_string(),
        cooperative_refused: false,
        claim_txid: None,
        nym: Some("alice".to_string()),
        amount_sat: 100_000,
        invoice_id: None,
    }
}

fn settlement_record(
    chain: crate::merchant_settlement_lifecycle::SettlementChain,
    status: &str,
) -> db::ChainSwapRecord {
    use crate::merchant_settlement_lifecycle::SettlementChain;

    db::ChainSwapRecord {
        id: Uuid::from_u128(10),
        invoice_id: Uuid::from_u128(20),
        nym: Some("alice".to_owned()),
        boltz_swap_id: "runtime-settlement".to_owned(),
        from_chain: "BTC".to_owned(),
        to_chain: "L-BTC".to_owned(),
        lockup_address: "bitcoin-lockup".to_owned(),
        lockup_bip21: None,
        user_lock_amount_sat: 75_000,
        server_lock_amount_sat: 73_219,
        preimage_hex: "11".repeat(32),
        claim_key_hex: "22".repeat(32),
        refund_key_hex: "33".repeat(32),
        boltz_response_json: "{}".to_owned(),
        status: status.to_owned(),
        claim_txid: matches!(chain, SettlementChain::Liquid)
            .then(|| settlement_txid('1').as_str().to_owned()),
        claim_tx_hex: None,
        claim_fee_authority: db::LiquidClaimFeeAuthority::Legacy,
        claim_attempts: 0,
        last_claim_error: None,
        cooperative_refused: false,
        creation_terms: None,
        renegotiated_server_lock_amount_sat: None,
        refund_address: Some("bitcoin-recovery".to_owned()),
        refund_txid: (matches!(chain, SettlementChain::Bitcoin) && status == "refunded")
            .then(|| settlement_txid('1').as_str().to_owned()),
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn settlement_txid(character: char) -> crate::merchant_settlement_lifecycle::SettlementTxid {
    crate::merchant_settlement_lifecycle::SettlementTxid::parse(&character.to_string().repeat(64))
        .unwrap()
}

fn settlement_block(
    height: u32,
    character: char,
) -> crate::merchant_settlement_lifecycle::SettlementBlock {
    crate::merchant_settlement_lifecycle::SettlementBlock::new(
        height,
        &character.to_string().repeat(64),
    )
    .unwrap()
}

fn settlement_context(
    chain: crate::merchant_settlement_lifecycle::SettlementChain,
) -> ChainSwapEvidence {
    use crate::chain_swap_action::{
        BitcoinSourceEvidence as BitcoinSource, BitcoinTimeoutEvidence as BitcoinTimeout,
        CooperativeRecoveryEvidence as CooperativeRecovery, EvidenceQuality,
        LiquidLockEvidence as LiquidLock, LiquidPathEvidence as LiquidPath,
        MerchantTransactionEvidence, ProviderStatusEvidence as ProviderStatus,
        RecoveryDestinationEvidence as RecoveryDestination, RenegotiationEvidence as Renegotiation,
    };
    use crate::merchant_settlement_lifecycle::SettlementChain;

    ChainSwapEvidence {
        quality: EvidenceQuality::CompleteAndAgreed,
        provider_status: ProviderStatus::Expired,
        bitcoin_source: match chain {
            SettlementChain::Liquid => BitcoinSource::ConfirmedUnspent,
            SettlementChain::Bitcoin => BitcoinSource::SpentByRecoveryTransaction,
        },
        liquid_lock: match chain {
            SettlementChain::Liquid => LiquidLock::SpentByMerchantClaim,
            SettlementChain::Bitcoin => LiquidLock::NotObserved,
        },
        liquid_path: LiquidPath::Unavailable,
        renegotiation: Renegotiation::ExplicitlyUnavailable,
        recovery_destination: RecoveryDestination::Committed,
        cooperative_recovery: CooperativeRecovery::Available,
        bitcoin_timeout: BitcoinTimeout::BeforeTimeout,
        liquid_claim_transaction: MerchantTransactionEvidence::None,
        bitcoin_recovery_transaction: MerchantTransactionEvidence::None,
    }
}

fn apply_settlement(
    lifecycle: &crate::merchant_settlement_lifecycle::MerchantSettlementLifecycle,
    evidence: crate::merchant_settlement_lifecycle::SettlementEvidence,
    policy: crate::merchant_settlement_lifecycle::SettlementFinalityPolicy,
) -> crate::merchant_settlement_lifecycle::MerchantSettlementLifecycle {
    crate::merchant_settlement_lifecycle::apply_settlement_evidence(lifecycle, &evidence, policy)
        .unwrap()
        .lifecycle
}

#[test]
fn runtime_settlement_keeps_one_confirmation_accounting_separate_from_finality() {
    use crate::merchant_settlement_lifecycle::{
        MerchantSettlementLifecycle, SettlementChain, SettlementEvidence, SettlementFinalityPolicy,
    };

    for (chain, final_confirmations) in
        [(SettlementChain::Liquid, 2), (SettlementChain::Bitcoin, 3)]
    {
        let policy = SettlementFinalityPolicy::default();
        let initial = MerchantSettlementLifecycle::new(chain, settlement_txid('1'));
        let confirmed = apply_settlement(
            &initial,
            SettlementEvidence::Confirmed {
                txid: settlement_txid('1'),
                block: settlement_block(100, 'a'),
                confirmations: 1,
            },
            policy,
        );
        let input = RestoredSettlementRuntimeInput {
            chain_evidence: settlement_context(chain),
            verified_actual_amount_sat: Some(73_219),
        };
        assert_eq!(
            decide_restored_chain_swap_settlement(
                &settlement_record(
                    chain,
                    match chain {
                        SettlementChain::Liquid => "claiming",
                        SettlementChain::Bitcoin => "refunding",
                    },
                ),
                &confirmed,
                input,
            ),
            ChainSwapSettlementRuntimeDecision {
                action: ChainSwapSettlementRuntimeAction::WatchTransaction,
                accounting_eligible_actual_amount_sat: Some(73_219),
            },
            "one-confirmation {chain:?}"
        );

        let finalized = apply_settlement(
            &confirmed,
            SettlementEvidence::Finalized {
                txid: settlement_txid('1'),
                block: settlement_block(100, 'a'),
                confirmations: final_confirmations,
            },
            policy,
        );
        assert_eq!(
            decide_restored_chain_swap_settlement(
                &settlement_record(
                    chain,
                    match chain {
                        SettlementChain::Liquid => "claiming",
                        SettlementChain::Bitcoin => "refunding",
                    },
                ),
                &finalized,
                input,
            ),
            ChainSwapSettlementRuntimeDecision {
                action: ChainSwapSettlementRuntimeAction::Finalize,
                accounting_eligible_actual_amount_sat: Some(73_219),
            },
            "finalized {chain:?}"
        );
    }
}

#[test]
fn runtime_settlement_demotion_blocks_finality_accounting_and_recovery_execution() {
    use crate::chain_swap_action::ChainSwapAction;
    use crate::merchant_settlement_lifecycle::{
        MerchantSettlementLifecycle, SettlementChain, SettlementEvidence, SettlementFinalityPolicy,
    };

    let policy = SettlementFinalityPolicy::default();
    let initial = MerchantSettlementLifecycle::new(SettlementChain::Liquid, settlement_txid('1'));
    let confirmed = apply_settlement(
        &initial,
        SettlementEvidence::Confirmed {
            txid: settlement_txid('1'),
            block: settlement_block(100, 'a'),
            confirmations: 1,
        },
        policy,
    );
    let reorged = apply_settlement(
        &confirmed,
        SettlementEvidence::Reorged {
            txid: settlement_txid('1'),
            previous_block: settlement_block(100, 'a'),
        },
        policy,
    );
    let decision = decide_restored_chain_swap_settlement(
        &settlement_record(SettlementChain::Liquid, "claiming"),
        &reorged,
        RestoredSettlementRuntimeInput {
            chain_evidence: settlement_context(SettlementChain::Liquid),
            verified_actual_amount_sat: Some(73_219),
        },
    );
    assert_eq!(
        decision,
        ChainSwapSettlementRuntimeDecision {
            action: ChainSwapSettlementRuntimeAction::Blocked(ChainSwapAction::Observe),
            accounting_eligible_actual_amount_sat: None,
        }
    );
}

#[test]
fn runtime_settlement_restart_restore_produces_the_identical_decision() {
    use crate::merchant_settlement_lifecycle::{
        MerchantSettlementLifecycle, SettlementChain, SettlementEvidence, SettlementFinalityPolicy,
    };

    let policy = SettlementFinalityPolicy::default();
    let initial = MerchantSettlementLifecycle::new(SettlementChain::Bitcoin, settlement_txid('1'));
    let confirmed = apply_settlement(
        &initial,
        SettlementEvidence::Confirmed {
            txid: settlement_txid('1'),
            block: settlement_block(840_000, 'a'),
            confirmations: 1,
        },
        policy,
    );
    let input = RestoredSettlementRuntimeInput {
        chain_evidence: settlement_context(SettlementChain::Bitcoin),
        verified_actual_amount_sat: Some(51_000),
    };
    let record = settlement_record(SettlementChain::Bitcoin, "refunding");
    let before_restart = decide_restored_chain_swap_settlement(&record, &confirmed, input);
    let restored = MerchantSettlementLifecycle::restore(confirmed.snapshot(), policy).unwrap();
    assert_eq!(
        decide_restored_chain_swap_settlement(&record, &restored, input),
        before_restart
    );
}

#[test]
fn runtime_settlement_recovery_requires_the_refunding_record_branch() {
    use crate::chain_swap_action::{
        BitcoinSourceEvidence, ChainSwapAction, MerchantTransactionEvidence,
    };
    use crate::merchant_settlement_lifecycle::{MerchantSettlementLifecycle, SettlementChain};

    let lifecycle =
        MerchantSettlementLifecycle::new(SettlementChain::Bitcoin, settlement_txid('1'));
    let mut input = RestoredSettlementRuntimeInput {
        chain_evidence: settlement_context(SettlementChain::Bitcoin),
        verified_actual_amount_sat: None,
    };
    input.chain_evidence.bitcoin_source = BitcoinSourceEvidence::ConfirmedUnspent;
    input.chain_evidence.bitcoin_recovery_transaction = MerchantTransactionEvidence::None;

    assert_eq!(
        decide_restored_chain_swap_settlement(
            &settlement_record(SettlementChain::Bitcoin, "refunding"),
            &lifecycle,
            input,
        ),
        ChainSwapSettlementRuntimeDecision {
            action: ChainSwapSettlementRuntimeAction::RecoverBitcoin,
            accounting_eligible_actual_amount_sat: None,
        }
    );
    assert_eq!(
        decide_restored_chain_swap_settlement(
            &settlement_record(SettlementChain::Bitcoin, "refunded"),
            &lifecycle,
            input,
        ),
        ChainSwapSettlementRuntimeDecision {
            action: ChainSwapSettlementRuntimeAction::Blocked(ChainSwapAction::IntegrityHold),
            accounting_eligible_actual_amount_sat: None,
        }
    );

    let mut wrong_direction = settlement_record(SettlementChain::Bitcoin, "refunding");
    wrong_direction.from_chain = "L-BTC".to_owned();
    wrong_direction.to_chain = "BTC".to_owned();
    assert_eq!(
        decide_restored_chain_swap_settlement(&wrong_direction, &lifecycle, input),
        ChainSwapSettlementRuntimeDecision {
            action: ChainSwapSettlementRuntimeAction::Blocked(ChainSwapAction::IntegrityHold),
            accounting_eligible_actual_amount_sat: None,
        }
    );
}

#[test]
fn runtime_rebroadcast_composition_preserves_unconfirmed_eviction_and_demotion() {
    use AppliedMerchantSettlementAction::{Demoted, Finalized, Watching};

    assert_eq!(
        compose_merchant_settlement_rebroadcast(Watching, false, false),
        Some(false)
    );
    assert_eq!(
        compose_merchant_settlement_rebroadcast(Watching, true, true),
        Some(true),
        "unconfirmed eviction remains Watching but must persist exact-byte replay"
    );
    assert_eq!(
        compose_merchant_settlement_rebroadcast(Demoted, false, true),
        Some(true),
        "accounting demotion always requires journal replay"
    );
    assert_eq!(
        compose_merchant_settlement_rebroadcast(Finalized, false, false),
        Some(false)
    );

    assert_eq!(
        compose_merchant_settlement_rebroadcast(Watching, true, false),
        None,
        "repository cannot discard the service replay request"
    );
    assert_eq!(
        compose_merchant_settlement_rebroadcast(Watching, false, true),
        None,
        "repository cannot invent a Watching replay transition"
    );
    assert_eq!(
        compose_merchant_settlement_rebroadcast(Demoted, false, false),
        None,
        "repository cannot demote without publishing replay"
    );
    assert_eq!(
        compose_merchant_settlement_rebroadcast(Finalized, true, true),
        None,
        "finalized accounting cannot request another broadcast"
    );
}

#[test]
fn runtime_worker_selects_journal_owned_active_and_finalized_paths() {
    use crate::{
        merchant_settlement_adoption::MerchantSettlementPath,
        merchant_settlement_lifecycle::SettlementChain,
    };

    let liquid = settlement_record(SettlementChain::Liquid, "claiming");
    let liquid_context = merchant_settlement_context_for_record(&liquid)
        .unwrap()
        .unwrap();
    assert_eq!(liquid_context.invoice_id(), liquid.invoice_id);
    assert_eq!(liquid_context.chain_swap_id(), liquid.id);
    assert_eq!(liquid_context.path(), MerchantSettlementPath::LiquidClaim);

    let bitcoin = settlement_record(SettlementChain::Bitcoin, "refunding");
    let bitcoin_context = merchant_settlement_context_for_record(&bitcoin)
        .unwrap()
        .unwrap();
    assert_eq!(bitcoin_context.invoice_id(), bitcoin.invoice_id);
    assert_eq!(bitcoin_context.chain_swap_id(), bitcoin.id);
    assert_eq!(
        bitcoin_context.path(),
        MerchantSettlementPath::BitcoinRecovery
    );

    let claimed = settlement_record(SettlementChain::Liquid, "claimed");
    assert_eq!(
        merchant_settlement_context_for_record(&claimed)
            .unwrap()
            .unwrap()
            .path(),
        MerchantSettlementPath::LiquidClaim
    );
    let refunded = settlement_record(SettlementChain::Bitcoin, "refunded");
    assert_eq!(
        merchant_settlement_context_for_record(&refunded)
            .unwrap()
            .unwrap()
            .path(),
        MerchantSettlementPath::BitcoinRecovery
    );

    for status in ["claim_failed", "claim_stuck"] {
        let record = settlement_record(SettlementChain::Liquid, status);
        assert_eq!(
            merchant_settlement_context_for_record(&record)
                .unwrap()
                .unwrap()
                .path(),
            MerchantSettlementPath::LiquidClaim,
            "{status}"
        );
    }

    for status in ["pending", "server_lock_confirmed"] {
        let record = settlement_record(SettlementChain::Liquid, status);
        assert!(
            merchant_settlement_context_for_record(&record)
                .unwrap()
                .is_none(),
            "{status}"
        );
    }
}

#[test]
fn boltz_swap_created_no_op() {
    let swap = fixture("pending");
    assert_eq!(decide_action(&swap, "swap.created"), ReconcilerAction::Noop);
}

#[test]
fn boltz_mempool_pending_advances() {
    let swap = fixture("pending");
    assert_eq!(
        decide_action(&swap, "transaction.mempool"),
        ReconcilerAction::AdvanceToLockupMempool
    );
}

#[test]
fn boltz_confirmed_pending_advances() {
    let swap = fixture("pending");
    assert_eq!(
        decide_action(&swap, "transaction.confirmed"),
        ReconcilerAction::AdvanceToLockupConfirmed
    );
}

#[test]
fn boltz_confirmed_mempool_advances() {
    let swap = fixture("lockup_mempool");
    assert_eq!(
        decide_action(&swap, "transaction.confirmed"),
        ReconcilerAction::AdvanceToLockupConfirmed
    );
}

#[test]
fn boltz_mempool_claimable_status_schedules_retry() {
    for our in &["claiming", "claim_failed", "lockup_confirmed"] {
        let swap = fixture(our);
        assert_eq!(
            decide_action(&swap, "transaction.mempool"),
            ReconcilerAction::ScheduleImmediateClaim,
            "unexpected for our_status={our}"
        );
    }
}

#[test]
fn boltz_swap_expired_schedules_script_retry() {
    for our in &[
        "lockup_mempool",
        "lockup_confirmed",
        "claiming",
        "claim_failed",
    ] {
        let swap = fixture(our);
        assert_eq!(
            decide_action(&swap, "swap.expired"),
            ReconcilerAction::ScheduleScriptPathRetry,
            "unexpected for our_status={our}"
        );
    }
}

#[test]
fn boltz_invoice_expired_marks_expired() {
    let swap = fixture("pending");
    assert_eq!(
        decide_action(&swap, "invoice.expired"),
        ReconcilerAction::MarkExpired
    );
}

#[test]
fn boltz_transaction_failed_marks_expired() {
    let swap = fixture("pending");
    assert_eq!(
        decide_action(&swap, "transaction.failed"),
        ReconcilerAction::MarkExpired
    );
}

#[test]
fn boltz_transaction_refunded_marks_lockup_refunded() {
    for our in &["lockup_mempool", "lockup_confirmed", "claiming"] {
        let swap = fixture(our);
        assert_eq!(
            decide_action(&swap, "transaction.refunded"),
            ReconcilerAction::MarkLockupRefunded,
            "unexpected for our_status={our}"
        );
    }
}

#[test]
fn boltz_invoice_settled_when_we_claimed_is_noop() {
    let swap = fixture("claimed");
    assert_eq!(
        decide_action(&swap, "invoice.settled"),
        ReconcilerAction::Noop
    );
}

#[test]
fn boltz_invoice_settled_when_we_did_not_claim_schedules_retry() {
    for our in &["claiming", "claim_failed", "lockup_confirmed", "pending"] {
        let swap = fixture(our);
        assert_eq!(
            decide_action(&swap, "invoice.settled"),
            ReconcilerAction::ScheduleImmediateClaim,
            "status {our} should schedule claimer recovery"
        );
    }
}

#[test]
fn terminal_status_always_noop() {
    for our in &["claimed", "expired", "claim_stuck", "lockup_refunded"] {
        for boltz in &[
            "swap.created",
            "transaction.mempool",
            "transaction.confirmed",
            "swap.expired",
            "invoice.settled",
            "invoice.expired",
            "transaction.failed",
            "transaction.refunded",
        ] {
            let swap = fixture(our);
            assert_eq!(
                decide_action(&swap, boltz),
                ReconcilerAction::Noop,
                "expected Noop for our={our} boltz={boltz}"
            );
        }
    }
}

#[test]
fn unknown_boltz_status_is_noop() {
    let swap = fixture("pending");
    assert_eq!(
        decide_action(&swap, "minerfee.paid"),
        ReconcilerAction::Noop
    );
    assert_eq!(
        decide_action(&swap, "boltz.future.event"),
        ReconcilerAction::Noop
    );
}

#[test]
fn slow_recovery_backoff_grows_and_caps() {
    let base = 3600;
    let cap = 86_400;
    // Doubles per slow_attempt.
    assert_eq!(super::slow_recovery_backoff_secs(0, base, cap), 3600);
    assert_eq!(super::slow_recovery_backoff_secs(1, base, cap), 7200);
    assert_eq!(super::slow_recovery_backoff_secs(2, base, cap), 14_400);
    // Caps (2^5 * 3600 = 115200 > 86400).
    assert_eq!(super::slow_recovery_backoff_secs(5, base, cap), cap);
    assert_eq!(super::slow_recovery_backoff_secs(50, base, cap), cap);
    // Never panics on large / negative-ish inputs (clamped).
    assert_eq!(super::slow_recovery_backoff_secs(-1, base, cap), 3600);
}

#[test]
fn slow_recovery_uses_one_fair_budget_across_both_rails() {
    use SlowRecoveryRail::{Chain, Reverse};

    assert_eq!(
        slow_recovery_rail_schedule(10, 10, 5),
        vec![Reverse, Chain, Reverse, Chain, Reverse]
    );
    assert_eq!(
        slow_recovery_rail_schedule(1, 10, 4),
        vec![Reverse, Chain, Chain, Chain]
    );
    assert_eq!(
        slow_recovery_rail_schedule(0, 10, 3),
        vec![Chain, Chain, Chain]
    );
    assert!(slow_recovery_rail_schedule(10, 10, 0).is_empty());
}

#[test]
fn combined_slow_recovery_sentinel_reports_remaining_work() {
    let limit = 5;

    assert_eq!(scan_outcome(limit, 3 + 2, true), ScanOutcome::Succeeded);
    assert_eq!(scan_outcome(limit, 3 + 3, true), ScanOutcome::Progress);
}

#[test]
fn capped_scan_outcome_uses_limit_plus_one_as_the_progress_sentinel() {
    let limit = 10;

    assert_eq!(sentinel_limit(limit), limit + 1);
    assert_eq!(
        scan_outcome(limit, (limit - 1) as usize, true),
        ScanOutcome::Succeeded
    );
    assert_eq!(
        scan_outcome(limit, limit as usize, true),
        ScanOutcome::Succeeded
    );
    assert_eq!(
        scan_outcome(limit, (limit + 1) as usize, true),
        ScanOutcome::Progress
    );
}

#[test]
fn capped_scan_failure_dominates_page_size_and_zero_cap_fails() {
    assert_eq!(scan_outcome(10, 0, false), ScanOutcome::Failed);
    assert_eq!(scan_outcome(10, 11, false), ScanOutcome::Failed);
    assert_eq!(scan_outcome(0, 0, true), ScanOutcome::Failed);
}

#[test]
fn process_local_epoch_retains_cursors_only_while_pages_remain() {
    let first = Uuid::from_u128(1);
    let second = Uuid::from_u128(2);
    let mut scan = EpochScan::<2>::default();
    scan.begin(42);
    scan.cursors[0].visit(first);
    scan.cursors[0].drained = true;
    scan.cursors[1].visit(second);

    scan.apply_outcome(ScanOutcome::Progress);
    assert_eq!(scan.epoch_micros, Some(42));
    assert_eq!(scan.cursors[0].after_id, Some(first));
    assert!(scan.cursors[0].drained);
    assert_eq!(scan.cursors[1].after_id, Some(second));

    scan.apply_outcome(ScanOutcome::Failed);
    assert_eq!(scan, EpochScan::default());

    scan.begin(43);
    scan.cursors[0].visit(first);
    scan.apply_outcome(ScanOutcome::Succeeded);
    assert_eq!(scan, EpochScan::default());

    scan.begin(44);
    scan.cursors[0].visit(first);
    scan.apply_outcome(ScanOutcome::Cancelled);
    assert_eq!(scan, EpochScan::default());
}

#[test]
fn independent_subset_latches_wait_for_every_cursor_to_drain() {
    let mut cursors = [ScanCursor::default(); 2];

    let reverse = cursors[0].finish_page(10, 10, true);
    let chain = cursors[1].finish_page(10, 11, true);
    assert_eq!(reverse.merge(chain), ScanOutcome::Progress);
    assert!(cursors[0].drained);
    assert!(!cursors[1].drained);

    let chain = cursors[1].finish_page(10, 0, true);
    assert_eq!(reverse.merge(chain), ScanOutcome::Succeeded);
    assert!(cursors.iter().all(|cursor| cursor.drained));
}

#[test]
fn cursor_advances_only_when_a_row_is_explicitly_visited() {
    let first = Uuid::from_u128(1);
    let second = Uuid::from_u128(2);
    let mut cursor = ScanCursor::default();

    assert_eq!(cursor.after_id, None);
    cursor.visit(first);
    assert_eq!(cursor.after_id, Some(first));
    cursor.visit(second);
    assert_eq!(cursor.after_id, Some(second));
}

#[test]
fn scan_sql_eligibility_ignores_shared_reconciliation_markers() {
    for sql in [
        db::REVERSE_RECONCILER_SCAN_SQL,
        db::REVERSE_SETTLEMENT_REPAIR_SCAN_SQL,
        db::CHAIN_RECONCILER_ELIGIBILITY_SQL,
        db::STALE_REFUNDING_CHAIN_SCAN_ELIGIBILITY_SQL,
        db::CHAIN_SETTLEMENT_REPAIR_ELIGIBILITY_SQL,
    ] {
        assert!(!sql.contains("last_reconciled_at"));
        assert!(sql.contains("$3::uuid"));
    }
}

#[test]
fn chain_settlement_scans_revisit_only_exactly_owned_terminal_rows() {
    assert!(db::CHAIN_RECONCILER_ELIGIBILITY_SQL.contains("c.status = 'claimed'"));
    assert!(db::CHAIN_RECONCILER_ELIGIBILITY_SQL.contains("m.settlement_path = 'liquid_claim'"));
    assert!(db::CHAIN_RECONCILER_ELIGIBILITY_SQL.contains("c.status = 'claim_stuck'"));
    assert!(db::CHAIN_RECONCILER_ELIGIBILITY_SQL.contains("a.purpose = 'liquid_claim'"));
    assert!(db::CHAIN_RECONCILER_ELIGIBILITY_SQL.contains("a.replaces_txid IS NULL"));
    assert!(db::CHAIN_RECONCILER_ELIGIBILITY_SQL.contains("a.txid = c.claim_txid"));
    assert!(db::CHAIN_RECONCILER_ELIGIBILITY_SQL.contains("a.raw_tx_hex = c.claim_tx_hex"));
    assert!(db::CHAIN_RECONCILER_ELIGIBILITY_SQL.contains("a.status <> 'integrity_hold'"));
    assert!(db::STALE_REFUNDING_CHAIN_SCAN_ELIGIBILITY_SQL.contains("c.status = 'refunded'"));
    assert!(db::STALE_REFUNDING_CHAIN_SCAN_ELIGIBILITY_SQL
        .contains("m.settlement_path = 'bitcoin_recovery'"));
    for sql in [
        db::CHAIN_RECONCILER_ELIGIBILITY_SQL,
        db::STALE_REFUNDING_CHAIN_SCAN_ELIGIBILITY_SQL,
    ] {
        assert!(sql.contains("merchant_settlement_checkpoints"));
    }
    assert!(db::CHAIN_SETTLEMENT_REPAIR_ELIGIBILITY_SQL.contains("merchant_chain_swap_id = c.id"));
    assert!(db::CHAIN_SETTLEMENT_REPAIR_ELIGIBILITY_SQL.contains("e.accounting_state = 'active'"));
}

#[test]
fn combined_rail_outcome_waits_for_every_page_and_failure_dominates() {
    assert_eq!(
        ScanOutcome::Succeeded.merge(ScanOutcome::Progress),
        ScanOutcome::Progress
    );
    assert_eq!(
        ScanOutcome::Progress.merge(ScanOutcome::Failed),
        ScanOutcome::Failed
    );
    assert_eq!(
        ScanOutcome::Succeeded.merge(ScanOutcome::Succeeded),
        ScanOutcome::Succeeded
    );
    assert_eq!(
        ScanOutcome::Failed.merge(ScanOutcome::Cancelled),
        ScanOutcome::Cancelled
    );
}

#[test]
fn cycle_health_fails_when_all_provider_operations_fail() {
    let mut health = CycleHealth::default();
    health.provider_failed();
    health.provider_failed();
    health.provider_failed();

    assert!(!health.is_healthy());
}

#[test]
fn cycle_health_isolates_one_provider_or_malformed_obligation() {
    let mut health = CycleHealth::default();
    health.provider_failed();
    health.provider_error(&BoltzClientError::HTTPStatusNotSuccess(
        reqwest::StatusCode::NOT_FOUND,
        serde_json::json!({"error": "swap not found"}),
    ));
    health.observe_app_error(&AppError::ClaimError(
        "invalid persisted chain status: bad value".to_string(),
    ));

    assert!(health.is_healthy());
}

#[test]
fn cycle_health_marks_handler_db_and_settlement_write_failures_systemic() {
    let mut handler_health = CycleHealth::default();
    handler_health.observe_app_error(&AppError::DbError("database unavailable".to_string()));
    assert!(!handler_health.is_healthy());

    let mut settlement_health = CycleHealth::default();
    settlement_health.settlement_write(false);
    assert!(!settlement_health.is_healthy());
}

#[test]
fn cycle_health_distinguishes_recovery_outages_from_local_deferral() {
    for error in [
        AppError::ElectrumError("Bitcoin evidence unavailable".to_string()),
        AppError::BoltzError("recovery pre-check unavailable".to_string()),
    ] {
        let mut health = CycleHealth::default();
        health.observe_app_error(&error);
        assert!(!health.is_healthy());
    }

    let mut local_deferral = CycleHealth::default();
    local_deferral.observe_app_error(&AppError::RecoveryNotAvailable(
        "BTC lockup is observed but not yet confirmed".to_string(),
    ));
    assert!(local_deferral.is_healthy());
}

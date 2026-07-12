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

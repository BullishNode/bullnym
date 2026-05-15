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
fn boltz_mempool_already_claiming_schedules_retry() {
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

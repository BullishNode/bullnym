//! Boltz state reconciler.
//!
//! Boltz's webhook delivery is best-effort: 5 retries × 60s constant
//! interval, 15s timeout per delivery, ~5 minutes total before
//! `Abandoned` (verified at boltz-backend `boltzr/src/webhook/caller.rs`).
//! If a webhook is dropped — Boltz incident, our deploy mid-flight,
//! transient 5xx — the row stays in `pending` / `lockup_*` while the
//! on-chain HTLC progresses, and the 30s background sweep can't
//! advance it because the sweep doesn't query Boltz for state, it just
//! retries claims.
//!
//! The reconciler closes that gap. It runs on a separate `tokio::spawn`
//! task, ticks every 90s by default, scans every non-terminal swap
//! older than 60s (capped at 200 per tick), and calls
//! `BoltzApiClientV2::get_swap` to fetch Boltz's current view. If the
//! views disagree, it patches our DB to match Boltz — Boltz's state is
//! the source of truth for the swap state machine.
//!
//! The reconciler **does not claim** — that's the sweep's job. The
//! reconciler only updates row state and schedules immediate retries
//! by setting `next_claim_attempt_at = NOW()`. This split keeps the
//! reconciler simple and idempotent.

use std::sync::Arc;
use std::time::Duration;

use boltz_client::swaps::boltz::BoltzApiClientV2;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use crate::config::ReconcilerConfig;
use crate::db::{self, ReconcilerSwap, SwapStatus};

/// Spawn the reconciler background task. One task per process.
pub fn spawn(
    pool: PgPool,
    boltz_api_url: String,
    config: Arc<ReconcilerConfig>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let client = BoltzApiClientV2::new(boltz_api_url, None);
        let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs));
        // Skip the immediate first tick so the rest of startup completes
        // before we hammer Boltz. Same pattern as gc::run.
        tick.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("reconciler: shutting down");
                    return;
                }
                _ = tick.tick() => {
                    if let Err(e) = run_one_tick(&pool, &client, &config, &cancel).await {
                        tracing::error!("reconciler tick failed: {e}");
                    }
                }
            }
        }
    });
}

async fn run_one_tick(
    pool: &PgPool,
    client: &BoltzApiClientV2,
    config: &ReconcilerConfig,
    cancel: &CancellationToken,
) -> Result<(), sqlx::Error> {
    let stale = db::list_non_terminal_swaps_oldest_first(
        pool,
        config.min_age_secs,
        config.max_per_tick,
    )
    .await?;

    if stale.is_empty() {
        tracing::debug!("reconciler: no stale swaps");
        return Ok(());
    }

    tracing::info!("reconciler: scanning {} stale swap(s)", stale.len());

    for swap in &stale {
        // Cooperative cancellation: at default config a single tick can
        // take ~50s (200 swaps × 250ms each); without this, SIGTERM has
        // to wait for the tick to complete. Bail mid-loop on cancel.
        if cancel.is_cancelled() {
            tracing::info!("reconciler: cancellation requested mid-tick; exiting early");
            break;
        }
        // Defensive throttle. With max_per_tick=200 and 50ms delay,
        // peak Boltz API RPM is ~133 — well below any reasonable rate
        // limit. Yields between calls to keep the runtime responsive.
        tokio::time::sleep(Duration::from_millis(config.inter_call_delay_ms)).await;

        let remote = match client.get_swap(&swap.boltz_swap_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "reconciler: get_swap({}) failed: {e}",
                    swap.boltz_swap_id
                );
                continue;
            }
        };

        let action = decide_action(swap, &remote.status);
        if let Err(e) = apply_action(pool, swap, action).await {
            tracing::error!(
                "reconciler: apply failed for swap {}: {e}",
                swap.boltz_swap_id
            );
        }
    }

    Ok(())
}

/// Decision matrix: (Boltz status × our status) → ReconcilerAction.
///
/// Centralized + pure so it's unit-testable without a DB or HTTP
/// client. The caller (`apply_action`) does the actual writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcilerAction {
    /// Views agree; nothing to do.
    Noop,
    /// Boltz says lockup is in mempool; advance our row.
    AdvanceToLockupMempool,
    /// Boltz says lockup is confirmed; advance our row.
    AdvanceToLockupConfirmed,
    /// Boltz says the lockup is on-chain and our row is in some
    /// claimable state; nudge `next_claim_attempt_at` so the sweep
    /// picks it up immediately. Status not changed.
    ScheduleImmediateClaim,
    /// Boltz emitted `swap.expired`. Flip `cooperative_refused` and
    /// schedule an immediate retry so the sweep takes the script path.
    /// Status NOT changed — the on-chain HTLC is still claimable until
    /// `timeoutBlockHeight`.
    ScheduleScriptPathRetry,
    /// Boltz says the LN side is dead (`invoice.expired` /
    /// `transaction.failed`). Terminal `expired`. User is safe — they
    /// never paid the LN invoice or Boltz never funded the lockup.
    MarkExpired,
    /// Boltz says the lockup was refunded. Terminal `lockup_refunded`.
    /// FUND LOSS. P0 alert.
    MarkLockupRefunded,
    /// Boltz says invoice settled but our row is not Claimed. Either
    /// our broadcast landed but we lost the response, or someone else
    /// claimed (shouldn't happen but possible). The reconciler can't
    /// disambiguate without an Electrum probe (PR #8); for now just
    /// log loudly and let manual-rescue decide.
    NeedsManualAttention(&'static str),
}

pub(crate) fn decide_action(swap: &ReconcilerSwap, boltz_status: &str) -> ReconcilerAction {
    use ReconcilerAction::*;

    let our_terminal = matches!(
        swap.status.as_str(),
        "claimed" | "expired" | "claim_stuck" | "lockup_refunded"
    );
    if our_terminal {
        // Reconciler scan filters terminal rows out, but be defensive:
        // a row that became terminal between SELECT and this dispatch
        // should never be touched again.
        return Noop;
    }

    match (boltz_status, swap.status.as_str()) {
        // Boltz still in pre-funding. Wait.
        ("swap.created", _) => Noop,

        // Boltz says the lockup is on-chain.
        ("transaction.mempool", "pending") => AdvanceToLockupMempool,
        ("transaction.confirmed", "pending") => AdvanceToLockupConfirmed,
        ("transaction.confirmed", "lockup_mempool") => AdvanceToLockupConfirmed,
        ("transaction.mempool" | "transaction.confirmed", _) => ScheduleImmediateClaim,

        // Wall-clock invoice timer expired but the on-chain HTLC is
        // still claimable until `timeoutBlockHeight`. Cooperative is
        // now refused — script-path is the only recovery.
        ("swap.expired", _) => ScheduleScriptPathRetry,

        // LN side died without us doing anything wrong.
        ("invoice.expired" | "transaction.failed", _) => MarkExpired,

        // Boltz refunded the lockup. We're past the on-chain claim
        // window; the user paid LN and got nothing back.
        ("transaction.refunded", _) => MarkLockupRefunded,

        // Boltz says invoice settled. That should mean WE claimed
        // (only path that reveals the preimage); if our row isn't
        // Claimed, something is out of sync.
        ("invoice.settled", "claimed") => Noop,
        ("invoice.settled", _) => NeedsManualAttention(
            "boltz reports invoice.settled but our status != claimed; PR #8 will electrum-probe",
        ),

        // `minerfee.paid` and any future Boltz-side states are
        // informational; debug-log and move on.
        _ => Noop,
    }
}

async fn apply_action(
    pool: &PgPool,
    swap: &ReconcilerSwap,
    action: ReconcilerAction,
) -> Result<(), sqlx::Error> {
    use ReconcilerAction::*;
    match action {
        Noop => Ok(()),
        AdvanceToLockupMempool => {
            tracing::info!(
                event = "reconciler_advance",
                swap_id = %swap.boltz_swap_id,
                from = %swap.status,
                to = "lockup_mempool",
                "reconciler advancing status (webhook missed)"
            );
            db::update_swap_status(pool, swap.id, SwapStatus::LockupMempool, None).await?;
            db::schedule_immediate_claim(pool, swap.id).await?;
            Ok(())
        }
        AdvanceToLockupConfirmed => {
            tracing::info!(
                event = "reconciler_advance",
                swap_id = %swap.boltz_swap_id,
                from = %swap.status,
                to = "lockup_confirmed",
                "reconciler advancing status (webhook missed)"
            );
            db::update_swap_status(pool, swap.id, SwapStatus::LockupConfirmed, None).await?;
            db::schedule_immediate_claim(pool, swap.id).await?;
            Ok(())
        }
        ScheduleImmediateClaim => {
            tracing::debug!(
                event = "reconciler_schedule_claim",
                swap_id = %swap.boltz_swap_id,
                "reconciler scheduling immediate claim retry"
            );
            db::schedule_immediate_claim(pool, swap.id).await?;
            Ok(())
        }
        ScheduleScriptPathRetry => {
            tracing::warn!(
                event = "reconciler_swap_expired",
                swap_id = %swap.boltz_swap_id,
                "boltz reports swap.expired; flipping cooperative_refused for script-path retry"
            );
            db::schedule_script_path_retry(pool, swap.id).await?;
            Ok(())
        }
        MarkExpired => {
            tracing::info!(
                event = "reconciler_expired",
                swap_id = %swap.boltz_swap_id,
                "boltz reports LN side dead; marking expired"
            );
            db::update_swap_status(pool, swap.id, SwapStatus::Expired, None).await?;
            Ok(())
        }
        MarkLockupRefunded => {
            tracing::error!(
                event = "swap_lockup_refunded",
                swap_id = %swap.boltz_swap_id,
                nym = %swap.nym,
                amount_sat = swap.amount_sat,
                "FUND LOSS: boltz refunded lockup; user paid LN side, no on-chain claim"
            );
            db::update_swap_status(pool, swap.id, SwapStatus::LockupRefunded, None).await?;
            Ok(())
        }
        NeedsManualAttention(reason) => {
            tracing::error!(
                event = "reconciler_needs_attention",
                swap_id = %swap.boltz_swap_id,
                nym = %swap.nym,
                our_status = %swap.status,
                reason,
                "reconciler cannot progress this swap; manual intervention required"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// Build a ReconcilerSwap fixture with given (status, cooperative_refused).
    /// `claim_txid` defaults to None (only used for the invoice.settled
    /// branch which we don't actually need to inspect in decide_action).
    fn fixture(our_status: &str) -> ReconcilerSwap {
        ReconcilerSwap {
            id: Uuid::nil(),
            boltz_swap_id: "test-swap".to_string(),
            status: our_status.to_string(),
            cooperative_refused: false,
            claim_txid: None,
            nym: "alice".to_string(),
            amount_sat: 100_000,
        }
    }

    #[test]
    fn boltz_swap_created_no_op() {
        let swap = fixture("pending");
        assert_eq!(
            decide_action(&swap, "swap.created"),
            ReconcilerAction::Noop
        );
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
        for our in &["lockup_mempool", "lockup_confirmed", "claiming", "claim_failed"] {
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
    fn boltz_invoice_settled_when_we_did_not_claim_needs_attention() {
        let swap = fixture("claiming");
        match decide_action(&swap, "invoice.settled") {
            ReconcilerAction::NeedsManualAttention(_) => {}
            other => panic!("expected NeedsManualAttention, got {other:?}"),
        }
    }

    /// Defense-in-depth: even if the scan returned a terminal row by
    /// mistake, decide_action should never write through.
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
}

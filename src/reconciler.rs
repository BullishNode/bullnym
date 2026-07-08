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
use crate::invoice;
use crate::AppState;

/// Spawn the reconciler background task. One task per process.
pub fn spawn(
    pool: PgPool,
    boltz_api_url: String,
    config: Arc<ReconcilerConfig>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        // Bounded timeout: a hung get_swap must not freeze the reconciler loop
        // (the only recovery for dropped webhooks / the only chain-swap poll
        // driver). Without it, one black-holed Boltz call permanently disables
        // recovery and in-flight swaps stay stuck.
        let client = BoltzApiClientV2::new(boltz_api_url, Some(Duration::from_secs(10)));
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

/// Chain-swap reconciler. The reverse `spawn` above only touches `swap_records`;
/// chain swaps have no other polling recovery, so a dropped Boltz webhook during
/// `pending`/`user_lock_*`/`server_lock_*` would strand the swap forever. This
/// polls Boltz `get_swap` for every non-terminal chain swap and re-drives it
/// through the same handler a webhook would (`claimer::handle_chain_swap_webhook`),
/// which is idempotent. Needs `AppState` because claiming a chain swap requires
/// electrum/boltz endpoints, the utxo backend, and accounting tolerances.
pub fn spawn_chain(state: AppState, config: Arc<ReconcilerConfig>, cancel: CancellationToken) {
    tokio::spawn(async move {
        // Bounded timeout (see spawn() above): a hung chain get_swap must not
        // freeze the chain reconciler loop.
        let client = BoltzApiClientV2::new(state.config.boltz.api_url.clone(), Some(Duration::from_secs(10)));
        let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs));
        tick.tick().await; // skip the immediate first tick (same as reverse spawn)
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("chain reconciler: shutting down");
                    return;
                }
                _ = tick.tick() => {
                    if let Err(e) = run_one_chain_tick(&state, &client, &config, &cancel).await {
                        tracing::error!("chain reconciler tick failed: {e}");
                    }
                }
            }
        }
    });
}

/// Settlement-repair task. Re-records invoice payment events for reverse
/// (Lightning) swaps that reached `claimed` — merchant funds are on chain —
/// but whose invoice flip never completed: the process died, or
/// `record_invoice_payment` transiently failed, between committing the
/// `claimed` status (`claimer.rs`) and running
/// `flip_invoice_on_lightning_settlement` (whose error is only logged). Without
/// this the merchant is paid while the invoice shows unpaid, and the reconciler
/// never revisits terminal `claimed` rows. The flip is idempotent (dedup by
/// event_key), so re-running is a safe no-op once the event exists.
pub fn spawn_settlement_repair(
    state: AppState,
    config: Arc<ReconcilerConfig>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs));
        tick.tick().await; // skip the immediate first tick
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("settlement repair: shutting down");
                    return;
                }
                _ = tick.tick() => {
                    if let Err(e) = run_settlement_repair_tick(&state, &config).await {
                        tracing::error!("settlement repair tick failed: {e}");
                    }
                }
            }
        }
    });
}

async fn run_settlement_repair_tick(
    state: &AppState,
    config: &ReconcilerConfig,
) -> Result<(), sqlx::Error> {
    // Only recently-claimed rows: a stuck flip is repaired within a tick or
    // two, after which the event exists and the row drops out of the query.
    // The window covers the maximum invoice lifetime.
    const REPAIR_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;
    let stuck = db::list_claimed_swaps_missing_lightning_event(
        &state.db,
        REPAIR_MAX_AGE_SECS,
        config.max_per_tick,
    )
    .await?;
    if stuck.is_empty() {
        return Ok(());
    }
    let tolerances = db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting);
    for swap in &stuck {
        let (Some(invoice_id), Some(claim_txid)) = (swap.invoice_id, swap.claim_txid.as_deref())
        else {
            continue;
        };
        tracing::warn!(
            event = "settlement_repair",
            swap_id = %swap.boltz_swap_id,
            invoice_id = %invoice_id,
            "re-recording missing invoice payment event for a claimed Lightning swap"
        );
        crate::invoice::flip_invoice_on_lightning_settlement(
            &state.db,
            Some(invoice_id),
            swap.amount_sat,
            &swap.boltz_swap_id,
            claim_txid,
            tolerances,
        )
        .await;
    }
    Ok(())
}

async fn run_one_chain_tick(
    state: &AppState,
    client: &BoltzApiClientV2,
    config: &ReconcilerConfig,
    cancel: &CancellationToken,
) -> Result<(), sqlx::Error> {
    // Phase 4 backstop: recover chain swaps stranded in `refunding` (customer
    // disconnected or the process restarted mid-refund). Revert them to
    // `refund_due` so a retry can complete; a re-broadcast is UTXO-conflict-safe
    // (same lockup UTXO, same immutable address). The age floor (10× the swap
    // reconciler min-age, min 10 min) keeps an actively-broadcasting refund from
    // being reverted out from under itself.
    let refunding_stale_secs = (config.min_age_secs as i64).saturating_mul(10).max(600);
    match db::revert_stale_refunding_chain_swaps(&state.db, refunding_stale_secs).await {
        Ok(reverted) if !reverted.is_empty() => {
            tracing::error!(
                event = "chain_swap_refunding_stuck_reverted",
                count = reverted.len(),
                ids = ?reverted,
                "reverted stuck `refunding` chain swap(s) to `refund_due` for retry (operator P1 — verify no refund tx confirmed before re-refunding)"
            );
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("chain reconciler: revert_stale_refunding failed: {e}"),
    }

    let stale = db::list_non_terminal_chain_swaps_oldest_first(
        &state.db,
        config.min_age_secs,
        config.max_per_tick,
    )
    .await?;

    if stale.is_empty() {
        tracing::debug!("chain reconciler: no stale chain swaps");
        return Ok(());
    }

    // Round-robin: stamp the whole batch up-front (see mark_chain_swaps_reconciled).
    let ids: Vec<uuid::Uuid> = stale.iter().map(|s| s.id).collect();
    db::mark_chain_swaps_reconciled(&state.db, &ids).await?;

    tracing::info!("chain reconciler: scanning {} stale chain swap(s)", stale.len());

    for swap in &stale {
        if cancel.is_cancelled() {
            tracing::info!("chain reconciler: cancellation requested mid-tick; exiting early");
            break;
        }
        tokio::time::sleep(Duration::from_millis(config.inter_call_delay_ms)).await;

        let remote = match client.get_swap(&swap.boltz_swap_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "chain reconciler: get_swap({}) failed: {e}",
                    swap.boltz_swap_id
                );
                continue;
            }
        };

        // Re-drive through the idempotent webhook handler with Boltz's current
        // view — exactly what a delivered webhook would have done.
        if let Err(e) = crate::claimer::handle_chain_swap_webhook(state, swap, &remote.status).await
        {
            tracing::error!(
                "chain reconciler: handle failed for {}: {e}",
                swap.boltz_swap_id
            );
        }
    }

    Ok(())
}

async fn run_one_tick(
    pool: &PgPool,
    client: &BoltzApiClientV2,
    config: &ReconcilerConfig,
    cancel: &CancellationToken,
) -> Result<(), sqlx::Error> {
    let stale =
        db::list_non_terminal_swaps_oldest_first(pool, config.min_age_secs, config.max_per_tick)
            .await?;

    if stale.is_empty() {
        tracing::debug!("reconciler: no stale swaps");
        return Ok(());
    }

    // Round-robin: stamp the whole batch up-front so the next tick rotates past
    // it (see mark_swaps_reconciled). Must precede the per-swap loop.
    let ids: Vec<uuid::Uuid> = stale.iter().map(|s| s.id).collect();
    db::mark_swaps_reconciled(pool, &ids).await?;

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
                tracing::warn!("reconciler: get_swap({}) failed: {e}", swap.boltz_swap_id);
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
    /// claimed. The reconciler logs loudly and leaves manual rescue to
    /// disambiguate.
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

        // Boltz says invoice settled. That means the claim API received
        // our preimage, but Boltz does not track whether our claim tx was
        // broadcast. If our row is not Claimed yet, nudge the claimer; it
        // owns the advisory lock and the lockup-outspend recovery probe.
        ("invoice.settled", "claimed") => Noop,
        ("invoice.settled", _) => ScheduleImmediateClaim,

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
            // Mempool sighting advances the checkout invoice to
            // `in_progress`. The matching webhook arm uses the same helper.
            invoice::flip_invoice_on_lightning_in_progress(
                pool,
                swap.invoice_id,
                &swap.boltz_swap_id,
            )
            .await;
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
            // Confirmed lockup is still settlement-pending. The claimer
            // records accounting only after our claim succeeds.
            invoice::flip_invoice_on_lightning_in_progress(
                pool,
                swap.invoice_id,
                &swap.boltz_swap_id,
            )
            .await;
            Ok(())
        }
        ScheduleImmediateClaim => {
            // If we never saw a lockup webhook the row is still `pending`, but
            // `get_ready_to_claim_swaps` only sweeps `lockup_mempool`/
            // `lockup_confirmed`/`claiming`/`claim_failed` — scheduling a claim
            // on a `pending` row is a silent no-op that recurs every tick while
            // the (still-claimable) HTLC is abandoned. Advance to
            // `lockup_confirmed` first so the sweep actually picks it up, the
            // same way the mempool/confirmed arms do.
            if swap.status == "pending" {
                db::update_swap_status(pool, swap.id, SwapStatus::LockupConfirmed, None).await?;
            }
            tracing::debug!(
                event = "reconciler_schedule_claim",
                swap_id = %swap.boltz_swap_id,
                "reconciler scheduling immediate claim retry"
            );
            db::schedule_immediate_claim(pool, swap.id).await?;
            Ok(())
        }
        ScheduleScriptPathRetry => {
            // Same `pending` no-op guard as ScheduleImmediateClaim: a swap that
            // reached `swap.expired` while still locally `pending` is excluded
            // by the sweep, so the script-path retry would never run.
            if swap.status == "pending" {
                db::update_swap_status(pool, swap.id, SwapStatus::LockupConfirmed, None).await?;
            }
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
                nym = %swap.nym.as_deref().unwrap_or("<invoice-only>"),
                amount_sat = swap.amount_sat,
                "FUND LOSS: boltz refunded lockup; user paid LN side, no on-chain claim"
            );
            db::update_swap_status(pool, swap.id, SwapStatus::LockupRefunded, None).await?;
            db::mark_invoice_settlement_status(pool, swap.invoice_id, "refunded").await?;
            // Do not record an invoice payment event. A refunded lockup
            // is an incident, not merchant-side settlement.
            Ok(())
        }
        NeedsManualAttention(reason) => {
            tracing::error!(
                event = "reconciler_needs_attention",
                swap_id = %swap.boltz_swap_id,
                nym = %swap.nym.as_deref().unwrap_or("<invoice-only>"),
                our_status = %swap.status,
                reason,
                "reconciler cannot progress this swap; manual intervention required"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;

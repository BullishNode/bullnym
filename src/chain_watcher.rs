//! Chain watcher background task.
//!
//! Periodically polls the Liquid Electrum backend for activity at each active
//! nym's "next address" (and a small lookahead window). When a payment is
//! observed at an address with index `>= next_addr_idx`, we advance
//! `users.next_addr_idx` past it so future LNURL callbacks return a fresh
//! unused address.
//!
//! Polling-based by design: simple, no subscription state to manage. ~30s
//! cadence is fine for our LUD-22 "last unused address" semantics.

use std::sync::Arc;
use std::time::Duration;

use std::str::FromStr;

use elements::encode::deserialize;
use lwk_wollet::elements;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use crate::admission::WorkerReporter;
use crate::db;
use crate::error::AppError;
use crate::rate_limit::RateLimiter;
use crate::utxo::UtxoBackend;

pub struct ChainWatcherConfig {
    /// How often to scan the "active" set (users with a recent callback).
    pub active_tick_secs: u64,
    /// How often to scan the "idle" set (everyone else). Idle ticks also
    /// re-scan the active set, so the active loop never stalls during an
    /// idle pass.
    pub idle_tick_secs: u64,
    /// A user is "active" if `last_callback_at` is within this many
    /// seconds. NULL last_callback_at always falls in the idle set.
    pub active_window_secs: u32,
    pub lookahead: u32,
}

impl Default for ChainWatcherConfig {
    fn default() -> Self {
        Self {
            active_tick_secs: 30,
            idle_tick_secs: 600,
            active_window_secs: 86_400,
            lookahead: 10,
        }
    }
}

impl ChainWatcherConfig {
    /// Build from `RateLimitConfig` so the watcher cadences come from one
    /// place (the deployed config) without each call site recomputing.
    pub fn from_rate_limit_config(rl: &crate::config::RateLimitConfig) -> Self {
        Self {
            active_tick_secs: rl.chain_watcher_active_user_tick_secs as u64,
            idle_tick_secs: rl.chain_watcher_idle_user_tick_secs as u64,
            active_window_secs: rl.chain_watcher_active_window_secs,
            lookahead: 10,
        }
    }
}

#[derive(Clone, Copy)]
struct ChainWatcherPollCtx<'a> {
    pool: &'a PgPool,
    backend: &'a (dyn UtxoBackend + Send + Sync),
    rate_limiter: &'a RateLimiter,
    cancel: &'a CancellationToken,
}

struct LiquidRecordOutcome {
    recorded: usize,
    healthy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CycleOutcome {
    Healthy,
    Incomplete,
    Failed,
}

impl CycleOutcome {
    fn after_token_exhaustion(useful_progress: usize) -> Self {
        if useful_progress == 0 {
            Self::Failed
        } else {
            Self::Incomplete
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchTier {
    Active,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportAction {
    Success,
    Failure,
    ProgressOnly,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum TierState {
    #[default]
    Unknown,
    Healthy,
    Failed,
}

#[derive(Debug, Default)]
struct TierHealth {
    active: TierState,
    idle: TierState,
}

#[derive(Debug, Default)]
struct LiquidTierScanEpoch {
    nyms: db::WatcherNymScanEpoch,
    invoices: db::WatcherScanEpoch,
    nyms_complete: bool,
}

impl LiquidTierScanEpoch {
    fn finish(&mut self) {
        self.nyms.finish();
        self.invoices.finish();
        self.nyms_complete = false;
    }
}

impl TierHealth {
    fn observe(&mut self, tier: WatchTier, outcome: CycleOutcome) -> ReportAction {
        let (current, other) = match tier {
            WatchTier::Active => (&mut self.active, self.idle),
            WatchTier::Idle => (&mut self.idle, self.active),
        };
        match outcome {
            CycleOutcome::Incomplete => ReportAction::ProgressOnly,
            CycleOutcome::Failed => {
                *current = TierState::Failed;
                ReportAction::Failure
            }
            CycleOutcome::Healthy => {
                *current = TierState::Healthy;
                if other == TierState::Healthy {
                    ReportAction::Success
                } else {
                    ReportAction::ProgressOnly
                }
            }
        }
    }
}

fn report_outcome(
    reporter: &WorkerReporter,
    tier_health: &mut TierHealth,
    tier: WatchTier,
    outcome: CycleOutcome,
) {
    match tier_health.observe(tier, outcome) {
        ReportAction::Success => reporter.cycle_succeeded(),
        ReportAction::Failure => reporter.cycle_failed(),
        ReportAction::ProgressOnly => reporter.progress(),
    }
}

/// Run the chain watcher loop. Spawned for the lifetime of the server.
/// Two cadences:
///   - `active_tick_secs`: scans only users with a recent callback.
///     Bounded by real traffic, not by the size of the `users` table.
///   - `idle_tick_secs`: scans every active user (active + idle). Catches
///     payments to users who haven't had a recent callback.
///
/// `rate_limiter` exposes a dedicated watcher-only Electrum bucket
/// (`check_electrum_watcher`) so a callback storm cannot starve the
/// watcher and vice-versa.
pub async fn run(
    pool: PgPool,
    backend: Arc<dyn UtxoBackend + Send + Sync>,
    rate_limiter: Arc<RateLimiter>,
    cancel: CancellationToken,
    cfg: ChainWatcherConfig,
    tolerances: db::InvoiceAccountingTolerances,
    mut reporter: WorkerReporter,
) {
    let mut tier_health = TierHealth::default();
    let mut active_epoch = LiquidTierScanEpoch::default();
    let mut idle_epoch = LiquidTierScanEpoch::default();
    if cancel.is_cancelled() {
        reporter.intentional_shutdown();
        return;
    }

    for (tier, active, epoch) in [
        (WatchTier::Active, true, &mut active_epoch),
        (WatchTier::Idle, false, &mut idle_epoch),
    ] {
        let startup_outcome = poll_cycle(
            ChainWatcherPollCtx {
                pool: &pool,
                backend: backend.as_ref(),
                rate_limiter: rate_limiter.as_ref(),
                cancel: &cancel,
            },
            &cfg,
            tolerances,
            active,
            &reporter,
            epoch,
        )
        .await;
        if cancel.is_cancelled() {
            reporter.intentional_shutdown();
            return;
        }
        report_outcome(&reporter, &mut tier_health, tier, startup_outcome);
    }

    let mut active_tick = tokio::time::interval(Duration::from_secs(cfg.active_tick_secs));
    let mut idle_tick = tokio::time::interval(Duration::from_secs(cfg.idle_tick_secs));
    active_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // The current process completed its startup scan above; consume each
    // interval's immediate tick so the next scans follow the configured cadence.
    active_tick.tick().await;
    idle_tick.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("chain_watcher: shutdown signal received, exiting");
                reporter.intentional_shutdown();
                return;
            }
            _ = active_tick.tick() => {
                let healthy = poll_cycle(
                    ChainWatcherPollCtx {
                        pool: &pool,
                        backend: backend.as_ref(),
                        rate_limiter: rate_limiter.as_ref(),
                        cancel: &cancel,
                    },
                    &cfg, tolerances, true, &reporter, &mut active_epoch,
                ).await;
                if cancel.is_cancelled() {
                    reporter.intentional_shutdown();
                    return;
                }
                report_outcome(
                    &reporter,
                    &mut tier_health,
                    WatchTier::Active,
                    healthy,
                );
            }
            _ = idle_tick.tick() => {
                let healthy = poll_cycle(
                    ChainWatcherPollCtx {
                        pool: &pool,
                        backend: backend.as_ref(),
                        rate_limiter: rate_limiter.as_ref(),
                        cancel: &cancel,
                    },
                    &cfg, tolerances, false, &reporter, &mut idle_epoch,
                ).await;
                if cancel.is_cancelled() {
                    reporter.intentional_shutdown();
                    return;
                }
                report_outcome(
                    &reporter,
                    &mut tier_health,
                    WatchTier::Idle,
                    healthy,
                );
            }
        }
    }
}

async fn poll_cycle(
    ctx: ChainWatcherPollCtx<'_>,
    cfg: &ChainWatcherConfig,
    tolerances: db::InvoiceAccountingTolerances,
    active: bool,
    reporter: &WorkerReporter,
    epoch: &mut LiquidTierScanEpoch,
) -> CycleOutcome {
    reporter.progress();
    if ctx.cancel.is_cancelled() {
        return CycleOutcome::Incomplete;
    }
    if let Err(error) = ctx.backend.health_check().await {
        tracing::warn!(
            tier = if active { "active" } else { "idle" },
            "chain_watcher: Liquid backend health check failed: {error}"
        );
        return CycleOutcome::Failed;
    }
    let tier = if active { "active" } else { "idle" };
    if !epoch.nyms_complete {
        if epoch.nyms.snapshot().is_none() {
            match db::watcher_scan_snapshot(ctx.pool).await {
                Ok(snapshot) => epoch.nyms.begin(snapshot),
                Err(e) => {
                    tracing::warn!("chain_watcher: nym scan snapshot failed: {e}");
                    return CycleOutcome::Failed;
                }
            }
        }
        let snapshot = epoch
            .nyms
            .snapshot()
            .expect("watcher nym epoch snapshot initialized before page query");
        let page = if active {
            db::list_recently_active_nyms_for_watcher_page(
                ctx.pool,
                cfg.active_window_secs,
                snapshot,
                epoch.nyms.query_cursor(),
            )
            .await
        } else {
            // Idle ticks scan all active users (active + idle subsets).
            db::list_active_nyms_for_watcher_page(ctx.pool, snapshot, epoch.nyms.query_cursor())
                .await
        };
        let page = match page {
            Ok(page) => page,
            Err(e) => {
                tracing::warn!("chain_watcher: list {tier} nym page failed: {e}");
                return CycleOutcome::Failed;
            }
        };
        let has_more = page.has_more;
        let nym_outcome = match poll_nyms(
            ctx,
            cfg.lookahead,
            page.rows,
            tier,
            reporter,
            &mut epoch.nyms,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::warn!("chain_watcher {tier} poll failed: {e:?}");
                CycleOutcome::Failed
            }
        };
        if ctx.cancel.is_cancelled() || nym_outcome != CycleOutcome::Healthy {
            return nym_outcome;
        }
        if has_more {
            return CycleOutcome::Incomplete;
        }
        // Keep the completed nym epoch latched while invoice pages drain.
        // Reset both phases together only after the invoice epoch is healthy.
        epoch.nyms_complete = true;
    }

    let outcome =
        poll_invoice_addresses(ctx, tolerances, tier, reporter, &mut epoch.invoices).await;
    if outcome == CycleOutcome::Healthy {
        epoch.finish();
    }
    outcome
}

/// Address-keyed scan for invoice Liquid destinations. This catches both
/// linked and unlinked invoices and runs alongside the per-nym lookahead in
/// `poll_nyms`. Payment events are idempotent by outpoint.
///
/// Direct Liquid accounting: inspect raw tx outputs, unblind outputs that
/// match the invoice script, and record exact LBTC amounts idempotently.
async fn poll_invoice_addresses(
    ctx: ChainWatcherPollCtx<'_>,
    tolerances: db::InvoiceAccountingTolerances,
    tier: &'static str,
    reporter: &WorkerReporter,
    epoch: &mut db::WatcherScanEpoch,
) -> CycleOutcome {
    reporter.progress();
    if epoch.snapshot().is_none() {
        match db::watcher_scan_snapshot(ctx.pool).await {
            Ok(snapshot) => epoch.begin(snapshot),
            Err(e) => {
                tracing::warn!("chain_watcher: invoice scan snapshot failed: {e}");
                return CycleOutcome::Failed;
            }
        }
    }
    let snapshot = epoch
        .snapshot()
        .expect("watcher epoch snapshot initialized before page query");
    let batch = match db::list_unpaid_invoices_with_liquid_address_page(
        ctx.pool,
        tolerances.payment_grace_secs,
        snapshot,
        epoch.cursor(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("chain_watcher: list invoice addresses failed: {e}");
            return CycleOutcome::Failed;
        }
    };
    let invoices = batch.rows;
    let n_total = invoices.len();
    if n_total == 0 {
        return CycleOutcome::Healthy;
    }
    let started = std::time::Instant::now();
    let mut hits = 0usize;
    let mut useful_progress = 0usize;
    for invoice in invoices {
        reporter.progress();
        if ctx.cancel.is_cancelled() {
            return CycleOutcome::Incomplete;
        }
        if ctx.rate_limiter.check_electrum_watcher().await.is_err() {
            tracing::debug!(
                "chain_watcher: invoice scan watcher Electrum bucket exhausted, deferring"
            );
            return CycleOutcome::after_token_exhaustion(useful_progress);
        }

        // Parse the wallet-supplied or descriptor-derived address into a
        // Liquid script. Bad/foreign-network addresses are rejected at
        // create time by the validators, so this should never fail in
        // practice; defensively log+skip if it does.
        let parsed = match elements::Address::from_str(&invoice.liquid_address) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    invoice_id = %invoice.id,
                    "chain_watcher: invoice liquid_address parse failed: {e}"
                );
                epoch.advance(invoice.scan_cursor());
                useful_progress = useful_progress.saturating_add(1);
                continue;
            }
        };
        let script = parsed.script_pubkey();

        match record_liquid_events_for_script(
            ctx,
            invoice.id,
            &invoice.liquid_address,
            &script,
            &invoice.liquid_blinding_key_hex,
            tolerances,
            reporter,
        )
        .await
        {
            Ok(record_outcome) => {
                hits += record_outcome.recorded;
                if !record_outcome.healthy {
                    // A required payment write failed. Do not advance past this
                    // invoice; retry it at the same keyset position next tick.
                    return CycleOutcome::Failed;
                }
                epoch.advance(invoice.scan_cursor());
                useful_progress = useful_progress.saturating_add(1);
            }
            Err(e) => {
                tracing::warn!(
                    invoice_id = %invoice.id,
                    "chain_watcher: invoice Liquid output scan failed: {e}"
                );
                if matches!(
                    e,
                    AppError::InvalidAmount(_) | AppError::InvalidDescriptor(_)
                ) {
                    // Malformed persisted row: isolate it, but count the row as
                    // visited so it cannot pin every later invoice forever.
                    epoch.advance(invoice.scan_cursor());
                    useful_progress = useful_progress.saturating_add(1);
                    continue;
                }
                return CycleOutcome::Failed;
            }
        }
    }
    let elapsed_ms = started.elapsed().as_millis();
    // Quiet ticks (no invoices in scope) stay at debug; non-empty ticks
    // log at info so the operator can see the address scan is alive
    // without sifting through verbose-mode logs.
    if n_total > 0 {
        tracing::info!(
            event = "chain_watcher_invoice_scan_tick",
            tier = tier,
            scanned = n_total,
            deferred = batch.has_more,
            hits = hits,
            elapsed_ms = elapsed_ms,
            "chain_watcher: invoice address scan tick"
        );
    } else {
        tracing::debug!(
            "chain_watcher: {} invoice address scan {} addrs, {} hits, {}ms",
            tier,
            n_total,
            hits,
            elapsed_ms
        );
    }
    if batch.has_more {
        CycleOutcome::Incomplete
    } else {
        CycleOutcome::Healthy
    }
}

async fn record_liquid_events_for_script(
    ctx: ChainWatcherPollCtx<'_>,
    invoice_id: uuid::Uuid,
    address: &str,
    script: &elements::Script,
    blinding_key_hex: &str,
    tolerances: db::InvoiceAccountingTolerances,
    reporter: &WorkerReporter,
) -> Result<LiquidRecordOutcome, AppError> {
    let blinding_key = elements::secp256k1_zkp::SecretKey::from_str(blinding_key_hex)
        .map_err(|e| AppError::InvalidAmount(format!("stored Liquid blinding key invalid: {e}")))?;
    let txids = ctx.backend.history_txids(script).await?;
    if txids.is_empty() {
        return Ok(LiquidRecordOutcome {
            recorded: 0,
            healthy: true,
        });
    }
    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let mut recorded = 0usize;
    let mut healthy = true;
    for txid in txids {
        reporter.progress();
        let raw = ctx.backend.get_raw_tx(&txid).await?;
        let tx: elements::Transaction = deserialize(&raw)
            .map_err(|e| AppError::ElectrumError(format!("liquid tx decode: {e}")))?;
        for (vout, txout) in tx.output.iter().enumerate() {
            if &txout.script_pubkey != script {
                continue;
            }
            let secrets = match txout.unblind(&secp, blinding_key) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(
                        invoice_id = %invoice_id,
                        txid = %txid,
                        vout = vout,
                        "chain_watcher: matching Liquid output did not unblind: {e}"
                    );
                    continue;
                }
            };
            if secrets.asset != elements::AssetId::LIQUID_BTC {
                tracing::debug!(
                    invoice_id = %invoice_id,
                    txid = %txid,
                    vout = vout,
                    asset = %secrets.asset,
                    "chain_watcher: ignoring non-LBTC Liquid invoice output"
                );
                continue;
            }
            let amount_sat = i64::try_from(secrets.value)
                .map_err(|_| AppError::InvalidAmount("Liquid output amount overflow".into()))?;
            let event_key = format!("liquid_direct:{txid}:{vout}");
            let vout_i32 = i32::try_from(vout)
                .map_err(|_| AppError::InvalidAmount("Liquid output vout overflow".into()))?;
            match db::record_invoice_payment(
                ctx.pool,
                invoice_id,
                db::InvoicePaymentEvidence {
                    rail: "liquid",
                    source: "liquid_direct",
                    event_key: &event_key,
                    amount_sat,
                    txid: Some(&txid),
                    vout: Some(vout_i32),
                    boltz_swap_id: None,
                    address: Some(address),
                },
                tolerances,
            )
            .await
            {
                Ok(rows) if rows > 0 => {
                    recorded += 1;
                    tracing::info!(
                        event = "invoice_payment_event_liquid",
                        invoice_id = %invoice_id,
                        txid = %txid,
                        vout = vout,
                        amount_sat = amount_sat,
                        "chain_watcher: recorded Liquid invoice payment event"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    healthy = false;
                    tracing::error!(
                        invoice_id = %invoice_id,
                        txid = %txid,
                        vout = vout,
                        "chain_watcher: record_invoice_payment failed: {e}"
                    );
                }
            }
        }
    }
    Ok(LiquidRecordOutcome { recorded, healthy })
}

async fn poll_nyms(
    ctx: ChainWatcherPollCtx<'_>,
    lookahead: u32,
    nyms: Vec<db::ActiveNymForWatcher>,
    tier: &'static str,
    reporter: &WorkerReporter,
    epoch: &mut db::WatcherNymScanEpoch,
) -> Result<CycleOutcome, AppError> {
    let n_total = nyms.len();
    let started = std::time::Instant::now();
    let mut useful_progress = 0usize;

    let mut rows = nyms.into_iter();
    loop {
        if epoch.current().is_none() {
            let Some(nym) = rows.next() else {
                break;
            };

            // Skip rows with negative indices defensively — DB schema uses i32,
            // but next_addr_idx is conceptually u32. This is obligation-local.
            let base_index = match u32::try_from(nym.next_addr_idx) {
                Ok(index) => index,
                Err(_) => {
                    tracing::warn!(
                        nym = %nym.nym,
                        next_addr_idx = nym.next_addr_idx,
                        "chain_watcher: nym has invalid next_addr_idx; skipping frozen scan"
                    );
                    epoch.advance(nym.nym);
                    useful_progress = useful_progress.saturating_add(1);
                    continue;
                }
            };
            let nym_name = nym.nym;
            if !epoch.begin_nym(nym_name.clone(), nym.ct_descriptor, base_index, lookahead) {
                tracing::warn!(
                    nym = %nym_name,
                    base_index,
                    lookahead,
                    "chain_watcher: frozen nym range exceeds address-index storage; isolating nym"
                );
                epoch.advance(nym_name);
                useful_progress = useful_progress.saturating_add(1);
                continue;
            }
        }

        let current = epoch
            .current()
            .expect("current nym initialized before address scan")
            .clone();
        reporter.progress();
        if ctx.cancel.is_cancelled() {
            return Ok(CycleOutcome::Incomplete);
        }

        let script = match derive_script_pubkey(&current.ct_descriptor, current.next_index) {
            Ok(script) => script,
            Err(error) => {
                tracing::warn!(
                    nym = %current.nym,
                    idx = current.next_index,
                    "chain_watcher: derive failed for frozen nym address: {error}"
                );
                // Malformed persisted descriptor: isolate this whole nym and
                // clear its address subcursor so later keyset rows can proceed.
                epoch.finish_current_nym();
                useful_progress = useful_progress.saturating_add(1);
                continue;
            }
        };

        // Use the watcher-dedicated Electrum bucket so a user-callback storm
        // cannot starve the watcher. The exact current address remains retained
        // when the bucket is empty; useful address progress in this page keeps
        // the cycle incomplete rather than falsely failed.
        if ctx.rate_limiter.check_electrum_watcher().await.is_err() {
            tracing::debug!(
                nym = %current.nym,
                idx = current.next_index,
                "chain_watcher: watcher Electrum bucket exhausted; retaining frozen address"
            );
            return Ok(CycleOutcome::after_token_exhaustion(useful_progress));
        }

        match ctx.backend.has_history(&script).await {
            Ok(true) => {
                // Preserve reservation-before-user-cursor ordering. The address
                // subcursor advances only after both idempotent writes succeed;
                // either failure retries this exact index on the next tick.
                let fulfilled = db::mark_reservations_fulfilled_at_idx(
                    ctx.pool,
                    &current.nym,
                    current.next_index,
                )
                .await?;
                db::advance_next_addr_idx(ctx.pool, &current.nym, current.next_index).await?;
                tracing::info!(
                    nym = %current.nym,
                    idx = current.next_index,
                    fulfilled,
                    "chain_watcher: observed payment in frozen nym range"
                );
            }
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(
                    nym = %current.nym,
                    idx = current.next_index,
                    "chain_watcher: has_history failed for frozen nym address: {error}"
                );
                return Ok(CycleOutcome::Failed);
            }
        }

        epoch.visit_current_address();
        useful_progress = useful_progress.saturating_add(1);
    }
    let elapsed_ms = started.elapsed().as_millis();
    tracing::debug!(
        "chain_watcher: {} tick scanned {} nyms in {}ms",
        tier,
        n_total,
        elapsed_ms
    );
    Ok(CycleOutcome::Healthy)
}

/// Derive the scriptpubkey for `(ct_descriptor, idx)`. Mirrors
/// `descriptor::derive_address` but returns a `Script` so we can hand it to
/// the Electrum backend without a string round-trip.
fn derive_script_pubkey(ct_descriptor: &str, index: u32) -> Result<elements::Script, AppError> {
    let desc: lwk_wollet::WolletDescriptor = ct_descriptor
        .parse()
        .map_err(|e| AppError::InvalidDescriptor(format!("{e}")))?;
    let addr = desc
        .address(index, &elements::AddressParams::LIQUID)
        .map_err(|e| AppError::InvalidDescriptor(format!("address derivation failed: {e}")))?;
    Ok(addr.script_pubkey())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{MoneyAdmission, Rail, Worker};
    use crate::config::RateLimitConfig;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_DESCRIPTOR: &str = "ct(slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023),elwpkh([73c5da0a/84h/1776h/0h]xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*))#y8jljyxl";

    enum FakeHistory {
        Empty,
        BackendFailure,
    }

    struct FakeNymBackend {
        history: FakeHistory,
        health_calls: Arc<AtomicUsize>,
        fail_health: bool,
    }

    #[async_trait::async_trait]
    impl UtxoBackend for FakeNymBackend {
        async fn health_check(&self) -> Result<(), AppError> {
            self.health_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_health {
                Err(AppError::ElectrumError(
                    "test health check failure".to_string(),
                ))
            } else {
                Ok(())
            }
        }

        async fn get_raw_tx(&self, _txid_hex: &str) -> Result<Vec<u8>, AppError> {
            Err(AppError::UtxoNotFound)
        }

        async fn is_unspent(
            &self,
            _script_pubkey: &elements::Script,
            _txid_hex: &str,
            _vout: u32,
        ) -> Result<bool, AppError> {
            Ok(false)
        }

        async fn has_history(&self, _script_pubkey: &elements::Script) -> Result<bool, AppError> {
            match self.history {
                FakeHistory::Empty => Ok(false),
                FakeHistory::BackendFailure => {
                    Err(AppError::ElectrumError("test backend failure".to_string()))
                }
            }
        }

        async fn history_txids(
            &self,
            _script_pubkey: &elements::Script,
        ) -> Result<Vec<String>, AppError> {
            Ok(Vec::new())
        }

        async fn find_spending_txid(
            &self,
            _script_pubkey: &elements::Script,
            _txid_hex: &str,
            _vout: u32,
        ) -> Result<Option<String>, AppError> {
            Ok(None)
        }
    }

    fn test_nym(nym: &str) -> db::ActiveNymForWatcher {
        db::ActiveNymForWatcher {
            nym: nym.to_string(),
            ct_descriptor: TEST_DESCRIPTOR.to_string(),
            next_addr_idx: 0,
        }
    }

    fn lazy_test_pool() -> PgPool {
        PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bullnym_watcher_unit_test")
            .expect("lazy test pool")
    }

    fn fixture() -> (MoneyAdmission, WorkerReporter, TierHealth) {
        let admission = MoneyAdmission::healthy_test_fixture();
        let reporter = admission.reporter(Worker::LiquidWatcher);
        (admission, reporter, TierHealth::default())
    }

    #[test]
    fn incomplete_startup_cycle_stays_closed() {
        let (admission, reporter, mut tier_health) = fixture();

        assert_eq!(
            TierHealth::default().observe(WatchTier::Active, CycleOutcome::Incomplete),
            ReportAction::ProgressOnly
        );

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Incomplete,
        );

        assert!(!admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn healthy_tier_cannot_open_startup_while_other_tier_is_unknown() {
        let (admission, reporter, mut tier_health) = fixture();

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Healthy,
        );
        assert_eq!(tier_health.active, TierState::Healthy);
        assert_eq!(tier_health.idle, TierState::Unknown);
        assert!(!admission.decision(Rail::DirectLiquid).allowed());

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Idle,
            CycleOutcome::Healthy,
        );
        assert!(admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn incomplete_page_does_not_mutate_tier_failure_or_recovery_latch() {
        let mut tier_health = TierHealth::default();
        assert_eq!(
            tier_health.observe(WatchTier::Idle, CycleOutcome::Failed),
            ReportAction::Failure
        );
        assert_eq!(tier_health.idle, TierState::Failed);

        assert_eq!(
            tier_health.observe(WatchTier::Idle, CycleOutcome::Incomplete),
            ReportAction::ProgressOnly
        );
        assert_eq!(tier_health.idle, TierState::Failed);
        assert_eq!(tier_health.active, TierState::Unknown);
    }

    #[test]
    fn token_exhaustion_requires_useful_progress_for_incomplete() {
        assert_eq!(
            CycleOutcome::after_token_exhaustion(0),
            CycleOutcome::Failed
        );
        assert_eq!(
            CycleOutcome::after_token_exhaustion(1),
            CycleOutcome::Incomplete
        );
    }

    #[test]
    fn completed_nym_phase_stays_latched_until_invoice_epoch_finishes() {
        let mut epoch = LiquidTierScanEpoch::default();
        epoch.nyms.begin("2026-07-12 12:00:00+00".to_string());
        epoch.nyms.advance("last-nym".to_string());
        epoch.nyms_complete = true;
        epoch.invoices.begin("2026-07-12 12:01:00+00".to_string());
        epoch.invoices.advance(db::WatcherScanCursor {
            created_at: "2026-07-12 11:00:00+00".to_string(),
            id: uuid::Uuid::from_u128(1),
        });

        // An incomplete invoice page leaves the completed nym phase intact,
        // so the next tick resumes invoices instead of restarting at nym one.
        assert!(epoch.nyms_complete);
        assert_eq!(epoch.nyms.cursor(), Some("last-nym"));
        assert!(epoch.invoices.cursor().is_some());

        epoch.finish();
        assert!(!epoch.nyms_complete);
        assert!(epoch.nyms.snapshot().is_none());
        assert!(epoch.nyms.cursor().is_none());
        assert!(epoch.invoices.snapshot().is_none());
        assert!(epoch.invoices.cursor().is_none());
    }

    #[tokio::test]
    async fn nym_token_exhaustion_resumes_after_last_complete_nym() {
        let pool = lazy_test_pool();
        let cfg = RateLimitConfig {
            chain_watcher_electrum_rate_per_sec: 1,
            ..RateLimitConfig::default()
        };
        let rate_limiter = RateLimiter::new(pool.clone(), cfg);
        let backend = FakeNymBackend {
            history: FakeHistory::Empty,
            health_calls: Arc::new(AtomicUsize::new(0)),
            fail_health: false,
        };
        let cancel = CancellationToken::new();
        let (_admission, reporter, _) = fixture();
        let ctx = ChainWatcherPollCtx {
            pool: &pool,
            backend: &backend,
            rate_limiter: &rate_limiter,
            cancel: &cancel,
        };
        let mut epoch = db::WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());

        let outcome = poll_nyms(
            ctx,
            0,
            vec![test_nym("alice"), test_nym("bob")],
            "active",
            &reporter,
            &mut epoch,
        )
        .await
        .expect("nym page outcome");
        assert_eq!(outcome, CycleOutcome::Incomplete);
        assert_eq!(epoch.cursor(), Some("alice"));
        let current = epoch
            .current()
            .expect("bob retained after token exhaustion");
        assert_eq!(current.nym, "bob");
        assert_eq!(current.next_index, 0);

        // The next keyset page begins after bob; bob itself resumes from the
        // frozen subcursor. With no newly-refilled token it makes zero address
        // progress, fails, and still does not skip bob.
        let outcome = poll_nyms(ctx, 0, vec![], "active", &reporter, &mut epoch)
            .await
            .expect("resumed nym page outcome");
        assert_eq!(outcome, CycleOutcome::Failed);
        assert_eq!(epoch.cursor(), Some("alice"));
        assert_eq!(epoch.current().expect("bob still retained").next_index, 0);
    }

    #[tokio::test]
    async fn mid_nym_token_exhaustion_resumes_at_exact_next_address() {
        let pool = lazy_test_pool();
        let cfg = RateLimitConfig {
            chain_watcher_electrum_rate_per_sec: 1,
            ..RateLimitConfig::default()
        };
        let rate_limiter = RateLimiter::new(pool.clone(), cfg);
        let backend = FakeNymBackend {
            history: FakeHistory::Empty,
            health_calls: Arc::new(AtomicUsize::new(0)),
            fail_health: false,
        };
        let cancel = CancellationToken::new();
        let (_admission, reporter, _) = fixture();
        let ctx = ChainWatcherPollCtx {
            pool: &pool,
            backend: &backend,
            rate_limiter: &rate_limiter,
            cancel: &cancel,
        };
        let mut epoch = db::WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());

        let outcome = poll_nyms(
            ctx,
            2,
            vec![test_nym("alice")],
            "active",
            &reporter,
            &mut epoch,
        )
        .await
        .expect("partial nym outcome");
        assert_eq!(outcome, CycleOutcome::Incomplete);
        let current = epoch.current().expect("mid-nym subcursor retained");
        assert_eq!(current.nym, "alice");
        assert_eq!(current.next_index, 1);
        assert_eq!(current.end_index, 2);
        assert_eq!(epoch.cursor(), None);
        assert_eq!(epoch.query_cursor(), Some("alice"));

        // Production fetches later rows strictly after query_cursor, so the
        // retained nym is absent from this page and resumes from memory.
        let outcome = poll_nyms(ctx, 2, vec![], "active", &reporter, &mut epoch)
            .await
            .expect("retained nym outcome");
        assert_eq!(outcome, CycleOutcome::Failed);
        assert_eq!(
            epoch.current().expect("exact address retained").next_index,
            1
        );
    }

    #[tokio::test]
    async fn systemic_nym_backend_failure_retains_current_nym() {
        let pool = lazy_test_pool();
        let rate_limiter = RateLimiter::new(pool.clone(), RateLimitConfig::default());
        let backend = FakeNymBackend {
            history: FakeHistory::BackendFailure,
            health_calls: Arc::new(AtomicUsize::new(0)),
            fail_health: false,
        };
        let cancel = CancellationToken::new();
        let (_admission, reporter, _) = fixture();
        let ctx = ChainWatcherPollCtx {
            pool: &pool,
            backend: &backend,
            rate_limiter: &rate_limiter,
            cancel: &cancel,
        };
        let mut epoch = db::WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        epoch.advance("alice".to_string());

        let outcome = poll_nyms(ctx, 0, vec![test_nym("bob")], "idle", &reporter, &mut epoch)
            .await
            .expect("backend failure outcome");
        assert_eq!(outcome, CycleOutcome::Failed);
        assert_eq!(epoch.cursor(), Some("alice"));
        let current = epoch.current().expect("systemic failure retains bob");
        assert_eq!(current.nym, "bob");
        assert_eq!(current.next_index, 0);
        assert_eq!(current.end_index, 0);
    }

    #[tokio::test]
    async fn disappeared_current_nym_finishes_frozen_work_before_later_page_rows() {
        let pool = lazy_test_pool();
        let rate_limiter = RateLimiter::new(pool.clone(), RateLimitConfig::default());
        let backend = FakeNymBackend {
            history: FakeHistory::Empty,
            health_calls: Arc::new(AtomicUsize::new(0)),
            fail_health: false,
        };
        let cancel = CancellationToken::new();
        let (_admission, reporter, _) = fixture();
        let ctx = ChainWatcherPollCtx {
            pool: &pool,
            backend: &backend,
            rate_limiter: &rate_limiter,
            cancel: &cancel,
        };
        let mut epoch = db::WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        assert!(epoch.begin_nym("gone".to_string(), TEST_DESCRIPTOR.to_string(), 0, 0));
        assert_eq!(epoch.query_cursor(), Some("gone"));

        // The DB page is keyed after `gone`, so a deactivated/deleted current
        // nym is not present. Its frozen address still drains safely, then the
        // later row proceeds without a pin or skip.
        let outcome = poll_nyms(
            ctx,
            0,
            vec![test_nym("later")],
            "idle",
            &reporter,
            &mut epoch,
        )
        .await
        .expect("disappeared nym convergence");
        assert_eq!(outcome, CycleOutcome::Healthy);
        assert!(epoch.current().is_none());
        assert_eq!(epoch.cursor(), Some("later"));
    }

    #[tokio::test]
    async fn failing_liquid_probe_prevents_empty_startup_success() {
        let pool = lazy_test_pool();
        let rate_limiter = RateLimiter::new(pool.clone(), RateLimitConfig::default());
        let health_calls = Arc::new(AtomicUsize::new(0));
        let backend = FakeNymBackend {
            history: FakeHistory::Empty,
            health_calls: health_calls.clone(),
            fail_health: true,
        };
        let cancel = CancellationToken::new();
        let (admission, reporter, mut tier_health) = fixture();
        let mut epoch = LiquidTierScanEpoch::default();

        // The lazy pool has no server behind it. The backend probe must run
        // before an empty/page lookup can short-circuit the tier as healthy.
        let outcome = poll_cycle(
            ChainWatcherPollCtx {
                pool: &pool,
                backend: &backend,
                rate_limiter: &rate_limiter,
                cancel: &cancel,
            },
            &ChainWatcherConfig::default(),
            db::InvoiceAccountingTolerances::default(),
            true,
            &reporter,
            &mut epoch,
        )
        .await;

        assert_eq!(health_calls.load(Ordering::SeqCst), 1);
        assert_eq!(outcome, CycleOutcome::Failed);
        report_outcome(&reporter, &mut tier_health, WatchTier::Active, outcome);
        assert_eq!(tier_health.active, TierState::Failed);
        assert!(!admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn active_success_does_not_reset_interleaved_idle_failures() {
        let (admission, reporter, mut tier_health) = fixture();
        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Healthy,
        );

        for attempt in 1..=3 {
            report_outcome(
                &reporter,
                &mut tier_health,
                WatchTier::Idle,
                CycleOutcome::Failed,
            );
            if attempt < 3 {
                report_outcome(
                    &reporter,
                    &mut tier_health,
                    WatchTier::Active,
                    CycleOutcome::Healthy,
                );
            }
        }

        assert!(!admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn two_successes_reopen_after_both_tiers_are_healthy() {
        let (admission, reporter, mut tier_health) = fixture();
        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Healthy,
        );
        for _ in 0..3 {
            report_outcome(
                &reporter,
                &mut tier_health,
                WatchTier::Idle,
                CycleOutcome::Failed,
            );
            report_outcome(
                &reporter,
                &mut tier_health,
                WatchTier::Active,
                CycleOutcome::Healthy,
            );
        }
        assert!(!admission.decision(Rail::DirectLiquid).allowed());

        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Idle,
            CycleOutcome::Healthy,
        );
        assert!(!admission.decision(Rail::DirectLiquid).allowed());
        report_outcome(
            &reporter,
            &mut tier_health,
            WatchTier::Active,
            CycleOutcome::Healthy,
        );

        assert!(admission.decision(Rail::DirectLiquid).allowed());
    }
}

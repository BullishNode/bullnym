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

use lwk_wollet::elements;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

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

/// Run the chain watcher loop. Spawned for the lifetime of the server.
/// Two cadences (P4):
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
) {
    let mut active_tick = tokio::time::interval(Duration::from_secs(cfg.active_tick_secs));
    let mut idle_tick = tokio::time::interval(Duration::from_secs(cfg.idle_tick_secs));
    active_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Skip the immediate-first-tick so we don't slam the DB/Electrum at
    // boot before the rest of the server has finished warming up.
    active_tick.tick().await;
    idle_tick.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("chain_watcher: shutdown signal received, exiting");
                break;
            }
            _ = active_tick.tick() => {
                let nyms = match db::list_recently_active_nyms_for_watcher(
                    &pool, cfg.active_window_secs,
                ).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!("chain_watcher: list active failed: {e}");
                        continue;
                    }
                };
                if let Err(e) = poll_nyms(
                    &pool, backend.as_ref(), rate_limiter.as_ref(),
                    cfg.lookahead, nyms, &cancel, "active",
                ).await {
                    tracing::warn!("chain_watcher active poll failed: {e:?}");
                }
            }
            _ = idle_tick.tick() => {
                // Idle tick scans all active users (active + idle subsets).
                // Slower cadence so this never blocks the active loop.
                let nyms = match db::list_active_nyms_for_watcher(&pool).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!("chain_watcher: list-all failed: {e}");
                        continue;
                    }
                };
                if let Err(e) = poll_nyms(
                    &pool, backend.as_ref(), rate_limiter.as_ref(),
                    cfg.lookahead, nyms, &cancel, "idle",
                ).await {
                    tracing::warn!("chain_watcher idle poll failed: {e:?}");
                }
            }
        }
    }
}

async fn poll_nyms(
    pool: &PgPool,
    backend: &(dyn UtxoBackend + Send + Sync),
    rate_limiter: &RateLimiter,
    lookahead: u32,
    nyms: Vec<db::ActiveNymForWatcher>,
    cancel: &CancellationToken,
    tier: &'static str,
) -> Result<(), AppError> {
    let n_total = nyms.len();
    let started = std::time::Instant::now();
    for n in nyms {
        if cancel.is_cancelled() {
            return Ok(());
        }
        // Skip rows with negative or implausible indices defensively — DB
        // schema uses i32, but next_addr_idx is conceptually u32.
        let base_idx: u32 = match u32::try_from(n.next_addr_idx) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    "chain_watcher: nym {} has invalid next_addr_idx {}; skipping",
                    n.nym,
                    n.next_addr_idx
                );
                continue;
            }
        };

        for offset in 0..=lookahead {
            let idx = match base_idx.checked_add(offset) {
                Some(v) => v,
                None => break, // overflow guard
            };

            let script = match derive_script_pubkey(&n.ct_descriptor, idx) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "chain_watcher: derive failed for nym={} idx={}: {e}",
                        n.nym,
                        idx
                    );
                    break;
                }
            };

            // Use the watcher-dedicated Electrum bucket (P4) so a user-
            // callback storm cannot starve the watcher. If our bucket
            // exhausts, drop the rest of this nym's lookahead and try
            // again on the next tick.
            if rate_limiter.check_electrum_watcher().await.is_err() {
                tracing::debug!(
                    "chain_watcher: watcher Electrum bucket exhausted, deferring nym={} idx={}",
                    n.nym,
                    idx
                );
                break;
            }

            match backend.has_history(&script).await {
                Ok(true) => {
                    db::advance_next_addr_idx(pool, &n.nym, idx).await?;
                    // Flip every still-pending reservation that pointed at
                    // this idx. In last-unused mode multiple concurrent
                    // senders share an addr_index, so one observed payment
                    // may fulfill many rows. Without this, the
                    // `count_unfulfilled_reservations` view stays artificially
                    // inflated and the per-nym pending cap could fire on a
                    // legitimate busy nym.
                    let fulfilled =
                        db::mark_reservations_fulfilled_at_idx(pool, &n.nym, idx).await?;
                    tracing::info!(
                        "chain_watcher: observed payment at nym={} idx={} \
                         (advanced next_addr_idx, fulfilled {} reservation row(s))",
                        n.nym,
                        idx,
                        fulfilled,
                    );
                    // Re-poll from the new next_addr_idx on the next cycle.
                    break;
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(
                        "chain_watcher: has_history failed for nym={} idx={}: {e}",
                        n.nym,
                        idx
                    );
                    // Stop scanning this nym this cycle; backend will likely
                    // also fail on the next idx. Try again next tick.
                    break;
                }
            }
        }
    }
    let elapsed_ms = started.elapsed().as_millis();
    tracing::debug!(
        "chain_watcher: {} tick scanned {} nyms in {}ms",
        tier, n_total, elapsed_ms
    );
    Ok(())
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

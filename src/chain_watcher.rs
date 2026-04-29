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
    pub poll_interval_secs: u64,
    pub lookahead: u32,
}

impl Default for ChainWatcherConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 30,
            lookahead: 10,
        }
    }
}

/// Run the chain watcher loop. Intended to be `tokio::spawn`-ed and run for
/// the lifetime of the server. Errors during a single poll are logged but do
/// not terminate the loop. Exits cleanly on `cancel.cancelled()`.
///
/// `rate_limiter` is shared with the request handlers so that this watcher's
/// Electrum traffic is metered by the same global token bucket — without it,
/// a 30s tick over many active nyms would burst-saturate the bucket and
/// starve real callbacks.
pub async fn run(
    pool: PgPool,
    backend: Arc<dyn UtxoBackend + Send + Sync>,
    rate_limiter: Arc<RateLimiter>,
    cancel: CancellationToken,
    cfg: ChainWatcherConfig,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(cfg.poll_interval_secs));
    // Skip the immediate-first-tick so we don't slam the DB/Electrum at boot
    // before the rest of the server has finished warming up.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("chain_watcher: shutdown signal received, exiting");
                break;
            }
            _ = interval.tick() => {}
        }
        if let Err(e) = poll_once(&pool, backend.as_ref(), rate_limiter.as_ref(), cfg.lookahead, &cancel).await {
            tracing::warn!("chain_watcher poll failed: {e:?}");
        }
    }
}

async fn poll_once(
    pool: &PgPool,
    backend: &(dyn UtxoBackend + Send + Sync),
    rate_limiter: &RateLimiter,
    lookahead: u32,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let nyms = db::list_active_nyms_for_watcher(pool).await?;
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

            // Honour the same global Electrum token bucket as the request
            // handlers. If we'd starve the bucket, drop this address (and
            // implicitly the rest of this nym's lookahead) and try again
            // next tick. Real user callbacks have priority.
            if rate_limiter.check_electrum().await.is_err() {
                tracing::debug!(
                    "chain_watcher: electrum bucket exhausted, deferring nym={} idx={}",
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

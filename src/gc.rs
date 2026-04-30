//! Background GC for the rate-limit tables.
//!
//! `rate_limit_events` and `nym_access_events` accumulate one row per
//! request/cache-miss and never self-clean. Without GC the windowed
//! `COUNT(*)` queries get progressively slower as the indexes bloat with
//! rows that are no longer in any active window.
//!
//! Strategy: every `tick_secs`, prune rows older than `retention_secs`.
//! `retention_secs` is set to 2× the longest configured rate-limit window
//! (so the limiter can never observe a "missing" row that should still
//! count). With windows in the 60s..3600s range, 24h retention is plenty.
//!
//! Pruning runs as a background `tokio::spawn` from `main.rs`, cancelled
//! by the same `CancellationToken` as the chain watcher. Errors are
//! logged and ignored — a transient DB hiccup shouldn't kill the GC loop.

use std::time::Duration;

use sqlx::PgPool;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy)]
pub struct GcConfig {
    pub tick_secs: u64,
    pub retention_secs: u64,
    /// TTL for unfulfilled `outpoint_addresses` rows (D1 fix). Rows that
    /// the chain watcher hasn't observed paid within this window are
    /// recycled. 1h is enough for any real payer to land their tx; longer
    /// just lets attackers fill the per-nym pending cap without paying.
    pub outpoint_pending_ttl_secs: u64,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            tick_secs: 600,         // 10 min
            retention_secs: 86_400, // 24 h — well past the longest 1h window
            outpoint_pending_ttl_secs: 3_600, // 1 h
        }
    }
}

pub async fn run(pool: PgPool, cancel: CancellationToken, cfg: GcConfig) {
    let mut tick = interval(Duration::from_secs(cfg.tick_secs));
    // Skip the initial immediate tick so we don't fire during startup.
    tick.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("rate-limit GC: shutdown requested");
                return;
            }
            _ = tick.tick() => {
                let removed_rl = prune_rate_limit_events(&pool, cfg.retention_secs).await;
                let removed_na = prune_nym_access_events(&pool, cfg.retention_secs).await;
                let removed_oa =
                    prune_outpoint_addresses(&pool, cfg.outpoint_pending_ttl_secs).await;
                tracing::info!(
                    "rate-limit GC: pruned rate_limit_events={} nym_access_events={} outpoint_addresses_pending={}",
                    removed_rl,
                    removed_na,
                    removed_oa
                );
            }
        }
    }
}

async fn prune_rate_limit_events(pool: &PgPool, retention_secs: u64) -> u64 {
    match sqlx::query(
        "DELETE FROM rate_limit_events \
         WHERE created_at < NOW() - ($1 || ' seconds')::interval",
    )
    .bind(retention_secs as i64)
    .execute(pool)
    .await
    {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            tracing::warn!("rate-limit GC: rate_limit_events prune failed: {e}");
            0
        }
    }
}

async fn prune_nym_access_events(pool: &PgPool, retention_secs: u64) -> u64 {
    match sqlx::query(
        "DELETE FROM nym_access_events \
         WHERE created_at < NOW() - ($1 || ' seconds')::interval",
    )
    .bind(retention_secs as i64)
    .execute(pool)
    .await
    {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            tracing::warn!("rate-limit GC: nym_access_events prune failed: {e}");
            0
        }
    }
}

/// D1 fix: recycle unfulfilled `outpoint_addresses` rows whose chain
/// watcher never observed a payment. The per-nym pending-reservation cap
/// is otherwise filled forever by an attacker submitting valid proofs
/// over UTXOs they never intend to spend.
async fn prune_outpoint_addresses(pool: &PgPool, ttl_secs: u64) -> u64 {
    match sqlx::query(
        "DELETE FROM outpoint_addresses \
         WHERE fulfilled = FALSE \
           AND created_at < NOW() - ($1 || ' seconds')::interval",
    )
    .bind(ttl_secs as i64)
    .execute(pool)
    .await
    {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            tracing::warn!("rate-limit GC: outpoint_addresses prune failed: {e}");
            0
        }
    }
}

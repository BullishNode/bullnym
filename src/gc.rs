//! Background cleanup for rate-limit events and worker-owned payment state.
//!
//! `rate_limit_events` and `nym_access_events` accumulate one row per
//! request/cache-miss and never self-clean. Without GC the windowed
//! `COUNT(*)` queries get progressively slower as the indexes bloat with
//! rows that are no longer in any active window.
//!
//! Strategy: every `tick_secs`, prune rows older than `retention_secs`.
//! `retention_secs` is set to 2x the longest configured rate-limit window
//! so the limiter cannot lose an event that should still count.
//!
//! Rate-limit pruning runs in every HTTP process. Payment-state cleanup runs
//! only with workers enabled. Both loops share the process cancellation token;
//! transient database failures are logged without terminating either loop.

use std::time::Duration;

use sqlx::PgPool;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

use crate::db;

#[derive(Debug, Clone, Copy)]
pub struct GcConfig {
    pub tick_secs: u64,
    pub retention_secs: u64,
    pub checkout_partial_terminal_grace_secs: u64,
    /// Post-expiry grace window (seconds): GC withholds expiry until
    /// `expires_at + payment_grace_secs`, so a payment confirming just after
    /// expiry is still credited (the expiry-cliff fix). Mirrors
    /// `InvoiceAccountingConfig::payment_grace_secs`.
    pub payment_grace_secs: u64,
    /// TTL for unfulfilled `outpoint_addresses` rows. Rows that the chain
    /// watcher hasn't observed paid within this window are recycled. 1h is
    /// enough for any real payer to land their tx; longer just lets
    /// attackers fill the per-nym pending cap without paying.
    pub outpoint_pending_ttl_secs: u64,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            tick_secs: 600,          // 10 min
            retention_secs: 172_800, // 48 h, twice the backup distinct-key window
            checkout_partial_terminal_grace_secs: 900,
            payment_grace_secs: 3_600,        // 1 h
            outpoint_pending_ttl_secs: 3_600, // 1 h
        }
    }
}

pub async fn run(pool: PgPool, cancel: CancellationToken, cfg: GcConfig) {
    let mut tick = interval(Duration::from_secs(cfg.tick_secs));
    // Skip the initial immediate tick to avoid cleanup work during startup.
    tick.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("operational GC: shutdown requested");
                return;
            }
            _ = tick.tick() => {
                let removed_oa =
                    prune_outpoint_addresses(&pool, cfg.outpoint_pending_ttl_secs).await;
                let removed_iv =
                    expire_invoices_past_deadline(&pool, cfg.payment_grace_secs).await;
                let terminalized_partials =
                    terminalize_stale_checkout_partial_invoices(
                        &pool,
                        cfg.checkout_partial_terminal_grace_secs,
                    ).await;
                tracing::info!(
                    "operational GC: pruned outpoint_addresses_pending={} \
                     invoices_expired={} checkout_partials_underpaid={}",
                    removed_oa,
                    removed_iv,
                    terminalized_partials,
                );
            }
        }
    }
}

pub async fn run_rate_limit_gc(
    pool: PgPool,
    cancel: CancellationToken,
    tick_secs: u64,
    retention_secs: u64,
) {
    let mut tick = interval(Duration::from_secs(tick_secs));
    tick.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("rate-limit GC: shutdown requested");
                return;
            }
            _ = tick.tick() => {
                let removed_rate_limits = prune_rate_limit_events(&pool, retention_secs).await;
                let removed_distinct = prune_nym_access_events(&pool, retention_secs).await;
                tracing::info!(
                    "rate-limit GC: pruned rate_limit_events={} nym_access_events={}",
                    removed_rate_limits,
                    removed_distinct,
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

/// Close evidence-free invoices past `expires_at + payment_grace_secs`.
/// Set-based idempotent UPDATE: re-runs are safe, and payment/settlement
/// projections are excluded by the predicate. The grace window keeps a
/// late-confirming payment creditable instead of expiring it out from under
/// the watcher.
async fn expire_invoices_past_deadline(pool: &PgPool, payment_grace_secs: u64) -> u64 {
    match db::expire_invoices_past_deadline(pool, payment_grace_secs).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("operational GC: expire_invoices_past_deadline failed: {e}");
            0
        }
    }
}

async fn terminalize_stale_checkout_partial_invoices(pool: &PgPool, grace_secs: u64) -> u64 {
    match db::terminalize_stale_checkout_partial_invoices(pool, grace_secs).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("operational GC: terminalize stale checkout partials failed: {e}");
            0
        }
    }
}

/// Recycle unfulfilled `outpoint_addresses` rows whose chain watcher never
/// observed a payment. The per-nym pending-reservation cap is otherwise
/// filled forever by an attacker submitting valid proofs over UTXOs they
/// never intend to spend.
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
            tracing::warn!("operational GC: outpoint_addresses prune failed: {e}");
            0
        }
    }
}

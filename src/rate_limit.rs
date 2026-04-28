//! Layered rate limiters.
//!
//! - Per-IP, per-pubkey, per-nym (lightning): sliding-window counts in
//!   Postgres (table `rate_limit_events`). Write-then-count pattern.
//! - Per-nym reservation cap: count of unfulfilled rows in
//!   `outpoint_addresses` — queried via `db::count_unfulfilled_reservations`.
//! - Global Electrum rate: in-process token bucket, refills every second.
//!
//! Whitelisted IPs are *not* handled here — the caller skips the limiter
//! entirely when an IP is whitelisted.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::RateLimitConfig;
use crate::db;
use crate::error::AppError;

pub struct RateLimiter {
    pool: PgPool,
    cfg: RateLimitConfig,
    electrum_bucket: Arc<AsyncMutex<TokenBucket>>,
}

impl RateLimiter {
    pub fn new(pool: PgPool, cfg: RateLimitConfig) -> Self {
        let bucket = TokenBucket::new(cfg.global_electrum_rate_per_sec);
        Self {
            pool,
            cfg,
            electrum_bucket: Arc::new(AsyncMutex::new(bucket)),
        }
    }

    pub fn config(&self) -> &RateLimitConfig {
        &self.cfg
    }

    // --- Per-IP limit (Liquid callback) ---
    pub async fn check_per_ip(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = format!("ip:{ip}");
        self.sliding_window_check(
            &bucket,
            self.cfg.per_ip_limit,
            self.cfg.per_ip_window_secs,
        )
        .await
    }

    // --- Per-pubkey limit (Liquid callback, post-sig-verify) ---
    pub async fn check_per_pubkey(&self, pubkey_hex: &str) -> Result<(), AppError> {
        let bucket = format!("pubkey:{pubkey_hex}");
        self.sliding_window_check(
            &bucket,
            self.cfg.per_pubkey_limit,
            self.cfg.per_pubkey_window_secs,
        )
        .await
    }

    // --- Distinct-nyms per IP (Liquid callback) ---
    pub async fn check_distinct_nyms_per_ip(
        &self,
        ip: IpAddr,
        nym: &str,
    ) -> Result<(), AppError> {
        let source_key = format!("ip:{ip}");
        self.distinct_nyms_check(
            &source_key,
            nym,
            self.cfg.distinct_nyms_per_ip_limit,
            self.cfg.distinct_nyms_window_secs,
        )
        .await
    }

    // --- Distinct-nyms per outpoint (Liquid callback) ---
    pub async fn check_distinct_nyms_per_outpoint(
        &self,
        outpoint: &str,
        nym: &str,
    ) -> Result<(), AppError> {
        let source_key = format!("outpoint:{outpoint}");
        self.distinct_nyms_check(
            &source_key,
            nym,
            self.cfg.distinct_nyms_per_outpoint_limit,
            self.cfg.distinct_nyms_window_secs,
        )
        .await
    }

    // --- Per-nym lightning-path rate limit ---
    pub async fn check_lightning_per_nym(&self, nym: &str) -> Result<(), AppError> {
        let bucket = format!("nym:{nym}");
        self.sliding_window_check(
            &bucket,
            self.cfg.lightning_rate_per_minute,
            60,
        )
        .await
    }

    // --- Per-nym pending reservation cap ---
    pub async fn check_pending_reservations(&self, nym: &str) -> Result<(), AppError> {
        let count = db::count_unfulfilled_reservations(&self.pool, nym).await?;
        if count as u32 >= self.cfg.max_pending_reservations_per_nym {
            return Err(AppError::TooManyPendingReservations);
        }
        Ok(())
    }

    // --- Global Electrum backend rate ---
    pub async fn check_electrum(&self) -> Result<(), AppError> {
        let mut bucket = self.electrum_bucket.lock().await;
        if bucket.try_consume() {
            Ok(())
        } else {
            Err(AppError::RateLimited)
        }
    }

    // --- Internal ---

    /// Record a hit in `bucket`, then reject if the count within `window_secs`
    /// already exceeds `limit`.
    ///
    /// Invariants: `limit == 0` disables the check (always allow). Window
    /// must be > 0.
    async fn sliding_window_check(
        &self,
        bucket: &str,
        limit: u32,
        window_secs: u32,
    ) -> Result<(), AppError> {
        if limit == 0 {
            return Ok(());
        }
        db::record_rate_limit_event(&self.pool, bucket).await?;
        let count = db::count_rate_limit_events(&self.pool, bucket, window_secs).await?;
        if count as u32 > limit {
            return Err(AppError::RateLimited);
        }
        Ok(())
    }

    /// Record a (source_key, nym) pair, then reject if the count of DISTINCT
    /// nyms seen for this source within `window_secs` exceeds `limit`.
    ///
    /// Invariants: `limit == 0` disables the check (always allow).
    async fn distinct_nyms_check(
        &self,
        source_key: &str,
        nym: &str,
        limit: u32,
        window_secs: u32,
    ) -> Result<(), AppError> {
        if limit == 0 {
            return Ok(());
        }
        db::record_nym_access(&self.pool, source_key, nym).await?;
        let count = db::count_distinct_nyms(&self.pool, source_key, window_secs).await?;
        if count as u32 > limit {
            return Err(AppError::RateLimited);
        }
        Ok(())
    }
}

// --- Token bucket ---

/// Simple refill-per-second token bucket. Capacity == refill rate == `rate`.
///
/// Separate from the sliding-window checker because the Electrum bottleneck
/// is real-time (calls/sec against a shared backend) — we don't want a DB
/// round-trip just to decide whether to make another RPC.
pub struct TokenBucket {
    capacity: u32,
    tokens: u32,
    last_refill: Instant,
    refill_per_sec: u32,
}

impl TokenBucket {
    pub fn new(rate_per_sec: u32) -> Self {
        Self {
            capacity: rate_per_sec.max(1),
            tokens: rate_per_sec.max(1),
            last_refill: Instant::now(),
            refill_per_sec: rate_per_sec.max(1),
        }
    }

    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed();
        if elapsed >= Duration::from_secs(1) {
            let seconds = elapsed.as_secs() as u32;
            let add = seconds.saturating_mul(self.refill_per_sec);
            self.tokens = (self.tokens.saturating_add(add)).min(self.capacity);
            self.last_refill = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_initial_full() {
        let mut b = TokenBucket::new(3);
        assert!(b.try_consume());
        assert!(b.try_consume());
        assert!(b.try_consume());
        assert!(!b.try_consume());
    }

    #[test]
    fn token_bucket_refills() {
        let mut b = TokenBucket::new(2);
        b.tokens = 0;
        b.last_refill = Instant::now() - Duration::from_secs(2);
        assert!(b.try_consume());
    }

    #[test]
    fn token_bucket_respects_capacity() {
        let mut b = TokenBucket::new(1);
        b.tokens = 1;
        b.last_refill = Instant::now() - Duration::from_secs(100);
        b.refill();
        assert_eq!(b.tokens, 1);
    }

    #[test]
    fn token_bucket_zero_rate_uses_min_one() {
        // Guard against divide-by-zero or permanent-0 states.
        let mut b = TokenBucket::new(0);
        assert!(b.try_consume());
    }
}

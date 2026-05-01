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

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::RateLimitConfig;
use crate::db;
use crate::error::AppError;
use crate::ip_whitelist::source_key;

pub struct RateLimiter {
    pool: PgPool,
    cfg: RateLimitConfig,
    /// User-facing Electrum bucket. Drained by `/lnurlp/callback` only.
    electrum_bucket: Arc<AsyncMutex<TokenBucket>>,
    /// Dedicated bucket for the chain watcher (P4). Separate so a callback
    /// storm cannot starve the watcher — and vice-versa.
    watcher_electrum_bucket: Arc<AsyncMutex<TokenBucket>>,
    /// In-memory per-bucket sliding-window counter for the hot per-IP-style
    /// axes (per-IP callback, register, metadata). Each bucket key is
    /// guarded by DashMap's per-shard lock, so the check-and-record
    /// sequence is naturally atomic — no INSERT-then-COUNT race.
    inmem: Arc<InMemorySliding>,
}

impl RateLimiter {
    pub fn new(pool: PgPool, cfg: RateLimitConfig) -> Self {
        let user_bucket = TokenBucket::new(cfg.global_electrum_rate_per_sec);
        let watcher_bucket = TokenBucket::new(cfg.chain_watcher_electrum_rate_per_sec);
        Self {
            pool,
            cfg,
            electrum_bucket: Arc::new(AsyncMutex::new(user_bucket)),
            watcher_electrum_bucket: Arc::new(AsyncMutex::new(watcher_bucket)),
            inmem: Arc::new(InMemorySliding::default()),
        }
    }

    /// Drop in-memory entries that haven't been touched in `max_age`.
    /// Called periodically from a background task in `main.rs`. Bounds
    /// memory growth from one-shot bursts of unique IPs.
    pub fn sweep_inmemory(&self, max_age: Duration) -> usize {
        self.inmem.sweep_idle(max_age)
    }

    pub fn config(&self) -> &RateLimitConfig {
        &self.cfg
    }

    // --- Per-IP limit (Liquid callback) ---
    pub async fn check_per_ip(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = source_key(ip);
        self.inmem_sliding_check(
            &bucket,
            self.cfg.per_ip_limit,
            self.cfg.per_ip_window_secs,
            AppError::RateLimitedSender,
        )
    }

    // --- Per-pubkey limit (Liquid callback, post-sig-verify) ---
    pub async fn check_per_pubkey(&self, pubkey_hex: &str) -> Result<(), AppError> {
        let bucket = format!("pubkey:{pubkey_hex}");
        // Pubkey is post-sig-verify and low-volume; correctness > speed.
        // Kept on the atomic-Postgres path so it's consistent across replicas.
        self.atomic_sliding_window_check(
            &bucket,
            self.cfg.per_pubkey_limit,
            self.cfg.per_pubkey_window_secs,
            AppError::RateLimitedSender,
        )
        .await
    }

    // --- Distinct-nyms per IP (Liquid callback) ---
    //
    // Asymmetric limit by IP family (PR D): IPv4 sources get a looser
    // cap because a single /32 is often shared by many real users
    // (CGNAT, office NAT, family WiFi). IPv6 /56 sources get a tighter
    // cap because /56 is the canonical ISP-customer block — one real
    // user / household per /56.
    pub async fn check_distinct_nyms_per_ip(
        &self,
        ip: IpAddr,
        nym: &str,
    ) -> Result<(), AppError> {
        let bucket = source_key(ip);
        let limit = match ip {
            IpAddr::V4(_) => self.cfg.distinct_nyms_per_ip_limit,
            IpAddr::V6(_) => self.cfg.distinct_nyms_per_ipv6_56_limit,
        };
        self.distinct_nyms_check(
            &bucket,
            nym,
            limit,
            self.cfg.distinct_nyms_window_secs,
            AppError::RateLimitedNetwork,
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
            AppError::RateLimitedNetwork,
        )
        .await
    }

    // --- Per-nym lightning-path rate limit ---
    pub async fn check_lightning_per_nym(&self, nym: &str) -> Result<(), AppError> {
        let bucket = format!("nym:{nym}");
        // Per-nym Lightning is low-volume and the cross-replica consistency
        // matters (a real attacker hitting one nym from many IPs lands on
        // the same DB bucket). Atomic Postgres is the right call.
        self.atomic_sliding_window_check(
            &bucket,
            self.cfg.lightning_rate_per_minute,
            60,
            AppError::RateLimitedRecipient,
        )
        .await
    }

    // --- Registration gates (P1) ---

    /// Cheap-CPU first-line gate on `/register*` and `/register/lookup`.
    /// Applied BEFORE Nostr signature verification so an attacker can't
    /// burn server CPU on sig verifies they were never going to clear.
    pub async fn check_register_per_ip(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = format!("register:{}", source_key(ip));
        self.inmem_sliding_check(
            &bucket,
            self.cfg.register_rate_limit,
            self.cfg.register_rate_window_secs,
            AppError::RateLimitedSender,
        )
    }

    /// Distinct-npubs-per-IP cap on `POST /register`. Stops slow-drip
    /// registration where one IP creates many distinct identities just
    /// under the per-IP rate-limit window.
    ///
    /// Reuses `nym_access_events` with a distinct source-key prefix
    /// (`register:ip:`) so it doesn't collide with the Liquid-callback
    /// distinct-nym counters that use `ip:` directly.
    pub async fn check_register_distinct_npubs_per_ip(
        &self,
        ip: IpAddr,
        npub_hex: &str,
    ) -> Result<(), AppError> {
        let bucket = format!("register:{}", source_key(ip));
        self.distinct_nyms_check(
            &bucket,
            npub_hex,
            self.cfg.register_distinct_npubs_per_ip_limit,
            self.cfg.register_distinct_npubs_per_ip_window_secs,
            AppError::RateLimitedNetwork,
        )
        .await
    }

    /// Hard ceiling on the number of active users. Returns
    /// `AppError::ServiceUnavailable` (HTTP 503) once the cap is reached.
    /// 0 disables the check.
    pub async fn check_max_active_users(&self) -> Result<(), AppError> {
        if self.cfg.max_active_users == 0 {
            return Ok(());
        }
        let active = db::count_active_users(&self.pool).await?;
        if active as u32 >= self.cfg.max_active_users {
            return Err(AppError::ServiceUnavailable(format!(
                "active user ceiling reached ({} >= {})",
                active, self.cfg.max_active_users
            )));
        }
        Ok(())
    }

    // --- Metadata + lookup gates (P2) ---

    /// Per-IP rate-limit for `GET /.well-known/lnurlp/:nym` and
    /// `GET /.well-known/nostr.json`. Closes R-enum: enumeration of the
    /// nym registry by hammering metadata endpoints from one IP.
    pub async fn check_metadata_per_ip(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = format!("meta:{}", source_key(ip));
        self.inmem_sliding_check(
            &bucket,
            self.cfg.metadata_rate_limit,
            self.cfg.metadata_rate_window_secs,
            AppError::RateLimitedSender,
        )
    }

    /// Distinct nyms-queried per IP across the metadata endpoints. Bounds
    /// slow-drip enumeration (one nym every couple of seconds, just under
    /// the per-IP rate). Reuses `nym_access_events` with the `meta:ip:`
    /// source-key prefix so it doesn't collide with the Liquid-callback
    /// distinct-nym counter that uses `ip:`.
    pub async fn check_metadata_distinct_nyms_per_ip(
        &self,
        ip: IpAddr,
        nym: &str,
    ) -> Result<(), AppError> {
        let bucket = format!("meta:{}", source_key(ip));
        self.distinct_nyms_check(
            &bucket,
            nym,
            self.cfg.metadata_distinct_nyms_per_ip_limit,
            self.cfg.metadata_distinct_nyms_per_ip_window_secs,
            AppError::RateLimitedNetwork,
        )
        .await
    }

    /// Distinct npubs-queried per IP via `GET /register/lookup`. Same
    /// shape as the metadata distinct-nyms cap but for the npub-side
    /// enumeration vector. Uses the `lookup:ip:` source-key prefix.
    /// Per-source rate-limit on `/webhook/boltz` (D2). Even after HMAC
    /// auth, webhook-bombing from one source is bounded by this. Real
    /// Boltz traffic is well under 10/min/IP for a healthy swap.
    pub async fn check_webhook_per_ip(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = format!("webhook:{}", source_key(ip));
        // Webhook errors go back to Boltz, not a wallet — copy is irrelevant
        // beyond the HTTP status. Use Sender for log-grouping consistency.
        self.inmem_sliding_check(
            &bucket,
            self.cfg.webhook_rate_limit,
            self.cfg.webhook_rate_window_secs,
            AppError::RateLimitedSender,
        )
    }

    /// Per-source Lightning ops cap (PR C). Covers BOTH explicit
    /// `network=lightning` callbacks AND Liquid→Lightning soft fallbacks.
    /// Loose by design (30/h default) — Lightning is the default rail and
    /// doesn't leak Liquid addresses; the cap exists only to bound
    /// per-source Boltz API spend.
    pub async fn check_lightning_per_source(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = format!("lightning:{}", source_key(ip));
        self.inmem_sliding_check(
            &bucket,
            self.cfg.lightning_per_source_limit,
            self.cfg.lightning_per_source_window_secs,
            AppError::RateLimitedSender,
        )
    }

    pub async fn check_lookup_distinct_npubs_per_ip(
        &self,
        ip: IpAddr,
        npub_hex: &str,
    ) -> Result<(), AppError> {
        let bucket = format!("lookup:{}", source_key(ip));
        self.distinct_nyms_check(
            &bucket,
            npub_hex,
            self.cfg.lookup_distinct_npubs_per_ip_limit,
            self.cfg.lookup_distinct_npubs_per_ip_window_secs,
            AppError::RateLimitedNetwork,
        )
        .await
    }

    // --- Per-nym pending reservation cap ---
    pub async fn check_pending_reservations(&self, nym: &str) -> Result<(), AppError> {
        let count = db::count_unfulfilled_reservations(&self.pool, nym).await?;
        if count as u32 >= self.cfg.max_pending_reservations_per_nym {
            tracing::warn!(
                event = "rate_limited",
                axis = "pending_reservations",
                nym = nym,
                count = count,
                limit = self.cfg.max_pending_reservations_per_nym,
                "pending-reservation cap reached"
            );
            return Err(AppError::TooManyPendingReservations);
        }
        Ok(())
    }

    // --- Global Electrum backend rate (user-facing) ---
    pub async fn check_electrum(&self) -> Result<(), AppError> {
        let mut bucket = self.electrum_bucket.lock().await;
        if bucket.try_consume() {
            Ok(())
        } else {
            tracing::warn!(
                event = "rate_limited",
                axis = "electrum_bucket",
                "global Electrum token bucket exhausted"
            );
            Err(AppError::BackendThrottled)
        }
    }

    /// Dedicated Electrum bucket for the chain watcher (P4). Separate
    /// budget from `check_electrum` so a user-callback storm cannot
    /// starve the watcher and vice-versa. Returns `Err(RateLimited)` when
    /// the bucket is exhausted; the watcher uses this as a signal to
    /// defer remaining work to the next tick.
    pub async fn check_electrum_watcher(&self) -> Result<(), AppError> {
        let mut bucket = self.watcher_electrum_bucket.lock().await;
        if bucket.try_consume() {
            Ok(())
        } else {
            tracing::debug!(
                event = "rate_limited",
                axis = "electrum_bucket_watcher",
                "watcher Electrum bucket exhausted"
            );
            Err(AppError::BackendThrottled)
        }
    }

    // --- Internal ---

    /// In-memory atomic check-and-record for the hot per-IP-style axes.
    /// DashMap's per-shard mutex serializes concurrent callers on the same
    /// bucket key, so two requests can't both pass under the limit and
    /// then both increment past it (the race that affected the old
    /// write-then-count path).
    fn inmem_sliding_check(
        &self,
        bucket: &str,
        limit: u32,
        window_secs: u32,
        on_limit: AppError,
    ) -> Result<(), AppError> {
        if limit == 0 {
            return Ok(());
        }
        let window = Duration::from_secs(window_secs as u64);
        let outcome = self.inmem.check_and_record(bucket, limit, window);
        match outcome {
            InmemOutcome::Allowed => Ok(()),
            InmemOutcome::Limited(count) => {
                tracing::warn!(
                    event = "rate_limited",
                    bucket = bucket,
                    count = count,
                    limit = limit,
                    window_secs = window_secs,
                    "in-memory sliding-window limit exceeded"
                );
                Err(on_limit)
            }
        }
    }

    /// Atomic Postgres sliding-window check, used for axes where
    /// cross-replica consistency matters (per-pubkey, per-nym Lightning).
    /// A `pg_advisory_xact_lock` keyed on the bucket-string hash
    /// serializes concurrent transactions on the same bucket: only one
    /// caller can be inside the INSERT-then-COUNT for a given bucket at
    /// a time, killing the write-then-count race.
    async fn atomic_sliding_window_check(
        &self,
        bucket: &str,
        limit: u32,
        window_secs: u32,
        on_limit: AppError,
    ) -> Result<(), AppError> {
        if limit == 0 {
            return Ok(());
        }
        let count = db::record_and_count_rate_limit_atomic(
            &self.pool,
            bucket,
            window_secs,
        )
        .await?;
        if count as u32 > limit {
            tracing::warn!(
                event = "rate_limited",
                bucket = bucket,
                count = count,
                limit = limit,
                window_secs = window_secs,
                "atomic sliding-window limit exceeded"
            );
            return Err(on_limit);
        }
        Ok(())
    }

    /// Atomic Postgres distinct-nyms check. Same atomicity story as
    /// `atomic_sliding_window_check` — the advisory lock serializes
    /// concurrent transactions on the same `source_key`.
    async fn distinct_nyms_check(
        &self,
        source_key: &str,
        nym: &str,
        limit: u32,
        window_secs: u32,
        on_limit: AppError,
    ) -> Result<(), AppError> {
        if limit == 0 {
            return Ok(());
        }
        let count = db::record_and_count_distinct_nyms_atomic(
            &self.pool,
            source_key,
            nym,
            window_secs,
        )
        .await?;
        if count as u32 > limit {
            tracing::warn!(
                event = "rate_limited",
                axis = "distinct_nyms",
                source_key = source_key,
                count = count,
                limit = limit,
                window_secs = window_secs,
                "distinct-nyms limit exceeded"
            );
            return Err(on_limit);
        }
        Ok(())
    }
}

// --- In-memory sliding-window limiter ---

#[derive(Debug)]
enum InmemOutcome {
    Allowed,
    /// Limit hit; carries the current count for logging.
    Limited(usize),
}

#[derive(Default)]
struct InMemorySliding {
    map: DashMap<String, VecDeque<Instant>>,
}

impl InMemorySliding {
    fn check_and_record(&self, key: &str, limit: u32, window: Duration) -> InmemOutcome {
        let mut entry = self
            .map
            .entry(key.to_string())
            .or_insert_with(VecDeque::new);
        let now = Instant::now();
        let cutoff = now.checked_sub(window).unwrap_or(now);
        // Drop expired timestamps. Deque is FIFO so once we hit one inside
        // the window we know everything after is also inside.
        while let Some(front) = entry.front() {
            if *front < cutoff {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() as u32 >= limit {
            return InmemOutcome::Limited(entry.len());
        }
        entry.push_back(now);
        InmemOutcome::Allowed
    }

    /// Drop entries whose latest timestamp is older than `max_age`.
    /// Returns the number of entries removed.
    fn sweep_idle(&self, max_age: Duration) -> usize {
        let cutoff = Instant::now().checked_sub(max_age).unwrap_or_else(Instant::now);
        let before = self.map.len();
        self.map.retain(|_, deque| {
            // Retain if the latest seen timestamp is recent enough.
            deque
                .back()
                .map(|last| *last >= cutoff)
                .unwrap_or(false)
        });
        before.saturating_sub(self.map.len())
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

    // --- InMemorySliding tests ---

    #[test]
    fn inmem_allows_under_limit_then_blocks() {
        let s = InMemorySliding::default();
        let win = Duration::from_secs(60);
        for _ in 0..3 {
            assert!(matches!(
                s.check_and_record("k", 3, win),
                InmemOutcome::Allowed
            ));
        }
        assert!(matches!(
            s.check_and_record("k", 3, win),
            InmemOutcome::Limited(_)
        ));
    }

    #[test]
    fn inmem_separate_keys_dont_share_budget() {
        let s = InMemorySliding::default();
        let win = Duration::from_secs(60);
        for _ in 0..3 {
            assert!(matches!(
                s.check_and_record("a", 3, win),
                InmemOutcome::Allowed
            ));
        }
        // "b" still has full budget — keys are isolated.
        assert!(matches!(
            s.check_and_record("b", 3, win),
            InmemOutcome::Allowed
        ));
    }

    #[test]
    fn inmem_window_expiry_releases_budget() {
        let s = InMemorySliding::default();
        // Insert a stale timestamp directly to simulate window expiry.
        let key = "k".to_string();
        s.map.insert(key.clone(), {
            let mut d = VecDeque::new();
            d.push_back(Instant::now() - Duration::from_secs(120));
            d
        });
        // Window=60s; the stored ts is 120s old → should be pruned.
        assert!(matches!(
            s.check_and_record(&key, 1, Duration::from_secs(60)),
            InmemOutcome::Allowed
        ));
    }

    #[test]
    fn inmem_concurrent_same_key_caps_at_limit() {
        // The atomicity property: 100 concurrent threads hitting the same
        // bucket with limit=10 must produce exactly 10 Allowed outcomes.
        // The old write-then-count Postgres path was vulnerable here;
        // DashMap's per-shard mutex makes the in-memory path safe.
        use std::sync::Arc;
        use std::thread;

        let s = Arc::new(InMemorySliding::default());
        let win = Duration::from_secs(60);
        let limit: u32 = 10;
        let n_threads = 100;

        let handles: Vec<_> = (0..n_threads)
            .map(|_| {
                let s = Arc::clone(&s);
                thread::spawn(move || match s.check_and_record("hot", limit, win) {
                    InmemOutcome::Allowed => 1u32,
                    InmemOutcome::Limited(_) => 0,
                })
            })
            .collect();
        let allowed: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(allowed, limit);
    }

    #[test]
    fn inmem_sweep_drops_idle_entries() {
        let s = InMemorySliding::default();
        // Insert one fresh and one stale entry.
        s.map.insert("fresh".into(), {
            let mut d = VecDeque::new();
            d.push_back(Instant::now());
            d
        });
        s.map.insert("stale".into(), {
            let mut d = VecDeque::new();
            d.push_back(Instant::now() - Duration::from_secs(7200));
            d
        });
        let evicted = s.sweep_idle(Duration::from_secs(3600));
        assert_eq!(evicted, 1);
        assert!(s.map.contains_key("fresh"));
        assert!(!s.map.contains_key("stale"));
    }
}

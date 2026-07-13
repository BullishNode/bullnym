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
use tokio_util::sync::CancellationToken;

use crate::config::RateLimitConfig;
use crate::db;
use crate::error::AppError;
use crate::ip_whitelist::source_key;

pub struct RateLimiter {
    pool: PgPool,
    cfg: RateLimitConfig,
    /// User-facing Electrum bucket. Drained by `/lnurlp/callback` only.
    electrum_bucket: Arc<AsyncMutex<TokenBucket>>,
    /// Dedicated bucket for the chain watcher. Separate so a callback
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
    // Asymmetric limit by IP family: IPv4 sources get a looser cap because
    // a single /32 is often shared by many real users (CGNAT, office NAT,
    // family WiFi). IPv6 /56 sources get a tighter cap because /56 is the
    // canonical ISP-customer block.
    pub async fn check_distinct_nyms_per_ip(&self, ip: IpAddr, nym: &str) -> Result<(), AppError> {
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

    // --- Registration gates ---

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

    // --- Metadata + lookup gates ---

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

    /// Per-source rate-limit on `/webhook/boltz`. Webhook-bombing from one
    /// source is bounded even when the URL secret is valid. Real Boltz
    /// traffic is well under 10/min/IP for a healthy swap.
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

    /// Per-source Lightning ops cap. Covers both explicit
    /// `network=lightning` callbacks and Liquid-to-Lightning soft fallbacks.
    /// Loose by design: Lightning is the default rail and doesn't leak
    /// Liquid addresses; the cap exists only to bound per-source Boltz API
    /// spend.
    pub async fn check_lightning_per_source(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = format!("lightning:{}", source_key(ip));
        self.inmem_sliding_check(
            &bucket,
            self.cfg.lightning_per_source_limit,
            self.cfg.lightning_per_source_window_secs,
            AppError::RateLimitedSender,
        )
    }

    /// Per-source rate-limit on `GET /<nym>` donation-page HTML renders.
    /// Public, browser-facing, no auth — bounds volumetric scraping. Uses
    /// the `donation_html:` bucket prefix to keep its keyspace separate
    /// from the Liquid-callback `ip:` and metadata `meta:ip:` buckets.
    pub async fn check_donation_html_per_source(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = format!("donation_html:{}", source_key(ip));
        self.inmem_sliding_check(
            &bucket,
            self.cfg.donation_html_rate_limit,
            self.cfg.donation_html_rate_window_secs,
            AppError::RateLimitedSender,
        )
    }

    /// Per-source rate-limit on `GET /<nym>/manifest.webmanifest`.
    /// Separate from donation HTML so a browser's manifest fetch doesn't
    /// spend the page-render budget for the same user.
    pub async fn check_donation_manifest_per_source(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = format!("donation_manifest:{}", source_key(ip));
        self.inmem_sliding_check(
            &bucket,
            self.cfg.donation_manifest_rate_limit,
            self.cfg.donation_manifest_rate_window_secs,
            AppError::RateLimitedSender,
        )
    }

    /// Per-npub rate-limit on `POST /donation-page/image`. A real user
    /// uploads avatar + OG once per session; six per hour is generous.
    /// Atomic Postgres path (cross-replica consistent) since uploads are
    /// low-volume and signature-verified.
    pub async fn check_donation_image_uploads_per_npub(
        &self,
        npub_hex: &str,
    ) -> Result<(), AppError> {
        let bucket = format!("donation_image_npub:{npub_hex}");
        self.atomic_sliding_window_check(
            &bucket,
            self.cfg.donation_image_uploads_per_npub_per_hour,
            3600,
            AppError::RateLimitedSender,
        )
        .await
    }

    /// Per-source rate-limit on image uploads. In-memory bucket; hot path
    /// before the more expensive npub check.
    pub async fn check_donation_image_uploads_per_source(
        &self,
        ip: IpAddr,
    ) -> Result<(), AppError> {
        let bucket = format!("donation_image_src:{}", source_key(ip));
        self.inmem_sliding_check(
            &bucket,
            self.cfg.donation_image_uploads_per_source_per_min,
            60,
            AppError::RateLimitedSender,
        )
    }

    /// Per-source rate-limit on anonymous `POST /<nym>/invoice`.
    /// Each success path creates a real invoice + Boltz reverse-swap; page
    /// refreshes hit the existing invoice URL and don't re-fire.
    pub async fn check_invoice_create_per_source(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = format!("invoice_create:{}", source_key(ip));
        self.inmem_sliding_check(
            &bucket,
            self.cfg.invoice_create_per_source_per_min,
            60,
            AppError::RateLimitedSender,
        )
    }

    /// Per-npub rate-limit on signed `POST /api/v1/<nym>/invoices`.
    /// Bounds wallet-origin invoice creation per identity, so
    /// a stolen credential cannot mass-create invoices even within the
    /// per-IP gate. Bucket key includes the lowercased npub; same
    /// keyspace prefix discipline as the metadata gates so AB/BA
    /// deadlocks with DB advisory locks are impossible.
    pub async fn check_invoice_create_per_npub(&self, npub_hex: &str) -> Result<(), AppError> {
        let bucket = format!("invoice_create_npub:{}", npub_hex.to_lowercase());
        self.inmem_sliding_check(
            &bucket,
            self.cfg.invoice_create_per_npub_per_hour,
            3600,
            AppError::RateLimitedSender,
        )
    }

    /// Per-source rate-limit on public invoice status polling.
    pub async fn check_invoice_status_per_source(&self, ip: IpAddr) -> Result<(), AppError> {
        let bucket = format!("invoice_status:{}", source_key(ip));
        self.inmem_sliding_check(
            &bucket,
            self.cfg.invoice_status_per_source_per_min,
            60,
            AppError::RateLimitedSender,
        )
    }

    /// Distinct npubs queried per IP via `GET /register/lookup`. Same shape
    /// as the metadata distinct-nyms cap but for the npub-side enumeration
    /// vector. Uses the `lookup:ip:` source-key prefix.
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

    /// Dedicated Electrum bucket for the chain watcher. Separate
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

    /// Wait for watcher-only capacity while one atomic chain obligation is in
    /// progress. Returning the partially fetched obligation to the outer loop
    /// would restart it from zero and can permanently pin every later row when
    /// its bounded work exceeds one bucketful. No database lock is held while
    /// this waits, and shutdown remains prompt.
    pub async fn acquire_electrum_watcher(&self, cancel: &CancellationToken) -> bool {
        loop {
            if cancel.is_cancelled() {
                return false;
            }
            let retry_after = {
                let mut bucket = self.watcher_electrum_bucket.lock().await;
                if cancel.is_cancelled() {
                    return false;
                }
                if bucket.try_consume() {
                    return true;
                }
                bucket.retry_after()
            };
            tokio::select! {
                _ = cancel.cancelled() => return false,
                _ = tokio::time::sleep(retry_after) => {}
            }
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
        let count = db::record_and_count_rate_limit_atomic(&self.pool, bucket, window_secs).await?;
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
        let count =
            db::record_and_count_distinct_nyms_atomic(&self.pool, source_key, nym, window_secs)
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
        let mut entry = self.map.entry(key.to_string()).or_default();
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
        let cutoff = Instant::now()
            .checked_sub(max_age)
            .unwrap_or_else(Instant::now);
        let before = self.map.len();
        self.map.retain(|_, deque| {
            // Retain if the latest seen timestamp is recent enough.
            deque.back().map(|last| *last >= cutoff).unwrap_or(false)
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

    pub(crate) fn has_available(&mut self) -> bool {
        self.refill();
        self.tokens > 0
    }

    pub(crate) fn retry_after(&self) -> Duration {
        Duration::from_secs(1).saturating_sub(self.last_refill.elapsed())
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
mod tests;

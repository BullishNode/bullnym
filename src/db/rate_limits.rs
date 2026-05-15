use sqlx::PgPool;

// --- Webhook idempotency ---

/// Try to record that a webhook event was processed. Returns `true` if
/// this is the first time we've seen `event_id` (caller should do the
/// work) or `false` if it was already processed (caller short-circuits
/// to 200 OK without acting).
pub async fn try_record_webhook_event(pool: &PgPool, event_id: &str) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO processed_webhook_events (event_id) VALUES ($1) \
         ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(event_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

// --- Active-user ceiling ---

/// Count rows with `is_active = TRUE` for the registration ceiling check.
/// Single-shot atomic query; used on the cheap path before signature verify.
pub async fn count_active_users(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

// --- Rate limit events ---

// NOTE: the non-atomic write-then-count pair (`record_rate_limit_event` +
// `count_rate_limit_events`) was removed. All sliding-window axes now
// go through either `record_and_count_rate_limit_atomic` (Postgres path
// with advisory lock) or the in-memory limiter in `rate_limit::InMemorySliding`.

/// Atomic INSERT-then-COUNT for sliding-window rate limits, serialized on
/// the bucket key via `pg_advisory_xact_lock`. Only one transaction with
/// the same bucket can be inside this critical section at a time, so two
/// concurrent callers can't both pass under the limit and then both
/// commit past it. Returns the post-insert count.
///
/// Advisory-lock keyspace: keys are `hashtext(<bucket>)` where bucket is
/// `register:ip:...`, `meta:ip:...`, `nym:...`, etc. The registration flow
/// (`register_user_atomic`) keys on `hashtext(<npub-hex>)`. Bucket strings
/// and raw npub hex live in disjoint string spaces, and rate-limit gates
/// run before `register_user_atomic` is called (never inside its tx), so
/// no AB/BA deadlock is possible.
pub async fn record_and_count_rate_limit_atomic(
    pool: &PgPool,
    bucket: &str,
    window_secs: u32,
) -> Result<i64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(bucket)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO rate_limit_events (bucket) VALUES ($1)")
        .bind(bucket)
        .execute(&mut *tx)
        .await?;
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM rate_limit_events \
         WHERE bucket = $1 AND created_at > NOW() - ($2 || ' seconds')::interval",
    )
    .bind(bucket)
    .bind(window_secs as i32)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.0)
}

// =====================================================================
// Distinct-nym rate-limit helpers
// =====================================================================
//
// NOTE: the non-atomic write-then-count pair was removed. All
// distinct-nyms axes now go through the atomic helper below.

/// Atomic INSERT-then-COUNT-DISTINCT for the distinct-nyms axes,
/// serialized on `source_key` via `pg_advisory_xact_lock`. Same atomicity
/// story as `record_and_count_rate_limit_atomic` — kills the race where
/// two concurrent callers both INSERT and then both COUNT under the limit
/// before either commit lands. Returns the post-insert distinct count.
pub async fn record_and_count_distinct_nyms_atomic(
    pool: &PgPool,
    source_key: &str,
    nym: &str,
    window_secs: u32,
) -> Result<i64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(source_key)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO nym_access_events (source_key, nym) VALUES ($1, $2)")
        .bind(source_key)
        .bind(nym)
        .execute(&mut *tx)
        .await?;
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT nym) FROM nym_access_events \
         WHERE source_key = $1 \
         AND created_at > NOW() - ($2 || ' seconds')::interval",
    )
    .bind(source_key)
    .bind(window_secs as i32)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.0)
}

use sqlx::PgPool;

// =====================================================================
// Chain watcher helpers (added 2026-04-27)
// =====================================================================

pub struct ActiveNymForWatcher {
    pub nym: String,
    pub ct_descriptor: String,
    pub next_addr_idx: i32,
}

pub async fn list_active_nyms_for_watcher(
    pool: &PgPool,
) -> Result<Vec<ActiveNymForWatcher>, sqlx::Error> {
    let rows: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT nym, ct_descriptor, next_addr_idx FROM users WHERE is_active = TRUE",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(nym, ct_descriptor, next_addr_idx)| ActiveNymForWatcher {
            nym,
            ct_descriptor,
            next_addr_idx,
        })
        .collect())
}

/// Watcher's "active" set: users whose `last_callback_at` is within the
/// last `active_window_secs`. This is the hot list scanned every fast
/// tick. Bounded in size by real callback traffic, not by the size of
/// the `users` table.
pub async fn list_recently_active_nyms_for_watcher(
    pool: &PgPool,
    active_window_secs: u32,
) -> Result<Vec<ActiveNymForWatcher>, sqlx::Error> {
    let rows: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT nym, ct_descriptor, next_addr_idx \
         FROM users \
         WHERE is_active = TRUE \
           AND last_callback_at > NOW() - ($1 || ' seconds')::interval",
    )
    .bind(active_window_secs as i32)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(nym, ct_descriptor, next_addr_idx)| ActiveNymForWatcher {
            nym,
            ct_descriptor,
            next_addr_idx,
        })
        .collect())
}

/// Mark that a user was just hit by `/lnurlp/callback`. Drives the
/// watcher's activity prioritization. Best-effort: an error here is
/// logged but not propagated — failing to update activity should never
/// fail a successful payment-address lookup.
pub async fn touch_user_callback(pool: &PgPool, nym: &str) {
    if let Err(e) =
        sqlx::query("UPDATE users SET last_callback_at = NOW() WHERE nym = $1 AND is_active = TRUE")
            .bind(nym)
            .execute(pool)
            .await
    {
        tracing::warn!("touch_user_callback: nym={nym} failed: {e}");
    }
}

/// Advance `users.next_addr_idx` past `observed_idx`, but only if it hasn't
/// already advanced beyond it. Idempotent under concurrent observations:
/// the `next_addr_idx <= observed_idx` guard ensures this update is a no-op
/// when the row has already moved on (e.g. due to a request handler
/// allocation racing with the watcher).
pub async fn advance_next_addr_idx(
    pool: &PgPool,
    nym: &str,
    observed_idx: u32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users SET next_addr_idx = $2 \
         WHERE nym = $1 AND is_active = TRUE AND next_addr_idx <= $3",
    )
    .bind(nym)
    .bind((observed_idx + 1) as i32)
    .bind(observed_idx as i32)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark every still-pending reservation that targets `addr_index` for `nym`
/// as fulfilled. Called by the chain watcher when a payment is observed at
/// `derive(descriptor, addr_index)` — under last-unused mode many concurrent
/// senders may share a single addr_index, so a single observed payment can
/// flip multiple rows. Returns the number of rows updated for diagnostics.
pub async fn mark_reservations_fulfilled_at_idx(
    pool: &PgPool,
    nym: &str,
    addr_index: u32,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE outpoint_addresses \
            SET fulfilled = TRUE, fulfilled_at = NOW() \
          WHERE nym = $1 AND addr_index = $2 AND fulfilled = FALSE",
    )
    .bind(nym)
    .bind(addr_index as i32)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

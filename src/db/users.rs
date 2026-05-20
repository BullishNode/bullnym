use sqlx::PgPool;
use uuid::Uuid;

// --- User ---

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub nym: String,
    pub npub: String,
    pub ct_descriptor: String,
    pub next_addr_idx: i32,
    pub is_active: bool,
}

pub async fn get_user_by_nym(pool: &PgPool, nym: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE nym = $1",
    )
    .bind(nym)
    .fetch_optional(pool)
    .await
}

pub async fn get_active_user_by_nym(pool: &PgPool, nym: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE nym = $1 AND is_active = TRUE",
    )
    .bind(nym)
    .fetch_optional(pool)
    .await
}

pub async fn get_user_by_npub(pool: &PgPool, npub: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = TRUE",
    )
    .bind(npub)
    .fetch_optional(pool)
    .await
}

pub async fn get_inactive_user_by_npub(
    pool: &PgPool,
    npub: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = FALSE \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(npub)
    .fetch_optional(pool)
    .await
}

/// Mark a user row as having seen real activity (a Lightning swap or a
/// Liquid LUD-22 reservation). Idempotent: the `WHERE has_been_used = FALSE`
/// guard makes re-marking a no-op. Caller passes the executor (a tx
/// borrow when this update belongs to a larger atomic flow, or the pool
/// directly otherwise).
pub async fn mark_user_used<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    nym: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET has_been_used = TRUE WHERE nym = $1 AND has_been_used = FALSE")
        .bind(nym)
        .execute(executor)
        .await?;
    Ok(())
}

/// Total nyms ever registered under this npub (active + inactive). Used
/// to enforce `max_lifetime_nyms_per_npub` so one key can't squat the
/// namespace via dereg/rereg cycles.
pub async fn count_lifetime_nyms_by_npub(pool: &PgPool, npub: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE npub = $1")
        .bind(npub)
        .fetch_one(pool)
        .await
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreviousNym {
    pub nym: String,
    pub created_at: String,
}

/// One round trip: `(active_nym, previous_nyms_most_recent_first, used_count)`.
pub async fn lookup_status_by_npub(
    pool: &PgPool,
    npub: &str,
) -> Result<(Option<String>, Vec<PreviousNym>, i64), sqlx::Error> {
    let row: (
        Option<String>,
        Option<sqlx::types::Json<Vec<PreviousNym>>>,
        Option<i64>,
    ) = sqlx::query_as(
        "SELECT \
                (SELECT nym FROM users WHERE npub = $1 AND is_active = TRUE ORDER BY created_at DESC LIMIT 1) \
                    AS active_nym, \
                (SELECT json_agg(json_build_object('nym', nym, 'created_at', created_at) \
                                 ORDER BY created_at DESC) \
                   FROM users WHERE npub = $1 AND is_active = FALSE) \
                    AS previous_nyms, \
                (SELECT COUNT(*) FROM users WHERE npub = $1) AS used",
    )
    .bind(npub)
    .fetch_one(pool)
    .await?;
    Ok((
        row.0,
        row.1.map(|j| j.0).unwrap_or_default(),
        row.2.unwrap_or(0),
    ))
}

/// Outcome of `register_user_atomic`. Mirrors the three branches of the
/// register handler so the caller can map each to the right `AppError`.
pub enum RegisterOutcome {
    /// New user row inserted.
    Created(User),
    /// Existing inactive row reactivated (caller asked for the same nym they
    /// previously held).
    Reactivated(User),
    /// This npub already has an active row under `nym`. Caller maps to
    /// `AppError::KeyAlreadyRegistered`.
    KeyAlreadyRegistered { nym: String },
    /// Inserting would push past the lifetime cap. Caller maps to
    /// `AppError::NymQuotaExceeded`. Carries `used` so the error envelope
    /// can ship the same `quota` object the mobile sees on lookup.
    QuotaExceeded { used: i64, cap: i64 },
}

/// Atomic register flow. Serializes concurrent registers from the same npub
/// via `pg_advisory_xact_lock(hashtext(npub))` so the cap check, the
/// active-row check, and the INSERT/UPDATE all observe a consistent view.
///
/// Advisory-lock keyspace audit (Kumulynja PLAN-3): the rate-limit code in
/// `record_and_count_rate_limit_atomic` and `record_and_count_distinct_nyms_atomic`
/// also uses `pg_advisory_xact_lock`, but keys on `hashtext(<bucket-string>)`
/// where the bucket is `register:ip:...`, `meta:ip:...`, etc. — never `npub`
/// raw. Bucket strings and raw npub hex live in disjoint string spaces, so
/// hashtext collisions are vanishingly improbable, and no single tx ever
/// holds both a registration lock and a rate-limit lock (the rate-limit gates
/// run before this function is called).
pub async fn register_user_atomic(
    pool: &PgPool,
    npub: &str,
    nym: &str,
    ct_descriptor: &str,
    cap: i64,
) -> Result<RegisterOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(npub)
        .execute(&mut *tx)
        .await?;

    // Re-check inside the lock — another tx may have inserted the active row
    // while we were waiting.
    let active = sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = TRUE",
    )
    .bind(npub)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(active) = active {
        tx.rollback().await?;
        return Ok(RegisterOutcome::KeyAlreadyRegistered { nym: active.nym });
    }

    let prior_inactive = sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = FALSE \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(npub)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(prior) = prior_inactive.as_ref().filter(|u| u.nym == nym) {
        // Reactivate same nym. Keep next_addr_idx monotonic: historical
        // invoices/reservations may still hold addresses from this descriptor,
        // and rewinding can collide with the global single-use address index.
        let user = sqlx::query_as::<_, User>(
            "UPDATE users SET ct_descriptor = $3, is_active = TRUE \
             WHERE npub = $1 AND nym = $2 AND is_active = FALSE \
             RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
        )
        .bind(npub)
        .bind(&prior.nym)
        .bind(ct_descriptor)
        .fetch_one(&mut *tx)
        .await?;
        // Descriptor may have changed, so cached outpoint→addr_index mappings
        // can point into the wrong keyspace. Drop them.
        sqlx::query("DELETE FROM outpoint_addresses WHERE nym = $1")
            .bind(&user.nym)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(RegisterOutcome::Reactivated(user));
    }

    // Cap check inside the lock.
    let used: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE npub = $1")
        .bind(npub)
        .fetch_one(&mut *tx)
        .await?;
    if used >= cap {
        tx.rollback().await?;
        return Ok(RegisterOutcome::QuotaExceeded { used, cap });
    }

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (nym, npub, ct_descriptor) VALUES ($1, $2, $3) \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
    )
    .bind(nym)
    .bind(npub)
    .bind(ct_descriptor)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(RegisterOutcome::Created(user))
}

pub async fn create_user(
    pool: &PgPool,
    nym: &str,
    npub: &str,
    ct_descriptor: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "INSERT INTO users (nym, npub, ct_descriptor) VALUES ($1, $2, $3) \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
    )
    .bind(nym)
    .bind(npub)
    .bind(ct_descriptor)
    .fetch_one(pool)
    .await
}

pub async fn update_user_descriptor(
    pool: &PgPool,
    npub: &str,
    ct_descriptor: &str,
) -> Result<Option<User>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let user_opt = sqlx::query_as::<_, User>(
        "UPDATE users SET ct_descriptor = $2 \
         WHERE npub = $1 AND is_active = TRUE \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
    )
    .bind(npub)
    .bind(ct_descriptor)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(user) = &user_opt {
        sqlx::query("DELETE FROM outpoint_addresses WHERE nym = $1")
            .bind(&user.nym)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(user_opt)
}

pub async fn deactivate_user(pool: &PgPool, npub: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "UPDATE users SET is_active = FALSE \
         WHERE npub = $1 AND is_active = TRUE \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
    )
    .bind(npub)
    .fetch_optional(pool)
    .await
}

/// Outcome of a purge attempt.
pub enum PurgeOutcome {
    /// Purge applied. Returns the (now-deactivated) user row.
    Purged(User),
    /// No active user exists for this npub.
    NotFound,
    /// Refused because in-flight swaps still hold live claim secrets.
    InFlightSwaps(usize),
}

/// Hard-delete every swap_record and outpoint_address tied to this npub's
/// active nym, then deactivate the user row while keeping `nym` and `npub`
/// so the address stays reserved and the original owner can re-register.
///
/// Refuses if any swap is non-terminal: those rows hold the only copy of
/// `claim_key_hex` / `preimage_hex` needed to redeem a Boltz lockup.
pub async fn purge_user(pool: &PgPool, npub: &str) -> Result<PurgeOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let user_opt = sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = TRUE FOR UPDATE",
    )
    .bind(npub)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(user) = user_opt else {
        tx.rollback().await?;
        return Ok(PurgeOutcome::NotFound);
    };

    let in_flight: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM swap_records \
         WHERE nym = $1 AND status NOT IN ('claimed', 'expired')",
    )
    .bind(&user.nym)
    .fetch_one(&mut *tx)
    .await?;
    if in_flight > 0 {
        tx.rollback().await?;
        return Ok(PurgeOutcome::InFlightSwaps(in_flight as usize));
    }

    sqlx::query("DELETE FROM swap_records WHERE nym = $1")
        .bind(&user.nym)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM outpoint_addresses WHERE nym = $1")
        .bind(&user.nym)
        .execute(&mut *tx)
        .await?;

    // Auto-archive any donation page tied to this nym so the public URL
    // stops accepting donations after the user purges. The page row stays
    // (so old social-media links resolve cleanly to a "this donation
    // page has been deleted" template) — same shape as user-initiated
    // archive via DELETE /donation-page.
    sqlx::query(
        "UPDATE donation_pages SET archived_at = now(), updated_at = now() \
         WHERE nym = $1 AND archived_at IS NULL",
    )
    .bind(&user.nym)
    .execute(&mut *tx)
    .await?;

    // Purge deactivates the user rather than deleting it. Existing
    // invoices remain queryable by id and will expire through GC.

    let purged = sqlx::query_as::<_, User>(
        "UPDATE users SET is_active = FALSE, ct_descriptor = '' \
         WHERE id = $1 \
         RETURNING id, nym, npub, ct_descriptor, next_addr_idx, is_active",
    )
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(PurgeOutcome::Purged(purged))
}

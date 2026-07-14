use sqlx::PgPool;
use uuid::Uuid;

// --- User ---

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub nym: String,
    pub npub: String,
    /// Public NIP-05 key, or `None` when the nym never opted into NIP-05.
    /// Nullable: the server no longer falls back to publishing the auth key
    /// (`npub`) as a NIP-05 identity (see migration 033 / ISS-S-01).
    pub verification_npub: Option<String>,
    pub ct_descriptor: String,
    pub next_addr_idx: i32,
    pub is_active: bool,
}

pub async fn get_user_by_nym<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    nym: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT users.id, users.nym, users.npub, users.verification_npub, \
                users.ct_descriptor, users.next_addr_idx, users.is_active \
         FROM users \
         JOIN public_names \
           ON public_names.name = users.nym \
          AND public_names.owner_npub = users.npub \
          AND public_names.kind = 'nym' \
         WHERE users.nym = $1",
    )
    .bind(nym)
    .fetch_optional(executor)
    .await
}

pub async fn get_active_user_by_nym(pool: &PgPool, nym: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT users.id, users.nym, users.npub, users.verification_npub, \
                users.ct_descriptor, users.next_addr_idx, users.is_active \
         FROM users \
         JOIN public_names \
           ON public_names.name = users.nym \
          AND public_names.owner_npub = users.npub \
          AND public_names.kind = 'nym' \
         WHERE users.nym = $1 AND users.is_active = TRUE",
    )
    .bind(nym)
    .fetch_optional(pool)
    .await
}

pub async fn get_user_by_npub(pool: &PgPool, npub: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT users.id, users.nym, users.npub, users.verification_npub, \
                users.ct_descriptor, users.next_addr_idx, users.is_active \
         FROM users \
         JOIN public_names \
           ON public_names.name = users.nym \
          AND public_names.owner_npub = users.npub \
          AND public_names.kind = 'nym' \
          AND public_names.canonical \
         WHERE users.npub = $1 AND users.is_active = TRUE",
    )
    .bind(npub)
    .fetch_optional(pool)
    .await
}

/// Resolve permanent nym ownership without coupling it to Lightning Address
/// availability. Page/POS management and routing remain available while the
/// owner's LA row is offline.
pub async fn get_user_by_npub_any(pool: &PgPool, npub: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT users.id, users.nym, users.npub, users.verification_npub, \
                users.ct_descriptor, users.next_addr_idx, users.is_active \
         FROM users \
         JOIN public_names \
           ON public_names.name = users.nym \
          AND public_names.owner_npub = users.npub \
          AND public_names.kind = 'nym' \
          AND public_names.canonical \
         WHERE users.npub = $1",
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
        "SELECT users.id, users.nym, users.npub, users.verification_npub, \
                users.ct_descriptor, users.next_addr_idx, users.is_active \
         FROM users \
         JOIN public_names \
           ON public_names.name = users.nym \
          AND public_names.owner_npub = users.npub \
          AND public_names.kind = 'nym' \
          AND public_names.canonical \
         WHERE users.npub = $1 AND users.is_active = FALSE",
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

/// Canonical permanent nym claims for this npub. Historical tombstones remain
/// reserved, but do not consume the compatibility API's current-name count.
pub async fn count_lifetime_nyms_by_npub(pool: &PgPool, npub: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM public_names \
         WHERE owner_npub = $1 AND kind = 'nym' AND canonical",
    )
    .bind(npub)
    .fetch_one(pool)
    .await
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreviousNym {
    pub nym: String,
    pub created_at: String,
}

/// One round trip: `(online_nym, compatibility_offline_nyms, used_count)`.
/// `previous_nyms` remains populated for an offline permanent nym so current
/// clients can still discover and reactivate it; it no longer implies release
/// or eligibility to choose another name.
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
                (SELECT public_names.name \
                   FROM public_names \
                   JOIN users \
                     ON users.npub = public_names.owner_npub \
                    AND users.nym = public_names.name \
                  WHERE public_names.owner_npub = $1 \
                    AND public_names.kind = 'nym' \
                    AND public_names.canonical \
                    AND users.is_active = TRUE) \
                    AS active_nym, \
                (SELECT json_agg(json_build_object( \
                                     'nym', public_names.name, \
                                     'created_at', public_names.claimed_at \
                                 ) ORDER BY public_names.claimed_at DESC) \
                   FROM public_names \
                   LEFT JOIN users \
                     ON users.npub = public_names.owner_npub \
                    AND users.nym = public_names.name \
                  WHERE public_names.owner_npub = $1 \
                    AND public_names.kind = 'nym' \
                    AND public_names.canonical \
                    AND COALESCE(users.is_active, FALSE) = FALSE) \
                    AS previous_nyms, \
                (SELECT COUNT(*) FROM public_names \
                  WHERE owner_npub = $1 AND kind = 'nym' AND canonical) AS used",
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

/// Outcome of one permanent-nym registration transaction.
pub enum RegisterOutcome {
    /// New user row inserted.
    Created(User),
    /// Existing offline Lightning Address brought online under the same nym.
    Reactivated(User),
    /// Exact online retry. No descriptor, key, cursor, timestamp, or row was
    /// mutated.
    Idempotent(User),
    /// This npub permanently owns a different nym.
    NymAlreadyAssigned { nym: String },
    /// The requested string is permanently reserved as either kind.
    NameTaken,
    /// Activating this registration would exceed the configured global active
    /// user ceiling. The count and activation are serialized across npubs.
    ActiveUserCapacityReached { active: i64, cap: i64 },
}

/// Atomic register flow. Serializes concurrent requests from the same npub so
/// ownership lookup, availability transition, and first claim share one view.
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
    verification_npub: Option<&str>,
    _legacy_cap: i64,
    max_active_users: i64,
) -> Result<RegisterOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Registration always takes the global capacity lock before the per-npub
    // lock. That ordering serializes active-count reads with every activation
    // or insert, so distinct npubs cannot race past the configured ceiling.
    if max_active_users > 0 {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('bullnym:active-user-cap')::bigint)")
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(npub)
        .execute(&mut *tx)
        .await?;

    let permanent_nym: Option<String> = sqlx::query_scalar(
        "SELECT name FROM public_names \
         WHERE owner_npub = $1 AND kind = 'nym' AND canonical",
    )
    .bind(npub)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(permanent_nym) = permanent_nym {
        if permanent_nym != nym {
            tx.rollback().await?;
            return Ok(RegisterOutcome::NymAlreadyAssigned { nym: permanent_nym });
        }

        let existing = sqlx::query_as::<_, User>(
            "SELECT id, nym, npub, verification_npub, \
                    ct_descriptor, next_addr_idx, is_active \
             FROM users WHERE npub = $1 AND nym = $2",
        )
        .bind(npub)
        .bind(nym)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(existing) = existing {
            if existing.is_active {
                tx.commit().await?;
                return Ok(RegisterOutcome::Idempotent(existing));
            }

            if let Some(outcome) = active_user_capacity_outcome(&mut tx, max_active_users).await? {
                tx.rollback().await?;
                return Ok(outcome);
            }

            // Keep the row identity and cursor stable. An offline wallet may
            // supply a restored descriptor, so only Lightning-specific state
            // is refreshed as availability turns online.
            let user = sqlx::query_as::<_, User>(
                "UPDATE users \
                    SET ct_descriptor = $3, verification_npub = $4, is_active = TRUE \
                  WHERE npub = $1 AND nym = $2 AND is_active = FALSE \
                  RETURNING id, nym, npub, verification_npub, \
                            ct_descriptor, next_addr_idx, is_active",
            )
            .bind(npub)
            .bind(nym)
            .bind(ct_descriptor)
            .bind(verification_npub)
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM outpoint_addresses WHERE nym = $1")
                .bind(&user.nym)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(RegisterOutcome::Reactivated(user));
        }

        // The permanent ownership row intentionally survives exceptional
        // operational-user purges. Recreate only the same owner's same nym.
        if let Some(outcome) = active_user_capacity_outcome(&mut tx, max_active_users).await? {
            tx.rollback().await?;
            return Ok(outcome);
        }
        let user = insert_user(&mut tx, npub, nym, ct_descriptor, verification_npub).await?;
        tx.commit().await?;
        return Ok(RegisterOutcome::Reactivated(user));
    }

    let name_is_reserved: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public_names WHERE name = $1)")
            .bind(nym)
            .fetch_one(&mut *tx)
            .await?;
    if name_is_reserved {
        tx.rollback().await?;
        return Ok(RegisterOutcome::NameTaken);
    }

    if let Some(outcome) = active_user_capacity_outcome(&mut tx, max_active_users).await? {
        tx.rollback().await?;
        return Ok(outcome);
    }

    let claim = sqlx::query(
        "INSERT INTO public_names (name, owner_npub, kind) \
         VALUES ($1, $2, 'nym')",
    )
    .bind(nym)
    .bind(npub)
    .execute(&mut *tx)
    .await;
    if let Err(error) = claim {
        let constraint = database_constraint(&error);
        tx.rollback().await?;
        if matches!(constraint, Some("public_names_shared_namespace_key")) {
            return Ok(RegisterOutcome::NameTaken);
        }
        if matches!(constraint, Some("public_names_owner_kind_lifetime_key")) {
            return Ok(RegisterOutcome::NymAlreadyAssigned { nym: String::new() });
        }
        return Err(error);
    }

    let user = insert_user(&mut tx, npub, nym, ct_descriptor, verification_npub).await?;
    tx.commit().await?;
    Ok(RegisterOutcome::Created(user))
}

fn database_constraint(error: &sqlx::Error) -> Option<&str> {
    match error {
        sqlx::Error::Database(database_error) => database_error.constraint(),
        _ => None,
    }
}

async fn insert_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    npub: &str,
    nym: &str,
    ct_descriptor: &str,
    verification_npub: Option<&str>,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "INSERT INTO users (nym, npub, ct_descriptor, verification_npub) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, nym, npub, verification_npub, \
                   ct_descriptor, next_addr_idx, is_active",
    )
    .bind(nym)
    .bind(npub)
    .bind(ct_descriptor)
    .bind(verification_npub)
    .fetch_one(&mut **tx)
    .await
}

async fn active_user_capacity_outcome(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    max_active_users: i64,
) -> Result<Option<RegisterOutcome>, sqlx::Error> {
    if max_active_users <= 0 {
        return Ok(None);
    }
    let active = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        .fetch_one(&mut **tx)
        .await?;
    if active >= max_active_users {
        return Ok(Some(RegisterOutcome::ActiveUserCapacityReached {
            active,
            cap: max_active_users,
        }));
    }
    Ok(None)
}

pub async fn create_user(
    pool: &PgPool,
    nym: &str,
    npub: &str,
    ct_descriptor: &str,
) -> Result<User, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(npub)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO public_names (name, owner_npub, kind) \
         VALUES ($1, $2, 'nym')",
    )
    .bind(nym)
    .bind(npub)
    .execute(&mut *tx)
    .await?;
    let user = insert_user(&mut tx, npub, nym, ct_descriptor, None).await?;
    tx.commit().await?;
    Ok(user)
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
         RETURNING id, nym, npub, verification_npub, \
                   ct_descriptor, next_addr_idx, is_active",
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
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(npub)
        .execute(&mut *tx)
        .await?;
    let user_opt = sqlx::query_as::<_, User>(
        "UPDATE users SET is_active = FALSE \
         WHERE npub = $1 AND is_active = TRUE \
         RETURNING id, nym, npub, verification_npub, \
                   ct_descriptor, next_addr_idx, is_active",
    )
    .bind(npub)
    .fetch_optional(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(user_opt)
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

/// Hard-delete every reverse/chain swap row and outpoint address tied to this
/// npub's active nym, then deactivate the user row while keeping `nym` and
/// `npub` so the address stays reserved and the original owner can re-register.
/// Migration-050's non-secret allocation journal and migration-044 high-water
/// ledger are deliberately retained.
///
/// Refuses if any swap is non-terminal: those rows hold the only copy of
/// `claim_key_hex` / `preimage_hex` needed to redeem a Boltz lockup.
pub async fn purge_user(pool: &PgPool, npub: &str) -> Result<PurgeOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(npub)
        .execute(&mut *tx)
        .await?;

    let user_opt = sqlx::query_as::<_, User>(
        "SELECT id, nym, npub, verification_npub, \
                ct_descriptor, next_addr_idx, is_active \
         FROM users WHERE npub = $1 AND is_active = TRUE FOR UPDATE",
    )
    .bind(npub)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(user) = user_opt else {
        tx.rollback().await?;
        return Ok(PurgeOutcome::NotFound);
    };

    // Reverse-swap obligations. `claim_stuck` (not in the excluded set) also
    // blocks purge — a stuck claim is still a live obligation.
    let reverse_in_flight: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM swap_records \
         WHERE nym = $1 AND status NOT IN ('claimed', 'expired')",
    )
    .bind(&user.nym)
    .fetch_one(&mut *tx)
    .await?;
    // Chain-swap obligations (issue #67): recovery and accounting depend on
    // retaining the owning merchant record until every chain swap is
    // economically final. Non-final = everything except claimed/refunded/
    // expired/lockup_failed, so claim_stuck, refund_due, and refunding (funded,
    // recoverable, or refund-in-flight) all block purge. The FOR UPDATE on the
    // user row above serializes this against swap creation that resolves the
    // owner through the same row.
    let chain_in_flight: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chain_swap_records \
         WHERE nym = $1 \
           AND status NOT IN ('claimed', 'refunded', 'expired', 'lockup_failed')",
    )
    .bind(&user.nym)
    .fetch_one(&mut *tx)
    .await?;
    let in_flight = reverse_in_flight + chain_in_flight;
    if in_flight > 0 {
        tx.rollback().await?;
        return Ok(PurgeOutcome::InFlightSwaps(in_flight as usize));
    }

    sqlx::query("DELETE FROM swap_records WHERE nym = $1")
        .bind(&user.nym)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM chain_swap_records WHERE nym = $1")
        .bind(&user.nym)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM outpoint_addresses WHERE nym = $1")
        .bind(&user.nym)
        .execute(&mut *tx)
        .await?;

    // Purge deactivates the user rather than deleting it. Existing
    // invoices remain queryable by id and will expire through GC.

    let purged = sqlx::query_as::<_, User>(
        "UPDATE users SET is_active = FALSE, ct_descriptor = '' \
         WHERE id = $1 \
         RETURNING id, nym, npub, verification_npub, \
                   ct_descriptor, next_addr_idx, is_active",
    )
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(PurgeOutcome::Purged(purged))
}

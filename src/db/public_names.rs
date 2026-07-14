use sqlx::{Postgres, Transaction};

/// Result of applying the optional alias field from a Page/POS save.
///
/// An omitted field is a no-op. A present alias is an insert-only lifetime
/// claim: the exact same owner/value is idempotent, while every other mutation
/// is rejected before the surface row is changed.
pub enum AliasClaimOutcome {
    Unchanged,
    Claimed,
    NameTaken,
    AlreadyAssigned { alias: String },
}

pub async fn apply_alias_claim(
    tx: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
    alias: Option<&str>,
) -> Result<AliasClaimOutcome, sqlx::Error> {
    let Some(alias) = alias else {
        return Ok(AliasClaimOutcome::Unchanged);
    };

    if let Some(existing) = sqlx::query_scalar::<_, String>(
        "SELECT name FROM public_names \
         WHERE owner_npub = $1 AND kind = 'alias' AND canonical",
    )
    .bind(owner_npub)
    .fetch_optional(&mut **tx)
    .await?
    {
        return Ok(if existing == alias {
            AliasClaimOutcome::Unchanged
        } else {
            AliasClaimOutcome::AlreadyAssigned { alias: existing }
        });
    }

    let name_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public_names WHERE name = $1)")
            .bind(alias)
            .fetch_one(&mut **tx)
            .await?;
    if name_exists {
        return Ok(AliasClaimOutcome::NameTaken);
    }

    sqlx::query(
        "INSERT INTO public_names (name, owner_npub, kind) \
         VALUES ($1, $2, 'alias')",
    )
    .bind(alias)
    .bind(owner_npub)
    .execute(&mut **tx)
    .await?;
    Ok(AliasClaimOutcome::Claimed)
}

/// Return the owner's canonical permanent alias after a transaction-level
/// uniqueness race. Callers use this only after rolling back the failed
/// transaction so the winning claim is visible and can be returned as typed
/// conflict detail.
pub async fn canonical_alias_by_npub(
    pool: &sqlx::PgPool,
    owner_npub: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT name FROM public_names \
         WHERE owner_npub = $1 AND kind = 'alias' AND canonical",
    )
    .bind(owner_npub)
    .fetch_optional(pool)
    .await
}

/// Authorize a historical invoice path without consulting Page/POS
/// availability. Alias ownership is permanent even if either surface is
/// archived or the Lightning Address is offline.
pub async fn alias_owns_nym(
    pool: &sqlx::PgPool,
    alias: &str,
    nym: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS( \
             SELECT 1 \
               FROM public_names alias_name \
               JOIN public_names nym_name \
                 ON nym_name.owner_npub = alias_name.owner_npub \
                AND nym_name.kind = 'nym' \
              WHERE alias_name.name = $1 \
                AND alias_name.kind = 'alias' \
                AND nym_name.name = $2 \
         )",
    )
    .bind(alias)
    .bind(nym)
    .fetch_one(pool)
    .await
}

pub fn public_name_constraint_is(error: &sqlx::Error, expected: &str) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error)
            if database_error.constraint() == Some(expected)
    )
}

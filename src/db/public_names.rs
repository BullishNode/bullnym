use sqlx::{Postgres, Transaction};

pub enum AliasUpdateOutcome {
    Unchanged,
    Updated,
    NameTaken,
    AlreadyAssigned,
}

pub async fn ensure_public_name_owner(
    tx: &mut Transaction<'_, Postgres>,
    npub: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO public_name_owners (npub) VALUES ($1) \
         ON CONFLICT (npub) DO NOTHING",
    )
    .bind(npub)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn apply_alias_update(
    tx: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
    alias_update: Option<Option<&str>>,
) -> Result<AliasUpdateOutcome, sqlx::Error> {
    let Some(alias_update) = alias_update else {
        return Ok(AliasUpdateOutcome::Unchanged);
    };

    if alias_update.is_none() {
        sqlx::query(
            "UPDATE public_names \
             SET active = FALSE, deactivated_at = COALESCE(deactivated_at, now()) \
             WHERE owner_npub = $1 AND kind = 'alias' AND active = TRUE",
        )
        .bind(owner_npub)
        .execute(&mut **tx)
        .await?;
        return Ok(AliasUpdateOutcome::Updated);
    }

    let alias = alias_update.expect("checked Some above");
    let owned_aliases = sqlx::query_as::<_, (String, bool)>(
        "SELECT name, active \
         FROM public_names \
         WHERE owner_npub = $1 AND kind = 'alias' \
         ORDER BY claimed_at, name",
    )
    .bind(owner_npub)
    .fetch_all(&mut **tx)
    .await?;

    if let Some((_, active)) = owned_aliases.iter().find(|(name, _)| name == alias) {
        if *active {
            return Ok(AliasUpdateOutcome::Unchanged);
        }

        // Grandfathered owners can have more than one historical alias. Only
        // one can be active, and reactivation never creates a new claim.
        sqlx::query(
            "UPDATE public_names \
             SET active = FALSE, deactivated_at = COALESCE(deactivated_at, now()) \
             WHERE owner_npub = $1 AND kind = 'alias' AND active = TRUE",
        )
        .bind(owner_npub)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "UPDATE public_names \
             SET active = TRUE, deactivated_at = NULL \
             WHERE owner_npub = $1 AND kind = 'alias' AND name = $2",
        )
        .bind(owner_npub)
        .bind(alias)
        .execute(&mut **tx)
        .await?;
        return Ok(AliasUpdateOutcome::Updated);
    }

    if !owned_aliases.is_empty() {
        return Ok(AliasUpdateOutcome::AlreadyAssigned);
    }

    let name_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public_names WHERE name = $1)")
            .bind(alias)
            .fetch_one(&mut **tx)
            .await?;
    if name_exists {
        return Ok(AliasUpdateOutcome::NameTaken);
    }

    ensure_public_name_owner(tx, owner_npub).await?;
    sqlx::query(
        "INSERT INTO public_names (name, owner_npub, kind) \
         VALUES ($1, $2, 'alias')",
    )
    .bind(alias)
    .bind(owner_npub)
    .execute(&mut **tx)
    .await?;
    Ok(AliasUpdateOutcome::Updated)
}

pub async fn alias_owns_nym(
    pool: &sqlx::PgPool,
    alias: &str,
    nym: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS( \
             SELECT 1 \
             FROM public_names \
             JOIN users ON users.npub = public_names.owner_npub \
             WHERE public_names.name = $1 \
               AND public_names.kind = 'alias' \
               AND users.nym = $2 \
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

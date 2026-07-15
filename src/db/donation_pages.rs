use sqlx::{Executor, PgPool, Postgres};

/// Surface discriminator for a donation_pages row. `payment_page` and `pos`
/// are separate surfaces with independent descriptors and cursors.
pub const KIND_PAYMENT_PAGE: &str = "payment_page";
pub const KIND_POS: &str = "pos";

/// Validate a caller-supplied surface kind. Returns the canonical value or
/// `None` if it is not a recognized surface.
pub fn normalize_kind(kind: &str) -> Option<&'static str> {
    match kind {
        KIND_PAYMENT_PAGE => Some(KIND_PAYMENT_PAGE),
        KIND_POS => Some(KIND_POS),
        _ => None,
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct DonationPage {
    pub nym: String,
    /// Surface kind: `payment_page` or `pos`. A nym may own one row of each.
    pub kind: String,
    pub ct_descriptor: String,
    pub next_addr_idx: i32,
    pub header: String,
    pub description: String,
    /// Server-generated, content-addressed social card.
    pub generated_og_key: Option<String>,
    pub generated_og_template_version: Option<i32>,
    /// Owner-level permanent public slug shared by Payment Page and POS.
    /// It is derived from `public_names`, never stored on this surface row.
    pub alias: Option<String>,
    pub display_currency: String,
    pub website: Option<String>,
    pub twitter: Option<String>,
    pub instagram: Option<String>,
    pub enabled: bool,
    /// Derived from `archived_at IS NOT NULL`. The full timestamp lives in
    /// the column for audit but isn't read into Rust (would require the
    /// chrono/time sqlx feature flag).
    pub is_archived: bool,
}

pub struct UpsertDonationPage<'a> {
    pub nym: &'a str,
    /// Surface kind for this row. Callers pass a canonical value from
    /// `normalize_kind`; the (nym, kind) pair is the conflict target.
    pub kind: &'a str,
    pub ct_descriptor: &'a str,
    pub header: &'a str,
    pub description: &'a str,
    pub display_currency: &'a str,
    pub website: Option<&'a str>,
    pub twitter: Option<&'a str>,
    pub instagram: Option<&'a str>,
    pub enabled: bool,
    /// The target renderer version for this content. A missing key with a
    /// present version selects the branded fallback while post-commit
    /// generation/reconciliation is pending.
    pub generated_og_template_version: Option<i32>,
    /// Optional insert-only alias claim. Omission preserves the owner's
    /// current claim. Once claimed, an alias can neither change nor clear.
    pub alias: Option<&'a str>,
}

#[derive(Debug)]
pub enum UpsertDonationPageError {
    Database(sqlx::Error),
    NameTaken,
    AliasAlreadyAssigned { alias: String },
}

impl From<sqlx::Error> for UpsertDonationPageError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// Insert-or-update a donation page row. Mobile sends the full page config on
/// every save (PUT semantics). Update path clears `archived_at` so a re-save
/// after archive un-archives.
pub async fn upsert_donation_page(
    pool: &PgPool,
    page: &UpsertDonationPage<'_>,
) -> Result<DonationPage, UpsertDonationPageError> {
    let mut tx = pool.begin().await?;
    let owner_npub: String = sqlx::query_scalar(
        "SELECT users.npub \
           FROM users \
           JOIN public_names \
             ON public_names.name = users.nym \
            AND public_names.owner_npub = users.npub \
            AND public_names.kind = 'nym' \
          WHERE users.nym = $1",
    )
    .bind(page.nym)
    .fetch_one(&mut *tx)
    .await?;

    let claim = match super::apply_alias_claim(&mut tx, &owner_npub, page.alias).await {
        Ok(outcome) => outcome,
        Err(error)
            if super::public_name_constraint_is(&error, "public_names_shared_namespace_key") =>
        {
            tx.rollback().await?;
            return Err(UpsertDonationPageError::NameTaken);
        }
        Err(error)
            if super::public_name_constraint_is(&error, "public_names_owner_kind_lifetime_key") =>
        {
            tx.rollback().await?;
            return match super::permanent_alias_by_npub(pool, &owner_npub).await? {
                Some(alias) => Err(UpsertDonationPageError::AliasAlreadyAssigned { alias }),
                None => Err(UpsertDonationPageError::Database(error)),
            };
        }
        Err(error) => return Err(error.into()),
    };
    match claim {
        super::AliasClaimOutcome::NameTaken => {
            tx.rollback().await?;
            return Err(UpsertDonationPageError::NameTaken);
        }
        super::AliasClaimOutcome::AlreadyAssigned { alias } => {
            tx.rollback().await?;
            return Err(UpsertDonationPageError::AliasAlreadyAssigned { alias });
        }
        super::AliasClaimOutcome::Unchanged | super::AliasClaimOutcome::Claimed => {}
    }

    sqlx::query(
        "INSERT INTO donation_pages \
            (nym, kind, ct_descriptor, header, description, display_currency, \
             website, twitter, instagram, enabled, \
             generated_og_key, generated_og_template_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                 NULL, $11) \
         ON CONFLICT (nym, kind) DO UPDATE SET \
             ct_descriptor = EXCLUDED.ct_descriptor, \
             header = EXCLUDED.header, \
             description = EXCLUDED.description, \
             display_currency = EXCLUDED.display_currency, \
             website = EXCLUDED.website, \
             twitter = EXCLUDED.twitter, \
             instagram = EXCLUDED.instagram, \
             enabled = EXCLUDED.enabled, \
             generated_og_key = CASE \
                 WHEN donation_pages.header = EXCLUDED.header \
                  AND donation_pages.description = EXCLUDED.description \
                  AND donation_pages.generated_og_template_version \
                      IS NOT DISTINCT FROM EXCLUDED.generated_og_template_version \
                 THEN donation_pages.generated_og_key \
                 ELSE NULL \
             END, \
             generated_og_template_version = EXCLUDED.generated_og_template_version, \
             generated_og_failure_count = 0, \
             generated_og_retry_after = NULL, \
             archived_at = NULL, \
             updated_at = now()",
    )
    .bind(page.nym)
    .bind(page.kind)
    .bind(page.ct_descriptor)
    .bind(page.header)
    .bind(page.description)
    .bind(page.display_currency)
    .bind(page.website)
    .bind(page.twitter)
    .bind(page.instagram)
    .bind(page.enabled)
    .bind(page.generated_og_template_version)
    .execute(&mut *tx)
    .await?;

    let row = get_donation_page_by_nym_with(&mut *tx, page.nym, page.kind)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
    tx.commit().await?;
    Ok(row)
}

/// Attach a generated social card only if the persisted Page still has the
/// exact content/version that was rendered. This is the cancellation/concurrent
/// edit guard for post-commit generation.
pub async fn attach_generated_og_if_current(
    pool: &PgPool,
    nym: &str,
    kind: &str,
    header: &str,
    description: &str,
    template_version: i32,
    key: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "UPDATE donation_pages \
         SET generated_og_key = $6, generated_og_failure_count = 0, \
             generated_og_retry_after = NULL \
         WHERE nym = $1 AND kind = $2 \
           AND header = $3 AND description = $4 \
           AND generated_og_template_version = $5",
    )
    .bind(nym)
    .bind(kind)
    .bind(header)
    .bind(description)
    .bind(template_version)
    .bind(key)
    .execute(pool)
    .await
    .map(|result| result.rows_affected())
}

/// Soft-delete: mark `archived_at = now()`. The row is preserved so the
/// public URL keeps resolving to the "archived" template instead of 404.
/// Returns the post-archive row, or None if no donation page exists.
pub async fn archive_donation_page(
    pool: &PgPool,
    nym: &str,
    kind: &str,
) -> Result<Option<DonationPage>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let updated = sqlx::query(
        "UPDATE donation_pages SET archived_at = now(), updated_at = now() \
         WHERE nym = $1 AND kind = $2 AND archived_at IS NULL",
    )
    .bind(nym)
    .bind(kind)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    let row = get_donation_page_by_nym_with(&mut *tx, nym, kind).await?;
    tx.commit().await?;
    Ok(row)
}

pub async fn get_donation_page_by_nym(
    pool: &PgPool,
    nym: &str,
    kind: &str,
) -> Result<Option<DonationPage>, sqlx::Error> {
    get_donation_page_by_nym_with(pool, nym, kind).await
}

async fn get_donation_page_by_nym_with<'e, E>(
    executor: E,
    nym: &str,
    kind: &str,
) -> Result<Option<DonationPage>, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<_, DonationPage>(
        "SELECT donation_pages.nym, donation_pages.kind, donation_pages.header, \
                donation_pages.description, \
                donation_pages.generated_og_key, donation_pages.generated_og_template_version, \
                alias_name.name AS alias, donation_pages.ct_descriptor, donation_pages.next_addr_idx, \
                donation_pages.display_currency, donation_pages.website, donation_pages.twitter, \
                donation_pages.instagram, donation_pages.enabled, \
                (donation_pages.archived_at IS NOT NULL) AS is_archived \
           FROM donation_pages \
           JOIN users ON users.nym = donation_pages.nym \
      LEFT JOIN public_names alias_name \
            ON alias_name.owner_npub = users.npub \
            AND alias_name.kind = 'alias' \
           JOIN public_names nym_name \
             ON nym_name.name = users.nym \
            AND nym_name.owner_npub = users.npub \
            AND nym_name.kind = 'nym' \
          WHERE donation_pages.nym = $1 AND donation_pages.kind = $2",
    )
    .bind(nym)
    .bind(kind)
    .fetch_optional(executor)
    .await
}

/// Resolve the requested surface through the owner's permanent alias claim.
/// Availability belongs to the selected surface row, not to the alias or the
/// owner's Lightning Address.
pub async fn get_donation_page_by_alias(
    pool: &PgPool,
    alias: &str,
    kind: &str,
) -> Result<Option<DonationPage>, sqlx::Error> {
    sqlx::query_as::<_, DonationPage>(
        "SELECT donation_pages.nym, donation_pages.kind, donation_pages.header, \
                donation_pages.description, \
                donation_pages.generated_og_key, donation_pages.generated_og_template_version, \
                alias_name.name AS alias, donation_pages.ct_descriptor, donation_pages.next_addr_idx, \
                donation_pages.display_currency, donation_pages.website, donation_pages.twitter, \
                donation_pages.instagram, donation_pages.enabled, \
                (donation_pages.archived_at IS NOT NULL) AS is_archived \
           FROM public_names alias_name \
           JOIN public_names nym_name \
             ON nym_name.owner_npub = alias_name.owner_npub \
            AND nym_name.kind = 'nym' \
           JOIN users \
             ON users.npub = nym_name.owner_npub \
            AND users.nym = nym_name.name \
           JOIN donation_pages \
             ON donation_pages.nym = users.nym AND donation_pages.kind = $2 \
          WHERE alias_name.name = $1 \
            AND alias_name.kind = 'alias'",
    )
    .bind(alias)
    .bind(kind)
    .fetch_optional(pool)
    .await
}

/// Bump `donation_pages.next_addr_idx` for an enabled, non-archived page and
/// derive the next Liquid address from the page-specific descriptor.
pub async fn allocate_next_liquid_for_donation_page<F>(
    pool: &PgPool,
    nym: &str,
    kind: &str,
    derive_address: F,
) -> Result<Option<(String, i32, String)>, sqlx::Error>
where
    F: Fn(&str, u32) -> Result<String, sqlx::Error>,
{
    let mut tx = pool.begin().await?;

    // Advisory lock is keyed per (nym, kind) so a hot Payment Page and a hot
    // POS under the same nym advance their independent cursors concurrently.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(format!("donation-page:{nym}:{kind}"))
        .execute(&mut *tx)
        .await?;

    let row: Option<(String, i32)> = sqlx::query_as(
        "SELECT ct_descriptor, next_addr_idx \
         FROM donation_pages \
         WHERE nym = $1 \
           AND kind = $2 \
           AND enabled = TRUE \
           AND archived_at IS NULL",
    )
    .bind(nym)
    .bind(kind)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((ct_descriptor, mut address_index)) = row else {
        return Ok(None);
    };

    for _ in 0..100 {
        let idx_u32 = u32::try_from(address_index).map_err(|_| {
            sqlx::Error::Protocol(format!("address index overflow: {address_index}"))
        })?;
        let address = derive_address(&ct_descriptor, idx_u32)?;
        let in_use: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
                SELECT 1 FROM invoice_payment_addresses \
                WHERE rail = 'liquid' AND address = $1 \
            )",
        )
        .bind(&address)
        .fetch_one(&mut *tx)
        .await?;

        if !in_use {
            sqlx::query(
                "UPDATE donation_pages SET next_addr_idx = $3 WHERE nym = $1 AND kind = $2",
            )
            .bind(nym)
            .bind(kind)
            .bind(address_index + 1)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(Some((address, address_index, ct_descriptor)));
        }

        address_index += 1;
    }

    sqlx::query("UPDATE donation_pages SET next_addr_idx = $3 WHERE nym = $1 AND kind = $2")
        .bind(nym)
        .bind(kind)
        .bind(address_index)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Err(sqlx::Error::Protocol(format!(
        "could not allocate unused Payment Page Liquid address for {nym} after 100 attempts"
    )))
}

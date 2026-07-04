use sqlx::PgPool;

/// Surface discriminator for a donation_pages row. `payment_page` is the
/// default (and the shape every legacy single-row nym carries); `pos` is the
/// separate Point-of-Sale surface with its own descriptor + cursor.
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
    pub ct_descriptor: Option<String>,
    pub next_addr_idx: i32,
    pub header: String,
    pub description: String,
    pub avatar_sha256: Option<String>,
    pub og_sha256: Option<String>,
    pub display_currency: String,
    pub website: Option<String>,
    pub twitter: Option<String>,
    pub instagram: Option<String>,
    pub pos_mode: bool,
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
    pub ct_descriptor: Option<&'a str>,
    pub header: &'a str,
    pub description: &'a str,
    pub display_currency: &'a str,
    pub website: Option<&'a str>,
    pub twitter: Option<&'a str>,
    pub instagram: Option<&'a str>,
    pub pos_mode: Option<bool>,
    pub enabled: bool,
}

/// Insert-or-update a donation page row. Mobile sends the full page config on
/// every save (PUT semantics). Update path clears `archived_at` so a re-save
/// after archive un-archives. Image hashes (`avatar_sha256`, `og_sha256`) are
/// owned by `POST /donation-page/image`.
pub async fn upsert_donation_page(
    pool: &PgPool,
    page: &UpsertDonationPage<'_>,
) -> Result<DonationPage, sqlx::Error> {
    sqlx::query_as::<_, DonationPage>(
        "INSERT INTO donation_pages \
            (nym, kind, ct_descriptor, header, description, display_currency, \
             website, twitter, instagram, pos_mode, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10, FALSE), $11) \
         ON CONFLICT (nym, kind) DO UPDATE SET \
             ct_descriptor = COALESCE(EXCLUDED.ct_descriptor, donation_pages.ct_descriptor), \
             header = EXCLUDED.header, \
             description = EXCLUDED.description, \
             display_currency = EXCLUDED.display_currency, \
             website = EXCLUDED.website, \
             twitter = EXCLUDED.twitter, \
             instagram = EXCLUDED.instagram, \
             pos_mode = COALESCE($10, donation_pages.pos_mode), \
             enabled = EXCLUDED.enabled, \
             archived_at = NULL, \
             updated_at = now() \
         RETURNING nym, kind, ct_descriptor, next_addr_idx, header, description, avatar_sha256, og_sha256, \
                   display_currency, website, twitter, \
                   instagram, pos_mode, enabled, (archived_at IS NOT NULL) AS is_archived",
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
    .bind(page.pos_mode)
    .bind(page.enabled)
    .fetch_one(pool)
    .await
}

/// Soft-delete: mark `archived_at = now()`. The row is preserved so the
/// public URL keeps resolving to the "archived" template instead of 404.
/// Returns the post-archive row, or None if no donation page exists.
pub async fn archive_donation_page(
    pool: &PgPool,
    nym: &str,
    kind: &str,
) -> Result<Option<DonationPage>, sqlx::Error> {
    sqlx::query_as::<_, DonationPage>(
        "UPDATE donation_pages SET archived_at = now(), updated_at = now() \
         WHERE nym = $1 AND kind = $2 AND archived_at IS NULL \
         RETURNING nym, kind, ct_descriptor, next_addr_idx, header, description, avatar_sha256, og_sha256, \
                   display_currency, website, twitter, \
                   instagram, pos_mode, enabled, (archived_at IS NOT NULL) AS is_archived",
    )
    .bind(nym)
    .bind(kind)
    .fetch_optional(pool)
    .await
}

/// Update the avatar or og image hash for a nym's donation page. Used by
/// `POST /donation-page/image` after the resized WebP has been atomically
/// written to disk. `kind_column` is one of `"avatar_sha256"` or
/// `"og_sha256"`; the allowlist is repeated here because SQL identifiers
/// cannot be parameterized.
pub async fn update_donation_page_image_hash(
    pool: &PgPool,
    nym: &str,
    kind: &str,
    image_column: &str,
    new_sha256: &str,
) -> Result<Option<DonationPage>, sqlx::Error> {
    let sql = match image_column {
        "avatar_sha256" => {
            "UPDATE donation_pages SET avatar_sha256 = $3, updated_at = now() \
             WHERE nym = $1 AND kind = $2 \
             RETURNING nym, kind, ct_descriptor, next_addr_idx, header, description, avatar_sha256, og_sha256, \
                       display_currency, website, twitter, \
                       instagram, pos_mode, enabled, (archived_at IS NOT NULL) AS is_archived"
        }
        "og_sha256" => {
            "UPDATE donation_pages SET og_sha256 = $3, updated_at = now() \
             WHERE nym = $1 AND kind = $2 \
             RETURNING nym, kind, ct_descriptor, next_addr_idx, header, description, avatar_sha256, og_sha256, \
                       display_currency, website, twitter, \
                       instagram, pos_mode, enabled, (archived_at IS NOT NULL) AS is_archived"
        }
        _ => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid image kind column: {image_column}"
            )))
        }
    };
    sqlx::query_as::<_, DonationPage>(sql)
        .bind(nym)
        .bind(kind)
        .bind(new_sha256)
        .fetch_optional(pool)
        .await
}

pub async fn get_donation_page_by_nym(
    pool: &PgPool,
    nym: &str,
    kind: &str,
) -> Result<Option<DonationPage>, sqlx::Error> {
    sqlx::query_as::<_, DonationPage>(
        "SELECT nym, kind, header, description, avatar_sha256, og_sha256, \
                ct_descriptor, next_addr_idx, \
                display_currency, website, twitter, \
                instagram, pos_mode, enabled, (archived_at IS NOT NULL) AS is_archived \
         FROM donation_pages WHERE nym = $1 AND kind = $2",
    )
    .bind(nym)
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
           AND archived_at IS NULL \
           AND ct_descriptor IS NOT NULL",
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
            sqlx::query("UPDATE donation_pages SET next_addr_idx = $3 WHERE nym = $1 AND kind = $2")
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

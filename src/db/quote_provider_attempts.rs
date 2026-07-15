use sqlx::PgExecutor;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InvoiceQuoteProviderAttempt {
    pub id: Uuid,
    pub invoice_id: Uuid,
    pub quote_version_id: Uuid,
    pub rail: String,
    pub request_key: String,
    pub operation: String,
    pub merchant_amount_sat: i64,
    pub request_authority_json: String,
    pub request_authority_sha256: String,
    pub claim_key_allocation_id: Uuid,
    pub claim_child_index: i64,
    pub refund_key_allocation_id: Option<Uuid>,
    pub refund_child_index: Option<i64>,
    pub dispatched: bool,
    pub completed: bool,
    pub integrity_hold_reason: Option<String>,
}

pub struct NewInvoiceQuoteProviderAttempt<'a> {
    pub invoice_id: Uuid,
    pub quote_version_id: Uuid,
    pub rail: &'a str,
    pub request_key: &'a str,
    pub operation: &'a str,
    pub merchant_amount_sat: i64,
    pub request_authority_json: &'a str,
    pub request_authority_sha256: &'a str,
    pub claim_key_allocation_id: Uuid,
    pub refund_key_allocation_id: Option<Uuid>,
}

const ATTEMPT_PROJECTION: &str =
    "attempt.id, attempt.invoice_id, attempt.quote_version_id, attempt.rail, \
     attempt.request_key, attempt.operation, attempt.merchant_amount_sat, \
     attempt.request_authority_json, attempt.request_authority_sha256, \
     attempt.claim_key_allocation_id, claim.child_index AS claim_child_index, \
     attempt.refund_key_allocation_id, refund.child_index AS refund_child_index, \
     (dispatch.provider_attempt_id IS NOT NULL) AS dispatched, \
     (completion.provider_attempt_id IS NOT NULL) AS completed, \
     hold.reason AS integrity_hold_reason";

pub async fn record_or_reuse_invoice_quote_provider_attempt<'e, E: PgExecutor<'e>>(
    executor: E,
    attempt: &NewInvoiceQuoteProviderAttempt<'_>,
) -> Result<(InvoiceQuoteProviderAttempt, bool), sqlx::Error> {
    // One statement both inserts and reloads the canonical row, allowing this
    // helper to work with every PgExecutor without accidentally dropping the
    // caller's transaction between those operations.
    let query = format!(
        "WITH inserted AS ( \
             INSERT INTO invoice_quote_provider_attempts (invoice_id, quote_version_id, rail, \
                 request_key, provider, operation, merchant_amount_sat, request_authority_json, \
                 request_authority_sha256, claim_key_allocation_id, refund_key_allocation_id) \
             VALUES ($1, $2, $3, $4, 'boltz', $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (quote_version_id, rail, request_key) DO NOTHING \
             RETURNING * \
         ), selected AS ( \
             SELECT inserted.*, TRUE AS inserted FROM inserted \
             UNION ALL \
             SELECT existing.*, FALSE AS inserted FROM invoice_quote_provider_attempts existing \
              WHERE existing.quote_version_id = $2 AND existing.rail = $3 \
                AND existing.request_key = $4 \
                AND NOT EXISTS (SELECT 1 FROM inserted) \
         ) \
         SELECT {ATTEMPT_PROJECTION}, attempt.inserted \
           FROM selected attempt \
           JOIN swap_key_allocations claim ON claim.id = attempt.claim_key_allocation_id \
           LEFT JOIN swap_key_allocations refund ON refund.id = attempt.refund_key_allocation_id \
           LEFT JOIN invoice_quote_provider_dispatches dispatch ON dispatch.provider_attempt_id = attempt.id \
           LEFT JOIN invoice_quote_provider_completions completion ON completion.provider_attempt_id = attempt.id \
           LEFT JOIN invoice_quote_provider_integrity_holds hold ON hold.provider_attempt_id = attempt.id"
    );
    #[derive(sqlx::FromRow)]
    struct SelectedAttempt {
        #[sqlx(flatten)]
        attempt: InvoiceQuoteProviderAttempt,
        inserted: bool,
    }
    let selected = sqlx::query_as::<_, SelectedAttempt>(&query)
        .bind(attempt.invoice_id)
        .bind(attempt.quote_version_id)
        .bind(attempt.rail)
        .bind(attempt.request_key)
        .bind(attempt.operation)
        .bind(attempt.merchant_amount_sat)
        .bind(attempt.request_authority_json)
        .bind(attempt.request_authority_sha256)
        .bind(attempt.claim_key_allocation_id)
        .bind(attempt.refund_key_allocation_id)
        .fetch_one(executor)
        .await?;
    let canonical = &selected.attempt;
    if canonical.invoice_id != attempt.invoice_id
        || canonical.quote_version_id != attempt.quote_version_id
        || canonical.rail != attempt.rail
        || canonical.request_key != attempt.request_key
        || canonical.operation != attempt.operation
        || canonical.merchant_amount_sat != attempt.merchant_amount_sat
        || canonical.request_authority_json != attempt.request_authority_json
        || canonical.request_authority_sha256 != attempt.request_authority_sha256
        || canonical.claim_key_allocation_id != attempt.claim_key_allocation_id
        || canonical.refund_key_allocation_id != attempt.refund_key_allocation_id
    {
        return Err(sqlx::Error::Protocol(
            "provider attempt identity conflicts with its canonical request authority".into(),
        ));
    }
    Ok((selected.attempt, selected.inserted))
}

pub async fn invoice_quote_provider_attempt<'e, E: PgExecutor<'e>>(
    executor: E,
    quote_version_id: Uuid,
    rail: &str,
    request_key: &str,
) -> Result<Option<InvoiceQuoteProviderAttempt>, sqlx::Error> {
    let query = format!(
        "SELECT {ATTEMPT_PROJECTION} \
           FROM invoice_quote_provider_attempts attempt \
           JOIN swap_key_allocations claim ON claim.id = attempt.claim_key_allocation_id \
           LEFT JOIN swap_key_allocations refund ON refund.id = attempt.refund_key_allocation_id \
           LEFT JOIN invoice_quote_provider_dispatches dispatch ON dispatch.provider_attempt_id = attempt.id \
           LEFT JOIN invoice_quote_provider_completions completion ON completion.provider_attempt_id = attempt.id \
           LEFT JOIN invoice_quote_provider_integrity_holds hold ON hold.provider_attempt_id = attempt.id \
          WHERE attempt.quote_version_id = $1 AND attempt.rail = $2 AND attempt.request_key = $3"
    );
    sqlx::query_as(&query)
        .bind(quote_version_id)
        .bind(rail)
        .bind(request_key)
        .fetch_optional(executor)
        .await
}

/// Returns true only for the process which durably crosses the dispatch
/// boundary. False means a prior process may already have sent the request and
/// the caller must reconcile rather than POST.
pub async fn record_invoice_quote_provider_dispatch<'e, E: PgExecutor<'e>>(
    executor: E,
    provider_attempt_id: Uuid,
    request_authority_sha256: &str,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO invoice_quote_provider_dispatches \
             (provider_attempt_id, request_authority_sha256) VALUES ($1, $2) \
         ON CONFLICT (provider_attempt_id) DO NOTHING RETURNING provider_attempt_id",
    )
    .bind(provider_attempt_id)
    .bind(request_authority_sha256)
    .fetch_optional(executor)
    .await?
    .is_some())
}

pub async fn record_invoice_quote_provider_integrity_hold<'e, E: PgExecutor<'e>>(
    executor: E,
    provider_attempt_id: Uuid,
    reason: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO invoice_quote_provider_integrity_holds (provider_attempt_id, reason) \
         VALUES ($1, $2) ON CONFLICT (provider_attempt_id) DO NOTHING",
    )
    .bind(provider_attempt_id)
    .bind(reason)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn record_invoice_quote_provider_completion<'e, E: PgExecutor<'e>>(
    executor: E,
    provider_attempt_id: Uuid,
    quote_offer_id: Uuid,
    provider_offer_id: &str,
    provider_response_sha256: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO invoice_quote_provider_completions (provider_attempt_id, quote_offer_id, \
             provider_offer_id, provider_response_sha256) VALUES ($1, $2, $3, $4)",
    )
    .bind(provider_attempt_id)
    .bind(quote_offer_id)
    .bind(provider_offer_id)
    .bind(provider_response_sha256)
    .execute(executor)
    .await?;
    Ok(())
}

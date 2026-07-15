use sqlx::PgExecutor;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InvoiceQuoteProviderAttempt {
    pub id: Uuid,
    pub claim_key_allocation_id: Uuid,
    pub refund_key_allocation_id: Option<Uuid>,
}

pub struct NewInvoiceQuoteProviderAttempt<'a> {
    pub invoice_id: Uuid,
    pub quote_version_id: Uuid,
    pub rail: &'a str,
    pub request_key: &'a str,
    pub operation: &'a str,
    pub merchant_amount_sat: i64,
    pub claim_key_allocation_id: Uuid,
    pub refund_key_allocation_id: Option<Uuid>,
}

pub async fn record_or_reuse_invoice_quote_provider_attempt<'e, E: PgExecutor<'e>>(
    executor: E,
    attempt: &NewInvoiceQuoteProviderAttempt<'_>,
) -> Result<(InvoiceQuoteProviderAttempt, bool), sqlx::Error> {
    let inserted = sqlx::query_as::<_, InvoiceQuoteProviderAttempt>(
        "INSERT INTO invoice_quote_provider_attempts (invoice_id, quote_version_id, rail, \
             request_key, provider, operation, merchant_amount_sat, claim_key_allocation_id, \
             refund_key_allocation_id) \
         VALUES ($1, $2, $3, $4, 'boltz', $5, $6, $7, $8) \
         ON CONFLICT (quote_version_id, rail, request_key) DO NOTHING \
         RETURNING id, claim_key_allocation_id, refund_key_allocation_id",
    )
    .bind(attempt.invoice_id)
    .bind(attempt.quote_version_id)
    .bind(attempt.rail)
    .bind(attempt.request_key)
    .bind(attempt.operation)
    .bind(attempt.merchant_amount_sat)
    .bind(attempt.claim_key_allocation_id)
    .bind(attempt.refund_key_allocation_id)
    .fetch_optional(executor)
    .await?;
    if let Some(row) = inserted {
        return Ok((row, true));
    }
    Err(sqlx::Error::Protocol(
        "provider attempt already exists; reconcile it instead of issuing another obligation"
            .into(),
    ))
}

pub async fn invoice_quote_provider_attempt<'e, E: PgExecutor<'e>>(
    executor: E,
    quote_version_id: Uuid,
    rail: &str,
    request_key: &str,
) -> Result<Option<InvoiceQuoteProviderAttempt>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, claim_key_allocation_id, refund_key_allocation_id \
           FROM invoice_quote_provider_attempts \
          WHERE quote_version_id = $1 AND rail = $2 AND request_key = $3",
    )
    .bind(quote_version_id)
    .bind(rail)
    .bind(request_key)
    .fetch_optional(executor)
    .await
}

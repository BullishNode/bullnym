use sqlx::PgPool;
use uuid::Uuid;

pub const MAX_GET_PAID_TRANSACTION_PAGE_SIZE: u16 = 100;

// Deliberately omit `Debug`: `comment` is authenticated private metadata and
// must not become printable through an incidental row/page debug log.
#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct GetPaidTransaction {
    pub transaction_id: Uuid,
    pub source: String,
    pub source_rank: i16,
    pub invoice_id: Option<Uuid>,
    pub amount_sat: i64,
    pub received_at_unix_micros: i64,
    pub rail: String,
    pub settlement_state: String,
    pub late: bool,
    pub comment: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetPaidTransactionCursor {
    pub received_at_unix_micros: i64,
    pub source_rank: i16,
    pub transaction_id: Uuid,
}

impl From<&GetPaidTransaction> for GetPaidTransactionCursor {
    fn from(value: &GetPaidTransaction) -> Self {
        Self {
            received_at_unix_micros: value.received_at_unix_micros,
            source_rank: value.source_rank,
            transaction_id: value.transaction_id,
        }
    }
}

pub struct GetPaidTransactionPage {
    pub transactions: Vec<GetPaidTransaction>,
    pub has_more: bool,
}

pub async fn list_get_paid_transactions(
    pool: &PgPool,
    owner_npub: &str,
    cursor: Option<GetPaidTransactionCursor>,
    limit: u16,
) -> Result<GetPaidTransactionPage, sqlx::Error> {
    if limit == 0 || limit > MAX_GET_PAID_TRANSACTION_PAGE_SIZE {
        return Err(sqlx::Error::Protocol(
            "invalid Get Paid transaction page size".into(),
        ));
    }
    let fetch_limit = i64::from(limit) + 1;
    let cursor_time = cursor.map(|value| value.received_at_unix_micros);
    let cursor_rank = cursor.map(|value| value.source_rank);
    let cursor_id = cursor.map(|value| value.transaction_id);

    let mut rows = sqlx::query_as::<_, GetPaidTransaction>(
        "WITH history AS ( \
             SELECT swap.id AS transaction_id, \
                    'lightning_address'::TEXT AS source, \
                    4::SMALLINT AS source_rank, \
                    NULL::UUID AS invoice_id, \
                    swap.amount_sat, \
                    (EXTRACT(EPOCH FROM swap.payment_first_observed_at) * 1000000)::BIGINT \
                        AS received_at_unix_micros, \
                    'lightning'::TEXT AS rail, \
                    CASE \
                        WHEN swap.status = 'claimed' THEN 'settled' \
                        WHEN swap.status IN ('claim_stuck', 'lockup_refunded') THEN 'problem' \
                        ELSE 'pending' \
                    END::TEXT AS settlement_state, \
                    FALSE AS late, \
                    comment.comment \
               FROM swap_records swap \
               JOIN users owner ON owner.nym = swap.nym \
          LEFT JOIN lnurl_comment_intents comment \
                 ON comment.owner_npub = owner.npub \
                AND comment.instruction_rail = 'lightning' \
                AND comment.instruction_reference = swap.boltz_swap_id \
                AND comment.payment_evidence_reference IS NOT NULL \
                AND comment.payment_evidenced_at IS NOT NULL \
              WHERE owner.npub = $1 \
                AND swap.invoice_id IS NULL \
                AND swap.payment_first_observed_at IS NOT NULL \
                AND swap.status IN ( \
                    'lockup_mempool', 'lockup_confirmed', 'claiming', 'claimed', \
                    'claim_failed', 'claim_stuck', 'lockup_refunded' \
                ) \
             UNION ALL \
             SELECT event.id AS transaction_id, \
                    CASE \
                        WHEN invoice.origin = 'wallet' THEN 'invoice' \
                        WHEN invoice.checkout_surface_kind = 'payment_page' \
                            THEN 'payment_page' \
                        WHEN invoice.checkout_surface_kind = 'pos' \
                            THEN 'point_of_sale' \
                    END::TEXT AS source, \
                    CASE \
                        WHEN invoice.origin = 'wallet' THEN 3 \
                        WHEN invoice.checkout_surface_kind = 'payment_page' THEN 2 \
                        ELSE 1 \
                    END::SMALLINT AS source_rank, \
                    event.invoice_id, \
                    event.amount_sat, \
                    (EXTRACT(EPOCH FROM COALESCE( \
                        event.quote_first_observed_at, \
                        observation.first_seen_at, \
                        event.created_at \
                    )) * 1000000)::BIGINT AS received_at_unix_micros, \
                    event.rail, \
                    CASE \
                        WHEN event.accounting_state = 'inactive' \
                            THEN 'problem' \
                        WHEN event.accounting_state = 'legacy_unverified' \
                            THEN 'pending' \
                        WHEN event.accounting_state = 'active' \
                         AND event.source IN ('bitcoin_direct', 'liquid_direct') \
                         AND observation.last_seen_state IN ( \
                            'seen_unconfirmed', 'awaiting_confirmations', \
                            'resolution_pending' \
                        ) THEN 'pending' \
                        WHEN event.accounting_state = 'active' \
                         AND event.source IN ('bitcoin_direct', 'liquid_direct') \
                         AND observation.last_seen_state = 'counted' \
                            THEN 'settled' \
                        WHEN event.accounting_state = 'active' \
                         AND event.source IN ('bitcoin_direct', 'liquid_direct') \
                         AND observation.id IS NULL \
                            THEN 'pending' \
                        WHEN event.accounting_state = 'active' \
                         AND event.source IN ( \
                            'bitcoin_boltz_chain', 'bitcoin_boltz_recovery' \
                        ) AND NOT event.merchant_settlement_finalized \
                            THEN 'pending' \
                        WHEN event.accounting_state = 'active' \
                         AND event.source IN ( \
                            'lightning_boltz_reverse', 'bitcoin_boltz_chain', \
                            'bitcoin_boltz_recovery' \
                         ) THEN 'settled' \
                        ELSE 'unknown' \
                    END::TEXT AS settlement_state, \
                    COALESCE( \
                        event.fiat_credit_policy = 'late_observation_rate_v1', \
                        FALSE \
                    ) AS late, \
                    CASE WHEN invoice.origin = 'checkout' THEN invoice.memo END AS comment \
               FROM invoice_payment_events event \
               JOIN invoices invoice ON invoice.id = event.invoice_id \
          LEFT JOIN invoice_payment_observations observation \
                 ON observation.id = event.observation_id \
              WHERE invoice.npub_owner = $1 \
                AND event.amount_sat > 0 \
                AND event.source IS NOT NULL \
                AND event.accounting_state <> 'superseded' \
         ) \
         SELECT transaction_id, source, source_rank, invoice_id, amount_sat, \
                received_at_unix_micros, rail, settlement_state, late, comment \
           FROM history \
          WHERE $2::BIGINT IS NULL \
             OR (received_at_unix_micros, source_rank, transaction_id) \
                < ($2::BIGINT, $3::SMALLINT, $4::UUID) \
          ORDER BY received_at_unix_micros DESC, source_rank DESC, transaction_id DESC \
          LIMIT $5",
    )
    .bind(owner_npub)
    .bind(cursor_time)
    .bind(cursor_rank)
    .bind(cursor_id)
    .bind(fetch_limit)
    .fetch_all(pool)
    .await?;

    let has_more = rows.len() > usize::from(limit);
    rows.truncate(usize::from(limit));
    Ok(GetPaidTransactionPage {
        transactions: rows,
        has_more,
    })
}

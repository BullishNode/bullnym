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
    pub settlement_present: bool,
    pub settlement_purpose: Option<String>,
    pub settlement_order_id: Option<Uuid>,
    pub settlement_currency: Option<String>,
    pub settlement_status_detail: Option<String>,
    pub settlement_credited_fiat_minor: Option<i64>,
    pub settlement_funding_route: Option<String>,
    pub settlement_fallback_category: Option<String>,
    pub settlement_bitcoin_amount_sat: Option<i64>,
    pub settlement_bitcoin_status: Option<String>,
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

    // Mixed settlements persist one accounting event per output. Build their
    // user-facing receipt from the canonical settlement row and suppress the
    // component events so pagination exposes one payer payment exactly once.
    let mut rows = sqlx::query_as::<_, GetPaidTransaction>(
        "WITH invoice_events AS MATERIALIZED ( \
             SELECT event.id AS transaction_id, event.source AS event_source, \
                    event.boltz_swap_id, event.merchant_chain_swap_id, \
                    event.bull_bitcoin_settlement_id, \
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
                    event.invoice_id, event.amount_sat, \
                    (EXTRACT(EPOCH FROM COALESCE( \
                        event.quote_first_observed_at, observation.first_seen_at, \
                        event.created_at \
                    )) * 1000000)::BIGINT AS received_at_unix_micros, \
                    event.rail, \
                    CASE \
                        WHEN event.accounting_state = 'inactive' THEN 'problem' \
                        WHEN event.accounting_state = 'legacy_unverified' THEN 'pending' \
                        WHEN event.accounting_state = 'active' \
                         AND event.source IN ('bitcoin_direct', 'liquid_direct') \
                         AND observation.last_seen_state IN ( \
                            'seen_unconfirmed', 'awaiting_confirmations', \
                            'resolution_pending' \
                         ) THEN 'pending' \
                        WHEN event.accounting_state = 'active' \
                         AND event.source IN ('bitcoin_direct', 'liquid_direct') \
                         AND observation.last_seen_state = 'counted' THEN 'settled' \
                        WHEN event.accounting_state = 'active' \
                         AND event.source IN ('bitcoin_direct', 'liquid_direct') \
                         AND observation.id IS NULL THEN 'pending' \
                        WHEN event.accounting_state = 'active' \
                         AND event.source IN ( \
                            'bitcoin_boltz_chain', 'bitcoin_boltz_recovery' \
                         ) AND NOT event.merchant_settlement_finalized THEN 'pending' \
                        WHEN event.accounting_state = 'active' \
                         AND event.source IN ( \
                            'lightning_boltz_reverse', 'bitcoin_boltz_chain', \
                            'bitcoin_boltz_recovery', 'bull_bitcoin_fiat' \
                         ) THEN 'settled' \
                        ELSE 'unknown' \
                    END::TEXT AS settlement_state, \
                    COALESCE( \
                        event.fiat_credit_policy = 'late_observation_rate_v1', FALSE \
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
         ), settlement_outputs AS MATERIALIZED ( \
             SELECT output.settlement_id, \
                    SUM(output.authorized_amount_sat)::BIGINT AS total_amount_sat, \
                    MAX(output.authorized_amount_sat) \
                        FILTER (WHERE output.role = 'merchant')::BIGINT \
                        AS merchant_amount_sat \
               FROM bull_bitcoin_claim_outputs output \
               JOIN bull_bitcoin_settlements owned_settlement \
                 ON owned_settlement.id = output.settlement_id \
                AND owned_settlement.owner_npub = $1 \
              GROUP BY output.settlement_id \
         ), history AS ( \
             SELECT swap.id AS transaction_id, \
                    'lightning_address'::TEXT AS source, 4::SMALLINT AS source_rank, \
                    NULL::UUID AS invoice_id, swap.amount_sat, \
                    (EXTRACT(EPOCH FROM swap.payment_first_observed_at) * 1000000)::BIGINT \
                        AS received_at_unix_micros, \
                    'lightning'::TEXT AS rail, \
                    CASE \
                        WHEN swap.status IN ('claim_stuck', 'lockup_refunded') THEN 'problem' \
                        WHEN settlement.id IS NOT NULL \
                         AND settlement.funding_route = 'bull_bitcoin' \
                         AND settlement.settlement_status <> 'settled' THEN 'pending' \
                        WHEN swap.status = 'claimed' THEN 'settled' \
                        ELSE 'pending' \
                    END::TEXT AS settlement_state, \
                    FALSE AS late, comment.comment, \
                    settlement.id IS NOT NULL AS settlement_present, \
                    settlement.purpose AS settlement_purpose, \
                    settlement.bull_bitcoin_order_id AS settlement_order_id, \
                    settlement.fiat_currency AS settlement_currency, \
                    settlement.settlement_status AS settlement_status_detail, \
                    settlement.credited_fiat_minor AS settlement_credited_fiat_minor, \
                    settlement.funding_route AS settlement_funding_route, \
                    settlement.fallback_category AS settlement_fallback_category, \
                    outputs.merchant_amount_sat AS settlement_bitcoin_amount_sat, \
                    CASE \
                        WHEN swap.status IN ('claim_stuck', 'lockup_refunded') THEN 'problem' \
                        WHEN swap.status = 'claimed' THEN 'settled' \
                        ELSE 'pending' \
                    END::TEXT AS settlement_bitcoin_status \
               FROM swap_records swap \
               JOIN users owner ON owner.nym = swap.nym \
          LEFT JOIN lnurl_comment_intents comment \
                 ON comment.owner_npub = owner.npub \
                AND comment.instruction_rail = 'lightning' \
                AND comment.instruction_reference = swap.boltz_swap_id \
                AND comment.payment_evidence_reference IS NOT NULL \
                AND comment.payment_evidenced_at IS NOT NULL \
          LEFT JOIN bull_bitcoin_settlements settlement \
                 ON settlement.reverse_swap_id = swap.id \
                AND settlement.owner_npub = owner.npub \
                AND settlement.product = 'lightning_address' \
          LEFT JOIN settlement_outputs outputs ON outputs.settlement_id = settlement.id \
              WHERE owner.npub = $1 AND swap.invoice_id IS NULL \
                AND swap.payment_first_observed_at IS NOT NULL \
                AND swap.status IN ( \
                    'lockup_mempool', 'lockup_confirmed', 'claiming', 'claimed', \
                    'claim_failed', 'claim_stuck', 'lockup_refunded' \
                ) \
             UNION ALL \
             SELECT settlement.id, 'lightning_address'::TEXT, 4::SMALLINT, \
                    NULL::UUID, settlement.actual_received_sat, \
                    (EXTRACT(EPOCH FROM settlement.terminal_at) * 1000000)::BIGINT, \
                    settlement.payer_rail, 'settled'::TEXT, FALSE, NULL::TEXT, \
                    TRUE, settlement.purpose, settlement.bull_bitcoin_order_id, \
                    settlement.fiat_currency, settlement.settlement_status, \
                    settlement.credited_fiat_minor, settlement.funding_route, \
                    settlement.fallback_category, NULL::BIGINT, NULL::TEXT \
               FROM bull_bitcoin_settlements settlement \
              WHERE settlement.owner_npub = $1 \
                AND settlement.product = 'lightning_address' \
                AND settlement.purpose = 'fiat_only' \
                AND settlement.provider_final \
                AND settlement.settlement_status = 'settled' \
                AND settlement.actual_received_sat > 0 \
                AND settlement.terminal_at IS NOT NULL \
             UNION ALL \
             SELECT event.transaction_id, event.source, event.source_rank, \
                    event.invoice_id, event.amount_sat, event.received_at_unix_micros, \
                    event.rail, event.settlement_state, event.late, event.comment, \
                    FALSE, NULL::TEXT, NULL::UUID, NULL::TEXT, NULL::TEXT, \
                    NULL::BIGINT, NULL::TEXT, NULL::TEXT, NULL::BIGINT, NULL::TEXT \
               FROM invoice_events event \
              WHERE event.bull_bitcoin_settlement_id IS NULL \
                AND NOT EXISTS ( \
                    SELECT 1 FROM bull_bitcoin_settlements settlement \
               LEFT JOIN swap_records reverse_swap \
                      ON reverse_swap.id = settlement.reverse_swap_id \
                   WHERE settlement.owner_npub = $1 \
                     AND settlement.purpose = 'mixed' \
                     AND ( \
                         (settlement.reverse_swap_id IS NOT NULL \
                          AND event.event_source = 'lightning_boltz_reverse' \
                          AND event.boltz_swap_id = reverse_swap.boltz_swap_id) \
                         OR (settlement.chain_swap_id IS NOT NULL \
                          AND event.event_source IN ( \
                              'bitcoin_boltz_chain', 'bitcoin_boltz_recovery' \
                          ) \
                          AND event.merchant_chain_swap_id = settlement.chain_swap_id) \
                     ) \
                ) \
             UNION ALL \
             SELECT settlement.id, event.source, event.source_rank, event.invoice_id, \
                    event.amount_sat, event.received_at_unix_micros, event.rail, \
                    event.settlement_state, event.late, event.comment, TRUE, \
                    settlement.purpose, settlement.bull_bitcoin_order_id, \
                    settlement.fiat_currency, settlement.settlement_status, \
                    settlement.credited_fiat_minor, settlement.funding_route, \
                    settlement.fallback_category, NULL::BIGINT, NULL::TEXT \
               FROM bull_bitcoin_settlements settlement \
               JOIN invoice_events event \
                 ON event.bull_bitcoin_settlement_id = settlement.id \
                AND event.event_source = 'bull_bitcoin_fiat' \
              WHERE settlement.owner_npub = $1 \
                AND settlement.purpose = 'fiat_only' \
             UNION ALL \
             SELECT settlement.id, event.source, event.source_rank, event.invoice_id, \
                    CASE WHEN settlement.funding_route = 'bull_bitcoin' \
                         THEN outputs.total_amount_sat ELSE event.amount_sat END, \
                    event.received_at_unix_micros, event.rail, \
                    CASE \
                        WHEN event.settlement_state = 'problem' THEN 'problem' \
                        WHEN settlement.funding_route = 'bull_bitcoin' \
                         AND (event.settlement_state <> 'settled' \
                              OR settlement.settlement_status <> 'settled') THEN 'pending' \
                        ELSE event.settlement_state \
                    END::TEXT, \
                    event.late, event.comment, TRUE, settlement.purpose, \
                    settlement.bull_bitcoin_order_id, settlement.fiat_currency, \
                    settlement.settlement_status, settlement.credited_fiat_minor, \
                    settlement.funding_route, settlement.fallback_category, \
                    outputs.merchant_amount_sat, event.settlement_state \
               FROM bull_bitcoin_settlements settlement \
          LEFT JOIN swap_records reverse_swap ON reverse_swap.id = settlement.reverse_swap_id \
               JOIN invoice_events event ON ( \
                    settlement.reverse_swap_id IS NOT NULL \
                    AND event.event_source = 'lightning_boltz_reverse' \
                    AND event.boltz_swap_id = reverse_swap.boltz_swap_id \
                 ) OR ( \
                    settlement.chain_swap_id IS NOT NULL \
                    AND event.event_source IN ( \
                        'bitcoin_boltz_chain', 'bitcoin_boltz_recovery' \
                    ) \
                    AND event.merchant_chain_swap_id = settlement.chain_swap_id \
                 ) \
          LEFT JOIN settlement_outputs outputs ON outputs.settlement_id = settlement.id \
              WHERE settlement.owner_npub = $1 AND settlement.purpose = 'mixed' \
         ) \
         SELECT transaction_id, source, source_rank, invoice_id, amount_sat, \
                received_at_unix_micros, rail, settlement_state, late, comment, \
                settlement_present, settlement_purpose, settlement_order_id, \
                settlement_currency, settlement_status_detail, \
                settlement_credited_fiat_minor, settlement_funding_route, \
                settlement_fallback_category, settlement_bitcoin_amount_sat, \
                settlement_bitcoin_status \
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

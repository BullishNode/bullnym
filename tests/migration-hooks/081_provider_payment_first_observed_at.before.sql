-- Two unfunded, quote-bound fiat-only settlements created by the schema-080
-- binary. Migration 081 must accept authoritative first-seen evidence only on
-- the first-funds transition and must reject a timestamp before the quote.

INSERT INTO invoices (
    id, nym_owner, npub_owner, origin,
    fiat_amount_minor, fiat_currency, amount_sat, rate_minor_per_btc,
    rate_locks_until, bitcoin_address,
    accept_btc, accept_ln, accept_liquid,
    status, pricing_mode, presentation_status, settlement_status, expires_at,
    client_request_id, client_request_digest, presentation_envelope
) VALUES
(
    '81000000-0000-4000-8000-000000000001',
    NULL, repeat('6', 64), 'wallet',
    1000, 'USD', 0, NULL, clock_timestamp() + INTERVAL '1 hour',
    'bc1q081providerpaymenttime000000000000000000000000',
    TRUE, FALSE, FALSE, 'unpaid', 'fiat_fixed', 'unpaid', 'none',
    clock_timestamp() + INTERVAL '1 hour',
    '81000000-0000-4000-8000-000000000004',
    decode(repeat('81', 32), 'hex'),
    decode('01' || repeat('81', 4124), 'hex')
),
(
    '81000000-0000-4000-8000-000000000011',
    NULL, repeat('6', 64), 'wallet',
    1000, 'USD', 0, NULL, clock_timestamp() + INTERVAL '1 hour',
    'bc1q081invalidpaymenttime00000000000000000000000',
    TRUE, FALSE, FALSE, 'unpaid', 'fiat_fixed', 'unpaid', 'none',
    clock_timestamp() + INTERVAL '1 hour',
    '81000000-0000-4000-8000-000000000014',
    decode(repeat('82', 32), 'hex'),
    decode('01' || repeat('82', 4124), 'hex')
);

INSERT INTO invoice_quote_versions (
    id, invoice_id, quote_purpose, fiat_target_amount_minor,
    rate_minor_per_btc, rate_source,
    rate_observed_at, rate_fetched_at, rate_fresh_until,
    merchant_amount_sat
) VALUES
(
    '81000000-0000-4000-8000-000000000002',
    '81000000-0000-4000-8000-000000000001',
    'payer_instruction', 1000, 10000000, 'test:migration-081-valid',
    clock_timestamp() - INTERVAL '1 second', clock_timestamp(),
    clock_timestamp() + INTERVAL '10 minutes', 10000
),
(
    '81000000-0000-4000-8000-000000000012',
    '81000000-0000-4000-8000-000000000011',
    'payer_instruction', 1000, 10000000, 'test:migration-081-invalid',
    clock_timestamp() - INTERVAL '1 second', clock_timestamp(),
    clock_timestamp() + INTERVAL '10 minutes', 10000
);

INSERT INTO bull_bitcoin_settlements (
    id, owner_npub, invoice_id, invoice_quote_version_id,
    credential_id, product, purpose, payer_rail, request_key,
    fiat_percentage, fiat_currency, requested_bitcoin_sat
)
SELECT
    fixture.settlement_id, repeat('6', 64), fixture.invoice_id, quote.id,
    '66000000-0000-4000-8000-000000000001',
    'invoice', 'fiat_only', 'liquid',
    encode(
        digest(
            convert_to('bullnym-invoice-quote-offer-v1', 'UTF8')
            || decode('00', 'hex')
            || decode(replace(quote.id::TEXT, '-', ''), 'hex')
            || decode('00', 'hex')
            || convert_to('liquid', 'UTF8')
            || decode('00', 'hex')
            || convert_to('bull_bitcoin_fiat_only', 'UTF8'),
            'sha256'
        ),
        'hex'
    ),
    100, 'CAD', quote.merchant_amount_sat
  FROM (VALUES
      ('81000000-0000-4000-8000-000000000003'::UUID,
       '81000000-0000-4000-8000-000000000001'::UUID,
       '81000000-0000-4000-8000-000000000002'::UUID),
      ('81000000-0000-4000-8000-000000000013'::UUID,
       '81000000-0000-4000-8000-000000000011'::UUID,
       '81000000-0000-4000-8000-000000000012'::UUID)
  ) fixture(settlement_id, invoice_id, quote_id)
  JOIN invoice_quote_versions quote ON quote.id = fixture.quote_id;

UPDATE bull_bitcoin_settlements
   SET provider_state = 'dispatch_started', updated_at = clock_timestamp()
 WHERE id IN (
    '81000000-0000-4000-8000-000000000003',
    '81000000-0000-4000-8000-000000000013'
 );

UPDATE bull_bitcoin_settlements
   SET provider_state = 'bound', funding_route = 'bull_bitcoin',
       funding_committed_at = clock_timestamp(), settlement_status = 'pending',
       bull_bitcoin_order_id = CASE id
           WHEN '81000000-0000-4000-8000-000000000003'::UUID
           THEN '81000000-0000-4000-8000-000000000005'::UUID
           ELSE '81000000-0000-4000-8000-000000000015'::UUID
       END,
       order_correlation_source = 'provider_response',
       order_correlated_at = clock_timestamp(),
       instruction_kind = 'liquid', payer_instruction = 'lq1migration081',
       retention_until = clock_timestamp() + INTERVAL '30 days',
       updated_at = clock_timestamp()
 WHERE id IN (
    '81000000-0000-4000-8000-000000000003',
    '81000000-0000-4000-8000-000000000013'
 );

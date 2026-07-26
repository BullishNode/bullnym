-- Reproduce a still-unfunded fiat-only order created by the schema-074
-- binary. Migration 075 must recover its exact payer quote from the request
-- commitment; amount or timestamp heuristics are not sufficient authority.

INSERT INTO invoices (
    id, nym_owner, npub_owner, origin,
    fiat_amount_minor, fiat_currency, amount_sat, rate_minor_per_btc,
    rate_locks_until, bitcoin_address,
    accept_btc, accept_ln, accept_liquid,
    status, pricing_mode, presentation_status, settlement_status, expires_at,
    client_request_id, client_request_digest, presentation_envelope
) VALUES (
    '75000000-0000-4000-8000-000000000001',
    NULL, repeat('6', 64), 'wallet',
    1000, 'USD', 0, NULL,
    clock_timestamp() + INTERVAL '1 hour',
    'bc1q075fiatonlyquoteaccounting000000000000000000000',
    TRUE, FALSE, FALSE,
    'unpaid', 'fiat_fixed', 'unpaid', 'none',
    clock_timestamp() + INTERVAL '1 hour',
    '75000000-0000-4000-8000-000000000004',
    decode(repeat('75', 32), 'hex'),
    decode('01' || repeat('75', 4124), 'hex')
);

INSERT INTO invoice_quote_versions (
    id, invoice_id, quote_purpose, fiat_target_amount_minor,
    rate_minor_per_btc, rate_source,
    rate_observed_at, rate_fetched_at, rate_fresh_until,
    merchant_amount_sat
) VALUES (
    '75000000-0000-4000-8000-000000000002',
    '75000000-0000-4000-8000-000000000001',
    'payer_instruction', 1000, 10000000,
    'test:migration-075-payer-quote',
    clock_timestamp() - INTERVAL '1 second', clock_timestamp(),
    clock_timestamp() + INTERVAL '5 minutes', 10000
);

INSERT INTO bull_bitcoin_settlements (
    id, owner_npub, invoice_id, credential_id, product, purpose,
    payer_rail, request_key, fiat_percentage, fiat_currency,
    requested_bitcoin_sat
)
SELECT
    '75000000-0000-4000-8000-000000000003', repeat('6', 64),
    '75000000-0000-4000-8000-000000000001',
    '66000000-0000-4000-8000-000000000001',
    'invoice', 'fiat_only', 'bitcoin',
    encode(
        digest(
            convert_to('bullnym-invoice-quote-offer-v1', 'UTF8')
            || decode('00', 'hex')
            || decode(replace(quote.id::TEXT, '-', ''), 'hex')
            || decode('00', 'hex')
            || convert_to('bitcoin', 'UTF8')
            || decode('00', 'hex')
            || convert_to('bull_bitcoin_fiat_only', 'UTF8'),
            'sha256'
        ),
        'hex'
    ),
    100, 'CAD', quote.merchant_amount_sat
  FROM invoice_quote_versions quote
 WHERE quote.id = '75000000-0000-4000-8000-000000000002';

UPDATE bull_bitcoin_settlements
   SET provider_state = 'dispatch_started', updated_at = clock_timestamp()
 WHERE id = '75000000-0000-4000-8000-000000000003';
UPDATE bull_bitcoin_settlements
   SET provider_state = 'bound', funding_route = 'bull_bitcoin',
       funding_committed_at = clock_timestamp(), settlement_status = 'pending',
       bull_bitcoin_order_id = '75000000-0000-4000-8000-000000000005',
       instruction_kind = 'bitcoin', payer_instruction = 'bc1q075payerinstruction',
       retention_until = clock_timestamp() + INTERVAL '30 days',
       updated_at = clock_timestamp()
 WHERE id = '75000000-0000-4000-8000-000000000003';

-- Reproduce the live pre-075 cache defect: a USD-face invoice was marked
-- overpaid using Bull Bitcoin's CAD payout amount. Migration 075 must retain
-- that provider evidence but rebuild the invoice cache without treating CAD
-- minor units as USD minor units.
INSERT INTO invoices (
    id, nym_owner, npub_owner, origin,
    fiat_amount_minor, fiat_currency, amount_sat, rate_minor_per_btc,
    rate_locks_until, bitcoin_address,
    accept_btc, accept_ln, accept_liquid,
    status, pricing_mode, presentation_status, settlement_status, expires_at,
    client_request_id, client_request_digest, presentation_envelope
) VALUES (
    '75000000-0000-4000-8000-000000000011',
    NULL, repeat('6', 64), 'wallet',
    1000, 'USD', 0, NULL,
    clock_timestamp() + INTERVAL '1 hour',
    'bc1q075legacyfiatcache0000000000000000000000000',
    TRUE, FALSE, FALSE,
    'unpaid', 'fiat_fixed', 'unpaid', 'none',
    clock_timestamp() + INTERVAL '1 hour',
    '75000000-0000-4000-8000-000000000014',
    decode(repeat('76', 32), 'hex'),
    decode('01' || repeat('76', 4124), 'hex')
);

INSERT INTO invoice_quote_versions (
    id, invoice_id, quote_purpose, fiat_target_amount_minor,
    rate_minor_per_btc, rate_source,
    rate_observed_at, rate_fetched_at, rate_fresh_until,
    merchant_amount_sat
) VALUES (
    '75000000-0000-4000-8000-000000000012',
    '75000000-0000-4000-8000-000000000011',
    'payer_instruction', 1000, 10000000,
    'test:migration-075-legacy-quote',
    clock_timestamp() - INTERVAL '1 second', clock_timestamp(),
    clock_timestamp() + INTERVAL '5 minutes', 10000
);

INSERT INTO bull_bitcoin_settlements (
    id, owner_npub, invoice_id, credential_id, product, purpose,
    payer_rail, request_key, fiat_percentage, fiat_currency,
    requested_bitcoin_sat
) VALUES (
    '75000000-0000-4000-8000-000000000013', repeat('6', 64),
    '75000000-0000-4000-8000-000000000011',
    '66000000-0000-4000-8000-000000000001',
    'invoice', 'fiat_only', 'bitcoin', 'migration-075-legacy-fiat',
    100, 'CAD', 10000
);
UPDATE bull_bitcoin_settlements
   SET provider_state = 'dispatch_started', updated_at = clock_timestamp()
 WHERE id = '75000000-0000-4000-8000-000000000013';
UPDATE bull_bitcoin_settlements
   SET provider_state = 'bound', funding_route = 'bull_bitcoin',
       funding_committed_at = clock_timestamp(), settlement_status = 'pending',
       bull_bitcoin_order_id = '75000000-0000-4000-8000-000000000015',
       instruction_kind = 'bitcoin', payer_instruction = 'bc1q075legacyinstruction',
       retention_until = clock_timestamp() + INTERVAL '30 days',
       updated_at = clock_timestamp()
 WHERE id = '75000000-0000-4000-8000-000000000013';
UPDATE bull_bitcoin_settlements
   SET order_status = 'Completed', payin_status = 'Completed',
       payout_status = 'Completed', actual_received_sat = 10000,
       credited_fiat_minor = 31406, provider_final = TRUE,
       settlement_status = 'settled', terminal_at = clock_timestamp(),
       payer_instruction = NULL, instruction_kind = NULL,
       instruction_expires_at = NULL, next_attempt_at = NULL,
       updated_at = clock_timestamp()
 WHERE id = '75000000-0000-4000-8000-000000000013';

INSERT INTO invoice_payment_events (
    invoice_id, rail, source, event_key, amount_sat,
    accounting_state, verification_state, bull_bitcoin_settlement_id,
    fiat_credited_minor, fiat_credit_policy, fiat_valued_at
) VALUES (
    '75000000-0000-4000-8000-000000000011', 'bitcoin',
    'bull_bitcoin_fiat',
    'bull_bitcoin_fiat:75000000-0000-4000-8000-000000000013',
    10000, 'active', 'not_applicable',
    '75000000-0000-4000-8000-000000000013',
    31406, 'bull_bitcoin_actual_v1', clock_timestamp()
);

UPDATE invoices
   SET status = 'overpaid', presentation_status = 'overpaid',
       paid_via = 'bitcoin', paid_amount_sat = 10000,
       paid_at = clock_timestamp()
 WHERE id = '75000000-0000-4000-8000-000000000011';

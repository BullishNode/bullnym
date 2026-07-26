-- Reproduce the historical mixed-valuation defect at the migration boundary.
-- The merchant leg is valued through its immutable payer quote, while the
-- Bull Bitcoin Liquid leg is intentionally left valuation-free by schema 070.
-- Migration 071 must repair that leg and rebuild the cached invoice projection
-- without inserting or deleting payment evidence.

INSERT INTO invoices (
    id, nym_owner, npub_owner, origin,
    fiat_amount_minor, fiat_currency, amount_sat, rate_minor_per_btc,
    rate_locks_until, bitcoin_address, liquid_address,
    liquid_blinding_key_hex,
    accept_btc, accept_ln, accept_liquid,
    status, pricing_mode, presentation_status, settlement_status, expires_at,
    client_request_id, client_request_digest, presentation_envelope
) VALUES (
    '71000000-0000-4000-8000-000000000001',
    NULL, repeat('6', 64), 'wallet',
    1000, 'USD', 0, NULL,
    clock_timestamp() + INTERVAL '1 hour',
    'bc1q071repairablemixedinvoice000000000000000000000',
    'lq1migration071repairableconfidentialaddress', repeat('83', 32),
    TRUE, TRUE, TRUE,
    'unpaid', 'fiat_fixed', 'unpaid', 'none',
    clock_timestamp() + INTERVAL '1 hour',
    '71000000-0000-4000-8000-000000000008',
    decode(repeat('84', 32), 'hex'),
    decode('01' || repeat('85', 4124), 'hex')
);

BEGIN;
SET LOCAL ROLE bullnym_app;
INSERT INTO invoice_quote_versions (
    invoice_id, quote_purpose, rate_minor_per_btc, rate_source,
    rate_observed_at, rate_fetched_at, rate_fresh_until,
    merchant_amount_sat
) VALUES (
    '71000000-0000-4000-8000-000000000001',
    'payer_instruction', 30000000, 'bullbitcoin-pricer:indexPrice',
    clock_timestamp() - INTERVAL '1 second', clock_timestamp(),
    clock_timestamp() + INTERVAL '5 minutes', 3334
);
COMMIT;

INSERT INTO swap_key_allocations (
    id, root_fingerprint, key_epoch, derivation_scheme_version, child_index,
    purpose, public_key_hex, preimage_hash_hex
) VALUES (
    '71000000-0000-4000-8000-000000000002',
    '7171717171717171', 1, 1, 710001, 'reverse_claim',
    '02' || repeat('72', 32), repeat('73', 32)
);

BEGIN;
INSERT INTO invoice_quote_provider_attempts (
    id, invoice_id, quote_version_id, rail, request_key, provider, operation,
    merchant_amount_sat, request_authority_json, request_authority_sha256,
    claim_key_allocation_id, refund_key_allocation_id
)
SELECT '71000000-0000-4000-8000-000000000003', q.invoice_id, q.id,
       'lightning', repeat('c', 64), 'boltz', 'fixed_checkout_reverse',
       q.merchant_amount_sat, '{"kind":"migration071"}',
       encode(digest(convert_to('{"kind":"migration071"}', 'UTF8'), 'sha256'), 'hex'),
       '71000000-0000-4000-8000-000000000002'::UUID, NULL
  FROM invoice_quote_versions q
 WHERE q.invoice_id = '71000000-0000-4000-8000-000000000001';

INSERT INTO invoice_quote_provider_dispatches (
    provider_attempt_id, request_authority_sha256
)
SELECT id, request_authority_sha256
  FROM invoice_quote_provider_attempts
 WHERE id = '71000000-0000-4000-8000-000000000003';

INSERT INTO invoice_quote_offers (
    id, invoice_id, quote_version_id, rail, offer_kind, request_key,
    provider, provider_offer_id, payer_amount_sat, expires_at,
    provider_attempt_id
)
SELECT '71000000-0000-4000-8000-000000000004', q.invoice_id, q.id,
       'lightning', 'boltz_reverse', repeat('c', 64), 'boltz',
       'migration-071-repairable-reverse', 4000, q.expires_at,
       '71000000-0000-4000-8000-000000000003'
  FROM invoice_quote_versions q
 WHERE q.invoice_id = '71000000-0000-4000-8000-000000000001';

INSERT INTO swap_records (
    id, nym, boltz_swap_id, amount_sat, invoice, preimage_hex,
    claim_key_hex, boltz_response_json, invoice_id, status,
    key_index, root_fingerprint, key_allocation_id, key_epoch,
    derivation_scheme_version, claim_public_key_hex, preimage_hash_hex,
    invoice_quote_version_id, invoice_quote_offer_id
)
SELECT '71000000-0000-4000-8000-000000000005', NULL,
       'migration-071-repairable-reverse', 3334, 'lnbc-migration-071',
       repeat('74', 32), repeat('75', 32),
       '{"id":"migration-071-repairable-reverse"}', q.invoice_id,
       'lockup_confirmed', 710001, '7171717171717171',
       '71000000-0000-4000-8000-000000000002', 1, 1,
       '02' || repeat('72', 32), repeat('73', 32), q.id,
       '71000000-0000-4000-8000-000000000004'
  FROM invoice_quote_versions q
 WHERE q.invoice_id = '71000000-0000-4000-8000-000000000001';

INSERT INTO invoice_quote_provider_completions (
    provider_attempt_id, quote_offer_id, provider_offer_id,
    provider_response_sha256
) VALUES (
    '71000000-0000-4000-8000-000000000003',
    '71000000-0000-4000-8000-000000000004',
    'migration-071-repairable-reverse',
    encode(digest(
        convert_to('{"id":"migration-071-repairable-reverse"}', 'UTF8'),
        'sha256'
    ), 'hex')
);
COMMIT;

INSERT INTO swap_fiat_settlement_policies (
    reverse_swap_id, owner_npub, credential_id, product,
    fiat_percentage, fiat_currency
) VALUES (
    '71000000-0000-4000-8000-000000000005', repeat('6', 64),
    '66000000-0000-4000-8000-000000000001', 'invoice', 40, 'CAD'
);

INSERT INTO bull_bitcoin_settlements (
    id, owner_npub, invoice_id, reverse_swap_id, credential_id,
    product, purpose, payer_rail, request_key, fiat_percentage,
    fiat_currency, requested_bitcoin_sat
) VALUES (
    '71000000-0000-4000-8000-000000000006', repeat('6', 64),
    '71000000-0000-4000-8000-000000000001',
    '71000000-0000-4000-8000-000000000005',
    '66000000-0000-4000-8000-000000000001',
    'invoice', 'mixed', 'lightning', 'migration-071-mixed-order',
    40, 'CAD', 1333
);
UPDATE bull_bitcoin_settlements
   SET provider_state = 'dispatch_started', updated_at = clock_timestamp()
 WHERE id = '71000000-0000-4000-8000-000000000006';
UPDATE bull_bitcoin_settlements
   SET provider_state = 'bound',
       bull_bitcoin_order_id = '71000000-0000-4000-8000-000000000007',
       instruction_kind = 'liquid',
       payer_instruction = 'VJL6migration071ConfidentialLiquidAddress',
       updated_at = clock_timestamp()
 WHERE id = '71000000-0000-4000-8000-000000000006';

INSERT INTO bull_bitcoin_claim_outputs (
    settlement_id, role, txid, vout, script_pubkey_hex,
    authorized_amount_sat, asset_commitment_sha256,
    value_commitment_sha256, nonce_commitment_sha256,
    surjection_proof_sha256, rangeproof_sha256
) VALUES
(
    '71000000-0000-4000-8000-000000000006', 'merchant', repeat('76', 32), 0,
    '0014' || repeat('77', 20), 2001,
    repeat('78', 32), repeat('79', 32), repeat('7a', 32),
    repeat('7b', 32), repeat('7c', 32)
),
(
    '71000000-0000-4000-8000-000000000006', 'bull_bitcoin', repeat('76', 32), 1,
    '0014' || repeat('7d', 20), 1333,
    repeat('7e', 32), repeat('7f', 32), repeat('80', 32),
    repeat('81', 32), repeat('82', 32)
);

UPDATE bull_bitcoin_settlements
   SET funding_route = 'bull_bitcoin', funding_committed_at = clock_timestamp(),
       settlement_status = 'pending', instruction_kind = NULL,
       payer_instruction = NULL, updated_at = clock_timestamp()
 WHERE id = '71000000-0000-4000-8000-000000000006';

BEGIN;
SET LOCAL ROLE bullnym_app;
INSERT INTO invoice_payment_events (
    invoice_id, rail, source, event_key, amount_sat, txid, boltz_swap_id,
    accounting_state, verification_state, invoice_quote_version_id,
    invoice_quote_offer_id, quote_first_observed_at
)
SELECT swap.invoice_id, 'lightning', 'lightning_boltz_reverse',
       'lightning_boltz_reverse:migration-071-repairable-reverse',
       2001, repeat('76', 32), swap.boltz_swap_id,
       'active', 'not_applicable', swap.invoice_quote_version_id,
       swap.invoice_quote_offer_id, swap.quote_payment_first_observed_at
  FROM swap_records swap
 WHERE swap.id = '71000000-0000-4000-8000-000000000005';

INSERT INTO invoice_payment_events (
    invoice_id, rail, source, event_key, amount_sat, txid, vout,
    accounting_state, verification_state, bull_bitcoin_settlement_id
) VALUES (
    '71000000-0000-4000-8000-000000000001', 'liquid',
    'bull_bitcoin_mixed_output',
    'bull_bitcoin_mixed_output:71000000-0000-4000-8000-000000000006',
    1333, repeat('76', 32), 1, 'active', 'not_applicable',
    '71000000-0000-4000-8000-000000000006'
);
COMMIT;

-- Mirror the runtime reducer state after only the first leg was valued.
-- The unvalued second leg keeps the invoice in progress before migration 071.
UPDATE invoices
   SET status = 'in_progress', presentation_status = 'partial',
       paid_via = 'lightning', paid_amount_sat = 2001
 WHERE id = '71000000-0000-4000-8000-000000000001';

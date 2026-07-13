-- Representative pre-050 rows already carry migration-044's partial identity,
-- but cannot truthfully be assigned an epoch, scheme, public key, or hash by a
-- schema migration alone.
INSERT INTO swap_records (
    id, nym, boltz_swap_id, amount_sat, invoice, preimage_hex,
    claim_key_hex, boltz_response_json, key_index, root_fingerprint
) VALUES (
    '50000000-0000-0000-0000-000000000001',
    'og-migration-fixture', 'migration-050-legacy-reverse', 50000,
    'lnbc-migration-050', repeat('44', 32), repeat('55', 32), '{}',
    5000, repeat('ab', 8)
);

UPDATE chain_swap_records
   SET claim_key_index = 5001,
       refund_key_index = 5002,
       root_fingerprint = repeat('ab', 8)
 WHERE id = '46000000-0000-0000-0000-000000000002';

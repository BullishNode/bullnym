-- A representative pre-046 recovery already in flight.  The migration must
-- preserve it as explicit legacy ambiguity; it must not invent raw bytes or
-- silently reset the row for reconstruction.
INSERT INTO invoices (
    id, nym_owner, npub_owner, origin, amount_sat, rate_locks_until,
    liquid_address, liquid_address_index, accept_btc, accept_ln,
    accept_liquid, expires_at
)
VALUES (
    '46000000-0000-0000-0000-000000000001',
    'og-migration-fixture', repeat('a', 64), 'checkout', 100000,
    NOW() + INTERVAL '1 hour', 'lq1migrationfixture', 46000,
    FALSE, FALSE, TRUE, NOW() + INTERVAL '1 hour'
);

INSERT INTO chain_swap_records (
    id, invoice_id, nym, boltz_swap_id, from_chain, to_chain,
    lockup_address, user_lock_amount_sat, server_lock_amount_sat,
    preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json,
    status, refund_address
)
VALUES (
    '46000000-0000-0000-0000-000000000002',
    '46000000-0000-0000-0000-000000000001',
    'og-migration-fixture', 'migration-046-legacy-recovery', 'BTC', 'L-BTC',
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 100000, 99000,
    repeat('11', 32), repeat('22', 32), repeat('33', 32), '{}',
    'refunding',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'
);

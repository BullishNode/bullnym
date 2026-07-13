-- Representative pre-047 money state. The migration must preserve the cached
-- invoice projection and all three accounting events, classify direct events as
-- countable legacy evidence, and never fabricate missing Liquid observations or
-- lifecycle history.
INSERT INTO invoices (
    id, nym_owner, npub_owner, origin, amount_sat, rate_locks_until,
    bitcoin_address, liquid_address, liquid_address_index,
    accept_btc, accept_ln, accept_liquid,
    status, paid_via, paid_amount_sat, paid_at, settlement_status, expires_at
)
VALUES (
    '47000000-0000-0000-0000-000000000001',
    'og-migration-fixture', repeat('a', 64), 'checkout', 100000,
    TIMESTAMPTZ '2027-01-01 00:00:00+00',
    'bc1q047migrationfixture000000000000000000000000',
    'lq1q047migrationfixture000000000000000000000000', 47000,
    TRUE, FALSE, TRUE,
    'paid', 'mixed', 100000, TIMESTAMPTZ '2026-01-01 00:00:04+00',
    'settled', TIMESTAMPTZ '2027-01-01 00:00:00+00'
);

INSERT INTO invoice_payment_observations (
    id, invoice_id, rail, source, event_key, txid, vout, address,
    amount_sat, confirmations, block_height, last_seen_state,
    first_seen_at, last_seen_at
)
VALUES (
    '47000000-0000-0000-0000-000000000002',
    '47000000-0000-0000-0000-000000000001',
    'bitcoin', 'bitcoin_direct',
    'bitcoin_direct:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0',
    repeat('a', 64), 0,
    'bc1q047migrationfixture000000000000000000000000',
    20000, 1, 840000, 'counted',
    TIMESTAMPTZ '2026-01-01 00:00:00+00',
    TIMESTAMPTZ '2026-01-01 00:00:01+00'
);

INSERT INTO invoice_payment_events (
    id, invoice_id, rail, source, event_key, amount_sat,
    txid, vout, boltz_swap_id, address, created_at
)
VALUES
(
    '47000000-0000-0000-0000-000000000003',
    '47000000-0000-0000-0000-000000000001',
    'bitcoin', 'bitcoin_direct',
    'bitcoin_direct:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0',
    20000, repeat('a', 64), 0, NULL,
    'bc1q047migrationfixture000000000000000000000000',
    TIMESTAMPTZ '2026-01-01 00:00:01+00'
),
(
    '47000000-0000-0000-0000-000000000004',
    '47000000-0000-0000-0000-000000000001',
    'liquid', 'liquid_direct',
    'liquid_direct:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1',
    30000, repeat('b', 64), 1, NULL,
    'lq1q047migrationfixture000000000000000000000000',
    TIMESTAMPTZ '2026-01-01 00:00:02+00'
),
(
    '47000000-0000-0000-0000-000000000005',
    '47000000-0000-0000-0000-000000000001',
    'lightning', 'lightning_boltz_reverse',
    'lightning_boltz_reverse:migration-047-boltz',
    50000, repeat('c', 64), NULL, 'migration-047-boltz', NULL,
    TIMESTAMPTZ '2026-01-01 00:00:03+00'
);

-- A pre-047 zero-confirmation BTC sighting has a durable observation and a
-- pending aggregate, but deliberately no countable payment event. Migration
-- must attribute that pending component to direct settlement, not to swaps.
INSERT INTO invoices (
    id, nym_owner, npub_owner, origin, amount_sat, rate_locks_until,
    bitcoin_address, accept_btc, accept_ln, accept_liquid,
    status, paid_via, paid_amount_sat, settlement_status, expires_at
)
VALUES (
    '47000000-0000-0000-0000-000000000010',
    NULL, repeat('d', 64), 'wallet', 1000,
    TIMESTAMPTZ '2027-01-01 00:00:00+00',
    'bc1q047zeroconffixture0000000000000000000000000',
    TRUE, FALSE, FALSE,
    'in_progress', NULL, NULL, 'pending',
    TIMESTAMPTZ '2027-01-01 00:00:00+00'
);

INSERT INTO invoice_payment_observations (
    id, invoice_id, rail, source, event_key, txid, vout, address,
    amount_sat, confirmations, block_height, last_seen_state,
    first_seen_at, last_seen_at
)
VALUES (
    '47000000-0000-0000-0000-000000000011',
    '47000000-0000-0000-0000-000000000010',
    'bitcoin', 'bitcoin_direct',
    'bitcoin_direct:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd:0',
    repeat('d', 64), 0,
    'bc1q047zeroconffixture0000000000000000000000000',
    1000, 0, NULL, 'seen_unconfirmed',
    TIMESTAMPTZ '2026-01-01 00:01:00+00',
    TIMESTAMPTZ '2026-01-01 00:01:00+00'
);

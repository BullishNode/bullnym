-- A real upgrade may already contain every supported invoice lifecycle. Keep
-- one closed Bitcoin destination present while migration 049 adds only the
-- independent watcher-rotation table.
INSERT INTO invoices (
    id, nym_owner, npub_owner, origin, amount_sat, rate_locks_until,
    bitcoin_address, accept_btc, accept_ln, accept_liquid, status,
    presentation_status, cancelled_at, expires_at
)
VALUES (
    '49000000-0000-0000-0000-000000000001',
    'og-migration-fixture', repeat('a', 64), 'wallet', 1000,
    TIMESTAMPTZ '2027-01-01 00:00:00+00',
    'bc1q049cancelledfixture00000000000000000000000',
    TRUE, FALSE, FALSE, 'cancelled', 'unpaid',
    TIMESTAMPTZ '2026-01-01 00:00:00+00',
    TIMESTAMPTZ '2027-01-01 00:00:00+00'
);

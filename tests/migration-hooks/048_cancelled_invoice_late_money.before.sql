-- Pre-048 rows use the old coherence constraint: a cancelled invoice cannot
-- yet identify money received after the close action.
INSERT INTO invoices (
    id, nym_owner, npub_owner, origin, amount_sat, rate_locks_until,
    liquid_address, liquid_address_index, accept_btc, accept_ln,
    accept_liquid, status, presentation_status, cancelled_at, expires_at
)
VALUES (
    '48000000-0000-0000-0000-000000000001',
    'og-migration-fixture', repeat('a', 64), 'wallet', 1000,
    TIMESTAMPTZ '2027-01-01 00:00:00+00',
    'lq1q048cancelledfixture00000000000000000000000', 48000,
    FALSE, FALSE, TRUE, 'cancelled', 'unpaid',
    TIMESTAMPTZ '2026-01-01 00:00:00+00',
    TIMESTAMPTZ '2027-01-01 00:00:00+00'
);

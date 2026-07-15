-- A legacy fiat invoice has a face/rate cache but no honest source/freshness or
-- quote-version identity. Migration 061 must preserve it without backfilling
-- invented attribution into this invoice or any older money-path row.
INSERT INTO invoices (
    id, nym_owner, npub_owner, origin,
    fiat_amount_minor, fiat_currency, amount_sat, rate_minor_per_btc,
    rate_locks_until, bitcoin_address,
    accept_btc, accept_ln, accept_liquid,
    status, pricing_mode, presentation_status, settlement_status, expires_at
) VALUES (
    '61000000-0000-0000-0000-000000000001',
    NULL, repeat('6', 64), 'wallet',
    1000, 'USD', 10000, 10000000,
    TIMESTAMPTZ '2030-01-01 00:00:00+00',
    'bc1q061legacyfiatinvoice000000000000000000000000',
    TRUE, FALSE, FALSE,
    'unpaid', 'fiat_fixed', 'unpaid', 'none',
    TIMESTAMPTZ '2030-01-01 00:00:00+00'
);

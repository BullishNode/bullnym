-- Migration 069 leaves a valid sat-priced mixed output without fiat quote
-- authority. Migration 071's repair fixture supplies a fiat-priced exception.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM invoice_mixed_valuation_exceptions
         WHERE bull_bitcoin_settlement_id =
               '67000000-0000-4000-8000-000000000003'
    ) THEN
        RAISE EXCEPTION 'migration 082 fixture requires the sat-priced false positive';
    END IF;
END
$$;

BEGIN;
SET LOCAL session_replication_role = replica;
UPDATE invoice_payment_events
   SET fiat_credited_minor = NULL,
       fiat_credit_policy = NULL,
       fiat_valued_at = NULL,
       fiat_valuation_quote_version_id = NULL,
       fiat_rate_minor_per_btc = NULL,
       fiat_rate_source = NULL,
       fiat_rate_observed_at = NULL,
       fiat_rate_fetched_at = NULL,
       fiat_rate_fresh_until = NULL
 WHERE bull_bitcoin_settlement_id =
       '71000000-0000-4000-8000-000000000006';
COMMIT;

CREATE TABLE migration_082_event_snapshot AS
SELECT event.*
  FROM invoice_payment_events event
 WHERE event.bull_bitcoin_settlement_id IN (
    '67000000-0000-4000-8000-000000000003',
    '71000000-0000-4000-8000-000000000006'
 );

CREATE TABLE migration_082_view_snapshot AS
SELECT exception.payment_event_id,
       exception.bull_bitcoin_settlement_id,
       exception.reason,
       invoice.pricing_mode
  FROM invoice_mixed_valuation_exceptions exception
  JOIN invoices invoice ON invoice.id = exception.invoice_id
 WHERE exception.bull_bitcoin_settlement_id IN (
    '67000000-0000-4000-8000-000000000003',
    '71000000-0000-4000-8000-000000000006'
 );

DO $$
BEGIN
    IF (SELECT COUNT(*) FROM migration_082_event_snapshot) <> 2
       OR (SELECT COUNT(*) FROM migration_082_view_snapshot) <> 2
       OR NOT EXISTS (
           SELECT 1 FROM migration_082_view_snapshot
            WHERE bull_bitcoin_settlement_id =
                  '67000000-0000-4000-8000-000000000003'
              AND pricing_mode = 'sat_fixed'
       )
       OR NOT EXISTS (
           SELECT 1 FROM migration_082_view_snapshot
            WHERE bull_bitcoin_settlement_id =
                  '71000000-0000-4000-8000-000000000006'
              AND pricing_mode = 'fiat_fixed'
       ) THEN
        RAISE EXCEPTION 'migration 082 fixture did not reproduce both scopes';
    END IF;
END
$$;

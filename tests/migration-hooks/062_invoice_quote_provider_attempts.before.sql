-- Migration 061 deliberately proved that it did not fabricate quote identity
-- for a legacy fiat row. Migration 062 deliberately refuses that old mutable
-- amount/rate shape rather than backfilling it. Remove the disposable hook
-- fixture after its 061 assertions so this upgrade test exercises the clean
-- cutover contract without pretending to migrate monetary evidence.
TRUNCATE TABLE invoice_quote_versions CASCADE;
DELETE FROM invoices
 WHERE id = '61000000-0000-0000-0000-000000000001';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM invoices
         WHERE pricing_mode = 'fiat_fixed'
           AND (amount_sat <> 0 OR rate_minor_per_btc IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'migration 062 hook retained an incompatible legacy fiat row';
    END IF;
END
$$;

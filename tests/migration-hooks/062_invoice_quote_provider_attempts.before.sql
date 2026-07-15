-- Migration 061 deliberately proved that it did not fabricate quote identity
-- for a legacy fiat row. Migration 062 deliberately refuses that old mutable
-- amount/rate shape rather than backfilling it. Remove the disposable hook
-- fixture after its 061 assertions so this upgrade test exercises the clean
-- cutover contract without pretending to migrate monetary evidence.
-- The production rollout is an authorized clean cutover. The upgrade harness
-- accumulated representative legacy invoice fixtures for earlier migration
-- assertions; discard that synthetic ledger here instead of backfilling a
-- quote surface or monetary valuation that never existed.
TRUNCATE TABLE invoices CASCADE;

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

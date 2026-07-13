-- Migration 052 creates a new append-only witness ledger. Existing operational
-- chain-swap rows are prerequisites, not rows to be rewritten or backfilled.
DO $$
BEGIN
    IF to_regclass('public.chain_swap_manifest_deliveries') IS NOT NULL THEN
        RAISE EXCEPTION 'manifest delivery ledger unexpectedly exists before migration 052';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM chain_swap_records
         WHERE id = '50000000-0000-0000-0000-000000000003'
    ) OR NOT EXISTS (
        SELECT 1 FROM chain_swap_records
         WHERE id = '51000000-0000-0000-0000-000000000003'
    ) THEN
        RAISE EXCEPTION 'migration 052 source fixtures are missing';
    END IF;
END
$$;

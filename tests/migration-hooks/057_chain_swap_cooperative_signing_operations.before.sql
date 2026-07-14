-- Migration 057 is a strict no-backfill boundary. Historical provider and
-- recovery activity must not be rewritten as a signing intent that never
-- existed durably.
DO $$
BEGIN
    IF to_regclass('public.chain_swap_cooperative_signing_operations') IS NOT NULL THEN
        RAISE EXCEPTION 'cooperative signing journal unexpectedly exists before migration 057';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM chain_swap_records
         WHERE id = '53000000-0000-0000-0000-000000000012'
    ) THEN
        RAISE EXCEPTION 'migration 057 historical chain-swap fixture is unavailable';
    END IF;
END
$$;

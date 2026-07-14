-- Preserve one pre-056 renegotiation result as an explicit upgrade fixture.
-- Migration 056 must not manufacture journal history for provider operations
-- that predate the crash-safe operation boundary.
DO $$
BEGIN
    IF to_regclass('public.chain_swap_renegotiation_operations') IS NOT NULL THEN
        RAISE EXCEPTION 'renegotiation journal unexpectedly exists before migration 056';
    END IF;

    UPDATE chain_swap_records
       SET renegotiated_server_lock_amount_sat = 24750,
           renegotiated_at = '2020-07-13 12:00:00+00'::TIMESTAMPTZ
     WHERE id = '53000000-0000-0000-0000-000000000012';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 056 historical renegotiation fixture is unavailable';
    END IF;
END
$$;

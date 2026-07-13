-- Migration 050 leaves one fully lineaged chain swap behind. Migration 051
-- must preserve it as a legacy row without fabricating creation evidence.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM chain_swap_records
         WHERE id = '50000000-0000-0000-0000-000000000003'
           AND boltz_swap_id = 'migration-050-lineaged-chain'
    ) THEN
        RAISE EXCEPTION 'migration 051 prerequisite legacy chain row is missing';
    END IF;
END
$$;

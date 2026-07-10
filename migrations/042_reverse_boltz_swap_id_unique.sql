-- Enforce global uniqueness of the reverse-swap Boltz identifier, matching the
-- constraint chain swaps already have (025: chain_swap_records.boltz_swap_id
-- UNIQUE). Reverse swaps only had a plain index (001), so a retry, concurrency
-- bug, or restore/import could insert two rows with the same boltz_swap_id,
-- making webhook routing, reconciliation, status lookup, and recovery ownership
-- ambiguous (issue #69).
--
-- Preflight: abort loudly if duplicates already exist rather than silently
-- merging or deleting monetary records. sqlx runs each migration in a
-- transaction, so RAISE fails the whole migration and nothing is changed.
-- Operator remediation (dedupe) must happen before this migration can apply.

DO $$
DECLARE
    dup TEXT;
BEGIN
    SELECT string_agg(boltz_swap_id, ', ')
      INTO dup
      FROM (
          SELECT boltz_swap_id
            FROM swap_records
           GROUP BY boltz_swap_id
          HAVING COUNT(*) > 1
      ) d;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION
            'duplicate reverse boltz_swap_id present; resolve before applying unique constraint: %',
            dup;
    END IF;
END $$;

-- The plain lookup index is subsumed by the unique index.
DROP INDEX IF EXISTS idx_swap_records_boltz_id;

CREATE UNIQUE INDEX swap_records_boltz_swap_id_key
    ON swap_records (boltz_swap_id);

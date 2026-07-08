-- ============================================================================
-- 039: reconciler round-robin + priority ordering (fixes head-of-line starvation)
-- ============================================================================
-- Both reconcilers fetch the oldest `max_per_tick` (default 200) non-terminal
-- swaps by `updated_at ASC`. A `Noop` reconciler action (swap.created/pending —
-- unpaid LNURL probes / unfetched offers, which live up to 24h) writes nothing,
-- so those rows keep their old `updated_at` and permanently occupy the window.
-- With more than `max_per_tick` pending rows, a funded lockup that actually
-- needs recovery (dropped Boltz webhook) is never fetched — funds stuck at
-- exactly the condition the reconciler exists for.
--
-- Fix has two parts, both backed by this migration:
--   * `last_reconciled_at` — stamped on every fetched batch at tick start; the
--     query orders by it so scanning round-robins across the whole corpus
--     instead of re-pinning the same oldest-by-updated_at rows every tick.
--   * priority ordering (in the query) puts potentially-funded / claim- or
--     refund-eligible statuses ahead of inert `pending`/`created` rows.
--
-- `last_reconciled_at` is a nullable column with no default, so ADD COLUMN is a
-- catalog-only change (no table rewrite) — safe on the ~1M-row tables. The
-- partial indexes backing the new ORDER BY are built CONCURRENTLY; that cannot
-- run inside a transaction block, so they live AFTER the COMMIT and rely on
-- psql autocommit (migrations are applied manually via `psql -f`, see README).
-- ============================================================================

BEGIN;

ALTER TABLE swap_records
    ADD COLUMN IF NOT EXISTS last_reconciled_at TIMESTAMPTZ;

ALTER TABLE chain_swap_records
    ADD COLUMN IF NOT EXISTS last_reconciled_at TIMESTAMPTZ;

COMMIT;

-- CONCURRENTLY: must not run inside a transaction block. Applied in autocommit.
-- Partial predicate mirrors the non-terminal WHERE clause of each reconciler
-- query so the planner can use the index for the round-robin ORDER BY.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_swap_records_reconcile_rr
    ON swap_records (last_reconciled_at ASC NULLS FIRST)
    WHERE status NOT IN ('claimed', 'expired', 'lockup_refunded', 'claim_stuck');

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_chain_swap_records_reconcile_rr
    ON chain_swap_records (last_reconciled_at ASC NULLS FIRST)
    WHERE status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck');

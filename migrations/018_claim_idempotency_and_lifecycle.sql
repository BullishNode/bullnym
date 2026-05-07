-- Claim-path idempotency, retry budgeting, and new lifecycle states.
--
-- Today's claim flow has three structural bugs that can leave funds stranded:
--   1. construct_claim is non-deterministic on Liquid (random MuSig2 nonces
--      + random asset/value blinding factors). Every retry produces a
--      different valid-but-conflicting tx; if the previous broadcast landed
--      and we retry, the new tx fails and the row goes to claim_failed.
--   2. Webhook handler + 30s background sweep have no single-flight; both
--      can call claim_swap on the same row concurrently.
--   3. claim_failed retries every 30s forever with no cap, no backoff, no
--      escape — a permanently-broken row burns Boltz/Electrum quota
--      indefinitely.
--
-- This migration adds the columns needed to fix all three at once:
--   - claim_tx_hex / claim_path / current_fee_rate persist the constructed
--     tx so retries re-broadcast THE SAME tx instead of building a new one.
--   - claim_attempts / next_claim_attempt_at drive bounded retries with
--     exponential backoff.
--   - cooperative_refused tracks whether Boltz refused the cooperative
--     MuSig2 partial-sig endpoint, so the next attempt takes the script
--     path instead of looping forever on cooperative.
--   - last_claim_error / last_claim_error_at give operators something
--     useful to read when a swap reaches claim_stuck.
--
-- Two new status values arrive with this migration (validated in the Rust
-- enum at db.rs SwapStatus, no DB-level CHECK constraint):
--   - 'claim_stuck'      — exhausted retry budget; manual intervention.
--   - 'lockup_refunded'  — Boltz auto-refunded its lockup before we
--                          claimed; the user lost the LN side. P0 alert.

ALTER TABLE swap_records
    ADD COLUMN claim_tx_hex          TEXT,
    ADD COLUMN claim_path            TEXT,
    ADD COLUMN claim_attempts        INT  NOT NULL DEFAULT 0,
    ADD COLUMN next_claim_attempt_at TIMESTAMPTZ,
    ADD COLUMN current_fee_rate      DOUBLE PRECISION,
    ADD COLUMN last_claim_error      TEXT,
    ADD COLUMN last_claim_error_at   TIMESTAMPTZ,
    ADD COLUMN cooperative_refused   BOOLEAN NOT NULL DEFAULT FALSE;

-- Defensive column-level allowlist for claim_path. The application code
-- only ever writes 'cooperative' or 'script', but a stray UPDATE from a
-- runbook should fail loudly rather than silently corrupt the row.
ALTER TABLE swap_records
    ADD CONSTRAINT swap_records_claim_path_chk
        CHECK (claim_path IS NULL OR claim_path IN ('cooperative', 'script'));

-- Background-sweep filter: rows that are claimable AND ready to retry.
-- The partial-index predicate matches the sweep query exactly; the
-- ORDER BY next_claim_attempt_at ASC NULLS FIRST drives oldest-ready-
-- first scheduling.
CREATE INDEX idx_swap_records_ready_to_claim
    ON swap_records (next_claim_attempt_at NULLS FIRST)
    WHERE status IN ('pending', 'lockup_mempool', 'lockup_confirmed',
                     'claiming', 'claim_failed');

-- Reconciler scan: oldest non-terminal first, capped per cycle. Predicate
-- mirrors the reconciler's "non-terminal" set (claim_stuck and
-- lockup_refunded are terminal — no Boltz state can recover them).
CREATE INDEX idx_swap_records_non_terminal_age
    ON swap_records (updated_at)
    WHERE status NOT IN ('claimed', 'expired', 'lockup_refunded',
                         'claim_stuck');

-- Post-#45991 pattern: when this migration is applied as `postgres`, the
-- new columns/indexes inherit the table's existing GRANTs, but a re-grant
-- belt-and-suspenders ensures the runtime role can read/write all columns
-- including the new ones. Guarded by pg_roles existence so fresh dev DBs
-- without the `payservice` role can still apply this migration.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON swap_records
            TO payservice;
    END IF;
END
$$;

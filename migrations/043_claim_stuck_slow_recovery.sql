-- Low-frequency recovery bookkeeping for funded swaps that exhausted their
-- normal claim retry budget and entered `claim_stuck` (issue #63).
--
-- `claim_stuck` was an abandonment policy: every claim-sweep selection query
-- excludes it, so a funded, still-claimable output stranded during a backend
-- outage (Liquid/Bitcoin down, fee mismatch, cooperative-claim unavailable,
-- deploy bug) is never retried again even after health returns. These columns
-- let a bounded, low-frequency recovery sweep revive such rows back into the
-- normal claim path on a long, persisted, capped backoff — without a hot loop
-- and without duplicating the (battle-tested) claim engine.
--
-- `slow_attempts` counts slow-recovery revivals (distinct from `claim_attempts`,
-- the fast in-cycle counter). `next_slow_attempt_at` gates the next revival and
-- is persisted so the schedule survives restarts.

ALTER TABLE swap_records
    ADD COLUMN slow_attempts        INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN next_slow_attempt_at TIMESTAMPTZ;

ALTER TABLE chain_swap_records
    ADD COLUMN slow_attempts        INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN next_slow_attempt_at TIMESTAMPTZ;

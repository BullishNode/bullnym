-- Phase 3 of the BTC on-chain refund waterfall (#33): quote renegotiation.
--
-- When a payer under- or over-pays the BTC lockup, Boltz emits
-- `transaction.lockupFailed`. Instead of stranding the funds (refund_due), we
-- call Boltz get_quote/accept_quote to settle the swap at the amount actually
-- locked. `renegotiated_server_lock_amount_sat` records the server-lockup
-- amount Boltz accepted for that renegotiation; the claimer credits the
-- merchant this value (falling back to the original `server_lock_amount_sat`
-- when NULL, i.e. no renegotiation occurred). `renegotiated_at` timestamps it
-- for operator forensics and is NULL for the un-renegotiated common case.
ALTER TABLE chain_swap_records
    ADD COLUMN IF NOT EXISTS renegotiated_server_lock_amount_sat BIGINT,
    ADD COLUMN IF NOT EXISTS renegotiated_at TIMESTAMPTZ;

-- =====================================================================
-- SUPERSEDED — applied 2026-05-01, then reverted by migration 013.
--
-- DO NOT REINTRODUCE `ON UPDATE CASCADE` on `users.nym` FKs. The current
-- design (since 013) is: nyms are permanently reserved to their original
-- npub; re-registering under a new nym INSERTs a new row instead of
-- renaming. Renaming via cascade would silently re-attribute a user's
-- prior swap history to the new nym, which is wrong for an audit trail.
--
-- This file is kept (not deleted) because:
--   1. It was applied to prod, so deleting it would break fresh-DB replay
--      against the prod migration history.
--   2. Leaving the rationale here means the next person grepping for
--      `users_nym_fkey` finds the "why we don't cascade" explanation
--      instead of guessing.
-- See 013_users_nym_no_cascade.sql for the revert + the policy.
-- =====================================================================
-- Re-register-after-deregister fix (original rationale, now obsolete).
--
-- BIP85 ties a phone's npub to a single seed, so a user who deregisters
-- one nym and registers a new one keeps the same npub. `reactivate_user`
-- handles this by `UPDATE users SET nym = $new_nym WHERE npub = $same`.
-- That rename violated the FKs on `swap_records.nym` and
-- `outpoint_addresses.nym` whenever the old nym had any history. Hit
-- prod 2026-05-01 (tester1 → tester2 retry returned 500).
--
-- ON UPDATE CASCADE propagates the rename through both child tables in
-- the same transaction. Old history follows the new nym, which matches
-- `reactivate_user`'s existing intent (it already wipes the descriptor
-- and resets `next_addr_idx`, treating the row as the same user under
-- a new label).

ALTER TABLE swap_records
    DROP CONSTRAINT IF EXISTS swap_records_nym_fkey;
ALTER TABLE swap_records
    ADD CONSTRAINT swap_records_nym_fkey
    FOREIGN KEY (nym) REFERENCES users(nym) ON UPDATE CASCADE;

ALTER TABLE outpoint_addresses
    DROP CONSTRAINT IF EXISTS outpoint_addresses_nym_fkey;
ALTER TABLE outpoint_addresses
    ADD CONSTRAINT outpoint_addresses_nym_fkey
    FOREIGN KEY (nym) REFERENCES users(nym) ON UPDATE CASCADE ON DELETE CASCADE;

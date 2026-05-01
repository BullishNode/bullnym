-- Track whether a registered nym has ever been used (Lightning swap
-- created OR Liquid LUD-22 callback succeeded). Status only — current
-- limit logic ignores this column. Reserved as a hook for later abuse
-- handling (e.g., bulk-deactivating unused nyms registered by squatters).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS has_been_used BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill existing rows. Any row that has a swap_record OR an
-- outpoint_addresses entry OR has advanced its address index has, by
-- definition, been used.
UPDATE users SET has_been_used = TRUE
 WHERE has_been_used = FALSE
   AND (
       next_addr_idx > 0
    OR EXISTS (SELECT 1 FROM swap_records       sr WHERE sr.nym = users.nym)
    OR EXISTS (SELECT 1 FROM outpoint_addresses oa WHERE oa.nym = users.nym)
   );

CREATE INDEX IF NOT EXISTS idx_users_npub_has_been_used
    ON users (npub) WHERE has_been_used = FALSE;

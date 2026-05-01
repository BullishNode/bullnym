-- Revert 012's ON UPDATE CASCADE on users.nym FKs.
--
-- The right semantic is: a nym, once registered, is permanently
-- attached to its original npub. Re-registering under a new nym from
-- the same key inserts a fresh user row instead of renaming the old
-- one — see register handler. With no rename path, there is no need
-- for cascade, and removing it preserves audit trail (a swap_record
-- always points at the nym that owned the address at swap creation
-- time).

ALTER TABLE swap_records
    DROP CONSTRAINT IF EXISTS swap_records_nym_fkey;
ALTER TABLE swap_records
    ADD CONSTRAINT swap_records_nym_fkey
    FOREIGN KEY (nym) REFERENCES users(nym);

ALTER TABLE outpoint_addresses
    DROP CONSTRAINT IF EXISTS outpoint_addresses_nym_fkey;
ALTER TABLE outpoint_addresses
    ADD CONSTRAINT outpoint_addresses_nym_fkey
    FOREIGN KEY (nym) REFERENCES users(nym) ON DELETE CASCADE;

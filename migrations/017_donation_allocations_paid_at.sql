-- Phase 4: per-donator payment status tracking on Liquid donations.
--
-- The chain watcher sets `last_paid_at = now()` when it observes a payment
-- at a `donation_allocations.address_index`. The donation-status endpoint
-- polled by the public donation page reads this column to flip the UI
-- from "waiting" to "paid".
--
-- Each donation_allocations row gets a unique address_index (the MISS
-- path bumps users.next_addr_idx to avoid two anonymous donators sharing
-- the same Liquid address). So `last_paid_at` is per-donator, not
-- per-recipient-address.

ALTER TABLE donation_allocations
    ADD COLUMN last_paid_at TIMESTAMPTZ;

-- Hot index for chain-watcher's per-(nym, address_index) update path.
-- Covers `WHERE nym = $1 AND address_index = $2` queries.
CREATE INDEX donation_allocations_paid_lookup_idx
    ON donation_allocations (nym, address_index);

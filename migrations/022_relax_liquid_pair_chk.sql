-- ============================================================================
-- 022: Relax invoices_liquid_pair_chk for wallet-supplied addresses
-- ============================================================================
--
-- Migration 019 added a symmetric constraint:
--   (liquid_address IS NULL  AND liquid_address_index IS NULL) OR
--   (liquid_address NOT NULL AND liquid_address_index NOT NULL)
--
-- That captured the legacy descriptor-allocator invariant: every Liquid
-- address came from `users.next_addr_idx` and carried its index.
--
-- The Get-paid wallet path (Steps 5–6) inserts wallet-supplied
-- liquid_address rows with `liquid_address_index = NULL` — there is no
-- server-side derivation. The symmetry constraint blocks those inserts.
--
-- The remaining real invariant is one-directional: if an index is set,
-- the address must also be set (the legacy allocator never bumps the
-- index without writing the derived address). The reverse — address
-- without index — is the new wallet path and must be allowed.
-- ============================================================================

BEGIN;

ALTER TABLE invoices DROP CONSTRAINT invoices_liquid_pair_chk;
ALTER TABLE invoices ADD CONSTRAINT invoices_liquid_pair_chk
  CHECK (liquid_address_index IS NULL OR liquid_address IS NOT NULL);

COMMIT;

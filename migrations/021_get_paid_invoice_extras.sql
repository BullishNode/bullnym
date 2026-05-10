-- ============================================================================
-- 021: Get-paid invoice extras + on-chain BTC + in_progress status
-- ============================================================================
--
-- Adds the schema layer for the "Get paid" feature:
--   - in_progress status for mempool-seen / unconfirmed payments
--   - 'bitcoin' added to paid_via enum (on-chain BTC settlement)
--   - new fields: bitcoin_address, accept_btc/ln/liquid, public_description, invoice_number
--   - coherence CHECKs for rail/address pairing
--   - identity rewrite: nym → nym_owner (nullable for unlinked invoices)
--                       + npub_owner (canonical, NOT NULL after backfill)
--   - address-keyed indexes for the watchers
--   - npub-keyed list index for the dashboard
--   - widened GC partial index to include in_progress
--
-- Pre-condition: 020_pre_get_paid_user_wipe.sql has been applied (operator-gated).
-- This migration is safe to apply with empty users + invoices tables; the backfill
-- step is a no-op in that case but is preserved for defensive correctness.
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. Status enum: add 'in_progress'
-- ----------------------------------------------------------------------------
ALTER TABLE invoices DROP CONSTRAINT invoices_status_check;
ALTER TABLE invoices ADD CONSTRAINT invoices_status_check
  CHECK (status IN ('unpaid','in_progress','paid','underpaid','overpaid','expired','cancelled'));

-- ----------------------------------------------------------------------------
-- 2. paid_via enum: add 'bitcoin' (on-chain BTC settlement)
-- ----------------------------------------------------------------------------
ALTER TABLE invoices DROP CONSTRAINT invoices_paid_via_check;
ALTER TABLE invoices ADD CONSTRAINT invoices_paid_via_check
  CHECK (paid_via IS NULL OR paid_via IN ('lightning', 'liquid', 'bitcoin'));

-- ----------------------------------------------------------------------------
-- 3. Widen the status↔paid_via coherence CHECK to permit in_progress + NULL
-- ----------------------------------------------------------------------------
ALTER TABLE invoices DROP CONSTRAINT invoices_paid_via_chk;
ALTER TABLE invoices ADD CONSTRAINT invoices_paid_via_chk CHECK (
    (status IN ('unpaid', 'in_progress', 'expired', 'cancelled') AND paid_via IS NULL)
 OR (status IN ('paid', 'underpaid', 'overpaid')                 AND paid_via IS NOT NULL)
);

-- ----------------------------------------------------------------------------
-- 4. New invoice columns
-- ----------------------------------------------------------------------------
ALTER TABLE invoices
  ADD COLUMN bitcoin_address    TEXT
    CHECK (bitcoin_address IS NULL OR length(bitcoin_address) BETWEEN 14 AND 90),
  ADD COLUMN accept_btc         BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN accept_ln          BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN accept_liquid      BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN public_description TEXT
    CHECK (public_description IS NULL OR length(public_description) <= 1000),
  ADD COLUMN invoice_number     TEXT
    CHECK (invoice_number IS NULL OR length(invoice_number) <= 50);

-- recipient_name uses the existing recipient_label column. JSON wire-name alias
-- via #[serde(rename = "recipient_name")] on the handler request struct (no
-- column rename — defer that to a v2 schema migration if ever needed).

-- ----------------------------------------------------------------------------
-- 5. Coherence CHECKs (server review A5)
-- ----------------------------------------------------------------------------
-- BTC rail accepted ⇒ bitcoin_address must be present.
ALTER TABLE invoices ADD CONSTRAINT invoices_btc_pair_chk
  CHECK (accept_btc = FALSE OR bitcoin_address IS NOT NULL);

-- LN or Liquid rail accepted ⇒ liquid_address must be present (one address
-- serves both: LN claim destination + Liquid direct deposit).
ALTER TABLE invoices ADD CONSTRAINT invoices_ln_or_liquid_addr_chk
  CHECK ((accept_ln = FALSE AND accept_liquid = FALSE) OR liquid_address IS NOT NULL);

-- At least one rail must be accepted; an invoice with all three FALSE has no
-- way to be paid.
ALTER TABLE invoices ADD CONSTRAINT invoices_at_least_one_rail_chk
  CHECK (accept_btc OR accept_ln OR accept_liquid);

-- ----------------------------------------------------------------------------
-- 6. Widen checkout_no_metadata_chk for new wallet-only fields
-- ----------------------------------------------------------------------------
-- Defense-in-depth: anonymous checkout senders cannot inject public_description
-- or invoice_number any more than they can inject memo or recipient_label.
ALTER TABLE invoices DROP CONSTRAINT invoices_checkout_no_metadata_chk;
ALTER TABLE invoices ADD CONSTRAINT invoices_checkout_no_metadata_chk
  CHECK (origin = 'wallet'
      OR (memo               IS NULL
          AND recipient_label    IS NULL
          AND public_description IS NULL
          AND invoice_number     IS NULL));

-- ----------------------------------------------------------------------------
-- 7. Identity rewrite: nym → nym_owner (nullable for unlinked) + npub_owner
-- ----------------------------------------------------------------------------
-- nym_owner: pointer back to the merchant's payment-page nym. NULL for unlinked
-- (wallet-created standalone) invoices. ON DELETE SET NULL preserves invoice
-- history if the merchant deletes their nym (rather than the previous
-- ON DELETE CASCADE which would have wiped invoices alongside the nym).
ALTER TABLE invoices ADD COLUMN nym_owner TEXT
  REFERENCES users(nym) ON UPDATE CASCADE ON DELETE SET NULL;

-- npub_owner: canonical recipient identity, hex-encoded x-only Schnorr pubkey.
-- Required for npub-keyed dashboard list and for cross-npub authorisation
-- checks (an npub can list/cancel only its own invoices).
ALTER TABLE invoices ADD COLUMN npub_owner TEXT
  CHECK (npub_owner ~ '^[0-9a-f]{64}$');

-- ----------------------------------------------------------------------------
-- 8. Backfill (no-op when applied after the operator-gated wipe; preserved for
--    defensive correctness if applied to any non-empty state)
-- ----------------------------------------------------------------------------
UPDATE invoices i
   SET nym_owner  = i.nym,
       npub_owner = u.npub
  FROM users u
 WHERE u.nym = i.nym;

-- ----------------------------------------------------------------------------
-- 9. After backfill, npub_owner becomes required.
-- ----------------------------------------------------------------------------
ALTER TABLE invoices ALTER COLUMN npub_owner SET NOT NULL;

-- ----------------------------------------------------------------------------
-- 10. Drop legacy nym column (auto-drops the FK + dependent indexes:
--     invoices_nym_status_idx, invoices_nym_created_idx, invoices_unpaid_liquid_idx)
-- ----------------------------------------------------------------------------
ALTER TABLE invoices DROP COLUMN nym;

-- Explicit DROP IF EXISTS for safety — these indexes were column-dependent
-- and should already be gone, but the IF EXISTS guard makes this idempotent
-- across replays and against manually-applied schema variants.
DROP INDEX IF EXISTS invoices_nym_status_idx;
DROP INDEX IF EXISTS invoices_nym_created_idx;
DROP INDEX IF EXISTS invoices_unpaid_liquid_idx;

-- ----------------------------------------------------------------------------
-- 11. New indexes (address-keyed for chain_watcher; address-keyed for
--     bitcoin_watcher; npub-keyed for dashboard)
-- ----------------------------------------------------------------------------

-- Liquid scan covers linked + unlinked invoices uniformly.
CREATE INDEX invoices_unpaid_liquid_addr_idx
  ON invoices (liquid_address)
  WHERE status IN ('unpaid', 'in_progress')
    AND accept_liquid = TRUE
    AND liquid_address IS NOT NULL;

-- Bitcoin scan, same shape.
CREATE INDEX invoices_unpaid_btc_addr_idx
  ON invoices (bitcoin_address)
  WHERE status IN ('unpaid', 'in_progress')
    AND accept_btc = TRUE
    AND bitcoin_address IS NOT NULL;

-- Dashboard list: npub-keyed, status-filterable, newest-first.
CREATE INDEX invoices_npub_owner_status_created_idx
  ON invoices (npub_owner, status, created_at DESC);

-- ----------------------------------------------------------------------------
-- 12. GC partial index: widen to include in_progress (mempool-seen but not
--     yet confirmed; can still expire if the broadcast tx never confirms).
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS invoices_unpaid_expiry_idx;
CREATE INDEX invoices_unpaid_or_inprog_expiry_idx
  ON invoices (expires_at)
  WHERE status IN ('unpaid', 'in_progress');

-- ----------------------------------------------------------------------------
-- 13. Re-grant payservice (defense-in-depth per #45991 — fresh objects added
--     above inherit the right grants even when applied as `postgres`)
-- ----------------------------------------------------------------------------
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON invoices TO payservice;
  END IF;
END $$;

COMMIT;

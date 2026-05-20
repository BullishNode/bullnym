-- ============================================================================
-- 029: Keep checkout underpaid Liquid attempts watchable until outer expiry
-- ============================================================================
--
-- ITEM-002 lets stale checkout partials become `underpaid`, but direct Liquid
-- top-ups already sent to the same address must still be discoverable. This
-- index mirrors the widened chain-watcher candidate predicate.
-- ============================================================================

BEGIN;

CREATE INDEX IF NOT EXISTS invoices_liquid_addr_watch_idx
  ON invoices (created_at)
  WHERE (
      status IN ('unpaid','in_progress','partially_paid')
      OR (origin = 'checkout' AND status = 'underpaid')
    )
    AND accept_liquid = TRUE
    AND liquid_address IS NOT NULL
    AND liquid_blinding_key_hex IS NOT NULL;

COMMIT;

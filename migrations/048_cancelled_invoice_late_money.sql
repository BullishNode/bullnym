-- ============================================================================
-- 048: Honest accounting for money received after invoice cancellation
-- ============================================================================
--
-- Cancellation closes payment instructions; it does not erase an address,
-- unwind an in-flight payment, or authorize dropping money that later lands.
-- Keep the durable lifecycle marker (`status = 'cancelled'`) while allowing
-- the accounting projection to identify the received rail and amount. The
-- same coherence rule covers expired invoices, whose addresses remain capable
-- of receiving a payment after their instruction deadline.
-- ============================================================================

BEGIN;

ALTER TABLE invoices DROP CONSTRAINT invoices_paid_via_chk;
ALTER TABLE invoices ADD CONSTRAINT invoices_paid_via_or_closed_chk CHECK (
    (status IN ('unpaid', 'in_progress') AND paid_via IS NULL)
 OR (status IN ('partially_paid', 'paid', 'underpaid', 'overpaid') AND paid_via IS NOT NULL)
 OR status IN ('cancelled', 'expired')
);

COMMIT;

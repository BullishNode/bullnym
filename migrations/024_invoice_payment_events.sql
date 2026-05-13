-- ============================================================================
-- 024: Invoice payment events + partial-payment accounting
-- ============================================================================
--
-- Keep the existing invoice object, but stop using a single terminal paid flip
-- as accounting truth. Payment events are idempotent evidence; invoices cache
-- cumulative received sats in the existing paid_amount_sat column.
-- ============================================================================

BEGIN;

ALTER TABLE invoices DROP CONSTRAINT invoices_status_check;
ALTER TABLE invoices ADD CONSTRAINT invoices_status_check
  CHECK (status IN ('unpaid','in_progress','partially_paid','paid','underpaid','overpaid','expired','cancelled'));

ALTER TABLE invoices DROP CONSTRAINT invoices_paid_via_check;
ALTER TABLE invoices ADD CONSTRAINT invoices_paid_via_check
  CHECK (paid_via IS NULL OR paid_via IN ('lightning', 'liquid', 'bitcoin', 'mixed'));

ALTER TABLE invoices DROP CONSTRAINT invoices_paid_via_chk;
ALTER TABLE invoices ADD CONSTRAINT invoices_paid_via_chk CHECK (
    (status IN ('unpaid', 'in_progress', 'expired', 'cancelled') AND paid_via IS NULL)
 OR (status IN ('partially_paid', 'paid', 'underpaid', 'overpaid') AND paid_via IS NOT NULL)
);

ALTER TABLE invoices
  ADD COLUMN pricing_mode TEXT NOT NULL DEFAULT 'sat_fixed'
    CHECK (pricing_mode IN ('sat_fixed', 'fiat_fixed')),
  ADD COLUMN settlement_status TEXT NOT NULL DEFAULT 'none'
    CHECK (settlement_status IN ('none', 'pending', 'settled', 'claim_stuck', 'refunded', 'failed')),
  ADD COLUMN liquid_blinding_key_hex TEXT CHECK (
    liquid_blinding_key_hex IS NULL OR liquid_blinding_key_hex ~ '^[0-9a-fA-F]{64}$'
  );

ALTER TABLE swap_records ALTER COLUMN nym DROP NOT NULL;

CREATE TABLE invoice_payment_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    rail TEXT NOT NULL CHECK (rail IN ('bitcoin', 'liquid', 'lightning')),
    event_key TEXT NOT NULL UNIQUE,
    amount_sat BIGINT NOT NULL CHECK (amount_sat > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX invoice_payment_events_invoice_idx
  ON invoice_payment_events(invoice_id, created_at ASC);

DROP INDEX IF EXISTS invoices_unpaid_or_inprog_expiry_idx;
CREATE INDEX invoices_active_expiry_idx
  ON invoices (expires_at)
  WHERE status IN ('unpaid','in_progress','partially_paid');

DROP INDEX IF EXISTS invoices_liquid_addr_active_idx;
CREATE INDEX invoices_liquid_addr_active_idx
  ON invoices (liquid_address)
  WHERE status IN ('unpaid','in_progress','partially_paid')
    AND liquid_address IS NOT NULL;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON invoice_payment_events
            TO payservice;
    END IF;
END
$$;

COMMIT;

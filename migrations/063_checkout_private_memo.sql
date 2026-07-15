-- ============================================================================
-- 063: checkout private memo contract
-- ============================================================================
--
-- Page and POS checkout accept a payer/terminal note and persist it in
-- invoices.memo for the authenticated merchant's private invoice history.
-- Migration 021's metadata constraint predated that current product contract
-- and still classified memo as wallet-only, so any checkout carrying a note
-- failed at INSERT.  Keep the genuinely wallet-only presentation fields
-- unavailable to anonymous checkout while allowing the private memo.

BEGIN;

ALTER TABLE invoices
    DROP CONSTRAINT invoices_checkout_no_metadata_chk,
    ADD CONSTRAINT invoices_checkout_no_metadata_chk CHECK (
        origin = 'wallet'
        OR (
            recipient_label IS NULL
            AND public_description IS NULL
            AND invoice_number IS NULL
        )
    );

COMMENT ON CONSTRAINT invoices_checkout_no_metadata_chk ON invoices IS
    'Checkout may carry a private memo; recipient label, public description, and invoice number remain wallet-only.';

COMMIT;

-- ============================================================================
-- 073: separate unpaid invoice expiry from unfunded provider-order watching
-- ============================================================================
--
-- A fiat-only Bull Bitcoin payer instruction is a real late-payment surface,
-- but binding that instruction is not evidence that the payer sent money.
-- Once the parent invoice expires or is cancelled, a never-funded provider row
-- remains locally auditable and pollable without keeping the invoice's public
-- settlement aggregate pending or unavailable.

BEGIN;

CREATE OR REPLACE FUNCTION sync_invoice_bull_bitcoin_settlement_status()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_invoice_id UUID := COALESCE(NEW.invoice_id, OLD.invoice_id);
BEGIN
    IF target_invoice_id IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE invoices invoice
       SET fiat_settlement_status = projection.status
      FROM (
          SELECT CASE
              WHEN BOOL_OR(settlement.settlement_status = 'integrity_error')
                  THEN 'integrity_error'
              WHEN BOOL_OR(settlement.settlement_status = 'unavailable')
                  THEN 'unavailable'
              WHEN BOOL_OR(settlement.settlement_status = 'pending')
                  THEN 'pending'
              WHEN BOOL_OR(settlement.settlement_status = 'settled')
                  THEN 'settled'
              ELSE 'none'
          END AS status
          FROM bull_bitcoin_settlements settlement
          JOIN invoices parent ON parent.id = target_invoice_id
          WHERE settlement.invoice_id = target_invoice_id
            AND settlement.provider_state = 'bound'
            AND settlement.funding_route = 'bull_bitcoin'
            AND settlement.funding_committed_at IS NOT NULL
            AND NOT (
                parent.status IN ('expired', 'cancelled')
                AND COALESCE(parent.presentation_status, parent.status) = 'unpaid'
                AND settlement.purpose = 'fiat_only'
                AND settlement.actual_received_sat IS NULL
                AND NOT settlement.provider_final
                AND settlement.settlement_status IN ('pending', 'unavailable')
                AND NOT EXISTS (
                    SELECT 1 FROM invoice_payment_events event
                     WHERE event.invoice_id = parent.id
                )
            )
      ) projection
     WHERE invoice.id = target_invoice_id
       AND invoice.fiat_settlement_status IS DISTINCT FROM projection.status;
    RETURN NULL;
END
$$;

DROP TRIGGER bull_bitcoin_settlements_sync_invoice_status
    ON bull_bitcoin_settlements;

CREATE TRIGGER bull_bitcoin_settlements_sync_invoice_status
    AFTER INSERT OR UPDATE OF provider_state, funding_route,
        funding_committed_at, settlement_status, actual_received_sat,
        provider_final
    ON bull_bitcoin_settlements
    FOR EACH ROW EXECUTE FUNCTION sync_invoice_bull_bitcoin_settlement_status();

-- Reproject any terminal parent rows that predate this migration. This is an
-- idempotent no-value update whose only intended effect is the AFTER trigger.
UPDATE bull_bitcoin_settlements settlement
   SET actual_received_sat = actual_received_sat
 WHERE settlement.invoice_id IS NOT NULL
   AND settlement.provider_state = 'bound'
   AND settlement.funding_route = 'bull_bitcoin'
   AND settlement.funding_committed_at IS NOT NULL
   AND settlement.purpose = 'fiat_only'
   AND settlement.actual_received_sat IS NULL
   AND NOT settlement.provider_final
   AND EXISTS (
       SELECT 1 FROM invoices invoice
        WHERE invoice.id = settlement.invoice_id
          AND invoice.status IN ('expired', 'cancelled')
          AND COALESCE(invoice.presentation_status, invoice.status) = 'unpaid'
          AND NOT EXISTS (
              SELECT 1 FROM invoice_payment_events event
               WHERE event.invoice_id = invoice.id
          )
   );

REVOKE ALL ON FUNCTION sync_invoice_bull_bitcoin_settlement_status()
    FROM PUBLIC;

COMMIT;

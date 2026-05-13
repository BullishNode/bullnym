-- ============================================================================
-- 028: Structured invoice payment evidence
-- ============================================================================
--
-- invoice_payment_events is the accounting source for invoice status changes.
-- The original event_key values were idempotent but opaque. Store the concrete
-- evidence fields separately so operators can inspect the tx output or Boltz
-- claim transaction that credited an invoice without parsing strings.
-- ============================================================================

BEGIN;

ALTER TABLE invoice_payment_events
  ADD COLUMN source TEXT,
  ADD COLUMN txid TEXT,
  ADD COLUMN vout INTEGER,
  ADD COLUMN boltz_swap_id TEXT,
  ADD COLUMN address TEXT;

UPDATE invoice_payment_events e
   SET source = 'bitcoin_direct',
       txid = split_part(e.event_key, ':', 2),
       vout = split_part(e.event_key, ':', 3)::INTEGER,
       address = i.bitcoin_address
  FROM invoices i
 WHERE e.invoice_id = i.id
   AND i.bitcoin_address IS NOT NULL
   AND e.event_key ~ '^bitcoin_direct:[0-9a-fA-F]{64}:[0-9]+$';

UPDATE invoice_payment_events e
   SET source = 'liquid_direct',
       txid = split_part(e.event_key, ':', 2),
       vout = split_part(e.event_key, ':', 3)::INTEGER,
       address = i.liquid_address
  FROM invoices i
 WHERE e.invoice_id = i.id
   AND i.liquid_address IS NOT NULL
   AND e.event_key ~ '^liquid_direct:[0-9a-fA-F]{64}:[0-9]+$';

UPDATE invoice_payment_events e
   SET source = 'lightning_boltz_reverse',
       boltz_swap_id = s.boltz_swap_id,
       txid = s.claim_txid
  FROM swap_records s
 WHERE e.event_key = 'lightning_boltz_reverse:' || s.boltz_swap_id
   AND s.claim_txid IS NOT NULL;

UPDATE invoice_payment_events e
   SET source = 'bitcoin_boltz_chain',
       boltz_swap_id = c.boltz_swap_id,
       txid = c.claim_txid
  FROM chain_swap_records c
 WHERE e.event_key = 'bitcoin_boltz_chain:' || c.boltz_swap_id
   AND c.claim_txid IS NOT NULL;

ALTER TABLE invoice_payment_events
  ADD CONSTRAINT invoice_payment_events_source_chk
  CHECK (
    source IS NULL OR source IN (
      'bitcoin_direct',
      'liquid_direct',
      'lightning_boltz_reverse',
      'bitcoin_boltz_chain'
    )
  );

ALTER TABLE invoice_payment_events
  ADD CONSTRAINT invoice_payment_events_source_rail_chk
  CHECK (
    source IS NULL OR (
      (source = 'bitcoin_direct' AND rail = 'bitcoin') OR
      (source = 'bitcoin_boltz_chain' AND rail = 'bitcoin') OR
      (source = 'liquid_direct' AND rail = 'liquid') OR
      (source = 'lightning_boltz_reverse' AND rail = 'lightning')
    )
  );

ALTER TABLE invoice_payment_events
  ADD CONSTRAINT invoice_payment_events_direct_evidence_chk
  CHECK (
    source IS NULL OR source NOT IN ('bitcoin_direct', 'liquid_direct') OR (
      txid IS NOT NULL
      AND txid ~ '^[0-9a-fA-F]{64}$'
      AND vout IS NOT NULL
      AND vout >= 0
      AND address IS NOT NULL
      AND boltz_swap_id IS NULL
    )
  );

ALTER TABLE invoice_payment_events
  ADD CONSTRAINT invoice_payment_events_boltz_evidence_chk
  CHECK (
    source IS NULL OR source NOT IN ('lightning_boltz_reverse', 'bitcoin_boltz_chain') OR (
      txid IS NOT NULL
      AND txid ~ '^[0-9a-fA-F]{64}$'
      AND boltz_swap_id IS NOT NULL
      AND vout IS NULL
    )
  );

COMMIT;

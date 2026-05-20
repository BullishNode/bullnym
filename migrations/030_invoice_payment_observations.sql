-- ============================================================================
-- 030: Non-accounting payment observations
-- ============================================================================
--
-- Observations are payment sightings that are useful to users and operators but
-- are not accounting truth. They must never be summed into paid_amount_sat.
-- Confirmed/counted value still flows only through invoice_payment_events.
-- ============================================================================

BEGIN;

CREATE TABLE invoice_payment_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    rail TEXT NOT NULL CHECK (rail = 'bitcoin'),
    source TEXT NOT NULL CHECK (source = 'bitcoin_direct'),
    event_key TEXT NOT NULL UNIQUE CHECK (
        event_key ~ '^bitcoin_direct:[0-9a-fA-F]{64}:[0-9]+$'
        AND event_key = 'bitcoin_direct:' || txid || ':' || vout::TEXT
    ),
    txid TEXT NOT NULL CHECK (txid ~ '^[0-9a-fA-F]{64}$'),
    vout INTEGER NOT NULL CHECK (vout >= 0),
    address TEXT NOT NULL CHECK (length(address) BETWEEN 14 AND 90),
    amount_sat BIGINT NOT NULL CHECK (amount_sat > 0),
    confirmations INTEGER NOT NULL DEFAULT 0 CHECK (confirmations >= 0),
    block_height INTEGER CHECK (block_height IS NULL OR block_height > 0),
    last_seen_state TEXT NOT NULL CHECK (
        last_seen_state IN ('seen_unconfirmed', 'awaiting_confirmations', 'counted', 'not_seen')
    ),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (last_seen_state = 'seen_unconfirmed' AND confirmations = 0 AND block_height IS NULL)
     OR (last_seen_state IN ('awaiting_confirmations', 'counted') AND confirmations > 0 AND block_height IS NOT NULL)
     OR (last_seen_state = 'not_seen')
    )
);

CREATE INDEX invoice_payment_observations_invoice_seen_idx
  ON invoice_payment_observations(invoice_id, last_seen_at DESC);

CREATE INDEX invoice_payment_observations_active_state_idx
  ON invoice_payment_observations(invoice_id, last_seen_state)
  WHERE last_seen_state IN ('seen_unconfirmed', 'awaiting_confirmations');

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON invoice_payment_observations
            TO payservice;
    END IF;
END
$$;

COMMIT;

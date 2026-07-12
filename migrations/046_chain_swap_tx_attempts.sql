-- ============================================================================
-- 046: write-ahead transaction journal for Bitcoin chain-swap recovery
-- ============================================================================
--
-- A recovery transaction must be reproducible after a crash or an ambiguous
-- broadcast response.  The exact signed bytes, source prevouts, immutable
-- destination, and fee decision therefore live in this table before any
-- broadcaster can see the transaction.
--
-- This first writer is intentionally limited to `btc_recovery`.  Liquid claim
-- adoption and replacement lineage are owned by later reliability phases.
-- ============================================================================

BEGIN;

CREATE TABLE chain_swap_tx_attempts (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_swap_id              UUID NOT NULL
                                  REFERENCES chain_swap_records(id)
                                  ON DELETE CASCADE,
    purpose                    TEXT NOT NULL DEFAULT 'btc_recovery'
                                  CHECK (purpose = 'btc_recovery'),

    raw_tx_hex                 TEXT NOT NULL
                                  CHECK (raw_tx_hex ~ '^[0-9a-f]+$'
                                     AND length(raw_tx_hex) % 2 = 0),
    txid                       TEXT NOT NULL UNIQUE
                                  CHECK (txid ~ '^[0-9a-f]{64}$'),
    source_prevouts            JSONB NOT NULL
                                  CHECK (jsonb_typeof(source_prevouts) = 'array'
                                     AND jsonb_array_length(source_prevouts) > 0),
    destination_address        TEXT NOT NULL,
    destination_script_hex     TEXT NOT NULL
                                  CHECK (destination_script_hex ~ '^[0-9a-f]+$'
                                     AND length(destination_script_hex) % 2 = 0),
    destination_vout           INTEGER NOT NULL CHECK (destination_vout >= 0),
    destination_amount_sat     BIGINT NOT NULL CHECK (destination_amount_sat > 0),
    fee_amount_sat             BIGINT NOT NULL CHECK (fee_amount_sat > 0),
    fee_rate_sat_vb            DOUBLE PRECISION NOT NULL
                                  CHECK (fee_rate_sat_vb > 0
                                     AND fee_rate_sat_vb NOT IN (
                                         'NaN'::DOUBLE PRECISION,
                                         'Infinity'::DOUBLE PRECISION,
                                         '-Infinity'::DOUBLE PRECISION
                                     )),

    status                     TEXT NOT NULL DEFAULT 'constructed'
                                  CHECK (status IN (
                                      'constructed',
                                      'broadcast_ambiguous',
                                      'broadcast',
                                      'confirmed',
                                      'finalized',
                                      'integrity_hold'
                                  )),
    broadcast_attempts         INTEGER NOT NULL DEFAULT 0
                                  CHECK (broadcast_attempts >= 0),
    last_broadcast_result      TEXT,
    integrity_reason           TEXT,
    constructed_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_broadcast_attempt_at TIMESTAMPTZ,
    last_broadcast_attempt_at  TIMESTAMPTZ,
    broadcast_at               TIMESTAMPTZ,
    confirmed_at               TIMESTAMPTZ,
    finalized_at               TIMESTAMPTZ,
    integrity_hold_at          TIMESTAMPTZ,
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One immutable initial recovery attempt per swap.  A later explicit RBF
    -- migration can replace this with lineage-aware uniqueness; #62 must not
    -- silently manufacture a second set of bytes.
    CONSTRAINT chain_swap_tx_attempts_one_recovery
        UNIQUE (chain_swap_id, purpose),
    CONSTRAINT chain_swap_tx_attempts_integrity_shape CHECK (
        (status = 'integrity_hold'
            AND integrity_reason IS NOT NULL
            AND integrity_hold_at IS NOT NULL)
        OR
        (status <> 'integrity_hold'
            AND integrity_reason IS NULL
            AND integrity_hold_at IS NULL)
    )
);

CREATE INDEX chain_swap_tx_attempts_status_idx
    ON chain_swap_tx_attempts(status, updated_at);

-- Exact transaction intent is immutable after insert.  Lifecycle/evidence
-- columns may advance, but retries can never rewrite the signed bytes,
-- destination, source prevouts, or fee decision in place.
CREATE FUNCTION guard_chain_swap_tx_attempt_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.chain_swap_id IS DISTINCT FROM OLD.chain_swap_id
       OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.raw_tx_hex IS DISTINCT FROM OLD.raw_tx_hex
       OR NEW.txid IS DISTINCT FROM OLD.txid
       OR NEW.source_prevouts IS DISTINCT FROM OLD.source_prevouts
       OR NEW.destination_address IS DISTINCT FROM OLD.destination_address
       OR NEW.destination_script_hex IS DISTINCT FROM OLD.destination_script_hex
       OR NEW.destination_vout IS DISTINCT FROM OLD.destination_vout
       OR NEW.destination_amount_sat IS DISTINCT FROM OLD.destination_amount_sat
       OR NEW.fee_amount_sat IS DISTINCT FROM OLD.fee_amount_sat
       OR NEW.fee_rate_sat_vb IS DISTINCT FROM OLD.fee_rate_sat_vb
       OR NEW.constructed_at IS DISTINCT FROM OLD.constructed_at THEN
        RAISE EXCEPTION 'chain-swap transaction intent is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER chain_swap_tx_attempts_immutable
BEFORE UPDATE ON chain_swap_tx_attempts
FOR EACH ROW
EXECUTE FUNCTION guard_chain_swap_tx_attempt_immutable();

-- `chain_swap_records.refund_address` is the compatibility copy used by the
-- existing API. Once an attempt exists, prevent even a direct SQL writer from
-- making that parent row disagree with the immutable journal destination.
CREATE FUNCTION guard_journaled_chain_swap_destination()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.refund_address IS DISTINCT FROM OLD.refund_address
       AND EXISTS (
           SELECT 1 FROM chain_swap_tx_attempts
            WHERE chain_swap_id = OLD.id AND purpose = 'btc_recovery'
       ) THEN
        RAISE EXCEPTION 'journaled chain-swap recovery destination is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER chain_swap_records_journaled_destination_immutable
BEFORE UPDATE OF refund_address ON chain_swap_records
FOR EACH ROW
EXECUTE FUNCTION guard_journaled_chain_swap_destination();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        GRANT SELECT, INSERT, UPDATE
            ON chain_swap_tx_attempts
            TO payservice;
    END IF;
END
$$;

COMMIT;

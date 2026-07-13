-- ============================================================================
-- 052: append-only chain-swap manifest delivery ledger
-- ============================================================================
--
-- This is the local durability half of issue #87. It records the exact opaque
-- encrypted envelope that a later delivery worker must create off-host. It
-- does not perform S3 I/O and does not authorize payer exposure.
--
-- The ledger deliberately has no persistent foreign key to
-- chain_swap_records: an operational cleanup must not cascade into witness
-- history. Insert-time validation locks and proves the source row in the same
-- transaction, after which the witness survives independently.

BEGIN;

CREATE TABLE chain_swap_manifest_deliveries (
    manifest_id          UUID PRIMARY KEY,
    chain_swap_id        UUID NOT NULL UNIQUE,
    manifest_sequence    BIGINT NOT NULL UNIQUE,
    previous_manifest_id UUID UNIQUE,
    encrypted_envelope   TEXT NOT NULL,
    envelope_sha256      TEXT NOT NULL,
    delivery_state       TEXT NOT NULL DEFAULT 'pending',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at         TIMESTAMPTZ,

    CONSTRAINT chain_swap_manifest_identity_non_nil_check CHECK (
        manifest_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND chain_swap_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND (
            previous_manifest_id IS NULL
            OR previous_manifest_id <> '00000000-0000-0000-0000-000000000000'::UUID
        )
    ),
    CONSTRAINT chain_swap_manifest_sequence_positive_check CHECK (
        manifest_sequence > 0
    ),
    CONSTRAINT chain_swap_manifest_sequence_link_check CHECK (
        (manifest_sequence = 1 AND previous_manifest_id IS NULL)
        OR
        (manifest_sequence > 1 AND previous_manifest_id IS NOT NULL)
    ),
    CONSTRAINT chain_swap_manifest_predecessor_not_self_check CHECK (
        previous_manifest_id IS NULL OR previous_manifest_id <> manifest_id
    ),
    CONSTRAINT chain_swap_manifest_envelope_size_check CHECK (
        octet_length(encrypted_envelope) BETWEEN 1 AND 1048576
    ),
    CONSTRAINT chain_swap_manifest_digest_shape_check CHECK (
        envelope_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chain_swap_manifest_digest_match_check CHECK (
        envelope_sha256 = encode(
            digest(convert_to(encrypted_envelope, 'UTF8'), 'sha256'),
            'hex'
        )
    ),
    CONSTRAINT chain_swap_manifest_delivery_state_check CHECK (
        delivery_state IN ('pending', 'delivered')
    ),
    CONSTRAINT chain_swap_manifest_delivered_at_check CHECK (
        (delivery_state = 'pending' AND delivered_at IS NULL)
        OR
        (
            delivery_state = 'delivered'
            AND delivered_at IS NOT NULL
            AND delivered_at >= created_at
        )
    ),
    CONSTRAINT chain_swap_manifest_previous_fkey FOREIGN KEY (previous_manifest_id)
        REFERENCES chain_swap_manifest_deliveries(manifest_id) ON DELETE RESTRICT
);

-- The pending barrier makes at most one interrupted delivery resumable. The
-- insert trigger below also checks it while holding the global tail lock.
CREATE UNIQUE INDEX chain_swap_manifest_one_pending_idx
    ON chain_swap_manifest_deliveries(delivery_state)
    WHERE delivery_state = 'pending';

CREATE FUNCTION enforce_chain_swap_manifest_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    pending_manifest UUID;
    tail_manifest UUID;
    tail_sequence BIGINT;
BEGIN
    -- Dedicated two-key transaction-lock namespace: ASCII "BULL", issue 87.
    -- Rust tail allocation takes this exact lock before it returns a sequence.
    PERFORM pg_advisory_xact_lock(1112886348, 87);

    IF NEW.delivery_state <> 'pending' OR NEW.delivered_at IS NOT NULL THEN
        RAISE EXCEPTION 'manifest delivery rows must start pending'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'chain_swap_manifest_delivered_at_check';
    END IF;

    -- This lock proves the operational source exists at insertion without
    -- making later witness retention depend on that source row.
    PERFORM 1
      FROM chain_swap_records
     WHERE id = NEW.chain_swap_id
       FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'manifest delivery source chain swap does not exist'
            USING ERRCODE = '23503',
                  TABLE = 'chain_swap_manifest_deliveries',
                  COLUMN = 'chain_swap_id',
                  CONSTRAINT = 'chain_swap_manifest_source_exists';
    END IF;

    SELECT manifest_id
      INTO pending_manifest
      FROM chain_swap_manifest_deliveries
     WHERE delivery_state = 'pending'
     ORDER BY manifest_sequence
     LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION 'a prior manifest delivery is still pending'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'chain_swap_manifest_pending_barrier';
    END IF;

    SELECT manifest_id, manifest_sequence
      INTO tail_manifest, tail_sequence
      FROM chain_swap_manifest_deliveries
     ORDER BY manifest_sequence DESC
     LIMIT 1;

    IF NOT FOUND THEN
        IF NEW.manifest_sequence <> 1 OR NEW.previous_manifest_id IS NOT NULL THEN
            RAISE EXCEPTION 'the first manifest must be sequence 1 without a predecessor'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'chain_swap_manifest_sequence_link_check';
        END IF;
    ELSE
        IF tail_sequence = 9223372036854775807 THEN
            RAISE EXCEPTION 'manifest delivery sequence exhausted BIGINT'
                USING ERRCODE = '54000';
        END IF;
        IF NEW.manifest_sequence <> tail_sequence + 1
           OR NEW.previous_manifest_id IS DISTINCT FROM tail_manifest THEN
            RAISE EXCEPTION 'manifest must extend the exact current delivery tail'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'chain_swap_manifest_sequence_link_check';
        END IF;
    END IF;

    RETURN NEW;
END
$$;

CREATE FUNCTION enforce_chain_swap_manifest_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(
        OLD.manifest_id,
        OLD.chain_swap_id,
        OLD.manifest_sequence,
        OLD.previous_manifest_id,
        OLD.encrypted_envelope,
        OLD.envelope_sha256,
        OLD.created_at
    ) IS DISTINCT FROM ROW(
        NEW.manifest_id,
        NEW.chain_swap_id,
        NEW.manifest_sequence,
        NEW.previous_manifest_id,
        NEW.encrypted_envelope,
        NEW.envelope_sha256,
        NEW.created_at
    ) THEN
        RAISE EXCEPTION 'manifest delivery identity and envelope are immutable'
            USING ERRCODE = '55000';
    END IF;

    -- Exact no-op updates make delivery acknowledgement idempotent.
    IF OLD.delivery_state = NEW.delivery_state
       AND OLD.delivered_at IS NOT DISTINCT FROM NEW.delivered_at THEN
        RETURN NEW;
    END IF;

    IF OLD.delivery_state = 'pending'
       AND OLD.delivered_at IS NULL
       AND NEW.delivery_state = 'delivered'
       AND NEW.delivered_at IS NOT NULL THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'manifest delivery state may only advance pending to delivered'
        USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION reject_chain_swap_manifest_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'manifest delivery rows are append-only and cannot be deleted'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER chain_swap_manifest_validate_insert
    BEFORE INSERT ON chain_swap_manifest_deliveries
    FOR EACH ROW EXECUTE FUNCTION enforce_chain_swap_manifest_insert();

CREATE TRIGGER chain_swap_manifest_validate_update
    BEFORE UPDATE ON chain_swap_manifest_deliveries
    FOR EACH ROW EXECUTE FUNCTION enforce_chain_swap_manifest_update();

CREATE TRIGGER chain_swap_manifest_reject_delete
    BEFORE DELETE ON chain_swap_manifest_deliveries
    FOR EACH ROW EXECUTE FUNCTION reject_chain_swap_manifest_delete();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        GRANT SELECT, INSERT, UPDATE
            ON chain_swap_manifest_deliveries
            TO payservice;
    END IF;
END
$$;

COMMIT;

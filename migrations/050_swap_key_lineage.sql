-- ============================================================================
-- 050: complete, immutable swap-key lineage for newly allocated keys
-- ============================================================================
--
-- Migration 044 recorded a seed fingerprint and child index on swap rows, but
-- its per-column partial indexes could not prevent the same derived key from
-- being used for a reverse claim, a chain claim, or a chain refund in different
-- tables.  The allocation registry below is the single global namespace for
-- all three purposes.  It stores only non-secret derivation evidence.
--
-- Existing swap rows deliberately remain legacy rows: every new lineage column
-- is nullable and this migration does not guess an epoch, scheme, public key,
-- or preimage hash for historical data.

BEGIN;

-- Migration 044's table-local partial indexes remain in place to protect
-- legacy rows. The registry supplements them with the cross-table/purpose
-- namespace that those indexes cannot provide.

CREATE TABLE swap_key_allocations (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    root_fingerprint            TEXT NOT NULL,
    key_epoch                   INTEGER NOT NULL,
    derivation_scheme_version   INTEGER NOT NULL,
    child_index                 BIGINT NOT NULL,
    purpose                     TEXT NOT NULL,
    public_key_hex              TEXT NOT NULL,
    preimage_hash_hex           TEXT,
    allocated_at                TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT swap_key_allocations_root_fingerprint_check
        CHECK (root_fingerprint ~ '^[0-9a-f]{16}$'),
    CONSTRAINT swap_key_allocations_key_epoch_check
        CHECK (key_epoch > 0),
    CONSTRAINT swap_key_allocations_scheme_version_check
        CHECK (derivation_scheme_version > 0),
    CONSTRAINT swap_key_allocations_child_index_check
        CHECK (child_index >= 0),
    CONSTRAINT swap_key_allocations_purpose_check
        CHECK (purpose IN ('reverse_claim', 'chain_claim', 'chain_refund')),
    CONSTRAINT swap_key_allocations_public_key_check
        CHECK (public_key_hex ~ '^(02|03)[0-9a-f]{64}$'),
    CONSTRAINT swap_key_allocations_preimage_hash_check
        CHECK (preimage_hash_hex IS NULL OR preimage_hash_hex ~ '^[0-9a-f]{64}$'),
    CONSTRAINT swap_key_allocations_preimage_purpose_check
        CHECK (
            (purpose IN ('reverse_claim', 'chain_claim') AND preimage_hash_hex IS NOT NULL)
            OR (purpose = 'chain_refund' AND preimage_hash_hex IS NULL)
        ),
    -- Purpose is intentionally absent: a derivation identity is global across
    -- reverse claims, chain claims, and chain refunds.
    CONSTRAINT swap_key_allocations_derivation_identity_key
        UNIQUE (root_fingerprint, key_epoch, derivation_scheme_version, child_index),
    CONSTRAINT swap_key_allocations_public_key_key UNIQUE (public_key_hex)
);

CREATE UNIQUE INDEX swap_key_allocations_preimage_hash_key
    ON swap_key_allocations (preimage_hash_hex)
    WHERE preimage_hash_hex IS NOT NULL;

-- Migration 044 intended each recorded identity to be either wholly unknown or
-- complete. Its nullable columns did not encode that shape, so fail closed
-- before calculating the permanent high-water ledger. Otherwise a corrupt
-- index with no root (or a partial chain pair) would be silently omitted and
-- could later be reused.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM swap_records
         WHERE (root_fingerprint IS NULL) <> (key_index IS NULL)
    ) THEN
        RAISE EXCEPTION
            'migration 050 refuses partially populated reverse migration-044 identities'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM chain_swap_records
         WHERE num_nonnulls(root_fingerprint, claim_key_index, refund_key_index)
               NOT IN (0, 3)
    ) THEN
        RAISE EXCEPTION
            'migration 050 refuses partially populated chain migration-044 identities'
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- Migration-044 rows may later be hard-deleted by the signed purge contract.
-- Preserve their non-secret, conservative per-root high-water mark first. One
-- row per root safely burns gaps and tolerates any historical cross-table or
-- cross-purpose reuse without making the upgrade fail.
CREATE TABLE swap_key_legacy_high_water (
    root_fingerprint   TEXT PRIMARY KEY,
    max_child_index    BIGINT NOT NULL,
    recorded_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT swap_key_legacy_high_water_root_fingerprint_check
        CHECK (root_fingerprint ~ '^[0-9a-f]{16}$'),
    CONSTRAINT swap_key_legacy_high_water_max_child_index_check
        CHECK (max_child_index >= 0)
);

INSERT INTO swap_key_legacy_high_water (root_fingerprint, max_child_index)
SELECT root_fingerprint, MAX(child_index)
  FROM (
      SELECT root_fingerprint, key_index AS child_index
        FROM swap_records
       WHERE root_fingerprint IS NOT NULL AND key_index IS NOT NULL
      UNION ALL
      SELECT root_fingerprint, claim_key_index AS child_index
        FROM chain_swap_records
       WHERE root_fingerprint IS NOT NULL AND claim_key_index IS NOT NULL
      UNION ALL
      SELECT root_fingerprint, refund_key_index AS child_index
        FROM chain_swap_records
       WHERE root_fingerprint IS NOT NULL AND refund_key_index IS NOT NULL
  ) legacy_indices
 GROUP BY root_fingerprint;

ALTER TABLE swap_records
    ADD COLUMN key_allocation_id UUID REFERENCES swap_key_allocations(id),
    ADD COLUMN key_epoch INTEGER,
    ADD COLUMN derivation_scheme_version INTEGER,
    ADD COLUMN claim_public_key_hex TEXT,
    ADD COLUMN preimage_hash_hex TEXT,
    ADD CONSTRAINT swap_records_lineage_shape_check CHECK (
        (
            key_allocation_id IS NULL
            AND key_epoch IS NULL
            AND derivation_scheme_version IS NULL
            AND claim_public_key_hex IS NULL
            AND preimage_hash_hex IS NULL
        )
        OR
        (
            key_allocation_id IS NOT NULL
            AND key_epoch IS NOT NULL
            AND derivation_scheme_version IS NOT NULL
            AND claim_public_key_hex IS NOT NULL
            AND preimage_hash_hex IS NOT NULL
            AND key_index IS NOT NULL
            AND root_fingerprint IS NOT NULL
        )
    ),
    ADD CONSTRAINT swap_records_lineage_epoch_check
        CHECK (key_epoch IS NULL OR key_epoch > 0),
    ADD CONSTRAINT swap_records_lineage_scheme_check
        CHECK (derivation_scheme_version IS NULL OR derivation_scheme_version > 0),
    ADD CONSTRAINT swap_records_claim_public_key_check
        CHECK (claim_public_key_hex IS NULL OR claim_public_key_hex ~ '^(02|03)[0-9a-f]{64}$'),
    ADD CONSTRAINT swap_records_preimage_hash_check
        CHECK (preimage_hash_hex IS NULL OR preimage_hash_hex ~ '^[0-9a-f]{64}$');

ALTER TABLE chain_swap_records
    ADD COLUMN claim_key_allocation_id UUID REFERENCES swap_key_allocations(id),
    ADD COLUMN refund_key_allocation_id UUID REFERENCES swap_key_allocations(id),
    ADD COLUMN key_epoch INTEGER,
    ADD COLUMN derivation_scheme_version INTEGER,
    ADD COLUMN claim_public_key_hex TEXT,
    ADD COLUMN refund_public_key_hex TEXT,
    ADD COLUMN preimage_hash_hex TEXT,
    ADD CONSTRAINT chain_swap_records_lineage_shape_check CHECK (
        (
            claim_key_allocation_id IS NULL
            AND refund_key_allocation_id IS NULL
            AND key_epoch IS NULL
            AND derivation_scheme_version IS NULL
            AND claim_public_key_hex IS NULL
            AND refund_public_key_hex IS NULL
            AND preimage_hash_hex IS NULL
        )
        OR
        (
            claim_key_allocation_id IS NOT NULL
            AND refund_key_allocation_id IS NOT NULL
            AND key_epoch IS NOT NULL
            AND derivation_scheme_version IS NOT NULL
            AND claim_public_key_hex IS NOT NULL
            AND refund_public_key_hex IS NOT NULL
            AND preimage_hash_hex IS NOT NULL
            AND claim_key_index IS NOT NULL
            AND refund_key_index IS NOT NULL
            AND root_fingerprint IS NOT NULL
        )
    ),
    ADD CONSTRAINT chain_swap_records_lineage_epoch_check
        CHECK (key_epoch IS NULL OR key_epoch > 0),
    ADD CONSTRAINT chain_swap_records_lineage_scheme_check
        CHECK (derivation_scheme_version IS NULL OR derivation_scheme_version > 0),
    ADD CONSTRAINT chain_swap_records_claim_public_key_check
        CHECK (claim_public_key_hex IS NULL OR claim_public_key_hex ~ '^(02|03)[0-9a-f]{64}$'),
    ADD CONSTRAINT chain_swap_records_refund_public_key_check
        CHECK (refund_public_key_hex IS NULL OR refund_public_key_hex ~ '^(02|03)[0-9a-f]{64}$'),
    ADD CONSTRAINT chain_swap_records_preimage_hash_check
        CHECK (preimage_hash_hex IS NULL OR preimage_hash_hex ~ '^[0-9a-f]{64}$');

-- An allocation may be referenced by at most one extant swap row in its
-- purpose slot. Signed purge can remove that row, but the immutable allocation
-- remains the permanent non-reuse authority; creation paths attach only their
-- freshly reserved allocation IDs. Partial indexes retain unlimited legacy
-- NULL rows.
CREATE UNIQUE INDEX swap_records_key_allocation_id_key
    ON swap_records (key_allocation_id)
    WHERE key_allocation_id IS NOT NULL;
CREATE UNIQUE INDEX chain_swap_records_claim_key_allocation_id_key
    ON chain_swap_records (claim_key_allocation_id)
    WHERE claim_key_allocation_id IS NOT NULL;
CREATE UNIQUE INDEX chain_swap_records_refund_key_allocation_id_key
    ON chain_swap_records (refund_key_allocation_id)
    WHERE refund_key_allocation_id IS NOT NULL;

-- Legacy migration-044 rows have no allocation record and their epoch/scheme
-- cannot be reconstructed. They therefore form a conservative, immutable
-- high-water exclusion for this root. Enforce it synchronously on every
-- allocation so a runtime sequence rewind cannot race the 30-second monitor,
-- expose a reused key to the provider, and then hide itself by advancing NEXT.
CREATE FUNCTION validate_swap_key_allocation_against_legacy() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    legacy_max BIGINT;
BEGIN
    SELECT MAX(idx) INTO legacy_max
      FROM (
          SELECT max_child_index AS idx
            FROM swap_key_legacy_high_water
           WHERE root_fingerprint = NEW.root_fingerprint
          UNION ALL
          SELECT key_index AS idx
            FROM swap_records
           WHERE root_fingerprint = NEW.root_fingerprint
             AND key_allocation_id IS NULL
             AND key_index IS NOT NULL
          UNION ALL
          SELECT claim_key_index AS idx
            FROM chain_swap_records
           WHERE root_fingerprint = NEW.root_fingerprint
             AND claim_key_allocation_id IS NULL
             AND refund_key_allocation_id IS NULL
             AND claim_key_index IS NOT NULL
          UNION ALL
          SELECT refund_key_index AS idx
            FROM chain_swap_records
           WHERE root_fingerprint = NEW.root_fingerprint
             AND claim_key_allocation_id IS NULL
             AND refund_key_allocation_id IS NULL
             AND refund_key_index IS NOT NULL
      ) legacy_indices;

    IF legacy_max IS NOT NULL AND NEW.child_index <= legacy_max THEN
        RAISE EXCEPTION
            'swap key allocation index % is not above legacy high-water mark % for root %',
            NEW.child_index, legacy_max, NEW.root_fingerprint
            USING ERRCODE = '23505',
                  CONSTRAINT = 'swap_key_allocations_legacy_high_water';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION validate_reverse_swap_key_lineage() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    allocation swap_key_allocations%ROWTYPE;
BEGIN
    IF NEW.key_allocation_id IS NULL THEN
        -- Existing legacy rows remain valid and ordinary lifecycle updates
        -- remain allowed, but every post-050 insert requires the allocation
        -- registry. This also fail-closes a pre-044 writer with all NULLs.
        IF TG_OP = 'INSERT' THEN
            RAISE EXCEPTION 'new reverse swaps require allocation lineage'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT allocation
      FROM swap_key_allocations
     WHERE id = NEW.key_allocation_id;

    IF allocation.purpose <> 'reverse_claim'
       OR allocation.root_fingerprint IS DISTINCT FROM NEW.root_fingerprint
       OR allocation.key_epoch IS DISTINCT FROM NEW.key_epoch
       OR allocation.derivation_scheme_version IS DISTINCT FROM NEW.derivation_scheme_version
       OR allocation.child_index IS DISTINCT FROM NEW.key_index
       OR allocation.public_key_hex IS DISTINCT FROM NEW.claim_public_key_hex
       OR allocation.preimage_hash_hex IS DISTINCT FROM NEW.preimage_hash_hex THEN
        RAISE EXCEPTION 'reverse swap lineage does not match reserved allocation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION validate_chain_swap_key_lineage() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    claim_allocation swap_key_allocations%ROWTYPE;
    refund_allocation swap_key_allocations%ROWTYPE;
BEGIN
    IF NEW.claim_key_allocation_id IS NULL THEN
        IF TG_OP = 'INSERT' THEN
            RAISE EXCEPTION 'new chain swaps require allocation lineage'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT claim_allocation
      FROM swap_key_allocations
     WHERE id = NEW.claim_key_allocation_id;
    SELECT * INTO STRICT refund_allocation
      FROM swap_key_allocations
     WHERE id = NEW.refund_key_allocation_id;

    IF claim_allocation.purpose <> 'chain_claim'
       OR refund_allocation.purpose <> 'chain_refund'
       OR claim_allocation.root_fingerprint IS DISTINCT FROM NEW.root_fingerprint
       OR refund_allocation.root_fingerprint IS DISTINCT FROM NEW.root_fingerprint
       OR claim_allocation.key_epoch IS DISTINCT FROM NEW.key_epoch
       OR refund_allocation.key_epoch IS DISTINCT FROM NEW.key_epoch
       OR claim_allocation.derivation_scheme_version IS DISTINCT FROM NEW.derivation_scheme_version
       OR refund_allocation.derivation_scheme_version IS DISTINCT FROM NEW.derivation_scheme_version
       OR claim_allocation.child_index IS DISTINCT FROM NEW.claim_key_index
       OR refund_allocation.child_index IS DISTINCT FROM NEW.refund_key_index
       OR claim_allocation.public_key_hex IS DISTINCT FROM NEW.claim_public_key_hex
       OR refund_allocation.public_key_hex IS DISTINCT FROM NEW.refund_public_key_hex
       OR claim_allocation.preimage_hash_hex IS DISTINCT FROM NEW.preimage_hash_hex
       OR refund_allocation.preimage_hash_hex IS NOT NULL THEN
        RAISE EXCEPTION 'chain swap lineage does not match reserved allocations'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION reject_swap_key_allocation_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'swap key allocations are immutable'
        USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION reject_swap_key_legacy_high_water_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'swap key legacy high-water rows are immutable'
        USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION reject_swap_record_lineage_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(
        OLD.key_index, OLD.root_fingerprint, OLD.key_allocation_id,
        OLD.key_epoch, OLD.derivation_scheme_version,
        OLD.claim_public_key_hex, OLD.preimage_hash_hex
    ) IS DISTINCT FROM ROW(
        NEW.key_index, NEW.root_fingerprint, NEW.key_allocation_id,
        NEW.key_epoch, NEW.derivation_scheme_version,
        NEW.claim_public_key_hex, NEW.preimage_hash_hex
    ) THEN
        RAISE EXCEPTION 'reverse swap key lineage is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION reject_chain_swap_record_lineage_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(
        OLD.claim_key_index, OLD.refund_key_index, OLD.root_fingerprint,
        OLD.claim_key_allocation_id, OLD.refund_key_allocation_id,
        OLD.key_epoch, OLD.derivation_scheme_version,
        OLD.claim_public_key_hex, OLD.refund_public_key_hex, OLD.preimage_hash_hex
    ) IS DISTINCT FROM ROW(
        NEW.claim_key_index, NEW.refund_key_index, NEW.root_fingerprint,
        NEW.claim_key_allocation_id, NEW.refund_key_allocation_id,
        NEW.key_epoch, NEW.derivation_scheme_version,
        NEW.claim_public_key_hex, NEW.refund_public_key_hex, NEW.preimage_hash_hex
    ) THEN
        RAISE EXCEPTION 'chain swap key lineage is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER swap_key_allocations_validate_legacy_high_water
    BEFORE INSERT ON swap_key_allocations
    FOR EACH ROW EXECUTE FUNCTION validate_swap_key_allocation_against_legacy();
CREATE TRIGGER swap_key_allocations_reject_update
    BEFORE UPDATE ON swap_key_allocations
    FOR EACH ROW EXECUTE FUNCTION reject_swap_key_allocation_mutation();
CREATE TRIGGER swap_key_allocations_reject_delete
    BEFORE DELETE ON swap_key_allocations
    FOR EACH ROW EXECUTE FUNCTION reject_swap_key_allocation_mutation();
CREATE TRIGGER swap_key_legacy_high_water_reject_update
    BEFORE UPDATE ON swap_key_legacy_high_water
    FOR EACH ROW EXECUTE FUNCTION reject_swap_key_legacy_high_water_mutation();
CREATE TRIGGER swap_key_legacy_high_water_reject_delete
    BEFORE DELETE ON swap_key_legacy_high_water
    FOR EACH ROW EXECUTE FUNCTION reject_swap_key_legacy_high_water_mutation();
CREATE TRIGGER swap_records_validate_lineage
    BEFORE INSERT OR UPDATE ON swap_records
    FOR EACH ROW EXECUTE FUNCTION validate_reverse_swap_key_lineage();
CREATE TRIGGER chain_swap_records_validate_lineage
    BEFORE INSERT OR UPDATE ON chain_swap_records
    FOR EACH ROW EXECUTE FUNCTION validate_chain_swap_key_lineage();
CREATE TRIGGER swap_records_reject_lineage_update
    BEFORE UPDATE ON swap_records
    FOR EACH ROW EXECUTE FUNCTION reject_swap_record_lineage_mutation();
CREATE TRIGGER chain_swap_records_reject_lineage_update
    BEFORE UPDATE ON chain_swap_records
    FOR EACH ROW EXECUTE FUNCTION reject_chain_swap_record_lineage_mutation();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        GRANT SELECT, INSERT ON swap_key_allocations TO payservice;
        GRANT SELECT ON swap_key_legacy_high_water TO payservice;
        GRANT SELECT, INSERT, UPDATE, DELETE ON swap_records TO payservice;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chain_swap_records TO payservice;
    END IF;
END
$$;

COMMIT;

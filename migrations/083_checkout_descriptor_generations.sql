-- ============================================================================
-- 083: durable checkout descriptor generations and Liquid reservations
-- ============================================================================
--
-- A Payment Page/POS descriptor replacement starts a new derivation domain.
-- Keep that domain explicit and reserve every candidate address before chain
-- admission so a crash or concurrent request can never expose it twice.

BEGIN;

SELECT set_config('bullnym.migration_runtime_role', :'runtime_role', TRUE);

DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(
        current_setting('bullnym.migration_runtime_role', TRUE), ''
    );
    runtime_role_oid OID;
    executor_role_oid OID;
BEGIN
    SELECT oid INTO runtime_role_oid
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF runtime_role_name IS NULL OR runtime_role_oid IS NULL THEN
        RAISE EXCEPTION 'migration 083 requires an existing runtime role'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid INTO STRICT executor_role_oid
      FROM pg_roles
     WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid THEN
        RAISE EXCEPTION 'migration 083 must run as the schema owner, not the runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 083 runtime role owns or can assume its schema owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

ALTER TABLE donation_pages
    ADD COLUMN descriptor_generation BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT donation_pages_descriptor_generation_check
        CHECK (descriptor_generation > 0);

CREATE FUNCTION enforce_checkout_descriptor_generation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.ct_descriptor IS DISTINCT FROM OLD.ct_descriptor THEN
        IF OLD.descriptor_generation = 9223372036854775807 THEN
            RAISE EXCEPTION 'checkout descriptor generation exhausted'
                USING ERRCODE = '22003';
        END IF;
        NEW.descriptor_generation := OLD.descriptor_generation + 1;
        NEW.next_addr_idx := 0;
    ELSIF NEW.descriptor_generation IS DISTINCT FROM OLD.descriptor_generation THEN
        RAISE EXCEPTION 'checkout descriptor generation is server-managed'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION enforce_checkout_descriptor_generation() FROM PUBLIC;

CREATE TRIGGER donation_pages_enforce_descriptor_generation
BEFORE UPDATE OF ct_descriptor, descriptor_generation
ON donation_pages FOR EACH ROW
EXECUTE FUNCTION enforce_checkout_descriptor_generation();

CREATE TABLE checkout_liquid_address_reservations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nym TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('payment_page', 'pos')),
    descriptor_generation BIGINT NOT NULL CHECK (descriptor_generation > 0),
    address_index INTEGER NOT NULL CHECK (address_index >= 0),
    address TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'certified', 'history_present', 'allocated')),
    -- Deliberately not a foreign key: invoice cancellation/retention may
    -- remove its row, but the address ownership tombstone must survive.
    invoice_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    certified_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    allocated_at TIMESTAMPTZ,
    CONSTRAINT checkout_liquid_reservation_derivation_key
        UNIQUE (nym, kind, descriptor_generation, address_index),
    CONSTRAINT checkout_liquid_reservation_address_key UNIQUE (address),
    CONSTRAINT checkout_liquid_reservation_invoice_key UNIQUE (invoice_id),
    CONSTRAINT checkout_liquid_reservation_state_check CHECK (
        (status = 'pending'
            AND certified_at IS NULL AND rejected_at IS NULL
            AND allocated_at IS NULL AND invoice_id IS NULL)
        OR (status = 'certified'
            AND certified_at IS NOT NULL AND rejected_at IS NULL
            AND allocated_at IS NULL AND invoice_id IS NULL)
        OR (status = 'history_present'
            AND certified_at IS NULL AND rejected_at IS NOT NULL
            AND allocated_at IS NULL AND invoice_id IS NULL)
        OR (status = 'allocated'
            AND certified_at IS NOT NULL AND rejected_at IS NULL
            AND allocated_at IS NOT NULL AND invoice_id IS NOT NULL)
    )
);

CREATE INDEX checkout_liquid_reservations_surface_idx
    ON checkout_liquid_address_reservations
       (nym, kind, descriptor_generation, address_index);

CREATE FUNCTION enforce_checkout_liquid_reservation_transition() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending'
           OR NEW.certified_at IS NOT NULL OR NEW.rejected_at IS NOT NULL
           OR NEW.allocated_at IS NOT NULL OR NEW.invoice_id IS NOT NULL THEN
            RAISE EXCEPTION 'checkout Liquid reservations must start pending'
                USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.id, NEW.nym, NEW.kind, NEW.descriptor_generation,
           NEW.address_index, NEW.address, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.nym, OLD.kind, OLD.descriptor_generation,
           OLD.address_index, OLD.address, OLD.created_at) THEN
        RAISE EXCEPTION 'checkout Liquid reservation identity is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NOT (
        (OLD.status = 'pending'
            AND NEW.status IN ('certified', 'history_present'))
        OR (OLD.status = 'certified' AND NEW.status = 'allocated')
    ) THEN
        RAISE EXCEPTION 'invalid checkout Liquid reservation transition: % -> %',
            OLD.status, NEW.status
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION enforce_checkout_liquid_reservation_transition() FROM PUBLIC;

CREATE TRIGGER checkout_liquid_reservations_enforce_transition
BEFORE INSERT OR UPDATE ON checkout_liquid_address_reservations
FOR EACH ROW EXECUTE FUNCTION enforce_checkout_liquid_reservation_transition();

COMMENT ON COLUMN donation_pages.descriptor_generation IS
    'Monotonic surface-local generation incremented whenever ct_descriptor changes.';
COMMENT ON TABLE checkout_liquid_address_reservations IS
    'Durable pre-invoice ownership and chain-admission result for Page/POS Liquid addresses.';

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON TABLE checkout_liquid_address_reservations FROM PUBLIC;
    EXECUTE format(
        'GRANT SELECT ON TABLE checkout_liquid_address_reservations TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT INSERT (nym, kind, descriptor_generation, address_index, address) ON TABLE checkout_liquid_address_reservations TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT UPDATE (status, invoice_id, certified_at, rejected_at, allocated_at) ON TABLE checkout_liquid_address_reservations TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT (descriptor_generation), UPDATE (descriptor_generation, next_addr_idx) ON TABLE donation_pages TO %I',
        runtime_role_name
    );
END
$$;

COMMIT;

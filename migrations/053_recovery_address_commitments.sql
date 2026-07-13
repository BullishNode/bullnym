-- ============================================================================
-- 053: append-only, npub-wide recovery-address commitments
-- ============================================================================
--
-- A recovery address is merchant policy, not mutable profile state. Every
-- accepted rotation therefore receives a new per-npub commitment version and
-- preserves the exact signed contract evidence. A later chain-swap slice may
-- select and reference the current row, but this migration deliberately adds
-- no swap foreign key or route/readiness wiring.

BEGIN;

-- PostgreSQL table owners retain implicit TRUNCATE/ALTER authority even after
-- REVOKE. This ledger's runtime ACL is meaningful only when migrations run as
-- a distinct privileged schema owner rather than the payservice runtime role.
DO $$
BEGIN
    IF current_user = 'payservice' THEN
        RAISE EXCEPTION 'migration 053 requires a privileged schema owner distinct from runtime role payservice'
            USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE TABLE recovery_address_commitments (
    commitment_id             UUID PRIMARY KEY,
    npub                      TEXT NOT NULL,
    contract_format_version   SMALLINT NOT NULL,
    commitment_version        BIGINT NOT NULL,
    canonical_btc_address     TEXT NOT NULL,
    original_signature        TEXT NOT NULL,
    signed_at_unix            BIGINT NOT NULL,
    registered_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT recovery_address_commitment_id_non_nil_check CHECK (
        commitment_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT recovery_address_commitment_npub_shape_check CHECK (
        npub ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT recovery_address_commitment_contract_version_check CHECK (
        contract_format_version = 1
    ),
    CONSTRAINT recovery_address_commitment_version_positive_check CHECK (
        commitment_version > 0
    ),
    CONSTRAINT recovery_address_commitment_address_shape_check CHECK (
        canonical_btc_address = btrim(canonical_btc_address)
        AND octet_length(canonical_btc_address) BETWEEN 26 AND 90
        AND (
            canonical_btc_address ~ '^[13][1-9A-HJ-NP-Za-km-z]{25,34}$'
            OR canonical_btc_address ~ '^bc1[023456789ac-hj-np-z]{6,87}$'
        )
    ),
    CONSTRAINT recovery_address_commitment_signature_shape_check CHECK (
        original_signature ~ '^[0-9a-f]{128}$'
    ),
    CONSTRAINT recovery_address_commitment_signed_at_check CHECK (
        signed_at_unix > 0
    ),
    CONSTRAINT recovery_address_commitment_npub_version_key UNIQUE (
        npub, commitment_version
    ),
    CONSTRAINT recovery_address_commitment_signature_once_key UNIQUE (
        npub, original_signature
    )
);

DO $$
DECLARE
    ledger_owner TEXT;
BEGIN
    SELECT pg_get_userbyid(relowner)
      INTO ledger_owner
      FROM pg_class
     WHERE oid = 'recovery_address_commitments'::REGCLASS;
    IF ledger_owner = 'payservice' THEN
        RAISE EXCEPTION 'migration 053 refused runtime ownership of recovery_address_commitments; apply as a distinct privileged schema owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE FUNCTION enforce_recovery_address_commitment_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    tail_version BIGINT;
BEGIN
    -- Registration time is database evidence. INSERT callers, including the
    -- runtime role, cannot forge or preserve a client-supplied value.
    NEW.registered_at := clock_timestamp();

    -- Dedicated two-key transaction-lock namespace: ASCII "RCMT" plus the
    -- npub hash. Hash collisions only over-serialize unrelated merchants.
    PERFORM pg_advisory_xact_lock(1380142420, hashtext(NEW.npub));

    -- Admission is tied to a currently active merchant identity. FOR UPDATE
    -- conflicts with the lifecycle's non-key is_active update, giving
    -- acceptance and deactivation one deterministic order. The evidence
    -- ledger deliberately keeps no persistent foreign key: accepted
    -- commitments must survive later deactivation and lifecycle cleanup.
    PERFORM 1
      FROM users
     WHERE npub = NEW.npub
       AND is_active = TRUE
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery-address commitment source identity is not active'
            USING ERRCODE = '23503',
                  TABLE = 'recovery_address_commitments',
                  COLUMN = 'npub',
                  CONSTRAINT = 'recovery_address_commitment_source_exists';
    END IF;

    SELECT commitment_version
      INTO tail_version
      FROM recovery_address_commitments
     WHERE npub = NEW.npub
     ORDER BY commitment_version DESC
     LIMIT 1;

    IF NOT FOUND THEN
        IF NEW.commitment_version <> 1 THEN
            RAISE EXCEPTION 'the first recovery-address commitment must be version 1'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'recovery_address_commitment_npub_version_key';
        END IF;
    ELSE
        IF tail_version = 9223372036854775807 THEN
            RAISE EXCEPTION 'recovery-address commitment version exhausted BIGINT'
                USING ERRCODE = '54000';
        END IF;
        IF NEW.commitment_version <> tail_version + 1 THEN
            RAISE EXCEPTION 'recovery-address commitment must extend the exact npub tail'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'recovery_address_commitment_npub_version_key';
        END IF;
    END IF;

    RETURN NEW;
END
$$;

CREATE FUNCTION reject_recovery_address_commitment_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recovery-address commitments are append-only and cannot be updated'
        USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION reject_recovery_address_commitment_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recovery-address commitments are append-only and cannot be deleted'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER recovery_address_commitment_validate_insert
    BEFORE INSERT ON recovery_address_commitments
    FOR EACH ROW EXECUTE FUNCTION enforce_recovery_address_commitment_insert();

CREATE TRIGGER recovery_address_commitment_reject_update
    BEFORE UPDATE ON recovery_address_commitments
    FOR EACH ROW EXECUTE FUNCTION reject_recovery_address_commitment_update();

CREATE TRIGGER recovery_address_commitment_reject_delete
    BEFORE DELETE ON recovery_address_commitments
    FOR EACH ROW EXECUTE FUNCTION reject_recovery_address_commitment_delete();

REVOKE ALL ON recovery_address_commitments FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        REVOKE ALL ON recovery_address_commitments FROM payservice;
        GRANT SELECT, INSERT ON recovery_address_commitments TO payservice;
        IF has_table_privilege('payservice', 'recovery_address_commitments', 'UPDATE')
           OR has_table_privilege('payservice', 'recovery_address_commitments', 'DELETE')
           OR has_table_privilege('payservice', 'recovery_address_commitments', 'TRUNCATE')
           OR has_table_privilege('payservice', 'recovery_address_commitments', 'REFERENCES')
           OR has_table_privilege('payservice', 'recovery_address_commitments', 'TRIGGER') THEN
            RAISE EXCEPTION 'migration 053 detected effective owner-level privileges for payservice; apply as a distinct privileged schema owner'
                USING ERRCODE = '42501';
        END IF;
    END IF;
END
$$;

COMMIT;

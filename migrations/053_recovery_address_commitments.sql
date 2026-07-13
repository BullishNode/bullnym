-- ============================================================================
-- 053: append-only, npub-wide recovery-address commitments
-- ============================================================================
--
-- A recovery address is merchant policy, not mutable profile state. Every
-- accepted rotation therefore receives a new per-npub commitment version and
-- preserves the exact signed contract evidence. Chain swaps created after this
-- migration bind both the exact commitment identity and its canonical address;
-- historical rows remain nullable and are never assigned fabricated evidence.

BEGIN;

-- The runtime identity is an operator-supplied deployment fact, not a name
-- embedded in schema history. Quoted psql substitution makes an omitted
-- `--set runtime_role=...` a transaction-aborting syntax error; the following
-- block also rejects an empty setting before any schema mutation.
SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

-- PostgreSQL table owners retain implicit TRUNCATE/ALTER authority even after
-- REVOKE. This ledger's runtime ACL is meaningful only when migrations run as
-- a distinct privileged schema owner that the named runtime role cannot
-- assume, directly or through role membership.
DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(
        current_setting('bullnym.migration_runtime_role', TRUE),
        ''
    );
    runtime_role_oid OID;
    runtime_role_is_superuser BOOLEAN;
    executor_role_oid OID;
BEGIN
    IF runtime_role_name IS NULL THEN
        RAISE EXCEPTION 'migration 053 requires a non-empty runtime_role psql variable'
            USING ERRCODE = '42501';
    END IF;

    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 053 runtime role % does not exist',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 053 refuses superuser runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    SELECT oid
      INTO STRICT executor_role_oid
      FROM pg_roles
     WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid THEN
        RAISE EXCEPTION 'migration 053 executor must be distinct from runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;
    IF pg_has_role(runtime_role_oid, executor_role_oid, 'MEMBER') THEN
        RAISE EXCEPTION 'migration 053 runtime role % can assume executor role %',
            quote_ident(runtime_role_name), quote_ident(current_user)
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
    ),
    -- PostgreSQL requires a unique target with the same ordered columns as the
    -- composite chain-swap foreign key. The UUID remains the primary identity;
    -- including the address makes an ID/address mismatch fail atomically.
    CONSTRAINT recovery_address_commitment_id_address_key UNIQUE (
        commitment_id, canonical_btc_address
    )
);

ALTER TABLE chain_swap_records
    ADD COLUMN recovery_address_commitment_id UUID,
    -- Existing rows may have no commitment identity. Migration 051 never wrote
    -- an uncommitted address; fail the upgrade if such unexplained historical
    -- evidence exists instead of silently legitimizing it. The insert trigger
    -- below then requires the non-NULL half of this exact pair for new rows.
    ADD CONSTRAINT chain_swap_records_recovery_commitment_pair_check CHECK (
        (recovery_address_commitment_id IS NULL)
        = (merchant_emergency_btc_address IS NULL)
    ),
    ADD CONSTRAINT chain_swap_records_recovery_commitment_fkey
        FOREIGN KEY (
            recovery_address_commitment_id,
            merchant_emergency_btc_address
        )
        REFERENCES recovery_address_commitments (
            commitment_id,
            canonical_btc_address
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;

DO $$
DECLARE
    runtime_role_name TEXT := current_setting(
        'bullnym.migration_runtime_role'
    );
    runtime_role_oid OID;
    ledger_owner_oid OID;
BEGIN
    SELECT oid
      INTO STRICT runtime_role_oid
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    SELECT relowner
      INTO STRICT ledger_owner_oid
      FROM pg_class
     WHERE oid = 'recovery_address_commitments'::REGCLASS;
    IF ledger_owner_oid = runtime_role_oid
       OR pg_has_role(runtime_role_oid, ledger_owner_oid, 'MEMBER') THEN
        RAISE EXCEPTION 'migration 053 runtime role % owns or can assume the owner of recovery_address_commitments',
            quote_ident(runtime_role_name)
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

CREATE FUNCTION require_chain_swap_recovery_commitment() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.recovery_address_commitment_id IS NULL
       OR NEW.merchant_emergency_btc_address IS NULL THEN
        RAISE EXCEPTION 'new chain swaps require an exact recovery-address commitment'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'chain_swap_records_recovery_commitment_pair_check';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION reject_chain_swap_recovery_commitment_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(
        OLD.recovery_address_commitment_id,
        OLD.merchant_emergency_btc_address
    ) IS DISTINCT FROM ROW(
        NEW.recovery_address_commitment_id,
        NEW.merchant_emergency_btc_address
    ) THEN
        RAISE EXCEPTION 'chain swap recovery-address commitment is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
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

CREATE TRIGGER chain_swap_records_require_recovery_commitment
    BEFORE INSERT ON chain_swap_records
    FOR EACH ROW EXECUTE FUNCTION require_chain_swap_recovery_commitment();

CREATE TRIGGER chain_swap_records_reject_recovery_commitment_update
    BEFORE UPDATE OF
        recovery_address_commitment_id,
        merchant_emergency_btc_address
    ON chain_swap_records
    FOR EACH ROW EXECUTE FUNCTION reject_chain_swap_recovery_commitment_mutation();

REVOKE ALL ON recovery_address_commitments FROM PUBLIC;

DO $$
DECLARE
    runtime_role_name TEXT := current_setting(
        'bullnym.migration_runtime_role'
    );
BEGIN
    EXECUTE format(
        'REVOKE ALL ON TABLE public.recovery_address_commitments FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE public.recovery_address_commitments TO %I',
        runtime_role_name
    );

    IF NOT has_table_privilege(
        runtime_role_name,
        'public.recovery_address_commitments',
        'SELECT'
    ) OR NOT has_table_privilege(
        runtime_role_name,
        'public.recovery_address_commitments',
        'INSERT'
    ) THEN
        RAISE EXCEPTION 'migration 053 failed to grant runtime SELECT/INSERT to %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;
    IF has_table_privilege(runtime_role_name, 'public.recovery_address_commitments', 'UPDATE')
       OR has_table_privilege(runtime_role_name, 'public.recovery_address_commitments', 'DELETE')
       OR has_table_privilege(runtime_role_name, 'public.recovery_address_commitments', 'TRUNCATE')
       OR has_table_privilege(runtime_role_name, 'public.recovery_address_commitments', 'REFERENCES')
       OR has_table_privilege(runtime_role_name, 'public.recovery_address_commitments', 'TRIGGER') THEN
        RAISE EXCEPTION 'migration 053 detected effective mutation or owner privileges for runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;
END
$$;

COMMIT;

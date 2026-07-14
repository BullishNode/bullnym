-- ============================================================================
-- 056: crash-safe chain-swap quote-renegotiation operation journal
-- ============================================================================
--
-- Persist the exact provider quote and local policy evidence before an
-- accept_quote side effect. One row owns the only renegotiation operation for
-- a chain swap. Versioned state transitions make retries compare-and-swap;
-- ambiguous transport outcomes remain retryable and can never be rewritten as
-- a refusal without first issuing a new durable accept request.

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

-- A runtime table owner retains implicit schema and destructive authority.
-- Require a distinct, non-assumable schema owner before creating the journal.
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
        RAISE EXCEPTION 'migration 056 requires a non-empty runtime_role psql variable'
            USING ERRCODE = '42501';
    END IF;

    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 056 runtime role % does not exist',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 056 refuses superuser runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    SELECT oid INTO STRICT executor_role_oid
      FROM pg_roles
     WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 056 runtime role % can assume its schema owner %',
            quote_ident(runtime_role_name), quote_ident(current_user)
            USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE TABLE chain_swap_renegotiation_operations (
    chain_swap_id             UUID PRIMARY KEY,
    state                     TEXT NOT NULL DEFAULT 'quoted',
    quoted_actual_amount_sat  BIGINT NOT NULL,
    quote_response_digest     TEXT NOT NULL,
    quote_observed_at         TIMESTAMPTZ NOT NULL,
    policy_version            TEXT NOT NULL,
    policy_evidence_digest    TEXT NOT NULL,
    policy_validated_at       TIMESTAMPTZ NOT NULL,
    accept_attempt_count      INTEGER NOT NULL DEFAULT 0,
    last_error_class          TEXT,
    version                   BIGINT NOT NULL DEFAULT 1,
    accept_requested_at       TIMESTAMPTZ,
    ambiguous_at              TIMESTAMPTZ,
    terminal_response_digest  TEXT,
    terminal_observed_at      TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chain_swap_renegotiation_operations_chain_fkey
        FOREIGN KEY (chain_swap_id) REFERENCES chain_swap_records(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT chain_swap_renegotiation_state_check CHECK (
        state IN (
            'quoted', 'accept_requested', 'ambiguous', 'accepted', 'declined'
        )
    ),
    CONSTRAINT chain_swap_renegotiation_quoted_amount_check CHECK (
        quoted_actual_amount_sat > 0
    ),
    CONSTRAINT chain_swap_renegotiation_quote_digest_check CHECK (
        quote_response_digest ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chain_swap_renegotiation_policy_evidence_check CHECK (
        policy_version = btrim(policy_version)
        AND octet_length(policy_version) BETWEEN 1 AND 128
        AND policy_version !~ '[[:space:]]'
        AND policy_evidence_digest ~ '^[0-9a-f]{64}$'
        AND quote_observed_at > '1970-01-01 00:00:00+00'::TIMESTAMPTZ
        AND policy_validated_at >= quote_observed_at
    ),
    CONSTRAINT chain_swap_renegotiation_attempt_count_check CHECK (
        accept_attempt_count >= 0
    ),
    CONSTRAINT chain_swap_renegotiation_error_class_check CHECK (
        last_error_class IS NULL OR last_error_class IN (
            'timeout', 'transport', 'provider_server_error',
            'malformed_response', 'backend_disagreement',
            'unknown_provider_outcome'
        )
    ),
    CONSTRAINT chain_swap_renegotiation_version_check CHECK (
        version > 0
    ),
    CONSTRAINT chain_swap_renegotiation_terminal_digest_check CHECK (
        terminal_response_digest IS NULL
        OR terminal_response_digest ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chain_swap_renegotiation_lifecycle_shape_check CHECK (
        updated_at >= created_at
        AND (
            (
                state = 'quoted'
                AND accept_attempt_count = 0
                AND last_error_class IS NULL
                AND accept_requested_at IS NULL
                AND ambiguous_at IS NULL
                AND terminal_response_digest IS NULL
                AND terminal_observed_at IS NULL
            ) OR (
                state = 'accept_requested'
                AND accept_attempt_count > 0
                AND accept_requested_at IS NOT NULL
                AND accept_requested_at >= policy_validated_at
                AND accept_requested_at >= created_at
                AND accept_requested_at <= updated_at
                AND (
                    (
                        ambiguous_at IS NULL
                        AND last_error_class IS NULL
                    ) OR (
                        ambiguous_at IS NOT NULL
                        AND last_error_class IS NOT NULL
                        AND ambiguous_at <= accept_requested_at
                    )
                )
                AND terminal_response_digest IS NULL
                AND terminal_observed_at IS NULL
            ) OR (
                state = 'ambiguous'
                AND accept_attempt_count > 0
                AND last_error_class IS NOT NULL
                AND accept_requested_at IS NOT NULL
                AND accept_requested_at >= policy_validated_at
                AND accept_requested_at >= created_at
                AND accept_requested_at <= updated_at
                AND ambiguous_at IS NOT NULL
                AND ambiguous_at >= accept_requested_at
                AND ambiguous_at <= updated_at
                AND terminal_response_digest IS NULL
                AND terminal_observed_at IS NULL
            ) OR (
                state = 'accepted'
                AND accept_attempt_count > 0
                AND accept_requested_at IS NOT NULL
                AND accept_requested_at >= policy_validated_at
                AND accept_requested_at >= created_at
                AND accept_requested_at <= updated_at
                AND terminal_response_digest IS NOT NULL
                AND terminal_observed_at IS NOT NULL
                AND terminal_observed_at >= accept_requested_at
                AND terminal_observed_at <= updated_at
                AND (
                    (
                        ambiguous_at IS NULL
                        AND last_error_class IS NULL
                    ) OR (
                        ambiguous_at IS NOT NULL
                        AND last_error_class IS NOT NULL
                        AND terminal_observed_at >= ambiguous_at
                    )
                )
            ) OR (
                state = 'declined'
                AND terminal_response_digest IS NOT NULL
                AND terminal_observed_at IS NOT NULL
                AND terminal_observed_at >= policy_validated_at
                AND terminal_observed_at >= created_at
                AND terminal_observed_at <= updated_at
                AND (
                    (
                        accept_attempt_count = 0
                        AND last_error_class IS NULL
                        AND accept_requested_at IS NULL
                        AND ambiguous_at IS NULL
                    ) OR (
                        accept_attempt_count > 0
                        AND accept_requested_at IS NOT NULL
                        AND accept_requested_at >= created_at
                        AND accept_requested_at <= updated_at
                        AND terminal_observed_at >= accept_requested_at
                        AND (
                            (
                                ambiguous_at IS NULL
                                AND last_error_class IS NULL
                            ) OR (
                                ambiguous_at IS NOT NULL
                                AND last_error_class IS NOT NULL
                                AND ambiguous_at <= accept_requested_at
                            )
                        )
                    )
                )
            )
        )
    )
);

CREATE INDEX chain_swap_renegotiation_active_idx
    ON chain_swap_renegotiation_operations(updated_at, chain_swap_id)
    WHERE state NOT IN ('accepted', 'declined');

CREATE FUNCTION enforce_chain_swap_renegotiation_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    persisted_at TIMESTAMPTZ := clock_timestamp();
BEGIN
    -- Database time is the durable persistence fact; callers supply only the
    -- earlier quote and policy observation times.
    NEW.created_at := persisted_at;
    NEW.updated_at := persisted_at;

    IF NEW.state <> 'quoted'
       OR NEW.version <> 1
       OR NEW.accept_attempt_count <> 0
       OR NEW.quote_observed_at > persisted_at
       OR NEW.policy_validated_at > persisted_at
       OR NEW.last_error_class IS NOT NULL
       OR NEW.accept_requested_at IS NOT NULL
       OR NEW.ambiguous_at IS NOT NULL
       OR NEW.terminal_response_digest IS NOT NULL
       OR NEW.terminal_observed_at IS NOT NULL THEN
        RAISE EXCEPTION 'renegotiation operations must start as a pristine quoted version 1'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'chain_swap_renegotiation_lifecycle_shape_check';
    END IF;

    RETURN NEW;
END
$$;

CREATE FUNCTION enforce_chain_swap_renegotiation_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        NEW.chain_swap_id,
        NEW.quoted_actual_amount_sat,
        NEW.quote_response_digest,
        NEW.quote_observed_at,
        NEW.policy_version,
        NEW.policy_evidence_digest,
        NEW.policy_validated_at,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.chain_swap_id,
        OLD.quoted_actual_amount_sat,
        OLD.quote_response_digest,
        OLD.quote_observed_at,
        OLD.policy_version,
        OLD.policy_evidence_digest,
        OLD.policy_validated_at,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'renegotiation quote and policy identity is immutable'
            USING ERRCODE = '55000';
    END IF;

    -- Exact retries are idempotent, including after a terminal outcome.
    IF ROW(
        NEW.state,
        NEW.accept_attempt_count,
        NEW.last_error_class,
        NEW.version,
        NEW.accept_requested_at,
        NEW.ambiguous_at,
        NEW.terminal_response_digest,
        NEW.terminal_observed_at,
        NEW.updated_at
    ) IS NOT DISTINCT FROM ROW(
        OLD.state,
        OLD.accept_attempt_count,
        OLD.last_error_class,
        OLD.version,
        OLD.accept_requested_at,
        OLD.ambiguous_at,
        OLD.terminal_response_digest,
        OLD.terminal_observed_at,
        OLD.updated_at
    ) THEN
        RETURN NEW;
    END IF;

    IF OLD.state IN ('accepted', 'declined') THEN
        RAISE EXCEPTION 'terminal renegotiation evidence is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.version = 9223372036854775807 THEN
        RAISE EXCEPTION 'renegotiation operation version exhausted BIGINT'
            USING ERRCODE = '54000';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'renegotiation transition must advance the exact version by one'
            USING ERRCODE = '40001';
    END IF;

    IF OLD.state = 'quoted' AND NEW.state = 'accept_requested' THEN
        IF NEW.accept_attempt_count <> 1
           OR NEW.accept_requested_at IS NULL
           OR NEW.ambiguous_at IS NOT NULL
           OR NEW.last_error_class IS NOT NULL THEN
            RAISE EXCEPTION 'initial quote acceptance requires one durable request attempt'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'quoted' AND NEW.state = 'declined' THEN
        IF NEW.accept_attempt_count <> 0
           OR NEW.last_error_class IS NOT NULL
           OR NEW.accept_requested_at IS NOT NULL
           OR NEW.ambiguous_at IS NOT NULL THEN
            RAISE EXCEPTION 'a quote may be declined before request only by local policy'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'accept_requested' AND NEW.state = 'ambiguous' THEN
        IF NEW.accept_attempt_count <> OLD.accept_attempt_count
           OR NEW.accept_requested_at IS DISTINCT FROM OLD.accept_requested_at
           OR NEW.ambiguous_at IS NULL
           OR NEW.last_error_class IS NULL THEN
            RAISE EXCEPTION 'ambiguous acceptance must preserve its exact request attempt'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'accept_requested' AND NEW.state = 'accepted' THEN
        IF NEW.accept_attempt_count <> OLD.accept_attempt_count
           OR NEW.accept_requested_at IS DISTINCT FROM OLD.accept_requested_at
           OR NEW.ambiguous_at IS DISTINCT FROM OLD.ambiguous_at
           OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class THEN
            RAISE EXCEPTION 'accepted renegotiation must resolve its exact request attempt'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'accept_requested' AND NEW.state = 'declined' THEN
        IF NEW.accept_attempt_count <> OLD.accept_attempt_count
           OR NEW.accept_requested_at IS DISTINCT FROM OLD.accept_requested_at
           OR NEW.ambiguous_at IS DISTINCT FROM OLD.ambiguous_at
           OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class THEN
            RAISE EXCEPTION 'post-request decline requires explicit provider refusal evidence'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'ambiguous' AND NEW.state = 'accept_requested' THEN
        IF NEW.accept_attempt_count <> OLD.accept_attempt_count + 1
           OR NEW.accept_requested_at IS NULL
           OR NEW.accept_requested_at < OLD.accept_requested_at
           OR NEW.ambiguous_at IS DISTINCT FROM OLD.ambiguous_at
           OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class THEN
            RAISE EXCEPTION 'ambiguous retry requires a new durable accept request'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'ambiguous' AND NEW.state = 'accepted' THEN
        IF NEW.accept_attempt_count <> OLD.accept_attempt_count
           OR NEW.accept_requested_at IS DISTINCT FROM OLD.accept_requested_at
           OR NEW.ambiguous_at IS DISTINCT FROM OLD.ambiguous_at
           OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class THEN
            RAISE EXCEPTION 'accepted reconciliation must preserve ambiguous request evidence'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid renegotiation state transition from % to %',
            OLD.state, NEW.state
            USING ERRCODE = '55000';
    END IF;

    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END
$$;

CREATE FUNCTION reject_chain_swap_renegotiation_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'renegotiation operation evidence cannot be deleted'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER chain_swap_renegotiation_validate_insert
    BEFORE INSERT ON chain_swap_renegotiation_operations
    FOR EACH ROW EXECUTE FUNCTION enforce_chain_swap_renegotiation_insert();
CREATE TRIGGER chain_swap_renegotiation_validate_update
    BEFORE UPDATE ON chain_swap_renegotiation_operations
    FOR EACH ROW EXECUTE FUNCTION enforce_chain_swap_renegotiation_update();
CREATE TRIGGER chain_swap_renegotiation_reject_delete
    BEFORE DELETE ON chain_swap_renegotiation_operations
    FOR EACH ROW EXECUTE FUNCTION reject_chain_swap_renegotiation_delete();

REVOKE ALL ON TABLE chain_swap_renegotiation_operations FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_chain_swap_renegotiation_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_chain_swap_renegotiation_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_chain_swap_renegotiation_delete() FROM PUBLIC;

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
    runtime_role_oid OID;
    relation_owner_oid OID;
    function_owner_oid OID;
    function_name TEXT;
BEGIN
    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles
     WHERE rolname = runtime_role_name;

    EXECUTE format(
        'REVOKE ALL ON TABLE public.chain_swap_renegotiation_operations FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE ON TABLE public.chain_swap_renegotiation_operations TO %I',
        runtime_role_name
    );
    FOREACH function_name IN ARRAY ARRAY[
        'enforce_chain_swap_renegotiation_insert',
        'enforce_chain_swap_renegotiation_update',
        'reject_chain_swap_renegotiation_delete'
    ] LOOP
        EXECUTE format(
            'REVOKE ALL ON FUNCTION public.%I() FROM %I',
            function_name, runtime_role_name
        );
    END LOOP;

    SELECT relowner INTO STRICT relation_owner_oid
      FROM pg_class
     WHERE oid = 'public.chain_swap_renegotiation_operations'::REGCLASS
       AND relkind = 'r';
    IF relation_owner_oid = runtime_role_oid
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'SET')
       OR NOT has_table_privilege(
           runtime_role_name,
           'public.chain_swap_renegotiation_operations',
           'SELECT'
       )
       OR NOT has_table_privilege(
           runtime_role_name,
           'public.chain_swap_renegotiation_operations',
           'INSERT'
       )
       OR NOT has_table_privilege(
           runtime_role_name,
           'public.chain_swap_renegotiation_operations',
           'UPDATE'
       )
       OR has_table_privilege(
           runtime_role_name,
           'public.chain_swap_renegotiation_operations',
           'DELETE'
       )
       OR has_table_privilege(
           runtime_role_name,
           'public.chain_swap_renegotiation_operations',
           'TRUNCATE'
       )
       OR has_table_privilege(
           runtime_role_name,
           'public.chain_swap_renegotiation_operations',
           'REFERENCES'
       )
       OR has_table_privilege(
           runtime_role_name,
           'public.chain_swap_renegotiation_operations',
           'TRIGGER'
       ) THEN
        RAISE EXCEPTION 'migration 056 failed protected runtime ACL for renegotiation journal'
            USING ERRCODE = '42501';
    END IF;

    FOREACH function_name IN ARRAY ARRAY[
        'enforce_chain_swap_renegotiation_insert',
        'enforce_chain_swap_renegotiation_update',
        'reject_chain_swap_renegotiation_delete'
    ] LOOP
        SELECT procedure_info.proowner
          INTO STRICT function_owner_oid
          FROM pg_proc procedure_info
          JOIN pg_namespace namespace
            ON namespace.oid = procedure_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND procedure_info.proname = function_name
           AND procedure_info.pronargs = 0;
        IF function_owner_oid = runtime_role_oid
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'USAGE')
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'SET')
           OR has_function_privilege(
               runtime_role_name,
               format('public.%I()', function_name),
               'EXECUTE'
           ) THEN
            RAISE EXCEPTION 'migration 056 failed protected owner/ACL for function %',
                function_name
                USING ERRCODE = '42501';
        END IF;
    END LOOP;
END
$$;

COMMIT;

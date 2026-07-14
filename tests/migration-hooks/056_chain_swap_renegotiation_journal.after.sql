-- Migration 056 is a strict no-backfill boundary. Historical renegotiation
-- output remains available for accounting, but no provider-operation history
-- may be invented during upgrade.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM chain_swap_records
         WHERE id = '53000000-0000-0000-0000-000000000012'
           AND renegotiated_server_lock_amount_sat = 24750
           AND renegotiated_at = '2020-07-13 12:00:00+00'::TIMESTAMPTZ
    ) OR EXISTS (SELECT 1 FROM chain_swap_renegotiation_operations) THEN
        RAISE EXCEPTION 'migration 056 changed or fabricated historical renegotiation evidence';
    END IF;
END
$$;

-- Lock the schema, FK behavior, transition guards, active-work index, and
-- least-privilege runtime boundary to the crash-safe journal contract.
DO $$
DECLARE
    runtime_role_oid OID;
    relation_owner_oid OID;
    function_name TEXT;
    function_owner_oid OID;
    actual_columns TEXT[];
BEGIN
    SELECT array_agg(
               format('%s:%s:%s', column_name, data_type, is_nullable)
               ORDER BY ordinal_position
           )
      INTO actual_columns
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'chain_swap_renegotiation_operations';
    IF actual_columns IS DISTINCT FROM ARRAY[
        'chain_swap_id:uuid:NO',
        'state:text:NO',
        'quoted_actual_amount_sat:bigint:NO',
        'quote_response_digest:text:NO',
        'quote_observed_at:timestamp with time zone:NO',
        'policy_version:text:NO',
        'policy_evidence_digest:text:NO',
        'policy_validated_at:timestamp with time zone:NO',
        'accept_attempt_count:integer:NO',
        'last_error_class:text:YES',
        'version:bigint:NO',
        'accept_requested_at:timestamp with time zone:YES',
        'ambiguous_at:timestamp with time zone:YES',
        'terminal_response_digest:text:YES',
        'terminal_observed_at:timestamp with time zone:YES',
        'created_at:timestamp with time zone:NO',
        'updated_at:timestamp with time zone:NO'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'migration 056 column contract changed: %', actual_columns;
    END IF;

    IF (
        SELECT array_agg(conname ORDER BY conname)
          FROM pg_constraint
         WHERE conrelid = 'public.chain_swap_renegotiation_operations'::REGCLASS
           AND contype = 'c'
    ) IS DISTINCT FROM ARRAY[
        'chain_swap_renegotiation_attempt_count_check',
        'chain_swap_renegotiation_error_class_check',
        'chain_swap_renegotiation_lifecycle_shape_check',
        'chain_swap_renegotiation_policy_evidence_check',
        'chain_swap_renegotiation_quote_digest_check',
        'chain_swap_renegotiation_quoted_amount_check',
        'chain_swap_renegotiation_state_check',
        'chain_swap_renegotiation_terminal_digest_check',
        'chain_swap_renegotiation_version_check'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'migration 056 check-constraint contract changed';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.chain_swap_renegotiation_operations'::REGCLASS
           AND conname = 'chain_swap_renegotiation_operations_pkey'
           AND contype = 'p'
    ) OR NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.chain_swap_renegotiation_operations'::REGCLASS
           AND conname = 'chain_swap_renegotiation_operations_chain_fkey'
           AND contype = 'f'
           AND confrelid = 'public.chain_swap_records'::REGCLASS
           AND confupdtype = 'r'
           AND confdeltype = 'r'
    ) THEN
        RAISE EXCEPTION 'migration 056 primary/FK boundary changed';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_index index_info
          JOIN pg_class index_relation ON index_relation.oid = index_info.indexrelid
         WHERE index_info.indrelid = 'public.chain_swap_renegotiation_operations'::REGCLASS
           AND index_relation.relname = 'chain_swap_renegotiation_active_idx'
           AND NOT index_info.indisunique
           AND pg_get_indexdef(index_info.indexrelid) LIKE
               '%(updated_at, chain_swap_id)%'
           AND pg_get_expr(index_info.indpred, index_info.indrelid) LIKE
               '%accepted%declined%'
    ) THEN
        RAISE EXCEPTION 'migration 056 active-work index changed';
    END IF;

    IF (
        SELECT COUNT(*)
          FROM pg_trigger
         WHERE tgrelid = 'public.chain_swap_renegotiation_operations'::REGCLASS
           AND NOT tgisinternal
           AND (
               (tgname = 'chain_swap_renegotiation_validate_insert' AND tgtype = 7)
               OR (tgname = 'chain_swap_renegotiation_validate_update' AND tgtype = 19)
               OR (tgname = 'chain_swap_renegotiation_reject_delete' AND tgtype = 11)
           )
    ) <> 3 THEN
        RAISE EXCEPTION 'migration 056 trigger contract changed';
    END IF;

    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles WHERE rolname = 'bullnym_app';
    SELECT relowner INTO STRICT relation_owner_oid
      FROM pg_class
     WHERE oid = 'public.chain_swap_renegotiation_operations'::REGCLASS;
    IF relation_owner_oid = runtime_role_oid
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'SET')
       OR NOT has_table_privilege('bullnym_app', 'public.chain_swap_renegotiation_operations', 'SELECT')
       OR NOT has_table_privilege('bullnym_app', 'public.chain_swap_renegotiation_operations', 'INSERT')
       OR NOT has_table_privilege('bullnym_app', 'public.chain_swap_renegotiation_operations', 'UPDATE')
       OR has_table_privilege('bullnym_app', 'public.chain_swap_renegotiation_operations', 'DELETE')
       OR has_table_privilege('bullnym_app', 'public.chain_swap_renegotiation_operations', 'TRUNCATE')
       OR has_table_privilege('bullnym_app', 'public.chain_swap_renegotiation_operations', 'REFERENCES')
       OR has_table_privilege('bullnym_app', 'public.chain_swap_renegotiation_operations', 'TRIGGER')
       OR EXISTS (
           SELECT 1
             FROM aclexplode(COALESCE(
                 (SELECT relacl FROM pg_class
                   WHERE oid = 'public.chain_swap_renegotiation_operations'::REGCLASS),
                 acldefault('r', relation_owner_oid)
             )) acl
            WHERE acl.grantee = 0
       ) THEN
        RAISE EXCEPTION 'migration 056 retained unsafe runtime owner/ACL';
    END IF;

    FOREACH function_name IN ARRAY ARRAY[
        'enforce_chain_swap_renegotiation_insert',
        'enforce_chain_swap_renegotiation_update',
        'reject_chain_swap_renegotiation_delete'
    ] LOOP
        SELECT proowner INTO STRICT function_owner_oid
          FROM pg_proc procedure_info
          JOIN pg_namespace namespace
            ON namespace.oid = procedure_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND procedure_info.proname = function_name
           AND procedure_info.pronargs = 0;
        IF function_owner_oid = runtime_role_oid
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'USAGE')
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'SET')
           OR EXISTS (
               SELECT 1
                 FROM pg_proc procedure_info,
                      LATERAL aclexplode(COALESCE(
                          procedure_info.proacl,
                          acldefault('f', procedure_info.proowner)
                      )) acl
                WHERE procedure_info.oid = format('public.%I()', function_name)::REGPROCEDURE
                  AND acl.grantee IN (0, runtime_role_oid)
                  AND acl.privilege_type = 'EXECUTE'
           ) THEN
            RAISE EXCEPTION 'migration 056 retained unsafe function owner/ACL for %',
                function_name;
        END IF;
    END LOOP;
END
$$;

-- A forced abort before the accept intent commits must leave the quote exact.
-- Once the intent commits, a forced abort before terminal-result persistence
-- must leave `accept_requested`, never a fabricated decline or retryable quote.
INSERT INTO chain_swap_renegotiation_operations (
    chain_swap_id, quoted_actual_amount_sat, quote_response_digest,
    quote_observed_at, policy_version, policy_evidence_digest,
    policy_validated_at
) VALUES (
    '53000000-0000-0000-0000-000000000012', 24750, repeat('a', 64),
    '2020-07-13 12:01:00+00', 'issue38-v1', repeat('b', 64),
    '2020-07-13 12:01:01+00'
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM chain_swap_renegotiation_operations
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012'
           AND state = 'quoted'
           AND accept_attempt_count = 0
           AND version = 1
           AND last_error_class IS NULL
           AND accept_requested_at IS NULL
           AND ambiguous_at IS NULL
           AND terminal_response_digest IS NULL
           AND terminal_observed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 056 quoted defaults changed';
    END IF;

    BEGIN
        UPDATE chain_swap_renegotiation_operations
           SET state = 'accept_requested',
               accept_attempt_count = 1,
               accept_requested_at = clock_timestamp(),
               version = 2
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION USING ERRCODE = 'P5601',
            MESSAGE = 'simulated crash before accept intent commit';
    EXCEPTION WHEN SQLSTATE 'P5601' THEN
        NULL;
    END;

    IF NOT EXISTS (
        SELECT 1
          FROM chain_swap_renegotiation_operations
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012'
           AND state = 'quoted'
           AND accept_attempt_count = 0
           AND version = 1
           AND accept_requested_at IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 056 leaked an uncommitted accept intent';
    END IF;
END
$$;

UPDATE chain_swap_renegotiation_operations
   SET state = 'accept_requested',
       accept_attempt_count = 1,
       accept_requested_at = clock_timestamp(),
       version = 2
 WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';

DO $$
BEGIN
    BEGIN
        UPDATE chain_swap_renegotiation_operations
           SET state = 'accepted',
               terminal_response_digest = repeat('c', 64),
               terminal_observed_at = clock_timestamp(),
               version = 3
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION USING ERRCODE = 'P5602',
            MESSAGE = 'simulated crash before terminal result commit';
    EXCEPTION WHEN SQLSTATE 'P5602' THEN
        NULL;
    END;

    IF NOT EXISTS (
        SELECT 1
          FROM chain_swap_renegotiation_operations
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012'
           AND state = 'accept_requested'
           AND accept_attempt_count = 1
           AND version = 2
           AND accept_requested_at IS NOT NULL
           AND terminal_response_digest IS NULL
           AND terminal_observed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 056 lost the durable accept intent after result abort';
    END IF;
END
$$;

-- Uncertain provider outcome is durable and cannot be downgraded to declined.
UPDATE chain_swap_renegotiation_operations
   SET state = 'ambiguous',
       last_error_class = 'transport',
       ambiguous_at = clock_timestamp(),
       version = 3
 WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';

DO $$
BEGIN
    BEGIN
        UPDATE chain_swap_renegotiation_operations
           SET state = 'declined',
               last_error_class = 'transport',
               terminal_response_digest = repeat('d', 64),
               terminal_observed_at = clock_timestamp(),
               version = 4
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 056 allowed ambiguous to become declined';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    IF NOT EXISTS (
        SELECT 1
          FROM chain_swap_renegotiation_operations
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012'
           AND state = 'ambiguous'
           AND last_error_class = 'transport'
           AND version = 3
           AND terminal_response_digest IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 056 changed ambiguous evidence after refusal';
    END IF;
END
$$;

UPDATE chain_swap_renegotiation_operations
   SET state = 'accepted',
       last_error_class = 'transport',
       terminal_response_digest = repeat('c', 64),
       terminal_observed_at = clock_timestamp(),
       version = 4
 WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';

-- Policy decline is a terminal, pre-attempt outcome. Identity and terminal
-- evidence remain immutable and rows cannot be deleted even by the owner.
INSERT INTO chain_swap_renegotiation_operations (
    chain_swap_id, quoted_actual_amount_sat, quote_response_digest,
    quote_observed_at, policy_version, policy_evidence_digest,
    policy_validated_at
) VALUES (
    '53000000-0000-0000-0000-000000000013', 69000, repeat('e', 64),
    '2020-07-13 12:05:00+00', 'issue38-v1', repeat('f', 64),
    '2020-07-13 12:05:01+00'
);

UPDATE chain_swap_renegotiation_operations
   SET state = 'declined',
       last_error_class = NULL,
       terminal_response_digest = repeat('1', 64),
       terminal_observed_at = clock_timestamp(),
       version = 2
 WHERE chain_swap_id = '53000000-0000-0000-0000-000000000013';

DO $$
BEGIN
    BEGIN
        UPDATE chain_swap_renegotiation_operations
           SET quote_response_digest = repeat('2', 64)
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 056 allowed immutable quote mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        UPDATE chain_swap_renegotiation_operations
           SET terminal_response_digest = repeat('3', 64)
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000013';
        RAISE EXCEPTION 'migration 056 allowed terminal evidence mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        DELETE FROM chain_swap_renegotiation_operations
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000013';
        RAISE EXCEPTION 'migration 056 allowed journal deletion';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    IF (
        SELECT COUNT(*)
          FROM chain_swap_renegotiation_operations
         WHERE (chain_swap_id = '53000000-0000-0000-0000-000000000012'
                AND state = 'accepted' AND version = 4)
            OR (chain_swap_id = '53000000-0000-0000-0000-000000000013'
                AND state = 'declined' AND version = 2
                AND last_error_class IS NULL)
    ) <> 2 THEN
        RAISE EXCEPTION 'migration 056 did not retain exact terminal evidence';
    END IF;
END
$$;

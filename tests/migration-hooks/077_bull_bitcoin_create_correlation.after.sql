DO $$
DECLARE
    runtime_role_oid OID;
    owner_role_oid OID;
BEGIN
    IF EXISTS (
        SELECT 1 FROM migration_077_bound_snapshot snapshot
        JOIN bull_bitcoin_settlements settlement USING (id)
        WHERE ROW(
            settlement.bull_bitcoin_order_id, settlement.provider_state,
            settlement.funding_route, settlement.settlement_status,
            settlement.instruction_kind, settlement.payer_instruction,
            settlement.actual_received_sat, settlement.credited_fiat_minor,
            settlement.provider_final, settlement.created_at,
            settlement.updated_at
        ) IS DISTINCT FROM ROW(
            snapshot.bull_bitcoin_order_id, snapshot.provider_state,
            snapshot.funding_route, snapshot.settlement_status,
            snapshot.instruction_kind, snapshot.payer_instruction,
            snapshot.actual_received_sat, snapshot.credited_fiat_minor,
            snapshot.provider_final, snapshot.created_at,
            snapshot.updated_at
        )
           OR settlement.order_correlation_source <> 'legacy_bound'
           OR settlement.order_correlated_at IS DISTINCT FROM snapshot.updated_at
           OR settlement.expected_instruction_script_len IS NOT NULL
    ) OR (
        SELECT COUNT(*) FROM migration_077_bound_snapshot
    ) <> (
        SELECT COUNT(*) FROM bull_bitcoin_settlements
         WHERE order_correlation_source = 'legacy_bound'
    ) THEN
        RAISE EXCEPTION 'migration 077 changed or incompletely correlated a bound order';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'bull_bitcoin_settlements'
           AND column_name = 'expected_instruction_script_len'
           AND data_type = 'integer'
           AND is_nullable = 'YES'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'bull_bitcoin_settlements'::REGCLASS
           AND conname =
               'bull_bitcoin_settlements_expected_instruction_shape_chk'
           AND convalidated
    ) OR NOT EXISTS (
        SELECT 1
          FROM pg_class index_info
          JOIN pg_index index_state ON index_state.indexrelid = index_info.oid
         WHERE index_info.oid = to_regclass(
                   'bull_bitcoin_settlements_ambiguous_dispatch_due_idx'
               )
           AND index_state.indrelid = 'bull_bitcoin_settlements'::REGCLASS
           AND index_state.indisvalid
           AND index_state.indisready
           AND pg_get_expr(index_state.indpred, index_state.indrelid)
               LIKE '%provider_state%dispatch_started%funding_route IS NULL%'
           AND pg_get_indexdef(index_info.oid)
               LIKE '%COALESCE(next_attempt_at, updated_at)%'
    ) THEN
        RAISE EXCEPTION 'migration 077 instruction-shape or due-work boundary is incomplete';
    END IF;

    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles WHERE rolname = 'bullnym_app';
    SELECT relowner INTO STRICT owner_role_oid
      FROM pg_class WHERE oid = 'bull_bitcoin_settlements'::REGCLASS;
    IF runtime_role_oid = owner_role_oid
       OR pg_has_role(runtime_role_oid, owner_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, owner_role_oid, 'SET')
       OR NOT has_table_privilege('bullnym_app', 'bull_bitcoin_settlements', 'SELECT')
       OR NOT has_table_privilege('bullnym_app', 'bull_bitcoin_settlements', 'INSERT')
       OR NOT has_table_privilege('bullnym_app', 'bull_bitcoin_settlements', 'UPDATE')
       OR has_table_privilege('bullnym_app', 'bull_bitcoin_settlements', 'DELETE')
       OR has_table_privilege('bullnym_app', 'bull_bitcoin_settlements', 'TRUNCATE')
       OR has_table_privilege('bullnym_app', 'bull_bitcoin_settlements', 'REFERENCES')
       OR has_table_privilege('bullnym_app', 'bull_bitcoin_settlements', 'TRIGGER')
       OR has_function_privilege(
            'bullnym_app',
            'attach_ambiguous_bull_bitcoin_order(UUID, UUID, TEXT, UUID)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'migration 077 did not preserve the owner/runtime boundary';
    END IF;
END
$$;

INSERT INTO bull_bitcoin_settlements (
    id, owner_npub, credential_id, product, purpose, payer_rail,
    request_key, fiat_percentage, fiat_currency, requested_bitcoin_sat
) VALUES (
    '77000000-0000-4000-8000-000000000001', repeat('6', 64),
    '66000000-0000-4000-8000-000000000001',
    'lightning_address', 'fiat_only', 'bitcoin',
    'migration-077-ambiguous-create', 100, 'CAD', 10000
);
UPDATE bull_bitcoin_settlements
   SET provider_state = 'dispatch_started', updated_at = clock_timestamp()
 WHERE id = '77000000-0000-4000-8000-000000000001';

DO $$
DECLARE
    attached BOOLEAN;
BEGIN
    attached := attach_ambiguous_bull_bitcoin_order(
        '77000000-0000-4000-8000-000000000001',
        '66000000-0000-4000-8000-000000000001',
        'migration-077-ambiguous-create',
        '77000000-0000-4000-8000-000000000002'
    );
    IF NOT attached OR NOT EXISTS (
        SELECT 1 FROM bull_bitcoin_settlements
         WHERE id = '77000000-0000-4000-8000-000000000001'
           AND provider_state = 'dispatch_started'
           AND funding_route IS NULL
           AND settlement_status = 'none'
           AND bull_bitcoin_order_id =
               '77000000-0000-4000-8000-000000000002'
           AND order_correlation_source = 'operator_recovery'
           AND order_correlated_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 077 did not attach an exact ambiguous order';
    END IF;
    IF attach_ambiguous_bull_bitcoin_order(
        '77000000-0000-4000-8000-000000000001',
        '66000000-0000-4000-8000-000000000001',
        'migration-077-ambiguous-create',
        '77000000-0000-4000-8000-000000000002'
    ) THEN
        RAISE EXCEPTION 'migration 077 recovery attachment is not idempotent';
    END IF;

    BEGIN
        PERFORM attach_ambiguous_bull_bitcoin_order(
            '77000000-0000-4000-8000-000000000001',
            gen_random_uuid(),
            'migration-077-ambiguous-create',
            '77000000-0000-4000-8000-000000000002'
        );
        RAISE EXCEPTION 'migration 077 accepted the wrong expected credential';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;

    BEGIN
        PERFORM attach_ambiguous_bull_bitcoin_order(
            '77000000-0000-4000-8000-000000000001',
            '66000000-0000-4000-8000-000000000001',
            'migration-077-wrong-request',
            '77000000-0000-4000-8000-000000000002'
        );
        RAISE EXCEPTION 'migration 077 accepted the wrong expected request key';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;

    BEGIN
        PERFORM attach_ambiguous_bull_bitcoin_order(
            '77000000-0000-4000-8000-000000000001',
            '66000000-0000-4000-8000-000000000001',
            'migration-077-ambiguous-create',
            '77000000-0000-4000-8000-000000000003'
        );
        RAISE EXCEPTION 'migration 077 replaced an existing candidate order';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;

    BEGIN
        PERFORM attach_ambiguous_bull_bitcoin_order(
            '77000000-0000-4000-8000-000000000001',
            '66000000-0000-4000-8000-000000000001',
            'migration-077-ambiguous-create',
            NULL
        );
        RAISE EXCEPTION 'migration 077 accepted a null candidate order';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
END
$$;

DROP TABLE migration_077_bound_snapshot;

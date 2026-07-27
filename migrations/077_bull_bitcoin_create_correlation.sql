-- ============================================================================
-- 077: durable Bull Bitcoin create correlation
-- ============================================================================
--
-- A provider create that crossed the dispatch boundary must never be rewritten
-- as an all-Bitcoin fallback merely because its response was lost or invalid.
-- Keep the local settlement UUID as the provider-facing JSON-RPC correlation
-- identity and permit an exact candidate order ID to be retained while the
-- dispatch remains ambiguous. Binding still requires a complete normalized
-- provider response.

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(
        current_setting('bullnym.migration_runtime_role', TRUE), ''
    );
    runtime_role_oid OID;
    table_owner_name TEXT;
    table_owner_oid OID;
BEGIN
    SELECT oid INTO runtime_role_oid
      FROM pg_roles WHERE rolname = runtime_role_name;
    IF runtime_role_name IS NULL OR runtime_role_oid IS NULL THEN
        RAISE EXCEPTION 'migration 077 requires an existing runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF current_user = runtime_role_name THEN
        RAISE EXCEPTION 'migration 077 must run as the schema owner, not the runtime role'
            USING ERRCODE = '42501';
    END IF;

    SELECT relowner, pg_get_userbyid(relowner)
      INTO table_owner_oid, table_owner_name
      FROM pg_class
     WHERE oid = to_regclass('public.bull_bitcoin_settlements');
    IF table_owner_name IS NULL OR table_owner_name <> current_user THEN
        RAISE EXCEPTION 'migration 077 must run as the Bull Bitcoin settlement table owner'
            USING ERRCODE = '42501';
    END IF;
    IF runtime_role_oid = table_owner_oid
       OR pg_has_role(runtime_role_oid, table_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, table_owner_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 077 runtime role can assume the settlement table owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

ALTER TABLE bull_bitcoin_settlements
    ADD COLUMN order_correlation_source TEXT,
    ADD COLUMN order_correlated_at TIMESTAMPTZ,
    ADD COLUMN expected_instruction_script_len INTEGER;

-- Existing bound rows already have authoritative provider identities. Record
-- only their local provenance; do not change any order, money, or instruction
-- field.
UPDATE bull_bitcoin_settlements
   SET order_correlation_source = 'legacy_bound',
       order_correlated_at = updated_at
 WHERE bull_bitcoin_order_id IS NOT NULL;

ALTER TABLE bull_bitcoin_settlements
    DROP CONSTRAINT bull_bitcoin_settlements_provider_binding_chk,
    ADD CONSTRAINT bull_bitcoin_settlements_provider_binding_chk CHECK (
        (provider_state IN ('reserved', 'abandoned')
            AND bull_bitcoin_order_id IS NULL)
        OR provider_state = 'dispatch_started'
        OR (provider_state = 'bound' AND bull_bitcoin_order_id IS NOT NULL)
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_order_correlation_chk CHECK (
        (
            bull_bitcoin_order_id IS NULL
            AND order_correlation_source IS NULL
            AND order_correlated_at IS NULL
        ) OR (
            bull_bitcoin_order_id IS NOT NULL
            AND order_correlation_source IN (
                'legacy_bound', 'provider_response', 'operator_recovery'
            )
            AND order_correlated_at IS NOT NULL
            AND (provider_state = 'bound'
                 OR provider_state = 'dispatch_started')
            AND (order_correlation_source <> 'legacy_bound'
                 OR provider_state = 'bound')
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_expected_instruction_shape_chk CHECK (
        expected_instruction_script_len IS NULL
        OR (
            purpose = 'mixed'
            AND expected_instruction_script_len BETWEEN 1 AND 10000
        )
    );

CREATE INDEX bull_bitcoin_settlements_ambiguous_dispatch_due_idx
    ON bull_bitcoin_settlements (
        (COALESCE(next_attempt_at, updated_at)), id
    )
    INCLUDE (updated_at, bull_bitcoin_order_id)
    WHERE provider_state = 'dispatch_started' AND funding_route IS NULL;

CREATE FUNCTION guard_bull_bitcoin_order_correlation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.order_correlation_source IS NOT NULL
       AND NEW.order_correlation_source IS DISTINCT FROM OLD.order_correlation_source THEN
        RAISE EXCEPTION 'Bull Bitcoin order correlation source is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_correlation_source_immutable';
    END IF;
    IF OLD.order_correlated_at IS NOT NULL
       AND NEW.order_correlated_at IS DISTINCT FROM OLD.order_correlated_at THEN
        RAISE EXCEPTION 'Bull Bitcoin order correlation time is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_correlation_time_immutable';
    END IF;
    IF OLD.expected_instruction_script_len IS NOT NULL
       AND NEW.expected_instruction_script_len
            IS DISTINCT FROM OLD.expected_instruction_script_len THEN
        RAISE EXCEPTION 'Bull Bitcoin expected instruction shape is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_instruction_shape_immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER bull_bitcoin_settlements_guard_order_correlation
    BEFORE UPDATE ON bull_bitcoin_settlements
    FOR EACH ROW EXECUTE FUNCTION guard_bull_bitcoin_order_correlation();

-- Schema-owner-only recovery boundary. An operator supplies the durable local
-- settlement UUID, exact expected credential and request identities, and the
-- provider order UUID found through the nonsecret JSON-RPC correlation ID.
-- This attaches evidence for the ordinary reconciler; it never binds, funds,
-- terminalizes, or creates an order.
CREATE FUNCTION attach_ambiguous_bull_bitcoin_order(
    target_settlement_id UUID,
    expected_credential_id UUID,
    expected_request_key TEXT,
    candidate_order_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    settlement_row bull_bitcoin_settlements%ROWTYPE;
BEGIN
    IF candidate_order_id IS NULL THEN
        RAISE EXCEPTION 'ambiguous Bull Bitcoin recovery requires a candidate order identity'
            USING ERRCODE = '55000';
    END IF;
    SELECT * INTO settlement_row
      FROM bull_bitcoin_settlements
     WHERE id = target_settlement_id
     FOR UPDATE;
    IF NOT FOUND
       OR settlement_row.credential_id IS DISTINCT FROM expected_credential_id
       OR settlement_row.request_key IS DISTINCT FROM expected_request_key THEN
        RAISE EXCEPTION 'ambiguous Bull Bitcoin recovery identity mismatch'
            USING ERRCODE = '55000';
    END IF;
    IF settlement_row.provider_state <> 'dispatch_started'
       OR settlement_row.funding_route IS NOT NULL
       OR settlement_row.funding_committed_at IS NOT NULL
       OR settlement_row.settlement_status <> 'none'
       OR settlement_row.provider_final
       OR settlement_row.terminal_at IS NOT NULL
       OR settlement_row.actual_received_sat IS NOT NULL
       OR EXISTS (
            SELECT 1 FROM bull_bitcoin_claim_outputs output
             WHERE output.settlement_id = target_settlement_id
       )
       OR EXISTS (
            SELECT 1 FROM invoice_payment_events event
             WHERE event.bull_bitcoin_settlement_id = target_settlement_id
       ) THEN
        RAISE EXCEPTION 'ambiguous Bull Bitcoin recovery row has financial or terminal evidence'
            USING ERRCODE = '55000';
    END IF;
    IF settlement_row.bull_bitcoin_order_id IS NOT NULL
       AND settlement_row.bull_bitcoin_order_id <> candidate_order_id THEN
        RAISE EXCEPTION 'ambiguous Bull Bitcoin recovery order identity mismatch'
            USING ERRCODE = '55000';
    END IF;
    IF settlement_row.bull_bitcoin_order_id = candidate_order_id THEN
        RETURN FALSE;
    END IF;

    UPDATE bull_bitcoin_settlements
       SET bull_bitcoin_order_id = candidate_order_id,
           order_correlation_source = 'operator_recovery',
           order_correlated_at = clock_timestamp(),
           next_attempt_at = now(),
           updated_at = clock_timestamp()
     WHERE id = target_settlement_id;
    RETURN TRUE;
END
$$;

COMMENT ON COLUMN bull_bitcoin_settlements.order_correlation_source IS
    'Local provenance for a retained provider order UUID; never provider account data.';
COMMENT ON COLUMN bull_bitcoin_settlements.order_correlated_at IS
    'First durable time at which Bullnym retained the provider order UUID.';
COMMENT ON COLUMN bull_bitcoin_settlements.expected_instruction_script_len IS
    'Immutable expected Liquid payer-output script length for a mixed claim; null for fiat-only and legacy rows.';
COMMENT ON FUNCTION attach_ambiguous_bull_bitcoin_order(UUID, UUID, TEXT, UUID) IS
    'Owner-only attachment of an externally correlated order UUID to an unfunded ambiguous dispatch.';

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON FUNCTION guard_bull_bitcoin_order_correlation() FROM PUBLIC;
    REVOKE ALL ON FUNCTION attach_ambiguous_bull_bitcoin_order(UUID, UUID, TEXT, UUID) FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON FUNCTION attach_ambiguous_bull_bitcoin_order(UUID, UUID, TEXT, UUID) FROM %I',
        runtime_role_name
    );

    REVOKE ALL ON TABLE bull_bitcoin_settlements FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON TABLE bull_bitcoin_settlements FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE ON TABLE bull_bitcoin_settlements TO %I',
        runtime_role_name
    );

    IF NOT has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'SELECT')
       OR NOT has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'INSERT')
       OR NOT has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'UPDATE')
       OR has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'DELETE')
       OR has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'TRUNCATE')
       OR has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'REFERENCES')
       OR has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'TRIGGER')
       OR has_function_privilege(
            runtime_role_name,
            'attach_ambiguous_bull_bitcoin_order(UUID, UUID, TEXT, UUID)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'migration 077 could not establish exact runtime correlation privileges'
            USING ERRCODE = '42501';
    END IF;
END
$$;

COMMIT;

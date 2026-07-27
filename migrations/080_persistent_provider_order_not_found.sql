-- ============================================================================
-- 080: durable escalation for a previously bound provider order that vanishes
-- ============================================================================
--
-- A single authenticated 404 can be eventual consistency. Repeated 404s for
-- an order Bullnym already bound are different from transport failures: retain
-- the binding, close payer admission, surface an integrity hold, and continue
-- a low-cadence exact-order watch. A later authoritative observation may
-- resolve only this specific hold; the order identity remains immutable.

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
    table_owner_oid OID;
BEGIN
    SELECT oid INTO runtime_role_oid
      FROM pg_roles WHERE rolname = runtime_role_name;
    IF runtime_role_name IS NULL OR runtime_role_oid IS NULL THEN
        RAISE EXCEPTION 'migration 080 requires an existing runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF current_user = runtime_role_name THEN
        RAISE EXCEPTION 'migration 080 must run as the schema owner, not the runtime role'
            USING ERRCODE = '42501';
    END IF;

    SELECT relowner INTO table_owner_oid
      FROM pg_class
     WHERE oid = to_regclass('public.bull_bitcoin_settlements');
    IF table_owner_oid IS NULL
       OR pg_get_userbyid(table_owner_oid) <> current_user THEN
        RAISE EXCEPTION 'migration 080 must run as the Bull Bitcoin settlement table owner'
            USING ERRCODE = '42501';
    END IF;
    IF runtime_role_oid = table_owner_oid
       OR pg_has_role(runtime_role_oid, table_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, table_owner_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 080 runtime role can assume the settlement table owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

ALTER TABLE bull_bitcoin_settlements
    ADD COLUMN provider_last_read_error_class TEXT,
    ADD COLUMN provider_last_read_error_at TIMESTAMPTZ,
    ADD COLUMN provider_last_success_at TIMESTAMPTZ,
    ADD COLUMN provider_not_found_first_at TIMESTAMPTZ,
    ADD COLUMN provider_not_found_consecutive INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN provider_missing_since TIMESTAMPTZ,
    ADD COLUMN provider_missing_last_resolved_at TIMESTAMPTZ,
    ADD CONSTRAINT bull_bitcoin_settlements_provider_read_error_chk CHECK (
        (
            provider_last_read_error_class IS NULL
            AND provider_last_read_error_at IS NULL
        ) OR (
            provider_last_read_error_class IN (
                'not_found', 'not_found_unverified', 'transient', 'authentication'
            )
            AND provider_last_read_error_at IS NOT NULL
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_not_found_streak_chk CHECK (
        (
            provider_not_found_consecutive = 0
            AND provider_not_found_first_at IS NULL
        ) OR (
            provider_not_found_consecutive > 0
            AND provider_not_found_first_at IS NOT NULL
            AND provider_last_read_error_class = 'not_found'
            AND provider_last_read_error_at >= provider_not_found_first_at
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_provider_missing_chk CHECK (
        provider_missing_since IS NULL
        OR (
            provider_state = 'bound'
            AND funding_route = 'bull_bitcoin'
            AND bull_bitcoin_order_id IS NOT NULL
            AND settlement_status = 'integrity_error'
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_provider_missing_resolution_chk CHECK (
        provider_missing_last_resolved_at IS NULL
        OR provider_missing_since IS NULL
        OR provider_missing_last_resolved_at <= provider_missing_since
    );

COMMENT ON COLUMN bull_bitcoin_settlements.provider_last_read_error_class IS
    'Last exact-order read failure class: qualified/unverified not_found, transient transport/upstream, or authentication.';
COMMENT ON COLUMN bull_bitcoin_settlements.provider_not_found_first_at IS
    'Start of the current consecutive authenticated exact-order NotFound streak.';
COMMENT ON COLUMN bull_bitcoin_settlements.provider_last_success_at IS
    'Most recent valid exact-order provider observation; NULL when no successful read has been observed locally.';
COMMENT ON COLUMN bull_bitcoin_settlements.provider_not_found_consecutive IS
    'Current consecutive authenticated exact-order NotFound count; reset by any non-NotFound result.';
COMMENT ON COLUMN bull_bitcoin_settlements.provider_missing_since IS
    'Current persistent-missing integrity hold; never authorizes abandonment or replacement.';
COMMENT ON COLUMN bull_bitcoin_settlements.provider_missing_last_resolved_at IS
    'Most recent authoritative observation that resolved a persistent-missing hold.';

CREATE INDEX bull_bitcoin_settlements_provider_missing_due_idx
    ON bull_bitcoin_settlements (next_attempt_at, created_at, id)
    WHERE provider_state = 'bound'
      AND funding_route = 'bull_bitcoin'
      AND settlement_status = 'integrity_error'
      AND provider_missing_since IS NOT NULL
      AND NOT provider_final;

-- Preserve every historical transition and add one narrowly evidenced recovery:
-- a row held only because its exact provider order was persistently missing may
-- return to the ordinary provider-observed lifecycle when that same immutable
-- order is readable again.
CREATE OR REPLACE FUNCTION enforce_bull_bitcoin_settlement_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF (NEW.owner_npub, NEW.invoice_id, NEW.credential_id, NEW.product,
        NEW.purpose, NEW.payer_rail, NEW.request_key, NEW.fiat_percentage,
        NEW.fiat_currency, NEW.requested_bitcoin_sat,
        NEW.created_at)
       IS DISTINCT FROM
       (OLD.owner_npub, OLD.invoice_id, OLD.credential_id, OLD.product,
        OLD.purpose, OLD.payer_rail, OLD.request_key, OLD.fiat_percentage,
        OLD.fiat_currency, OLD.requested_bitcoin_sat,
        OLD.created_at) THEN
        RAISE EXCEPTION 'Bull Bitcoin settlement identity is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_identity_immutable';
    END IF;

    IF NOT (
        NEW.provider_state = OLD.provider_state
        OR (OLD.provider_state = 'reserved'
            AND NEW.provider_state IN ('dispatch_started', 'abandoned'))
        OR (OLD.provider_state = 'dispatch_started'
            AND NEW.provider_state IN ('bound', 'abandoned'))
    ) THEN
        RAISE EXCEPTION 'invalid Bull Bitcoin provider-state transition'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_provider_transition';
    END IF;

    IF OLD.bull_bitcoin_order_id IS NOT NULL
       AND NEW.bull_bitcoin_order_id IS DISTINCT FROM OLD.bull_bitcoin_order_id THEN
        RAISE EXCEPTION 'Bull Bitcoin order binding is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_order_immutable';
    END IF;

    IF OLD.funding_route IS NOT NULL
       AND NEW.funding_route IS DISTINCT FROM OLD.funding_route THEN
        RAISE EXCEPTION 'Bull Bitcoin settlement funding route is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_route_immutable';
    END IF;

    IF OLD.provider_final AND NOT NEW.provider_final THEN
        RAISE EXCEPTION 'Bull Bitcoin provider finality is monotonic'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_finality_monotonic';
    END IF;

    IF NOT (
        NEW.settlement_status = OLD.settlement_status
        OR (OLD.settlement_status = 'none'
            AND NEW.settlement_status = 'pending')
        OR (OLD.settlement_status = 'pending'
            AND NEW.settlement_status IN (
                'settled', 'unavailable', 'integrity_error'
            ))
        OR (
            OLD.settlement_status = 'integrity_error'
            AND OLD.provider_missing_since IS NOT NULL
            AND NEW.provider_missing_since IS NULL
            AND NEW.provider_missing_last_resolved_at IS NOT NULL
            AND NEW.provider_missing_last_resolved_at >= OLD.provider_missing_since
            AND NEW.provider_last_read_error_class IS NULL
            AND NEW.provider_last_read_error_at IS NULL
            AND NEW.provider_not_found_consecutive = 0
            AND NEW.provider_not_found_first_at IS NULL
            AND NEW.settlement_status IN ('pending', 'settled', 'unavailable')
        )
    ) THEN
        RAISE EXCEPTION 'invalid Bull Bitcoin settlement-status transition'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_status_transition';
    END IF;

    IF OLD.terminal_at IS NOT NULL
       AND NEW.terminal_at IS DISTINCT FROM OLD.terminal_at THEN
        RAISE EXCEPTION 'Bull Bitcoin terminal time is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_terminal_immutable';
    END IF;
    RETURN NEW;
END
$$;

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
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
       OR has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'TRIGGER') THEN
        RAISE EXCEPTION 'migration 080 could not establish exact runtime settlement privileges'
            USING ERRCODE = '42501';
    END IF;
END
$$;

COMMIT;

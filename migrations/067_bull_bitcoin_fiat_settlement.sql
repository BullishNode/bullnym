-- ============================================================================
-- 066: privacy-minimal Bull Bitcoin fiat-settlement foundation
-- ============================================================================

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

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
        RAISE EXCEPTION 'migration 067 requires a non-empty runtime_role'
            USING ERRCODE = '42501';
    END IF;

    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 067 runtime role % does not exist',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 067 refuses superuser runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    SELECT oid INTO STRICT executor_role_oid
      FROM pg_roles
     WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 067 runtime role % owns or can assume schema owner %',
            quote_ident(runtime_role_name), quote_ident(current_user)
            USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE TABLE bull_bitcoin_credentials (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_npub              TEXT        NOT NULL,
    ciphertext              BYTEA,
    nonce                   BYTEA,
    encryption_format       SMALLINT    NOT NULL DEFAULT 1,
    admitted_for_new_orders BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    deletion_requested_at   TIMESTAMPTZ,
    erased_at               TIMESTAMPTZ,
    CONSTRAINT bull_bitcoin_credentials_id_owner_key
        UNIQUE (id, owner_npub),
    CONSTRAINT bull_bitcoin_credentials_owner_shape_chk CHECK (
        owner_npub ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT bull_bitcoin_credentials_encryption_format_chk CHECK (
        encryption_format = 1
    ),
    CONSTRAINT bull_bitcoin_credentials_material_shape_chk CHECK (
        (ciphertext IS NOT NULL AND octet_length(ciphertext) = 85
            AND nonce IS NOT NULL AND octet_length(nonce) = 24
            AND erased_at IS NULL)
        OR
        (ciphertext IS NULL AND nonce IS NULL AND erased_at IS NOT NULL)
    ),
    CONSTRAINT bull_bitcoin_credentials_lifecycle_chk CHECK (
        (admitted_for_new_orders AND deletion_requested_at IS NULL AND erased_at IS NULL)
        OR
        (NOT admitted_for_new_orders AND deletion_requested_at IS NOT NULL)
    ),
    CONSTRAINT bull_bitcoin_credentials_time_order_chk CHECK (
        (deletion_requested_at IS NULL OR deletion_requested_at >= created_at)
        AND (erased_at IS NULL OR erased_at >= deletion_requested_at)
    )
);

CREATE UNIQUE INDEX bull_bitcoin_credentials_one_admitted_per_owner_idx
    ON bull_bitcoin_credentials (owner_npub)
    WHERE admitted_for_new_orders;

CREATE TABLE fiat_settlement_settings (
    owner_npub        TEXT        NOT NULL,
    product           TEXT        NOT NULL,
    credential_id     UUID        NOT NULL,
    fiat_percentage   SMALLINT    NOT NULL,
    fiat_currency     TEXT        NOT NULL,
    terms_version     TEXT        NOT NULL,
    terms_accepted_at TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_npub, product),
    CONSTRAINT fiat_settlement_settings_credential_owner_fkey
        FOREIGN KEY (credential_id, owner_npub)
        REFERENCES bull_bitcoin_credentials(id, owner_npub)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fiat_settlement_settings_product_chk CHECK (
        product IN ('lightning_address', 'payment_page', 'pos', 'invoice')
    ),
    CONSTRAINT fiat_settlement_settings_percentage_chk CHECK (
        fiat_percentage BETWEEN 1 AND 100
    ),
    CONSTRAINT fiat_settlement_settings_currency_chk CHECK (
        fiat_currency IN ('ARS', 'CAD', 'COP', 'CRC', 'EUR', 'MXN', 'USD')
    ),
    CONSTRAINT fiat_settlement_settings_terms_chk CHECK (
        terms_version = 'bull-bitcoin-fiat-settlement-v1'
    ),
    CONSTRAINT fiat_settlement_settings_time_order_chk CHECK (
        updated_at >= terms_accepted_at
    )
);

CREATE TABLE invoice_fiat_settlement_policies (
    invoice_id         UUID        PRIMARY KEY,
    owner_npub         TEXT        NOT NULL,
    credential_id      UUID        NOT NULL,
    product            TEXT        NOT NULL,
    fiat_percentage    SMALLINT    NOT NULL,
    fiat_currency      TEXT        NOT NULL,
    terms_version      TEXT        NOT NULL,
    allowed_rail_mask  SMALLINT    NOT NULL,
    captured_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT invoice_fiat_settlement_policies_invoice_fkey
        FOREIGN KEY (invoice_id) REFERENCES invoices(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT invoice_fiat_settlement_policies_credential_owner_fkey
        FOREIGN KEY (credential_id, owner_npub)
        REFERENCES bull_bitcoin_credentials(id, owner_npub)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT invoice_fiat_settlement_policies_product_chk CHECK (
        product IN ('payment_page', 'pos', 'invoice')
    ),
    CONSTRAINT invoice_fiat_settlement_policies_percentage_chk CHECK (
        fiat_percentage BETWEEN 1 AND 100
    ),
    CONSTRAINT invoice_fiat_settlement_policies_currency_chk CHECK (
        fiat_currency IN ('ARS', 'CAD', 'COP', 'CRC', 'EUR', 'MXN', 'USD')
    ),
    CONSTRAINT invoice_fiat_settlement_policies_terms_chk CHECK (
        terms_version = 'bull-bitcoin-fiat-settlement-v1'
    ),
    CONSTRAINT invoice_fiat_settlement_policies_rails_chk CHECK (
        allowed_rail_mask BETWEEN 1 AND 7
    )
);

CREATE FUNCTION reject_invoice_fiat_policy_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'invoice fiat-settlement policy is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'invoice_fiat_settlement_policies_immutable';
END
$$;

CREATE TRIGGER invoice_fiat_settlement_policies_reject_update
    BEFORE UPDATE OR DELETE ON invoice_fiat_settlement_policies
    FOR EACH ROW EXECUTE FUNCTION reject_invoice_fiat_policy_mutation();

CREATE TABLE bull_bitcoin_settlements (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_npub               TEXT        NOT NULL,
    invoice_id               UUID,
    credential_id            UUID        NOT NULL,
    product                  TEXT        NOT NULL,
    purpose                  TEXT        NOT NULL,
    payer_rail               TEXT        NOT NULL,
    request_key              TEXT        NOT NULL,
    fiat_percentage          SMALLINT    NOT NULL,
    fiat_currency            TEXT        NOT NULL,
    terms_version            TEXT        NOT NULL,
    provider_state           TEXT        NOT NULL DEFAULT 'reserved',
    funding_route            TEXT,
    fallback_category        TEXT,
    requested_bitcoin_sat    BIGINT      NOT NULL,
    bull_bitcoin_order_id    UUID,
    order_status             TEXT,
    payin_status             TEXT,
    payout_status            TEXT,
    actual_received_sat      BIGINT,
    credited_fiat_minor      BIGINT,
    instruction_kind         TEXT,
    payer_instruction        TEXT,
    instruction_expires_at   TIMESTAMPTZ,
    last_checked_at          TIMESTAMPTZ,
    next_attempt_at          TIMESTAMPTZ,
    reconcile_attempts       INTEGER     NOT NULL DEFAULT 0,
    provider_final           BOOLEAN     NOT NULL DEFAULT FALSE,
    retention_until          TIMESTAMPTZ,
    terminal_at              TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT bull_bitcoin_settlements_invoice_fkey
        FOREIGN KEY (invoice_id) REFERENCES invoices(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT bull_bitcoin_settlements_credential_owner_fkey
        FOREIGN KEY (credential_id, owner_npub)
        REFERENCES bull_bitcoin_credentials(id, owner_npub)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT bull_bitcoin_settlements_owner_shape_chk CHECK (
        owner_npub ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT bull_bitcoin_settlements_product_chk CHECK (
        product IN ('lightning_address', 'payment_page', 'pos', 'invoice')
    ),
    CONSTRAINT bull_bitcoin_settlements_invoice_scope_chk CHECK (
        (product = 'lightning_address' AND invoice_id IS NULL)
        OR (product <> 'lightning_address' AND invoice_id IS NOT NULL)
    ),
    CONSTRAINT bull_bitcoin_settlements_purpose_chk CHECK (
        purpose IN ('fiat_only', 'mixed')
    ),
    CONSTRAINT bull_bitcoin_settlements_percentage_chk CHECK (
        (purpose = 'fiat_only' AND fiat_percentage = 100)
        OR (purpose = 'mixed' AND fiat_percentage BETWEEN 1 AND 99)
    ),
    CONSTRAINT bull_bitcoin_settlements_rail_chk CHECK (
        payer_rail IN ('bitcoin', 'lightning', 'liquid')
        AND (purpose = 'fiat_only' OR payer_rail = 'liquid')
    ),
    CONSTRAINT bull_bitcoin_settlements_currency_chk CHECK (
        fiat_currency IN ('ARS', 'CAD', 'COP', 'CRC', 'EUR', 'MXN', 'USD')
    ),
    CONSTRAINT bull_bitcoin_settlements_terms_chk CHECK (
        terms_version = 'bull-bitcoin-fiat-settlement-v1'
    ),
    CONSTRAINT bull_bitcoin_settlements_request_key_chk CHECK (
        length(request_key) BETWEEN 1 AND 200
        AND request_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT bull_bitcoin_settlements_requested_amount_chk CHECK (
        requested_bitcoin_sat > 0
        AND requested_bitcoin_sat <= 2100000000000000
    ),
    CONSTRAINT bull_bitcoin_settlements_provider_state_chk CHECK (
        provider_state IN ('reserved', 'dispatch_started', 'bound', 'abandoned')
    ),
    CONSTRAINT bull_bitcoin_settlements_provider_binding_chk CHECK (
        (provider_state IN ('reserved', 'dispatch_started', 'abandoned')
            AND bull_bitcoin_order_id IS NULL)
        OR (provider_state = 'bound' AND bull_bitcoin_order_id IS NOT NULL)
    ),
    CONSTRAINT bull_bitcoin_settlements_funding_route_chk CHECK (
        funding_route IS NULL
        OR funding_route IN ('bull_bitcoin', 'bitcoin_fallback')
    ),
    CONSTRAINT bull_bitcoin_settlements_fallback_chk CHECK (
        (funding_route = 'bitcoin_fallback'
            AND fallback_category IN (
                'below_minimum', 'invalid_split',
                'conversion_unavailable', 'ambiguous_create'
            ))
        OR (funding_route IS DISTINCT FROM 'bitcoin_fallback'
            AND fallback_category IS NULL)
    ),
    CONSTRAINT bull_bitcoin_settlements_route_state_chk CHECK (
        (provider_state IN ('reserved', 'dispatch_started') AND funding_route IS NULL)
        OR provider_state = 'bound'
        OR (provider_state = 'abandoned' AND funding_route = 'bitcoin_fallback')
    ),
    CONSTRAINT bull_bitcoin_settlements_observation_shape_chk CHECK (
        (provider_state <> 'bound'
            AND order_status IS NULL AND payin_status IS NULL
            AND payout_status IS NULL AND actual_received_sat IS NULL
            AND credited_fiat_minor IS NULL AND NOT provider_final)
        OR provider_state = 'bound'
    ),
    CONSTRAINT bull_bitcoin_settlements_status_length_chk CHECK (
        (order_status IS NULL OR length(order_status) BETWEEN 1 AND 64)
        AND (payin_status IS NULL OR length(payin_status) BETWEEN 1 AND 64)
        AND (payout_status IS NULL OR length(payout_status) BETWEEN 1 AND 64)
    ),
    CONSTRAINT bull_bitcoin_settlements_actual_amount_chk CHECK (
        actual_received_sat IS NULL OR actual_received_sat > 0
    ),
    CONSTRAINT bull_bitcoin_settlements_fiat_amount_chk CHECK (
        credited_fiat_minor IS NULL OR credited_fiat_minor > 0
    ),
    CONSTRAINT bull_bitcoin_settlements_instruction_chk CHECK (
        (instruction_kind IS NULL AND payer_instruction IS NULL)
        OR (
            provider_state = 'bound'
            AND funding_route IS DISTINCT FROM 'bitcoin_fallback'
            AND instruction_kind = payer_rail
            AND payer_instruction IS NOT NULL
            AND length(payer_instruction) BETWEEN 1 AND 4096
            AND payer_instruction !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT bull_bitcoin_settlements_reconcile_attempts_chk CHECK (
        reconcile_attempts >= 0
    ),
    CONSTRAINT bull_bitcoin_settlements_terminal_chk CHECK (
        (provider_final AND terminal_at IS NOT NULL)
        OR (NOT provider_final AND terminal_at IS NULL)
    ),
    CONSTRAINT bull_bitcoin_settlements_time_order_chk CHECK (
        updated_at >= created_at
        AND (last_checked_at IS NULL OR last_checked_at >= created_at)
        AND (retention_until IS NULL OR retention_until >= created_at)
        AND (terminal_at IS NULL OR terminal_at >= created_at)
    ),
    CONSTRAINT bull_bitcoin_settlements_owner_request_key
        UNIQUE (owner_npub, request_key)
);

CREATE UNIQUE INDEX bull_bitcoin_settlements_order_id_idx
    ON bull_bitcoin_settlements (bull_bitcoin_order_id)
    WHERE bull_bitcoin_order_id IS NOT NULL;

CREATE INDEX bull_bitcoin_settlements_reconcile_idx
    ON bull_bitcoin_settlements (next_attempt_at, created_at, id)
    WHERE provider_state = 'bound' AND NOT provider_final;

CREATE INDEX bull_bitcoin_settlements_invoice_idx
    ON bull_bitcoin_settlements (invoice_id, created_at, id)
    WHERE invoice_id IS NOT NULL;

CREATE INDEX bull_bitcoin_settlements_credential_dependencies_idx
    ON bull_bitcoin_settlements (credential_id, provider_final, provider_state);

CREATE FUNCTION enforce_bull_bitcoin_settlement_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF (NEW.owner_npub, NEW.invoice_id, NEW.credential_id, NEW.product,
        NEW.purpose, NEW.payer_rail, NEW.request_key, NEW.fiat_percentage,
        NEW.fiat_currency, NEW.terms_version, NEW.requested_bitcoin_sat,
        NEW.created_at)
       IS DISTINCT FROM
       (OLD.owner_npub, OLD.invoice_id, OLD.credential_id, OLD.product,
        OLD.purpose, OLD.payer_rail, OLD.request_key, OLD.fiat_percentage,
        OLD.fiat_currency, OLD.terms_version, OLD.requested_bitcoin_sat,
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

    IF OLD.terminal_at IS NOT NULL
       AND NEW.terminal_at IS DISTINCT FROM OLD.terminal_at THEN
        RAISE EXCEPTION 'Bull Bitcoin terminal time is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_terminal_immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER bull_bitcoin_settlements_validate_update
    BEFORE UPDATE ON bull_bitcoin_settlements
    FOR EACH ROW EXECUTE FUNCTION enforce_bull_bitcoin_settlement_update();

ALTER TABLE invoices
    ADD COLUMN fiat_settlement_status TEXT NOT NULL DEFAULT 'none',
    ADD CONSTRAINT invoices_fiat_settlement_status_chk CHECK (
        fiat_settlement_status IN (
            'none', 'pending', 'settled', 'unavailable', 'integrity_error'
        )
    );

COMMENT ON TABLE bull_bitcoin_credentials IS
    'XChaCha20-Poly1305 encrypted scoped sell-to-balance capabilities; never returned by Bullnym.';
COMMENT ON TABLE fiat_settlement_settings IS
    'Current merchant product policy. Absence means settle fully to the Bitcoin wallet.';
COMMENT ON TABLE invoice_fiat_settlement_policies IS
    'Immutable per-invoice snapshot; never contains payer or Bull Bitcoin account identity.';
COMMENT ON TABLE bull_bitcoin_settlements IS
    'One privacy-minimal local record per payer instruction or mixed fiat leg; not generic order history.';
COMMENT ON COLUMN bull_bitcoin_settlements.payer_instruction IS
    'Transient payment instruction cleared after terminal reconciliation; never exposed by read APIs.';

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON TABLE bull_bitcoin_credentials FROM PUBLIC;
    REVOKE ALL ON TABLE fiat_settlement_settings FROM PUBLIC;
    REVOKE ALL ON TABLE invoice_fiat_settlement_policies FROM PUBLIC;
    REVOKE ALL ON TABLE bull_bitcoin_settlements FROM PUBLIC;
    REVOKE ALL ON FUNCTION reject_invoice_fiat_policy_mutation() FROM PUBLIC;
    REVOKE ALL ON FUNCTION enforce_bull_bitcoin_settlement_update() FROM PUBLIC;

    EXECUTE format('REVOKE ALL ON TABLE bull_bitcoin_credentials FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON TABLE fiat_settlement_settings FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON TABLE invoice_fiat_settlement_policies FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON TABLE bull_bitcoin_settlements FROM %I', runtime_role_name);

    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE ON TABLE bull_bitcoin_credentials TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE fiat_settlement_settings TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE invoice_fiat_settlement_policies TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE ON TABLE bull_bitcoin_settlements TO %I',
        runtime_role_name
    );
END
$$;

COMMIT;

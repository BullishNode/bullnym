-- ============================================================================
-- 078: swap-backed 100%-fiat Lightning Address settlement
-- ============================================================================
--
-- New Lightning Address callbacks always expose a Boltz BOLT11. A captured
-- 100% allocation is represented internally as `provider_only`: the funded
-- reverse swap produces one confidential Bull Bitcoin output and no zero-value
-- merchant output. Historical direct-provider `fiat_only` rows are unchanged.

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
        RAISE EXCEPTION 'migration 079 requires an existing runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF current_user = runtime_role_name THEN
        RAISE EXCEPTION 'migration 079 must run as the schema owner, not the runtime role'
            USING ERRCODE = '42501';
    END IF;
    SELECT relowner, pg_get_userbyid(relowner)
      INTO table_owner_oid, table_owner_name
      FROM pg_class
     WHERE oid = to_regclass('public.bull_bitcoin_settlements');
    IF table_owner_name IS NULL OR table_owner_name <> current_user THEN
        RAISE EXCEPTION 'migration 079 must run as the Bull Bitcoin settlement table owner'
            USING ERRCODE = '42501';
    END IF;
    IF runtime_role_oid = table_owner_oid
       OR pg_has_role(runtime_role_oid, table_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, table_owner_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 079 runtime role can assume the settlement table owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

ALTER TABLE swap_fiat_settlement_policies
    DROP CONSTRAINT swap_fiat_settlement_policies_percentage_chk,
    ADD CONSTRAINT swap_fiat_settlement_policies_percentage_chk CHECK (
        fiat_percentage BETWEEN 1 AND 100
    );

ALTER TABLE bull_bitcoin_settlements
    DROP CONSTRAINT bull_bitcoin_settlements_purpose_chk,
    DROP CONSTRAINT bull_bitcoin_settlements_percentage_chk,
    DROP CONSTRAINT bull_bitcoin_settlements_rail_chk,
    DROP CONSTRAINT bull_bitcoin_settlements_funding_commitment_chk,
    DROP CONSTRAINT bull_bitcoin_settlements_status_chk,
    DROP CONSTRAINT bull_bitcoin_settlements_swap_binding_chk,
    DROP CONSTRAINT bull_bitcoin_settlements_instruction_chk,
    DROP CONSTRAINT bull_bitcoin_settlements_expected_instruction_shape_chk,
    ADD CONSTRAINT bull_bitcoin_settlements_purpose_chk CHECK (
        purpose IN ('fiat_only', 'mixed', 'provider_only')
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_percentage_chk CHECK (
        (purpose = 'fiat_only' AND fiat_percentage = 100)
        OR (purpose = 'mixed' AND fiat_percentage BETWEEN 1 AND 99)
        OR (purpose = 'provider_only' AND fiat_percentage = 100)
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_rail_chk CHECK (
        payer_rail IN ('bitcoin', 'lightning', 'liquid')
        AND (
            purpose = 'fiat_only'
            OR (purpose = 'mixed' AND payer_rail IN ('bitcoin', 'lightning'))
            OR (purpose = 'provider_only' AND payer_rail = 'lightning')
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_funding_commitment_chk CHECK (
        (funding_route IS DISTINCT FROM 'bull_bitcoin'
            AND funding_committed_at IS NULL)
        OR (
            funding_route = 'bull_bitcoin'
            AND provider_state = 'bound'
            AND (
                (purpose = 'fiat_only' AND funding_committed_at IS NOT NULL)
                OR purpose IN ('mixed', 'provider_only')
            )
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_status_chk CHECK (
        settlement_status IN (
            'none', 'pending', 'settled', 'unavailable', 'integrity_error'
        )
        AND (
            (
                settlement_status = 'none'
                AND (
                    provider_state <> 'bound'
                    OR funding_route = 'bitcoin_fallback'
                    OR (
                        purpose IN ('mixed', 'provider_only')
                        AND funding_committed_at IS NULL
                    )
                )
            ) OR (
                settlement_status <> 'none'
                AND provider_state = 'bound'
                AND funding_route = 'bull_bitcoin'
                AND funding_committed_at IS NOT NULL
            )
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_swap_binding_chk CHECK (
        (
            purpose = 'fiat_only'
            AND reverse_swap_id IS NULL AND chain_swap_id IS NULL
        ) OR (
            purpose = 'mixed'
            AND (
                (reverse_swap_id IS NOT NULL)::INTEGER
                + (chain_swap_id IS NOT NULL)::INTEGER = 1
            )
            AND (
                (reverse_swap_id IS NOT NULL AND payer_rail = 'lightning')
                OR (chain_swap_id IS NOT NULL AND payer_rail = 'bitcoin')
            )
        ) OR (
            purpose = 'provider_only'
            AND reverse_swap_id IS NOT NULL
            AND chain_swap_id IS NULL
            AND product = 'lightning_address'
            AND invoice_id IS NULL
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_instruction_chk CHECK (
        (instruction_kind IS NULL AND payer_instruction IS NULL)
        OR (
            provider_state = 'bound'
            AND funding_route IS DISTINCT FROM 'bitcoin_fallback'
            AND (
                purpose NOT IN ('mixed', 'provider_only')
                OR funding_committed_at IS NULL
            )
            AND instruction_kind = CASE
                WHEN purpose IN ('mixed', 'provider_only') THEN 'liquid'
                ELSE payer_rail
            END
            AND payer_instruction IS NOT NULL
            AND length(payer_instruction) BETWEEN 1 AND 4096
            AND payer_instruction !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_expected_instruction_shape_chk CHECK (
        expected_instruction_script_len IS NULL
        OR (
            purpose IN ('mixed', 'provider_only')
            AND expected_instruction_script_len BETWEEN 1 AND 10000
        )
    );

CREATE OR REPLACE FUNCTION guard_bull_bitcoin_swap_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    policy_row RECORD;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.reverse_swap_id IS DISTINCT FROM OLD.reverse_swap_id
           OR NEW.chain_swap_id IS DISTINCT FROM OLD.chain_swap_id THEN
            RAISE EXCEPTION 'Bull Bitcoin swap binding is immutable'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'bull_bitcoin_settlements_swap_binding_immutable';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.purpose NOT IN ('mixed', 'provider_only') THEN
        RETURN NEW;
    END IF;

    SELECT policy.owner_npub, policy.credential_id, policy.product,
           policy.fiat_percentage, policy.fiat_currency,
           COALESCE(reverse_swap.invoice_id, chain_swap.invoice_id)
               AS expected_invoice_id
      INTO policy_row
      FROM swap_fiat_settlement_policies policy
      LEFT JOIN swap_records reverse_swap
        ON reverse_swap.id = policy.reverse_swap_id
      LEFT JOIN chain_swap_records chain_swap
        ON chain_swap.id = policy.chain_swap_id
     WHERE policy.reverse_swap_id IS NOT DISTINCT FROM NEW.reverse_swap_id
       AND policy.chain_swap_id IS NOT DISTINCT FROM NEW.chain_swap_id;
    IF NOT FOUND
       OR ROW(
            policy_row.owner_npub, policy_row.credential_id,
            policy_row.product, policy_row.fiat_percentage,
            policy_row.fiat_currency
          ) IS DISTINCT FROM ROW(
            NEW.owner_npub, NEW.credential_id, NEW.product,
            NEW.fiat_percentage, NEW.fiat_currency
          )
       OR (NEW.purpose = 'provider_only'
           AND policy_row.fiat_percentage <> 100)
       OR (NEW.purpose = 'mixed'
           AND policy_row.fiat_percentage NOT BETWEEN 1 AND 99) THEN
        RAISE EXCEPTION 'Bull Bitcoin swap settlement lacks its exact policy'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_swap_policy_authority';
    END IF;
    IF policy_row.expected_invoice_id IS DISTINCT FROM NEW.invoice_id THEN
        RAISE EXCEPTION 'Bull Bitcoin swap settlement borrowed another invoice'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_swap_invoice_authority';
    END IF;
    RETURN NEW;
END
$$;

ALTER TABLE bull_bitcoin_claim_outputs
    DROP CONSTRAINT bull_bitcoin_claim_outputs_role_vout_chk,
    ADD CONSTRAINT bull_bitcoin_claim_outputs_role_vout_chk CHECK (
        (role = 'merchant' AND vout = 0)
        OR (role = 'bull_bitcoin' AND vout IN (0, 1))
    );

CREATE OR REPLACE FUNCTION guard_bull_bitcoin_claim_output_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    settlement_row RECORD;
BEGIN
    SELECT purpose, provider_state, funding_route, funding_committed_at,
           requested_bitcoin_sat
      INTO settlement_row
      FROM bull_bitcoin_settlements
     WHERE id = NEW.settlement_id
     FOR SHARE;
    IF NOT FOUND
       OR settlement_row.purpose NOT IN ('mixed', 'provider_only')
       OR settlement_row.provider_state <> 'bound'
       OR settlement_row.funding_route IS NOT NULL
       OR settlement_row.funding_committed_at IS NOT NULL
       OR NEW.authorized_amount_sat <= 0
       OR (
            NEW.role = 'bull_bitcoin'
            AND NEW.authorized_amount_sat IS DISTINCT FROM
                settlement_row.requested_bitcoin_sat
       )
       OR (
            settlement_row.purpose = 'mixed'
            AND NOT (
                (NEW.role = 'merchant' AND NEW.vout = 0)
                OR (NEW.role = 'bull_bitcoin' AND NEW.vout = 1)
            )
       )
       OR (
            settlement_row.purpose = 'provider_only'
            AND NOT (NEW.role = 'bull_bitcoin' AND NEW.vout = 0)
       ) THEN
        RAISE EXCEPTION 'claim output lacks exact unfunded swap-order authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_claim_outputs_settlement_authority';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION guard_bull_bitcoin_funding_commitment()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    output_count INTEGER;
    output_txids INTEGER;
    merchant_amount_sat BIGINT;
    bull_bitcoin_amount_sat BIGINT;
    bull_bitcoin_vout SMALLINT;
BEGIN
    IF OLD.funding_committed_at IS NOT NULL
       AND NEW.funding_committed_at IS DISTINCT FROM OLD.funding_committed_at THEN
        RAISE EXCEPTION 'Bull Bitcoin funding commitment is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_funding_commitment_immutable';
    END IF;
    IF OLD.funding_committed_at IS NULL
       AND NEW.funding_committed_at IS NOT NULL THEN
        IF NOT (
            NEW.provider_state = 'bound'
            AND NEW.funding_route = 'bull_bitcoin'
            AND NEW.funding_committed_at >= NEW.created_at
        ) THEN
            RAISE EXCEPTION 'invalid Bull Bitcoin funding commitment'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'bull_bitcoin_settlements_funding_commitment_transition';
        END IF;
        IF NEW.purpose IN ('mixed', 'provider_only') THEN
            SELECT COUNT(*), COUNT(DISTINCT txid),
                   MAX(authorized_amount_sat) FILTER (WHERE role = 'merchant'),
                   MAX(authorized_amount_sat) FILTER (WHERE role = 'bull_bitcoin'),
                   MAX(vout) FILTER (WHERE role = 'bull_bitcoin')
              INTO output_count, output_txids,
                   merchant_amount_sat, bull_bitcoin_amount_sat,
                   bull_bitcoin_vout
              FROM bull_bitcoin_claim_outputs
             WHERE settlement_id = NEW.id;
            IF (
                NEW.purpose = 'mixed'
                AND (
                    output_count <> 2
                    OR output_txids <> 1
                    OR bull_bitcoin_vout <> 1
                    OR bull_bitcoin_amount_sat IS DISTINCT FROM
                       ((merchant_amount_sat + bull_bitcoin_amount_sat)
                        * NEW.fiat_percentage / 100)
                )
            ) OR (
                NEW.purpose = 'provider_only'
                AND (
                    output_count <> 1
                    OR output_txids <> 1
                    OR merchant_amount_sat IS NOT NULL
                    OR bull_bitcoin_vout <> 0
                    OR bull_bitcoin_amount_sat IS DISTINCT FROM
                       NEW.requested_bitcoin_sat
                )
            ) THEN
                RAISE EXCEPTION 'swap funding lacks its exact output journal'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'bull_bitcoin_settlements_mixed_output_authority';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END
$$;

COMMENT ON CONSTRAINT bull_bitcoin_settlements_purpose_chk
    ON bull_bitcoin_settlements IS
    'provider_only is a swap-backed 100% allocation; fiat_only remains the historical direct-provider payer path.';

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON FUNCTION guard_bull_bitcoin_swap_binding() FROM PUBLIC;
    REVOKE ALL ON FUNCTION guard_bull_bitcoin_claim_output_insert() FROM PUBLIC;
    REVOKE ALL ON FUNCTION guard_bull_bitcoin_funding_commitment() FROM PUBLIC;

    IF NOT has_table_privilege(
        runtime_role_name, 'swap_fiat_settlement_policies', 'SELECT'
    ) OR NOT has_table_privilege(
        runtime_role_name, 'swap_fiat_settlement_policies', 'INSERT'
    ) OR NOT has_table_privilege(
        runtime_role_name, 'bull_bitcoin_settlements', 'SELECT'
    ) OR NOT has_table_privilege(
        runtime_role_name, 'bull_bitcoin_settlements', 'INSERT'
    ) OR NOT has_table_privilege(
        runtime_role_name, 'bull_bitcoin_settlements', 'UPDATE'
    ) OR NOT has_table_privilege(
        runtime_role_name, 'bull_bitcoin_claim_outputs', 'SELECT'
    ) OR NOT has_table_privilege(
        runtime_role_name, 'bull_bitcoin_claim_outputs', 'INSERT'
    ) THEN
        RAISE EXCEPTION 'migration 079 requires the established least-privilege runtime grants'
            USING ERRCODE = '42501';
    END IF;
END
$$;

COMMIT;

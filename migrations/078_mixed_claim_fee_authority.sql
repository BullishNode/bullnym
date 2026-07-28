-- ============================================================================
-- 078: immutable payer-funded fee authority for mixed Liquid claims
-- ============================================================================
--
-- New mixed reverse and chain offers reserve the exact two-output script-path
-- claim fee before the payer instruction is exposed. The invoice target stays
-- unchanged; the Boltz Liquid source is target + this fee budget. Historical
-- and non-mixed rows retain NULL/NULL and their existing recovery behavior.

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
    reverse_owner_oid OID;
    chain_owner_oid OID;
BEGIN
    SELECT oid INTO runtime_role_oid
      FROM pg_roles WHERE rolname = runtime_role_name;
    IF runtime_role_name IS NULL OR runtime_role_oid IS NULL THEN
        RAISE EXCEPTION 'migration 078 requires an existing runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF current_user = runtime_role_name THEN
        RAISE EXCEPTION 'migration 078 must run as the schema owner, not the runtime role'
            USING ERRCODE = '42501';
    END IF;

    SELECT relowner INTO reverse_owner_oid
      FROM pg_class WHERE oid = to_regclass('public.swap_records');
    SELECT relowner INTO chain_owner_oid
      FROM pg_class WHERE oid = to_regclass('public.chain_swap_records');
    IF reverse_owner_oid IS NULL OR chain_owner_oid IS NULL
       OR pg_get_userbyid(reverse_owner_oid) <> current_user
       OR pg_get_userbyid(chain_owner_oid) <> current_user THEN
        RAISE EXCEPTION 'migration 078 must run as both swap table owners'
            USING ERRCODE = '42501';
    END IF;
    IF runtime_role_oid = reverse_owner_oid
       OR runtime_role_oid = chain_owner_oid
       OR pg_has_role(runtime_role_oid, reverse_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, reverse_owner_oid, 'SET')
       OR pg_has_role(runtime_role_oid, chain_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, chain_owner_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 078 runtime role can assume a swap table owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

ALTER TABLE swap_records
    ADD COLUMN mixed_claim_path TEXT,
    ADD COLUMN mixed_claim_fee_budget_sat BIGINT,
    ADD CONSTRAINT swap_records_mixed_claim_fee_authority_chk CHECK (
        (mixed_claim_path IS NULL AND mixed_claim_fee_budget_sat IS NULL)
        OR
        (mixed_claim_path = 'script' AND mixed_claim_fee_budget_sat > 0)
    );

ALTER TABLE chain_swap_records
    ADD COLUMN mixed_claim_path TEXT,
    ADD COLUMN mixed_claim_fee_budget_sat BIGINT,
    ADD CONSTRAINT chain_swap_records_mixed_claim_fee_authority_chk CHECK (
        (mixed_claim_path IS NULL AND mixed_claim_fee_budget_sat IS NULL)
        OR
        (mixed_claim_path = 'script' AND mixed_claim_fee_budget_sat > 0)
    );

COMMENT ON COLUMN swap_records.mixed_claim_path IS
    'NULL for legacy/non-mixed rows; script for a mixed offer priced with immutable two-output claim authority.';
COMMENT ON COLUMN swap_records.mixed_claim_fee_budget_sat IS
    'Exact two-output script-claim fee funded before payer exposure; paired with mixed_claim_path.';
COMMENT ON COLUMN chain_swap_records.mixed_claim_path IS
    'NULL for legacy/non-mixed rows; script for a mixed offer priced with immutable two-output claim authority.';
COMMENT ON COLUMN chain_swap_records.mixed_claim_fee_budget_sat IS
    'Exact two-output script-claim fee funded before payer exposure; paired with mixed_claim_path.';

CREATE FUNCTION enforce_mixed_claim_fee_authority_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.mixed_claim_path IS NOT DISTINCT FROM OLD.mixed_claim_path
       AND NEW.mixed_claim_fee_budget_sat IS NOT DISTINCT FROM OLD.mixed_claim_fee_budget_sat THEN
        RETURN NEW;
    END IF;

    -- The creation coordinator first makes the provider obligation durable,
    -- then captures the immutable invoice split and funded authority before
    -- returning anything to a payer. That single NULL -> valid-pair transition
    -- is allowed only before claim bytes exist. Every later mutation is an
    -- accounting-integrity violation.
    IF OLD.mixed_claim_path IS NULL
       AND OLD.mixed_claim_fee_budget_sat IS NULL
       AND NEW.mixed_claim_path = 'script'
       AND NEW.mixed_claim_fee_budget_sat > 0
       AND OLD.claim_tx_hex IS NULL THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'mixed claim fee authority is immutable once captured'
        USING ERRCODE = '23514';
END
$$;

REVOKE ALL ON FUNCTION enforce_mixed_claim_fee_authority_immutability() FROM PUBLIC;

CREATE TRIGGER swap_records_mixed_claim_fee_authority_immutable
BEFORE UPDATE OF mixed_claim_path, mixed_claim_fee_budget_sat ON swap_records
FOR EACH ROW EXECUTE FUNCTION enforce_mixed_claim_fee_authority_immutability();

CREATE TRIGGER chain_swap_records_mixed_claim_fee_authority_immutable
BEFORE UPDATE OF mixed_claim_path, mixed_claim_fee_budget_sat ON chain_swap_records
FOR EACH ROW EXECUTE FUNCTION enforce_mixed_claim_fee_authority_immutability();

COMMIT;

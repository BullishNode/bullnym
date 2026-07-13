-- ============================================================================
-- 054: live fee-policy authority and immutable construction provenance
-- ============================================================================
-- Existing transaction bytes remain replayable with NULL metadata. Every new
-- journal write must atomically bind the exact accepted quote, policy inputs,
-- and actual fee derived from the signed bytes.

BEGIN;

SELECT set_config('bullnym.migration_runtime_role', :'runtime_role', TRUE);

DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(
        current_setting('bullnym.migration_runtime_role', TRUE), ''
    );
    runtime_role_oid OID;
    runtime_role_is_superuser BOOLEAN;
    executor_role_oid OID;
BEGIN
    IF runtime_role_name IS NULL THEN
        RAISE EXCEPTION 'migration 054 requires a non-empty runtime_role psql variable'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 054 runtime role % does not exist',
            quote_ident(runtime_role_name) USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 054 refuses superuser runtime role %',
            quote_ident(runtime_role_name) USING ERRCODE = '42501';
    END IF;
    SELECT oid INTO STRICT executor_role_oid FROM pg_roles WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'MEMBER') THEN
        RAISE EXCEPTION 'migration 054 executor must be distinct from runtime role %',
            quote_ident(runtime_role_name) USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE TABLE fee_last_known_good_observations (
    rail                         TEXT PRIMARY KEY
                                     CHECK (rail IN ('bitcoin', 'liquid')),
    generation                   BIGINT NOT NULL CHECK (generation > 0),
    rate_sat_per_vbyte           DOUBLE PRECISION NOT NULL
                                     CHECK (rate_sat_per_vbyte > 0
                                        AND rate_sat_per_vbyte NOT IN (
                                            'NaN'::DOUBLE PRECISION,
                                            'Infinity'::DOUBLE PRECISION,
                                            '-Infinity'::DOUBLE PRECISION
                                        )),
    observed_at_unix             BIGINT NOT NULL CHECK (observed_at_unix >= 0),
    source                       TEXT NOT NULL,
    target                       TEXT NOT NULL,
    provenance                   TEXT NOT NULL
                                     CHECK (btrim(provenance) <> ''
                                        AND octet_length(provenance) <= 512),
    accepted_at_unix             BIGINT NOT NULL CHECK (accepted_at_unix >= 0),
    live_max_age_secs            BIGINT NOT NULL CHECK (live_max_age_secs > 0),
    last_known_good_max_age_secs BIGINT NOT NULL
                                     CHECK (last_known_good_max_age_secs > 0),

    CONSTRAINT fee_lkg_accepted_clock_check CHECK (
        accepted_at_unix >= observed_at_unix
        AND accepted_at_unix - observed_at_unix <= live_max_age_secs
    ),
    CONSTRAINT fee_lkg_rail_authority_check CHECK (
        (rail = 'bitcoin' AND source = 'bitcoin_live' AND target = 'fastestFee')
        OR
        (rail = 'liquid' AND source = 'liquid_live' AND target = '1')
    )
);

CREATE FUNCTION enforce_fee_lkg_monotonic_write()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.generation <> 1 THEN
            RAISE EXCEPTION 'the first fee observation generation must be 1'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.rail IS DISTINCT FROM OLD.rail
       OR NEW.generation <> OLD.generation + 1
       OR NEW.observed_at_unix <= OLD.observed_at_unix THEN
        RAISE EXCEPTION 'fee observations must advance rail generation and observation time'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER fee_lkg_monotonic_write
BEFORE INSERT OR UPDATE ON fee_last_known_good_observations
FOR EACH ROW EXECUTE FUNCTION enforce_fee_lkg_monotonic_write();

ALTER TABLE swap_records
    ADD COLUMN claim_actual_fee_sat BIGINT,
    ADD COLUMN claim_actual_fee_rate_sat_vb DOUBLE PRECISION,
    ADD COLUMN claim_fee_decision_purpose TEXT,
    ADD COLUMN claim_fee_decision_rail TEXT,
    ADD COLUMN claim_fee_decision_target TEXT,
    ADD COLUMN claim_fee_decision_source TEXT,
    ADD COLUMN claim_fee_decision_rate_sat_vb DOUBLE PRECISION,
    ADD COLUMN claim_fee_decision_quoted_at_unix BIGINT,
    ADD COLUMN claim_fee_decision_evaluated_at_unix BIGINT,
    ADD COLUMN claim_fee_decision_freshness_age_secs BIGINT,
    ADD COLUMN claim_fee_decision_freshness_max_age_secs BIGINT,
    ADD COLUMN claim_fee_decision_provenance TEXT,
    ADD COLUMN claim_fee_decision_policy_floor_sat_vb DOUBLE PRECISION,
    ADD COLUMN claim_fee_decision_policy_cap_sat_vb DOUBLE PRECISION,
    ADD COLUMN claim_fee_decision_policy_version TEXT,
    ADD CONSTRAINT swap_records_fee_authority_shape_check CHECK (
        num_nonnulls(
            claim_actual_fee_sat, claim_actual_fee_rate_sat_vb,
            claim_fee_decision_purpose, claim_fee_decision_rail,
            claim_fee_decision_target, claim_fee_decision_source,
            claim_fee_decision_rate_sat_vb, claim_fee_decision_quoted_at_unix,
            claim_fee_decision_evaluated_at_unix,
            claim_fee_decision_freshness_age_secs,
            claim_fee_decision_freshness_max_age_secs,
            claim_fee_decision_provenance,
            claim_fee_decision_policy_floor_sat_vb,
            claim_fee_decision_policy_cap_sat_vb,
            claim_fee_decision_policy_version
        ) IN (0, 15)
    ),
    ADD CONSTRAINT swap_records_fee_authority_value_check CHECK (
        claim_fee_decision_purpose IS NULL OR (
            claim_tx_hex IS NOT NULL
            AND claim_actual_fee_sat > 0
            AND claim_actual_fee_rate_sat_vb > 0
            AND claim_actual_fee_rate_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND claim_fee_decision_purpose = 'reverse_liquid_claim'
            AND claim_fee_decision_rail = 'liquid'
            AND claim_fee_decision_target = '1'
            AND claim_fee_decision_source IN ('liquid_live', 'liquid_last_known_good')
            AND claim_fee_decision_rate_sat_vb > 0
            AND claim_fee_decision_rate_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND claim_fee_decision_quoted_at_unix >= 0
            AND claim_fee_decision_evaluated_at_unix >= claim_fee_decision_quoted_at_unix
            AND claim_fee_decision_freshness_age_secs >= 0
            AND claim_fee_decision_freshness_max_age_secs > 0
            AND claim_fee_decision_evaluated_at_unix
                - claim_fee_decision_quoted_at_unix
                = claim_fee_decision_freshness_age_secs
            AND claim_fee_decision_freshness_age_secs
                <= claim_fee_decision_freshness_max_age_secs
            AND btrim(claim_fee_decision_provenance) <> ''
            AND octet_length(claim_fee_decision_provenance) <= 512
            AND claim_fee_decision_policy_floor_sat_vb > 0
            AND claim_fee_decision_policy_floor_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND claim_fee_decision_policy_cap_sat_vb
                >= claim_fee_decision_policy_floor_sat_vb
            AND claim_fee_decision_policy_cap_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND claim_fee_decision_rate_sat_vb BETWEEN
                claim_fee_decision_policy_floor_sat_vb
                AND claim_fee_decision_policy_cap_sat_vb
            AND claim_fee_decision_policy_version = 'review25-v1'
        )
    );

ALTER TABLE chain_swap_records
    ADD COLUMN claim_actual_fee_sat BIGINT,
    ADD COLUMN claim_actual_fee_rate_sat_vb DOUBLE PRECISION,
    ADD COLUMN claim_fee_decision_purpose TEXT,
    ADD COLUMN claim_fee_decision_rail TEXT,
    ADD COLUMN claim_fee_decision_target TEXT,
    ADD COLUMN claim_fee_decision_source TEXT,
    ADD COLUMN claim_fee_decision_rate_sat_vb DOUBLE PRECISION,
    ADD COLUMN claim_fee_decision_quoted_at_unix BIGINT,
    ADD COLUMN claim_fee_decision_evaluated_at_unix BIGINT,
    ADD COLUMN claim_fee_decision_freshness_age_secs BIGINT,
    ADD COLUMN claim_fee_decision_freshness_max_age_secs BIGINT,
    ADD COLUMN claim_fee_decision_provenance TEXT,
    ADD COLUMN claim_fee_decision_policy_floor_sat_vb DOUBLE PRECISION,
    ADD COLUMN claim_fee_decision_policy_cap_sat_vb DOUBLE PRECISION,
    ADD COLUMN claim_fee_decision_policy_version TEXT,
    ADD CONSTRAINT chain_swap_records_fee_authority_shape_check CHECK (
        num_nonnulls(
            claim_actual_fee_sat, claim_actual_fee_rate_sat_vb,
            claim_fee_decision_purpose, claim_fee_decision_rail,
            claim_fee_decision_target, claim_fee_decision_source,
            claim_fee_decision_rate_sat_vb, claim_fee_decision_quoted_at_unix,
            claim_fee_decision_evaluated_at_unix,
            claim_fee_decision_freshness_age_secs,
            claim_fee_decision_freshness_max_age_secs,
            claim_fee_decision_provenance,
            claim_fee_decision_policy_floor_sat_vb,
            claim_fee_decision_policy_cap_sat_vb,
            claim_fee_decision_policy_version
        ) IN (0, 15)
    ),
    ADD CONSTRAINT chain_swap_records_fee_authority_value_check CHECK (
        claim_fee_decision_purpose IS NULL OR (
            claim_tx_hex IS NOT NULL
            AND claim_actual_fee_sat > 0
            AND claim_actual_fee_rate_sat_vb > 0
            AND claim_actual_fee_rate_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND claim_fee_decision_purpose = 'chain_liquid_claim'
            AND claim_fee_decision_rail = 'liquid'
            AND claim_fee_decision_target = '1'
            AND claim_fee_decision_source IN ('liquid_live', 'liquid_last_known_good')
            AND claim_fee_decision_rate_sat_vb > 0
            AND claim_fee_decision_rate_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND claim_fee_decision_quoted_at_unix >= 0
            AND claim_fee_decision_evaluated_at_unix >= claim_fee_decision_quoted_at_unix
            AND claim_fee_decision_freshness_age_secs >= 0
            AND claim_fee_decision_freshness_max_age_secs > 0
            AND claim_fee_decision_evaluated_at_unix
                - claim_fee_decision_quoted_at_unix
                = claim_fee_decision_freshness_age_secs
            AND claim_fee_decision_freshness_age_secs
                <= claim_fee_decision_freshness_max_age_secs
            AND btrim(claim_fee_decision_provenance) <> ''
            AND octet_length(claim_fee_decision_provenance) <= 512
            AND claim_fee_decision_policy_floor_sat_vb > 0
            AND claim_fee_decision_policy_floor_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND claim_fee_decision_policy_cap_sat_vb
                >= claim_fee_decision_policy_floor_sat_vb
            AND claim_fee_decision_policy_cap_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND claim_fee_decision_rate_sat_vb BETWEEN
                claim_fee_decision_policy_floor_sat_vb
                AND claim_fee_decision_policy_cap_sat_vb
            AND claim_fee_decision_policy_version = 'review25-v1'
        )
    );

CREATE FUNCTION guard_review25_liquid_claim_fee_authority()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.claim_tx_hex IS NOT NULL
           AND NEW.claim_fee_decision_purpose IS NULL THEN
            RAISE EXCEPTION 'new Liquid claim bytes require Review-25 fee authority'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.claim_tx_hex IS NULL
       AND NEW.claim_tx_hex IS NOT NULL
       AND NEW.claim_fee_decision_purpose IS NULL THEN
        RAISE EXCEPTION 'new Liquid claim bytes require Review-25 fee authority'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.claim_tx_hex IS NOT NULL
       AND NEW.claim_tx_hex IS DISTINCT FROM OLD.claim_tx_hex THEN
        RAISE EXCEPTION 'journaled Liquid claim bytes are immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.claim_tx_hex IS NOT NULL
       AND OLD.claim_fee_decision_purpose IS NULL
       AND NEW.claim_fee_decision_purpose IS NOT NULL THEN
        RAISE EXCEPTION 'historical Liquid fee authority cannot be fabricated'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.claim_fee_decision_purpose IS NOT NULL
       AND ROW(
               NEW.claim_actual_fee_sat, NEW.claim_actual_fee_rate_sat_vb,
               NEW.claim_fee_decision_purpose, NEW.claim_fee_decision_rail,
               NEW.claim_fee_decision_target, NEW.claim_fee_decision_source,
               NEW.claim_fee_decision_rate_sat_vb,
               NEW.claim_fee_decision_quoted_at_unix,
               NEW.claim_fee_decision_evaluated_at_unix,
               NEW.claim_fee_decision_freshness_age_secs,
               NEW.claim_fee_decision_freshness_max_age_secs,
               NEW.claim_fee_decision_provenance,
               NEW.claim_fee_decision_policy_floor_sat_vb,
               NEW.claim_fee_decision_policy_cap_sat_vb,
               NEW.claim_fee_decision_policy_version
       ) IS DISTINCT FROM ROW(
               OLD.claim_actual_fee_sat, OLD.claim_actual_fee_rate_sat_vb,
               OLD.claim_fee_decision_purpose, OLD.claim_fee_decision_rail,
               OLD.claim_fee_decision_target, OLD.claim_fee_decision_source,
               OLD.claim_fee_decision_rate_sat_vb,
               OLD.claim_fee_decision_quoted_at_unix,
               OLD.claim_fee_decision_evaluated_at_unix,
               OLD.claim_fee_decision_freshness_age_secs,
               OLD.claim_fee_decision_freshness_max_age_secs,
               OLD.claim_fee_decision_provenance,
               OLD.claim_fee_decision_policy_floor_sat_vb,
               OLD.claim_fee_decision_policy_cap_sat_vb,
               OLD.claim_fee_decision_policy_version
       ) THEN
        RAISE EXCEPTION 'Liquid claim fee authority is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER swap_records_guard_review25_fee_authority
BEFORE INSERT OR UPDATE ON swap_records
FOR EACH ROW EXECUTE FUNCTION guard_review25_liquid_claim_fee_authority();

CREATE TRIGGER chain_swap_records_guard_review25_fee_authority
BEFORE INSERT OR UPDATE ON chain_swap_records
FOR EACH ROW EXECUTE FUNCTION guard_review25_liquid_claim_fee_authority();

ALTER TABLE chain_swap_tx_attempts
    ADD COLUMN fee_decision_purpose TEXT,
    ADD COLUMN fee_decision_rail TEXT,
    ADD COLUMN fee_decision_target TEXT,
    ADD COLUMN fee_decision_source TEXT,
    ADD COLUMN fee_decision_rate_sat_vb DOUBLE PRECISION,
    ADD COLUMN fee_decision_quoted_at_unix BIGINT,
    ADD COLUMN fee_decision_evaluated_at_unix BIGINT,
    ADD COLUMN fee_decision_freshness_age_secs BIGINT,
    ADD COLUMN fee_decision_freshness_max_age_secs BIGINT,
    ADD COLUMN fee_decision_provenance TEXT,
    ADD COLUMN fee_decision_policy_floor_sat_vb DOUBLE PRECISION,
    ADD COLUMN fee_decision_policy_cap_sat_vb DOUBLE PRECISION,
    ADD COLUMN fee_decision_policy_version TEXT,
    ADD CONSTRAINT chain_swap_tx_attempts_fee_authority_shape_check CHECK (
        num_nonnulls(
            fee_decision_purpose, fee_decision_rail, fee_decision_target,
            fee_decision_source, fee_decision_rate_sat_vb,
            fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix,
            fee_decision_freshness_age_secs,
            fee_decision_freshness_max_age_secs, fee_decision_provenance,
            fee_decision_policy_floor_sat_vb, fee_decision_policy_cap_sat_vb,
            fee_decision_policy_version
        ) IN (0, 13)
    ),
    ADD CONSTRAINT chain_swap_tx_attempts_fee_authority_value_check CHECK (
        fee_decision_purpose IS NULL OR (
            fee_decision_purpose = 'bitcoin_recovery'
            AND fee_decision_rail = 'bitcoin'
            AND fee_decision_target = 'fastestFee'
            AND fee_decision_source IN ('bitcoin_live', 'bitcoin_last_known_good')
            AND fee_decision_rate_sat_vb > 0
            AND fee_decision_rate_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND fee_decision_quoted_at_unix >= 0
            AND fee_decision_evaluated_at_unix >= fee_decision_quoted_at_unix
            AND fee_decision_freshness_age_secs >= 0
            AND fee_decision_freshness_max_age_secs > 0
            AND fee_decision_evaluated_at_unix - fee_decision_quoted_at_unix
                = fee_decision_freshness_age_secs
            AND fee_decision_freshness_age_secs
                <= fee_decision_freshness_max_age_secs
            AND btrim(fee_decision_provenance) <> ''
            AND octet_length(fee_decision_provenance) <= 512
            AND fee_decision_policy_floor_sat_vb > 0
            AND fee_decision_policy_floor_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND fee_decision_policy_cap_sat_vb >= fee_decision_policy_floor_sat_vb
            AND fee_decision_policy_cap_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND fee_decision_rate_sat_vb BETWEEN fee_decision_policy_floor_sat_vb
                                             AND fee_decision_policy_cap_sat_vb
            AND fee_decision_policy_version = 'review25-v1'
        )
    );

CREATE FUNCTION require_review25_bitcoin_attempt_fee_authority()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.fee_decision_purpose IS NULL THEN
        RAISE EXCEPTION 'new Bitcoin recovery bytes require Review-25 fee authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER chain_swap_tx_attempts_require_review25_fee_authority
BEFORE INSERT ON chain_swap_tx_attempts
FOR EACH ROW EXECUTE FUNCTION require_review25_bitcoin_attempt_fee_authority();

CREATE OR REPLACE FUNCTION guard_chain_swap_tx_attempt_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.chain_swap_id IS DISTINCT FROM OLD.chain_swap_id
       OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.raw_tx_hex IS DISTINCT FROM OLD.raw_tx_hex
       OR NEW.txid IS DISTINCT FROM OLD.txid
       OR NEW.source_prevouts IS DISTINCT FROM OLD.source_prevouts
       OR NEW.destination_address IS DISTINCT FROM OLD.destination_address
       OR NEW.destination_script_hex IS DISTINCT FROM OLD.destination_script_hex
       OR NEW.destination_vout IS DISTINCT FROM OLD.destination_vout
       OR NEW.destination_amount_sat IS DISTINCT FROM OLD.destination_amount_sat
       OR NEW.fee_amount_sat IS DISTINCT FROM OLD.fee_amount_sat
       OR NEW.fee_rate_sat_vb IS DISTINCT FROM OLD.fee_rate_sat_vb
       OR NEW.fee_decision_purpose IS DISTINCT FROM OLD.fee_decision_purpose
       OR NEW.fee_decision_rail IS DISTINCT FROM OLD.fee_decision_rail
       OR NEW.fee_decision_target IS DISTINCT FROM OLD.fee_decision_target
       OR NEW.fee_decision_source IS DISTINCT FROM OLD.fee_decision_source
       OR NEW.fee_decision_rate_sat_vb IS DISTINCT FROM OLD.fee_decision_rate_sat_vb
       OR NEW.fee_decision_quoted_at_unix IS DISTINCT FROM OLD.fee_decision_quoted_at_unix
       OR NEW.fee_decision_evaluated_at_unix IS DISTINCT FROM OLD.fee_decision_evaluated_at_unix
       OR NEW.fee_decision_freshness_age_secs IS DISTINCT FROM OLD.fee_decision_freshness_age_secs
       OR NEW.fee_decision_freshness_max_age_secs IS DISTINCT FROM OLD.fee_decision_freshness_max_age_secs
       OR NEW.fee_decision_provenance IS DISTINCT FROM OLD.fee_decision_provenance
       OR NEW.fee_decision_policy_floor_sat_vb IS DISTINCT FROM OLD.fee_decision_policy_floor_sat_vb
       OR NEW.fee_decision_policy_cap_sat_vb IS DISTINCT FROM OLD.fee_decision_policy_cap_sat_vb
       OR NEW.fee_decision_policy_version IS DISTINCT FROM OLD.fee_decision_policy_version
       OR NEW.constructed_at IS DISTINCT FROM OLD.constructed_at THEN
        RAISE EXCEPTION 'chain-swap transaction intent is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

ALTER TABLE swap_records DROP COLUMN current_fee_rate;

DO $$
DECLARE runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
        cache_acl RECORD;
BEGIN
    EXECUTE format(
        'REVOKE ALL ON public.fee_last_known_good_observations FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE ON public.fee_last_known_good_observations TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'SELECT has_table_privilege(%L, ''public.fee_last_known_good_observations'', ''SELECT'') AS can_select, \
                has_table_privilege(%L, ''public.fee_last_known_good_observations'', ''INSERT'') AS can_insert, \
                has_table_privilege(%L, ''public.fee_last_known_good_observations'', ''UPDATE'') AS can_update, \
                has_table_privilege(%L, ''public.fee_last_known_good_observations'', ''DELETE'') AS can_delete, \
                has_table_privilege(%L, ''public.fee_last_known_good_observations'', ''TRUNCATE'') AS can_truncate, \
                has_table_privilege(%L, ''public.fee_last_known_good_observations'', ''REFERENCES'') AS can_reference, \
                has_table_privilege(%L, ''public.fee_last_known_good_observations'', ''TRIGGER'') AS can_trigger',
        runtime_role_name, runtime_role_name, runtime_role_name,
        runtime_role_name, runtime_role_name, runtime_role_name,
        runtime_role_name
    ) INTO cache_acl;
    IF NOT cache_acl.can_select OR NOT cache_acl.can_insert OR NOT cache_acl.can_update
       OR cache_acl.can_delete OR cache_acl.can_truncate
       OR cache_acl.can_reference OR cache_acl.can_trigger THEN
        RAISE EXCEPTION 'migration 054 runtime fee-cache privileges are unsafe'
            USING ERRCODE = '42501';
    END IF;
END
$$;

COMMIT;

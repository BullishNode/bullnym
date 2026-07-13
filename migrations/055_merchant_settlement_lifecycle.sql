-- ============================================================================
-- 055: exact merchant-output settlement lifecycle
-- ============================================================================
--
-- Extend the immutable chain-swap transaction journal to Liquid claims and
-- persist the exact confirmation/accounting lifecycle consumed by the runtime.
-- Historical claim bytes cannot be assigned source, confidential asset, or
-- destination evidence after the fact, so the upgrade aborts instead of
-- manufacturing a journal for any still-claimable legacy row.

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
    relation_owner_oid OID;
    relation_name TEXT;
    executor_role_name TEXT := current_user;
    function_owner_oid OID;
    function_name TEXT;
BEGIN
    IF runtime_role_name IS NULL THEN
        RAISE EXCEPTION 'migration 055 requires a non-empty runtime_role psql variable'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 055 runtime role % does not exist',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 055 refuses superuser runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;
    SELECT oid INTO STRICT executor_role_oid FROM pg_roles WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'MEMBER') THEN
        RAISE EXCEPTION 'migration 055 runtime role % can assume its schema owner %',
            quote_ident(runtime_role_name), quote_ident(current_user)
            USING ERRCODE = '42501';
    END IF;

    FOREACH relation_name IN ARRAY ARRAY[
        'chain_swap_tx_attempts', 'invoice_payment_events'
    ] LOOP
        SELECT relation.relowner
          INTO STRICT relation_owner_oid
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relname = relation_name
           AND relation.relkind = 'r';
        IF relation_owner_oid = runtime_role_oid THEN
            EXECUTE format(
                'ALTER TABLE public.%I OWNER TO %I',
                relation_name, executor_role_name
            );
            SELECT relation.relowner
              INTO STRICT relation_owner_oid
              FROM pg_class relation
              JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname = 'public'
               AND relation.relname = relation_name
               AND relation.relkind = 'r';
        END IF;
        IF relation_owner_oid = runtime_role_oid
           OR pg_has_role(runtime_role_oid, relation_owner_oid, 'MEMBER') THEN
            RAISE EXCEPTION 'migration 055 runtime role % owns or can assume owner of %',
                quote_ident(runtime_role_name), relation_name
                USING ERRCODE = '42501';
        END IF;
    END LOOP;

    SELECT relation.relowner
      INTO STRICT relation_owner_oid
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relname = 'invoice_payment_events_accounting_sequence_seq'
       AND relation.relkind = 'S';
    IF relation_owner_oid = runtime_role_oid THEN
        EXECUTE format(
            'ALTER SEQUENCE public.invoice_payment_events_accounting_sequence_seq OWNER TO %I',
            executor_role_name
        );
    END IF;
    SELECT relation.relowner
      INTO STRICT relation_owner_oid
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relname = 'invoice_payment_events_accounting_sequence_seq'
       AND relation.relkind = 'S';
    IF relation_owner_oid = runtime_role_oid
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'MEMBER') THEN
        RAISE EXCEPTION 'migration 055 runtime role owns or can assume the accounting sequence owner'
            USING ERRCODE = '42501';
    END IF;

    FOREACH function_name IN ARRAY ARRAY[
        'guard_chain_swap_tx_attempt_immutable',
        'require_review25_bitcoin_attempt_fee_authority',
        'guard_invoice_payment_event_evidence'
    ] LOOP
        SELECT procedure_info.proowner
          INTO STRICT function_owner_oid
          FROM pg_proc procedure_info
          JOIN pg_namespace namespace ON namespace.oid = procedure_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND procedure_info.proname = function_name
           AND procedure_info.pronargs = 0;
        IF function_owner_oid = runtime_role_oid THEN
            EXECUTE format(
                'ALTER FUNCTION public.%I() OWNER TO %I',
                function_name, executor_role_name
            );
        END IF;
        SELECT procedure_info.proowner
          INTO STRICT function_owner_oid
          FROM pg_proc procedure_info
          JOIN pg_namespace namespace ON namespace.oid = procedure_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND procedure_info.proname = function_name
           AND procedure_info.pronargs = 0;
        IF function_owner_oid = runtime_role_oid
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'MEMBER') THEN
            RAISE EXCEPTION 'migration 055 runtime role owns or can assume owner of function %',
                function_name
                USING ERRCODE = '42501';
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1
          FROM chain_swap_records
         WHERE status IN (
             'server_lock_mempool', 'server_lock_confirmed',
             'claiming', 'claim_failed'
         )
           AND (claim_tx_hex IS NOT NULL OR claim_txid IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'migration 055 refuses unverifiable claimable legacy claim bytes'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'migration_055_zero_legacy_claim_journal';
    END IF;
END
$$;

-- One immutable family now covers Bitcoin recovery, the original Liquid
-- claim, and at most one explicitly linked Liquid replacement.
ALTER TABLE chain_swap_tx_attempts
    DROP CONSTRAINT chain_swap_tx_attempts_purpose_check,
    DROP CONSTRAINT chain_swap_tx_attempts_one_recovery,
    DROP CONSTRAINT chain_swap_tx_attempts_fee_authority_value_check,
    ADD COLUMN replaces_txid TEXT,
    ADD COLUMN destination_asset_id TEXT,
    ADD COLUMN liquid_blinding_key_hex TEXT,
    ADD CONSTRAINT chain_swap_tx_attempts_purpose_check CHECK (
        purpose IN ('btc_recovery', 'liquid_claim', 'liquid_claim_replacement')
    ),
    ADD CONSTRAINT chain_swap_tx_attempts_one_purpose_key
        UNIQUE (chain_swap_id, purpose),
    ADD CONSTRAINT chain_swap_tx_attempts_replaces_shape_check CHECK (
        (purpose = 'liquid_claim_replacement') = (replaces_txid IS NOT NULL)
        AND (replaces_txid IS NULL OR replaces_txid ~ '^[0-9a-f]{64}$')
        AND replaces_txid IS DISTINCT FROM txid
    ),
    ADD CONSTRAINT chain_swap_tx_attempts_asset_shape_check CHECK (
        (
            purpose = 'btc_recovery'
            AND destination_asset_id IS NULL
            AND liquid_blinding_key_hex IS NULL
        ) OR (
            purpose IN ('liquid_claim', 'liquid_claim_replacement')
            AND destination_asset_id IS NOT NULL
            AND destination_asset_id ~ '^[0-9a-f]{64}$'
            AND liquid_blinding_key_hex IS NOT NULL
            AND liquid_blinding_key_hex ~ '^[0-9a-f]{64}$'
        )
    ),
    ADD CONSTRAINT chain_swap_tx_attempts_fee_authority_value_check CHECK (
        fee_decision_purpose IS NULL OR ((
            (
                purpose = 'btc_recovery'
                AND fee_decision_purpose = 'bitcoin_recovery'
                AND fee_decision_rail = 'bitcoin'
                AND fee_decision_target = 'fastestFee'
                AND fee_decision_source IN (
                    'bitcoin_live', 'bitcoin_last_known_good'
                )
            ) OR (
                purpose IN ('liquid_claim', 'liquid_claim_replacement')
                AND fee_decision_purpose = 'chain_liquid_claim'
                AND fee_decision_rail = 'liquid'
                AND fee_decision_target = '1'
                AND fee_decision_source IN (
                    'liquid_live', 'liquid_last_known_good'
                )
            )
        ) AND (
            fee_decision_rate_sat_vb > 0
            AND fee_decision_rate_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND fee_decision_quoted_at_unix >= 0
            AND fee_decision_evaluated_at_unix
                >= fee_decision_quoted_at_unix
            AND fee_decision_freshness_age_secs >= 0
            AND fee_decision_freshness_max_age_secs > 0
            AND fee_decision_evaluated_at_unix
                - fee_decision_quoted_at_unix
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
            AND fee_decision_policy_cap_sat_vb
                >= fee_decision_policy_floor_sat_vb
            AND fee_decision_policy_cap_sat_vb NOT IN (
                'NaN'::DOUBLE PRECISION,
                'Infinity'::DOUBLE PRECISION,
                '-Infinity'::DOUBLE PRECISION
            )
            AND fee_decision_rate_sat_vb BETWEEN
                fee_decision_policy_floor_sat_vb
                AND fee_decision_policy_cap_sat_vb
            AND fee_decision_policy_version = 'review25-v1'
        ))
    ),
    ADD CONSTRAINT chain_swap_tx_attempts_replaces_fkey
        FOREIGN KEY (replaces_txid)
        REFERENCES chain_swap_tx_attempts(txid)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION require_review25_bitcoin_attempt_fee_authority()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    parent chain_swap_records%ROWTYPE;
BEGIN
    IF NEW.fee_decision_purpose IS NULL THEN
        RAISE EXCEPTION 'new transaction attempt bytes require Review-25 fee authority'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.purpose = 'liquid_claim' THEN
        SELECT * INTO parent
          FROM chain_swap_records
         WHERE id = NEW.chain_swap_id
         FOR KEY SHARE;
        IF NOT FOUND
           OR ROW(
               NEW.raw_tx_hex, NEW.txid,
               NEW.fee_amount_sat, NEW.fee_rate_sat_vb,
               NEW.fee_decision_purpose, NEW.fee_decision_rail,
               NEW.fee_decision_target, NEW.fee_decision_source,
               NEW.fee_decision_rate_sat_vb,
               NEW.fee_decision_quoted_at_unix,
               NEW.fee_decision_evaluated_at_unix,
               NEW.fee_decision_freshness_age_secs,
               NEW.fee_decision_freshness_max_age_secs,
               NEW.fee_decision_provenance,
               NEW.fee_decision_policy_floor_sat_vb,
               NEW.fee_decision_policy_cap_sat_vb,
               NEW.fee_decision_policy_version
           ) IS DISTINCT FROM ROW(
               parent.claim_tx_hex, parent.claim_txid,
               parent.claim_actual_fee_sat,
               parent.claim_actual_fee_rate_sat_vb,
               parent.claim_fee_decision_purpose,
               parent.claim_fee_decision_rail,
               parent.claim_fee_decision_target,
               parent.claim_fee_decision_source,
               parent.claim_fee_decision_rate_sat_vb,
               parent.claim_fee_decision_quoted_at_unix,
               parent.claim_fee_decision_evaluated_at_unix,
               parent.claim_fee_decision_freshness_age_secs,
               parent.claim_fee_decision_freshness_max_age_secs,
               parent.claim_fee_decision_provenance,
               parent.claim_fee_decision_policy_floor_sat_vb,
               parent.claim_fee_decision_policy_cap_sat_vb,
               parent.claim_fee_decision_policy_version
           ) THEN
            RAISE EXCEPTION 'Liquid claim attempt authority differs from its parent claim'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION guard_chain_swap_tx_attempt_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.chain_swap_id IS DISTINCT FROM OLD.chain_swap_id
       OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.replaces_txid IS DISTINCT FROM OLD.replaces_txid
       OR NEW.raw_tx_hex IS DISTINCT FROM OLD.raw_tx_hex
       OR NEW.txid IS DISTINCT FROM OLD.txid
       OR NEW.source_prevouts IS DISTINCT FROM OLD.source_prevouts
       OR NEW.destination_address IS DISTINCT FROM OLD.destination_address
       OR NEW.destination_script_hex IS DISTINCT FROM OLD.destination_script_hex
       OR NEW.destination_asset_id IS DISTINCT FROM OLD.destination_asset_id
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
       OR NEW.liquid_blinding_key_hex IS DISTINCT FROM OLD.liquid_blinding_key_hex
       OR NEW.constructed_at IS DISTINCT FROM OLD.constructed_at THEN
        RAISE EXCEPTION 'chain-swap transaction intent is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION enforce_liquid_claim_replacement_lineage()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    original chain_swap_tx_attempts%ROWTYPE;
BEGIN
    IF NEW.purpose <> 'liquid_claim_replacement' THEN
        RETURN NEW;
    END IF;
    SELECT * INTO original
      FROM chain_swap_tx_attempts
     WHERE txid = NEW.replaces_txid
     FOR KEY SHARE;
    IF NOT FOUND
       OR original.chain_swap_id <> NEW.chain_swap_id
       OR original.purpose <> 'liquid_claim'
       OR original.status = 'integrity_hold'
       OR original.destination_address <> NEW.destination_address
       OR original.destination_script_hex <> NEW.destination_script_hex
       OR original.destination_asset_id IS DISTINCT FROM NEW.destination_asset_id
       OR original.liquid_blinding_key_hex IS DISTINCT FROM NEW.liquid_blinding_key_hex THEN
        RAISE EXCEPTION 'Liquid claim replacement does not extend its exact journal family'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'chain_swap_tx_attempts_replacement_family_check';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER chain_swap_tx_attempts_validate_replacement
    BEFORE INSERT ON chain_swap_tx_attempts
    FOR EACH ROW EXECUTE FUNCTION enforce_liquid_claim_replacement_lineage();

-- Exact settlement events are distinguishable from legacy provider-value
-- events. No existing event is relabelled or linked to a chain swap.
ALTER TABLE invoice_payment_events
    DROP CONSTRAINT invoice_payment_events_source_chk,
    DROP CONSTRAINT invoice_payment_events_source_rail_chk,
    DROP CONSTRAINT invoice_payment_events_boltz_evidence_chk,
    ADD COLUMN merchant_settlement_family_key TEXT,
    ADD COLUMN merchant_chain_swap_id UUID,
    ADD COLUMN merchant_settlement_finalized BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT invoice_payment_events_source_chk CHECK (
        source IS NULL OR source IN (
            'bitcoin_direct', 'liquid_direct', 'lightning_boltz_reverse',
            'bitcoin_boltz_chain', 'bitcoin_boltz_recovery'
        )
    ),
    ADD CONSTRAINT invoice_payment_events_source_rail_chk CHECK (
        source IS NULL OR (
            (source IN ('bitcoin_direct', 'bitcoin_boltz_chain', 'bitcoin_boltz_recovery')
                AND rail = 'bitcoin')
            OR (source = 'liquid_direct' AND rail = 'liquid')
            OR (source = 'lightning_boltz_reverse' AND rail = 'lightning')
        )
    ),
    ADD CONSTRAINT invoice_payment_events_boltz_evidence_chk CHECK (
        source IS NULL
        OR source NOT IN (
            'lightning_boltz_reverse', 'bitcoin_boltz_chain',
            'bitcoin_boltz_recovery'
        )
        OR (
            txid IS NOT NULL
            AND txid ~ '^[0-9a-fA-F]{64}$'
            AND boltz_swap_id IS NOT NULL
            AND (
                (source = 'lightning_boltz_reverse' AND vout IS NULL)
                OR (
                    source = 'bitcoin_boltz_chain'
                    AND merchant_chain_swap_id IS NULL
                    AND vout IS NULL
                )
                OR (
                    source IN ('bitcoin_boltz_chain', 'bitcoin_boltz_recovery')
                    AND merchant_chain_swap_id IS NOT NULL
                    AND vout >= 0
                    AND address IS NOT NULL
                )
            )
        )
    ),
    ADD CONSTRAINT invoice_payment_events_merchant_settlement_shape_check CHECK (
        (
            merchant_settlement_family_key IS NULL
            AND merchant_chain_swap_id IS NULL
            AND merchant_settlement_finalized = FALSE
        ) OR (
            merchant_settlement_family_key IS NOT NULL
            AND merchant_chain_swap_id IS NOT NULL
            AND source IN ('bitcoin_boltz_chain', 'bitcoin_boltz_recovery')
            AND verification_state = 'verified'
            AND txid IS NOT NULL
            AND txid ~ '^[0-9a-f]{64}$'
            AND vout IS NOT NULL
            AND vout >= 0
            AND address IS NOT NULL
            AND merchant_settlement_family_key ~
                '^chain_swap_merchant_output:[0-9a-f-]{36}:[0-9a-f]{64}$'
            AND split_part(merchant_settlement_family_key, ':', 2)
                = merchant_chain_swap_id::TEXT
            AND event_key = merchant_settlement_family_key || ':' || txid || ':' || vout::TEXT
        )
    ),
    ADD CONSTRAINT invoice_payment_events_merchant_chain_swap_fkey
        FOREIGN KEY (merchant_chain_swap_id)
        REFERENCES chain_swap_records(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE UNIQUE INDEX invoice_payment_events_one_active_merchant_settlement_idx
    ON invoice_payment_events(merchant_chain_swap_id)
    WHERE merchant_chain_swap_id IS NOT NULL AND accounting_state = 'active';

CREATE OR REPLACE FUNCTION guard_invoice_payment_event_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.invoice_id IS DISTINCT FROM OLD.invoice_id
     OR NEW.rail IS DISTINCT FROM OLD.rail
     OR NEW.source IS DISTINCT FROM OLD.source
     OR NEW.event_key IS DISTINCT FROM OLD.event_key
     OR NEW.amount_sat IS DISTINCT FROM OLD.amount_sat
     OR NEW.txid IS DISTINCT FROM OLD.txid
     OR NEW.vout IS DISTINCT FROM OLD.vout
     OR NEW.boltz_swap_id IS DISTINCT FROM OLD.boltz_swap_id
     OR NEW.address IS DISTINCT FROM OLD.address
     OR NEW.accounting_sequence IS DISTINCT FROM OLD.accounting_sequence
     OR NEW.merchant_settlement_family_key IS DISTINCT FROM OLD.merchant_settlement_family_key
     OR NEW.merchant_chain_swap_id IS DISTINCT FROM OLD.merchant_chain_swap_id
     OR (OLD.observation_id IS NOT NULL
         AND NEW.observation_id IS DISTINCT FROM OLD.observation_id) THEN
    RAISE EXCEPTION 'invoice payment event evidence is immutable'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION reject_merchant_settlement_event_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.merchant_chain_swap_id IS NOT NULL THEN
        RAISE EXCEPTION 'exact merchant settlement events cannot be deleted or cascaded'
            USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER invoice_payment_event_reject_merchant_settlement_delete
    BEFORE DELETE ON invoice_payment_events
    FOR EACH ROW EXECUTE FUNCTION reject_merchant_settlement_event_delete();

CREATE TABLE merchant_settlement_checkpoints (
    chain_swap_id       UUID NOT NULL,
    settlement_path     TEXT NOT NULL,
    invoice_id          UUID NOT NULL,
    boltz_swap_id       TEXT NOT NULL,
    format_version      SMALLINT NOT NULL,
    checkpoint_version  BIGINT NOT NULL,
    journal_txid        TEXT NOT NULL,
    snapshot_json       JSONB NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (chain_swap_id, settlement_path),
    CONSTRAINT merchant_settlement_checkpoint_chain_fkey
        FOREIGN KEY (chain_swap_id) REFERENCES chain_swap_records(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT merchant_settlement_checkpoint_invoice_fkey
        FOREIGN KEY (invoice_id) REFERENCES invoices(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT merchant_settlement_checkpoint_journal_fkey
        FOREIGN KEY (journal_txid) REFERENCES chain_swap_tx_attempts(txid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT merchant_settlement_checkpoint_shape_check CHECK (
        settlement_path IN ('liquid_claim', 'bitcoin_recovery')
        AND octet_length(boltz_swap_id) BETWEEN 1 AND 200
        AND format_version = 1
        AND checkpoint_version > 0
        AND journal_txid ~ '^[0-9a-f]{64}$'
        AND jsonb_typeof(snapshot_json) = 'object'
        AND updated_at >= created_at
    )
);

CREATE INDEX merchant_settlement_checkpoints_invoice_idx
    ON merchant_settlement_checkpoints(invoice_id);

CREATE TABLE merchant_settlement_retained_outputs (
    event_key              TEXT PRIMARY KEY,
    family_key             TEXT NOT NULL,
    invoice_id             UUID NOT NULL,
    chain_swap_id          UUID NOT NULL,
    boltz_swap_id          TEXT NOT NULL,
    settlement_path        TEXT NOT NULL,
    journal_txid           TEXT NOT NULL,
    txid                   TEXT NOT NULL,
    destination_address    TEXT NOT NULL,
    destination_script_hex TEXT NOT NULL,
    asset_id               TEXT,
    actual_amount_sat      BIGINT NOT NULL,
    vout                   INTEGER NOT NULL,
    confirmations          INTEGER NOT NULL,
    block_height           INTEGER NOT NULL,
    block_hash             TEXT NOT NULL,
    linked_replacement     BOOLEAN NOT NULL,
    recorded               BOOLEAN NOT NULL,
    active                 BOOLEAN NOT NULL,
    finalized              BOOLEAN NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT merchant_settlement_retained_chain_fkey
        FOREIGN KEY (chain_swap_id) REFERENCES chain_swap_records(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT merchant_settlement_retained_invoice_fkey
        FOREIGN KEY (invoice_id) REFERENCES invoices(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT merchant_settlement_retained_event_fkey
        FOREIGN KEY (event_key) REFERENCES invoice_payment_events(event_key)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT merchant_settlement_retained_journal_fkey
        FOREIGN KEY (journal_txid) REFERENCES chain_swap_tx_attempts(txid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT merchant_settlement_retained_checkpoint_fkey
        FOREIGN KEY (chain_swap_id, settlement_path)
        REFERENCES merchant_settlement_checkpoints(chain_swap_id, settlement_path)
        ON UPDATE RESTRICT ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT merchant_settlement_retained_shape_check CHECK (
        settlement_path IN ('liquid_claim', 'bitcoin_recovery')
        AND octet_length(boltz_swap_id) BETWEEN 1 AND 200
        AND journal_txid ~ '^[0-9a-f]{64}$'
        AND txid ~ '^[0-9a-f]{64}$'
        AND octet_length(destination_address) BETWEEN 1 AND 256
        AND destination_script_hex ~ '^[0-9a-f]+$'
        AND length(destination_script_hex) % 2 = 0
        AND (
            (settlement_path = 'liquid_claim'
                AND asset_id IS NOT NULL
                AND asset_id ~ '^[0-9a-f]{64}$')
            OR (settlement_path = 'bitcoin_recovery' AND asset_id IS NULL)
        )
        AND actual_amount_sat > 0
        AND vout >= 0
        AND confirmations > 0
        AND block_height > 0
        AND block_hash ~ '^[0-9a-f]{64}$'
        AND family_key ~ '^chain_swap_merchant_output:[0-9a-f-]{36}:[0-9a-f]{64}$'
        AND split_part(family_key, ':', 2) = chain_swap_id::TEXT
        AND event_key = family_key || ':' || txid || ':' || vout::TEXT
        AND (NOT active OR recorded)
        AND (NOT finalized OR active)
        AND updated_at >= created_at
    )
);

CREATE INDEX merchant_settlement_retained_chain_idx
    ON merchant_settlement_retained_outputs(chain_swap_id, settlement_path);

CREATE FUNCTION enforce_merchant_settlement_checkpoint_write()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    journal_chain_swap_id UUID;
    journal_purpose TEXT;
    journal_status TEXT;
    parent_invoice_id UUID;
    parent_boltz_swap_id TEXT;
BEGIN
    SELECT chain_swap_id, purpose, status
      INTO journal_chain_swap_id, journal_purpose, journal_status
      FROM chain_swap_tx_attempts
     WHERE txid = NEW.journal_txid
     FOR KEY SHARE;
    IF NOT FOUND
       OR journal_chain_swap_id <> NEW.chain_swap_id
       OR journal_status = 'integrity_hold'
       OR (NEW.settlement_path = 'liquid_claim' AND journal_purpose <> 'liquid_claim')
       OR (NEW.settlement_path = 'bitcoin_recovery' AND journal_purpose <> 'btc_recovery') THEN
        RAISE EXCEPTION 'merchant settlement checkpoint does not match its original journal'
            USING ERRCODE = '23514';
    END IF;
    SELECT invoice_id, boltz_swap_id
      INTO parent_invoice_id, parent_boltz_swap_id
      FROM chain_swap_records
     WHERE id = NEW.chain_swap_id
     FOR KEY SHARE;
    IF NOT FOUND
       OR parent_invoice_id <> NEW.invoice_id
       OR parent_boltz_swap_id <> NEW.boltz_swap_id THEN
        RAISE EXCEPTION 'merchant settlement checkpoint does not match its parent swap'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.checkpoint_version <> 1 THEN
            RAISE EXCEPTION 'merchant settlement checkpoint must start at version 1'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(
        NEW.chain_swap_id, NEW.settlement_path, NEW.invoice_id,
        NEW.boltz_swap_id, NEW.format_version, NEW.journal_txid, NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.chain_swap_id, OLD.settlement_path, OLD.invoice_id,
        OLD.boltz_swap_id, OLD.format_version, OLD.journal_txid, OLD.created_at
    ) OR NEW.checkpoint_version <> OLD.checkpoint_version + 1 THEN
        RAISE EXCEPTION 'merchant settlement checkpoint identity/version is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION enforce_merchant_settlement_retained_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    journal_chain_swap_id UUID;
    journal_purpose TEXT;
    journal_status TEXT;
    candidate_replaces_txid TEXT;
    candidate_status TEXT;
    event_invoice_id UUID;
    event_chain_swap_id UUID;
    event_family_key TEXT;
    event_txid TEXT;
    event_vout INTEGER;
    event_amount_sat BIGINT;
    event_address TEXT;
BEGIN
    IF TG_OP = 'UPDATE' AND ROW(
        NEW.event_key, NEW.family_key, NEW.invoice_id, NEW.chain_swap_id,
        NEW.boltz_swap_id, NEW.settlement_path, NEW.journal_txid, NEW.txid,
        NEW.destination_address, NEW.destination_script_hex, NEW.asset_id,
        NEW.actual_amount_sat, NEW.vout, NEW.linked_replacement, NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.event_key, OLD.family_key, OLD.invoice_id, OLD.chain_swap_id,
        OLD.boltz_swap_id, OLD.settlement_path, OLD.journal_txid, OLD.txid,
        OLD.destination_address, OLD.destination_script_hex, OLD.asset_id,
        OLD.actual_amount_sat, OLD.vout, OLD.linked_replacement, OLD.created_at
    ) THEN
        RAISE EXCEPTION 'retained merchant settlement identity is immutable'
            USING ERRCODE = '55000';
    END IF;
    SELECT chain_swap_id, purpose, status
      INTO journal_chain_swap_id, journal_purpose, journal_status
      FROM chain_swap_tx_attempts
     WHERE txid = NEW.journal_txid
     FOR KEY SHARE;
    IF NOT FOUND
       OR journal_chain_swap_id <> NEW.chain_swap_id
       OR journal_status = 'integrity_hold'
       OR (NEW.settlement_path = 'liquid_claim' AND journal_purpose <> 'liquid_claim')
       OR (NEW.settlement_path = 'bitcoin_recovery' AND journal_purpose <> 'btc_recovery') THEN
        RAISE EXCEPTION 'retained merchant output does not match its original journal'
            USING ERRCODE = '23514';
    END IF;
    SELECT invoice_id, merchant_chain_swap_id, merchant_settlement_family_key,
           txid, vout, amount_sat, address
      INTO event_invoice_id, event_chain_swap_id, event_family_key,
           event_txid, event_vout, event_amount_sat, event_address
      FROM invoice_payment_events
     WHERE event_key = NEW.event_key
     FOR KEY SHARE;
    IF NOT FOUND
       OR event_invoice_id <> NEW.invoice_id
       OR event_chain_swap_id <> NEW.chain_swap_id
       OR event_family_key <> NEW.family_key
       OR event_txid <> NEW.txid
       OR event_vout <> NEW.vout
       OR event_amount_sat <> NEW.actual_amount_sat
       OR event_address <> NEW.destination_address THEN
        RAISE EXCEPTION 'retained merchant output does not match its accounting event'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.linked_replacement THEN
        SELECT replaces_txid, status
          INTO candidate_replaces_txid, candidate_status
          FROM chain_swap_tx_attempts
         WHERE chain_swap_id = NEW.chain_swap_id
           AND purpose = 'liquid_claim_replacement'
           AND txid = NEW.txid
         FOR KEY SHARE;
        IF NOT FOUND
           OR candidate_replaces_txid <> NEW.journal_txid
           OR candidate_status = 'integrity_hold' THEN
            RAISE EXCEPTION 'retained replacement is not linked to its original journal'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.txid <> NEW.journal_txid THEN
        RAISE EXCEPTION 'retained original output txid differs from its journal'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION reject_merchant_settlement_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'merchant settlement evidence cannot be deleted'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER merchant_settlement_checkpoint_validate_write
    BEFORE INSERT OR UPDATE ON merchant_settlement_checkpoints
    FOR EACH ROW EXECUTE FUNCTION enforce_merchant_settlement_checkpoint_write();
CREATE TRIGGER merchant_settlement_checkpoint_reject_delete
    BEFORE DELETE ON merchant_settlement_checkpoints
    FOR EACH ROW EXECUTE FUNCTION reject_merchant_settlement_delete();
CREATE TRIGGER merchant_settlement_retained_validate_update
    BEFORE INSERT OR UPDATE ON merchant_settlement_retained_outputs
    FOR EACH ROW EXECUTE FUNCTION enforce_merchant_settlement_retained_update();
CREATE TRIGGER merchant_settlement_retained_reject_delete
    BEFORE DELETE ON merchant_settlement_retained_outputs
    FOR EACH ROW EXECUTE FUNCTION reject_merchant_settlement_delete();

REVOKE ALL ON chain_swap_tx_attempts FROM PUBLIC;
REVOKE ALL ON invoice_payment_events FROM PUBLIC;
REVOKE ALL ON merchant_settlement_checkpoints FROM PUBLIC;
REVOKE ALL ON merchant_settlement_retained_outputs FROM PUBLIC;

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
    relation_name TEXT;
    relation_owner_oid OID;
    runtime_role_oid OID;
BEGIN
    SELECT oid INTO STRICT runtime_role_oid FROM pg_roles WHERE rolname = runtime_role_name;
    FOREACH relation_name IN ARRAY ARRAY[
        'chain_swap_tx_attempts', 'invoice_payment_events',
        'merchant_settlement_checkpoints', 'merchant_settlement_retained_outputs'
    ] LOOP
        EXECUTE format('REVOKE ALL ON TABLE public.%I FROM %I', relation_name, runtime_role_name);
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON TABLE public.%I TO %I',
            relation_name, runtime_role_name
        );
        SELECT relowner INTO STRICT relation_owner_oid
          FROM pg_class WHERE oid = format('public.%I', relation_name)::REGCLASS;
        IF relation_owner_oid = runtime_role_oid
           OR pg_has_role(runtime_role_oid, relation_owner_oid, 'MEMBER')
           OR NOT has_table_privilege(runtime_role_name, format('public.%I', relation_name), 'SELECT')
           OR NOT has_table_privilege(runtime_role_name, format('public.%I', relation_name), 'INSERT')
           OR NOT has_table_privilege(runtime_role_name, format('public.%I', relation_name), 'UPDATE')
           OR has_table_privilege(runtime_role_name, format('public.%I', relation_name), 'DELETE')
           OR has_table_privilege(runtime_role_name, format('public.%I', relation_name), 'TRUNCATE')
           OR has_table_privilege(runtime_role_name, format('public.%I', relation_name), 'REFERENCES')
           OR has_table_privilege(runtime_role_name, format('public.%I', relation_name), 'TRIGGER') THEN
            RAISE EXCEPTION 'migration 055 failed protected runtime ACL for %', relation_name
                USING ERRCODE = '42501';
        END IF;
    END LOOP;
END
$$;

COMMIT;

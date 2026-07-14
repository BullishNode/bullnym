-- ==========================================================================
-- 060: private, rail-neutral LNURL payer-comment intents
-- ==========================================================================
--
-- LUD-12 comments are payer-supplied private payment metadata. This ledger is
-- deliberately independent of reverse swaps and direct-Liquid reservations so
-- one intent can survive rail fallback and later cleanup. Runtime wiring is a
-- separate slice: it must supply a stable callback digest and bind an exact
-- instruction before returning it.

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

-- The schema owner must remain distinct and non-assumable. Otherwise table
-- ACLs cannot protect private comments or append-only history from the runtime
-- role itself.
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
        RAISE EXCEPTION 'migration 060 requires a non-empty runtime_role psql variable'
            USING ERRCODE = '42501';
    END IF;

    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 060 runtime role % does not exist',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 060 refuses superuser runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    SELECT oid INTO STRICT executor_role_oid
      FROM pg_roles
     WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 060 runtime role % owns or can assume its schema owner %',
            quote_ident(runtime_role_name), quote_ident(current_user)
            USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE TABLE lnurl_comment_intents (
    intent_id                   UUID PRIMARY KEY,
    owner_npub                 TEXT NOT NULL,
    nym                        TEXT NOT NULL,
    idempotency_key            TEXT NOT NULL,
    amount_msat                BIGINT NOT NULL,
    comment                    TEXT NOT NULL,
    comment_grapheme_count     SMALLINT NOT NULL,
    instruction_rail           TEXT,
    instruction_reference      TEXT,
    payment_evidence_reference TEXT,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    instruction_bound_at        TIMESTAMPTZ,
    payment_evidenced_at        TIMESTAMPTZ,

    CONSTRAINT lnurl_comment_intents_id_non_nil_check CHECK (
        intent_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT lnurl_comment_intents_owner_shape_check CHECK (
        owner_npub ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT lnurl_comment_intents_nym_shape_check CHECK (
        nym = btrim(nym)
        AND nym ~ '^(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,30}[a-z0-9])$'
    ),
    CONSTRAINT lnurl_comment_intents_idempotency_shape_check CHECK (
        idempotency_key ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT lnurl_comment_intents_amount_check CHECK (
        amount_msat > 0 AND amount_msat % 1000 = 0
    ),
    -- PostgreSQL has no extended-grapheme-cluster primitive. Rust validates
    -- the exact text and this independently stored count; reads re-segment and
    -- reject a mismatch before private projection.
    CONSTRAINT lnurl_comment_intents_grapheme_count_check CHECK (
        comment_grapheme_count BETWEEN 1 AND 120
    ),
    CONSTRAINT lnurl_comment_intents_comment_bytes_check CHECK (
        octet_length(comment) BETWEEN 1 AND 512
    ),
    CONSTRAINT lnurl_comment_intents_instruction_rail_check CHECK (
        instruction_rail IS NULL
        OR instruction_rail IN ('lightning', 'liquid')
    ),
    CONSTRAINT lnurl_comment_intents_instruction_shape_check CHECK (
        num_nonnulls(
            instruction_rail,
            instruction_reference,
            instruction_bound_at
        ) IN (0, 3)
        AND (
            instruction_reference IS NULL
            OR (
                instruction_reference = btrim(instruction_reference)
                AND octet_length(instruction_reference) BETWEEN 1 AND 255
            )
        )
    ),
    CONSTRAINT lnurl_comment_intents_evidence_shape_check CHECK (
        num_nonnulls(
            payment_evidence_reference,
            payment_evidenced_at
        ) IN (0, 2)
        AND (
            payment_evidence_reference IS NULL
            OR (
                payment_evidence_reference = btrim(payment_evidence_reference)
                AND octet_length(payment_evidence_reference) BETWEEN 1 AND 255
                AND instruction_rail IS NOT NULL
            )
        )
    ),
    CONSTRAINT lnurl_comment_intents_owner_idempotency_key UNIQUE (
        owner_npub,
        idempotency_key
    ),
    CONSTRAINT lnurl_comment_intents_instruction_once_key UNIQUE (
        instruction_rail,
        instruction_reference
    ),
    CONSTRAINT lnurl_comment_intents_payment_evidence_once_key UNIQUE (
        instruction_rail,
        payment_evidence_reference
    )
);

CREATE INDEX lnurl_comment_intents_received_history_idx
    ON lnurl_comment_intents (
        owner_npub,
        payment_evidenced_at DESC,
        intent_id DESC
    )
    WHERE payment_evidence_reference IS NOT NULL;

CREATE FUNCTION enforce_lnurl_comment_intent_write() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.instruction_rail IS NOT NULL
           OR NEW.instruction_reference IS NOT NULL
           OR NEW.instruction_bound_at IS NOT NULL
           OR NEW.payment_evidence_reference IS NOT NULL
           OR NEW.payment_evidenced_at IS NOT NULL THEN
            RAISE EXCEPTION 'LNURL comment intent must be persisted before instruction/evidence binding'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'lnurl_comment_intents_insert_phase_check';
        END IF;

        NEW.created_at := clock_timestamp();
        PERFORM pg_advisory_xact_lock(
            1280474196,
            hashtext(NEW.owner_npub || ':' || NEW.idempotency_key)
        );
        -- Share the user-lifecycle lock used by create/deactivate/purge. The
        -- runtime role has read-only user access here; taking this advisory
        -- lock before the read gives admission one database-defined order.
        PERFORM pg_advisory_xact_lock(hashtext(NEW.owner_npub)::BIGINT);
        PERFORM 1
          FROM users
         WHERE npub = NEW.owner_npub
           AND nym = NEW.nym
           AND is_active = TRUE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'LNURL comment intent source identity is not active'
                USING ERRCODE = '42501',
                      CONSTRAINT = 'lnurl_comment_intents_active_owner_check';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(
        OLD.intent_id,
        OLD.owner_npub,
        OLD.nym,
        OLD.idempotency_key,
        OLD.amount_msat,
        OLD.comment,
        OLD.comment_grapheme_count,
        OLD.created_at
    ) IS DISTINCT FROM ROW(
        NEW.intent_id,
        NEW.owner_npub,
        NEW.nym,
        NEW.idempotency_key,
        NEW.amount_msat,
        NEW.comment,
        NEW.comment_grapheme_count,
        NEW.created_at
    ) THEN
        RAISE EXCEPTION 'LNURL comment intent identity and text are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.instruction_rail IS NULL THEN
        IF NEW.instruction_rail IS NULL
           OR NEW.instruction_reference IS NULL
           OR NEW.instruction_bound_at IS NOT NULL THEN
            RAISE EXCEPTION 'LNURL comment instruction must bind once as a complete server-timestamped pair'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'lnurl_comment_intents_instruction_transition_check';
        END IF;
        NEW.instruction_bound_at := clock_timestamp();
    ELSIF ROW(
        OLD.instruction_rail,
        OLD.instruction_reference,
        OLD.instruction_bound_at
    ) IS DISTINCT FROM ROW(
        NEW.instruction_rail,
        NEW.instruction_reference,
        NEW.instruction_bound_at
    ) THEN
        RAISE EXCEPTION 'LNURL comment instruction binding is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.payment_evidence_reference IS NULL THEN
        IF NEW.payment_evidence_reference IS NULL THEN
            IF NEW.payment_evidenced_at IS NOT NULL THEN
                RAISE EXCEPTION 'LNURL comment evidence timestamp requires evidence'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'lnurl_comment_intents_evidence_transition_check';
            END IF;
        ELSE
            IF OLD.instruction_rail IS NULL
               OR NEW.payment_evidenced_at IS NOT NULL THEN
                RAISE EXCEPTION 'LNURL comment evidence requires a prior instruction and server timestamp'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'lnurl_comment_intents_evidence_transition_check';
            END IF;
            NEW.payment_evidenced_at := clock_timestamp();
        END IF;
    ELSIF ROW(
        OLD.payment_evidence_reference,
        OLD.payment_evidenced_at
    ) IS DISTINCT FROM ROW(
        NEW.payment_evidence_reference,
        NEW.payment_evidenced_at
    ) THEN
        RAISE EXCEPTION 'LNURL comment payment evidence is immutable'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END
$$;

CREATE FUNCTION reject_lnurl_comment_intent_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'LNURL comment intent history is append-only'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER lnurl_comment_intents_enforce_write
BEFORE INSERT OR UPDATE ON lnurl_comment_intents
FOR EACH ROW EXECUTE FUNCTION enforce_lnurl_comment_intent_write();

CREATE TRIGGER lnurl_comment_intents_reject_delete
BEFORE DELETE ON lnurl_comment_intents
FOR EACH ROW EXECUTE FUNCTION reject_lnurl_comment_intent_delete();

DO $$
DECLARE
    runtime_role_name TEXT := current_setting(
        'bullnym.migration_runtime_role'
    );
    runtime_role_oid OID;
    ledger_owner_oid OID;
BEGIN
    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    SELECT relowner INTO STRICT ledger_owner_oid
      FROM pg_class
     WHERE oid = 'lnurl_comment_intents'::REGCLASS;
    IF ledger_owner_oid = runtime_role_oid
       OR pg_has_role(runtime_role_oid, ledger_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, ledger_owner_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 060 runtime role % owns or can assume the LNURL comment ledger owner',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    REVOKE ALL ON TABLE lnurl_comment_intents FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON TABLE lnurl_comment_intents FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT ON TABLE lnurl_comment_intents TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT INSERT (intent_id, owner_npub, nym, idempotency_key, amount_msat, comment, comment_grapheme_count) ON TABLE lnurl_comment_intents TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT UPDATE (instruction_rail, instruction_reference, payment_evidence_reference) ON TABLE lnurl_comment_intents TO %I',
        runtime_role_name
    );

    REVOKE ALL ON FUNCTION enforce_lnurl_comment_intent_write() FROM PUBLIC;
    REVOKE ALL ON FUNCTION reject_lnurl_comment_intent_delete() FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON FUNCTION enforce_lnurl_comment_intent_write() FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'REVOKE ALL ON FUNCTION reject_lnurl_comment_intent_delete() FROM %I',
        runtime_role_name
    );
END
$$;

COMMIT;

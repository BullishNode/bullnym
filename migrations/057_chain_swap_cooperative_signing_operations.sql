-- ============================================================================
-- 057: crash-safe cooperative Bitcoin recovery signing operation journal
-- ============================================================================
--
-- A Boltz refund-signature request changes provider-side state even when the
-- HTTP response is lost. Persist one exact source, transaction template, fee
-- authority, MuSig session, and encrypted local secret nonce before that
-- request. A request is issued at most once; an ambiguous request can only be
-- resolved by its late exact response or superseded after the unilateral
-- timeout. Completion keeps a recovery copy of the exact signed transaction,
-- but the transition is accepted only after matching immutable bytes already
-- exist in the transaction-attempt journal in the same database transaction.

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
        RAISE EXCEPTION 'migration 057 requires a non-empty runtime_role psql variable'
            USING ERRCODE = '42501';
    END IF;

    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 057 runtime role % does not exist',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 057 refuses superuser runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    SELECT oid INTO STRICT executor_role_oid
      FROM pg_roles
     WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 057 runtime role % can assume its schema owner %',
            quote_ident(runtime_role_name), quote_ident(current_user)
            USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE TABLE public.chain_swap_cooperative_signing_operations (
    chain_swap_id                         UUID PRIMARY KEY,
    state                                 TEXT NOT NULL DEFAULT 'prepared',
    boltz_swap_id                         TEXT NOT NULL,

    source_txid                           TEXT NOT NULL,
    source_vout                           BIGINT NOT NULL,
    source_amount_sat                     BIGINT NOT NULL,
    source_script_pubkey_hex              TEXT NOT NULL,
    destination_address                   TEXT NOT NULL,
    destination_script_pubkey_hex         TEXT NOT NULL,
    destination_amount_sat                BIGINT NOT NULL,

    fee_amount_sat                        BIGINT NOT NULL,
    fee_vbytes                            BIGINT NOT NULL,
    fee_decision_purpose                  TEXT NOT NULL,
    fee_decision_rail                     TEXT NOT NULL,
    fee_decision_target                   TEXT NOT NULL,
    fee_decision_source                   TEXT NOT NULL,
    fee_decision_rate_sat_vb              DOUBLE PRECISION NOT NULL,
    fee_decision_quoted_at_unix           BIGINT NOT NULL,
    fee_decision_evaluated_at_unix        BIGINT NOT NULL,
    fee_decision_freshness_age_secs       BIGINT NOT NULL,
    fee_decision_freshness_max_age_secs   BIGINT NOT NULL,
    fee_decision_provenance               TEXT NOT NULL,
    fee_decision_policy_floor_sat_vb       DOUBLE PRECISION NOT NULL,
    fee_decision_policy_cap_sat_vb         DOUBLE PRECISION NOT NULL,
    fee_decision_policy_version            TEXT NOT NULL,

    request_transaction_hex               TEXT NOT NULL,
    request_transaction_sha256            TEXT NOT NULL,
    request_transaction_txid              TEXT NOT NULL,
    request_input_index                   INTEGER NOT NULL DEFAULT 0,
    sighash_hex                            TEXT NOT NULL,
    aggregate_key_xonly_hex               TEXT NOT NULL,
    client_public_nonce_hex               TEXT NOT NULL,
    provider_request_sha256               TEXT NOT NULL,
    session_sha256                        TEXT NOT NULL,

    secret_nonce_format                   TEXT NOT NULL,
    secret_nonce_encryption_algorithm     TEXT NOT NULL,
    secret_nonce_key_id                   TEXT NOT NULL,
    secret_nonce_encryption_nonce         BYTEA NOT NULL,
    secret_nonce_ciphertext               BYTEA NOT NULL,
    secret_nonce_plaintext_sha256         TEXT NOT NULL,

    request_attempt_count                 INTEGER NOT NULL DEFAULT 0,
    version                               BIGINT NOT NULL DEFAULT 1,
    requested_at                          TIMESTAMPTZ,
    ambiguous_at                          TIMESTAMPTZ,
    last_error_class                      TEXT,

    provider_public_nonce_hex             TEXT,
    provider_partial_signature_hex        TEXT,
    provider_response_sha256              TEXT,
    response_received_at                  TIMESTAMPTZ,

    final_transaction_hex                 TEXT,
    final_transaction_sha256              TEXT,
    final_txid                            TEXT,
    local_partial_signature_sha256        TEXT,
    completed_at                          TIMESTAMPTZ,

    integrity_reason_sha256               TEXT,
    integrity_hold_at                     TIMESTAMPTZ,
    superseded_reason                     TEXT,
    superseded_at                         TIMESTAMPTZ,

    created_at                            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chain_swap_cooperative_signing_chain_fkey
        FOREIGN KEY (chain_swap_id) REFERENCES public.chain_swap_records(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT chain_swap_cooperative_signing_state_check CHECK (
        state IN (
            'prepared', 'requested', 'ambiguous', 'response_received',
            'completed', 'integrity_hold', 'superseded'
        )
    ),
    CONSTRAINT chain_swap_cooperative_signing_parent_identity_check CHECK (
        boltz_swap_id = btrim(boltz_swap_id)
        AND octet_length(boltz_swap_id) BETWEEN 1 AND 200
        AND boltz_swap_id !~ '[[:space:]]'
    ),
    CONSTRAINT chain_swap_cooperative_signing_source_check CHECK (
        source_txid ~ '^[0-9a-f]{64}$'
        AND source_vout BETWEEN 0 AND 4294967295
        AND source_amount_sat > 0
        AND octet_length(source_script_pubkey_hex) BETWEEN 2 AND 20000
        AND octet_length(source_script_pubkey_hex) % 2 = 0
        AND source_script_pubkey_hex ~ '^[0-9a-f]+$'
    ),
    CONSTRAINT chain_swap_cooperative_signing_destination_check CHECK (
        destination_address = btrim(destination_address)
        AND octet_length(destination_address) BETWEEN 1 AND 200
        AND destination_address !~ '[[:space:]]'
        AND destination_amount_sat > 0
        AND octet_length(destination_script_pubkey_hex) BETWEEN 2 AND 20000
        AND octet_length(destination_script_pubkey_hex) % 2 = 0
        AND destination_script_pubkey_hex ~ '^[0-9a-f]+$'
    ),
    CONSTRAINT chain_swap_cooperative_signing_exact_fee_check CHECK (
        fee_amount_sat > 0
        AND fee_vbytes > 0
        AND source_amount_sat = destination_amount_sat + fee_amount_sat
    ),
    CONSTRAINT chain_swap_cooperative_signing_fee_authority_check CHECK (
        fee_decision_purpose = 'bitcoin_recovery'
        AND fee_decision_rail = 'bitcoin'
        AND fee_decision_target = 'fastestFee'
        AND fee_decision_source IN (
            'bitcoin_live', 'bitcoin_last_known_good'
        )
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
        AND fee_decision_rate_sat_vb BETWEEN
            fee_decision_policy_floor_sat_vb
            AND fee_decision_policy_cap_sat_vb
        AND fee_decision_policy_version = 'review25-v1'
        AND fee_amount_sat = CEIL(fee_decision_rate_sat_vb * fee_vbytes)
    ),
    CONSTRAINT chain_swap_cooperative_signing_request_check CHECK (
        request_input_index = 0
        AND octet_length(request_transaction_hex) BETWEEN 2 AND 200000
        AND octet_length(request_transaction_hex) % 2 = 0
        AND request_transaction_hex ~ '^[0-9a-f]+$'
        AND request_transaction_sha256 ~ '^[0-9a-f]{64}$'
        AND request_transaction_sha256 = encode(
            digest(decode(request_transaction_hex, 'hex'), 'sha256'), 'hex'
        )
        AND request_transaction_txid ~ '^[0-9a-f]{64}$'
        AND sighash_hex ~ '^[0-9a-f]{64}$'
        AND aggregate_key_xonly_hex ~ '^[0-9a-f]{64}$'
        AND client_public_nonce_hex ~ '^[0-9a-f]{132}$'
        AND provider_request_sha256 ~ '^[0-9a-f]{64}$'
        AND session_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chain_swap_cooperative_signing_secret_nonce_check CHECK (
        secret_nonce_format = 'secp256k1-musig-secnonce-132-v1'
        AND secret_nonce_encryption_algorithm = 'xchacha20poly1305-v1'
        AND secret_nonce_key_id ~ '^[A-Za-z0-9._:-]{1,64}$'
        AND octet_length(secret_nonce_encryption_nonce) = 24
        AND octet_length(secret_nonce_ciphertext) = 148
        AND secret_nonce_plaintext_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chain_swap_cooperative_signing_attempt_check CHECK (
        request_attempt_count BETWEEN 0 AND 1
        AND version > 0
    ),
    CONSTRAINT chain_swap_cooperative_signing_error_check CHECK (
        last_error_class IS NULL OR last_error_class IN (
            'timeout', 'transport', 'provider_server_error',
            'malformed_response', 'local_commit_uncertainty',
            'unknown_provider_outcome'
        )
    ),
    CONSTRAINT chain_swap_cooperative_signing_response_check CHECK (
        (provider_public_nonce_hex IS NULL) =
            (provider_partial_signature_hex IS NULL)
        AND (provider_public_nonce_hex IS NULL) =
            (provider_response_sha256 IS NULL)
        AND (provider_public_nonce_hex IS NULL) =
            (response_received_at IS NULL)
        AND (
            provider_public_nonce_hex IS NULL
            OR (
                provider_public_nonce_hex ~ '^[0-9a-f]{132}$'
                AND provider_partial_signature_hex ~ '^[0-9a-f]{64}$'
                AND provider_response_sha256 ~ '^[0-9a-f]{64}$'
                AND provider_response_sha256 = encode(
                    digest(
                        convert_to(
                            'bullnym:cooperative-signing-provider-response:v1:',
                            'UTF8'
                        )
                        || decode(provider_public_nonce_hex, 'hex')
                        || decode(provider_partial_signature_hex, 'hex'),
                        'sha256'
                    ),
                    'hex'
                )
            )
        )
    ),
    CONSTRAINT chain_swap_cooperative_signing_completion_check CHECK (
        (final_transaction_hex IS NULL) =
            (final_transaction_sha256 IS NULL)
        AND (final_transaction_hex IS NULL) = (final_txid IS NULL)
        AND (final_transaction_hex IS NULL) =
            (local_partial_signature_sha256 IS NULL)
        AND (final_transaction_hex IS NULL) = (completed_at IS NULL)
        AND (
            final_transaction_hex IS NULL
            OR (
                octet_length(final_transaction_hex) BETWEEN 2 AND 200000
                AND octet_length(final_transaction_hex) % 2 = 0
                AND final_transaction_hex ~ '^[0-9a-f]+$'
                AND final_transaction_sha256 = encode(
                    digest(decode(final_transaction_hex, 'hex'), 'sha256'), 'hex'
                )
                AND final_txid ~ '^[0-9a-f]{64}$'
                AND final_txid = request_transaction_txid
                AND local_partial_signature_sha256 ~ '^[0-9a-f]{64}$'
            )
        )
    ),
    CONSTRAINT chain_swap_cooperative_signing_terminal_check CHECK (
        (integrity_reason_sha256 IS NULL) = (integrity_hold_at IS NULL)
        AND (
            integrity_reason_sha256 IS NULL
            OR integrity_reason_sha256 ~ '^[0-9a-f]{64}$'
        )
        AND (superseded_reason IS NULL) = (superseded_at IS NULL)
        AND (
            superseded_reason IS NULL
            OR superseded_reason = 'unilateral_timeout_reached'
        )
    ),
    CONSTRAINT chain_swap_cooperative_signing_lifecycle_shape_check CHECK (
        updated_at >= created_at
        AND (requested_at IS NULL OR requested_at BETWEEN created_at AND updated_at)
        AND (ambiguous_at IS NULL OR ambiguous_at BETWEEN requested_at AND updated_at)
        AND (
            response_received_at IS NULL
            OR response_received_at BETWEEN requested_at AND updated_at
        )
        AND (completed_at IS NULL OR completed_at BETWEEN response_received_at AND updated_at)
        AND (
            integrity_hold_at IS NULL
            OR integrity_hold_at BETWEEN created_at AND updated_at
        )
        AND (
            superseded_at IS NULL
            OR superseded_at BETWEEN created_at AND updated_at
        )
        AND (
            (
                state = 'prepared'
                AND request_attempt_count = 0
                AND requested_at IS NULL
                AND ambiguous_at IS NULL
                AND last_error_class IS NULL
                AND provider_public_nonce_hex IS NULL
                AND final_transaction_hex IS NULL
                AND integrity_reason_sha256 IS NULL
                AND superseded_reason IS NULL
            ) OR (
                state = 'requested'
                AND request_attempt_count = 1
                AND requested_at IS NOT NULL
                AND ambiguous_at IS NULL
                AND last_error_class IS NULL
                AND provider_public_nonce_hex IS NULL
                AND final_transaction_hex IS NULL
                AND integrity_reason_sha256 IS NULL
                AND superseded_reason IS NULL
            ) OR (
                state = 'ambiguous'
                AND request_attempt_count = 1
                AND requested_at IS NOT NULL
                AND ambiguous_at IS NOT NULL
                AND last_error_class IS NOT NULL
                AND provider_public_nonce_hex IS NULL
                AND final_transaction_hex IS NULL
                AND integrity_reason_sha256 IS NULL
                AND superseded_reason IS NULL
            ) OR (
                state = 'response_received'
                AND request_attempt_count = 1
                AND requested_at IS NOT NULL
                AND provider_public_nonce_hex IS NOT NULL
                AND final_transaction_hex IS NULL
                AND integrity_reason_sha256 IS NULL
                AND superseded_reason IS NULL
                AND (
                    (ambiguous_at IS NULL AND last_error_class IS NULL)
                    OR (ambiguous_at IS NOT NULL AND last_error_class IS NOT NULL)
                )
            ) OR (
                state = 'completed'
                AND request_attempt_count = 1
                AND requested_at IS NOT NULL
                AND provider_public_nonce_hex IS NOT NULL
                AND final_transaction_hex IS NOT NULL
                AND integrity_reason_sha256 IS NULL
                AND superseded_reason IS NULL
                AND (
                    (ambiguous_at IS NULL AND last_error_class IS NULL)
                    OR (ambiguous_at IS NOT NULL AND last_error_class IS NOT NULL)
                )
            ) OR (
                state = 'integrity_hold'
                AND final_transaction_hex IS NULL
                AND integrity_reason_sha256 IS NOT NULL
                AND superseded_reason IS NULL
                AND (
                    (request_attempt_count = 0 AND requested_at IS NULL)
                    OR (request_attempt_count = 1 AND requested_at IS NOT NULL)
                )
                AND (
                    (ambiguous_at IS NULL AND last_error_class IS NULL)
                    OR (ambiguous_at IS NOT NULL AND last_error_class IS NOT NULL)
                )
            ) OR (
                state = 'superseded'
                AND provider_public_nonce_hex IS NULL
                AND final_transaction_hex IS NULL
                AND integrity_reason_sha256 IS NULL
                AND superseded_reason = 'unilateral_timeout_reached'
                AND (
                    (request_attempt_count = 0 AND requested_at IS NULL)
                    OR (request_attempt_count = 1 AND requested_at IS NOT NULL)
                )
                AND (
                    (ambiguous_at IS NULL AND last_error_class IS NULL)
                    OR (ambiguous_at IS NOT NULL AND last_error_class IS NOT NULL)
                )
            )
        )
    )
);

CREATE INDEX chain_swap_cooperative_signing_active_idx
    ON public.chain_swap_cooperative_signing_operations(updated_at, chain_swap_id)
    WHERE state NOT IN ('completed', 'integrity_hold', 'superseded');

CREATE FUNCTION public.enforce_chain_swap_cooperative_signing_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    persisted_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
    parent_boltz_swap_id TEXT;
BEGIN
    SELECT boltz_swap_id
      INTO parent_boltz_swap_id
      FROM public.chain_swap_records
     WHERE id = NEW.chain_swap_id
     FOR KEY SHARE;
    IF NOT FOUND OR parent_boltz_swap_id <> NEW.boltz_swap_id THEN
        RAISE EXCEPTION 'cooperative signing operation parent identity mismatch'
            USING ERRCODE = '23503';
    END IF;

    NEW.created_at := persisted_at;
    NEW.updated_at := persisted_at;
    IF NEW.state <> 'prepared'
       OR NEW.version <> 1
       OR NEW.request_attempt_count <> 0
       OR NEW.requested_at IS NOT NULL
       OR NEW.ambiguous_at IS NOT NULL
       OR NEW.last_error_class IS NOT NULL
       OR NEW.provider_public_nonce_hex IS NOT NULL
       OR NEW.provider_partial_signature_hex IS NOT NULL
       OR NEW.provider_response_sha256 IS NOT NULL
       OR NEW.response_received_at IS NOT NULL
       OR NEW.final_transaction_hex IS NOT NULL
       OR NEW.final_transaction_sha256 IS NOT NULL
       OR NEW.final_txid IS NOT NULL
       OR NEW.local_partial_signature_sha256 IS NOT NULL
       OR NEW.completed_at IS NOT NULL
       OR NEW.integrity_reason_sha256 IS NOT NULL
       OR NEW.integrity_hold_at IS NOT NULL
       OR NEW.superseded_reason IS NOT NULL
       OR NEW.superseded_at IS NOT NULL THEN
        RAISE EXCEPTION 'cooperative signing operations must start as pristine prepared version 1'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'chain_swap_cooperative_signing_lifecycle_shape_check';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.enforce_chain_swap_cooperative_signing_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    transitioned_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
    immutable_changed BOOLEAN := ROW(
        NEW.chain_swap_id, NEW.boltz_swap_id,
        NEW.source_txid, NEW.source_vout, NEW.source_amount_sat,
        NEW.source_script_pubkey_hex, NEW.destination_address,
        NEW.destination_script_pubkey_hex, NEW.destination_amount_sat,
        NEW.fee_amount_sat, NEW.fee_vbytes,
        NEW.fee_decision_purpose, NEW.fee_decision_rail,
        NEW.fee_decision_target, NEW.fee_decision_source,
        NEW.fee_decision_rate_sat_vb, NEW.fee_decision_quoted_at_unix,
        NEW.fee_decision_evaluated_at_unix,
        NEW.fee_decision_freshness_age_secs,
        NEW.fee_decision_freshness_max_age_secs,
        NEW.fee_decision_provenance, NEW.fee_decision_policy_floor_sat_vb,
        NEW.fee_decision_policy_cap_sat_vb,
        NEW.fee_decision_policy_version,
        NEW.request_transaction_hex, NEW.request_transaction_sha256,
        NEW.request_transaction_txid,
        NEW.request_input_index, NEW.sighash_hex,
        NEW.aggregate_key_xonly_hex, NEW.client_public_nonce_hex,
        NEW.provider_request_sha256, NEW.session_sha256,
        NEW.secret_nonce_format, NEW.secret_nonce_encryption_algorithm,
        NEW.secret_nonce_key_id, NEW.secret_nonce_encryption_nonce,
        NEW.secret_nonce_ciphertext, NEW.secret_nonce_plaintext_sha256,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.chain_swap_id, OLD.boltz_swap_id,
        OLD.source_txid, OLD.source_vout, OLD.source_amount_sat,
        OLD.source_script_pubkey_hex, OLD.destination_address,
        OLD.destination_script_pubkey_hex, OLD.destination_amount_sat,
        OLD.fee_amount_sat, OLD.fee_vbytes,
        OLD.fee_decision_purpose, OLD.fee_decision_rail,
        OLD.fee_decision_target, OLD.fee_decision_source,
        OLD.fee_decision_rate_sat_vb, OLD.fee_decision_quoted_at_unix,
        OLD.fee_decision_evaluated_at_unix,
        OLD.fee_decision_freshness_age_secs,
        OLD.fee_decision_freshness_max_age_secs,
        OLD.fee_decision_provenance, OLD.fee_decision_policy_floor_sat_vb,
        OLD.fee_decision_policy_cap_sat_vb,
        OLD.fee_decision_policy_version,
        OLD.request_transaction_hex, OLD.request_transaction_sha256,
        OLD.request_transaction_txid,
        OLD.request_input_index, OLD.sighash_hex,
        OLD.aggregate_key_xonly_hex, OLD.client_public_nonce_hex,
        OLD.provider_request_sha256, OLD.session_sha256,
        OLD.secret_nonce_format, OLD.secret_nonce_encryption_algorithm,
        OLD.secret_nonce_key_id, OLD.secret_nonce_encryption_nonce,
        OLD.secret_nonce_ciphertext, OLD.secret_nonce_plaintext_sha256,
        OLD.created_at
    );
BEGIN
    IF immutable_changed THEN
        RAISE EXCEPTION 'cooperative signing request identity is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.state, NEW.request_attempt_count, NEW.version,
        NEW.requested_at, NEW.ambiguous_at, NEW.last_error_class,
        NEW.provider_public_nonce_hex, NEW.provider_partial_signature_hex,
        NEW.provider_response_sha256, NEW.response_received_at,
        NEW.final_transaction_hex, NEW.final_transaction_sha256,
        NEW.final_txid, NEW.local_partial_signature_sha256, NEW.completed_at,
        NEW.integrity_reason_sha256, NEW.integrity_hold_at,
        NEW.superseded_reason, NEW.superseded_at, NEW.updated_at
    ) IS NOT DISTINCT FROM ROW(
        OLD.state, OLD.request_attempt_count, OLD.version,
        OLD.requested_at, OLD.ambiguous_at, OLD.last_error_class,
        OLD.provider_public_nonce_hex, OLD.provider_partial_signature_hex,
        OLD.provider_response_sha256, OLD.response_received_at,
        OLD.final_transaction_hex, OLD.final_transaction_sha256,
        OLD.final_txid, OLD.local_partial_signature_sha256, OLD.completed_at,
        OLD.integrity_reason_sha256, OLD.integrity_hold_at,
        OLD.superseded_reason, OLD.superseded_at, OLD.updated_at
    ) THEN
        RETURN NEW;
    END IF;

    IF OLD.state IN ('completed', 'integrity_hold', 'superseded') THEN
        RAISE EXCEPTION 'terminal cooperative signing evidence is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.version = 9223372036854775807 THEN
        RAISE EXCEPTION 'cooperative signing operation version exhausted BIGINT'
            USING ERRCODE = '54000';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'cooperative signing transition must advance version by one'
            USING ERRCODE = '40001';
    END IF;

    IF OLD.state = 'prepared' AND NEW.state = 'requested' THEN
        NEW.requested_at := transitioned_at;
        IF NEW.request_attempt_count <> 1
           OR NEW.requested_at IS NULL THEN
            RAISE EXCEPTION 'prepared signing intent requires one durable request'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'requested' AND NEW.state = 'ambiguous' THEN
        NEW.ambiguous_at := transitioned_at;
        IF NEW.request_attempt_count <> OLD.request_attempt_count
           OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
           OR NEW.ambiguous_at IS NULL
           OR NEW.last_error_class IS NULL THEN
            RAISE EXCEPTION 'ambiguous signing outcome must retain its exact request'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state IN ('requested', 'ambiguous')
          AND NEW.state = 'response_received' THEN
        NEW.response_received_at := transitioned_at;
        IF NEW.request_attempt_count <> OLD.request_attempt_count
           OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
           OR NEW.ambiguous_at IS DISTINCT FROM OLD.ambiguous_at
           OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class
           OR NEW.provider_public_nonce_hex IS NULL
           OR NEW.provider_partial_signature_hex IS NULL
           OR NEW.provider_response_sha256 IS NULL
           OR NEW.response_received_at IS NULL THEN
            RAISE EXCEPTION 'provider response must resolve the exact persisted request'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'response_received' AND NEW.state = 'completed' THEN
        NEW.completed_at := transitioned_at;
        IF NEW.request_attempt_count <> OLD.request_attempt_count
           OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
           OR NEW.ambiguous_at IS DISTINCT FROM OLD.ambiguous_at
           OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class
           OR NEW.provider_public_nonce_hex IS DISTINCT FROM OLD.provider_public_nonce_hex
           OR NEW.provider_partial_signature_hex IS DISTINCT FROM OLD.provider_partial_signature_hex
           OR NEW.provider_response_sha256 IS DISTINCT FROM OLD.provider_response_sha256
           OR NEW.response_received_at IS DISTINCT FROM OLD.response_received_at
           OR NEW.final_transaction_hex IS NULL
           OR NEW.local_partial_signature_sha256 IS NULL
           OR NEW.completed_at IS NULL THEN
            RAISE EXCEPTION 'completion must consume one exact response and signing session'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1
              FROM public.chain_swap_tx_attempts attempt
             WHERE attempt.chain_swap_id = NEW.chain_swap_id
               AND attempt.purpose = 'btc_recovery'
               AND attempt.raw_tx_hex = NEW.final_transaction_hex
               AND attempt.txid = NEW.final_txid
               AND pg_catalog.jsonb_array_length(attempt.source_prevouts) = 1
               AND attempt.source_prevouts -> 0 ->> 'txid' = NEW.source_txid
               AND (attempt.source_prevouts -> 0 ->> 'vout')::BIGINT = NEW.source_vout
               AND (attempt.source_prevouts -> 0 ->> 'amount_sat')::BIGINT = NEW.source_amount_sat
               AND attempt.source_prevouts -> 0 ->> 'script_pubkey_hex'
                     = NEW.source_script_pubkey_hex
               AND attempt.destination_address = NEW.destination_address
               AND attempt.destination_script_hex = NEW.destination_script_pubkey_hex
               AND attempt.destination_vout = 0
               AND attempt.destination_amount_sat = NEW.destination_amount_sat
               AND attempt.fee_amount_sat = NEW.fee_amount_sat
               AND attempt.fee_rate_sat_vb =
                     NEW.fee_amount_sat::DOUBLE PRECISION
                     / NEW.fee_vbytes::DOUBLE PRECISION
               AND attempt.fee_decision_purpose = NEW.fee_decision_purpose
               AND attempt.fee_decision_rail = NEW.fee_decision_rail
               AND attempt.fee_decision_target = NEW.fee_decision_target
               AND attempt.fee_decision_source = NEW.fee_decision_source
               AND attempt.fee_decision_rate_sat_vb = NEW.fee_decision_rate_sat_vb
               AND attempt.fee_decision_quoted_at_unix = NEW.fee_decision_quoted_at_unix
               AND attempt.fee_decision_evaluated_at_unix = NEW.fee_decision_evaluated_at_unix
               AND attempt.fee_decision_freshness_age_secs
                     = NEW.fee_decision_freshness_age_secs
               AND attempt.fee_decision_freshness_max_age_secs
                     = NEW.fee_decision_freshness_max_age_secs
               AND attempt.fee_decision_provenance = NEW.fee_decision_provenance
               AND attempt.fee_decision_policy_floor_sat_vb
                     = NEW.fee_decision_policy_floor_sat_vb
               AND attempt.fee_decision_policy_cap_sat_vb
                     = NEW.fee_decision_policy_cap_sat_vb
               AND attempt.fee_decision_policy_version = NEW.fee_decision_policy_version
        ) THEN
            RAISE EXCEPTION 'completion requires the exact immutable recovery attempt'
                USING ERRCODE = '23503';
        END IF;
    ELSIF NEW.state = 'integrity_hold' THEN
        NEW.integrity_hold_at := transitioned_at;
        IF NEW.request_attempt_count <> OLD.request_attempt_count
           OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
           OR NEW.ambiguous_at IS DISTINCT FROM OLD.ambiguous_at
           OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class
           OR NEW.provider_public_nonce_hex IS DISTINCT FROM OLD.provider_public_nonce_hex
           OR NEW.provider_partial_signature_hex IS DISTINCT FROM OLD.provider_partial_signature_hex
           OR NEW.provider_response_sha256 IS DISTINCT FROM OLD.provider_response_sha256
           OR NEW.response_received_at IS DISTINCT FROM OLD.response_received_at
           OR NEW.integrity_reason_sha256 IS NULL
           OR NEW.integrity_hold_at IS NULL THEN
            RAISE EXCEPTION 'integrity hold must preserve exact cooperative signing evidence'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state IN ('prepared', 'requested', 'ambiguous')
          AND NEW.state = 'superseded' THEN
        NEW.superseded_at := transitioned_at;
        IF NEW.request_attempt_count <> OLD.request_attempt_count
           OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
           OR NEW.ambiguous_at IS DISTINCT FROM OLD.ambiguous_at
           OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class
           OR NEW.provider_public_nonce_hex IS NOT NULL
           OR NEW.superseded_reason <> 'unilateral_timeout_reached'
           OR NEW.superseded_at IS NULL THEN
            RAISE EXCEPTION 'timeout supersession must preserve an unsigned cooperative request'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid cooperative signing transition from % to %',
            OLD.state, NEW.state
            USING ERRCODE = '55000';
    END IF;

    NEW.updated_at := transitioned_at;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.reject_chain_swap_cooperative_signing_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'cooperative signing operation evidence cannot be deleted'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER chain_swap_cooperative_signing_validate_insert
    BEFORE INSERT ON public.chain_swap_cooperative_signing_operations
    FOR EACH ROW EXECUTE FUNCTION public.enforce_chain_swap_cooperative_signing_insert();
CREATE TRIGGER chain_swap_cooperative_signing_validate_update
    BEFORE UPDATE ON public.chain_swap_cooperative_signing_operations
    FOR EACH ROW EXECUTE FUNCTION public.enforce_chain_swap_cooperative_signing_update();
CREATE TRIGGER chain_swap_cooperative_signing_reject_delete
    BEFORE DELETE ON public.chain_swap_cooperative_signing_operations
    FOR EACH ROW EXECUTE FUNCTION public.reject_chain_swap_cooperative_signing_delete();

REVOKE ALL ON TABLE public.chain_swap_cooperative_signing_operations FROM PUBLIC;
REVOKE ALL ON FUNCTION public.enforce_chain_swap_cooperative_signing_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.enforce_chain_swap_cooperative_signing_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.reject_chain_swap_cooperative_signing_delete() FROM PUBLIC;

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
    runtime_role_oid OID;
    relation_owner_oid OID;
    function_owner_oid OID;
    function_name TEXT;
BEGIN
    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles
     WHERE rolname = runtime_role_name;

    EXECUTE format(
        'REVOKE ALL ON TABLE public.chain_swap_cooperative_signing_operations FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE ON TABLE public.chain_swap_cooperative_signing_operations TO %I',
        runtime_role_name
    );
    FOREACH function_name IN ARRAY ARRAY[
        'enforce_chain_swap_cooperative_signing_insert',
        'enforce_chain_swap_cooperative_signing_update',
        'reject_chain_swap_cooperative_signing_delete'
    ] LOOP
        EXECUTE format(
            'REVOKE ALL ON FUNCTION public.%I() FROM %I',
            function_name, runtime_role_name
        );
    END LOOP;

    SELECT relowner INTO STRICT relation_owner_oid
      FROM pg_class
     WHERE oid = 'public.chain_swap_cooperative_signing_operations'::REGCLASS
       AND relkind = 'r';
    IF relation_owner_oid = runtime_role_oid
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'SET')
       OR NOT has_table_privilege(
           runtime_role_name,
           'public.chain_swap_cooperative_signing_operations',
           'SELECT'
       )
       OR NOT has_table_privilege(
           runtime_role_name,
           'public.chain_swap_cooperative_signing_operations',
           'INSERT'
       )
       OR NOT has_table_privilege(
           runtime_role_name,
           'public.chain_swap_cooperative_signing_operations',
           'UPDATE'
       )
       OR has_table_privilege(
           runtime_role_name,
           'public.chain_swap_cooperative_signing_operations',
           'DELETE'
       )
       OR has_table_privilege(
           runtime_role_name,
           'public.chain_swap_cooperative_signing_operations',
           'TRUNCATE'
       )
       OR has_table_privilege(
           runtime_role_name,
           'public.chain_swap_cooperative_signing_operations',
           'REFERENCES'
       )
       OR has_table_privilege(
           runtime_role_name,
           'public.chain_swap_cooperative_signing_operations',
           'TRIGGER'
       ) THEN
        RAISE EXCEPTION 'migration 057 failed protected runtime ACL for cooperative signing journal'
            USING ERRCODE = '42501';
    END IF;

    FOREACH function_name IN ARRAY ARRAY[
        'enforce_chain_swap_cooperative_signing_insert',
        'enforce_chain_swap_cooperative_signing_update',
        'reject_chain_swap_cooperative_signing_delete'
    ] LOOP
        SELECT procedure_info.proowner
          INTO STRICT function_owner_oid
          FROM pg_proc procedure_info
          JOIN pg_namespace namespace
            ON namespace.oid = procedure_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND procedure_info.proname = function_name
           AND procedure_info.pronargs = 0;
        IF function_owner_oid = runtime_role_oid
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'USAGE')
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'SET')
           OR has_function_privilege(
               runtime_role_name,
               format('public.%I()', function_name),
               'EXECUTE'
           ) THEN
            RAISE EXCEPTION 'migration 057 failed protected owner/ACL for function %',
                function_name
                USING ERRCODE = '42501';
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1
          FROM information_schema.columns column_info
         WHERE column_info.table_schema = 'public'
           AND column_info.table_name = 'chain_swap_cooperative_signing_operations'
           AND (
               column_info.is_identity <> 'NO'
               OR column_info.is_generated <> 'NEVER'
               OR column_info.column_default LIKE 'nextval(%'
           )
    ) OR EXISTS (
        SELECT 1
          FROM pg_depend dependency
          JOIN pg_class sequence_info ON sequence_info.oid = dependency.objid
         WHERE dependency.classid = 'pg_class'::REGCLASS
           AND dependency.refclassid = 'pg_class'::REGCLASS
           AND dependency.refobjid =
                 'public.chain_swap_cooperative_signing_operations'::REGCLASS
           AND dependency.deptype IN ('a', 'i')
           AND sequence_info.relkind = 'S'
    ) THEN
        RAISE EXCEPTION 'migration 057 unexpectedly created generated or sequence-backed authority'
            USING ERRCODE = '55000';
    END IF;
END
$$;

COMMIT;

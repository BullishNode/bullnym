use axum::http::StatusCode;
use axum::{response::IntoResponse, Json};
use serde::Serialize;
use std::time::Duration;
use tokio::time::timeout;

use crate::version::EXPECTED_SCHEMA_MARKER;
use crate::AppState;

const READINESS_DB_TIMEOUT: Duration = Duration::from_secs(2);

const EXPECTED_PRIVATE_INVOICE_SHAPE_EXPRESSION: &str = concat!(
    "origin='wallet'::textANDclient_request_idISNOTNULLAND",
    "client_request_digestISNOTNULLANDoctet_length(client_request_digest)=32AND",
    "presentation_envelopeISNOTNULLANDCASEWHEN",
    "octet_length(presentation_envelope)=4125THEN",
    "get_byte(presentation_envelope,0)=1ELSEfalseENDOR",
    "origin='checkout'::textANDclient_request_idISNULLAND",
    "client_request_digestISNULLANDpresentation_envelopeISNULL"
);
const EXPECTED_PRIVATE_INVOICE_TRIGGER_DEFINITION: &str = concat!(
    "CREATETRIGGERinvoices_reject_private_presentation_updateBEFOREUPDATEOF",
    "client_request_id,client_request_digest,presentation_envelopeONinvoices",
    "FOREACHROWEXECUTEFUNCTIONreject_invoice_private_presentation_update()"
);
const EXPECTED_PRIVATE_INVOICE_TRIGGER_BODY_SHA256: &str =
    "eaf7c3093aeba6409ea484e8d2570fe480725e7dcd53a920143cacb7c647628b";

const EXPECTED_MERCHANT_SETTLEMENT_FEE_SHAPE_EXPRESSION: &str = concat!(
    "num_nonnulls(fee_decision_purpose,fee_decision_rail,fee_decision_target,",
    "fee_decision_source,fee_decision_rate_sat_vb,fee_decision_quoted_at_unix,",
    "fee_decision_evaluated_at_unix,fee_decision_freshness_age_secs,",
    "fee_decision_freshness_max_age_secs,fee_decision_provenance,",
    "fee_decision_policy_floor_sat_vb,fee_decision_policy_cap_sat_vb,",
    "fee_decision_policy_version)=ANY(ARRAY[0,13])"
);

const EXPECTED_MERCHANT_SETTLEMENT_FEE_VALUE_EXPRESSION: &str = concat!(
    "fee_decision_purposeISNULLOR(purpose='btc_recovery'::textAND",
    "fee_decision_purpose='bitcoin_recovery'::textAND",
    "fee_decision_rail='bitcoin'::textANDfee_decision_target='fastestFee'::textAND",
    "(fee_decision_source=ANY(ARRAY['bitcoin_live'::text,",
    "'bitcoin_last_known_good'::text]))OR",
    "(purpose=ANY(ARRAY['liquid_claim'::text,'liquid_claim_replacement'::text]))AND",
    "fee_decision_purpose='chain_liquid_claim'::textAND",
    "fee_decision_rail='liquid'::textANDfee_decision_target='1'::textAND",
    "(fee_decision_source=ANY(ARRAY['liquid_live'::text,",
    "'liquid_last_known_good'::text])))AND",
    "fee_decision_rate_sat_vb>0::doubleprecisionAND",
    "(fee_decision_rate_sat_vb<>ALL(ARRAY['NaN'::doubleprecision,",
    "'Infinity'::doubleprecision,'-Infinity'::doubleprecision]))AND",
    "fee_decision_quoted_at_unix>=0AND",
    "fee_decision_evaluated_at_unix>=fee_decision_quoted_at_unixAND",
    "fee_decision_freshness_age_secs>=0ANDfee_decision_freshness_max_age_secs>0AND",
    "(fee_decision_evaluated_at_unix-fee_decision_quoted_at_unix)=",
    "fee_decision_freshness_age_secsAND",
    "fee_decision_freshness_age_secs<=fee_decision_freshness_max_age_secsAND",
    "btrim(fee_decision_provenance)<>''::textAND",
    "octet_length(fee_decision_provenance)<=512AND",
    "fee_decision_policy_floor_sat_vb>0::doubleprecisionAND",
    "(fee_decision_policy_floor_sat_vb<>ALL(ARRAY['NaN'::doubleprecision,",
    "'Infinity'::doubleprecision,'-Infinity'::doubleprecision]))AND",
    "fee_decision_policy_cap_sat_vb>=fee_decision_policy_floor_sat_vbAND",
    "(fee_decision_policy_cap_sat_vb<>ALL(ARRAY['NaN'::doubleprecision,",
    "'Infinity'::doubleprecision,'-Infinity'::doubleprecision]))AND",
    "fee_decision_rate_sat_vb>=fee_decision_policy_floor_sat_vbAND",
    "fee_decision_rate_sat_vb<=fee_decision_policy_cap_sat_vbAND",
    "fee_decision_policy_version='review25-v1'::text"
);

const MERCHANT_SETTLEMENT_FEE_SCHEMA_SQL: &str =
    "WITH required_columns(column_name, type_oid, ordinal) AS (VALUES \
         ('fee_decision_purpose', 'text'::REGTYPE, 1), \
         ('fee_decision_rail', 'text'::REGTYPE, 2), \
         ('fee_decision_target', 'text'::REGTYPE, 3), \
         ('fee_decision_source', 'text'::REGTYPE, 4), \
         ('fee_decision_rate_sat_vb', 'float8'::REGTYPE, 5), \
         ('fee_decision_quoted_at_unix', 'int8'::REGTYPE, 6), \
         ('fee_decision_evaluated_at_unix', 'int8'::REGTYPE, 7), \
         ('fee_decision_freshness_age_secs', 'int8'::REGTYPE, 8), \
         ('fee_decision_freshness_max_age_secs', 'int8'::REGTYPE, 9), \
         ('fee_decision_provenance', 'text'::REGTYPE, 10), \
         ('fee_decision_policy_floor_sat_vb', 'float8'::REGTYPE, 11), \
         ('fee_decision_policy_cap_sat_vb', 'float8'::REGTYPE, 12), \
         ('fee_decision_policy_version', 'text'::REGTYPE, 13) \
     ), validated_constraints AS ( \
         SELECT constraint_info.conname, \
                regexp_replace( \
                    pg_get_expr( \
                        constraint_info.conbin, constraint_info.conrelid, TRUE \
                    ), \
                    '[[:space:]]+', '', 'g' \
                ) AS expression \
           FROM pg_constraint constraint_info \
           JOIN pg_class relation ON relation.oid = constraint_info.conrelid \
           JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
          WHERE namespace.nspname = 'public' \
            AND relation.relname = 'chain_swap_tx_attempts' \
            AND relation.relkind = 'r' \
            AND constraint_info.contype = 'c' \
            AND constraint_info.convalidated \
            AND constraint_info.conname IN ( \
                'chain_swap_tx_attempts_fee_authority_shape_check', \
                'chain_swap_tx_attempts_fee_authority_value_check' \
            ) \
     ) \
     SELECT NOT EXISTS ( \
         SELECT 1 FROM required_columns required \
          WHERE NOT EXISTS ( \
              SELECT 1 \
                FROM pg_attribute attribute \
                JOIN pg_class relation ON relation.oid = attribute.attrelid \
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
               WHERE namespace.nspname = 'public' \
                 AND relation.relname = 'chain_swap_tx_attempts' \
                 AND relation.relkind = 'r' \
                 AND attribute.attname = required.column_name \
                 AND attribute.atttypid = required.type_oid \
                 AND attribute.atttypmod = -1 \
                 AND NOT attribute.attnotnull \
                 AND attribute.attnum > 0 \
                 AND NOT attribute.attisdropped \
          ) \
     ) \
     AND (SELECT COUNT(*) FROM validated_constraints) = 2 \
     AND EXISTS ( \
         SELECT 1 FROM validated_constraints \
          WHERE conname = 'chain_swap_tx_attempts_fee_authority_shape_check' \
            AND expression = $1 \
     ) \
     AND EXISTS ( \
         SELECT 1 FROM validated_constraints \
          WHERE conname = 'chain_swap_tx_attempts_fee_authority_value_check' \
            AND expression = $2 \
     )";

const MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL: &str =
    "WITH required_function_bodies(function_name, body_sha256) AS (VALUES \
         ('enforce_liquid_claim_replacement_lineage', '2c6eb8d351f5fe1330d101915e897b2984b91f747d31e879d31d555f18105f27'), \
         ('enforce_merchant_settlement_checkpoint_write', '5e8189d952b8a1f921bafc6da90c2ae658c46691b243f6bbd5e16d056bf7ca29'), \
         ('enforce_merchant_settlement_retained_update', '840d9f3ee9d6fb05f27a2fa9c56f583b411d34b47b92d3a27bc0089622d5ddd0'), \
         ('guard_chain_swap_tx_attempt_immutable', 'a11b15a80a879cb5cc9b1b9f3a6c795d72c82263f53b01b1e52e4bb726f800d3'), \
         ('guard_invoice_payment_event_evidence', '893b3f4effa66be50635c1e6a7904783e85d52e30e015123f8438a8a62c295d8'), \
         ('reject_merchant_settlement_delete', '475959643f22379df0eb575f0c2410ee523fe9d15591c73838eecaba7ac9a875'), \
         ('reject_merchant_settlement_event_delete', '6da9435887b06e540a1833528587547bbee9a27dca5e42004d2bd576c1e32be8'), \
         ('require_review25_bitcoin_attempt_fee_authority', '33021f5da06d90a78139df9bacf9d29f84e8225f6f656d6968a1bc99ad169678') \
     ) \
     SELECT NOT EXISTS ( \
         SELECT 1 \
           FROM (VALUES \
             ('chain_swap_tx_attempts', 'chain_swap_tx_attempts_require_review25_fee_authority', 'require_review25_bitcoin_attempt_fee_authority', 7), \
             ('chain_swap_tx_attempts', 'chain_swap_tx_attempts_immutable', 'guard_chain_swap_tx_attempt_immutable', 19), \
             ('chain_swap_tx_attempts', 'chain_swap_tx_attempts_validate_replacement', 'enforce_liquid_claim_replacement_lineage', 7), \
             ('invoice_payment_events', 'invoice_payment_event_evidence_guard', 'guard_invoice_payment_event_evidence', 19), \
             ('invoice_payment_events', 'invoice_payment_event_reject_merchant_settlement_delete', 'reject_merchant_settlement_event_delete', 11), \
             ('merchant_settlement_checkpoints', 'merchant_settlement_checkpoint_validate_write', 'enforce_merchant_settlement_checkpoint_write', 23), \
             ('merchant_settlement_checkpoints', 'merchant_settlement_checkpoint_reject_delete', 'reject_merchant_settlement_delete', 11), \
             ('merchant_settlement_retained_outputs', 'merchant_settlement_retained_validate_update', 'enforce_merchant_settlement_retained_update', 23), \
             ('merchant_settlement_retained_outputs', 'merchant_settlement_retained_reject_delete', 'reject_merchant_settlement_delete', 11) \
           ) required(table_name, trigger_name, function_name, trigger_type) \
          WHERE NOT EXISTS ( \
              SELECT 1 \
                FROM pg_trigger trigger_info \
                JOIN pg_class relation ON relation.oid = trigger_info.tgrelid \
                JOIN pg_namespace relation_namespace \
                  ON relation_namespace.oid = relation.relnamespace \
                JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid \
                JOIN pg_namespace function_namespace \
                  ON function_namespace.oid = function_info.pronamespace \
               WHERE relation_namespace.nspname = 'public' \
                 AND function_namespace.nspname = 'public' \
                 AND relation.relname = required.table_name \
                 AND relation.relkind = 'r' \
                 AND trigger_info.tgname = required.trigger_name \
                 AND function_info.proname = required.function_name \
                 AND function_info.pronargs = 0 \
                 AND trigger_info.tgtype = required.trigger_type::SMALLINT \
                 AND trigger_info.tgnargs = 0 \
                 AND trigger_info.tgattr::TEXT = '' \
                 AND trigger_info.tgqual IS NULL \
                 AND trigger_info.tgconstraint = 0 \
                 AND NOT trigger_info.tgdeferrable \
                 AND NOT trigger_info.tginitdeferred \
                 AND NOT trigger_info.tgisinternal \
                 AND trigger_info.tgenabled = 'O' \
          ) \
    ) \
    AND NOT EXISTS ( \
        SELECT 1 FROM required_function_bodies required \
         WHERE NOT EXISTS ( \
             SELECT 1 \
               FROM pg_proc function_info \
               JOIN pg_namespace function_namespace \
                 ON function_namespace.oid = function_info.pronamespace \
               JOIN pg_language language_info \
                 ON language_info.oid = function_info.prolang \
              WHERE function_namespace.nspname = 'public' \
                AND function_info.proname = required.function_name \
                AND function_info.pronargs = 0 \
                AND function_info.prokind = 'f' \
                AND function_info.prorettype = 'trigger'::REGTYPE \
                AND language_info.lanname = 'plpgsql' \
                AND function_info.provolatile = 'v' \
                AND NOT function_info.proisstrict \
                AND NOT function_info.prosecdef \
                AND NOT function_info.proleakproof \
                AND function_info.proparallel = 'u' \
                AND function_info.proconfig IS NULL \
                AND encode( \
                    sha256(convert_to(function_info.prosrc, 'UTF8')), 'hex' \
                ) = required.body_sha256 \
         ) \
    )";

const MERCHANT_SETTLEMENT_PRIVILEGES_SQL: &str =
    "WITH required_tables(table_name) AS (VALUES \
         ('chain_swap_tx_attempts'), \
         ('invoice_payment_events'), \
         ('merchant_settlement_checkpoints'), \
         ('merchant_settlement_retained_outputs') \
     ), required_functions(function_name) AS (VALUES \
         ('guard_chain_swap_tx_attempt_immutable'), \
         ('require_review25_bitcoin_attempt_fee_authority'), \
         ('enforce_liquid_claim_replacement_lineage'), \
         ('guard_invoice_payment_event_evidence'), \
         ('reject_merchant_settlement_event_delete'), \
         ('enforce_merchant_settlement_checkpoint_write'), \
         ('enforce_merchant_settlement_retained_update'), \
         ('reject_merchant_settlement_delete') \
     ) \
     SELECT NOT EXISTS ( \
         SELECT 1 FROM required_tables required \
          WHERE NOT EXISTS ( \
              SELECT 1 \
                FROM pg_class relation \
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
               WHERE namespace.nspname = 'public' \
                 AND relation.relname = required.table_name \
                 AND relation.relkind = 'r' \
                 AND pg_get_userbyid(relation.relowner) <> current_user \
                 AND NOT pg_has_role(current_user, pg_get_userbyid(relation.relowner), 'USAGE') \
                 AND NOT pg_has_role(current_user, pg_get_userbyid(relation.relowner), 'SET') \
                 AND has_table_privilege(current_user, relation.oid, 'SELECT') \
                 AND has_table_privilege(current_user, relation.oid, 'INSERT') \
                 AND has_table_privilege(current_user, relation.oid, 'UPDATE') \
                 AND NOT has_table_privilege(current_user, relation.oid, 'DELETE') \
                 AND NOT has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                 AND NOT has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                 AND NOT has_table_privilege(current_user, relation.oid, 'TRIGGER') \
          ) \
     ) \
     AND NOT EXISTS ( \
         SELECT 1 \
           FROM pg_class relation \
           JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
           CROSS JOIN LATERAL aclexplode(COALESCE( \
               relation.relacl, acldefault('r', relation.relowner) \
           )) acl \
          WHERE namespace.nspname = 'public' \
            AND relation.relname IN (SELECT table_name FROM required_tables) \
            AND acl.grantee = 0 \
     ) \
     AND NOT EXISTS ( \
         SELECT 1 FROM required_functions required \
          WHERE NOT EXISTS ( \
              SELECT 1 \
                FROM pg_proc function_info \
                JOIN pg_namespace namespace \
                  ON namespace.oid = function_info.pronamespace \
               WHERE namespace.nspname = 'public' \
                 AND function_info.proname = required.function_name \
                 AND function_info.pronargs = 0 \
                 AND pg_get_userbyid(function_info.proowner) <> current_user \
                 AND NOT pg_has_role(current_user, pg_get_userbyid(function_info.proowner), 'USAGE') \
                 AND NOT pg_has_role(current_user, pg_get_userbyid(function_info.proowner), 'SET') \
          ) \
     ) \
     AND EXISTS ( \
         SELECT 1 \
           FROM pg_class sequence_info \
           JOIN pg_namespace namespace ON namespace.oid = sequence_info.relnamespace \
          WHERE namespace.nspname = 'public' \
            AND sequence_info.relname = 'invoice_payment_events_accounting_sequence_seq' \
            AND sequence_info.relkind = 'S' \
            AND pg_get_userbyid(sequence_info.relowner) <> current_user \
            AND NOT pg_has_role(current_user, pg_get_userbyid(sequence_info.relowner), 'USAGE') \
            AND NOT pg_has_role(current_user, pg_get_userbyid(sequence_info.relowner), 'SET') \
            AND has_sequence_privilege(current_user, sequence_info.oid, 'USAGE') \
            AND NOT has_sequence_privilege(current_user, sequence_info.oid, 'SELECT') \
            AND NOT has_sequence_privilege(current_user, sequence_info.oid, 'UPDATE') \
            AND NOT EXISTS ( \
                SELECT 1 \
                  FROM aclexplode(COALESCE( \
                      sequence_info.relacl, acldefault('S', sequence_info.relowner) \
                  )) acl \
                 WHERE acl.grantee = 0 \
            ) \
     )";

const CHAIN_SWAP_RENEGOTIATION_INVARIANTS_SQL: &str = r#"
SELECT
    COALESCE((
        SELECT array_agg(
                   format('%s:%s:%s', column_name, data_type, is_nullable)
                   ORDER BY ordinal_position
               ) = ARRAY[
                   'chain_swap_id:uuid:NO',
                   'state:text:NO',
                   'quoted_actual_amount_sat:bigint:NO',
                   'quote_response_digest:text:NO',
                   'quote_observed_at:timestamp with time zone:NO',
                   'policy_version:text:NO',
                   'policy_evidence_digest:text:NO',
                   'policy_validated_at:timestamp with time zone:NO',
                   'accept_attempt_count:integer:NO',
                   'last_error_class:text:YES',
                   'version:bigint:NO',
                   'accept_requested_at:timestamp with time zone:YES',
                   'ambiguous_at:timestamp with time zone:YES',
                   'terminal_response_digest:text:YES',
                   'terminal_observed_at:timestamp with time zone:YES',
                   'created_at:timestamp with time zone:NO',
                   'updated_at:timestamp with time zone:NO'
               ]::TEXT[]
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'chain_swap_renegotiation_operations'
    ), FALSE)
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('state', '''quoted''::text'),
              ('accept_attempt_count', '0'),
              ('version', '1'),
              ('created_at', 'now()'),
              ('updated_at', 'now()')
          ) required(column_name, expected_default)
         WHERE NOT EXISTS (
             SELECT 1
               FROM information_schema.columns column_info
              WHERE column_info.table_schema = 'public'
                AND column_info.table_name =
                    'chain_swap_renegotiation_operations'
                AND column_info.column_name = required.column_name
                AND column_info.column_default = required.expected_default
         )
    )
    AND (
        SELECT COUNT(*)
          FROM pg_constraint constraint_info
         WHERE constraint_info.conrelid =
             to_regclass('public.chain_swap_renegotiation_operations')
           AND constraint_info.contype = 'c'
    ) = 9
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_renegotiation_state_check'),
              ('chain_swap_renegotiation_quoted_amount_check'),
              ('chain_swap_renegotiation_quote_digest_check'),
              ('chain_swap_renegotiation_policy_evidence_check'),
              ('chain_swap_renegotiation_attempt_count_check'),
              ('chain_swap_renegotiation_error_class_check'),
              ('chain_swap_renegotiation_version_check'),
              ('chain_swap_renegotiation_terminal_digest_check'),
              ('chain_swap_renegotiation_lifecycle_shape_check')
          ) required(constraint_name)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_constraint constraint_info
              WHERE constraint_info.conrelid =
                  to_regclass('public.chain_swap_renegotiation_operations')
                AND constraint_info.conname = required.constraint_name
                AND constraint_info.contype = 'c'
                AND constraint_info.convalidated
         )
    )
    AND EXISTS (
        SELECT 1
          FROM pg_constraint constraint_info
         WHERE constraint_info.conrelid =
             to_regclass('public.chain_swap_renegotiation_operations')
           AND constraint_info.conname =
               'chain_swap_renegotiation_operations_pkey'
           AND constraint_info.contype = 'p'
           AND constraint_info.convalidated
    )
    AND EXISTS (
        SELECT 1
          FROM pg_constraint foreign_key
         WHERE foreign_key.conrelid =
             to_regclass('public.chain_swap_renegotiation_operations')
           AND foreign_key.confrelid = to_regclass('public.chain_swap_records')
           AND foreign_key.conname =
               'chain_swap_renegotiation_operations_chain_fkey'
           AND foreign_key.contype = 'f'
           AND foreign_key.convalidated
           AND foreign_key.confupdtype = 'r'
           AND foreign_key.confdeltype = 'r'
           AND NOT foreign_key.condeferrable
           AND NOT foreign_key.condeferred
    )
    AND EXISTS (
        SELECT 1
         FROM pg_constraint constraint_info
         WHERE constraint_info.conrelid =
             to_regclass('public.chain_swap_renegotiation_operations')
           AND constraint_info.conname =
               'chain_swap_renegotiation_error_class_check'
           AND pg_get_constraintdef(constraint_info.oid) LIKE '%timeout%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE '%transport%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%provider_server_error%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%malformed_response%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%backend_disagreement%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%local_commit_uncertainty%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%unknown_provider_outcome%'
    )
    AND EXISTS (
        SELECT 1
         FROM pg_constraint constraint_info
         WHERE constraint_info.conrelid =
             to_regclass('public.chain_swap_renegotiation_operations')
           AND constraint_info.conname =
               'chain_swap_renegotiation_state_check'
           AND pg_get_constraintdef(constraint_info.oid) LIKE '%quoted%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%accept_requested%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE '%ambiguous%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE '%accepted%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE '%declined%'
    )
    AND EXISTS (
        SELECT 1
         FROM pg_constraint constraint_info
         WHERE constraint_info.conrelid =
             to_regclass('public.chain_swap_renegotiation_operations')
           AND constraint_info.conname =
               'chain_swap_renegotiation_policy_evidence_check'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%policy_version%[[:space:]]%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%policy_evidence_digest%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%quote_observed_at%1970-01-01%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%policy_validated_at >= quote_observed_at%'
    )
    AND EXISTS (
        SELECT 1
         FROM pg_constraint constraint_info
         WHERE constraint_info.conrelid =
             to_regclass('public.chain_swap_renegotiation_operations')
           AND constraint_info.conname =
               'chain_swap_renegotiation_lifecycle_shape_check'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%accept_requested_at >= created_at%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%accept_requested_at <= updated_at%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%ambiguous_at <= updated_at%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%terminal_observed_at >= created_at%'
           AND pg_get_constraintdef(constraint_info.oid) LIKE
               '%terminal_observed_at <= updated_at%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_index index_info
         JOIN pg_class index_relation
            ON index_relation.oid = index_info.indexrelid
         WHERE index_info.indrelid =
             to_regclass('public.chain_swap_renegotiation_operations')
           AND index_relation.relname = 'chain_swap_renegotiation_active_idx'
           AND NOT index_info.indisunique
           AND index_info.indisvalid
           AND pg_get_indexdef(index_info.indexrelid) LIKE
               '%(updated_at, chain_swap_id)%'
           AND pg_get_expr(index_info.indpred, index_info.indrelid) LIKE
               '%accepted%declined%'
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_renegotiation_validate_insert',
                  'enforce_chain_swap_renegotiation_insert', 7),
              ('chain_swap_renegotiation_validate_update',
                  'enforce_chain_swap_renegotiation_update', 19),
              ('chain_swap_renegotiation_reject_delete',
                  'reject_chain_swap_renegotiation_delete', 11)
          ) required(trigger_name, function_name, trigger_type)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_trigger trigger_info
               JOIN pg_class relation ON relation.oid = trigger_info.tgrelid
               JOIN pg_namespace relation_namespace
                 ON relation_namespace.oid = relation.relnamespace
               JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid
               JOIN pg_namespace function_namespace
                 ON function_namespace.oid = function_info.pronamespace
              WHERE relation_namespace.nspname = 'public'
                AND function_namespace.nspname = 'public'
                AND relation.relname = 'chain_swap_renegotiation_operations'
                AND relation.relkind = 'r'
                AND trigger_info.tgname = required.trigger_name
                AND trigger_info.tgtype = required.trigger_type::SMALLINT
                AND NOT trigger_info.tgisinternal
                AND trigger_info.tgenabled IN ('O', 'A')
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
         )
    )
    AND EXISTS (
        SELECT 1
          FROM pg_proc function_info
          JOIN pg_namespace namespace
            ON namespace.oid = function_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND function_info.proname =
               'enforce_chain_swap_renegotiation_insert'
           AND function_info.pronargs = 0
           AND pg_get_functiondef(function_info.oid) LIKE
               '%NEW.state <> ''quoted''%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%NEW.version <> 1%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%NEW.quote_observed_at > persisted_at%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%NEW.policy_validated_at > persisted_at%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_proc function_info
          JOIN pg_namespace namespace
            ON namespace.oid = function_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND function_info.proname =
               'enforce_chain_swap_renegotiation_update'
           AND function_info.pronargs = 0
           AND pg_get_functiondef(function_info.oid) LIKE
               '%OLD.state IN (''accepted'', ''declined'')%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%NEW.version <> OLD.version + 1%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%OLD.state = ''ambiguous'' AND NEW.state = ''accept_requested''%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%OLD.state = ''ambiguous'' AND NEW.state = ''accepted''%'
           AND pg_get_functiondef(function_info.oid) NOT LIKE
               '%OLD.state = ''ambiguous'' AND NEW.state = ''declined''%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%NEW.quote_response_digest%OLD.quote_response_digest%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%NEW.policy_evidence_digest%OLD.policy_evidence_digest%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_proc function_info
          JOIN pg_namespace namespace
            ON namespace.oid = function_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND function_info.proname =
               'reject_chain_swap_renegotiation_delete'
           AND function_info.pronargs = 0
           AND pg_get_functiondef(function_info.oid) LIKE
               '%renegotiation operation evidence cannot be deleted%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relname = 'chain_swap_renegotiation_operations'
           AND relation.relkind = 'r'
           AND pg_get_userbyid(relation.relowner) <> current_user
           AND NOT pg_has_role(
               current_user, pg_get_userbyid(relation.relowner), 'USAGE'
           )
           AND NOT pg_has_role(
               current_user, pg_get_userbyid(relation.relowner), 'SET'
           )
           AND has_table_privilege(current_user, relation.oid, 'SELECT')
           AND has_table_privilege(current_user, relation.oid, 'INSERT')
           AND has_table_privilege(current_user, relation.oid, 'UPDATE')
           AND NOT has_table_privilege(current_user, relation.oid, 'DELETE')
           AND NOT has_table_privilege(current_user, relation.oid, 'TRUNCATE')
           AND NOT has_table_privilege(current_user, relation.oid, 'REFERENCES')
           AND NOT has_table_privilege(current_user, relation.oid, 'TRIGGER')
           AND NOT EXISTS (
               SELECT 1
                 FROM aclexplode(COALESCE(
                     relation.relacl, acldefault('r', relation.relowner)
                 )) acl
                WHERE acl.grantee = 0
           )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('enforce_chain_swap_renegotiation_insert'),
              ('enforce_chain_swap_renegotiation_update'),
              ('reject_chain_swap_renegotiation_delete')
          ) required(function_name)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_proc function_info
               JOIN pg_namespace namespace
                 ON namespace.oid = function_info.pronamespace
              WHERE namespace.nspname = 'public'
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
                AND pg_get_userbyid(function_info.proowner) <> current_user
                AND NOT pg_has_role(
                    current_user,
                    pg_get_userbyid(function_info.proowner),
                    'USAGE'
                )
                AND NOT pg_has_role(
                    current_user,
                    pg_get_userbyid(function_info.proowner),
                    'SET'
                )
                AND NOT has_function_privilege(
                    current_user, function_info.oid, 'EXECUTE'
                )
                AND NOT EXISTS (
                    SELECT 1
                      FROM aclexplode(COALESCE(
                          function_info.proacl,
                          acldefault('f', function_info.proowner)
                      )) acl
                     WHERE acl.grantee = 0
                       AND acl.privilege_type = 'EXECUTE'
                )
         )
    )
"#;

const CHAIN_SWAP_COOPERATIVE_SIGNING_INVARIANTS_SQL: &str = r#"
SELECT
    to_regclass('public.chain_swap_cooperative_signing_operations') IS NOT NULL
    AND (SELECT COUNT(*) = 60
           FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'chain_swap_cooperative_signing_operations')
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('request_transaction_txid', 'text', 'NO'),
              ('secret_nonce_encryption_nonce', 'bytea', 'NO'),
              ('secret_nonce_ciphertext', 'bytea', 'NO'),
              ('provider_response_sha256', 'text', 'YES'),
              ('final_transaction_hex', 'text', 'YES'),
              ('local_partial_signature_sha256', 'text', 'YES'),
              ('superseded_reason', 'text', 'YES')
          ) required(column_name, data_type, is_nullable)
         WHERE NOT EXISTS (
             SELECT 1
               FROM information_schema.columns column_info
              WHERE column_info.table_schema = 'public'
                AND column_info.table_name =
                    'chain_swap_cooperative_signing_operations'
                AND column_info.column_name = required.column_name
                AND column_info.data_type = required.data_type
                AND column_info.is_nullable = required.is_nullable
         )
    )
    AND (SELECT COUNT(*) = 14
           FROM pg_constraint
          WHERE conrelid =
                to_regclass('public.chain_swap_cooperative_signing_operations')
            AND contype = 'c')
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_cooperative_signing_state_check'),
              ('chain_swap_cooperative_signing_exact_fee_check'),
              ('chain_swap_cooperative_signing_fee_authority_check'),
              ('chain_swap_cooperative_signing_request_check'),
              ('chain_swap_cooperative_signing_secret_nonce_check'),
              ('chain_swap_cooperative_signing_response_check'),
              ('chain_swap_cooperative_signing_completion_check'),
              ('chain_swap_cooperative_signing_lifecycle_shape_check')
          ) required(constraint_name)
         WHERE NOT EXISTS (
             SELECT 1 FROM pg_constraint constraint_info
              WHERE constraint_info.conrelid =
                    to_regclass('public.chain_swap_cooperative_signing_operations')
                AND constraint_info.conname = required.constraint_name
                AND constraint_info.contype = 'c'
                AND constraint_info.convalidated
         )
    )
    AND EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid =
               to_regclass('public.chain_swap_cooperative_signing_operations')
           AND confrelid = to_regclass('public.chain_swap_records')
           AND conname = 'chain_swap_cooperative_signing_chain_fkey'
           AND contype = 'f' AND convalidated
           AND confupdtype = 'r' AND confdeltype = 'r'
           AND NOT condeferrable AND NOT condeferred
    )
    AND EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid =
               to_regclass('public.chain_swap_cooperative_signing_operations')
           AND conname = 'chain_swap_cooperative_signing_response_check'
           AND pg_get_constraintdef(oid) LIKE
               '%bullnym:cooperative-signing-provider-response:v1:%'
    )
    AND EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid =
               to_regclass('public.chain_swap_cooperative_signing_operations')
           AND conname = 'chain_swap_cooperative_signing_completion_check'
           AND pg_get_constraintdef(oid) LIKE
               '%final_txid = request_transaction_txid%'
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_cooperative_signing_validate_insert',
                  'enforce_chain_swap_cooperative_signing_insert'),
              ('chain_swap_cooperative_signing_validate_update',
                  'enforce_chain_swap_cooperative_signing_update'),
              ('chain_swap_cooperative_signing_reject_delete',
                  'reject_chain_swap_cooperative_signing_delete')
          ) required(trigger_name, function_name)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_trigger trigger_info
               JOIN pg_class relation ON relation.oid = trigger_info.tgrelid
               JOIN pg_namespace relation_namespace
                 ON relation_namespace.oid = relation.relnamespace
               JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid
              WHERE relation_namespace.nspname = 'public'
                AND relation.relname =
                    'chain_swap_cooperative_signing_operations'
                AND trigger_info.tgname = required.trigger_name
                AND NOT trigger_info.tgisinternal
                AND trigger_info.tgenabled = 'O'
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
         )
    )
    AND EXISTS (
        SELECT 1
          FROM pg_proc function_info
          JOIN pg_namespace namespace ON namespace.oid = function_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND function_info.proname =
               'enforce_chain_swap_cooperative_signing_insert'
           AND function_info.pronargs = 0
           AND pg_get_functiondef(function_info.oid) LIKE
               '%FROM public.chain_swap_records%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%pg_catalog.clock_timestamp()%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_proc function_info
          JOIN pg_namespace namespace ON namespace.oid = function_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND function_info.proname =
               'enforce_chain_swap_cooperative_signing_update'
           AND function_info.pronargs = 0
           AND pg_get_functiondef(function_info.oid) LIKE
               '%FROM public.chain_swap_tx_attempts attempt%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%pg_catalog.jsonb_array_length(attempt.source_prevouts)%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%pg_catalog.clock_timestamp()%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relname = 'chain_swap_cooperative_signing_operations'
           AND relation.relkind = 'r'
           AND pg_get_userbyid(relation.relowner) <> current_user
           AND NOT pg_has_role(
               current_user, pg_get_userbyid(relation.relowner), 'USAGE'
           )
           AND NOT pg_has_role(
               current_user, pg_get_userbyid(relation.relowner), 'SET'
           )
           AND has_table_privilege(current_user, relation.oid, 'SELECT')
           AND has_table_privilege(current_user, relation.oid, 'INSERT')
           AND has_table_privilege(current_user, relation.oid, 'UPDATE')
           AND NOT has_table_privilege(current_user, relation.oid, 'DELETE')
           AND NOT has_table_privilege(current_user, relation.oid, 'TRUNCATE')
           AND NOT has_table_privilege(current_user, relation.oid, 'REFERENCES')
           AND NOT has_table_privilege(current_user, relation.oid, 'TRIGGER')
           AND NOT EXISTS (
               SELECT 1 FROM aclexplode(COALESCE(
                   relation.relacl, acldefault('r', relation.relowner)
               )) acl WHERE acl.grantee = 0
           )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('enforce_chain_swap_cooperative_signing_insert'),
              ('enforce_chain_swap_cooperative_signing_update'),
              ('reject_chain_swap_cooperative_signing_delete')
          ) required(function_name)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_proc function_info
               JOIN pg_namespace namespace
                 ON namespace.oid = function_info.pronamespace
              WHERE namespace.nspname = 'public'
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
                AND pg_get_userbyid(function_info.proowner) <> current_user
                AND NOT pg_has_role(
                    current_user, pg_get_userbyid(function_info.proowner), 'USAGE'
                )
                AND NOT pg_has_role(
                    current_user, pg_get_userbyid(function_info.proowner), 'SET'
                )
                AND NOT has_function_privilege(
                    current_user, function_info.oid, 'EXECUTE'
                )
         )
    )
"#;

const PERMANENT_PUBLIC_NAME_INVARIANTS_SQL: &str = r#"
SELECT COALESCE((
    to_regclass('public.public_names') IS NOT NULL
    AND COALESCE((
        SELECT array_agg(
                   format('%s:%s:%s', column_name, data_type, is_nullable)
                   ORDER BY ordinal_position
               ) = ARRAY[
                   'id:uuid:NO',
                   'name:text:NO',
                   'owner_npub:text:NO',
                   'kind:text:NO',
                   'claimed_at:timestamp with time zone:NO'
               ]::TEXT[]
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'public_names'
    ), FALSE)
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('public_names_pkey', 'p'),
              ('public_names_kind_check', 'c'),
              ('public_names_claimed_at_check', 'c'),
              ('public_names_name_shape_check', 'c'),
              ('public_names_owner_shape_check', 'c'),
              ('public_names_shared_namespace_key', 'u'),
              ('public_names_owner_kind_lifetime_key', 'u')
          ) required(constraint_name, constraint_type)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_constraint constraint_info
              WHERE constraint_info.conrelid =
                    to_regclass('public.public_names')
                AND constraint_info.conname = required.constraint_name
                AND constraint_info.contype =
                    required.constraint_type::"char"
                AND constraint_info.convalidated
         )
    )
    -- Lightning Address availability remains independent from permanent-name
    -- ownership, but there can still be at most one active row per owner.
    AND EXISTS (
        SELECT 1
          FROM pg_index index_info
          JOIN pg_class index_relation ON index_relation.oid = index_info.indexrelid
         WHERE index_info.indrelid = to_regclass('public.users')
           AND index_relation.relname = 'users_npub_active_key'
           AND index_info.indisunique
           AND index_info.indisvalid
           AND index_info.indisready
           AND index_info.indnkeyatts = 1
           AND index_info.indnatts = 1
           AND ARRAY(
               SELECT attribute.attname::TEXT
                 FROM unnest(index_info.indkey) WITH ORDINALITY
                      AS key_column(attnum, position)
                 JOIN pg_attribute attribute
                   ON attribute.attrelid = index_info.indrelid
                  AND attribute.attnum = key_column.attnum
                ORDER BY key_column.position
           ) = ARRAY['npub']::TEXT[]
           AND pg_get_expr(index_info.indpred, index_info.indrelid)
               IN ('is_active', '(is_active = true)')
    )
    AND NOT EXISTS (
        SELECT 1
          FROM public_names AS aliases
         WHERE aliases.kind = 'alias'
           AND NOT EXISTS (
               SELECT 1
                FROM public_names AS nyms
                WHERE nyms.owner_npub = aliases.owner_npub
                  AND nyms.kind = 'nym'
           )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM users
         WHERE NOT EXISTS (
               SELECT 1
                 FROM public_names
                WHERE public_names.name = users.nym
                  AND public_names.owner_npub = users.npub
                  AND public_names.kind = 'nym'
           )
    )
    AND NOT EXISTS (
        SELECT 1 FROM donation_pages WHERE ct_descriptor IS NULL
    )
    AND EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'donation_pages'
           AND column_name = 'ct_descriptor'
           AND is_nullable = 'NO'
    )
    AND NOT EXISTS (
        SELECT 1
          FROM pg_attribute
         WHERE attrelid = to_regclass('public.donation_pages')
           AND attname IN ('alias', 'pos_mode')
           AND attnum > 0
           AND NOT attisdropped
    )
    AND to_regclass('public.donation_pages_alias_uidx') IS NULL
    AND to_regclass('public.public_name_migration_choices') IS NULL
    AND to_regclass('public.public_name_migration_merchant_communications') IS NULL
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('public_names', 'public_names_validate_insert',
                  'enforce_public_name_insert', 7),
              ('public_names', 'public_names_reject_mutation',
                  'reject_public_name_mutation', 27),
              ('users', 'users_require_permanent_nym',
                  'require_user_permanent_nym', 23)
          ) required(table_name, trigger_name, function_name, trigger_type)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_trigger trigger_info
               JOIN pg_class relation ON relation.oid = trigger_info.tgrelid
               JOIN pg_namespace relation_namespace
                 ON relation_namespace.oid = relation.relnamespace
               JOIN pg_proc function_info
                 ON function_info.oid = trigger_info.tgfoid
               JOIN pg_namespace function_namespace
                 ON function_namespace.oid = function_info.pronamespace
              WHERE relation_namespace.nspname = 'public'
                AND function_namespace.nspname = 'public'
                AND relation.relname = required.table_name
                AND trigger_info.tgname = required.trigger_name
                AND trigger_info.tgtype = required.trigger_type::SMALLINT
                AND NOT trigger_info.tgisinternal
                AND trigger_info.tgenabled = 'O'
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
         )
    )
    AND EXISTS (
        SELECT 1
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relname = 'public_names'
           AND relation.relkind = 'r'
           AND pg_get_userbyid(relation.relowner) <> current_user
           AND NOT pg_has_role(
               current_user, pg_get_userbyid(relation.relowner), 'USAGE'
           )
           AND NOT pg_has_role(
               current_user, pg_get_userbyid(relation.relowner), 'SET'
           )
           AND has_table_privilege(current_user, relation.oid, 'SELECT')
           AND NOT has_table_privilege(current_user, relation.oid, 'INSERT')
           AND NOT has_table_privilege(current_user, relation.oid, 'UPDATE')
           AND NOT has_table_privilege(current_user, relation.oid, 'DELETE')
           AND NOT has_table_privilege(current_user, relation.oid, 'TRUNCATE')
    )
    AND has_column_privilege(
        current_user, 'public.public_names', 'name', 'INSERT'
    )
    AND has_column_privilege(
        current_user, 'public.public_names', 'owner_npub', 'INSERT'
    )
    AND has_column_privilege(
        current_user, 'public.public_names', 'kind', 'INSERT'
    )
    AND NOT has_column_privilege(
        current_user, 'public.public_names', 'id', 'INSERT'
    )
    AND NOT has_column_privilege(
        current_user, 'public.public_names', 'claimed_at', 'INSERT'
    )
    AND NOT EXISTS (
        SELECT 1
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          CROSS JOIN LATERAL aclexplode(COALESCE(
              relation.relacl, acldefault('r', relation.relowner)
          )) acl
         WHERE namespace.nspname = 'public'
           AND relation.relname = 'public_names'
           AND acl.grantee = 0
    )
    AND NOT EXISTS (
        SELECT 1
          FROM pg_attribute attribute
          CROSS JOIN LATERAL aclexplode(COALESCE(
              attribute.attacl,
              acldefault('c', (
                  SELECT relowner FROM pg_class
                   WHERE oid = attribute.attrelid
              ))
          )) acl
         WHERE attribute.attrelid = to_regclass('public.public_names')
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
           AND acl.grantee = 0
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('enforce_public_name_insert'),
              ('reject_public_name_mutation'),
              ('require_user_permanent_nym')
          ) required(function_name)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_proc function_info
               JOIN pg_namespace namespace
                 ON namespace.oid = function_info.pronamespace
              WHERE namespace.nspname = 'public'
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
                AND function_info.prorettype = 'trigger'::REGTYPE
                AND pg_get_userbyid(function_info.proowner) <> current_user
                AND NOT pg_has_role(
                    current_user,
                    pg_get_userbyid(function_info.proowner),
                    'USAGE'
                )
                AND NOT pg_has_role(
                    current_user,
                    pg_get_userbyid(function_info.proowner),
                    'SET'
                )
                AND NOT has_function_privilege(
                    current_user, function_info.oid, 'EXECUTE'
                )
         )
    )
), FALSE)
"#;

type DirectLifecyclePrivileges = (
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
);

type WatcherLanePrivileges = (Option<bool>, Option<bool>, Option<bool>);
type SwapKeyLineagePrivileges = (Option<bool>, Option<bool>, Option<bool>);
type ChainSwapRecordPrivileges = (Option<bool>, Option<bool>, Option<bool>);
type RecoveryCommitmentPrivileges = (
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
);

#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    pub service: &'static str,
    pub ready: bool,
    pub expected_schema_marker: &'static str,
    pub database: ComponentStatus,
    pub schema: ComponentStatus,
}

#[derive(Debug, Serialize)]
pub struct ComponentStatus {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ComponentStatus {
    fn ok() -> Self {
        Self {
            ok: true,
            detail: None,
        }
    }

    fn error(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: Some(detail.into()),
        }
    }
}

pub async fn ready(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl IntoResponse {
    let database = check_database(&state.db).await;
    let schema = if database.ok {
        check_schema(&state.db).await
    } else {
        ComponentStatus::error("database unavailable")
    };
    let ready = database.ok && schema.ok;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(ReadinessResponse {
            service: "pay-service",
            ready,
            expected_schema_marker: EXPECTED_SCHEMA_MARKER,
            database,
            schema,
        }),
    )
}

async fn check_database(pool: &sqlx::PgPool) -> ComponentStatus {
    match timeout(
        READINESS_DB_TIMEOUT,
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool),
    )
    .await
    {
        Ok(Ok(1)) => ComponentStatus::ok(),
        Ok(Ok(_)) => ComponentStatus::error("unexpected database probe result"),
        Ok(Err(e)) => {
            tracing::warn!("readiness database probe failed: {e}");
            ComponentStatus::error("database probe failed")
        }
        Err(_) => ComponentStatus::error("database probe timed out"),
    }
}

async fn check_schema(pool: &sqlx::PgPool) -> ComponentStatus {
    match timeout(READINESS_DB_TIMEOUT, schema_and_journal_ready(pool)).await {
        Ok(Ok(true)) => ComponentStatus::ok(),
        Ok(Ok(false)) => ComponentStatus::error(format!(
            "expected schema marker {EXPECTED_SCHEMA_MARKER} is not present or a required durable journal is not writable"
        )),
        Ok(Err(e)) => {
            tracing::warn!("readiness schema probe failed: {e}");
            ComponentStatus::error("schema probe failed")
        }
        Err(_) => ComponentStatus::error("schema probe timed out"),
    }
}

/// Verify the complete current schema marker and the write privilege required
/// by the recovery journal. Normal startup treats this as a foundation; the
/// HTTP readiness endpoint reuses the same predicate so deploy and runtime
/// checks cannot drift.
pub async fn schema_and_journal_ready(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    if !schema_marker_present(pool).await?
        || !wallet_backup_storage_invariants_present(pool).await?
        || !private_invoice_storage_contract_present(pool).await?
        || !swap_key_lineage_invariants_present(pool).await?
        || !merchant_settlement_fee_schema_present(pool).await?
        || !merchant_settlement_trigger_invariants_present(pool).await?
        || !merchant_settlement_privileges_present(pool).await?
        || !chain_swap_renegotiation_invariants_present(pool).await?
        || !chain_swap_cooperative_signing_invariants_present(pool).await?
        || !permanent_public_name_invariants_present(pool).await?
        || !lnurl_private_comment_invariants_present(pool).await?
        || !invoice_quote_foundation_invariants_present(pool).await?
    {
        return Ok(false);
    }

    let privileges = sqlx::query_as::<_, (Option<bool>, Option<bool>, Option<bool>)>(
        "SELECT \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_tx_attempts'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_tx_attempts'), \
                'INSERT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_tx_attempts'), \
                'UPDATE' \
            )",
    )
    .fetch_one(pool)
    .await?;

    let direct_lifecycle_privileges = sqlx::query_as::<_, DirectLifecyclePrivileges>(
        "SELECT \
            has_table_privilege( \
                current_user, \
                to_regclass('public.invoice_direct_scan_heads'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.invoice_direct_scan_heads'), \
                'INSERT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.invoice_direct_scan_heads'), \
                'UPDATE' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.invoice_direct_payment_transitions'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.invoice_direct_payment_transitions'), \
                'INSERT' \
            )",
    )
    .fetch_one(pool)
    .await?;

    let watcher_lane_privileges = sqlx::query_as::<_, WatcherLanePrivileges>(
        "SELECT \
            has_table_privilege( \
                current_user, \
                to_regclass('public.watcher_lane_progress'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.watcher_lane_progress'), \
                'INSERT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.watcher_lane_progress'), \
                'UPDATE' \
            )",
    )
    .fetch_one(pool)
    .await?;

    let swap_key_lineage_privileges = sqlx::query_as::<_, SwapKeyLineagePrivileges>(
        "SELECT \
            has_table_privilege( \
                current_user, \
                to_regclass('public.swap_key_allocations'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.swap_key_allocations'), \
                'INSERT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.swap_key_legacy_high_water'), \
                'SELECT' \
            )",
    )
    .fetch_one(pool)
    .await?;

    let chain_swap_record_privileges = sqlx::query_as::<_, ChainSwapRecordPrivileges>(
        "SELECT \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_records'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_records'), \
                'INSERT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_records'), \
                'UPDATE' \
            )",
    )
    .fetch_one(pool)
    .await?;

    Ok(journal_privileges_ready(privileges)
        && direct_lifecycle_privileges_ready(direct_lifecycle_privileges)
        && watcher_lane_privileges_ready(watcher_lane_privileges)
        && swap_key_lineage_privileges_ready(swap_key_lineage_privileges)
        && chain_swap_record_privileges_ready(chain_swap_record_privileges))
}

async fn wallet_backup_storage_invariants_present(
    pool: &sqlx::PgPool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT \
            to_regclass('public.wallet_backup_blobs') IS NOT NULL \
            AND NOT EXISTS ( \
                SELECT 1 FROM (VALUES \
                    ('stream', 'text'::REGTYPE, 1, TRUE, FALSE), \
                    ('author_pubkey', 'bytea'::REGTYPE, 2, TRUE, FALSE), \
                    ('generation', 'int8'::REGTYPE, 3, TRUE, FALSE), \
                    ('etag', 'bytea'::REGTYPE, 4, TRUE, FALSE), \
                    ('ciphertext', 'bytea'::REGTYPE, 5, FALSE, FALSE), \
                    ('ciphertext_sha256', 'bytea'::REGTYPE, 6, FALSE, FALSE), \
                    ('ciphertext_bytes', 'int4'::REGTYPE, 7, FALSE, FALSE), \
                    ('created_at', 'timestamptz'::REGTYPE, 8, TRUE, TRUE), \
                    ('updated_at', 'timestamptz'::REGTYPE, 9, TRUE, TRUE), \
                    ('deleted_at', 'timestamptz'::REGTYPE, 10, FALSE, FALSE) \
                ) required(column_name, type_oid, ordinal, not_null, has_default) \
                 WHERE NOT EXISTS ( \
                    SELECT 1 FROM pg_attribute attribute_info \
                     WHERE attribute_info.attrelid = \
                               to_regclass('public.wallet_backup_blobs') \
                       AND attribute_info.attname = required.column_name \
                       AND attribute_info.atttypid = required.type_oid \
                       AND attribute_info.attnum = required.ordinal \
                       AND attribute_info.attnotnull = required.not_null \
                       AND attribute_info.atthasdef = required.has_default \
                       AND NOT attribute_info.attisdropped \
                 ) \
            ) \
            AND ( \
                SELECT COUNT(*) FROM pg_attribute attribute_info \
                 WHERE attribute_info.attrelid = \
                           to_regclass('public.wallet_backup_blobs') \
                   AND attribute_info.attnum > 0 \
                   AND NOT attribute_info.attisdropped \
            ) = 10 \
            AND NOT EXISTS ( \
                SELECT 1 FROM (VALUES \
                    ('wallet_backup_blobs_pkey', 'p'), \
                    ('wallet_backup_blobs_generation_positive_chk', 'c'), \
                    ('wallet_backup_blobs_stream_chk', 'c'), \
                    ('wallet_backup_blobs_author_pubkey_len_chk', 'c'), \
                    ('wallet_backup_blobs_etag_len_chk', 'c'), \
                    ('wallet_backup_blobs_live_tombstone_chk', 'c'), \
                    ('wallet_backup_blobs_payload_columns_chk', 'c'), \
                    ('wallet_backup_blobs_hash_len_chk', 'c'), \
                    ('wallet_backup_blobs_size_matches_chk', 'c'), \
                    ('wallet_backup_blobs_size_limit_chk', 'c') \
                ) required(constraint_name, constraint_type) \
                 WHERE NOT EXISTS ( \
                    SELECT 1 FROM pg_constraint constraint_info \
                     WHERE constraint_info.conrelid = \
                               to_regclass('public.wallet_backup_blobs') \
                       AND constraint_info.conname = required.constraint_name \
                       AND constraint_info.contype = required.constraint_type::\"char\" \
                       AND constraint_info.convalidated \
                 ) \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_indexes \
                 WHERE schemaname = 'public' \
                   AND tablename = 'wallet_backup_blobs' \
                   AND indexname = 'wallet_backup_blobs_tombstone_cleanup_idx' \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                  FROM pg_class relation \
                  CROSS JOIN LATERAL aclexplode(COALESCE( \
                      relation.relacl, acldefault('r', relation.relowner) \
                  )) acl \
                 WHERE relation.oid = to_regclass('public.wallet_backup_blobs') \
                   AND acl.grantee = 0 \
            ) \
            AND pg_get_userbyid( \
                (SELECT relowner FROM pg_class \
                  WHERE oid = to_regclass('public.wallet_backup_blobs')) \
            ) <> current_user \
            AND NOT pg_has_role( \
                current_user, \
                pg_get_userbyid( \
                    (SELECT relowner FROM pg_class \
                      WHERE oid = to_regclass('public.wallet_backup_blobs')) \
                ), \
                'USAGE' \
            ) \
            AND NOT pg_has_role( \
                current_user, \
                pg_get_userbyid( \
                    (SELECT relowner FROM pg_class \
                      WHERE oid = to_regclass('public.wallet_backup_blobs')) \
                ), \
                'SET' \
            ) \
            AND has_table_privilege( \
                current_user, to_regclass('public.wallet_backup_blobs'), 'SELECT' \
            ) \
            AND has_table_privilege( \
                current_user, to_regclass('public.wallet_backup_blobs'), 'INSERT' \
            ) \
            AND has_table_privilege( \
                current_user, to_regclass('public.wallet_backup_blobs'), 'UPDATE' \
            ) \
            AND has_table_privilege( \
                current_user, to_regclass('public.wallet_backup_blobs'), 'DELETE' \
            ) \
            AND NOT has_table_privilege( \
                current_user, to_regclass('public.wallet_backup_blobs'), 'TRUNCATE' \
            ) \
            AND NOT has_table_privilege( \
                current_user, to_regclass('public.wallet_backup_blobs'), 'REFERENCES' \
            ) \
            AND NOT has_table_privilege( \
                current_user, to_regclass('public.wallet_backup_blobs'), 'TRIGGER' \
            )",
    )
    .fetch_one(pool)
    .await
}

async fn private_invoice_storage_contract_present(
    pool: &sqlx::PgPool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT \
            NOT EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = 'invoices' \
                   AND column_name IN ( \
                       'recipient_label', 'public_description', 'invoice_number' \
                   ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 FROM (VALUES \
                    ('client_request_id', 'uuid'), \
                    ('client_request_digest', 'bytea'), \
                    ('presentation_envelope', 'bytea') \
                ) required(column_name, data_type) \
                WHERE NOT EXISTS ( \
                    SELECT 1 FROM information_schema.columns column_info \
                     WHERE column_info.table_schema = 'public' \
                       AND column_info.table_name = 'invoices' \
                       AND column_info.column_name = required.column_name \
                       AND column_info.data_type = required.data_type \
                       AND column_info.is_nullable = 'YES' \
                ) \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint constraint_info \
                 WHERE constraint_info.conrelid = to_regclass('public.invoices') \
                   AND constraint_info.conname = \
                       'invoices_private_presentation_shape_check' \
                   AND constraint_info.contype = 'c' \
                   AND constraint_info.convalidated \
                   AND regexp_replace( \
                       pg_get_expr( \
                           constraint_info.conbin, constraint_info.conrelid, TRUE \
                       ), '[[:space:]]+', '', 'g' \
                   ) = $1 \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint constraint_info \
                 WHERE constraint_info.conrelid = to_regclass('public.invoices') \
                   AND constraint_info.conname = 'invoices_owner_client_request_key' \
                   AND constraint_info.contype = 'u' \
                   AND constraint_info.convalidated \
                   AND constraint_info.conkey = ARRAY[ \
                       (SELECT attribute_info.attnum::SMALLINT \
                          FROM pg_attribute attribute_info \
                         WHERE attribute_info.attrelid = \
                                   to_regclass('public.invoices') \
                           AND attribute_info.attname = 'npub_owner'), \
                       (SELECT attribute_info.attnum::SMALLINT \
                          FROM pg_attribute attribute_info \
                         WHERE attribute_info.attrelid = \
                                   to_regclass('public.invoices') \
                           AND attribute_info.attname = 'client_request_id') \
                   ]::SMALLINT[] \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                  FROM pg_trigger trigger_info \
                  JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid \
                  JOIN pg_namespace function_namespace \
                    ON function_namespace.oid = function_info.pronamespace \
                 WHERE trigger_info.tgrelid = to_regclass('public.invoices') \
                   AND trigger_info.tgname = \
                       'invoices_reject_private_presentation_update' \
                   AND trigger_info.tgtype = 19 \
                   AND trigger_info.tgenabled = 'O' \
                   AND NOT trigger_info.tgisinternal \
                   AND function_namespace.nspname = 'public' \
                   AND function_info.proname = \
                       'reject_invoice_private_presentation_update' \
                   AND function_info.pronargs = 0 \
                   AND function_info.prorettype = 'trigger'::REGTYPE \
                   AND NOT function_info.prosecdef \
                   AND function_info.proconfig = ARRAY['search_path=pg_catalog'] \
                   AND regexp_replace( \
                       pg_get_triggerdef(trigger_info.oid, TRUE), \
                       '[[:space:]]+', '', 'g' \
                   ) = $2 \
                   AND encode( \
                       sha256(convert_to(function_info.prosrc, 'UTF8')), 'hex' \
                   ) = $3 \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM aclexplode(COALESCE( \
                           function_info.proacl, \
                           acldefault('f', function_info.proowner) \
                       )) acl \
                        WHERE acl.grantee = 0 \
                          AND acl.privilege_type = 'EXECUTE' \
                   ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                  FROM pg_index index_info \
                  JOIN pg_attribute attribute_info \
                    ON attribute_info.attrelid = index_info.indrelid \
                   AND attribute_info.attnum = ANY(index_info.indkey) \
                 WHERE index_info.indrelid = to_regclass('public.invoices') \
                   AND attribute_info.attname = 'presentation_envelope' \
            )",
    )
    .bind(EXPECTED_PRIVATE_INVOICE_SHAPE_EXPRESSION)
    .bind(EXPECTED_PRIVATE_INVOICE_TRIGGER_DEFINITION)
    .bind(EXPECTED_PRIVATE_INVOICE_TRIGGER_BODY_SHA256)
    .fetch_one(pool)
    .await
}

async fn merchant_settlement_privileges_present(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(MERCHANT_SETTLEMENT_PRIVILEGES_SQL)
        .fetch_one(pool)
        .await
}

async fn merchant_settlement_fee_schema_present(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(MERCHANT_SETTLEMENT_FEE_SCHEMA_SQL)
        .bind(EXPECTED_MERCHANT_SETTLEMENT_FEE_SHAPE_EXPRESSION)
        .bind(EXPECTED_MERCHANT_SETTLEMENT_FEE_VALUE_EXPRESSION)
        .fetch_one(pool)
        .await
}

async fn merchant_settlement_trigger_invariants_present(
    pool: &sqlx::PgPool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL)
        .fetch_one(pool)
        .await
}

async fn chain_swap_renegotiation_invariants_present(
    pool: &sqlx::PgPool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(CHAIN_SWAP_RENEGOTIATION_INVARIANTS_SQL)
        .fetch_one(pool)
        .await
}

async fn chain_swap_cooperative_signing_invariants_present(
    pool: &sqlx::PgPool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(CHAIN_SWAP_COOPERATIVE_SIGNING_INVARIANTS_SQL)
        .fetch_one(pool)
        .await
}

async fn lnurl_private_comment_invariants_present(
    pool: &sqlx::PgPool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT \
            to_regclass('public.lnurl_comment_intents') IS NOT NULL \
            AND ( \
                SELECT COUNT(*) FROM information_schema.columns \
                 WHERE table_schema = 'public' \
                   AND table_name = 'lnurl_comment_intents' \
                   AND column_name IN ( \
                       'intent_id', 'owner_npub', 'nym', 'idempotency_key', \
                       'amount_msat', 'comment', 'comment_grapheme_count', \
                       'instruction_rail', 'instruction_reference', \
                       'payment_evidence_reference', 'created_at', \
                       'instruction_bound_at', 'payment_evidenced_at' \
                   ) \
            ) = 13 \
            AND NOT EXISTS ( \
                SELECT 1 FROM (VALUES \
                    ('lnurl_comment_intents_pkey', 'p'), \
                    ('lnurl_comment_intents_id_non_nil_check', 'c'), \
                    ('lnurl_comment_intents_owner_shape_check', 'c'), \
                    ('lnurl_comment_intents_nym_shape_check', 'c'), \
                    ('lnurl_comment_intents_idempotency_shape_check', 'c'), \
                    ('lnurl_comment_intents_amount_check', 'c'), \
                    ('lnurl_comment_intents_grapheme_count_check', 'c'), \
                    ('lnurl_comment_intents_comment_bytes_check', 'c'), \
                    ('lnurl_comment_intents_instruction_rail_check', 'c'), \
                    ('lnurl_comment_intents_instruction_shape_check', 'c'), \
                    ('lnurl_comment_intents_evidence_shape_check', 'c'), \
                    ('lnurl_comment_intents_owner_idempotency_key', 'u'), \
                    ('lnurl_comment_intents_instruction_once_key', 'u'), \
                    ('lnurl_comment_intents_payment_evidence_once_key', 'u') \
                ) required(constraint_name, constraint_type) \
                 WHERE NOT EXISTS ( \
                    SELECT 1 \
                      FROM pg_constraint constraint_info \
                     WHERE constraint_info.conrelid = \
                               to_regclass('public.lnurl_comment_intents') \
                       AND constraint_info.conname = required.constraint_name \
                       AND constraint_info.contype = required.constraint_type::\"char\" \
                       AND constraint_info.convalidated \
                 ) \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_indexes \
                 WHERE schemaname = 'public' \
                   AND tablename = 'lnurl_comment_intents' \
                   AND indexname = 'lnurl_comment_intents_received_history_idx' \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 FROM (VALUES \
                    ('lnurl_comment_intents_enforce_write', \
                     'enforce_lnurl_comment_intent_write', 23), \
                    ('lnurl_comment_intents_reject_delete', \
                     'reject_lnurl_comment_intent_delete', 11) \
                ) required(trigger_name, function_name, trigger_type) \
                 WHERE NOT EXISTS ( \
                    SELECT 1 \
                      FROM pg_trigger trigger_info \
                      JOIN pg_proc function_info \
                        ON function_info.oid = trigger_info.tgfoid \
                     WHERE trigger_info.tgrelid = \
                               to_regclass('public.lnurl_comment_intents') \
                       AND trigger_info.tgname = required.trigger_name \
                       AND function_info.proname = required.function_name \
                       AND trigger_info.tgtype = required.trigger_type::SMALLINT \
                       AND NOT trigger_info.tgisinternal \
                       AND trigger_info.tgenabled = 'O' \
                 ) \
            ) \
            AND pg_get_userbyid( \
                (SELECT relowner FROM pg_class \
                  WHERE oid = to_regclass('public.lnurl_comment_intents')) \
            ) <> current_user \
            AND NOT pg_has_role( \
                current_user, \
                pg_get_userbyid( \
                    (SELECT relowner FROM pg_class \
                      WHERE oid = to_regclass('public.lnurl_comment_intents')) \
                ), \
                'USAGE' \
            ) \
            AND NOT pg_has_role( \
                current_user, \
                pg_get_userbyid( \
                    (SELECT relowner FROM pg_class \
                      WHERE oid = to_regclass('public.lnurl_comment_intents')) \
                ), \
                'SET' \
            ) \
            AND has_table_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), 'SELECT' \
            ) \
            AND NOT has_table_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), 'INSERT' \
            ) \
            AND NOT has_table_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), 'UPDATE' \
            ) \
            AND NOT has_table_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), 'DELETE' \
            ) \
            AND NOT has_table_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), 'TRUNCATE' \
            ) \
            AND NOT has_table_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), 'REFERENCES' \
            ) \
            AND NOT has_table_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), 'TRIGGER' \
            ) \
            AND has_column_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), \
                'comment', 'INSERT' \
            ) \
            AND NOT has_column_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), \
                'comment', 'UPDATE' \
            ) \
            AND has_column_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), \
                'instruction_reference', 'UPDATE' \
            ) \
            AND has_column_privilege( \
                current_user, to_regclass('public.lnurl_comment_intents'), \
                'payment_evidence_reference', 'UPDATE' \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                  FROM pg_class relation \
                  CROSS JOIN LATERAL aclexplode(COALESCE( \
                      relation.relacl, acldefault('r', relation.relowner) \
                  )) acl \
                 WHERE relation.oid = to_regclass('public.lnurl_comment_intents') \
                   AND acl.grantee = 0 \
            )",
    )
    .fetch_one(pool)
    .await
}

async fn invoice_quote_foundation_invariants_present(
    pool: &sqlx::PgPool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT COALESCE(( \
            to_regclass('public.invoice_quote_versions') IS NOT NULL \
            AND to_regclass('public.invoice_quote_offers') IS NOT NULL \
            AND to_regclass('public.invoice_quote_provider_attempts') IS NOT NULL \
            AND to_regclass('public.invoice_quote_provider_dispatches') IS NOT NULL \
            AND to_regclass('public.invoice_quote_provider_completions') IS NOT NULL \
            AND to_regclass('public.invoice_quote_provider_integrity_holds') IS NOT NULL \
            AND to_regclass('public.invoice_quote_active_fiat_projection') IS NOT NULL \
            AND to_regclass('public.invoice_quote_versions_late_valuation_snapshot_key') IS NOT NULL \
            AND to_regprocedure('public.invoice_quote_credit_for_sats(integer,bigint,bigint,bigint)') IS NOT NULL \
            AND NOT EXISTS ( \
                SELECT 1 FROM (VALUES \
                    ('invoices', 'invoices_pricing_amount_authority_check', 'c'), \
                    ('invoices', 'invoices_checkout_surface_kind_check', 'c'), \
                    ('invoice_quote_versions', 'invoice_quote_versions_pkey', 'p'), \
                    ('invoice_quote_versions', 'invoice_quote_versions_invoice_number_key', 'u'), \
                    ('invoice_quote_versions', 'invoice_quote_versions_window_check', 'c'), \
                    ('invoice_quote_versions', 'invoice_quote_versions_purpose_check', 'c'), \
                    ('invoice_quote_versions', 'invoice_quote_versions_late_instruction_fkey', 'f'), \
                    ('invoice_quote_versions', 'invoice_quote_versions_fiat_target_check', 'c'), \
                    ('invoice_quote_offers', 'invoice_quote_offers_pkey', 'p'), \
                    ('invoice_quote_offers', 'invoice_quote_offers_request_key', 'u'), \
                    ('invoice_quote_offers', 'invoice_quote_offers_quote_invoice_fkey', 'f'), \
                    ('invoice_quote_offers', 'invoice_quote_offers_rail_kind_check', 'c'), \
                    ('invoice_quote_offers', 'invoice_quote_offers_provider_shape_check', 'c'), \
                    ('invoice_quote_provider_attempts', 'invoice_quote_provider_attempts_pkey', 'p'), \
                    ('invoice_quote_provider_attempts', 'invoice_quote_provider_attempts_identity_key', 'u'), \
                    ('invoice_quote_provider_attempts', 'invoice_quote_provider_attempts_quote_invoice_fkey', 'f'), \
                    ('invoice_quote_provider_attempts', 'invoice_quote_provider_attempts_shape_check', 'c'), \
                    ('invoice_quote_provider_attempts', 'invoice_quote_provider_attempts_authority_check', 'c'), \
                    ('invoice_quote_provider_dispatches', 'invoice_quote_provider_dispatches_pkey', 'p'), \
                    ('invoice_quote_provider_dispatches', 'invoice_quote_provider_dispatches_provider_attempt_id_fkey', 'f'), \
                    ('invoice_quote_provider_dispatches', 'invoice_quote_provider_dispatches_digest_check', 'c'), \
                    ('invoice_quote_provider_completions', 'invoice_quote_provider_completions_pkey', 'p'), \
                    ('invoice_quote_provider_completions', 'invoice_quote_provider_completions_provider_attempt_id_fkey', 'f'), \
                    ('invoice_quote_provider_completions', 'invoice_quote_provider_completions_quote_offer_id_fkey', 'f'), \
                    ('invoice_quote_provider_completions', 'invoice_quote_provider_completions_quote_offer_id_key', 'u'), \
                    ('invoice_quote_provider_completions', 'invoice_quote_provider_completions_digest_check', 'c'), \
                    ('invoice_quote_provider_completions', 'invoice_quote_provider_completions_provider_id_check', 'c'), \
                    ('invoice_quote_provider_integrity_holds', 'invoice_quote_provider_integrity_holds_pkey', 'p'), \
                    ('invoice_quote_provider_integrity_holds', 'invoice_quote_provider_integrity_holds_provider_attempt_id_fkey', 'f'), \
                    ('invoice_quote_provider_integrity_holds', 'invoice_quote_provider_integrity_holds_reason_check', 'c'), \
                    ('invoice_quote_offers', 'invoice_quote_offers_provider_attempt_shape_check', 'c'), \
                    ('invoice_quote_offers', 'invoice_quote_offers_provider_attempt_fkey', 'f'), \
                    ('swap_records', 'swap_records_invoice_quote_shape_check', 'c'), \
                    ('swap_records', 'swap_records_invoice_quote_offer_fkey', 'f'), \
                    ('chain_swap_records', 'chain_swap_records_invoice_quote_shape_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_invoice_quote_offer_fkey', 'f'), \
                    ('invoice_payment_events', 'invoice_payment_events_quote_attribution_shape_check', 'c'), \
                    ('invoice_payment_events', 'invoice_payment_events_fiat_valuation_policy_check', 'c'), \
                    ('invoice_payment_events', 'invoice_payment_events_fiat_valuation_quote_fkey', 'f'), \
                    ('invoice_payment_events', 'invoice_payment_events_quote_offer_fkey', 'f') \
                ) required(table_name, constraint_name, constraint_type) \
                 WHERE NOT EXISTS ( \
                    SELECT 1 \
                      FROM pg_constraint constraint_info \
                     WHERE constraint_info.conrelid = \
                               to_regclass('public.' || required.table_name) \
                       AND constraint_info.conname = required.constraint_name \
                       AND constraint_info.contype = required.constraint_type::\"char\" \
                       AND constraint_info.convalidated \
                 ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 FROM (VALUES \
                    ('invoice_quote_versions', 'invoice_quote_versions_enforce_insert', \
                     'enforce_invoice_quote_version_insert', 7), \
                    ('invoice_quote_versions', 'invoice_quote_versions_reject_update', \
                     'reject_invoice_quote_version_mutation', 19), \
                    ('invoice_quote_versions', 'invoice_quote_versions_reject_delete', \
                     'reject_invoice_quote_version_mutation', 11), \
                    ('invoice_quote_offers', 'invoice_quote_offers_enforce_insert', \
                     'enforce_invoice_quote_offer_insert', 7), \
                    ('invoice_quote_offers', 'invoice_quote_offers_reject_update', \
                     'reject_invoice_quote_offer_mutation', 19), \
                    ('invoice_quote_offers', 'invoice_quote_offers_reject_delete', \
                     'reject_invoice_quote_offer_mutation', 11), \
                    ('invoice_quote_provider_attempts', 'invoice_quote_provider_attempts_enforce_insert', \
                     'enforce_invoice_quote_provider_attempt_insert', 7), \
                    ('invoice_quote_provider_attempts', 'invoice_quote_provider_attempts_reject_update', \
                     'reject_invoice_quote_provider_attempt_mutation', 19), \
                    ('invoice_quote_provider_attempts', 'invoice_quote_provider_attempts_reject_delete', \
                     'reject_invoice_quote_provider_attempt_mutation', 11), \
                    ('invoice_quote_offers', 'invoice_quote_offers_enforce_attempt_binding', \
                     'enforce_invoice_quote_offer_attempt_binding', 7), \
                    ('invoice_quote_provider_dispatches', 'invoice_quote_provider_dispatches_enforce_insert', \
                     'enforce_invoice_quote_provider_dispatch_insert', 7), \
                    ('invoice_quote_provider_completions', 'invoice_quote_provider_completions_enforce_insert', \
                     'enforce_invoice_quote_provider_completion_insert', 7), \
                    ('invoice_quote_provider_integrity_holds', 'invoice_quote_provider_integrity_holds_enforce_insert', \
                     'enforce_invoice_quote_provider_hold_insert', 7), \
                    ('invoice_quote_provider_dispatches', 'invoice_quote_provider_dispatches_reject_update', \
                     'reject_invoice_quote_provider_attempt_mutation', 27), \
                    ('invoice_quote_provider_completions', 'invoice_quote_provider_completions_reject_update', \
                     'reject_invoice_quote_provider_attempt_mutation', 27), \
                    ('invoice_quote_provider_integrity_holds', 'invoice_quote_provider_integrity_holds_reject_update', \
                     'reject_invoice_quote_provider_attempt_mutation', 27), \
                    ('invoice_quote_offers', 'invoice_quote_offers_require_provider_completion', \
                     'require_invoice_quote_provider_completion', 5), \
                    ('swap_records', 'swap_records_guard_quote_attribution', \
                     'guard_swap_quote_attribution', 19), \
                    ('chain_swap_records', 'chain_swap_records_guard_quote_attribution', \
                     'guard_swap_quote_attribution', 19), \
                    ('swap_records', 'swap_records_stamp_quote_payment_first_observed', \
                     'stamp_quote_payment_first_observed', 23), \
                    ('chain_swap_records', 'chain_swap_records_stamp_quote_payment_first_observed', \
                     'stamp_quote_payment_first_observed', 23), \
                    ('invoice_payment_events', 'invoice_payment_events_guard_quote_attribution', \
                     'guard_invoice_payment_quote_attribution', 23) \
                ) required(table_name, trigger_name, function_name, trigger_type) \
                 WHERE NOT EXISTS ( \
                    SELECT 1 \
                      FROM pg_trigger trigger_info \
                      JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid \
                     WHERE trigger_info.tgrelid = \
                               to_regclass('public.' || required.table_name) \
                       AND trigger_info.tgname = required.trigger_name \
                       AND function_info.proname = required.function_name \
                       AND trigger_info.tgtype = required.trigger_type::SMALLINT \
                       AND NOT trigger_info.tgisinternal \
                       AND trigger_info.tgenabled = 'O' \
                 ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 FROM (VALUES \
                    ('invoices', 'checkout_surface_kind'), \
                    ('invoice_quote_versions', 'quote_purpose'), \
                    ('invoice_quote_versions', 'late_instruction_quote_version_id'), \
                    ('invoice_quote_versions', 'late_observation_at'), \
                    ('invoice_quote_versions', 'fiat_target_amount_minor'), \
                    ('invoice_quote_offers', 'provider_attempt_id'), \
                    ('invoice_quote_provider_attempts', 'request_authority_json'), \
                    ('invoice_quote_provider_attempts', 'request_authority_sha256'), \
                    ('swap_records', 'invoice_quote_version_id'), \
                    ('swap_records', 'invoice_quote_offer_id'), \
                    ('swap_records', 'quote_payment_first_observed_at'), \
                    ('chain_swap_records', 'invoice_quote_version_id'), \
                    ('chain_swap_records', 'invoice_quote_offer_id'), \
                    ('chain_swap_records', 'quote_payment_first_observed_at'), \
                    ('invoice_payment_events', 'invoice_quote_version_id'), \
                    ('invoice_payment_events', 'invoice_quote_offer_id'), \
                    ('invoice_payment_events', 'quote_first_observed_at'), \
                    ('invoice_payment_events', 'fiat_credited_minor'), \
                    ('invoice_payment_events', 'fiat_credit_policy'), \
                    ('invoice_payment_events', 'fiat_valued_at'), \
                    ('invoice_payment_events', 'fiat_valuation_quote_version_id'), \
                    ('invoice_payment_events', 'fiat_rate_minor_per_btc'), \
                    ('invoice_payment_events', 'fiat_rate_source'), \
                    ('invoice_payment_events', 'fiat_rate_observed_at'), \
                    ('invoice_payment_events', 'fiat_rate_fetched_at'), \
                    ('invoice_payment_events', 'fiat_rate_fresh_until') \
                ) required(table_name, column_name) \
                 WHERE NOT EXISTS ( \
                    SELECT 1 FROM information_schema.columns \
                     WHERE table_schema = 'public' \
                       AND information_schema.columns.table_name = required.table_name \
                       AND information_schema.columns.column_name = required.column_name \
                 ) \
            ) \
            AND pg_get_userbyid(( \
                SELECT relowner FROM pg_class \
                 WHERE oid = to_regclass('public.invoice_quote_versions') \
            )) <> current_user \
            AND NOT pg_has_role(current_user, pg_get_userbyid(( \
                SELECT relowner FROM pg_class \
                 WHERE oid = to_regclass('public.invoice_quote_versions') \
            )), 'USAGE') \
            AND NOT pg_has_role(current_user, pg_get_userbyid(( \
                SELECT relowner FROM pg_class \
                 WHERE oid = to_regclass('public.invoice_quote_versions') \
            )), 'SET') \
            AND has_column_privilege(current_user, 'public.invoices', 'checkout_surface_kind', 'INSERT') \
            AND has_table_privilege(current_user, 'public.invoice_quote_versions', 'SELECT') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_versions', 'UPDATE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_versions', 'DELETE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_versions', 'TRUNCATE') \
            AND has_column_privilege(current_user, 'public.invoice_quote_versions', 'invoice_id', 'INSERT') \
            AND has_column_privilege(current_user, 'public.invoice_quote_versions', 'fiat_target_amount_minor', 'INSERT') \
            AND has_column_privilege(current_user, 'public.invoice_quote_versions', 'quote_purpose', 'INSERT') \
            AND has_column_privilege(current_user, 'public.invoice_quote_versions', 'late_instruction_quote_version_id', 'INSERT') \
            AND has_column_privilege(current_user, 'public.invoice_quote_versions', 'late_observation_at', 'INSERT') \
            AND NOT has_column_privilege(current_user, 'public.invoice_quote_versions', 'version_number', 'INSERT') \
            AND NOT has_column_privilege(current_user, 'public.invoice_quote_versions', 'created_at', 'INSERT') \
            AND has_table_privilege(current_user, 'public.invoice_quote_offers', 'SELECT') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_offers', 'UPDATE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_offers', 'DELETE') \
            AND has_column_privilege(current_user, 'public.invoice_quote_offers', 'request_key', 'INSERT') \
            AND NOT has_column_privilege(current_user, 'public.invoice_quote_offers', 'created_at', 'INSERT') \
            AND has_column_privilege(current_user, 'public.invoice_quote_offers', 'provider_attempt_id', 'INSERT') \
            AND has_table_privilege(current_user, 'public.invoice_quote_active_fiat_projection', 'SELECT') \
            AND has_function_privilege(current_user, 'public.invoice_quote_credit_for_sats(integer,bigint,bigint,bigint)', 'EXECUTE') \
            AND has_table_privilege(current_user, 'public.invoice_quote_provider_attempts', 'SELECT') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_attempts', 'UPDATE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_attempts', 'DELETE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_attempts', 'TRUNCATE') \
            AND has_column_privilege(current_user, 'public.invoice_quote_provider_attempts', 'request_key', 'INSERT') \
            AND has_column_privilege(current_user, 'public.invoice_quote_provider_attempts', 'request_authority_json', 'INSERT') \
            AND has_column_privilege(current_user, 'public.invoice_quote_provider_attempts', 'request_authority_sha256', 'INSERT') \
            AND NOT has_column_privilege(current_user, 'public.invoice_quote_provider_attempts', 'created_at', 'INSERT') \
            AND has_table_privilege(current_user, 'public.invoice_quote_provider_dispatches', 'SELECT') \
            AND has_column_privilege(current_user, 'public.invoice_quote_provider_dispatches', 'provider_attempt_id', 'INSERT') \
            AND NOT has_column_privilege(current_user, 'public.invoice_quote_provider_dispatches', 'dispatched_at', 'INSERT') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_dispatches', 'UPDATE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_dispatches', 'DELETE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_dispatches', 'TRUNCATE') \
            AND has_table_privilege(current_user, 'public.invoice_quote_provider_completions', 'SELECT') \
            AND has_column_privilege(current_user, 'public.invoice_quote_provider_completions', 'provider_attempt_id', 'INSERT') \
            AND NOT has_column_privilege(current_user, 'public.invoice_quote_provider_completions', 'completed_at', 'INSERT') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_completions', 'UPDATE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_completions', 'DELETE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_completions', 'TRUNCATE') \
            AND has_table_privilege(current_user, 'public.invoice_quote_provider_integrity_holds', 'SELECT') \
            AND has_column_privilege(current_user, 'public.invoice_quote_provider_integrity_holds', 'provider_attempt_id', 'INSERT') \
            AND NOT has_column_privilege(current_user, 'public.invoice_quote_provider_integrity_holds', 'held_at', 'INSERT') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_integrity_holds', 'UPDATE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_integrity_holds', 'DELETE') \
            AND NOT has_table_privilege(current_user, 'public.invoice_quote_provider_integrity_holds', 'TRUNCATE') \
            AND NOT EXISTS ( \
                SELECT 1 FROM pg_class relation \
                CROSS JOIN LATERAL aclexplode(COALESCE( \
                    relation.relacl, acldefault('r', relation.relowner) \
                )) acl \
                WHERE relation.oid IN ( \
                    to_regclass('public.invoice_quote_versions'), \
                    to_regclass('public.invoice_quote_offers'), \
                    to_regclass('public.invoice_quote_provider_attempts'), \
                    to_regclass('public.invoice_quote_provider_dispatches'), \
                    to_regclass('public.invoice_quote_provider_completions'), \
                    to_regclass('public.invoice_quote_provider_integrity_holds'), \
                    to_regclass('public.invoice_quote_active_fiat_projection') \
                ) AND acl.grantee = 0 \
            ) \
        ), FALSE)"
    )
    .fetch_one(pool)
    .await
}

async fn permanent_public_name_invariants_present(
    pool: &sqlx::PgPool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(PERMANENT_PUBLIC_NAME_INVARIANTS_SQL)
        .fetch_one(pool)
        .await
}

/// Global #84 capability boundary. This does not assert that any particular
/// merchant has registered a policy; creation performs that separate lookup.
/// It proves that the current runtime role has append/read-only ledger rights,
/// PUBLIC has no table ACL, and PostgreSQL will bind every new chain swap to
/// one immutable ID/address pair.
pub async fn recovery_commitment_ready(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    if !recovery_commitment_invariants_present(pool).await? {
        return Ok(false);
    }

    let privileges = sqlx::query_as::<_, RecoveryCommitmentPrivileges>(
        "SELECT \
            (SELECT pg_get_userbyid(relation.relowner) <> current_user \
               FROM pg_class relation \
               JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
              WHERE namespace.nspname = 'public' \
                AND relation.relname = 'recovery_address_commitments'), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'SELECT' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'INSERT' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'UPDATE' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'DELETE' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'TRUNCATE' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'REFERENCES' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'TRIGGER' \
            )",
    )
    .fetch_one(pool)
    .await?;

    Ok(recovery_commitment_privileges_ready(privileges))
}

/// Inspect the exact migration-053 contract rather than trusting a table-name
/// marker. Column types/nullability, constraints, ordered FK columns, actions,
/// trigger functions/events, and PUBLIC ACL state all fail closed.
async fn recovery_commitment_invariants_present(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT \
            NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('recovery_address_commitments', 'commitment_id', 'uuid', FALSE), \
                    ('recovery_address_commitments', 'npub', 'text', FALSE), \
                    ('recovery_address_commitments', 'contract_format_version', 'int2', FALSE), \
                    ('recovery_address_commitments', 'commitment_version', 'int8', FALSE), \
                    ('recovery_address_commitments', 'canonical_btc_address', 'text', FALSE), \
                    ('recovery_address_commitments', 'original_signature', 'text', FALSE), \
                    ('recovery_address_commitments', 'signed_at_unix', 'int8', FALSE), \
                    ('recovery_address_commitments', 'registered_at', 'timestamptz', FALSE), \
                    ('chain_swap_records', 'recovery_address_commitment_id', 'uuid', TRUE), \
                    ('chain_swap_records', 'merchant_emergency_btc_address', 'text', TRUE) \
                ) AS required(table_name, column_name, type_name, is_nullable) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_attribute attribute \
                    JOIN pg_class relation ON relation.oid = attribute.attrelid \
                    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                    JOIN pg_type column_type ON column_type.oid = attribute.atttypid \
                    WHERE namespace.nspname = 'public' \
                      AND relation.relname = required.table_name \
                      AND attribute.attname = required.column_name \
                      AND column_type.typname = required.type_name \
                      AND NOT attribute.attisdropped \
                      AND attribute.attnum > 0 \
                      AND (NOT attribute.attnotnull) = required.is_nullable \
                ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('recovery_address_commitments', 'recovery_address_commitments_pkey', 'p'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_id_non_nil_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_npub_shape_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_contract_version_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_version_positive_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_address_shape_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_signature_shape_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_signed_at_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_npub_version_key', 'u'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_signature_once_key', 'u'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_id_address_key', 'u'), \
                    ('chain_swap_records', 'chain_swap_records_recovery_commitment_pair_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_recovery_commitment_fkey', 'f') \
                ) AS required(table_name, constraint_name, constraint_type) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_constraint constraint_info \
                    JOIN pg_class relation ON relation.oid = constraint_info.conrelid \
                    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                    WHERE namespace.nspname = 'public' \
                      AND relation.relname = required.table_name \
                      AND constraint_info.conname = required.constraint_name \
                      AND constraint_info.contype::TEXT = required.constraint_type \
                      AND constraint_info.convalidated \
                ) \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint pair_constraint \
                JOIN pg_class relation ON relation.oid = pair_constraint.conrelid \
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                WHERE namespace.nspname = 'public' \
                  AND relation.relname = 'chain_swap_records' \
                  AND pair_constraint.conname = 'chain_swap_records_recovery_commitment_pair_check' \
                  AND pair_constraint.contype = 'c' \
                  AND pair_constraint.convalidated \
                  AND pg_get_expr( \
                      pair_constraint.conbin, \
                      pair_constraint.conrelid, \
                      TRUE \
                  ) = '(recovery_address_commitment_id IS NULL) = (merchant_emergency_btc_address IS NULL)' \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint unique_constraint \
                JOIN pg_class relation ON relation.oid = unique_constraint.conrelid \
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                WHERE namespace.nspname = 'public' \
                  AND relation.relname = 'recovery_address_commitments' \
                  AND unique_constraint.conname = 'recovery_address_commitment_id_address_key' \
                  AND unique_constraint.contype = 'u' \
                  AND unique_constraint.convalidated \
                  AND ( \
                      SELECT array_agg(attribute.attname::TEXT ORDER BY key_column.ordinality) \
                      FROM unnest(unique_constraint.conkey) WITH ORDINALITY \
                           AS key_column(attnum, ordinality) \
                      JOIN pg_attribute attribute \
                        ON attribute.attrelid = relation.oid \
                       AND attribute.attnum = key_column.attnum \
                  ) = ARRAY['commitment_id', 'canonical_btc_address']::TEXT[] \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint foreign_key \
                JOIN pg_class source_relation ON source_relation.oid = foreign_key.conrelid \
                JOIN pg_namespace source_namespace ON source_namespace.oid = source_relation.relnamespace \
                JOIN pg_class target_relation ON target_relation.oid = foreign_key.confrelid \
                JOIN pg_namespace target_namespace ON target_namespace.oid = target_relation.relnamespace \
                WHERE source_namespace.nspname = 'public' \
                  AND source_relation.relname = 'chain_swap_records' \
                  AND target_namespace.nspname = 'public' \
                  AND target_relation.relname = 'recovery_address_commitments' \
                  AND foreign_key.conname = 'chain_swap_records_recovery_commitment_fkey' \
                  AND foreign_key.contype = 'f' \
                  AND foreign_key.convalidated \
                  AND NOT foreign_key.condeferrable \
                  AND NOT foreign_key.condeferred \
                  AND foreign_key.confupdtype = 'r' \
                  AND foreign_key.confdeltype = 'r' \
                  AND foreign_key.confmatchtype = 's' \
                  AND ( \
                      SELECT array_agg(attribute.attname::TEXT ORDER BY key_column.ordinality) \
                      FROM unnest(foreign_key.conkey) WITH ORDINALITY \
                           AS key_column(attnum, ordinality) \
                      JOIN pg_attribute attribute \
                        ON attribute.attrelid = source_relation.oid \
                       AND attribute.attnum = key_column.attnum \
                  ) = ARRAY['recovery_address_commitment_id', 'merchant_emergency_btc_address']::TEXT[] \
                  AND ( \
                      SELECT array_agg(attribute.attname::TEXT ORDER BY key_column.ordinality) \
                      FROM unnest(foreign_key.confkey) WITH ORDINALITY \
                           AS key_column(attnum, ordinality) \
                      JOIN pg_attribute attribute \
                        ON attribute.attrelid = target_relation.oid \
                       AND attribute.attnum = key_column.attnum \
                  ) = ARRAY['commitment_id', 'canonical_btc_address']::TEXT[] \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('recovery_address_commitments', 'recovery_address_commitment_validate_insert', 'enforce_recovery_address_commitment_insert', 7), \
                    ('recovery_address_commitments', 'recovery_address_commitment_reject_update', 'reject_recovery_address_commitment_update', 19), \
                    ('recovery_address_commitments', 'recovery_address_commitment_reject_delete', 'reject_recovery_address_commitment_delete', 11), \
                    ('chain_swap_records', 'chain_swap_records_require_recovery_commitment', 'require_chain_swap_recovery_commitment', 7), \
                    ('chain_swap_records', 'chain_swap_records_reject_recovery_commitment_update', 'reject_chain_swap_recovery_commitment_mutation', 19) \
                ) AS required(table_name, trigger_name, function_name, trigger_type) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_trigger trigger_info \
                    JOIN pg_class relation ON relation.oid = trigger_info.tgrelid \
                    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                    JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid \
                    WHERE namespace.nspname = 'public' \
                      AND relation.relname = required.table_name \
                      AND trigger_info.tgname = required.trigger_name \
                      AND function_info.proname = required.function_name \
                      AND trigger_info.tgtype = required.trigger_type::SMALLINT \
                      AND NOT trigger_info.tgisinternal \
                      AND trigger_info.tgenabled IN ('O', 'A') \
                      AND ( \
                          required.trigger_name <> 'chain_swap_records_reject_recovery_commitment_update' \
                          OR cardinality(trigger_info.tgattr::SMALLINT[]) = 0 \
                          OR ( \
                              SELECT array_agg(attribute.attname::TEXT) \
                              FROM unnest(trigger_info.tgattr::SMALLINT[]) attribute_number \
                              JOIN pg_attribute attribute \
                                ON attribute.attrelid = relation.oid \
                               AND attribute.attnum = attribute_number \
                          ) @> ARRAY[ \
                              'recovery_address_commitment_id', \
                              'merchant_emergency_btc_address' \
                          ]::TEXT[] \
                      ) \
                ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                FROM pg_class relation \
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                CROSS JOIN LATERAL aclexplode( \
                    COALESCE(relation.relacl, acldefault('r', relation.relowner)) \
                ) acl \
                WHERE namespace.nspname = 'public' \
                  AND relation.relname = 'recovery_address_commitments' \
                  AND acl.grantee = 0 \
            )",
    )
    .fetch_one(pool)
    .await
}

/// Migration 050 is a safety boundary, not merely an additive table marker.
/// Verify every database invariant that prevents swap-key reuse or mutable
/// lineage. Trigger checks include the owning table, function, timing, event,
/// row scope, and enabled state via PostgreSQL's exact `tgtype` bitmask.
async fn swap_key_lineage_invariants_present(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT \
            NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('swap_key_allocations', 'swap_key_allocations_root_fingerprint_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_key_epoch_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_scheme_version_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_child_index_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_purpose_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_public_key_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_preimage_hash_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_preimage_purpose_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_derivation_identity_key', 'u'), \
                    ('swap_key_allocations', 'swap_key_allocations_public_key_key', 'u'), \
                    ('swap_key_legacy_high_water', 'swap_key_legacy_high_water_pkey', 'p'), \
                    ('swap_key_legacy_high_water', 'swap_key_legacy_high_water_root_fingerprint_check', 'c'), \
                    ('swap_key_legacy_high_water', 'swap_key_legacy_high_water_max_child_index_check', 'c'), \
                    ('swap_records', 'swap_records_key_allocation_id_fkey', 'f'), \
                    ('swap_records', 'swap_records_lineage_shape_check', 'c'), \
                    ('swap_records', 'swap_records_lineage_epoch_check', 'c'), \
                    ('swap_records', 'swap_records_lineage_scheme_check', 'c'), \
                    ('swap_records', 'swap_records_claim_public_key_check', 'c'), \
                    ('swap_records', 'swap_records_preimage_hash_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_claim_key_allocation_id_fkey', 'f'), \
                    ('chain_swap_records', 'chain_swap_records_refund_key_allocation_id_fkey', 'f'), \
                    ('chain_swap_records', 'chain_swap_records_lineage_shape_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_lineage_epoch_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_lineage_scheme_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_claim_public_key_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_refund_public_key_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_preimage_hash_check', 'c') \
                ) AS required(table_name, constraint_name, constraint_type) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_constraint c \
                    JOIN pg_class relation ON relation.oid = c.conrelid \
                    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                    WHERE namespace.nspname = 'public' \
                      AND relation.relname = required.table_name \
                      AND c.conname = required.constraint_name \
                      AND c.contype::TEXT = required.constraint_type \
                ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('swap_key_allocations', 'swap_key_allocations_preimage_hash_key'), \
                    ('swap_records', 'swap_records_key_allocation_id_key'), \
                    ('chain_swap_records', 'chain_swap_records_claim_key_allocation_id_key'), \
                    ('chain_swap_records', 'chain_swap_records_refund_key_allocation_id_key'), \
                    ('swap_records', 'swap_records_fingerprint_key_index_key'), \
                    ('chain_swap_records', 'chain_swap_records_fingerprint_claim_index_key'), \
                    ('chain_swap_records', 'chain_swap_records_fingerprint_refund_index_key') \
                ) AS required(table_name, index_name) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_index i \
                    JOIN pg_class index_relation ON index_relation.oid = i.indexrelid \
                    JOIN pg_class table_relation ON table_relation.oid = i.indrelid \
                    JOIN pg_namespace namespace ON namespace.oid = table_relation.relnamespace \
                    WHERE namespace.nspname = 'public' \
                      AND table_relation.relname = required.table_name \
                      AND index_relation.relname = required.index_name \
                      AND i.indisunique \
                      AND i.indisvalid \
                      AND i.indpred IS NOT NULL \
                ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('swap_key_allocations', 'swap_key_allocations_validate_legacy_high_water', 'validate_swap_key_allocation_against_legacy', 7), \
                    ('swap_key_allocations', 'swap_key_allocations_reject_update', 'reject_swap_key_allocation_mutation', 19), \
                    ('swap_key_allocations', 'swap_key_allocations_reject_delete', 'reject_swap_key_allocation_mutation', 11), \
                    ('swap_key_legacy_high_water', 'swap_key_legacy_high_water_reject_update', 'reject_swap_key_legacy_high_water_mutation', 19), \
                    ('swap_key_legacy_high_water', 'swap_key_legacy_high_water_reject_delete', 'reject_swap_key_legacy_high_water_mutation', 11), \
                    ('swap_records', 'swap_records_validate_lineage', 'validate_reverse_swap_key_lineage', 23), \
                    ('chain_swap_records', 'chain_swap_records_validate_lineage', 'validate_chain_swap_key_lineage', 23), \
                    ('swap_records', 'swap_records_reject_lineage_update', 'reject_swap_record_lineage_mutation', 19), \
                    ('chain_swap_records', 'chain_swap_records_reject_lineage_update', 'reject_chain_swap_record_lineage_mutation', 19) \
                ) AS required(table_name, trigger_name, function_name, trigger_type) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_trigger trg \
                    JOIN pg_class relation ON relation.oid = trg.tgrelid \
                    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                    JOIN pg_proc proc ON proc.oid = trg.tgfoid \
                    WHERE namespace.nspname = 'public' \
                      AND relation.relname = required.table_name \
                      AND trg.tgname = required.trigger_name \
                      AND proc.proname = required.function_name \
                      AND trg.tgtype = required.trigger_type::SMALLINT \
                      AND NOT trg.tgisinternal \
                      AND trg.tgenabled IN ('O', 'A') \
                ) \
            )",
    )
    .fetch_one(pool)
    .await
}

fn journal_privileges_ready(
    (select, insert, update): (Option<bool>, Option<bool>, Option<bool>),
) -> bool {
    matches!(
        (select, insert, update),
        (Some(true), Some(true), Some(true))
    )
}

fn direct_lifecycle_privileges_ready(
    (scan_select, scan_insert, scan_update, transition_select, transition_insert): DirectLifecyclePrivileges,
) -> bool {
    matches!(
        (
            scan_select,
            scan_insert,
            scan_update,
            transition_select,
            transition_insert,
        ),
        (Some(true), Some(true), Some(true), Some(true), Some(true),)
    )
}

fn watcher_lane_privileges_ready((select, insert, update): WatcherLanePrivileges) -> bool {
    matches!(
        (select, insert, update),
        (Some(true), Some(true), Some(true))
    )
}

fn swap_key_lineage_privileges_ready(
    (allocation_select, allocation_insert, high_water_select): SwapKeyLineagePrivileges,
) -> bool {
    matches!(
        (allocation_select, allocation_insert, high_water_select),
        (Some(true), Some(true), Some(true))
    )
}

fn chain_swap_record_privileges_ready((select, insert, update): ChainSwapRecordPrivileges) -> bool {
    matches!(
        (select, insert, update),
        (Some(true), Some(true), Some(true))
    )
}

fn recovery_commitment_privileges_ready(
    (
        distinct_owner,
        select,
        insert,
        update,
        delete,
        truncate,
        references,
        trigger,
    ): RecoveryCommitmentPrivileges,
) -> bool {
    matches!(
        (
            distinct_owner,
            select,
            insert,
            update,
            delete,
            truncate,
            references,
            trigger,
        ),
        (
            Some(true),
            Some(true),
            Some(true),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
        )
    )
}

async fn schema_marker_present(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT \
            EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'users' \
                  AND column_name = 'verification_npub' \
                  AND is_nullable = 'YES' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'ct_descriptor' \
                  AND is_nullable = 'NO' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'next_addr_idx' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'kind' \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'donation_pages' \
                  AND c.contype = 'p' \
                  AND ( \
                      SELECT array_agg(a.attname::text ORDER BY k.ord) \
                      FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) \
                      JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum \
                  ) = ARRAY['nym', 'kind']::text[] \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'cooperative_refused' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint \
                WHERE conname = 'chain_swap_records_status_check' \
                  AND pg_get_constraintdef(oid) LIKE '%refund_due%' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'renegotiated_server_lock_amount_sat' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'refund_address' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_records' \
                  AND column_name = 'last_reconciled_at' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'invoices' \
                  AND column_name = 'public_slug' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_indexes \
                WHERE schemaname = 'public' \
                  AND tablename = 'swap_records' \
                  AND indexname = 'swap_records_boltz_swap_id_key' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_records' \
                  AND column_name = 'next_slow_attempt_at' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'next_slow_attempt_at' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_records' \
                  AND column_name = 'key_index' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_records' \
                  AND column_name = 'root_fingerprint' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'claim_key_index' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'generated_og_key' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'generated_og_template_version' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'generated_og_failure_count' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'generated_og_retry_after' \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name IN ('avatar_sha256', 'og_sha256', 'pos_mode') \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_tx_attempts' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'invoices' \
                  AND column_name = 'presentation_status' \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'invoices' \
                  AND c.conname = 'invoices_paid_via_or_closed_chk' \
                  AND c.contype = 'c' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name = 'watcher_lane_progress' \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'watcher_lane_progress' \
                  AND c.conname = 'watcher_lane_progress_pkey' \
                  AND c.contype = 'p' \
                  AND ( \
                      SELECT array_agg(a.attname::text ORDER BY k.ord) \
                      FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) \
                      JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum \
                  ) = ARRAY['worker', 'lane']::text[] \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'watcher_lane_progress' \
                  AND c.conname = 'watcher_lane_progress_worker_check' \
                  AND c.contype = 'c' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'watcher_lane_progress' \
                  AND c.conname = 'watcher_lane_progress_lane_check' \
                  AND c.contype = 'c' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'watcher_lane_progress' \
                  AND c.conname = 'watcher_lane_progress_cursor_shape_check' \
                  AND c.contype = 'c' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'invoice_payment_events' \
                  AND column_name = 'accounting_state' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name = 'invoice_direct_scan_heads' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name = 'invoice_direct_payment_transitions' \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_trigger t \
                JOIN pg_class c ON c.oid = t.tgrelid \
                JOIN pg_namespace n ON n.oid = c.relnamespace \
                WHERE n.nspname = 'public' \
                  AND c.relname = 'invoice_direct_payment_transitions' \
                  AND t.tgname = 'invoice_direct_payment_transition_history_guard' \
                  AND NOT t.tgisinternal \
                  AND t.tgenabled IN ('O', 'A') \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_trigger t \
                JOIN pg_class c ON c.oid = t.tgrelid \
                JOIN pg_namespace n ON n.oid = c.relnamespace \
                WHERE n.nspname = 'public' \
                  AND c.relname = 'invoice_payment_events' \
                  AND t.tgname = 'invoice_payment_event_compatibility_insert_classifier' \
                  AND NOT t.tgisinternal \
                  AND t.tgenabled IN ('O', 'A') \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_key_allocations' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'swap_key_allocations' \
                  AND c.conname = 'swap_key_allocations_derivation_identity_key' \
                  AND c.contype = 'u' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_records' \
                  AND column_name = 'key_allocation_id' \
                  AND is_nullable = 'YES' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'refund_key_allocation_id' \
                  AND is_nullable = 'YES' \
            ) \
            AND ( \
                SELECT COUNT(*) FROM pg_indexes \
                WHERE schemaname = 'public' \
                  AND indexname IN ( \
                      'swap_records_key_allocation_id_key', \
                      'chain_swap_records_claim_key_allocation_id_key', \
                      'chain_swap_records_refund_key_allocation_id_key' \
                  ) \
            ) = 3 \
            AND ( \
                SELECT COUNT(*) FROM pg_indexes \
                WHERE schemaname = 'public' \
                  AND indexname IN ( \
                      'swap_records_fingerprint_key_index_key', \
                      'chain_swap_records_fingerprint_claim_index_key', \
                      'chain_swap_records_fingerprint_refund_index_key' \
                  ) \
            ) = 3 \
            AND EXISTS ( \
                SELECT 1 FROM pg_trigger t \
                JOIN pg_class c ON c.oid = t.tgrelid \
                JOIN pg_namespace n ON n.oid = c.relnamespace \
                WHERE n.nspname = 'public' \
                  AND c.relname = 'swap_key_allocations' \
                  AND t.tgname = 'swap_key_allocations_reject_update' \
                  AND NOT t.tgisinternal \
                  AND t.tgenabled IN ('O', 'A') \
            ) \
            AND ( \
                SELECT COUNT(*) FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name IN ( \
                      'pinned_pair_hash', \
                      'canonical_pair_quote_json', \
                      'creation_response_sha256', \
                      'btc_claim_script_sha256', \
                      'btc_refund_script_sha256', \
                      'liquid_claim_script_sha256', \
                      'liquid_refund_script_sha256', \
                      'btc_timeout_height', \
                      'liquid_timeout_height', \
                      'btc_network', \
                      'liquid_network', \
                      'liquid_asset_id', \
                      'merchant_liquid_destination', \
                      'merchant_emergency_btc_address' \
                  ) \
            ) = 14 \
            AND ( \
                SELECT COUNT(*) FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'chain_swap_records' \
                  AND c.conname IN ( \
                      'chain_swap_records_creation_terms_shape_check', \
                      'chain_swap_records_pinned_pair_hash_check', \
                      'chain_swap_records_pair_quote_json_check', \
                      'chain_swap_records_creation_response_sha256_check', \
                      'chain_swap_records_btc_claim_script_sha256_check', \
                      'chain_swap_records_btc_refund_script_sha256_check', \
                      'chain_swap_records_liquid_claim_script_sha256_check', \
                      'chain_swap_records_liquid_refund_script_sha256_check', \
                      'chain_swap_records_btc_timeout_height_check', \
                      'chain_swap_records_liquid_timeout_height_check', \
                      'chain_swap_records_btc_network_check', \
                      'chain_swap_records_liquid_network_check', \
                      'chain_swap_records_liquid_asset_id_check', \
                      'chain_swap_records_merchant_liquid_destination_check', \
                      'chain_swap_records_merchant_emergency_btc_address_check' \
                  ) \
                  AND c.contype = 'c' \
                  AND c.convalidated \
            ) = 15 \
            AND ( \
                SELECT COUNT(*) FROM pg_trigger t \
                JOIN pg_class c ON c.oid = t.tgrelid \
                JOIN pg_namespace n ON n.oid = c.relnamespace \
                WHERE n.nspname = 'public' \
                  AND c.relname = 'chain_swap_records' \
                  AND t.tgname IN ( \
                      'chain_swap_records_require_creation_terms', \
                      'chain_swap_records_reject_creation_terms_update' \
                  ) \
                  AND NOT t.tgisinternal \
                  AND t.tgenabled IN ('O', 'A') \
            ) = 2 \
            AND ( \
                SELECT COUNT(*) FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND (table_name, column_name) IN ( \
                      ('chain_swap_tx_attempts', 'replaces_txid'), \
                      ('chain_swap_tx_attempts', 'destination_asset_id'), \
                      ('chain_swap_tx_attempts', 'liquid_blinding_key_hex'), \
                      ('invoice_payment_events', 'merchant_settlement_family_key'), \
                      ('invoice_payment_events', 'merchant_chain_swap_id'), \
                      ('invoice_payment_events', 'merchant_settlement_finalized') \
                  ) \
            ) = 6 \
            AND ( \
                SELECT COUNT(*) FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name IN ( \
                      'merchant_settlement_checkpoints', \
                      'merchant_settlement_retained_outputs' \
                  ) \
            ) = 2 \
            AND ( \
                SELECT COUNT(*) \
                  FROM pg_constraint constraint_info \
                  JOIN pg_class relation ON relation.oid = constraint_info.conrelid \
                  JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                 WHERE namespace.nspname = 'public' \
                   AND constraint_info.convalidated \
                   AND constraint_info.conname IN ( \
                       'chain_swap_tx_attempts_replaces_fkey', \
                       'invoice_payment_events_merchant_chain_swap_fkey', \
                       'merchant_settlement_checkpoint_journal_fkey', \
                       'merchant_settlement_retained_event_fkey', \
                       'merchant_settlement_retained_journal_fkey', \
                       'merchant_settlement_retained_checkpoint_fkey' \
                   ) \
            ) = 6",
    )
    .fetch_one(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        chain_swap_record_privileges_ready, direct_lifecycle_privileges_ready,
        journal_privileges_ready, recovery_commitment_privileges_ready,
        swap_key_lineage_privileges_ready, watcher_lane_privileges_ready,
        EXPECTED_MERCHANT_SETTLEMENT_FEE_SHAPE_EXPRESSION,
        EXPECTED_MERCHANT_SETTLEMENT_FEE_VALUE_EXPRESSION, MERCHANT_SETTLEMENT_FEE_SCHEMA_SQL,
        MERCHANT_SETTLEMENT_PRIVILEGES_SQL, MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL,
    };

    #[test]
    fn merchant_settlement_readiness_matches_deploy_boundary() {
        for (column, type_name, ordinal) in [
            ("fee_decision_purpose", "text", 1),
            ("fee_decision_rail", "text", 2),
            ("fee_decision_target", "text", 3),
            ("fee_decision_source", "text", 4),
            ("fee_decision_rate_sat_vb", "float8", 5),
            ("fee_decision_quoted_at_unix", "int8", 6),
            ("fee_decision_evaluated_at_unix", "int8", 7),
            ("fee_decision_freshness_age_secs", "int8", 8),
            ("fee_decision_freshness_max_age_secs", "int8", 9),
            ("fee_decision_provenance", "text", 10),
            ("fee_decision_policy_floor_sat_vb", "float8", 11),
            ("fee_decision_policy_cap_sat_vb", "float8", 12),
            ("fee_decision_policy_version", "text", 13),
        ] {
            let exact_column = format!("('{column}', '{type_name}'::REGTYPE, {ordinal})");
            assert!(
                MERCHANT_SETTLEMENT_FEE_SCHEMA_SQL.contains(&exact_column),
                "missing exact nullable fee column: {exact_column}"
            );
        }
        for schema_guard in [
            "attribute.atttypid = required.type_oid",
            "attribute.atttypmod = -1",
            "NOT attribute.attnotnull",
            "constraint_info.contype = 'c'",
            "constraint_info.convalidated",
            "chain_swap_tx_attempts_fee_authority_shape_check",
            "chain_swap_tx_attempts_fee_authority_value_check",
            "regexp_replace(",
            "expression = $1",
            "expression = $2",
        ] {
            assert!(
                MERCHANT_SETTLEMENT_FEE_SCHEMA_SQL.contains(schema_guard),
                "missing fee-schema guard: {schema_guard}"
            );
        }
        assert_eq!(
            EXPECTED_MERCHANT_SETTLEMENT_FEE_SHAPE_EXPRESSION,
            concat!(
                "num_nonnulls(fee_decision_purpose,fee_decision_rail,",
                "fee_decision_target,fee_decision_source,fee_decision_rate_sat_vb,",
                "fee_decision_quoted_at_unix,fee_decision_evaluated_at_unix,",
                "fee_decision_freshness_age_secs,fee_decision_freshness_max_age_secs,",
                "fee_decision_provenance,fee_decision_policy_floor_sat_vb,",
                "fee_decision_policy_cap_sat_vb,fee_decision_policy_version)=",
                "ANY(ARRAY[0,13])"
            )
        );
        for value_marker in [
            "btc_recovery",
            "bitcoin_recovery",
            "bitcoin_live",
            "bitcoin_last_known_good",
            "liquid_claim",
            "liquid_claim_replacement",
            "chain_liquid_claim",
            "liquid_live",
            "liquid_last_known_good",
            "review25-v1",
        ] {
            assert!(
                EXPECTED_MERCHANT_SETTLEMENT_FEE_VALUE_EXPRESSION.contains(value_marker),
                "missing fee-value authority marker: {value_marker}"
            );
        }

        for (table, trigger, function, trigger_type) in [
            (
                "chain_swap_tx_attempts",
                "chain_swap_tx_attempts_require_review25_fee_authority",
                "require_review25_bitcoin_attempt_fee_authority",
                7,
            ),
            (
                "chain_swap_tx_attempts",
                "chain_swap_tx_attempts_immutable",
                "guard_chain_swap_tx_attempt_immutable",
                19,
            ),
            (
                "chain_swap_tx_attempts",
                "chain_swap_tx_attempts_validate_replacement",
                "enforce_liquid_claim_replacement_lineage",
                7,
            ),
            (
                "invoice_payment_events",
                "invoice_payment_event_evidence_guard",
                "guard_invoice_payment_event_evidence",
                19,
            ),
            (
                "invoice_payment_events",
                "invoice_payment_event_reject_merchant_settlement_delete",
                "reject_merchant_settlement_event_delete",
                11,
            ),
            (
                "merchant_settlement_checkpoints",
                "merchant_settlement_checkpoint_validate_write",
                "enforce_merchant_settlement_checkpoint_write",
                23,
            ),
            (
                "merchant_settlement_checkpoints",
                "merchant_settlement_checkpoint_reject_delete",
                "reject_merchant_settlement_delete",
                11,
            ),
            (
                "merchant_settlement_retained_outputs",
                "merchant_settlement_retained_validate_update",
                "enforce_merchant_settlement_retained_update",
                23,
            ),
            (
                "merchant_settlement_retained_outputs",
                "merchant_settlement_retained_reject_delete",
                "reject_merchant_settlement_delete",
                11,
            ),
        ] {
            let binding = format!("('{table}', '{trigger}', '{function}', {trigger_type})");
            assert!(
                MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL.contains(&binding),
                "missing exact trigger binding: {binding}"
            );
        }
        for exact_catalog_guard in [
            "relation_namespace.nspname = 'public'",
            "function_namespace.nspname = 'public'",
            "function_info.pronargs = 0",
            "trigger_info.tgtype = required.trigger_type::SMALLINT",
            "trigger_info.tgnargs = 0",
            "trigger_info.tgattr::TEXT = ''",
            "trigger_info.tgqual IS NULL",
            "trigger_info.tgconstraint = 0",
            "NOT trigger_info.tgdeferrable",
            "NOT trigger_info.tginitdeferred",
            "NOT trigger_info.tgisinternal",
            "trigger_info.tgenabled = 'O'",
        ] {
            assert!(
                MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL.contains(exact_catalog_guard),
                "missing trigger catalog guard: {exact_catalog_guard}"
            );
        }
        for (function_name, body_sha256) in [
            (
                "enforce_liquid_claim_replacement_lineage",
                "2c6eb8d351f5fe1330d101915e897b2984b91f747d31e879d31d555f18105f27",
            ),
            (
                "enforce_merchant_settlement_checkpoint_write",
                "5e8189d952b8a1f921bafc6da90c2ae658c46691b243f6bbd5e16d056bf7ca29",
            ),
            (
                "enforce_merchant_settlement_retained_update",
                "840d9f3ee9d6fb05f27a2fa9c56f583b411d34b47b92d3a27bc0089622d5ddd0",
            ),
            (
                "guard_chain_swap_tx_attempt_immutable",
                "a11b15a80a879cb5cc9b1b9f3a6c795d72c82263f53b01b1e52e4bb726f800d3",
            ),
            (
                "guard_invoice_payment_event_evidence",
                "893b3f4effa66be50635c1e6a7904783e85d52e30e015123f8438a8a62c295d8",
            ),
            (
                "reject_merchant_settlement_delete",
                "475959643f22379df0eb575f0c2410ee523fe9d15591c73838eecaba7ac9a875",
            ),
            (
                "reject_merchant_settlement_event_delete",
                "6da9435887b06e540a1833528587547bbee9a27dca5e42004d2bd576c1e32be8",
            ),
            (
                "require_review25_bitcoin_attempt_fee_authority",
                "33021f5da06d90a78139df9bacf9d29f84e8225f6f656d6968a1bc99ad169678",
            ),
        ] {
            assert!(
                MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL
                    .contains(&format!("('{function_name}', '{body_sha256}')")),
                "missing exact function body digest: {function_name}"
            );
        }
        for function_catalog_guard in [
            "function_info.prokind = 'f'",
            "function_info.prorettype = 'trigger'::REGTYPE",
            "language_info.lanname = 'plpgsql'",
            "function_info.provolatile = 'v'",
            "NOT function_info.proisstrict",
            "NOT function_info.prosecdef",
            "NOT function_info.proleakproof",
            "function_info.proparallel = 'u'",
            "function_info.proconfig IS NULL",
            "sha256(convert_to(function_info.prosrc, 'UTF8'))",
        ] {
            assert!(
                MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL.contains(function_catalog_guard),
                "missing exact function catalog guard: {function_catalog_guard}"
            );
        }

        for table in [
            "chain_swap_tx_attempts",
            "invoice_payment_events",
            "merchant_settlement_checkpoints",
            "merchant_settlement_retained_outputs",
        ] {
            assert!(MERCHANT_SETTLEMENT_PRIVILEGES_SQL.contains(&format!("('{table}')")));
        }
        for function in [
            "guard_chain_swap_tx_attempt_immutable",
            "require_review25_bitcoin_attempt_fee_authority",
            "enforce_liquid_claim_replacement_lineage",
            "guard_invoice_payment_event_evidence",
            "reject_merchant_settlement_event_delete",
            "enforce_merchant_settlement_checkpoint_write",
            "enforce_merchant_settlement_retained_update",
            "reject_merchant_settlement_delete",
        ] {
            assert!(
                MERCHANT_SETTLEMENT_PRIVILEGES_SQL.contains(&format!("('{function}')")),
                "missing function owner guard: {function}"
            );
        }
        for owner_guard in [
            "relation.relowner) <> current_user",
            "function_info.proowner) <> current_user",
            "sequence_info.relowner) <> current_user",
            "relation.relowner), 'USAGE'",
            "relation.relowner), 'SET'",
            "function_info.proowner), 'USAGE'",
            "function_info.proowner), 'SET'",
            "sequence_info.relowner), 'USAGE'",
            "sequence_info.relowner), 'SET'",
            "invoice_payment_events_accounting_sequence_seq",
        ] {
            assert!(
                MERCHANT_SETTLEMENT_PRIVILEGES_SQL.contains(owner_guard),
                "missing owner capability guard: {owner_guard}"
            );
        }
        assert!(!MERCHANT_SETTLEMENT_PRIVILEGES_SQL.contains("'MEMBER'"));
    }

    #[test]
    fn recovery_journal_requires_every_privilege() {
        assert!(journal_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
        )));

        for privileges in [
            (Some(false), Some(true), Some(true)),
            (Some(true), Some(false), Some(true)),
            (Some(true), Some(true), Some(false)),
            (None, Some(true), Some(true)),
            (Some(true), None, Some(true)),
            (Some(true), Some(true), None),
        ] {
            assert!(!journal_privileges_ready(privileges));
        }
    }

    #[test]
    fn recovery_commitment_requires_private_append_only_runtime_acl() {
        assert!(recovery_commitment_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
        )));

        for privileges in [
            (
                Some(false),
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
            (
                Some(true),
                Some(false),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
            (
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
            (
                Some(true),
                Some(true),
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
            (
                Some(true),
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(true),
            ),
            (
                None,
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
        ] {
            assert!(!recovery_commitment_privileges_ready(privileges));
        }
    }

    #[test]
    fn direct_lifecycle_requires_scan_and_transition_privileges() {
        assert!(direct_lifecycle_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
            Some(true),
            Some(true),
        )));

        for privileges in [
            (Some(false), Some(true), Some(true), Some(true), Some(true)),
            (Some(true), Some(false), Some(true), Some(true), Some(true)),
            (Some(true), Some(true), Some(false), Some(true), Some(true)),
            (Some(true), Some(true), Some(true), Some(false), Some(true)),
            (Some(true), Some(true), Some(true), Some(true), Some(false)),
            (None, Some(true), Some(true), Some(true), Some(true)),
        ] {
            assert!(!direct_lifecycle_privileges_ready(privileges));
        }
    }

    #[test]
    fn watcher_lane_progress_requires_read_write_privileges() {
        assert!(watcher_lane_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
        )));

        for privileges in [
            (Some(false), Some(true), Some(true)),
            (Some(true), Some(false), Some(true)),
            (Some(true), Some(true), Some(false)),
            (None, Some(true), Some(true)),
            (Some(true), None, Some(true)),
            (Some(true), Some(true), None),
        ] {
            assert!(!watcher_lane_privileges_ready(privileges));
        }
    }

    #[test]
    fn swap_key_lineage_requires_allocation_write_and_high_water_read_privileges() {
        assert!(swap_key_lineage_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
        )));
        assert!(!swap_key_lineage_privileges_ready((
            Some(false),
            Some(true),
            Some(true),
        )));
        assert!(!swap_key_lineage_privileges_ready((
            Some(true),
            Some(false),
            Some(true),
        )));
        assert!(!swap_key_lineage_privileges_ready((
            Some(true),
            Some(true),
            Some(false),
        )));
        assert!(!swap_key_lineage_privileges_ready((
            None,
            Some(true),
            Some(true),
        )));
    }

    #[test]
    fn chain_swap_creation_requires_record_read_write_privileges() {
        assert!(chain_swap_record_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
        )));
        for privileges in [
            (Some(false), Some(true), Some(true)),
            (Some(true), Some(false), Some(true)),
            (Some(true), Some(true), Some(false)),
            (None, Some(true), Some(true)),
            (Some(true), None, Some(true)),
            (Some(true), Some(true), None),
        ] {
            assert!(!chain_swap_record_privileges_ready(privileges));
        }
    }
}

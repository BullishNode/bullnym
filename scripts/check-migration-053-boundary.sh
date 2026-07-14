#!/usr/bin/env bash
# Verify migration 053 through the protected runtime connection, without
# exposing its DATABASE_URL. Positional defaults describe Bullnym production;
# explicit arguments keep the probe reusable in disposable test environments.
set -euo pipefail

if (($# > 3)); then
  echo "usage: $0 [env-file [expected-runtime-role [expected-database]]]" >&2
  exit 2
fi

env_file="${1:-/etc/bullnym/bullnym.env}"
expected_runtime_role="${2:-bullnym_app}"
expected_database="${3:-bullnym}"
require_migration_055="${REQUIRE_MIGRATION_055:-0}"

[[ "$require_migration_055" == "0" || "$require_migration_055" == "1" ]] || {
  echo "migration boundary: REQUIRE_MIGRATION_055 must be 0 or 1" >&2
  exit 2
}

[[ -f "$env_file" && ! -L "$env_file" && -O "$env_file" && -r "$env_file" ]] || {
  echo "migration-053 boundary: runtime environment is not a protected owned file: $env_file" >&2
  exit 1
}
env_mode="$(stat --format='%a' "$env_file")"
(( (8#$env_mode & 077) == 0 )) || {
  echo "migration-053 boundary: runtime environment has group/other permissions: $env_file" >&2
  exit 1
}
[[ -n "$expected_runtime_role" && "$expected_runtime_role" != *$'\n'* && "$expected_runtime_role" != *'|'* ]] || {
  echo "migration-053 boundary: invalid expected runtime role" >&2
  exit 2
}
[[ -n "$expected_database" && "$expected_database" != *$'\n'* && "$expected_database" != *'|'* ]] || {
  echo "migration-053 boundary: invalid expected database" >&2
  exit 2
}

# The environment file is trusted deployment configuration. Source it only in
# this process, then pass only parsed libpq connection fields and fixed process
# basics to psql. No unrelated runtime secret reaches the database client.
safe_home="${HOME:-/root}"
safe_path="$PATH"
psql_bin="$(command -v psql)"
python_bin="$(command -v python3)"
# shellcheck disable=SC1090
source "$env_file"
[[ -n "${DATABASE_URL:-}" ]] || {
  echo "migration-053 boundary: DATABASE_URL is missing from $env_file" >&2
  exit 1
}
database_url="$DATABASE_URL"
unset DATABASE_URL

# PGDATABASE does not expand a URI into libpq's host/user/password parameters.
# Parse the protected URL once, allow only connection parameters this probe
# needs, then give psql those individual values in its clean environment.
connection_fields=()
mapfile -d '' -t connection_fields < <(
  env -i DATABASE_URL="$database_url" "$python_bin" <<'PY'
import os
import sys
import urllib.parse

url = urllib.parse.urlsplit(os.environ["DATABASE_URL"])
if url.scheme not in {"postgres", "postgresql"}:
    raise SystemExit("DATABASE_URL must use postgres or postgresql")
if url.hostname is None or url.username is None:
    raise SystemExit("DATABASE_URL must include host and user")
try:
    port = str(url.port or 5432)
except ValueError as error:
    raise SystemExit(f"invalid DATABASE_URL port: {error}") from error
database = urllib.parse.unquote(url.path.removeprefix("/"))
if not database:
    raise SystemExit("DATABASE_URL must include a database")

allowed = {
    "sslmode": "",
    "sslrootcert": "",
    "sslcert": "",
    "sslkey": "",
    "channel_binding": "",
    "target_session_attrs": "",
}
query = urllib.parse.parse_qs(
    url.query,
    keep_blank_values=True,
    strict_parsing=True,
)
unknown = sorted(set(query) - set(allowed))
if unknown:
    raise SystemExit(f"unsupported DATABASE_URL parameter: {unknown[0]}")
for key, values in query.items():
    if len(values) != 1:
        raise SystemExit(f"duplicate DATABASE_URL parameter: {key}")
    allowed[key] = values[0]

values = [
    url.hostname,
    port,
    urllib.parse.unquote(url.username),
    urllib.parse.unquote(url.password or ""),
    database,
    allowed["sslmode"],
    allowed["sslrootcert"],
    allowed["sslcert"],
    allowed["sslkey"],
    allowed["channel_binding"],
    allowed["target_session_attrs"],
]
if any("\n" in value or "\x00" in value for value in values):
    raise SystemExit("DATABASE_URL contains an invalid connection value")
sys.stdout.buffer.write(b"\x00".join(value.encode() for value in values) + b"\x00")
PY
)
unset database_url
(( ${#connection_fields[@]} == 11 )) || {
  echo "migration-053 boundary: DATABASE_URL could not be parsed safely" >&2
  exit 1
}

libpq_environment=(
  "PGHOST=${connection_fields[0]}"
  "PGPORT=${connection_fields[1]}"
  "PGUSER=${connection_fields[2]}"
  "PGPASSWORD=${connection_fields[3]}"
  "PGDATABASE=${connection_fields[4]}"
)
optional_libpq_names=(
  PGSSLMODE PGSSLROOTCERT PGSSLCERT PGSSLKEY PGCHANNELBINDING
  PGTARGETSESSIONATTRS
)
for index in {5..10}; do
  if [[ -n "${connection_fields[$index]}" ]]; then
    libpq_environment+=(
      "${optional_libpq_names[$((index - 5))]}=${connection_fields[$index]}"
    )
  fi
done

clean_psql() {
  env -i \
    HOME="$safe_home" \
    PATH="$safe_path" \
    PGCONNECT_TIMEOUT=5 \
    "${libpq_environment[@]}" \
    "$psql_bin" "$@"
}

result="$(
  clean_psql --no-psqlrc --no-password --set ON_ERROR_STOP=1 \
    --tuples-only --no-align --field-separator='|' <<'SQL'
WITH ledger AS (
    SELECT relation.oid, relation.relowner
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relname = 'recovery_address_commitments'
       AND relation.relkind = 'r'
)
SELECT current_user,
       current_database(),
       COALESCE((
           SELECT pg_get_userbyid(ledger.relowner) <> current_user
              AND NOT pg_has_role(current_user, pg_get_userbyid(ledger.relowner), 'MEMBER')
              AND has_table_privilege(current_user, ledger.oid, 'SELECT')
              AND has_table_privilege(current_user, ledger.oid, 'INSERT')
              AND NOT has_table_privilege(current_user, ledger.oid, 'UPDATE')
              AND NOT has_table_privilege(current_user, ledger.oid, 'DELETE')
              AND NOT has_table_privilege(current_user, ledger.oid, 'TRUNCATE')
              AND NOT has_table_privilege(current_user, ledger.oid, 'REFERENCES')
              AND NOT has_table_privilege(current_user, ledger.oid, 'TRIGGER')
              AND NOT EXISTS (
                  SELECT 1
                    FROM aclexplode(COALESCE(
                        (SELECT relation.relacl
                           FROM pg_class relation
                          WHERE relation.oid = ledger.oid),
                        acldefault('r', ledger.relowner)
                    )) acl
                   WHERE acl.grantee = 0
              )
              AND EXISTS (
                  SELECT 1
                    FROM pg_constraint foreign_key
                    JOIN pg_class source_relation
                      ON source_relation.oid = foreign_key.conrelid
                    JOIN pg_namespace source_namespace
                      ON source_namespace.oid = source_relation.relnamespace
                    JOIN pg_class target_relation
                      ON target_relation.oid = foreign_key.confrelid
                    JOIN pg_namespace target_namespace
                      ON target_namespace.oid = target_relation.relnamespace
                   WHERE source_namespace.nspname = 'public'
                     AND source_relation.relname = 'chain_swap_records'
                     AND target_namespace.nspname = 'public'
                     AND target_relation.relname = 'recovery_address_commitments'
                     AND foreign_key.conname = 'chain_swap_records_recovery_commitment_fkey'
                     AND foreign_key.contype = 'f'
                     AND foreign_key.convalidated
                     AND NOT foreign_key.condeferrable
                     AND NOT foreign_key.condeferred
                     AND foreign_key.confupdtype = 'r'
                     AND foreign_key.confdeltype = 'r'
                     AND foreign_key.confmatchtype = 's'
                     AND (
                         SELECT array_agg(
                             attribute.attname::TEXT
                             ORDER BY key_column.ordinality
                         )
                           FROM unnest(foreign_key.conkey) WITH ORDINALITY
                                AS key_column(attnum, ordinality)
                           JOIN pg_attribute attribute
                             ON attribute.attrelid = source_relation.oid
                            AND attribute.attnum = key_column.attnum
                     ) = ARRAY[
                         'recovery_address_commitment_id',
                         'merchant_emergency_btc_address'
                     ]::TEXT[]
                     AND (
                         SELECT array_agg(
                             attribute.attname::TEXT
                             ORDER BY key_column.ordinality
                         )
                           FROM unnest(foreign_key.confkey) WITH ORDINALITY
                                AS key_column(attnum, ordinality)
                           JOIN pg_attribute attribute
                             ON attribute.attrelid = target_relation.oid
                            AND attribute.attnum = key_column.attnum
                     ) = ARRAY[
                         'commitment_id',
                         'canonical_btc_address'
                     ]::TEXT[]
              )
              AND EXISTS (
                  SELECT 1
                    FROM pg_constraint pair_check
                    JOIN pg_class relation ON relation.oid = pair_check.conrelid
                    JOIN pg_namespace namespace
                      ON namespace.oid = relation.relnamespace
                   WHERE namespace.nspname = 'public'
                     AND relation.relname = 'chain_swap_records'
                     AND pair_check.conname = 'chain_swap_records_recovery_commitment_pair_check'
                     AND pair_check.contype = 'c'
                     AND pair_check.convalidated
                     AND pg_get_expr(
                         pair_check.conbin,
                         pair_check.conrelid,
                         TRUE
                     ) = '(recovery_address_commitment_id IS NULL) = (merchant_emergency_btc_address IS NULL)'
              )
              AND NOT EXISTS (
                  SELECT 1
                    FROM (VALUES
                        ('recovery_address_commitments', 'recovery_address_commitment_validate_insert', 'enforce_recovery_address_commitment_insert', 7),
                        ('recovery_address_commitments', 'recovery_address_commitment_reject_update', 'reject_recovery_address_commitment_update', 19),
                        ('recovery_address_commitments', 'recovery_address_commitment_reject_delete', 'reject_recovery_address_commitment_delete', 11),
                        ('chain_swap_records', 'chain_swap_records_require_recovery_commitment', 'require_chain_swap_recovery_commitment', 7),
                        ('chain_swap_records', 'chain_swap_records_reject_recovery_commitment_update', 'reject_chain_swap_recovery_commitment_mutation', 19)
                    ) AS required(
                        table_name,
                        trigger_name,
                        function_name,
                        trigger_type
                    )
                   WHERE NOT EXISTS (
                       SELECT 1
                         FROM pg_trigger trigger_info
                         JOIN pg_class relation
                           ON relation.oid = trigger_info.tgrelid
                         JOIN pg_namespace namespace
                           ON namespace.oid = relation.relnamespace
                         JOIN pg_proc function_info
                           ON function_info.oid = trigger_info.tgfoid
                        WHERE namespace.nspname = 'public'
                          AND relation.relname = required.table_name
                          AND trigger_info.tgname = required.trigger_name
                          AND function_info.proname = required.function_name
                          AND trigger_info.tgtype = required.trigger_type::SMALLINT
                          AND NOT trigger_info.tgisinternal
                          AND trigger_info.tgenabled IN ('O', 'A')
                          AND (
                              required.trigger_name <> 'chain_swap_records_reject_recovery_commitment_update'
                              OR cardinality(trigger_info.tgattr::SMALLINT[]) = 0
                              OR (
                                  SELECT array_agg(attribute.attname::TEXT)
                                    FROM unnest(trigger_info.tgattr::SMALLINT[])
                                         attribute_number
                                    JOIN pg_attribute attribute
                                      ON attribute.attrelid = relation.oid
                                     AND attribute.attnum = attribute_number
                              ) @> ARRAY[
                                  'recovery_address_commitment_id',
                                  'merchant_emergency_btc_address'
                              ]::TEXT[]
                          )
                   )
              )
             FROM ledger
       ), FALSE)::INT;
SQL
)"

IFS='|' read -r actual_runtime_role actual_database ready extra <<<"$result"
[[ -z "${extra:-}" && "$actual_runtime_role" == "$expected_runtime_role" ]] || {
  echo "migration-053 boundary: connected runtime role does not match expected role" >&2
  exit 1
}
[[ "$actual_database" == "$expected_database" ]] || {
  echo "migration-053 boundary: connected database does not match expected database" >&2
  exit 1
}
[[ "$ready" == "1" ]] || {
  echo "migration-053 boundary: ACL, ownership, constraint, or trigger drift detected" >&2
  exit 1
}

if [[ "$require_migration_055" == "1" ]]; then
  migration_055_ready="$(
    clean_psql --no-psqlrc --no-password --set ON_ERROR_STOP=1 \
      --quiet --tuples-only --no-align <<'SQL'
DO $migration_055_authority_probe$
DECLARE
    value_check_expression TEXT;
    admitted BOOLEAN;
    probe RECORD;
BEGIN
    SELECT pg_get_expr(
               constraint_info.conbin,
               constraint_info.conrelid,
               TRUE
           )
      INTO STRICT value_check_expression
      FROM pg_constraint constraint_info
     WHERE constraint_info.conrelid =
               'public.chain_swap_tx_attempts'::REGCLASS
       AND constraint_info.conname =
               'chain_swap_tx_attempts_fee_authority_value_check'
       AND constraint_info.contype = 'c'
       AND constraint_info.convalidated;

    FOR probe IN
        SELECT *
          FROM (VALUES
              ('btc_recovery', 'bitcoin_recovery', 'bitcoin',
                  'fastestFee', 'bitcoin_live', TRUE),
              ('btc_recovery', 'bitcoin_recovery', 'bitcoin',
                  'fastestFee', 'bitcoin_last_known_good', TRUE),
              ('liquid_claim', 'chain_liquid_claim', 'liquid',
                  '1', 'liquid_live', TRUE),
              ('liquid_claim', 'chain_liquid_claim', 'liquid',
                  '1', 'liquid_last_known_good', TRUE),
              ('liquid_claim_replacement', 'chain_liquid_claim', 'liquid',
                  '1', 'liquid_live', TRUE),
              ('liquid_claim_replacement', 'chain_liquid_claim', 'liquid',
                  '1', 'liquid_last_known_good', TRUE),
              ('btc_recovery', 'chain_liquid_claim', 'liquid',
                  '1', 'liquid_live', FALSE),
              ('liquid_claim', 'bitcoin_recovery', 'bitcoin',
                  'fastestFee', 'bitcoin_live', FALSE)
          ) AS probes(
              purpose, decision_purpose, rail, target, source, expected
          )
    LOOP
        EXECUTE format(
            'SELECT (%s) FROM (SELECT '
            || '$1::TEXT AS purpose, '
            || '$2::TEXT AS fee_decision_purpose, '
            || '$3::TEXT AS fee_decision_rail, '
            || '$4::TEXT AS fee_decision_target, '
            || '$5::TEXT AS fee_decision_source, '
            || '1.5::DOUBLE PRECISION AS fee_decision_rate_sat_vb, '
            || '1700000100::BIGINT AS fee_decision_quoted_at_unix, '
            || '1700000105::BIGINT AS fee_decision_evaluated_at_unix, '
            || '5::BIGINT AS fee_decision_freshness_age_secs, '
            || '60::BIGINT AS fee_decision_freshness_max_age_secs, '
            || '''migration-055-boundary''::TEXT '
            || 'AS fee_decision_provenance, '
            || '0.1::DOUBLE PRECISION '
            || 'AS fee_decision_policy_floor_sat_vb, '
            || '10.0::DOUBLE PRECISION '
            || 'AS fee_decision_policy_cap_sat_vb, '
            || '''review25-v1''::TEXT '
            || 'AS fee_decision_policy_version) authority_probe',
            value_check_expression
        )
        INTO admitted
        USING probe.purpose, probe.decision_purpose, probe.rail,
              probe.target, probe.source;
        IF admitted IS DISTINCT FROM probe.expected THEN
            RAISE EXCEPTION
                'migration 055 fee-authority constraint admitted=% for purpose=% authority=%/%/%/%; expected=%',
                admitted, probe.purpose, probe.decision_purpose,
                probe.rail, probe.target, probe.source, probe.expected
                USING ERRCODE = '23514';
        END IF;
    END LOOP;
END
$migration_055_authority_probe$;

SELECT (
    NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_tx_attempts', 'replaces_txid'),
              ('chain_swap_tx_attempts', 'destination_asset_id'),
              ('chain_swap_tx_attempts', 'liquid_blinding_key_hex'),
              ('chain_swap_tx_attempts', 'fee_decision_purpose'),
              ('chain_swap_tx_attempts', 'fee_decision_rail'),
              ('chain_swap_tx_attempts', 'fee_decision_target'),
              ('chain_swap_tx_attempts', 'fee_decision_source'),
              ('chain_swap_tx_attempts', 'fee_decision_rate_sat_vb'),
              ('chain_swap_tx_attempts', 'fee_decision_quoted_at_unix'),
              ('chain_swap_tx_attempts', 'fee_decision_evaluated_at_unix'),
              ('chain_swap_tx_attempts', 'fee_decision_freshness_age_secs'),
              ('chain_swap_tx_attempts', 'fee_decision_freshness_max_age_secs'),
              ('chain_swap_tx_attempts', 'fee_decision_provenance'),
              ('chain_swap_tx_attempts', 'fee_decision_policy_floor_sat_vb'),
              ('chain_swap_tx_attempts', 'fee_decision_policy_cap_sat_vb'),
              ('chain_swap_tx_attempts', 'fee_decision_policy_version'),
              ('invoice_payment_events', 'merchant_settlement_family_key'),
              ('invoice_payment_events', 'merchant_chain_swap_id'),
              ('invoice_payment_events', 'merchant_settlement_finalized')
          ) required(table_name, column_name)
         WHERE NOT EXISTS (
             SELECT 1
               FROM information_schema.columns
              WHERE table_schema = 'public'
                AND table_name = required.table_name
                AND column_name = required.column_name
         )
    )
    AND to_regclass('public.merchant_settlement_checkpoints') IS NOT NULL
    AND to_regclass('public.merchant_settlement_retained_outputs') IS NOT NULL
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_tx_attempts', 'chain_swap_tx_attempts_fee_authority_shape_check'),
              ('chain_swap_tx_attempts', 'chain_swap_tx_attempts_fee_authority_value_check'),
              ('chain_swap_tx_attempts', 'chain_swap_tx_attempts_replaces_fkey'),
              ('invoice_payment_events', 'invoice_payment_events_merchant_chain_swap_fkey'),
              ('merchant_settlement_checkpoints', 'merchant_settlement_checkpoint_journal_fkey'),
              ('merchant_settlement_retained_outputs', 'merchant_settlement_retained_event_fkey'),
              ('merchant_settlement_retained_outputs', 'merchant_settlement_retained_journal_fkey'),
              ('merchant_settlement_retained_outputs', 'merchant_settlement_retained_checkpoint_fkey')
          ) required(table_name, constraint_name)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_constraint constraint_info
               JOIN pg_class relation ON relation.oid = constraint_info.conrelid
               JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
              WHERE namespace.nspname = 'public'
                AND relation.relname = required.table_name
                AND constraint_info.conname = required.constraint_name
                AND constraint_info.convalidated
         )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_tx_attempts',
                  'chain_swap_tx_attempts_require_review25_fee_authority',
                  'require_review25_bitcoin_attempt_fee_authority', 7),
              ('chain_swap_tx_attempts',
                  'chain_swap_tx_attempts_immutable',
                  'guard_chain_swap_tx_attempt_immutable', 19),
              ('chain_swap_tx_attempts',
                  'chain_swap_tx_attempts_validate_replacement',
                  'enforce_liquid_claim_replacement_lineage', 7),
              ('invoice_payment_events',
                  'invoice_payment_event_evidence_guard',
                  'guard_invoice_payment_event_evidence', 19),
              ('invoice_payment_events',
                  'invoice_payment_event_reject_merchant_settlement_delete',
                  'reject_merchant_settlement_event_delete', 11),
              ('merchant_settlement_checkpoints',
                  'merchant_settlement_checkpoint_validate_write',
                  'enforce_merchant_settlement_checkpoint_write', 23),
              ('merchant_settlement_checkpoints',
                  'merchant_settlement_checkpoint_reject_delete',
                  'reject_merchant_settlement_delete', 11),
              ('merchant_settlement_retained_outputs',
                  'merchant_settlement_retained_validate_update',
                  'enforce_merchant_settlement_retained_update', 23),
              ('merchant_settlement_retained_outputs',
                  'merchant_settlement_retained_reject_delete',
                  'reject_merchant_settlement_delete', 11)
          ) required(table_name, trigger_name, function_name, trigger_type)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_trigger trigger_info
               JOIN pg_class relation ON relation.oid = trigger_info.tgrelid
               JOIN pg_namespace namespace
                 ON namespace.oid = relation.relnamespace
               JOIN pg_proc function_info
                 ON function_info.oid = trigger_info.tgfoid
               JOIN pg_namespace function_namespace
                 ON function_namespace.oid = function_info.pronamespace
              WHERE namespace.nspname = 'public'
                AND function_namespace.nspname = 'public'
                AND relation.relname = required.table_name
                AND trigger_info.tgname = required.trigger_name
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
                AND trigger_info.tgtype = required.trigger_type::SMALLINT
                AND NOT trigger_info.tgisinternal
                AND trigger_info.tgenabled IN ('O', 'A')
         )
    )
    AND EXISTS (
        SELECT 1
          FROM pg_trigger trigger_info
          JOIN pg_class relation ON relation.oid = trigger_info.tgrelid
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid
         WHERE namespace.nspname = 'public'
           AND relation.relname = 'chain_swap_tx_attempts'
           AND trigger_info.tgname =
               'chain_swap_tx_attempts_require_review25_fee_authority'
           AND trigger_info.tgtype = 7
           AND NOT trigger_info.tgisinternal
           AND trigger_info.tgenabled IN ('O', 'A')
           AND function_info.proname =
               'require_review25_bitcoin_attempt_fee_authority'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%IF NEW.fee_decision_purpose IS NULL THEN%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%IF NEW.purpose = ''liquid_claim'' THEN%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%parent.claim_fee_decision_policy_version%'
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('fee_decision_purpose'),
              ('fee_decision_rail'),
              ('fee_decision_target'),
              ('fee_decision_source'),
              ('fee_decision_rate_sat_vb'),
              ('fee_decision_quoted_at_unix'),
              ('fee_decision_evaluated_at_unix'),
              ('fee_decision_freshness_age_secs'),
              ('fee_decision_freshness_max_age_secs'),
              ('fee_decision_provenance'),
              ('fee_decision_policy_floor_sat_vb'),
              ('fee_decision_policy_cap_sat_vb'),
              ('fee_decision_policy_version')
          ) required(column_name)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_proc function_info
               JOIN pg_namespace namespace
                 ON namespace.oid = function_info.pronamespace
              WHERE namespace.nspname = 'public'
                AND function_info.proname =
                    'guard_chain_swap_tx_attempt_immutable'
                AND function_info.pronargs = 0
                AND position(
                    format(
                        'NEW.%s IS DISTINCT FROM OLD.%s',
                        required.column_name,
                        required.column_name
                    ) IN pg_get_functiondef(function_info.oid)
                ) > 0
         )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('guard_chain_swap_tx_attempt_immutable'),
              ('require_review25_bitcoin_attempt_fee_authority'),
              ('enforce_liquid_claim_replacement_lineage'),
              ('guard_invoice_payment_event_evidence'),
              ('reject_merchant_settlement_event_delete'),
              ('enforce_merchant_settlement_checkpoint_write'),
              ('enforce_merchant_settlement_retained_update'),
              ('reject_merchant_settlement_delete')
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
                    'MEMBER'
                )
         )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_tx_attempts'),
              ('invoice_payment_events'),
              ('merchant_settlement_checkpoints'),
              ('merchant_settlement_retained_outputs')
          ) required(table_name)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_class relation
               JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
              WHERE namespace.nspname = 'public'
                AND relation.relname = required.table_name
                AND relation.relkind = 'r'
                AND pg_get_userbyid(relation.relowner) <> current_user
                AND NOT pg_has_role(current_user, pg_get_userbyid(relation.relowner), 'MEMBER')
                AND has_table_privilege(current_user, relation.oid, 'SELECT')
                AND has_table_privilege(current_user, relation.oid, 'INSERT')
                AND has_table_privilege(current_user, relation.oid, 'UPDATE')
                AND NOT has_table_privilege(current_user, relation.oid, 'DELETE')
                AND NOT has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                AND NOT has_table_privilege(current_user, relation.oid, 'REFERENCES')
                AND NOT has_table_privilege(current_user, relation.oid, 'TRIGGER')
         )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          CROSS JOIN LATERAL aclexplode(COALESCE(
              relation.relacl,
              acldefault('r', relation.relowner)
          )) acl
         WHERE namespace.nspname = 'public'
           AND relation.relname IN (
               'chain_swap_tx_attempts', 'invoice_payment_events',
               'merchant_settlement_checkpoints',
               'merchant_settlement_retained_outputs'
           )
           AND acl.grantee = 0
    )
    AND EXISTS (
        SELECT 1
          FROM pg_class sequence_info
          JOIN pg_namespace namespace
            ON namespace.oid = sequence_info.relnamespace
         WHERE namespace.nspname = 'public'
           AND sequence_info.relname =
               'invoice_payment_events_accounting_sequence_seq'
           AND sequence_info.relkind = 'S'
           AND pg_get_userbyid(sequence_info.relowner) <> current_user
           AND NOT pg_has_role(
               current_user,
               pg_get_userbyid(sequence_info.relowner),
               'MEMBER'
           )
           AND has_sequence_privilege(
               current_user,
               sequence_info.oid,
               'USAGE'
           )
           AND NOT has_sequence_privilege(
               current_user,
               sequence_info.oid,
               'SELECT'
           )
           AND NOT has_sequence_privilege(
               current_user,
               sequence_info.oid,
               'UPDATE'
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM aclexplode(COALESCE(
                     sequence_info.relacl,
                     acldefault('S', sequence_info.relowner)
                 )) acl
                WHERE acl.grantee = 0
           )
    )
    AND NOT EXISTS (
        SELECT 1 FROM chain_swap_records
         WHERE status IN (
             'server_lock_mempool', 'server_lock_confirmed',
             'claiming', 'claim_failed'
         )
           AND (claim_tx_hex IS NOT NULL OR claim_txid IS NOT NULL)
           AND (
               claim_tx_hex IS NULL OR claim_txid IS NULL
               OR NOT EXISTS (
                   SELECT 1 FROM chain_swap_tx_attempts attempt
                    WHERE attempt.chain_swap_id = chain_swap_records.id
                      AND attempt.purpose = 'liquid_claim'
                      AND attempt.replaces_txid IS NULL
                      AND attempt.raw_tx_hex = chain_swap_records.claim_tx_hex
                      AND attempt.txid = chain_swap_records.claim_txid
               )
           )
    )
)::INT;
SQL
  )"
  [[ "$migration_055_ready" == "1" ]] || {
    echo "migration-055 boundary: schema, ACL, journal, or zero-legacy invariant failed" >&2
    exit 1
  }
fi

echo "migration 053 boundary verified for runtime role $actual_runtime_role on database $actual_database"
if [[ "$require_migration_055" == "1" ]]; then
  echo "migration 055 boundary verified for runtime role $actual_runtime_role on database $actual_database"
fi

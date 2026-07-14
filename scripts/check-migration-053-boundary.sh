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
require_migration_056="${REQUIRE_MIGRATION_056:-0}"
require_migration_057="${REQUIRE_MIGRATION_057:-0}"

[[ "$require_migration_055" == "0" || "$require_migration_055" == "1" ]] || {
  echo "migration boundary: REQUIRE_MIGRATION_055 must be 0 or 1" >&2
  exit 2
}
[[ "$require_migration_056" == "0" || "$require_migration_056" == "1" ]] || {
  echo "migration boundary: REQUIRE_MIGRATION_056 must be 0 or 1" >&2
  exit 2
}
[[ "$require_migration_057" == "0" || "$require_migration_057" == "1" ]] || {
  echo "migration boundary: REQUIRE_MIGRATION_057 must be 0 or 1" >&2
  exit 2
}
if [[ "$require_migration_056" == "1" && "$require_migration_055" != "1" ]]; then
  echo "migration boundary: REQUIRE_MIGRATION_056 requires REQUIRE_MIGRATION_055=1" >&2
  exit 2
fi
if [[ "$require_migration_057" == "1" && "$require_migration_056" != "1" ]]; then
  echo "migration boundary: REQUIRE_MIGRATION_057 requires REQUIRE_MIGRATION_056=1" >&2
  exit 2
fi

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
              AND NOT pg_has_role(current_user, pg_get_userbyid(ledger.relowner), 'USAGE')
              AND NOT pg_has_role(current_user, pg_get_userbyid(ledger.relowner), 'SET')
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
                         JOIN pg_namespace function_namespace
                           ON function_namespace.oid = function_info.pronamespace
                        WHERE namespace.nspname = 'public'
                          AND function_namespace.nspname = 'public'
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
                AND trigger_info.tgnargs = 0
                AND trigger_info.tgattr::TEXT = ''
                AND trigger_info.tgqual IS NULL
                AND trigger_info.tgconstraint = 0
                AND NOT trigger_info.tgdeferrable
                AND NOT trigger_info.tginitdeferred
                AND NOT trigger_info.tgisinternal
                AND trigger_info.tgenabled = 'O'
         )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('enforce_liquid_claim_replacement_lineage',
                  '2c6eb8d351f5fe1330d101915e897b2984b91f747d31e879d31d555f18105f27'),
              ('enforce_merchant_settlement_checkpoint_write',
                  '5e8189d952b8a1f921bafc6da90c2ae658c46691b243f6bbd5e16d056bf7ca29'),
              ('enforce_merchant_settlement_retained_update',
                  '840d9f3ee9d6fb05f27a2fa9c56f583b411d34b47b92d3a27bc0089622d5ddd0'),
              ('guard_chain_swap_tx_attempt_immutable',
                  'a11b15a80a879cb5cc9b1b9f3a6c795d72c82263f53b01b1e52e4bb726f800d3'),
              ('guard_invoice_payment_event_evidence',
                  '893b3f4effa66be50635c1e6a7904783e85d52e30e015123f8438a8a62c295d8'),
              ('reject_merchant_settlement_delete',
                  '475959643f22379df0eb575f0c2410ee523fe9d15591c73838eecaba7ac9a875'),
              ('reject_merchant_settlement_event_delete',
                  '6da9435887b06e540a1833528587547bbee9a27dca5e42004d2bd576c1e32be8'),
              ('require_review25_bitcoin_attempt_fee_authority',
                  '33021f5da06d90a78139df9bacf9d29f84e8225f6f656d6968a1bc99ad169678')
          ) required(function_name, body_sha256)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_proc function_info
               JOIN pg_namespace namespace
                 ON namespace.oid = function_info.pronamespace
               JOIN pg_language language_info
                 ON language_info.oid = function_info.prolang
              WHERE namespace.nspname = 'public'
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
                AND function_info.prokind = 'f'
                AND function_info.prorettype = 'trigger'::REGTYPE
                AND language_info.lanname = 'plpgsql'
                AND function_info.provolatile = 'v'
                AND NOT function_info.proisstrict
                AND NOT function_info.prosecdef
                AND NOT function_info.proleakproof
                AND function_info.proparallel = 'u'
                AND function_info.proconfig IS NULL
                AND encode(
                    sha256(convert_to(function_info.prosrc, 'UTF8')), 'hex'
                ) = required.body_sha256
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
                    'USAGE'
                )
                AND NOT pg_has_role(
                    current_user,
                    pg_get_userbyid(function_info.proowner),
                    'SET'
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
                AND NOT pg_has_role(current_user, pg_get_userbyid(relation.relowner), 'USAGE')
                AND NOT pg_has_role(current_user, pg_get_userbyid(relation.relowner), 'SET')
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
               'USAGE'
           )
           AND NOT pg_has_role(
               current_user,
               pg_get_userbyid(sequence_info.relowner),
               'SET'
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

if [[ "$require_migration_056" == "1" ]]; then
  migration_056_ready="$(
    clean_psql --no-psqlrc --no-password --set ON_ERROR_STOP=1 \
      --quiet --tuples-only --no-align <<'SQL'
SELECT (
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
             'public.chain_swap_renegotiation_operations'::REGCLASS
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
                  'public.chain_swap_renegotiation_operations'::REGCLASS
                AND constraint_info.conname = required.constraint_name
                AND constraint_info.contype = 'c'
                AND constraint_info.convalidated
         )
    )
    AND EXISTS (
        SELECT 1
          FROM pg_constraint constraint_info
         WHERE constraint_info.conrelid =
             'public.chain_swap_renegotiation_operations'::REGCLASS
           AND constraint_info.conname =
               'chain_swap_renegotiation_operations_pkey'
           AND constraint_info.contype = 'p'
           AND constraint_info.convalidated
    )
    AND EXISTS (
        SELECT 1
          FROM pg_constraint foreign_key
         WHERE foreign_key.conrelid =
             'public.chain_swap_renegotiation_operations'::REGCLASS
           AND foreign_key.confrelid = 'public.chain_swap_records'::REGCLASS
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
             'public.chain_swap_renegotiation_operations'::REGCLASS
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
             'public.chain_swap_renegotiation_operations'::REGCLASS
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
             'public.chain_swap_renegotiation_operations'::REGCLASS
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
             'public.chain_swap_renegotiation_operations'::REGCLASS
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
             'public.chain_swap_renegotiation_operations'::REGCLASS
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
                AND trigger_info.tgnargs = 0
                AND trigger_info.tgattr::TEXT = ''
                AND trigger_info.tgqual IS NULL
                AND trigger_info.tgconstraint = 0
                AND NOT trigger_info.tgdeferrable
                AND NOT trigger_info.tginitdeferred
                AND NOT trigger_info.tgisinternal
                AND trigger_info.tgenabled = 'O'
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
         )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('enforce_chain_swap_renegotiation_insert',
                  'd4e7f872cc933a4179535eb8b726f3b3b381b98bef4f811b3c233160df1af5f9'),
              ('enforce_chain_swap_renegotiation_update',
                  '4e8e004ca1509192f13c56a58ebbac285bf7bc8699954431b97bdcdfcd05d222'),
              ('reject_chain_swap_renegotiation_delete',
                  'cf155d3f1e2fd1429049e21e0a00535de72d4459dee453f1149b9144cc6e25c9')
          ) required(function_name, body_sha256)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_proc function_info
               JOIN pg_namespace namespace
                 ON namespace.oid = function_info.pronamespace
               JOIN pg_language language_info
                 ON language_info.oid = function_info.prolang
              WHERE namespace.nspname = 'public'
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
                AND function_info.prokind = 'f'
                AND function_info.prorettype = 'trigger'::REGTYPE
                AND language_info.lanname = 'plpgsql'
                AND function_info.provolatile = 'v'
                AND NOT function_info.proisstrict
                AND NOT function_info.prosecdef
                AND NOT function_info.proleakproof
                AND function_info.proparallel = 'u'
                AND function_info.proconfig IS NULL
                AND encode(
                    sha256(convert_to(function_info.prosrc, 'UTF8')), 'hex'
                ) = required.body_sha256
         )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM information_schema.columns column_info
         WHERE column_info.table_schema = 'public'
           AND column_info.table_name = 'chain_swap_renegotiation_operations'
           AND (
               column_info.is_identity <> 'NO'
               OR column_info.is_generated <> 'NEVER'
               OR column_info.column_default LIKE 'nextval(%'
           )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM pg_depend dependency
          JOIN pg_class sequence_info ON sequence_info.oid = dependency.objid
         WHERE dependency.classid = 'pg_class'::REGCLASS
           AND dependency.refclassid = 'pg_class'::REGCLASS
           AND dependency.refobjid =
                 'public.chain_swap_renegotiation_operations'::REGCLASS
           AND dependency.deptype IN ('a', 'i')
           AND sequence_info.relkind = 'S'
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
)::INT;
SQL
  )"
  [[ "$migration_056_ready" == "1" ]] || {
    echo "migration-056 boundary: schema, state machine, owner, or ACL invariant failed" >&2
    exit 1
  }
fi

if [[ "$require_migration_057" == "1" ]]; then
  migration_057_ready="$(
    clean_psql --no-psqlrc --no-password --set ON_ERROR_STOP=1 \
      --quiet --tuples-only --no-align <<'SQL'
SELECT (
    (SELECT COUNT(*) = 60
       FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'chain_swap_cooperative_signing_operations')
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_id', 'uuid', 'NO'),
              ('state', 'text', 'NO'),
              ('boltz_swap_id', 'text', 'NO'),
              ('source_txid', 'text', 'NO'),
              ('source_vout', 'bigint', 'NO'),
              ('source_amount_sat', 'bigint', 'NO'),
              ('source_script_pubkey_hex', 'text', 'NO'),
              ('destination_address', 'text', 'NO'),
              ('destination_script_pubkey_hex', 'text', 'NO'),
              ('destination_amount_sat', 'bigint', 'NO'),
              ('fee_amount_sat', 'bigint', 'NO'),
              ('fee_vbytes', 'bigint', 'NO'),
              ('fee_decision_purpose', 'text', 'NO'),
              ('fee_decision_rail', 'text', 'NO'),
              ('fee_decision_target', 'text', 'NO'),
              ('fee_decision_source', 'text', 'NO'),
              ('fee_decision_rate_sat_vb', 'double precision', 'NO'),
              ('fee_decision_quoted_at_unix', 'bigint', 'NO'),
              ('fee_decision_evaluated_at_unix', 'bigint', 'NO'),
              ('fee_decision_freshness_age_secs', 'bigint', 'NO'),
              ('fee_decision_freshness_max_age_secs', 'bigint', 'NO'),
              ('fee_decision_provenance', 'text', 'NO'),
              ('fee_decision_policy_floor_sat_vb', 'double precision', 'NO'),
              ('fee_decision_policy_cap_sat_vb', 'double precision', 'NO'),
              ('fee_decision_policy_version', 'text', 'NO'),
              ('request_transaction_hex', 'text', 'NO'),
              ('request_transaction_sha256', 'text', 'NO'),
              ('request_transaction_txid', 'text', 'NO'),
              ('request_input_index', 'integer', 'NO'),
              ('sighash_hex', 'text', 'NO'),
              ('aggregate_key_xonly_hex', 'text', 'NO'),
              ('client_public_nonce_hex', 'text', 'NO'),
              ('provider_request_sha256', 'text', 'NO'),
              ('session_sha256', 'text', 'NO'),
              ('secret_nonce_format', 'text', 'NO'),
              ('secret_nonce_encryption_algorithm', 'text', 'NO'),
              ('secret_nonce_key_id', 'text', 'NO'),
              ('secret_nonce_encryption_nonce', 'bytea', 'NO'),
              ('secret_nonce_ciphertext', 'bytea', 'NO'),
              ('secret_nonce_plaintext_sha256', 'text', 'NO'),
              ('request_attempt_count', 'integer', 'NO'),
              ('version', 'bigint', 'NO'),
              ('requested_at', 'timestamp with time zone', 'YES'),
              ('ambiguous_at', 'timestamp with time zone', 'YES'),
              ('last_error_class', 'text', 'YES'),
              ('provider_public_nonce_hex', 'text', 'YES'),
              ('provider_partial_signature_hex', 'text', 'YES'),
              ('provider_response_sha256', 'text', 'YES'),
              ('response_received_at', 'timestamp with time zone', 'YES'),
              ('final_transaction_hex', 'text', 'YES'),
              ('final_transaction_sha256', 'text', 'YES'),
              ('final_txid', 'text', 'YES'),
              ('local_partial_signature_sha256', 'text', 'YES'),
              ('completed_at', 'timestamp with time zone', 'YES'),
              ('integrity_reason_sha256', 'text', 'YES'),
              ('integrity_hold_at', 'timestamp with time zone', 'YES'),
              ('superseded_reason', 'text', 'YES'),
              ('superseded_at', 'timestamp with time zone', 'YES'),
              ('created_at', 'timestamp with time zone', 'NO'),
              ('updated_at', 'timestamp with time zone', 'NO')
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
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('state', '''prepared''::text'),
              ('request_input_index', '0'),
              ('request_attempt_count', '0'),
              ('version', '1'),
              ('created_at', 'now()'),
              ('updated_at', 'now()')
          ) required(column_name, column_default)
         WHERE NOT EXISTS (
             SELECT 1
               FROM information_schema.columns column_info
              WHERE column_info.table_schema = 'public'
                AND column_info.table_name =
                    'chain_swap_cooperative_signing_operations'
                AND column_info.column_name = required.column_name
                AND column_info.column_default = required.column_default
         )
    )
    AND (SELECT COUNT(*) = 14
           FROM pg_constraint
          WHERE conrelid =
              'public.chain_swap_cooperative_signing_operations'::REGCLASS
            AND contype = 'c')
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_cooperative_signing_state_check'),
              ('chain_swap_cooperative_signing_parent_identity_check'),
              ('chain_swap_cooperative_signing_source_check'),
              ('chain_swap_cooperative_signing_destination_check'),
              ('chain_swap_cooperative_signing_exact_fee_check'),
              ('chain_swap_cooperative_signing_fee_authority_check'),
              ('chain_swap_cooperative_signing_request_check'),
              ('chain_swap_cooperative_signing_secret_nonce_check'),
              ('chain_swap_cooperative_signing_attempt_check'),
              ('chain_swap_cooperative_signing_error_check'),
              ('chain_swap_cooperative_signing_response_check'),
              ('chain_swap_cooperative_signing_completion_check'),
              ('chain_swap_cooperative_signing_terminal_check'),
              ('chain_swap_cooperative_signing_lifecycle_shape_check')
          ) required(constraint_name)
         WHERE NOT EXISTS (
             SELECT 1
               FROM pg_constraint constraint_info
              WHERE constraint_info.conrelid =
                    'public.chain_swap_cooperative_signing_operations'::REGCLASS
                AND constraint_info.conname = required.constraint_name
                AND constraint_info.contype = 'c'
                AND constraint_info.convalidated
         )
    )
    AND EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid =
               'public.chain_swap_cooperative_signing_operations'::REGCLASS
           AND conname = 'chain_swap_cooperative_signing_operations_pkey'
           AND contype = 'p' AND convalidated
    )
    AND EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid =
               'public.chain_swap_cooperative_signing_operations'::REGCLASS
           AND confrelid = 'public.chain_swap_records'::REGCLASS
           AND conname = 'chain_swap_cooperative_signing_chain_fkey'
           AND contype = 'f' AND convalidated
           AND confupdtype = 'r' AND confdeltype = 'r'
           AND NOT condeferrable AND NOT condeferred
    )
    AND EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid =
               'public.chain_swap_cooperative_signing_operations'::REGCLASS
           AND conname = 'chain_swap_cooperative_signing_state_check'
           AND pg_get_constraintdef(oid) LIKE '%prepared%requested%ambiguous%response_received%completed%integrity_hold%superseded%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid =
               'public.chain_swap_cooperative_signing_operations'::REGCLASS
           AND conname = 'chain_swap_cooperative_signing_response_check'
           AND pg_get_constraintdef(oid) LIKE
               '%bullnym:cooperative-signing-provider-response:v1:%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid =
               'public.chain_swap_cooperative_signing_operations'::REGCLASS
           AND conname = 'chain_swap_cooperative_signing_completion_check'
           AND pg_get_constraintdef(oid) LIKE
               '%final_txid = request_transaction_txid%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_index index_info
          JOIN pg_class index_relation
            ON index_relation.oid = index_info.indexrelid
         WHERE index_info.indrelid =
               'public.chain_swap_cooperative_signing_operations'::REGCLASS
           AND index_relation.relname =
               'chain_swap_cooperative_signing_active_idx'
           AND NOT index_info.indisunique AND index_info.indisvalid
           AND pg_get_indexdef(index_info.indexrelid) LIKE
               '%(updated_at, chain_swap_id)%'
           AND pg_get_expr(index_info.indpred, index_info.indrelid) LIKE
               '%completed%integrity_hold%superseded%'
    )
    AND NOT EXISTS (
        SELECT 1
          FROM (VALUES
              ('chain_swap_cooperative_signing_validate_insert',
                  'enforce_chain_swap_cooperative_signing_insert', 7),
              ('chain_swap_cooperative_signing_validate_update',
                  'enforce_chain_swap_cooperative_signing_update', 19),
              ('chain_swap_cooperative_signing_reject_delete',
                  'reject_chain_swap_cooperative_signing_delete', 11)
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
                AND relation.relname =
                    'chain_swap_cooperative_signing_operations'
                AND relation.relkind = 'r'
                AND trigger_info.tgname = required.trigger_name
                AND trigger_info.tgtype = required.trigger_type::SMALLINT
                AND trigger_info.tgnargs = 0
                AND trigger_info.tgattr::TEXT = ''
                AND trigger_info.tgqual IS NULL
                AND trigger_info.tgconstraint = 0
                AND NOT trigger_info.tgdeferrable
                AND NOT trigger_info.tginitdeferred
                AND NOT trigger_info.tgisinternal
                AND trigger_info.tgenabled = 'O'
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
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
               JOIN pg_language language_info
                 ON language_info.oid = function_info.prolang
              WHERE namespace.nspname = 'public'
                AND function_info.proname = required.function_name
                AND function_info.pronargs = 0
                AND function_info.prokind = 'f'
                AND function_info.prorettype = 'trigger'::REGTYPE
                AND language_info.lanname = 'plpgsql'
                AND function_info.provolatile = 'v'
                AND NOT function_info.proisstrict
                AND NOT function_info.prosecdef
                AND NOT function_info.proleakproof
                AND function_info.proparallel = 'u'
                AND function_info.proconfig IS NULL
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
    AND EXISTS (
        SELECT 1
          FROM pg_proc function_info
          JOIN pg_namespace namespace ON namespace.oid = function_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND function_info.proname =
               'enforce_chain_swap_cooperative_signing_update'
           AND function_info.pronargs = 0
           AND pg_get_functiondef(function_info.oid) LIKE
               '%NEW.requested_at := transitioned_at%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%terminal cooperative signing evidence is immutable%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%completion requires the exact immutable recovery attempt%'
           AND pg_get_functiondef(function_info.oid) LIKE
               '%unilateral_timeout_reached%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_proc function_info
          JOIN pg_namespace namespace ON namespace.oid = function_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND function_info.proname =
               'reject_chain_swap_cooperative_signing_delete'
           AND function_info.pronargs = 0
           AND pg_get_functiondef(function_info.oid) LIKE
               '%cooperative signing operation evidence cannot be deleted%'
    )
    AND EXISTS (
        SELECT 1
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relname =
               'chain_swap_cooperative_signing_operations'
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
          FROM information_schema.columns column_info
         WHERE column_info.table_schema = 'public'
           AND column_info.table_name =
               'chain_swap_cooperative_signing_operations'
           AND (
               column_info.is_identity <> 'NO'
               OR column_info.is_generated <> 'NEVER'
               OR column_info.column_default LIKE 'nextval(%'
           )
    )
    AND NOT EXISTS (
        SELECT 1
          FROM pg_depend dependency
          JOIN pg_class sequence_info ON sequence_info.oid = dependency.objid
         WHERE dependency.classid = 'pg_class'::REGCLASS
           AND dependency.refclassid = 'pg_class'::REGCLASS
           AND dependency.refobjid =
               'public.chain_swap_cooperative_signing_operations'::REGCLASS
           AND dependency.deptype IN ('a', 'i')
           AND sequence_info.relkind = 'S'
    )
)::INT;
SQL
  )"
  [[ "$migration_057_ready" == "1" ]] || {
    echo "migration-057 boundary: schema, state machine, owner, or ACL invariant failed" >&2
    exit 1
  }
fi

echo "migration 053 boundary verified for runtime role $actual_runtime_role on database $actual_database"
if [[ "$require_migration_055" == "1" ]]; then
  echo "migration 055 boundary verified for runtime role $actual_runtime_role on database $actual_database"
fi
if [[ "$require_migration_056" == "1" ]]; then
  echo "migration 056 boundary verified for runtime role $actual_runtime_role on database $actual_database"
fi
if [[ "$require_migration_057" == "1" ]]; then
  echo "migration 057 boundary verified for runtime role $actual_runtime_role on database $actual_database"
fi

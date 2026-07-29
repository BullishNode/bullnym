#!/usr/bin/env bash
# Run Bullnym's DB integration target against disposable PostgreSQL databases.
# The fresh lane applies the complete migration chain to an empty database. The
# upgrade lane applies the same chain while executing checked-in before/after
# fixtures at real migration boundaries.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16}"
PG_USER="bullnym_test"
PG_PASSWORD="bullnym_test"
RUNTIME_ROLE="bullnym_app"
CONTAINER="bullnym-test-pg-${USER:-user}-$$-${RANDOM}"
FRESH_DB="bullnym_fresh"
UPGRADE_DB="bullnym_upgrade"
MODE="all"
FILTER=""
KEEP=0
STARTED=0
RUN_IGNORED=0
LOCKED=0
BULLNYM_CARGO_SERIALIZED_WRAPPER="${BULLNYM_CARGO_SERIALIZED_WRAPPER:-}"
BULLNYM_CARGO_SERIALIZED_LANE="${BULLNYM_CARGO_SERIALIZED_LANE:-}"
DATA_VOLUME=""
CLEANUP_FAILURE_PROBE=0
CLEANUP_FAILURE_STATUS=86
EXPECTED_MIGRATION_COUNT=82
MIGRATION_FILES=()

usage() {
  cat <<'USAGE'
Usage: scripts/test-db.sh [options] [test-filter]

Options:
  --mode fresh|upgrade|all  Select migration/test lanes (default: all).
  --filter NAME             Pass one test-name filter to cargo test.
  --ignored                 Run the exact ignored test selected by --filter.
  --locked                  Require Cargo.lock to remain unchanged.
  --cleanup-failure-probe   Exit after startup to prove trap cleanup.
  --keep                    Leave the uniquely named container running.
  -h, --help                Show this help.

The integration target is always single-threaded because its tests reset a
shared database. Override the image with POSTGRES_IMAGE when needed.
USAGE
}

die() {
  echo "test-db: $*" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --mode)
      (($# >= 2)) || die "--mode requires a value"
      MODE="$2"
      shift 2
      ;;
    --filter)
      (($# >= 2)) || die "--filter requires a value"
      FILTER="$2"
      shift 2
      ;;
    --keep)
      KEEP=1
      shift
      ;;
    --ignored)
      RUN_IGNORED=1
      shift
      ;;
    --locked)
      LOCKED=1
      shift
      ;;
    --cleanup-failure-probe)
      CLEANUP_FAILURE_PROBE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      die "unknown option: $1"
      ;;
    *)
      [[ -z "$FILTER" ]] || die "only one test filter is supported"
      FILTER="$1"
      shift
      ;;
  esac
done

case "$MODE" in
  fresh|upgrade|all) ;;
  *) die "invalid mode '$MODE' (expected fresh, upgrade, or all)" ;;
esac
if ((CLEANUP_FAILURE_PROBE == 1 && KEEP == 1)); then
  die "--cleanup-failure-probe cannot be combined with --keep"
fi

mapfile -t MIGRATION_FILES < <(
  find migrations -maxdepth 1 -type f -name '*.sql' -printf '%f\n' | LC_ALL=C sort
)
[[ "${#MIGRATION_FILES[@]}" -eq "$EXPECTED_MIGRATION_COUNT" ]] \
  || die "expected exactly $EXPECTED_MIGRATION_COUNT migrations, found ${#MIGRATION_FILES[@]}"
for ((migration_number = 1; migration_number <= EXPECTED_MIGRATION_COUNT; migration_number += 1)); do
  expected_prefix="$(printf '%03d_' "$migration_number")"
  migration_name="${MIGRATION_FILES[migration_number - 1]}"
  [[ "$migration_name" == "$expected_prefix"*.sql ]] \
    || die "migration boundary is not contiguous at $expected_prefix (found $migration_name)"
done
[[ "${MIGRATION_FILES[0]}" == "001_initial.sql" ]] \
  || die "unexpected migration-001 boundary: ${MIGRATION_FILES[0]}"
[[ "${MIGRATION_FILES[EXPECTED_MIGRATION_COUNT - 1]}" == \
    "082_mixed_valuation_exception_scope.sql" ]] \
  || die "unexpected migration-082 boundary: ${MIGRATION_FILES[EXPECTED_MIGRATION_COUNT - 1]}"

command -v docker >/dev/null || die "docker is required"
docker info >/dev/null 2>&1 || die "docker daemon is unavailable"

cleanup() {
  local status=$?
  local cleanup_failed=0
  trap - EXIT
  if ((STARTED == 1)); then
    if ((status != 0 && CLEANUP_FAILURE_PROBE == 0)); then
      echo "test-db: PostgreSQL log tail after failure:" >&2
      docker logs --tail 50 "$CONTAINER" >&2 || true
    fi
    if ((KEEP == 1)); then
      echo "test-db: kept container $CONTAINER (host port ${HOST_PORT:-unknown})"
    else
      docker rm -fv "$CONTAINER" >/dev/null 2>&1 || cleanup_failed=1
      if docker inspect "$CONTAINER" >/dev/null 2>&1; then
        echo "test-db: container cleanup verification failed" >&2
        cleanup_failed=1
      fi
      if [[ -n "$DATA_VOLUME" ]] && docker volume inspect "$DATA_VOLUME" >/dev/null 2>&1; then
        echo "test-db: anonymous data-volume cleanup verification failed" >&2
        cleanup_failed=1
      fi
      if ((cleanup_failed == 0)); then
        echo "test-db: verified container and anonymous data-volume cleanup"
      else
        status=1
      fi
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

docker run --detach \
  --name "$CONTAINER" \
  --env "POSTGRES_USER=$PG_USER" \
  --env "POSTGRES_PASSWORD=$PG_PASSWORD" \
  --env POSTGRES_DB=postgres \
  --publish 127.0.0.1::5432 \
  "$POSTGRES_IMAGE" >/dev/null
STARTED=1

DATA_VOLUME="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}' "$CONTAINER")"
[[ "$DATA_VOLUME" =~ ^[0-9a-f]{64}$ ]] \
  || die "could not resolve the anonymous PostgreSQL data volume"
if ((CLEANUP_FAILURE_PROBE == 1)); then
  echo "test-db: exercising intentional post-start cleanup failure path"
  exit "$CLEANUP_FAILURE_STATUS"
fi

READY=0
READY_STREAK=0
for _ in $(seq 1 60); do
  # The official image briefly starts a temporary server during initdb and
  # then restarts it. Require PID 1 to be the final postgres process as well as
  # a stable readiness window, or createdb can land in that restart gap.
  if docker exec "$CONTAINER" sh -c 'test "$(cat /proc/1/comm)" = postgres' \
      && docker exec "$CONTAINER" pg_isready --quiet --username "$PG_USER" --dbname postgres; then
    ((READY_STREAK += 1))
    if ((READY_STREAK >= 3)); then
      READY=1
      break
    fi
  else
    READY_STREAK=0
  fi
  sleep 0.5
done
((READY == 1)) || die "PostgreSQL did not remain ready within 30 seconds"

HOST_PORT="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "$CONTAINER")"
[[ "$HOST_PORT" =~ ^[0-9]+$ ]] || die "could not resolve the published PostgreSQL port"

db_url() {
  local database="$1"
  printf 'postgres://%s:%s@127.0.0.1:%s/%s' "$PG_USER" "$PG_PASSWORD" "$HOST_PORT" "$database"
}

create_database() {
  docker exec "$CONTAINER" createdb --username "$PG_USER" "$1"
}

run_sql_file() {
  local database="$1"
  local file="$2"
  shift 2
  docker exec --interactive "$CONTAINER" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" --dbname "$database" \
    "$@" \
    < "$file" >/dev/null
}

assert_empty_name_cutover_refusal() {
  local database="$1"
  local migration="$2"
  local number="$3"
  local scratch="${database}_migration_${number}_nonempty"
  local refusal_output rollback_state

  docker exec "$CONTAINER" dropdb --if-exists --username "$PG_USER" "$scratch"
  docker exec "$CONTAINER" createdb --username "$PG_USER" --template "$database" "$scratch"
  docker exec "$CONTAINER" psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --username "$PG_USER" --dbname "$scratch" \
    --command "INSERT INTO users (nym, npub, ct_descriptor, is_active) VALUES ('nonempty-cutover', repeat('d', 64), 'nonempty-descriptor', FALSE);" >/dev/null

  if refusal_output="$(
    docker exec --interactive "$CONTAINER" \
      psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" --dbname "$scratch" \
        --set "runtime_role=$RUNTIME_ROLE" < "$migration" 2>&1
  )"; then
    die "migration $number unexpectedly accepted nonempty ownership state"
  fi
  [[ "$refusal_output" == *"requires the documented empty production reset"* ]] \
    || die "migration $number returned the wrong empty-state failure: $refusal_output"

  rollback_state="$(
    docker exec "$CONTAINER" \
      psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
        --username "$PG_USER" --dbname "$scratch" \
        --command "SELECT COALESCE(to_regclass('public.public_names')::TEXT, '') || ':' || EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'donation_pages' AND column_name = 'alias')::TEXT || ':' || (SELECT COUNT(*) FROM users)::TEXT"
  )"
  [[ "$rollback_state" == ":true:1" ]] \
    || die "migration $number leaked cutover state after refusal ($rollback_state)"
  docker exec "$CONTAINER" dropdb --username "$PG_USER" "$scratch"
  echo "test-db: migration $number refused nonempty ownership state transactionally"
}

assert_private_invoice_cutover_refusal() {
  local database="$1"
  local migration="$2"
  local scratch="${database}_migration_065_nonempty"
  local refusal_output rollback_state

  docker exec "$CONTAINER" dropdb --if-exists --username "$PG_USER" "$scratch"
  docker exec "$CONTAINER" createdb --username "$PG_USER" --template "$database" "$scratch"
  docker exec "$CONTAINER" psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --username "$PG_USER" --dbname "$scratch" \
    --command "INSERT INTO invoices (nym_owner, npub_owner, origin, fiat_amount_minor, fiat_currency, amount_sat, rate_minor_per_btc, rate_locks_until, bitcoin_address, accept_btc, accept_ln, accept_liquid, status, pricing_mode, presentation_status, settlement_status, expires_at) VALUES (NULL, repeat('6', 64), 'wallet', NULL, NULL, 21000, NULL, TIMESTAMPTZ '2030-01-01 00:00:00+00', 'bc1q065refusal0000000000000000000000000000000000000', TRUE, FALSE, FALSE, 'unpaid', 'sat_fixed', 'unpaid', 'none', TIMESTAMPTZ '2030-01-01 00:00:00+00');" >/dev/null

  if refusal_output="$(
    docker exec --interactive "$CONTAINER" \
      psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" --dbname "$scratch" \
        --set "runtime_role=$RUNTIME_ROLE" < "$migration" 2>&1
  )"; then
    die "migration 065 unexpectedly accepted an existing wallet invoice"
  fi
  [[ "$refusal_output" == *"migration 065 refuses wallet-origin rows"* ]] \
    || die "migration 065 returned the wrong nonempty-wallet failure: $refusal_output"

  rollback_state="$(
    docker exec "$CONTAINER" \
      psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
        --username "$PG_USER" --dbname "$scratch" \
        --command "SELECT (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'invoices' AND column_name IN ('recipient_label', 'public_description', 'invoice_number'))::TEXT || ':' || (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'invoices' AND column_name IN ('client_request_id', 'client_request_digest', 'presentation_envelope'))::TEXT || ':' || (SELECT COUNT(*) FROM invoices WHERE origin = 'wallet')::TEXT"
  )"
  [[ "$rollback_state" == "3:0:1" ]] \
    || die "migration 065 leaked cutover state after refusal ($rollback_state)"
  docker exec "$CONTAINER" dropdb --username "$PG_USER" "$scratch"
  echo "test-db: migration 065 refused an existing wallet invoice transactionally"
}

assert_wallet_backup_migration_owner_boundary() {
  local database="$1"
  local migration="$2"
  local runtime_scratch="${database}_migration_076_runtime_role"
  local refusal_output rollback_state

  docker exec "$CONTAINER" dropdb --if-exists --username "$PG_USER" "$runtime_scratch"
  docker exec "$CONTAINER" createdb --username "$PG_USER" --template "$database" "$runtime_scratch"
  if refusal_output="$(
    {
      printf 'SET ROLE %s;\n' "$RUNTIME_ROLE"
      cat "$migration"
    } | docker exec --interactive "$CONTAINER" \
          psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" \
            --dbname "$runtime_scratch" --set "runtime_role=$RUNTIME_ROLE" 2>&1
  )"; then
    die "migration 076 unexpectedly ran as the runtime role"
  fi
  [[ "$refusal_output" == *"must run as the schema owner, not the runtime role"* ]] \
    || die "migration 076 returned the wrong runtime-role failure: $refusal_output"
  rollback_state="$(
    docker exec "$CONTAINER" \
      psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
        --username "$PG_USER" --dbname "$runtime_scratch" \
        --command "SELECT (pg_get_constraintdef(oid) LIKE '%wallet_metadata%')::TEXT || ':' || (pg_get_constraintdef(oid) LIKE '%wallet_backup%')::TEXT FROM pg_constraint WHERE conrelid = 'wallet_backup_blobs'::REGCLASS AND conname = 'wallet_backup_blobs_stream_chk';"
  )"
  [[ "$rollback_state" == "true:false" ]] \
    || die "migration 076 runtime-role refusal mutated the stream contract ($rollback_state)"
  docker exec "$CONTAINER" dropdb --username "$PG_USER" "$runtime_scratch"
  echo "test-db: migration 076 refused runtime-role execution transactionally"
}

assert_mixed_claim_fee_migration_owner_boundary() {
  local database="$1"
  local migration="$2"
  local runtime_scratch="${database}_migration_078_runtime_role"
  local refusal_output rollback_state

  docker exec "$CONTAINER" dropdb --if-exists --username "$PG_USER" "$runtime_scratch"
  docker exec "$CONTAINER" createdb --username "$PG_USER" --template "$database" "$runtime_scratch"
  if refusal_output="$(
    {
      printf 'SET ROLE %s;\n' "$RUNTIME_ROLE"
      cat "$migration"
    } | docker exec --interactive "$CONTAINER" \
          psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" \
            --dbname "$runtime_scratch" --set "runtime_role=$RUNTIME_ROLE" 2>&1
  )"; then
    die "migration 078 unexpectedly ran as the runtime role"
  fi
  [[ "$refusal_output" == *"must run as the schema owner, not the runtime role"* ]] \
    || die "migration 078 returned the wrong runtime-role failure: $refusal_output"
  rollback_state="$(
    docker exec "$CONTAINER" \
      psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
        --username "$PG_USER" --dbname "$runtime_scratch" \
        --command "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name IN ('swap_records', 'chain_swap_records') AND column_name IN ('mixed_claim_path', 'mixed_claim_fee_budget_sat');"
  )"
  [[ "$rollback_state" == "0" ]] \
    || die "migration 078 runtime-role refusal leaked authority columns ($rollback_state)"
  docker exec "$CONTAINER" dropdb --username "$PG_USER" "$runtime_scratch"
  echo "test-db: migration 078 refused runtime-role execution transactionally"
}

assert_provider_not_found_migration_owner_boundary() {
  local database="$1"
  local migration="$2"
  local runtime_scratch="${database}_migration_080_runtime_role"
  local refusal_output rollback_state

  docker exec "$CONTAINER" dropdb --if-exists --username "$PG_USER" "$runtime_scratch"
  docker exec "$CONTAINER" createdb --username "$PG_USER" --template "$database" "$runtime_scratch"
  if refusal_output="$(
    {
      printf 'SET ROLE %s;\n' "$RUNTIME_ROLE"
      cat "$migration"
    } | docker exec --interactive "$CONTAINER" \
          psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" \
            --dbname "$runtime_scratch" --set "runtime_role=$RUNTIME_ROLE" 2>&1
  )"; then
    die "migration 080 unexpectedly ran as the runtime role"
  fi
  [[ "$refusal_output" == *"must run as the schema owner, not the runtime role"* ]] \
    || die "migration 080 returned the wrong runtime-role failure: $refusal_output"
  rollback_state="$(
    docker exec "$CONTAINER" \
      psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
        --username "$PG_USER" --dbname "$runtime_scratch" \
        --command "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'bull_bitcoin_settlements' AND column_name IN ('provider_last_read_error_class', 'provider_last_read_error_at', 'provider_last_success_at', 'provider_not_found_first_at', 'provider_not_found_consecutive', 'provider_missing_since', 'provider_missing_last_resolved_at');"
  )"
  [[ "$rollback_state" == "0" ]] \
    || die "migration 080 runtime-role refusal leaked provider-read columns ($rollback_state)"
  docker exec "$CONTAINER" dropdb --username "$PG_USER" "$runtime_scratch"
  echo "test-db: migration 080 refused runtime-role execution transactionally"
}

assert_mixed_valuation_scope_migration_owner_boundary() {
  local database="$1"
  local migration="$2"
  local runtime_scratch="${database}_migration_082_runtime_role"
  local refusal_output rollback_state

  docker exec "$CONTAINER" dropdb --if-exists --username "$PG_USER" "$runtime_scratch"
  docker exec "$CONTAINER" createdb --username "$PG_USER" --template "$database" "$runtime_scratch"
  if refusal_output="$(
    {
      printf 'SET ROLE %s;\n' "$RUNTIME_ROLE"
      cat "$migration"
    } | docker exec --interactive "$CONTAINER" \
          psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" \
            --dbname "$runtime_scratch" --set "runtime_role=$RUNTIME_ROLE" 2>&1
  )"; then
    die "migration 082 unexpectedly ran as the runtime role"
  fi
  [[ "$refusal_output" == *"must run as the schema owner, not the runtime role"* ]] \
    || die "migration 082 returned the wrong runtime-role failure: $refusal_output"
  rollback_state="$(
    docker exec "$CONTAINER" \
      psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
        --username "$PG_USER" --dbname "$runtime_scratch" \
        --command "SELECT (POSITION('parent_invoice.pricing_mode = ''fiat_fixed''::text' IN pg_get_viewdef('invoice_mixed_valuation_exceptions'::REGCLASS, TRUE)) = 0)::TEXT;"
  )"
  [[ "$rollback_state" == "true" ]] \
    || die "migration 082 runtime-role refusal changed the exception scope ($rollback_state)"
  docker exec "$CONTAINER" dropdb --username "$PG_USER" "$runtime_scratch"
  echo "test-db: migration 082 refused runtime-role execution transactionally"
}

apply_migrations() {
  local database="$1"
  local with_hooks="$2"
  local count=0
  local migration migration_name base before after

  for migration_name in "${MIGRATION_FILES[@]}"; do
    migration="migrations/$migration_name"
    base="$(basename "$migration" .sql)"
    before="tests/migration-hooks/${base}.before.sql"
    after="tests/migration-hooks/${base}.after.sql"
    if [[ "$with_hooks" == "true" && -f "$before" ]]; then
      echo "test-db: applying pre-migration fixture $before"
      run_sql_file "$database" "$before"
    fi
    if [[ "$with_hooks" == "true" && "$base" == "058_permanent_public_names" ]]; then
      assert_empty_name_cutover_refusal "$database" "$migration" "058"
    fi
    if [[ "$with_hooks" == "true" && "$base" == "059_remove_surface_alias" ]]; then
      assert_empty_name_cutover_refusal "$database" "$migration" "059"
    fi
    if [[ "$with_hooks" == "true" && "$base" == "065_private_invoice_presentations" ]]; then
      assert_private_invoice_cutover_refusal "$database" "$migration"
    fi
    if [[ "$with_hooks" == "true" && "$base" == "076_unified_wallet_backup_stream" ]]; then
      assert_wallet_backup_migration_owner_boundary "$database" "$migration"
    fi
    if [[ "$with_hooks" == "true" && "$base" == "078_mixed_claim_fee_authority" ]]; then
      assert_mixed_claim_fee_migration_owner_boundary "$database" "$migration"
    fi
    if [[ "$with_hooks" == "true" && "$base" == "080_persistent_provider_order_not_found" ]]; then
      assert_provider_not_found_migration_owner_boundary "$database" "$migration"
    fi
    if [[ "$with_hooks" == "true" && "$base" == "082_mixed_valuation_exception_scope" ]]; then
      assert_mixed_valuation_scope_migration_owner_boundary "$database" "$migration"
    fi
    if [[ "$base" == "053_recovery_address_commitments" \
       || "$base" == "054_fee_policy_authority" \
       || "$base" == "055_merchant_settlement_lifecycle" \
       || "$base" == "056_chain_swap_renegotiation_journal" \
       || "$base" == "057_chain_swap_cooperative_signing_operations" \
       || "$base" == "058_permanent_public_names" \
       || "$base" == "059_remove_surface_alias" \
       || "$base" == "060_lnurl_private_comment_intents" \
       || "$base" == "061_invoice_quote_versions" \
       || "$base" == "062_invoice_quote_provider_attempts" \
       || "$base" == "063_checkout_private_memo" \
       || "$base" == "064_wallet_backup_blobs" \
       || "$base" == "065_private_invoice_presentations" \
       || "$base" == "066_get_paid_transaction_history" \
       || "$base" == "067_bull_bitcoin_fiat_settlement" \
       || "$base" == "068_bull_bitcoin_invoice_accounting" \
       || "$base" == "069_bull_bitcoin_mixed_settlement" \
       || "$base" == "070_bull_bitcoin_quoted_fiat" \
       || "$base" == "071_mixed_invoice_payin_valuation" \
       || "$base" == "072_mixed_invoice_blinding_key_invariant" \
       || "$base" == "073_unfunded_provider_watch" \
       || "$base" == "074_bull_bitcoin_execution_rate" \
       || "$base" == "075_fiat_only_quote_accounting" \
       || "$base" == "076_unified_wallet_backup_stream" \
       || "$base" == "077_bull_bitcoin_create_correlation" \
       || "$base" == "078_mixed_claim_fee_authority" \
       || "$base" == "079_lightning_address_provider_only" \
       || "$base" == "080_persistent_provider_order_not_found" \
       || "$base" == "081_provider_payment_first_observed_at" \
       || "$base" == "082_mixed_valuation_exception_scope" ]]; then
      run_sql_file "$database" "$migration" --set "runtime_role=$RUNTIME_ROLE"
    else
      run_sql_file "$database" "$migration"
    fi
    ((count += 1))
    if [[ "$with_hooks" == "true" && -f "$after" ]]; then
      echo "test-db: applying post-migration assertion $after"
      run_sql_file "$database" "$after"
    fi
  done
  echo "test-db: applied $count migrations to $database (hooks=$with_hooks)"
}

run_integration_suite() {
  local database="$1"
  local -a args=(test)
  if ((LOCKED == 1)); then
    args+=(--locked)
  fi
  args+=(--test integration_test)
  if [[ -n "$FILTER" ]]; then
    args+=("$FILTER")
  fi
  if ((RUN_IGNORED == 1)); then
    [[ -n "$FILTER" ]] || die "--ignored requires --filter"
    args+=(-- --ignored --exact --test-threads=1)
  else
    args+=(-- --test-threads=1)
  fi
  echo "test-db: running serial integration suite against $database"
  if [[ -n "$BULLNYM_CARGO_SERIALIZED_WRAPPER" || -n "$BULLNYM_CARGO_SERIALIZED_LANE" ]]; then
    [[ -x "$BULLNYM_CARGO_SERIALIZED_WRAPPER" ]] \
      || die "BULLNYM_CARGO_SERIALIZED_WRAPPER must be executable"
    [[ -n "$BULLNYM_CARGO_SERIALIZED_LANE" ]] \
      || die "BULLNYM_CARGO_SERIALIZED_LANE is required with the wrapper"
    TEST_DATABASE_URL="$(db_url "$database")" \
      "$BULLNYM_CARGO_SERIALIZED_WRAPPER" "$BULLNYM_CARGO_SERIALIZED_LANE" "${args[@]}"
  else
    TEST_DATABASE_URL="$(db_url "$database")" cargo "${args[@]}"
  fi
}

docker exec "$CONTAINER" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" --dbname postgres \
  --command "CREATE ROLE $RUNTIME_ROLE NOLOGIN" >/dev/null

if [[ "$MODE" == "fresh" || "$MODE" == "all" ]]; then
  create_database "$FRESH_DB"
  apply_migrations "$FRESH_DB" false
  run_integration_suite "$FRESH_DB"
fi

if [[ "$MODE" == "upgrade" || "$MODE" == "all" ]]; then
  create_database "$UPGRADE_DB"
  apply_migrations "$UPGRADE_DB" true
  run_integration_suite "$UPGRADE_DB"
fi

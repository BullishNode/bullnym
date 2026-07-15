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
EXPECTED_MIGRATION_COUNT=61
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
    "061_invoice_quote_versions.sql" ]] \
  || die "unexpected migration-061 boundary: ${MIGRATION_FILES[EXPECTED_MIGRATION_COUNT - 1]}"

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

assert_migration_058_refusal_case() {
  local database="$1"
  local migration="$2"
  local suffix="$3"
  local mutation="$4"
  local expected="$5"
  local scratch="${database}_migration_058_${suffix}"
  local refusal_output rollback_state

  docker exec "$CONTAINER" dropdb --if-exists --username "$PG_USER" "$scratch"
  docker exec "$CONTAINER" createdb --username "$PG_USER" --template "$database" "$scratch"
  docker exec "$CONTAINER" psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --username "$PG_USER" --dbname "$scratch" --command "$mutation" >/dev/null

  if refusal_output="$(
    docker exec --interactive "$CONTAINER" \
      psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" --dbname "$scratch" \
        --set "runtime_role=$RUNTIME_ROLE" < "$migration" 2>&1
  )"; then
    die "migration 058 unexpectedly accepted $suffix"
  fi
  [[ "$refusal_output" == *"$expected"* ]] \
    || die "migration 058 $suffix returned the wrong failure: $refusal_output"

  rollback_state="$(
    docker exec "$CONTAINER" \
      psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
        --username "$PG_USER" --dbname "$scratch" \
        --command "SELECT COALESCE(to_regclass('public.public_name_migration_choices')::TEXT, '') || ':' || EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'donation_pages' AND column_name = 'alias')::TEXT || ':' || (SELECT next_addr_idx::TEXT FROM donation_pages WHERE nym = 'independent-page-owner' AND kind = 'payment_page')"
  )"
  [[ "$rollback_state" == ":true:3" ]] \
    || die "migration 058 $suffix leaked preflight state after rollback ($rollback_state)"
  docker exec "$CONTAINER" dropdb --username "$PG_USER" "$scratch"
  echo "test-db: migration 058 refused $suffix transactionally"
}

assert_migration_058_refuses_ambiguous_history() {
  local database="$1"
  local migration="$2"

  assert_migration_058_refusal_case \
    "$database" "$migration" "invalid_invoice_owner" \
    "UPDATE invoices SET npub_owner = repeat('9', 64) WHERE id = '46000000-0000-0000-0000-000000000001';" \
    "cannot attribute historical invoice aliases"

  assert_migration_058_refusal_case \
    "$database" "$migration" "ambiguous_alias_owner" \
    "UPDATE invoices SET public_slug = 'shop-page' WHERE id = '46000000-0000-0000-0000-000000000001';" \
    "aliases attributed to multiple owners"
}

assert_migration_059_refusal_case() {
  local database="$1"
  local migration="$2"
  local suffix="$3"
  local mutation="$4"
  local expected="$5"
  local scratch="${database}_migration_059_${suffix}"
  local refusal_output rollback_state

  docker exec "$CONTAINER" dropdb --if-exists --username "$PG_USER" "$scratch"
  docker exec "$CONTAINER" createdb --username "$PG_USER" --template "$database" "$scratch"
  docker exec "$CONTAINER" psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --username "$PG_USER" --dbname "$scratch" --command "$mutation" >/dev/null

  if refusal_output="$(
    docker exec --interactive "$CONTAINER" \
      psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" --dbname "$scratch" \
        --set "runtime_role=$RUNTIME_ROLE" < "$migration" 2>&1
  )"; then
    die "migration 059 unexpectedly accepted $suffix"
  fi
  [[ "$refusal_output" == *"$expected"* ]] \
    || die "migration 059 $suffix returned the wrong failure: $refusal_output"

  rollback_state="$(
    docker exec "$CONTAINER" \
      psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
        --username "$PG_USER" --dbname "$scratch" \
        --command "SELECT COALESCE(to_regclass('public.public_names')::TEXT, '') || ':' || EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'donation_pages' AND column_name = 'alias')::TEXT || ':' || (SELECT next_addr_idx::TEXT FROM donation_pages WHERE nym = 'independent-page-owner' AND kind = 'payment_page')"
  )"
  [[ "$rollback_state" == ":true:3" ]] \
    || die "migration 059 $suffix leaked cutover state after rollback ($rollback_state)"
  docker exec "$CONTAINER" dropdb --username "$PG_USER" "$scratch"
  echo "test-db: migration 059 refused $suffix transactionally"
}

assert_migration_059_refuses_drift_and_unresolved() {
  local database="$1"
  local migration="$2"

  assert_migration_059_refusal_case \
    "$database" "$migration" "nym_drift" \
    "INSERT INTO users (nym, npub, ct_descriptor, is_active) VALUES ('post-preflight-nym', repeat('d', 64), 'drift-descriptor', FALSE);" \
    "public-name candidates changed after preflight"

  assert_migration_059_refusal_case \
    "$database" "$migration" "alias_drift" \
    "UPDATE donation_pages SET alias = 'shop-pos-drift' WHERE nym = 'multi-alias-owner' AND kind = 'pos';" \
    "public-name candidates changed after preflight"

  assert_migration_059_refusal_case \
    "$database" "$migration" "unresolved" \
    "UPDATE public_name_migration_choices SET resolved = FALSE WHERE owner_npub = repeat('d', 64);" \
    "resolve every canonical choice first"

  assert_migration_059_refusal_case \
    "$database" "$migration" "descriptorless_surface" \
    "UPDATE donation_pages SET ct_descriptor = NULL WHERE nym = 'independent-page-owner' AND kind = 'payment_page';" \
    "descriptor-less surfaces violate the current contract"
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
      assert_migration_058_refuses_ambiguous_history "$database" "$migration"
    fi
    if [[ "$with_hooks" == "true" && "$base" == "059_remove_surface_alias" ]]; then
      assert_migration_059_refuses_drift_and_unresolved "$database" "$migration"
    fi
    if [[ "$base" == "053_recovery_address_commitments" \
       || "$base" == "054_fee_policy_authority" \
       || "$base" == "055_merchant_settlement_lifecycle" \
       || "$base" == "056_chain_swap_renegotiation_journal" \
       || "$base" == "057_chain_swap_cooperative_signing_operations" \
       || "$base" == "058_permanent_public_names" \
       || "$base" == "059_remove_surface_alias" \
       || "$base" == "060_lnurl_private_comment_intents" \
       || "$base" == "061_invoice_quote_versions" ]]; then
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

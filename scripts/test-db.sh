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
CONTAINER="bullnym-test-pg-${USER:-user}-$$-${RANDOM}"
FRESH_DB="bullnym_fresh"
UPGRADE_DB="bullnym_upgrade"
MODE="all"
FILTER=""
KEEP=0
STARTED=0

usage() {
  cat <<'USAGE'
Usage: scripts/test-db.sh [options] [test-filter]

Options:
  --mode fresh|upgrade|all  Select migration/test lanes (default: all).
  --filter NAME             Pass one test-name filter to cargo test.
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

command -v docker >/dev/null || die "docker is required"
docker info >/dev/null 2>&1 || die "docker daemon is unavailable"

cleanup() {
  local status=$?
  trap - EXIT
  if ((STARTED == 1)); then
    if ((status != 0)); then
      echo "test-db: PostgreSQL log tail after failure:" >&2
      docker logs --tail 50 "$CONTAINER" >&2 || true
    fi
    if ((KEEP == 1)); then
      echo "test-db: kept container $CONTAINER (host port ${HOST_PORT:-unknown})"
    else
      docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
      echo "test-db: removed container $CONTAINER"
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
  docker exec --interactive "$CONTAINER" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$PG_USER" --dbname "$database" \
    < "$file" >/dev/null
}

apply_migrations() {
  local database="$1"
  local with_hooks="$2"
  local count=0
  local migration base before after

  for migration in migrations/*.sql; do
    base="$(basename "$migration" .sql)"
    before="tests/migration-hooks/${base}.before.sql"
    after="tests/migration-hooks/${base}.after.sql"
    if [[ "$with_hooks" == "true" && -f "$before" ]]; then
      echo "test-db: applying pre-migration fixture $before"
      run_sql_file "$database" "$before"
    fi
    run_sql_file "$database" "$migration"
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
  local -a args=(test --test integration_test)
  if [[ -n "$FILTER" ]]; then
    args+=("$FILTER")
  fi
  args+=(-- --test-threads=1)
  echo "test-db: running serial integration suite against $database"
  TEST_DATABASE_URL="$(db_url "$database")" cargo "${args[@]}"
}

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

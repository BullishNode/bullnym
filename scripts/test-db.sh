#!/usr/bin/env bash
# DB integration tests, self-contained: throwaway Postgres in Docker,
# all migrations applied fresh, suite run single-threaded.
#
#   ./scripts/test-db.sh            run the integration suite
#   ./scripts/test-db.sh --keep     leave the container running afterwards
#   ./scripts/test-db.sh <filter>   pass a cargo test name filter
#
# Single-threaded is required, not a preference: every test calls
# cleanup_db() against the shared database, so parallel tests destroy
# each other's fixtures (symptom: dozens of failures that all pass in
# isolation). Migrations applying cleanly to an empty database is itself
# part of what this script verifies.
set -euo pipefail
cd "$(dirname "$0")/.."

CONTAINER=bullnym-testpg
PORT=15432
URL="postgres://postgres:test@127.0.0.1:${PORT}/bullnym_test"
KEEP=0
FILTER=""
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    *) FILTER="$arg" ;;
  esac
done

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  docker run -d --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=test -e POSTGRES_DB=bullnym_test \
    -p "127.0.0.1:${PORT}:5432" postgres:16-alpine >/dev/null
elif [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != "true" ]; then
  docker start "$CONTAINER" >/dev/null
fi

for _ in $(seq 1 30); do
  docker exec "$CONTAINER" pg_isready -U postgres -q && break
  sleep 1
done

# Fresh schema every run: migrations must apply cleanly to an empty DB.
docker exec "$CONTAINER" psql -U postgres -q -c \
  "DROP DATABASE IF EXISTS bullnym_test WITH (FORCE)" >/dev/null
docker exec "$CONTAINER" psql -U postgres -q -c \
  "CREATE DATABASE bullnym_test" >/dev/null

for f in migrations/*.sql; do
  psql "$URL" -q -1 -v ON_ERROR_STOP=1 -f "$f" >/dev/null
done
echo "applied $(ls migrations/*.sql | wc -l) migrations to fresh database"

TEST_DATABASE_URL="$URL" cargo test --test integration_test ${FILTER:+"$FILTER"} -- --test-threads=1

if [ "$KEEP" -eq 0 ]; then
  docker rm -f "$CONTAINER" >/dev/null
  echo "container removed (use --keep to reuse it)"
fi

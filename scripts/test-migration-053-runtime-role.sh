#!/usr/bin/env bash
# Focused real-PostgreSQL proof for migration 053's operator-supplied runtime
# role and the production boundary probe. This does not run application tests.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16}"
CONTAINER="bullnym-migration-053-role-${USER:-user}-$$-${RANDOM}"
PG_USER=bullnym_test
PG_PASSWORD=bullnym_test
STARTED=0
ENV_FILE=""
DATA_VOLUME=""

cleanup() {
  local status=$?
  trap - EXIT
  [[ -z "$ENV_FILE" ]] || rm -f "$ENV_FILE"
  if ((STARTED == 1)); then
    docker rm -fv "$CONTAINER" >/dev/null 2>&1 || status=1
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
      echo "migration-053 test: container cleanup verification failed" >&2
      status=1
    fi
    if [[ -n "$DATA_VOLUME" ]] \
        && docker volume inspect "$DATA_VOLUME" >/dev/null 2>&1; then
      echo "migration-053 test: anonymous volume cleanup verification failed" >&2
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

command -v docker >/dev/null
command -v psql >/dev/null
docker info >/dev/null 2>&1

docker run --detach \
  --name "$CONTAINER" \
  --env "POSTGRES_USER=$PG_USER" \
  --env "POSTGRES_PASSWORD=$PG_PASSWORD" \
  --env POSTGRES_DB=postgres \
  --publish 127.0.0.1::5432 \
  "$POSTGRES_IMAGE" >/dev/null
STARTED=1
DATA_VOLUME="$(
  docker inspect \
    --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}' \
    "$CONTAINER"
)"
[[ "$DATA_VOLUME" =~ ^[0-9a-f]{64}$ ]] || {
  echo "migration-053 test: could not resolve anonymous data volume" >&2
  exit 1
}

ready=0
ready_streak=0
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" \
      sh -c 'test "$(cat /proc/1/comm)" = postgres' \
      && docker exec "$CONTAINER" \
        pg_isready --quiet --username "$PG_USER" --dbname postgres; then
    ((ready_streak += 1))
    if ((ready_streak >= 3)); then
      ready=1
      break
    fi
  else
    ready_streak=0
  fi
  sleep 0.5
done
((ready == 1)) || { echo "migration-053 test: PostgreSQL did not become ready" >&2; exit 1; }

HOST_PORT="$(
  docker inspect \
    --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' \
    "$CONTAINER"
)"
[[ "$HOST_PORT" =~ ^[0-9]+$ ]]

admin_sql() {
  local database="$1"
  local sql="$2"
  docker exec "$CONTAINER" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 \
      --username "$PG_USER" --dbname "$database" --command "$sql" >/dev/null
}

admin_sql postgres "
  CREATE ROLE migration_owner NOLOGIN;
  GRANT migration_owner TO $PG_USER;
  CREATE ROLE bullnym_app LOGIN PASSWORD 'bullnym_app';
  CREATE ROLE runtime_superuser SUPERUSER NOLOGIN;
"
docker exec "$CONTAINER" createdb \
  --username "$PG_USER" --owner migration_owner baseline_052

for migration in migrations/*.sql; do
  [[ "$(basename "$migration")" == "053_recovery_address_commitments.sql" ]] && break
  docker exec --interactive "$CONTAINER" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 \
      --username "$PG_USER" --dbname baseline_052 \
      --command 'SET ROLE migration_owner' --file=- \
    <"$migration" >/dev/null
done

create_case() {
  docker exec "$CONTAINER" createdb \
    --username "$PG_USER" --owner migration_owner \
    --template baseline_052 "$1"
}

run_migration() {
  local database="$1"
  local runtime_role="${2-__missing__}"
  local -a command=(
    docker exec --interactive "$CONTAINER"
    psql --no-psqlrc --set ON_ERROR_STOP=1
    --username "$PG_USER" --dbname "$database"
    --command "SET ROLE migration_owner"
  )
  if [[ "$runtime_role" != "__missing__" ]]; then
    command+=(--set "runtime_role=$runtime_role")
  fi
  command+=(--file=-)
  "${command[@]}" <migrations/053_recovery_address_commitments.sql
}

assert_no_053_mutation() {
  local database="$1"
  local intact
  intact="$(
    docker exec "$CONTAINER" \
      psql --no-psqlrc --set ON_ERROR_STOP=1 \
        --username "$PG_USER" --dbname "$database" \
        --tuples-only --no-align --command "
          SELECT (
              to_regclass('public.recovery_address_commitments') IS NULL
              AND to_regclass('public.migration_053_injected') IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public'
                     AND table_name = 'chain_swap_records'
                     AND column_name = 'recovery_address_commitment_id'
              )
          )::INT
        "
  )"
  [[ "$intact" == "1" ]] || {
    echo "migration-053 test: refusal mutated schema in $database" >&2
    exit 1
  }
}

expect_refusal() {
  local name="$1"
  local runtime_role="${2-__missing__}"
  local database="refuse_$name"
  local log
  log="$(mktemp)"
  create_case "$database"
  if run_migration "$database" "$runtime_role" >"$log" 2>&1; then
    echo "migration-053 test: $name unexpectedly succeeded" >&2
    rm -f "$log"
    exit 1
  fi
  assert_no_053_mutation "$database"
  rm -f "$log"
  echo "migration-053 test: $name refusal preserved pre-053 schema"
}

expect_refusal missing
expect_refusal empty ''
expect_refusal nonexistent does_not_exist
expect_refusal injection "bullnym_app'; CREATE TABLE migration_053_injected(value int); --"
expect_refusal same_role migration_owner
expect_refusal superuser runtime_superuser

admin_sql postgres 'GRANT migration_owner TO bullnym_app'
expect_refusal owner_membership bullnym_app
admin_sql postgres 'REVOKE migration_owner FROM bullnym_app'

create_case success
run_migration success bullnym_app >/dev/null

ENV_FILE="$(mktemp)"
printf 'DATABASE_URL=postgres://bullnym_app:bullnym_app@127.0.0.1:%s/success\n' \
  "$HOST_PORT" >"$ENV_FILE"
printf 'SWAP_MNEMONIC=must-not-reach-psql\n' >>"$ENV_FILE"
chmod 600 "$ENV_FILE"

scripts/check-migration-053-boundary.sh "$ENV_FILE" bullnym_app success >/dev/null

chmod 640 "$ENV_FILE"
if scripts/check-migration-053-boundary.sh \
    "$ENV_FILE" bullnym_app success >/dev/null 2>&1; then
  echo "migration-053 test: probe accepted a group-readable environment" >&2
  exit 1
fi
chmod 600 "$ENV_FILE"

if scripts/check-migration-053-boundary.sh \
    "$ENV_FILE" wrong_runtime success >/dev/null 2>&1; then
  echo "migration-053 test: probe accepted the wrong runtime role" >&2
  exit 1
fi
if scripts/check-migration-053-boundary.sh \
    "$ENV_FILE" bullnym_app wrong_database >/dev/null 2>&1; then
  echo "migration-053 test: probe accepted the wrong database" >&2
  exit 1
fi

# Advance the same empty disposable database through the 058 stopped-writer
# preflight first. Migration 058 deliberately creates no compatibility or
# review objects; its exact intermediate boundary is an empty database with the
# pre-cutover surface columns still present.
for later_migration in \
  migrations/054_fee_policy_authority.sql \
  migrations/055_merchant_settlement_lifecycle.sql \
  migrations/056_chain_swap_renegotiation_journal.sql \
  migrations/057_chain_swap_cooperative_signing_operations.sql \
  migrations/058_permanent_public_names.sql; do
  docker exec --interactive "$CONTAINER" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 \
      --username "$PG_USER" --dbname success \
      --command 'SET ROLE migration_owner' \
      --set runtime_role=bullnym_app --file=- \
    <"$later_migration" >/dev/null
done

# The historical bootstrap migrations granted application access to the old
# role name. Model the production role handoff so the operator probe itself is
# exercised as the supplied current runtime role.
admin_sql success "
  GRANT SELECT ON users, donation_pages, invoices, swap_records,
    chain_swap_records, outpoint_addresses, swap_key_allocations,
    swap_key_legacy_high_water, recovery_address_commitments,
    rate_limit_events, nym_access_events, processed_webhook_events,
    watcher_lane_progress, fee_last_known_good_observations
  TO bullnym_app;
"

migration_058_probe="$(
  scripts/check-migration-058-boundary.sh \
    "$ENV_FILE" bullnym_app success
)"
[[ "$migration_058_probe" == *"migration 058 boundary verified"* ]] || {
  echo "migration-058 test: stopped-writer preflight boundary was not verified" >&2
  exit 1
}

admin_sql success "
  INSERT INTO users (nym, npub, ct_descriptor)
  VALUES ('precutover', repeat('1', 64), 'descriptor');
"
if scripts/check-migration-058-boundary.sh \
    "$ENV_FILE" bullnym_app success >/dev/null 2>&1; then
  echo "migration-058 test: probe accepted nonempty source state" >&2
  exit 1
fi
if docker exec --interactive "$CONTAINER" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 \
      --username "$PG_USER" --dbname success \
      --command 'SET ROLE migration_owner' \
      --set runtime_role=bullnym_app --file=- \
    <migrations/059_remove_surface_alias.sql >/dev/null 2>&1; then
  echo "migration-059 test: nonempty cutover unexpectedly succeeded" >&2
  exit 1
fi
nonempty_refusal_intact="$(
  docker exec "$CONTAINER" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 \
      --username "$PG_USER" --dbname success \
      --tuples-only --no-align --command "
        SELECT (
          to_regclass('public.public_names') IS NULL
          AND EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = 'donation_pages'
               AND column_name = 'alias'
          )
        )::INT
      "
)"
[[ "$nonempty_refusal_intact" == "1" ]] || {
  echo "migration-059 test: nonempty refusal mutated the pre-cutover schema" >&2
  exit 1
}
admin_sql success "DELETE FROM users WHERE nym = 'precutover';"
scripts/check-migration-058-boundary.sh \
  "$ENV_FILE" bullnym_app success >/dev/null

# Complete the stopped-writer cutover and then the private-comment schema.
for later_migration in \
  migrations/059_remove_surface_alias.sql \
  migrations/060_lnurl_private_comment_intents.sql \
  migrations/061_invoice_quote_versions.sql \
  migrations/062_invoice_quote_provider_attempts.sql \
  migrations/063_checkout_private_memo.sql \
  migrations/064_wallet_backup_blobs.sql \
  migrations/065_private_invoice_presentations.sql \
  migrations/066_get_paid_transaction_history.sql \
  migrations/067_bull_bitcoin_fiat_settlement.sql; do
  docker exec --interactive "$CONTAINER" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 \
      --username "$PG_USER" --dbname success \
      --command 'SET ROLE migration_owner' \
      --set runtime_role=bullnym_app --file=- \
    <"$later_migration" >/dev/null
done

if scripts/check-migration-058-boundary.sh \
    "$ENV_FILE" bullnym_app success >/dev/null 2>&1; then
  echo "migration-058 test: exact preflight probe accepted the 059 cutover" >&2
  exit 1
fi

migration_059_probe="$(
  scripts/check-migration-059-boundary.sh \
    "$ENV_FILE" bullnym_app success
)"
[[ "$migration_059_probe" == *"migration 059 boundary verified"* ]] || {
  echo "migration-059 test: complete deploy boundary was not verified" >&2
  exit 1
}

admin_sql success "
  SET ROLE migration_owner;
  ALTER TABLE public_names DISABLE TRIGGER public_names_reject_mutation;
"
if scripts/check-migration-059-boundary.sh \
    "$ENV_FILE" bullnym_app success >/dev/null 2>&1; then
  echo "migration-059 test: probe accepted a disabled immutability guard" >&2
  exit 1
fi
admin_sql success "
  SET ROLE migration_owner;
  ALTER TABLE public_names ENABLE TRIGGER public_names_reject_mutation;
"
scripts/check-migration-059-boundary.sh \
  "$ENV_FILE" bullnym_app success >/dev/null

admin_sql success "
  SET ROLE migration_owner;
  GRANT UPDATE ON public_names TO bullnym_app;
"
if scripts/check-migration-059-boundary.sh \
    "$ENV_FILE" bullnym_app success >/dev/null 2>&1; then
  echo "migration-059 test: probe accepted runtime UPDATE authority" >&2
  exit 1
fi
admin_sql success "
  SET ROLE migration_owner;
  REVOKE UPDATE ON public_names FROM bullnym_app;
  GRANT INSERT (id) ON public_names TO bullnym_app;
"
if scripts/check-migration-059-boundary.sh \
    "$ENV_FILE" bullnym_app success >/dev/null 2>&1; then
  echo "migration-059 test: probe accepted runtime id insertion" >&2
  exit 1
fi
admin_sql success "
  SET ROLE migration_owner;
  REVOKE INSERT (id) ON public_names FROM bullnym_app;
  GRANT EXECUTE ON FUNCTION reject_public_name_mutation() TO bullnym_app;
"
if scripts/check-migration-059-boundary.sh \
    "$ENV_FILE" bullnym_app success >/dev/null 2>&1; then
  echo "migration-059 test: probe accepted trigger-function execution authority" >&2
  exit 1
fi
admin_sql success "
  SET ROLE migration_owner;
  REVOKE EXECUTE ON FUNCTION reject_public_name_mutation() FROM bullnym_app;
"
scripts/check-migration-059-boundary.sh \
  "$ENV_FILE" bullnym_app success >/dev/null

admin_sql success "
  SET ROLE migration_owner;
  ALTER TABLE donation_pages ADD COLUMN alias TEXT;
"
if scripts/check-migration-059-boundary.sh \
    "$ENV_FILE" bullnym_app success >/dev/null 2>&1; then
  echo "migration-059 test: probe accepted restored mutable alias authority" >&2
  exit 1
fi
admin_sql success "
  SET ROLE migration_owner;
  ALTER TABLE donation_pages DROP COLUMN alias;
"
scripts/check-migration-059-boundary.sh \
  "$ENV_FILE" bullnym_app success >/dev/null

admin_sql success "
  SET ROLE migration_owner;
  ALTER TABLE donation_pages ADD COLUMN pos_mode BOOLEAN;
"
if scripts/check-migration-059-boundary.sh \
    "$ENV_FILE" bullnym_app success >/dev/null 2>&1; then
  echo "migration-059 test: probe accepted restored pos_mode authority" >&2
  exit 1
fi
admin_sql success "
  SET ROLE migration_owner;
  ALTER TABLE donation_pages DROP COLUMN pos_mode;
"
scripts/check-migration-059-boundary.sh \
  "$ENV_FILE" bullnym_app success >/dev/null

admin_sql success "
  SET ROLE migration_owner;
  DROP TRIGGER chain_swap_records_reject_recovery_commitment_update
    ON chain_swap_records;
  CREATE TRIGGER chain_swap_records_reject_recovery_commitment_update
    BEFORE UPDATE OF recovery_address_commitment_id ON chain_swap_records
    FOR EACH ROW EXECUTE FUNCTION reject_chain_swap_recovery_commitment_mutation();
"
if scripts/check-migration-053-boundary.sh \
    "$ENV_FILE" bullnym_app success >/dev/null 2>&1; then
  echo "migration-053 test: probe accepted an incomplete UPDATE OF boundary" >&2
  exit 1
fi

echo "migration-053/061 test: runtime-role refusals and privileged bootstrap passed"

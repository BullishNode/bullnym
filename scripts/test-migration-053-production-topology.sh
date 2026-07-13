#!/usr/bin/env bash
# Rehearse the production ownership boundary for migration 053. Historical
# migrations belong to the Bullnym runtime role; 053 must be applied by a
# distinct privileged owner while granting the runtime only append/read access
# to the new private ledger.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16}"
RUNTIME_ROLE="bullnym_app"
RUNTIME_PASSWORD="bullnym-topology-test"
DATABASE_NAME="bullnym"
ADMIN_ROLE="postgres"
ADMIN_PASSWORD="bullnym-topology-admin"
CONTAINER="bullnym-053-topology-${USER:-user}-$$-${RANDOM}"
STARTED=0
DATA_VOLUME=""
RUNTIME_ENV_FILE=""

die() {
  echo "migration-053-topology: $*" >&2
  exit 1
}

cleanup() {
  local status=$?
  local cleanup_failed=0
  trap - EXIT
  if [[ -n "$RUNTIME_ENV_FILE" ]]; then
    rm -f "$RUNTIME_ENV_FILE"
  fi
  if ((STARTED == 1)); then
    if ((status != 0)); then
      docker logs --tail 50 "$CONTAINER" >&2 || true
    fi
    docker rm -fv "$CONTAINER" >/dev/null 2>&1 || cleanup_failed=1
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
      echo "migration-053-topology: container cleanup verification failed" >&2
      cleanup_failed=1
    fi
    if [[ -n "$DATA_VOLUME" ]] && docker volume inspect "$DATA_VOLUME" >/dev/null 2>&1; then
      echo "migration-053-topology: anonymous data-volume cleanup verification failed" >&2
      cleanup_failed=1
    fi
    if ((cleanup_failed == 0)); then
      echo "migration-053-topology: verified container and anonymous data-volume cleanup"
    else
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

command -v docker >/dev/null || die "docker is required"
command -v psql >/dev/null || die "the PostgreSQL client is required"
docker info >/dev/null 2>&1 || die "docker daemon is unavailable"

docker run --detach \
  --name "$CONTAINER" \
  --env "POSTGRES_PASSWORD=$ADMIN_PASSWORD" \
  --publish 127.0.0.1::5432 \
  "$POSTGRES_IMAGE" >/dev/null
STARTED=1

DATA_VOLUME="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}' "$CONTAINER")"
[[ "$DATA_VOLUME" =~ ^[0-9a-f]{64}$ ]] \
  || die "could not resolve the anonymous PostgreSQL data volume"

ready=0
ready_streak=0
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" sh -c 'test "$(cat /proc/1/comm)" = postgres' \
      && docker exec "$CONTAINER" pg_isready --quiet --username "$ADMIN_ROLE" --dbname postgres; then
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
((ready == 1)) || die "PostgreSQL did not remain ready within 30 seconds"

HOST_PORT="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "$CONTAINER")"
[[ "$HOST_PORT" =~ ^[0-9]+$ ]] || die "could not resolve the published PostgreSQL port"

admin_psql() {
  docker exec --interactive \
    --env "PGPASSWORD=$ADMIN_PASSWORD" \
    "$CONTAINER" psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --host 127.0.0.1 --username "$ADMIN_ROLE" --dbname "$DATABASE_NAME" "$@"
}

runtime_psql() {
  docker exec --interactive \
    --env "PGPASSWORD=$RUNTIME_PASSWORD" \
    "$CONTAINER" psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --host 127.0.0.1 --username "$RUNTIME_ROLE" --dbname "$DATABASE_NAME" "$@"
}

docker exec \
  --env "PGPASSWORD=$ADMIN_PASSWORD" \
  "$CONTAINER" psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --host 127.0.0.1 --username "$ADMIN_ROLE" --dbname postgres \
  --command "CREATE ROLE $RUNTIME_ROLE LOGIN PASSWORD '$RUNTIME_PASSWORD'" >/dev/null
docker exec \
  --env "PGPASSWORD=$ADMIN_PASSWORD" \
  "$CONTAINER" createdb \
  --host 127.0.0.1 --username "$ADMIN_ROLE" --owner "$RUNTIME_ROLE" \
  "$DATABASE_NAME"

migration_count=0
for migration in migrations/*.sql; do
  migration_version="$(basename "$migration" | cut -d_ -f1)"
  if ((10#$migration_version >= 53)); then
    break
  fi
  runtime_psql <"$migration" >/dev/null
  ((migration_count += 1))
done
[[ "$migration_count" == "52" ]] \
  || die "expected the runtime role to apply 52 historical migrations, got $migration_count"

wrong_historical_owner_count="$(admin_psql --tuples-only --no-align --command "
  SELECT COUNT(*)
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
   WHERE namespace.nspname = 'public'
     AND relation.relkind IN ('r', 'p', 'S', 'v', 'm')
     AND pg_get_userbyid(relation.relowner) <> '$RUNTIME_ROLE'
")"
[[ "$wrong_historical_owner_count" == "0" ]] \
  || die "migrations 001-052 left $wrong_historical_owner_count public relations outside runtime ownership"

if [[ "$(admin_psql --tuples-only --no-align --command \
  "SELECT to_regrole('payservice') IS NULL")" != "t" ]]; then
  die "historical rehearsal unexpectedly created the obsolete payservice database role"
fi

admin_psql --set runtime_role="$RUNTIME_ROLE" \
  <migrations/053_recovery_address_commitments.sql >/dev/null

IFS='|' read -r database_name connected_role ledger_owner can_select can_insert \
  can_update can_delete can_truncate can_references can_trigger runtime_is_owner \
  obsolete_role_absent runtime_inherits_owner <<EOF
$(runtime_psql --tuples-only --no-align --field-separator '|' --command "
  SELECT current_database(),
         current_user,
         pg_get_userbyid(ledger.relowner),
         has_table_privilege(current_user, ledger.oid, 'SELECT'),
         has_table_privilege(current_user, ledger.oid, 'INSERT'),
         has_table_privilege(current_user, ledger.oid, 'UPDATE'),
         has_table_privilege(current_user, ledger.oid, 'DELETE'),
         has_table_privilege(current_user, ledger.oid, 'TRUNCATE'),
         has_table_privilege(current_user, ledger.oid, 'REFERENCES'),
         has_table_privilege(current_user, ledger.oid, 'TRIGGER'),
         ledger.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user),
         to_regrole('payservice') IS NULL,
         pg_has_role(current_user, pg_get_userbyid(ledger.relowner), 'MEMBER')
    FROM pg_class ledger
   WHERE ledger.oid = 'public.recovery_address_commitments'::REGCLASS
")
EOF

[[ "$database_name" == "$DATABASE_NAME" ]] \
  || die "runtime probe selected database '$database_name', expected '$DATABASE_NAME'"
[[ "$connected_role" == "$RUNTIME_ROLE" ]] \
  || die "runtime probe selected role '$connected_role', expected '$RUNTIME_ROLE'"
[[ -n "$ledger_owner" && "$ledger_owner" != "$RUNTIME_ROLE" ]] \
  || die "migration 053 ledger owner was not distinct from the runtime role"
[[ "$can_select|$can_insert" == "t|t" ]] \
  || die "runtime role lacks exact SELECT/INSERT ledger access"
[[ "$can_update|$can_delete|$can_truncate|$can_references|$can_trigger" == "f|f|f|f|f" ]] \
  || die "runtime role retained mutation or ownership-adjacent ledger privileges"
[[ "$runtime_is_owner|$obsolete_role_absent|$runtime_inherits_owner" == "f|t|f" ]] \
  || die "runtime ownership, obsolete-role, or role-membership boundary is unsafe"

RUNTIME_ENV_FILE="$(mktemp)"
chmod 600 "$RUNTIME_ENV_FILE"
printf 'DATABASE_URL=postgres://%s:%s@127.0.0.1:%s/%s\n' \
  "$RUNTIME_ROLE" "$RUNTIME_PASSWORD" "$HOST_PORT" "$DATABASE_NAME" \
  >"$RUNTIME_ENV_FILE"
[[ "$(stat --format '%a' "$RUNTIME_ENV_FILE")" == "600" ]] \
  || die "disposable runtime environment did not retain mode 0600"

probe_output="$(
  scripts/check-migration-053-boundary.sh \
    "$RUNTIME_ENV_FILE" "$RUNTIME_ROLE" "$DATABASE_NAME"
)"
[[ "$probe_output" == \
   "migration 053 boundary verified for runtime role $RUNTIME_ROLE on database $DATABASE_NAME" ]] \
  || die "deploy probe did not bind the exact production role/database"
[[ "$probe_output" != *"$RUNTIME_PASSWORD"* && "$probe_output" != *'postgres://'* ]] \
  || die "deploy probe exposed the runtime connection string"
if scripts/check-migration-053-boundary.sh \
    "$RUNTIME_ENV_FILE" payservice "$DATABASE_NAME" >/dev/null 2>&1; then
  die "deploy probe accepted the obsolete payservice database role"
fi
if scripts/check-migration-053-boundary.sh \
    "$RUNTIME_ENV_FILE" "$RUNTIME_ROLE" payservice >/dev/null 2>&1; then
  die "deploy probe accepted the obsolete payservice database name"
fi

admin_psql --command \
  "GRANT UPDATE ON recovery_address_commitments TO $RUNTIME_ROLE" >/dev/null
if scripts/check-migration-053-boundary.sh \
    "$RUNTIME_ENV_FILE" "$RUNTIME_ROLE" "$DATABASE_NAME" >/dev/null 2>&1; then
  die "deploy probe accepted runtime UPDATE drift"
fi
admin_psql --command \
  "REVOKE UPDATE ON recovery_address_commitments FROM $RUNTIME_ROLE" >/dev/null
restored_probe_output="$(
  scripts/check-migration-053-boundary.sh \
    "$RUNTIME_ENV_FILE" "$RUNTIME_ROLE" "$DATABASE_NAME"
)"
[[ "$restored_probe_output" == "$probe_output" ]] \
  || die "deploy probe did not recover after exact ACL restoration"

runtime_psql --command "
  INSERT INTO users (nym, npub, ct_descriptor, is_active)
  VALUES (
      'production-topology-runtime',
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      'production-topology-runtime',
      TRUE
  );
  INSERT INTO recovery_address_commitments (
      commitment_id, npub, contract_format_version, commitment_version,
      canonical_btc_address, original_signature, signed_at_unix
  ) VALUES (
      '53000000-0000-0000-0000-000000000053',
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      1, 1, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', repeat('53', 64),
      1700000053
  );
  SELECT commitment_id
    FROM recovery_address_commitments
   WHERE commitment_id = '53000000-0000-0000-0000-000000000053';
" >/dev/null

if runtime_psql --command \
  "UPDATE recovery_address_commitments SET commitment_version = 2" \
  >/dev/null 2>&1; then
  die "runtime role unexpectedly updated the recovery ledger"
fi
if runtime_psql --command "DELETE FROM recovery_address_commitments" \
  >/dev/null 2>&1; then
  die "runtime role unexpectedly deleted from the recovery ledger"
fi

echo "migration-053-topology: production owner/runtime rehearsal passed"

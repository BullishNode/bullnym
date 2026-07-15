#!/usr/bin/env bash
# Generic Bullnym self-build layout: git pull → build → install. Current
# production uses the hosted-artifact runbook and different filesystem/unit
# paths; see docs/operations/deployment.md. Do not use this script there.
#   ./deploy.sh           verified binary + PWA deploy, migrations check, restart
# Pre-push gate: run `cd pwa && npm run check:dist`. This script deploys the
# committed dist only; it does not rebuild the PWA on the VM. nginx changes
# from docs/nginx-bullpay.conf.snippet are applied manually with nginx -T,
# nginx -t, then reload.
set -euo pipefail

if (($# != 0)); then
  echo "usage: $0" >&2
  echo "PWA-only deploys are unsupported because they invalidate embedded release provenance." >&2
  exit 2
fi

REPO=$HOME/src/bullnym
APP=/opt/payservice
RUNTIME_ENV_FILE=/etc/bullnym/bullnym.env
RUNTIME_DB_ROLE=bullnym_app
RUNTIME_DATABASE=bullnym
source "$HOME/.cargo/env"

cd "$REPO"
git fetch origin
git reset --hard origin/main
echo "deploying $(git log --oneline -1)"

stage_pwa() {
  sudo rm -rf "$APP/pwa/dist.new"
  sudo install -d -o root -g root -m 755 "$APP/pwa/dist.new"
  sudo cp -a "$REPO/pwa/dist/." "$APP/pwa/dist.new/"
  sudo chown -R root:root "$APP/pwa/dist.new"
  sudo find "$APP/pwa/dist.new" -type d -exec chmod 755 {} +
  sudo find "$APP/pwa/dist.new" -type f -exec chmod 644 {} +
}

binary_switch_started=0
pwa_switch_started=0
rollback_writer_stopped=0
compatibility_writer_stopped=0
compatibility_writer_was_active=0
ready_response="$(mktemp)"
version_response="$(mktemp)"
candidate_build_info="$(mktemp)"
previous_build_info="$(mktemp)"

build_info_schema_marker() {
  python3 - "$1" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
marker = payload.get("expected_schema_marker")
if not isinstance(marker, str) or not marker:
    raise SystemExit("build info has no expected_schema_marker")
print(marker)
PY
}

runtime_guard_count() {
  local query_kind="$1"
  sudo -n bash -s -- \
    "$RUNTIME_ENV_FILE" "$RUNTIME_DB_ROLE" "$RUNTIME_DATABASE" \
    "$query_kind" <<'ROOT'
set -euo pipefail
env_file="$1"
expected_role="$2"
expected_database="$3"
query_kind="$4"
[[ -f "$env_file" && ! -L "$env_file" && -O "$env_file" && -r "$env_file" ]]
env_mode="$(stat --format='%a' "$env_file")"
(( (8#$env_mode & 077) == 0 ))
safe_home="${HOME:-/root}"
safe_path="$PATH"
psql_bin="$(command -v psql)"
python_bin="$(command -v python3)"
# shellcheck disable=SC1090
source "$env_file"
[[ -n "${DATABASE_URL:-}" ]]
database_url="$DATABASE_URL"
unset DATABASE_URL

connection_fields=()
mapfile -d '' -t connection_fields < <(
  env -i DATABASE_URL="$database_url" "$python_bin" <<'PY'
import os
import sys
import urllib.parse

url = urllib.parse.urlsplit(os.environ["DATABASE_URL"])
if url.scheme not in {"postgres", "postgresql"} or url.hostname is None or url.username is None:
    raise SystemExit("invalid DATABASE_URL authority")
port = str(url.port or 5432)
database = urllib.parse.unquote(url.path.removeprefix("/"))
if not database:
    raise SystemExit("DATABASE_URL has no database")
allowed = {
    "sslmode": "", "sslrootcert": "", "sslcert": "", "sslkey": "",
    "channel_binding": "", "target_session_attrs": "",
}
query = urllib.parse.parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
if set(query) - set(allowed) or any(len(values) != 1 for values in query.values()):
    raise SystemExit("unsupported DATABASE_URL parameters")
for key, values in query.items():
    allowed[key] = values[0]
values = [
    url.hostname, port, urllib.parse.unquote(url.username),
    urllib.parse.unquote(url.password or ""), database, allowed["sslmode"],
    allowed["sslrootcert"], allowed["sslcert"], allowed["sslkey"],
    allowed["channel_binding"], allowed["target_session_attrs"],
]
if any("\n" in value or "\x00" in value for value in values):
    raise SystemExit("invalid DATABASE_URL value")
sys.stdout.buffer.write(b"\x00".join(value.encode() for value in values) + b"\x00")
PY
)
unset database_url
(( ${#connection_fields[@]} == 11 ))
libpq_environment=(
  "PGHOST=${connection_fields[0]}" "PGPORT=${connection_fields[1]}"
  "PGUSER=${connection_fields[2]}" "PGPASSWORD=${connection_fields[3]}"
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

identity="$(
  clean_psql --no-psqlrc --no-password --set ON_ERROR_STOP=1 \
    --tuples-only --no-align --field-separator='|' \
    --command 'SELECT current_user, current_database()'
)"
IFS='|' read -r actual_role actual_database extra <<<"$identity"
[[ -z "${extra:-}" && "$actual_role" == "$expected_role" \
   && "$actual_database" == "$expected_database" ]]

case "$query_kind" in
  direct-transition-history)
    relation_query="SELECT COALESCE(to_regclass('public.invoice_direct_payment_transitions')::TEXT, '')"
    count_query='SELECT COUNT(*) FROM public.invoice_direct_payment_transitions'
    missing_relation_count=0
    ;;
  cooperative-signing-nonterminal)
    relation_query="SELECT COALESCE(to_regclass('public.chain_swap_cooperative_signing_operations')::TEXT, '')"
    count_query="SELECT COUNT(*) FROM public.chain_swap_cooperative_signing_operations WHERE state IN ('prepared', 'requested', 'ambiguous', 'response_received')"
    missing_relation_count=
    ;;
  *)
    exit 1
    ;;
esac

relation="$(
  clean_psql --no-psqlrc --no-password --set ON_ERROR_STOP=1 \
    --tuples-only --no-align --command "$relation_query"
)"
if [[ -z "$relation" ]]; then
  if [[ -n "$missing_relation_count" ]]; then
    echo "$missing_relation_count"
    exit 0
  fi
  exit 1
fi
count="$(
  clean_psql --no-psqlrc --no-password --set ON_ERROR_STOP=1 \
    --tuples-only --no-align --command "$count_query"
)"
[[ "$count" =~ ^[0-9]+$ ]]
echo "$count"
ROOT
}

direct_transition_history_count() {
  runtime_guard_count direct-transition-history
}

cooperative_nonterminal_count() {
  runtime_guard_count cooperative-signing-nonterminal
}

require_no_nonterminal_cooperative_operations() {
  local context="$1" count
  count="$(cooperative_nonterminal_count)" || {
    echo "$context refused: cooperative-signing state could not be inspected" >&2
    return 1
  }
  [[ "$count" =~ ^[0-9]+$ ]] || {
    echo "$context refused: cooperative-signing state could not be inspected" >&2
    return 1
  }
  if ((10#$count != 0)); then
    echo "$context refused: a nonterminal cooperative-signing operation still binds the current runtime" >&2
    return 1
  fi
}

migration_053_boundary_ready() {
  sudo -n "$REPO/scripts/check-migration-053-boundary.sh" \
    "$RUNTIME_ENV_FILE" "$RUNTIME_DB_ROLE" "$RUNTIME_DATABASE"
}

migration_055_boundary_ready() {
  sudo -n "$REPO/scripts/check-migration-055-boundary.sh" \
    "$RUNTIME_ENV_FILE" "$RUNTIME_DB_ROLE" "$RUNTIME_DATABASE"
}

migration_056_boundary_ready() {
  sudo -n "$REPO/scripts/check-migration-056-boundary.sh" \
    "$RUNTIME_ENV_FILE" "$RUNTIME_DB_ROLE" "$RUNTIME_DATABASE"
}

migration_057_boundary_ready() {
  sudo -n "$REPO/scripts/check-migration-057-boundary.sh" \
    "$RUNTIME_ENV_FILE" "$RUNTIME_DB_ROLE" "$RUNTIME_DATABASE"
}

migration_058_boundary_ready() {
  sudo -n "$REPO/scripts/check-migration-058-boundary.sh" \
    "$RUNTIME_ENV_FILE" "$RUNTIME_DB_ROLE" "$RUNTIME_DATABASE"
}

migration_059_boundary_ready() {
  sudo -n "$REPO/scripts/check-migration-059-boundary.sh" \
    "$RUNTIME_ENV_FILE" "$RUNTIME_DB_ROLE" "$RUNTIME_DATABASE"
}

automatic_binary_rollback_allowed() {
  local previous_schema candidate_schema previous_version candidate_version transition_count
  [[ -s "$previous_build_info" && -s "$candidate_build_info" ]] || {
    echo "automatic rollback refused: missing previous/candidate build-info evidence" >&2
    return 1
  }
  previous_schema="$(build_info_schema_marker "$previous_build_info")" || return 1
  candidate_schema="$(build_info_schema_marker "$candidate_build_info")" || return 1
  previous_version="${previous_schema%%_*}"
  candidate_version="${candidate_schema%%_*}"

  if [[ "$candidate_version" =~ ^[0-9]+$ ]] \
      && ((10#$candidate_version >= 53)) \
      && { [[ ! "$previous_version" =~ ^[0-9]+$ ]] \
           || ((10#$previous_version < 53)); }; then
    echo "automatic rollback refused: migration 053 is a stopped-writer, roll-forward-only recovery-commitment boundary" >&2
    return 1
  fi

  if [[ "$candidate_version" =~ ^[0-9]+$ ]] \
      && ((10#$candidate_version >= 59)) \
      && { [[ ! "$previous_version" =~ ^[0-9]+$ ]] \
           || ((10#$previous_version < 59)); }; then
    echo "automatic rollback refused: migration 059 removes mutable per-surface alias authority" >&2
    return 1
  fi

  if [[ "$candidate_version" =~ ^[0-9]+$ ]] \
      && ((10#$candidate_version >= 55)) \
      && { [[ ! "$previous_version" =~ ^[0-9]+$ ]] \
           || ((10#$previous_version < 55)); }; then
    echo "automatic rollback refused: migration 055 is a roll-forward-only exact-settlement boundary" >&2
    return 1
  fi

  if [[ "$candidate_version" =~ ^[0-9]+$ ]] \
      && ((10#$candidate_version >= 56)) \
      && { [[ ! "$previous_version" =~ ^[0-9]+$ ]] \
           || ((10#$previous_version < 56)); }; then
    echo "automatic rollback refused: migration 056 is a roll-forward-only renegotiation-intent boundary" >&2
    return 1
  fi

  if [[ "$candidate_version" =~ ^[0-9]+$ ]] \
      && ((10#$candidate_version >= 57)) \
      && { [[ ! "$previous_version" =~ ^[0-9]+$ ]] \
           || ((10#$previous_version < 57)); }; then
    echo "automatic rollback refused: migration 057 is a roll-forward-only cooperative-signing-intent boundary" >&2
    return 1
  fi

  if [[ "$candidate_version" =~ ^[0-9]+$ \
        && "$previous_version" =~ ^[0-9]+$ ]] \
      && ((10#$candidate_version >= 57 && 10#$previous_version >= 57)); then
    if ((rollback_writer_stopped != 1)); then
      echo "automatic rollback refused: candidate writer is not proven stopped for the cooperative-signing compatibility check" >&2
      return 1
    fi
    require_no_nonterminal_cooperative_operations "automatic rollback" \
      || return 1
  fi

  if [[ "$previous_schema" == "$candidate_schema" ]]; then
    transition_count=0
  elif [[ "$previous_schema" == "046_chain_swap_tx_attempts" \
       && "$candidate_schema" == "047_direct_payment_lifecycle_foundation" ]]; then
    transition_count="$(direct_transition_history_count)" || {
      echo "automatic rollback refused: could not inspect direct lifecycle history" >&2
      return 1
    }
  else
    transition_count=0
  fi

  "$REPO/scripts/check-direct-lifecycle-rollback.py" \
    "$previous_schema" "$candidate_schema" "$transition_count"
}

rollback_on_failure() {
  status=$?
  trap - EXIT
  set +e
  rollback_failed=0
  rm -f "$ready_response" "$version_response"
  if ((status != 0)); then
    if ((binary_switch_started == 0 \
          && compatibility_writer_stopped == 1 \
          && compatibility_writer_was_active == 1)); then
      if sudo systemctl start payservice; then
        compatibility_writer_stopped=0
      else
        rollback_failed=1
        echo "deployment failed before the binary switch and the prior writer could not be restarted" >&2
      fi
    fi
    rollback_allowed=1
    if ((binary_switch_started == 1)); then
      if sudo systemctl stop payservice \
          && ! sudo systemctl is-active --quiet payservice; then
        rollback_writer_stopped=1
      else
        rollback_allowed=0
        rollback_failed=1
        echo "deployment failed; automatic rollback refused because the candidate writer could not be stopped" >&2
      fi
      if ((rollback_allowed == 1)) \
          && ! automatic_binary_rollback_allowed; then
        rollback_allowed=0
        rollback_failed=1
        echo "deployment failed; automatic binary/PWA rollback refused; candidate files remain installed and the writer remains stopped for operator recovery" >&2
      fi
    fi
    if ((rollback_allowed == 1)); then
      echo "deployment failed; restoring previous binary and PWA" >&2
      if ((pwa_switch_started == 1)); then
        sudo rm -rf "$APP/pwa/dist" || rollback_failed=1
        if sudo test -d "$APP/pwa/dist.prev"; then
          sudo mv "$APP/pwa/dist.prev" "$APP/pwa/dist" || rollback_failed=1
        fi
      fi
      if ((binary_switch_started == 1)); then
        sudo rm -f "$APP/pay-service" || rollback_failed=1
        if sudo test -f "$APP/pay-service.prev"; then
          sudo mv "$APP/pay-service.prev" "$APP/pay-service" || rollback_failed=1
        fi
      fi
      if ((binary_switch_started == 1 || pwa_switch_started == 1)); then
        sudo systemctl restart payservice || rollback_failed=1
        restored_ready=0
        for _ in $(seq 1 15); do
          if curl --fail --silent --show-error --max-time 2 \
              http://127.0.0.1:8080/ready >/dev/null; then
            restored_ready=1
            break
          fi
          sleep 1
        done
        ((restored_ready == 1)) || rollback_failed=1
      fi
    fi
    if ((rollback_failed != 0)); then
      echo "WARNING: automatic rollback did not restore a ready service; operator action required" >&2
    fi
  fi
  rm -f "$candidate_build_info" "$previous_build_info"
  exit "$status"
}
trap rollback_on_failure EXIT

if [[ -f "$REPO/migrations/053_recovery_address_commitments.sql" ]]; then
  if ! migration_053_boundary_ready; then
    cat >&2 <<'EOF'
deployment refused before build: migration 053 is absent or its exact runtime boundary could not be verified.
Stop payservice and every database writer, then apply migration 053 with
psql --no-psqlrc --set ON_ERROR_STOP=1 --set runtime_role=bullnym_app as a
distinct privileged schema owner. Never apply migration 053 as bullnym_app.
Follow
docs/operations/deployment.md, including its pre- and post-migration checks,
then rerun this script.
EOF
    exit 1
  fi
  echo "migration 053 privileged-owner ACL/FK/trigger boundary verified through bullnym_app on bullnym"
fi
if [[ -f "$REPO/migrations/055_merchant_settlement_lifecycle.sql" ]]; then
  if ! migration_055_boundary_ready; then
    cat >&2 <<'EOF'
deployment refused before build: migration 055 is absent or its exact runtime boundary could not be verified.
Stop payservice and every database writer, apply migration 055 with
--set runtime_role=bullnym_app as the distinct privileged schema owner, and
resolve every zero-legacy claim-journal blocker without fabricating evidence.
Then rerun this script.
EOF
    exit 1
  fi
fi
if [[ -f "$REPO/migrations/056_chain_swap_renegotiation_journal.sql" ]]; then
  if ! migration_056_boundary_ready; then
    cat >&2 <<'EOF'
deployment refused before build: migration 056 is absent or its exact runtime boundary could not be verified.
Stop payservice and every database writer, apply migration 056 with
--set runtime_role=bullnym_app as the distinct privileged schema owner, then
rerun this script. Never fabricate operation rows for historical renegotiations.
EOF
    exit 1
  fi
fi
if [[ -f "$REPO/migrations/057_chain_swap_cooperative_signing_operations.sql" ]]; then
  if ! migration_057_boundary_ready; then
    cat >&2 <<'EOF'
deployment refused before build: migration 057 is absent or its exact runtime boundary could not be verified.
Stop payservice and every database writer, apply migration 057 with
--set runtime_role=bullnym_app as the distinct privileged schema owner, then
rerun this script. Never fabricate cooperative signing operation evidence.
EOF
    exit 1
  fi
fi
if [[ -f "$REPO/migrations/058_permanent_public_names.sql" \
   && ! -f "$REPO/migrations/059_remove_surface_alias.sql" ]]; then
  if ! migration_058_boundary_ready; then
    cat >&2 <<'EOF'
deployment refused before build: migration 058 is absent or its exact immutable public-name boundary could not be verified.
Stop every database writer, retain the documented pre-reset backup, and verify
that the fresh production database contains no users, surfaces, invoices,
swaps, allocations, returned-address history, or stale public-name objects.
Apply migration 058 with --set runtime_role=bullnym_app as the distinct
privileged schema owner. Keep writers stopped until migration 059 completes;
never bypass the empty-state refusal.
EOF
    exit 1
  fi
fi
if [[ -f "$REPO/migrations/059_remove_surface_alias.sql" ]]; then
  if ! migration_059_boundary_ready; then
    cat >&2 <<'EOF'
deployment refused before build: migration 059 is absent or mutable per-surface alias authority remains.
Keep payservice and every database writer stopped. Retain the documented final
pre-reset backup, reset production to an empty database, and apply the complete
migration sequence with --set runtime_role=bullnym_app as the distinct
privileged schema owner. Migrations 058 and 059 each revalidate the empty-state
boundary; 059 then creates the current five-column permanent-name registry,
requires surface descriptors, and removes the pre-launch alias/pos_mode
columns. Never bypass a nonempty-state, obsolete-object, descriptor, owner, or
runtime-ACL refusal.
EOF
    exit 1
  fi
fi
echo "NOTE: all migrations are applied manually using their documented ownership and stopped-writer boundaries."
ls -1 "$REPO"/migrations | tail -3 | sed 's/^/  latest in repo: /'

export CARGO_BUILD_JOBS=2
./scripts/build-release.sh

release_binary="$REPO/target/verified-release/pay-service"
release_record="$REPO/target/verified-release/pay-service.release.json"
./scripts/verify-release-record.sh "$release_record" "$release_binary" "$REPO"
"$release_binary" --build-info >"$candidate_build_info"
if sudo test -x "$APP/pay-service"; then
  sudo "$APP/pay-service" --build-info >"$previous_build_info"
else
  rm -f "$previous_build_info"
fi
artifact_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["artifact_sha256"])' "$release_record")"
[[ "$artifact_digest" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid release artifact digest" >&2; exit 1; }
expected_pwa_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["build"]["pwa_content_sha256"])' "$release_record")"
[[ "$expected_pwa_digest" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid release PWA digest" >&2; exit 1; }

sudo install -o root -g root -m 755 "$release_binary" "$APP/pay-service.new"
stage_pwa
staged_pwa_digest="$(./scripts/content-sha256.py "$APP/pwa/dist.new")"
[[ "$staged_pwa_digest" == "$expected_pwa_digest" ]] \
  || { echo "staged PWA digest does not match release record" >&2; exit 1; }

candidate_schema="$(build_info_schema_marker "$candidate_build_info")" \
  || { echo "candidate schema marker is unreadable" >&2; exit 1; }
candidate_schema_version="${candidate_schema%%_*}"
if [[ "$candidate_schema_version" =~ ^[0-9]+$ ]] \
    && ((10#$candidate_schema_version >= 57)); then
  if sudo systemctl is-active --quiet payservice; then
    compatibility_writer_was_active=1
  fi
  sudo systemctl stop payservice \
    || { echo "deployment refused: the current writer could not be stopped" >&2; exit 1; }
  if sudo systemctl is-active --quiet payservice; then
    echo "deployment refused: the current writer remains active" >&2
    exit 1
  fi
  compatibility_writer_stopped=1
  if ! require_no_nonterminal_cooperative_operations "deployment"; then
    if ((compatibility_writer_was_active == 1)) \
        && sudo systemctl start payservice; then
      compatibility_writer_stopped=0
    fi
    exit 1
  fi
fi

sudo rm -f "$APP/pay-service.prev"
if sudo test -f "$APP/pay-service"; then
  sudo mv "$APP/pay-service" "$APP/pay-service.prev"
fi
binary_switch_started=1
sudo mv "$APP/pay-service.new" "$APP/pay-service"

sudo rm -rf "$APP/pwa/dist.prev"
if sudo test -d "$APP/pwa/dist"; then
  sudo mv "$APP/pwa/dist" "$APP/pwa/dist.prev"
fi
pwa_switch_started=1
sudo mv "$APP/pwa/dist.new" "$APP/pwa/dist"
sudo systemctl restart payservice

ready=0
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error --max-time 2 \
      http://127.0.0.1:8080/ready >"$ready_response"; then
    ready=1
    break
  fi
  sleep 1
done
((ready == 1)) || { echo "deployed service did not become ready" >&2; exit 1; }
sudo systemctl is-active --quiet payservice
curl --fail --silent --show-error --max-time 2 \
  http://127.0.0.1:8080/health >/dev/null
curl --fail --silent --show-error --max-time 2 \
  http://127.0.0.1:8080/version >"$version_response"

main_pid="$(sudo systemctl show payservice --property MainPID --value)"
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]] || { echo "invalid payservice MainPID: $main_pid" >&2; exit 1; }
running_digest="$(sudo sha256sum "/proc/$main_pid/exe" | awk '{print $1}')"
deployed_pwa_digest="$(./scripts/content-sha256.py "$APP/pwa/dist")"
python3 - "$release_record" "$version_response" "$running_digest" "$deployed_pwa_digest" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text())
live = json.loads(pathlib.Path(sys.argv[2]).read_text())
running_digest, deployed_pwa_digest = sys.argv[3:]
if running_digest != record["artifact_sha256"]:
    raise SystemExit(
        f"running artifact digest {running_digest} does not match release record "
        f"{record['artifact_sha256']}"
    )
if deployed_pwa_digest != record["build"]["pwa_content_sha256"]:
    raise SystemExit(
        f"deployed PWA digest {deployed_pwa_digest} does not match release record "
        f"{record['build']['pwa_content_sha256']}"
    )
for field in ("service", "crate_version", "build_commit", "expected_schema_marker"):
    if live.get(field) != record["build"].get(field):
        raise SystemExit(
            f"live /version {field}={live.get(field)!r} does not match "
            f"release record {record['build'].get(field)!r}"
        )
if live.get("build_dirty") != "false":
    raise SystemExit(f"live /version reports build_dirty={live.get('build_dirty')!r}")
PY

release_commit="$(git rev-parse HEAD)"
history_record="$APP/releases/$release_commit-$artifact_digest.json"
sudo install -d -o root -g root -m 755 "$APP/releases"
if sudo test -e "$history_record"; then
  sudo cmp --silent "$release_record" "$history_record" \
    || { echo "conflicting immutable release record: $history_record" >&2; exit 1; }
else
  sudo install -o root -g root -m 644 "$release_record" "$history_record"
fi
sudo install -o root -g root -m 644 "$release_record" "$APP/release.json.new"
sudo mv "$APP/release.json.new" "$APP/release.json"
rm -f "$ready_response" "$version_response" \
  "$candidate_build_info" "$previous_build_info" || true
trap - EXIT
echo "verified release deployed: $release_commit ($artifact_digest)"

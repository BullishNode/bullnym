#!/usr/bin/env bash
# bullnym deploy: git pull → build → install. Run as debian on the prod VM.
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

direct_transition_history_count() {
  local relation count password
  password="$(<"$HOME/.pgpass_payservice")"
  relation="$(
    PGPASSWORD="$password" psql --no-psqlrc --set ON_ERROR_STOP=1 \
      --host 127.0.0.1 --username payservice --dbname payservice \
      --tuples-only --no-align \
      --command "SELECT COALESCE(to_regclass('public.invoice_direct_payment_transitions')::TEXT, '')"
  )" || return 1
  if [[ -z "$relation" ]]; then
    echo 0
    return 0
  fi
  count="$(
    PGPASSWORD="$password" psql --no-psqlrc --set ON_ERROR_STOP=1 \
      --host 127.0.0.1 --username payservice --dbname payservice \
      --tuples-only --no-align \
      --command "SELECT COUNT(*) FROM public.invoice_direct_payment_transitions"
  )" || return 1
  [[ "$count" =~ ^[0-9]+$ ]] || return 1
  echo "$count"
}

migration_053_boundary_ready() {
  local password ready
  [[ -r "$HOME/.pgpass_payservice" ]] || return 1
  password="$(<"$HOME/.pgpass_payservice")"
  ready="$(
    PGPASSWORD="$password" psql --no-psqlrc --set ON_ERROR_STOP=1 \
      --host 127.0.0.1 --username payservice --dbname payservice \
      --tuples-only --no-align \
      --command "WITH ledger AS ( \
          SELECT relation.oid, relation.relowner \
            FROM pg_class relation \
            JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
           WHERE namespace.nspname = 'public' \
             AND relation.relname = 'recovery_address_commitments' \
      ) \
      SELECT COALESCE(( \
          SELECT pg_get_userbyid(ledger.relowner) <> current_user \
             AND has_table_privilege(current_user, ledger.oid, 'SELECT') \
             AND has_table_privilege(current_user, ledger.oid, 'INSERT') \
             AND NOT has_table_privilege(current_user, ledger.oid, 'UPDATE') \
             AND NOT has_table_privilege(current_user, ledger.oid, 'DELETE') \
             AND NOT has_table_privilege(current_user, ledger.oid, 'TRUNCATE') \
             AND NOT has_table_privilege(current_user, ledger.oid, 'REFERENCES') \
             AND NOT has_table_privilege(current_user, ledger.oid, 'TRIGGER') \
             AND NOT EXISTS ( \
                 SELECT 1 \
                   FROM aclexplode(COALESCE( \
                       (SELECT relation.relacl FROM pg_class relation WHERE relation.oid = ledger.oid), \
                       acldefault('r', ledger.relowner) \
                   )) acl \
                  WHERE acl.grantee = 0 \
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
             AND EXISTS ( \
                 SELECT 1 \
                   FROM pg_constraint pair_check \
                   JOIN pg_class relation ON relation.oid = pair_check.conrelid \
                   JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                  WHERE namespace.nspname = 'public' \
                    AND relation.relname = 'chain_swap_records' \
                    AND pair_check.conname = 'chain_swap_records_recovery_commitment_pair_check' \
                    AND pair_check.contype = 'c' \
                    AND pair_check.convalidated \
                    AND pg_get_expr(pair_check.conbin, pair_check.conrelid, TRUE) = \
                        '(recovery_address_commitment_id IS NULL) = (merchant_emergency_btc_address IS NULL)' \
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
                  ) \
             ) \
            FROM ledger \
      ), FALSE)::INT"
  )" || return 1
  [[ "$ready" == "1" ]]
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
    rollback_allowed=1
    if ((binary_switch_started == 1)) \
        && ! automatic_binary_rollback_allowed; then
      rollback_allowed=0
      rollback_failed=1
      echo "deployment failed; automatic binary/PWA rollback refused; candidate files remain installed for operator recovery" >&2
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
psql --no-psqlrc --set ON_ERROR_STOP=1 as a distinct privileged schema owner.
Never apply migration 053 as the runtime role payservice. Follow
docs/operations/deployment.md, including its pre- and post-migration checks,
then rerun this script.
EOF
    exit 1
  fi
  echo "migration 053 privileged-owner ACL/FK/trigger boundary verified read-only as payservice"
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

#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$ROOT_DIR/scripts/deploy.sh"

fail() {
  echo "renegotiation rollback test failed: $*" >&2
  exit 1
}

function_source="$(
  awk '
    /^automatic_binary_rollback_allowed\(\) \{/ { capture = 1 }
    capture { print }
    capture && /^}$/ { exit }
  ' "$DEPLOY"
)"
[[ "$function_source" == automatic_binary_rollback_allowed* ]] \
  || fail "could not extract automatic_binary_rollback_allowed"
eval "$function_source"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
REPO="$tmp/repo"
mkdir -p "$REPO/scripts"
cat > "$REPO/scripts/check-direct-lifecycle-rollback.py" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$REPO/scripts/check-direct-lifecycle-rollback.py"

previous_build_info="$tmp/previous.build-info"
candidate_build_info="$tmp/candidate.build-info"

build_info_schema_marker() {
  sed -n '1p' "$1"
}

direct_transition_history_count() {
  echo 0
}

expect_refusal() {
  local previous="$1"
  local candidate="$2"
  local boundary="$3"
  printf '%s\n' "$previous" > "$previous_build_info"
  printf '%s\n' "$candidate" > "$candidate_build_info"
  if automatic_binary_rollback_allowed >"$tmp/stdout" 2>"$tmp/stderr"; then
    fail "rollback unexpectedly allowed from $candidate to $previous"
  fi
  grep -Fq \
    "$boundary" \
    "$tmp/stderr" \
    || fail "rollback refusal for $candidate to $previous named the wrong boundary"
}

expect_allowed() {
  local previous="$1"
  local candidate="$2"
  printf '%s\n' "$previous" > "$previous_build_info"
  printf '%s\n' "$candidate" > "$candidate_build_info"
  automatic_binary_rollback_allowed >"$tmp/stdout" 2>"$tmp/stderr" \
    || fail "rollback unexpectedly refused from $candidate to $previous"
}

expect_refusal 055_merchant_settlement_lifecycle 056_chain_swap_renegotiation_journal \
  'migration 056 is a roll-forward-only renegotiation-intent boundary'
expect_refusal 055_merchant_settlement_lifecycle 057_chain_swap_cooperative_signing_operations \
  'migration 056 is a roll-forward-only renegotiation-intent boundary'
expect_refusal 056_chain_swap_renegotiation_journal 057_chain_swap_cooperative_signing_operations \
  'migration 057 is a roll-forward-only cooperative-signing-intent boundary'
expect_allowed 056_chain_swap_renegotiation_journal 056_chain_swap_renegotiation_journal
expect_allowed 057_chain_swap_cooperative_signing_operations 057_chain_swap_cooperative_signing_operations

echo "renegotiation rollback checks passed"

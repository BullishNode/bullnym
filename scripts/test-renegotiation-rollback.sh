#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$ROOT_DIR/scripts/deploy.sh"

fail() {
  echo "renegotiation rollback test failed: $*" >&2
  exit 1
}

guard_source="$(
  awk '
    /^require_no_nonterminal_cooperative_operations\(\) \{/ { capture = 1 }
    capture { print }
    capture && /^}$/ { exit }
  ' "$DEPLOY"
)"
[[ "$guard_source" == require_no_nonterminal_cooperative_operations* ]] \
  || fail "could not extract require_no_nonterminal_cooperative_operations"
eval "$guard_source"

rollback_source="$(
  awk '
    /^automatic_binary_rollback_allowed\(\) \{/ { capture = 1 }
    capture { print }
    capture && /^}$/ { exit }
  ' "$DEPLOY"
)"
[[ "$rollback_source" == automatic_binary_rollback_allowed* ]] \
  || fail "could not extract automatic_binary_rollback_allowed"
eval "$rollback_source"

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

cooperative_count=0
cooperative_query_fails=0
rollback_writer_stopped=1

cooperative_nonterminal_count() {
  ((cooperative_query_fails == 0)) || return 1
  echo "$cooperative_count"
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

expect_refusal \
  055_merchant_settlement_lifecycle \
  056_chain_swap_renegotiation_journal \
  'migration 056 is a roll-forward-only renegotiation-intent boundary'
expect_refusal \
  055_merchant_settlement_lifecycle \
  057_chain_swap_cooperative_signing_operations \
  'migration 056 is a roll-forward-only renegotiation-intent boundary'
expect_refusal \
  055_merchant_settlement_lifecycle \
  058_permanent_public_names \
  'migration 056 is a roll-forward-only renegotiation-intent boundary'
expect_refusal \
  056_chain_swap_renegotiation_journal \
  057_chain_swap_cooperative_signing_operations \
  'migration 057 is a roll-forward-only cooperative-signing-intent boundary'
expect_refusal \
  056_chain_swap_renegotiation_journal \
  058_permanent_public_names \
  'migration 057 is a roll-forward-only cooperative-signing-intent boundary'
expect_refusal \
  064_wallet_backup_blobs \
  065_private_invoice_presentations \
  'migration 065 replaces wallet-invoice plaintext with required encrypted presentations'
rollback_writer_stopped=0
cooperative_query_fails=1
expect_allowed 056_chain_swap_renegotiation_journal 056_chain_swap_renegotiation_journal
rollback_writer_stopped=1
cooperative_query_fails=0
cooperative_count=0
expect_allowed 057_chain_swap_cooperative_signing_operations 057_chain_swap_cooperative_signing_operations
cooperative_count=1
expect_refusal 057_chain_swap_cooperative_signing_operations \
  057_chain_swap_cooperative_signing_operations \
  'a nonterminal cooperative-signing operation still binds the current runtime'
cooperative_count=not-a-count
expect_refusal 057_chain_swap_cooperative_signing_operations \
  057_chain_swap_cooperative_signing_operations \
  'cooperative-signing state could not be inspected'
cooperative_count=0
cooperative_query_fails=1
expect_refusal 057_chain_swap_cooperative_signing_operations \
  057_chain_swap_cooperative_signing_operations \
  'cooperative-signing state could not be inspected'
cooperative_query_fails=0
rollback_writer_stopped=0
expect_refusal 057_chain_swap_cooperative_signing_operations \
  057_chain_swap_cooperative_signing_operations \
  'candidate writer is not proven stopped'

rollback_failure_source="$(
  awk '
    /^rollback_on_failure\(\) \{/ { capture = 1 }
    capture { print }
    capture && /^}$/ { exit }
  ' "$DEPLOY"
)"
stop_line="$(grep -n -m1 'systemctl stop payservice' <<<"$rollback_failure_source" | cut -d: -f1)"
check_line="$(grep -n -m1 'automatic_binary_rollback_allowed' <<<"$rollback_failure_source" | cut -d: -f1)"
[[ "$stop_line" =~ ^[0-9]+$ && "$check_line" =~ ^[0-9]+$ \
    && "$stop_line" -lt "$check_line" ]] \
  || fail "rollback must stop the candidate writer before its compatibility check"

forward_switch_source="$(
  awk '
    /^candidate_schema="\$\(build_info_schema_marker / { capture = 1 }
    capture { print }
    capture && /^sudo rm -f "\$APP\/pay-service\.prev"$/ { exit }
  ' "$DEPLOY"
)"
[[ "$forward_switch_source" == candidate_schema=* ]] \
  || fail "could not extract the forward schema-057 switch guard"
stop_line="$(grep -n -m1 'systemctl stop payservice' <<<"$forward_switch_source" | cut -d: -f1)"
check_line="$(grep -n -m1 'require_no_nonterminal_cooperative_operations "deployment"' \
  <<<"$forward_switch_source" | cut -d: -f1)"
[[ "$stop_line" =~ ^[0-9]+$ && "$check_line" =~ ^[0-9]+$ \
    && "$stop_line" -lt "$check_line" ]] \
  || fail "forward deploy must stop the current writer before its compatibility check"

rollback_writer_stopped=1
cooperative_query_fails=0
cooperative_count=0
expect_allowed 057_chain_swap_cooperative_signing_operations 058_permanent_public_names
expect_allowed 058_permanent_public_names 058_permanent_public_names
expect_refusal \
  058_permanent_public_names \
  059_remove_surface_alias \
  'migration 059 removes mutable per-surface alias authority'
expect_allowed 059_remove_surface_alias 059_remove_surface_alias
expect_allowed 059_remove_surface_alias 060_lnurl_private_comment_intents
expect_allowed 060_lnurl_private_comment_intents 060_lnurl_private_comment_intents
expect_allowed 060_lnurl_private_comment_intents 061_invoice_quote_versions
expect_allowed 061_invoice_quote_versions 061_invoice_quote_versions
expect_allowed 061_invoice_quote_versions 062_invoice_quote_provider_attempts
expect_allowed 062_invoice_quote_provider_attempts 062_invoice_quote_provider_attempts
expect_allowed 062_invoice_quote_provider_attempts 063_checkout_private_memo
expect_allowed 063_checkout_private_memo 063_checkout_private_memo

echo "renegotiation rollback checks passed"

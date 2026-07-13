#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke_script="$root/scripts/issue64-offline-smoke.sh"
source "$smoke_script"

self_test_fail() {
    printf 'test-issue64-offline-smoke: FAIL: %s\n' "$*" >&2
    exit 1
}

expect_failure() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        self_test_fail "$label unexpectedly passed"
    fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bash -n "$smoke_script"
bash -n "$root/scripts/test-issue64-offline-smoke.sh"
"$smoke_script" --static-only >/dev/null

mkdir -p "$tmp/fee/src"
printf '%s\n' 'fee_policy_ready: false,' > "$tmp/fee/src/main.rs"
issue64_assert_fee_policy_closed "$tmp/fee"
printf '%s\n' 'fee_policy_ready: true,' > "$tmp/fee/src/main.rs"
expect_failure "enabled fee-policy admission tripwire" \
    issue64_assert_fee_policy_closed "$tmp/fee"

mkdir -p "$tmp/defaults/src" "$tmp/defaults/tests"
printf '%s\n' 'fn clean() {}' > "$tmp/defaults/src/lib.rs"
issue64_assert_removed_defaults_absent "$tmp/defaults"
removed_symbol="$(printf '%s%s' 'from_legacy_' 'default')"
printf 'fn %s() {}\n' "$removed_symbol" > "$tmp/defaults/src/lib.rs"
expect_failure "removed default authority tripwire" \
    issue64_assert_removed_defaults_absent "$tmp/defaults"

scope_repo="$tmp/scope-repo"
mkdir -p "$scope_repo/scripts"
git -C "$scope_repo" init -q
git -C "$scope_repo" config user.name 'Issue 64 Smoke Test'
git -C "$scope_repo" config user.email 'issue64-smoke@example.invalid'
printf '%s\n' 'baseline' > "$scope_repo/README.md"
git -C "$scope_repo" add README.md
git -C "$scope_repo" commit -qm 'baseline'
printf '%s\n' '#!/usr/bin/env bash' > "$scope_repo/$ISSUE64_SMOKE_SCRIPT"
printf '%s\n' '#!/usr/bin/env bash' > "$scope_repo/$ISSUE64_SMOKE_SELF_TEST"
git -C "$scope_repo" add "$ISSUE64_SMOKE_SCRIPT" "$ISSUE64_SMOKE_SELF_TEST"
git -C "$scope_repo" commit -qm 'add smoke scripts'
issue64_assert_owned_diff_only "$scope_repo"

mkdir -p "$scope_repo/migrations"
printf '%s\n' '-- later mainline schema' > "$scope_repo/migrations/053_later_main.sql"
expect_failure "dirty migration tripwire" issue64_assert_owned_diff_only "$scope_repo"
git -C "$scope_repo" add migrations/053_later_main.sql
git -C "$scope_repo" commit -qm 'later mainline schema'
issue64_assert_owned_diff_only "$scope_repo"

printf '%s\n' '# smoke change' >> "$scope_repo/$ISSUE64_SMOKE_SCRIPT"
printf '%s\n' '-- bundled schema' > "$scope_repo/migrations/054_bundled_with_smoke.sql"
git -C "$scope_repo" add "$ISSUE64_SMOKE_SCRIPT" migrations/054_bundled_with_smoke.sql
git -C "$scope_repo" commit -qm 'invalid mixed smoke change'
printf '%s\n' '# later clean change' >> "$scope_repo/$ISSUE64_SMOKE_SELF_TEST"
git -C "$scope_repo" add "$ISSUE64_SMOKE_SELF_TEST"
git -C "$scope_repo" commit -qm 'later clean smoke change'
expect_failure "historical bundled migration tripwire" \
    issue64_assert_owned_diff_only "$scope_repo"

mkdir -p "$tmp/runtime-source/src"
printf '%s\n' 'pub mod existing;' > "$tmp/runtime-source/src/lib.rs"
[[ "$(issue64_runtime_source_test_state "$tmp/runtime-source")" == "absent" ]] || \
    self_test_fail "missing runtime source module was not explicit"
printf '%s\n' 'pub mod runtime_fee_sources;' > "$tmp/runtime-source/src/lib.rs"
expect_failure "declared runtime source without module tripwire" \
    issue64_runtime_source_test_state "$tmp/runtime-source"
printf '%s\n' 'pub fn project() {}' > "$tmp/runtime-source/src/runtime_fee_sources.rs"
expect_failure "runtime source without tests tripwire" \
    issue64_runtime_source_test_state "$tmp/runtime-source"
printf '%s\n' \
    'pub fn project() {}' \
    '#[cfg(test)]' \
    'mod tests {' \
    '    #[test]' \
    '    fn projects_sources() {}' \
    '}' > "$tmp/runtime-source/src/runtime_fee_sources.rs"
[[ "$(issue64_runtime_source_test_state "$tmp/runtime-source")" == "present" ]] || \
    self_test_fail "valid runtime source tests were not required"

mkdir -p "$tmp/refresh-cycle/src"
printf '%s\n' 'pub mod existing;' > "$tmp/refresh-cycle/src/lib.rs"
[[ "$(issue64_fee_refresh_cycle_test_state "$tmp/refresh-cycle")" == "absent" ]] || \
    self_test_fail "missing fee refresh cycle was not explicit"
printf '%s\n' 'pub mod fee_refresh_cycle;' > "$tmp/refresh-cycle/src/lib.rs"
expect_failure "declared fee refresh cycle without module tripwire" \
    issue64_fee_refresh_cycle_test_state "$tmp/refresh-cycle"
printf '%s\n' 'pub mod existing;' > "$tmp/refresh-cycle/src/lib.rs"
printf '%s\n' 'pub fn refresh() {}' > "$tmp/refresh-cycle/src/fee_refresh_cycle.rs"
expect_failure "unexported fee refresh cycle file tripwire" \
    issue64_fee_refresh_cycle_test_state "$tmp/refresh-cycle"
printf '%s\n' 'pub mod fee_refresh_cycle;' > "$tmp/refresh-cycle/src/lib.rs"
expect_failure "fee refresh cycle without tests tripwire" \
    issue64_fee_refresh_cycle_test_state "$tmp/refresh-cycle"
printf '%s\n' \
    'pub fn refresh() {}' \
    '#[cfg(test)]' \
    'mod tests {' \
    '    #[test]' \
    '    fn refreshes_once() {}' \
    '}' > "$tmp/refresh-cycle/src/fee_refresh_cycle.rs"
[[ "$(issue64_fee_refresh_cycle_test_state "$tmp/refresh-cycle")" == "present" ]] || \
    self_test_fail "valid fee refresh cycle tests were not required"

printf '%s\n' \
    'export CARGO_NET_OFFLINE=true' \
    'cargo test --locked --offline' > "$tmp/offline-script.sh"
issue64_assert_locked_offline_cargo "$tmp/offline-script.sh"
printf '%s\n' \
    'export CARGO_NET_OFFLINE=true' \
    'cargo test --locked' > "$tmp/offline-script.sh"
expect_failure "Cargo offline flag tripwire" \
    issue64_assert_locked_offline_cargo "$tmp/offline-script.sh"

printf '%s\n' 'cargo test --locked --offline' > "$tmp/offline-script.sh"
issue64_assert_operational_commands_absent "$tmp/offline-script.sh"
external_command="$(printf '%s%s' 'cu' 'rl')"
printf '%s %s\n' "$external_command" 'https://example.invalid' > "$tmp/offline-script.sh"
expect_failure "external command tripwire" \
    issue64_assert_operational_commands_absent "$tmp/offline-script.sh"
mutating_request="$(printf '%s%s' '--re' 'quest')"
mutating_method="$(printf '%s%s' 'PO' 'ST')"
printf '%s %s\n' "$mutating_request" "$mutating_method" > "$tmp/offline-script.sh"
expect_failure "mutating request tripwire" \
    issue64_assert_operational_commands_absent "$tmp/offline-script.sh"

issue64_validate_test_database_url 'postgres://tester:secret@127.0.0.1:5432/bullnym_test'
expect_failure "non-loopback database tripwire" \
    issue64_validate_test_database_url 'postgres://tester:secret@db.example.invalid/bullnym_test'
expect_failure "non-test database tripwire" \
    issue64_validate_test_database_url 'postgres://tester:secret@127.0.0.1:5432/bullnym'

target_fixture="$tmp/target-validation"
target_checkout="$target_fixture/checkout"
target_outside="$target_fixture/outside"
mkdir -p "$target_checkout" "$target_outside"
expect_failure "missing Cargo target tripwire" \
    issue64_canonical_cargo_target_dir "$target_checkout" ''
expect_failure "relative Cargo target tripwire" \
    issue64_canonical_cargo_target_dir "$target_checkout" 'relative-target'
expect_failure "checkout Cargo target tripwire" \
    issue64_canonical_cargo_target_dir "$target_checkout" "$target_checkout"
expect_failure "checkout descendant Cargo target tripwire" \
    issue64_canonical_cargo_target_dir "$target_checkout" "$target_checkout/missing/target"
ln -s "$target_checkout" "$target_fixture/outside-link"
expect_failure "outside symlink into checkout tripwire" \
    issue64_canonical_cargo_target_dir \
        "$target_checkout" "$target_fixture/outside-link/missing/target"
valid_target="$target_outside/missing/target"
canonical_target="$(issue64_canonical_cargo_target_dir "$target_checkout" "$valid_target")"
[[ "$canonical_target" == "$(realpath --canonicalize-missing -- "$valid_target")" ]] || \
    self_test_fail "valid outside Cargo target was not canonicalized"

issue64_is_owned_path "$ISSUE64_SMOKE_SCRIPT"
issue64_is_owned_path "$ISSUE64_SMOKE_SELF_TEST"
expect_failure "unowned path tripwire" issue64_is_owned_path 'src/main.rs'

issue64_run_static_tripwires "$root"
printf 'test-issue64-offline-smoke: PASS\n'

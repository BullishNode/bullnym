#!/usr/bin/env bash
# Deterministic, offline foundation gate for issue #64 fee-policy work.
set -Eeuo pipefail
IFS=$'\n\t'

readonly ISSUE64_SMOKE_SCRIPT="scripts/issue64-offline-smoke.sh"
readonly ISSUE64_SMOKE_SELF_TEST="scripts/test-issue64-offline-smoke.sh"

readonly -a ISSUE64_DB_FILTERS=(
    "provider_ready_claims_without_a_liquid_quote_stay_pending_without_construction"
    "changed_fee_applies_before_journal_and_no_quote_replays_persisted_bytes"
    "unjournaled_recovery_without_a_quote_stays_retryable_and_constructs_no_bytes"
)

# Each entry is filter|source file|one test function that proves the filter is
# still populated. Cargo treats an empty filter as success, so the marker is a
# deliberate tripwire against silently losing coverage during a rebase.
readonly -a ISSUE64_UNIT_FILTERS=(
    "fee_policy::tests|src/fee_policy.rs|four_typed_sources_are_distinct_and_stable"
    "bitcoin_fee_adapter::tests|src/bitcoin_fee_adapter.rs|observes_fastest_fee_with_explicit_units_time_and_source"
    "liquid_fee_adapter::tests|src/liquid_fee_adapter.rs|observes_exact_target_one_with_units_time_source_and_request_contract"
    "liquid_fee_sources::tests|src/liquid_fee_sources.rs|source_ids_are_stable_sanitized_bounded_and_debug_redacted"
    "config::tests::fee_|src/config/tests.rs|fee_policy_defaults_are_complete_bounded_and_quote_free"
    "config::tests::invalid_fee_config_exposes_false_facts_without_changing_startup_validation|src/config/tests.rs|invalid_fee_config_exposes_false_facts_without_changing_startup_validation"
    "current_fee_snapshot::tests|src/current_fee_snapshot.rs|new_and_restarted_snapshots_are_empty"
    "builder_fee::tests|src/builder_fee.rs|only_policy_decisions_cross_each_rail_boundary_without_rate_drift"
    "claimer::tests::reverse_and_chain_claim_paths_preserve_upstream_min_midrange_and_max_rates|src/claimer/tests.rs|reverse_and_chain_claim_paths_preserve_upstream_min_midrange_and_max_rates"
    "claimer::tests::changed_liquid_decision_changes_each_next_claim_construction_path|src/claimer/tests.rs|changed_liquid_decision_changes_each_next_claim_construction_path"
    "chain_recovery::tests::bitcoin_recovery_preserves_upstream_min_midrange_and_max_rates|src/chain_recovery.rs|bitcoin_recovery_preserves_upstream_min_midrange_and_max_rates"
)

issue64_smoke_fail() {
    printf 'issue64-offline-smoke: FAIL: %s\n' "$*" >&2
    return 1
}

issue64_repo_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

issue64_require_canonicalization_tool() {
    command -v realpath >/dev/null 2>&1 || issue64_smoke_fail \
        "realpath is required to canonicalize CARGO_TARGET_DIR"
}

issue64_canonical_cargo_target_dir() {
    local root="$1"
    local candidate="${2:-}"
    local canonical_root canonical_target

    issue64_require_canonicalization_tool || return 1
    if [[ -z "$candidate" ]]; then
        issue64_smoke_fail "CARGO_TARGET_DIR must be set to an explicit isolated path"
        return 1
    fi
    if [[ "$candidate" != /* ]]; then
        issue64_smoke_fail "CARGO_TARGET_DIR must be absolute"
        return 1
    fi
    canonical_root="$(realpath --canonicalize-existing -- "$root")" || {
        issue64_smoke_fail "checkout path could not be canonicalized"
        return 1
    }
    canonical_target="$(realpath --canonicalize-missing -- "$candidate")" || {
        issue64_smoke_fail "CARGO_TARGET_DIR could not be canonicalized"
        return 1
    }
    case "$canonical_target" in
        "$canonical_root"|"$canonical_root"/*)
            issue64_smoke_fail "CARGO_TARGET_DIR must resolve outside the checkout"
            return 1
            ;;
    esac
    printf '%s\n' "$canonical_target"
}

issue64_assert_fee_policy_closed() {
    local root="$1"
    local main="$root/src/main.rs"
    local disabled_count

    [[ -f "$main" ]] || issue64_smoke_fail "missing src/main.rs"
    if rg -n --no-heading -e 'fee_policy_ready[[:space:]]*:[[:space:]]*true' \
        -e 'set_fee_policy_ready[[:space:]]*\([[:space:]]*true' "$main"; then
        issue64_smoke_fail "production fee-policy admission was enabled"
        return 1
    fi

    disabled_count="$(rg -c 'fee_policy_ready[[:space:]]*:[[:space:]]*false' "$main" || true)"
    [[ "$disabled_count" == "1" ]] || issue64_smoke_fail \
        "expected exactly one fail-closed fee-policy admission initializer"
}

issue64_assert_removed_defaults_absent() {
    local root="$1"
    local pattern

    pattern='from_legacy_default|legacy_liquid_claim_fee_decision|legacy_bitcoin_recovery_fee_decision|default_rate\(|BITCOIN_DEFAULT_SAT_PER_VBYTE|LIQUID_DEFAULT_SAT_PER_VBYTE|display_default|FeeRateClamp|DefaultOutsideBounds|ConfiguredRateOutsideBounds|ObservationFromFuture|default_bitcoin_fee_decision'
    if rg -n --no-heading -e "$pattern" "$root/src" "$root/tests"; then
        issue64_smoke_fail "removed default-quote construction authority reappeared"
        return 1
    fi
}

issue64_is_owned_path() {
    case "$1" in
        "$ISSUE64_SMOKE_SCRIPT"|"$ISSUE64_SMOKE_SELF_TEST") return 0 ;;
        *) return 1 ;;
    esac
}

issue64_assert_script_files() {
    local root="$1"
    local script

    for script in "$ISSUE64_SMOKE_SCRIPT" "$ISSUE64_SMOKE_SELF_TEST"; do
        if [[ ! -f "$root/$script" || ! -x "$root/$script" ]]; then
            issue64_smoke_fail "required smoke script is missing or not executable: $script"
            return 1
        fi
    done
}

issue64_assert_owned_commit() {
    local root="$1"
    local commit="$2"
    local path commit_line
    local -a commit_fields=()
    local -a changed_paths=()

    commit_line="$(git -C "$root" rev-list --parents -n 1 "$commit")"
    IFS=' ' read -r -a commit_fields <<< "$commit_line"
    if ((${#commit_fields[@]} > 2)); then
        issue64_smoke_fail "smoke scripts must not be changed by a merge commit: $commit"
        return 1
    fi
    mapfile -t changed_paths < <(
        git -C "$root" diff-tree --root --no-commit-id --name-only -r "$commit" | \
            LC_ALL=C sort -u
    )

    for path in "${changed_paths[@]}"; do
        [[ -n "$path" ]] || continue
        if ! issue64_is_owned_path "$path"; then
            issue64_smoke_fail "smoke-script commit $commit changed an unowned path: $path"
            return 1
        fi
    done
}

issue64_assert_owned_diff_only() {
    local root="$1"
    local path commit
    local -a commits=()
    local -a dirty_paths=()

    mapfile -t commits < <(
        git -C "$root" log --format=%H -- \
            "$ISSUE64_SMOKE_SCRIPT" "$ISSUE64_SMOKE_SELF_TEST" | LC_ALL=C sort -u
    )
    for commit in "${commits[@]}"; do
        [[ -n "$commit" ]] || continue
        issue64_assert_owned_commit "$root" "$commit" || return 1
    done

    mapfile -t dirty_paths < <(
        {
            git -C "$root" diff --name-only
            git -C "$root" diff --cached --name-only
            git -C "$root" ls-files --others --exclude-standard
        } | LC_ALL=C sort -u
    )
    for path in "${dirty_paths[@]}"; do
        [[ -n "$path" ]] || continue
        if ! issue64_is_owned_path "$path"; then
            issue64_smoke_fail "smoke lane has an unowned dirty path: $path"
            return 1
        fi
    done
}

# Assemble operational command names from fragments so the audit does not
# exempt its own source. The resulting expression rejects shell commands that
# can contact external systems, control hosts, or move value.
issue64_forbidden_command_pattern() {
    printf '%s' \
        '(^|[;&|()]|[[:space:]])(' \
        'cu''rl|wg''et|ss''h|sc''p|rsy''nc|n''c|so''cat|tel''net|pi''ng|' \
        'dock''er|kub''ectl|system''ctl|ter''raform|ans''ible|vag''rant|vir''sh|' \
        'qemu-system-[^[:space:]]+|depl''oy|provider''ctl|boltz-''cli|' \
        'bitcoin-''cli|elements-''cli|lightning-''cli|ln''cli|' \
        'sendto''address|sendraw''transaction|fundraw''transaction|' \
        'walletcreatefunded''psbt|key''send' \
        ')([[:space:]]|$)'
}

issue64_forbidden_mutating_request_pattern() {
    printf '%s' \
        '(-X|--request)[[:space:]]*(' \
        'PO''ST|PU''T|PAT''CH|DEL''ETE' \
        ')([[:space:]]|$)'
}

issue64_assert_operational_commands_absent() {
    local -a paths=("$@")
    local command_pattern
    local request_pattern

    command_pattern="$(issue64_forbidden_command_pattern)"
    request_pattern="$(issue64_forbidden_mutating_request_pattern)"
    if rg -n -i --no-heading -e "$command_pattern" -e "$request_pattern" "${paths[@]}"; then
        issue64_smoke_fail "offline smoke lane contains an operational command"
        return 1
    fi
}

issue64_assert_locked_offline_cargo() {
    local script="$1"
    local line
    local command_count=0

    while IFS= read -r line; do
        ((command_count += 1))
        if [[ "$line" != *'--locked'* || "$line" != *'--offline'* ]]; then
            issue64_smoke_fail "every Cargo command must be locked and offline"
            return 1
        fi
    done < <(rg '^[[:space:]]*cargo[[:space:]]' "$script")
    if ((command_count == 0)); then
        issue64_smoke_fail "offline smoke contains no Cargo commands"
        return 1
    fi
    if ! rg -q '^[[:space:]]*export[[:space:]]+CARGO_NET_OFFLINE=true[[:space:]]*$' "$script"; then
        issue64_smoke_fail "offline smoke must force Cargo network-offline mode"
        return 1
    fi
}

issue64_assert_test_function() {
    local file="$1"
    local function_name="$2"

    [[ -f "$file" ]] || issue64_smoke_fail "missing test source: $file"
    rg -q -e "^[[:space:]]*(async[[:space:]]+)?fn[[:space:]]+${function_name}[[:space:]]*\\(" \
        "$file" || issue64_smoke_fail "required test function disappeared: $function_name"
}

issue64_runtime_source_test_state() {
    local root="$1"
    local declaration_count
    local source_path=""

    declaration_count="$(rg -c \
        '^[[:space:]]*pub[[:space:]]+mod[[:space:]]+runtime_fee_sources[[:space:]]*;' \
        "$root/src/lib.rs" || true)"
    if [[ -f "$root/src/runtime_fee_sources.rs" ]]; then
        source_path="$root/src/runtime_fee_sources.rs"
    fi
    if [[ -f "$root/src/runtime_fee_sources/mod.rs" ]]; then
        if [[ -n "$source_path" ]]; then
            issue64_smoke_fail "runtime fee sources has two competing module roots"
            return 1
        fi
        source_path="$root/src/runtime_fee_sources"
    fi

    if [[ -z "$declaration_count" && -z "$source_path" ]]; then
        printf 'absent\n'
        return 0
    fi
    if [[ "$declaration_count" != "1" || -z "$source_path" ]]; then
        issue64_smoke_fail "runtime fee sources must have exactly one exported module root"
        return 1
    fi
    if ! rg -q -e 'mod[[:space:]]+tests[[:space:]]*[{;]' "$source_path"; then
        issue64_smoke_fail "runtime fee sources exists without a tests module"
        return 1
    fi
    if ! rg -q -e '#\[(tokio::)?test\]' "$source_path"; then
        issue64_smoke_fail "runtime fee sources tests module contains no tests"
        return 1
    fi
    printf 'present\n'
}

issue64_fee_refresh_cycle_test_state() {
    local root="$1"
    local declaration_count
    local source_path=""

    declaration_count="$(rg -c \
        '^[[:space:]]*pub[[:space:]]+mod[[:space:]]+fee_refresh_cycle[[:space:]]*;' \
        "$root/src/lib.rs" || true)"
    if [[ -f "$root/src/fee_refresh_cycle.rs" ]]; then
        source_path="$root/src/fee_refresh_cycle.rs"
    fi
    if [[ -f "$root/src/fee_refresh_cycle/mod.rs" ]]; then
        if [[ -n "$source_path" ]]; then
            issue64_smoke_fail "fee refresh cycle has two competing module roots"
            return 1
        fi
        source_path="$root/src/fee_refresh_cycle"
    fi

    if [[ -z "$declaration_count" && -z "$source_path" ]]; then
        printf 'absent\n'
        return 0
    fi
    if [[ "$declaration_count" != "1" || -z "$source_path" ]]; then
        issue64_smoke_fail "fee refresh cycle must have exactly one exported module root"
        return 1
    fi
    if ! rg -q -e 'mod[[:space:]]+tests[[:space:]]*[{;]' "$source_path"; then
        issue64_smoke_fail "fee refresh cycle exists without a tests module"
        return 1
    fi
    if ! rg -q -e '#\[(tokio::)?test\]' "$source_path"; then
        issue64_smoke_fail "fee refresh cycle tests module contains no tests"
        return 1
    fi
    printf 'present\n'
}

issue64_assert_test_manifest() {
    local root="$1"
    local entry filter relative_file function_name runtime_source_state refresh_cycle_state

    for entry in "${ISSUE64_UNIT_FILTERS[@]}"; do
        IFS='|' read -r filter relative_file function_name <<< "$entry"
        if [[ -z "$filter" ]]; then
            issue64_smoke_fail "empty unit-test filter"
            return 1
        fi
        issue64_assert_test_function "$root/$relative_file" "$function_name" || return 1
    done
    for function_name in "${ISSUE64_DB_FILTERS[@]}"; do
        issue64_assert_test_function "$root/tests/integration_test.rs" "$function_name" || return 1
    done

    runtime_source_state="$(issue64_runtime_source_test_state "$root")"
    case "$runtime_source_state" in
        present)
            printf 'issue64-offline-smoke: runtime-source-filter=required\n'
            ;;
        absent)
            printf 'issue64-offline-smoke: runtime-source-filter=absent-on-this-revision; admission-remains-closed\n'
            ;;
        *) issue64_smoke_fail "invalid runtime source test state" ;;
    esac

    refresh_cycle_state="$(issue64_fee_refresh_cycle_test_state "$root")"
    case "$refresh_cycle_state" in
        present)
            printf 'issue64-offline-smoke: fee-refresh-cycle-filter=required\n'
            ;;
        absent)
            printf 'issue64-offline-smoke: fee-refresh-cycle-filter=absent-on-this-revision; admission-remains-closed\n'
            ;;
        *) issue64_smoke_fail "invalid fee refresh cycle test state" ;;
    esac
}

issue64_run_static_tripwires() {
    local root="$1"

    issue64_require_canonicalization_tool || return 1
    issue64_assert_script_files "$root" || return 1
    issue64_assert_fee_policy_closed "$root" || return 1
    issue64_assert_removed_defaults_absent "$root" || return 1
    issue64_assert_owned_diff_only "$root" || return 1
    issue64_assert_locked_offline_cargo "$root/$ISSUE64_SMOKE_SCRIPT" || return 1
    issue64_assert_operational_commands_absent \
        "$root/$ISSUE64_SMOKE_SCRIPT" \
        "$root/$ISSUE64_SMOKE_SELF_TEST" || return 1
    issue64_assert_test_manifest "$root" || return 1
    printf 'issue64-offline-smoke: static tripwires passed\n'
}

issue64_validate_test_database_url() {
    local url="$1"
    local remainder authority host_port database

    case "$url" in
        postgres://*|postgresql://*) ;;
        *) issue64_smoke_fail "TEST_DATABASE_URL must use PostgreSQL"; return 1 ;;
    esac
    remainder="${url#*://}"
    authority="${remainder%%/*}"
    host_port="${authority##*@}"
    case "$host_port" in
        localhost|localhost:*|127.0.0.1|127.0.0.1:*|'[::1]'|'[::1]':*) ;;
        *) issue64_smoke_fail "TEST_DATABASE_URL must use a loopback host"; return 1 ;;
    esac
    database="${remainder#*/}"
    database="${database%%\?*}"
    [[ -n "$database" && "$database" == *test* ]] || issue64_smoke_fail \
        "TEST_DATABASE_URL must name an explicit test database"
}

issue64_run_unit_filters() {
    local root="$1"
    local entry filter relative_file function_name runtime_source_state refresh_cycle_state

    for entry in "${ISSUE64_UNIT_FILTERS[@]}"; do
        IFS='|' read -r filter relative_file function_name <<< "$entry"
        printf 'issue64-offline-smoke: unit-filter=%s\n' "$filter"
        cargo test --locked --offline --color never --lib "$filter" -- --test-threads=1
    done

    runtime_source_state="$(issue64_runtime_source_test_state "$root")"
    if [[ "$runtime_source_state" == "present" ]]; then
        printf 'issue64-offline-smoke: unit-filter=runtime_fee_sources::tests\n'
        cargo test --locked --offline --color never --lib 'runtime_fee_sources::tests' -- \
            --test-threads=1
    else
        printf 'issue64-offline-smoke: unit-filter=runtime_fee_sources::tests status=absent-on-this-revision\n'
    fi

    refresh_cycle_state="$(issue64_fee_refresh_cycle_test_state "$root")"
    if [[ "$refresh_cycle_state" == "present" ]]; then
        printf 'issue64-offline-smoke: unit-filter=fee_refresh_cycle::tests\n'
        cargo test --locked --offline --color never --lib 'fee_refresh_cycle::tests' -- \
            --test-threads=1
    else
        printf 'issue64-offline-smoke: unit-filter=fee_refresh_cycle::tests status=absent-on-this-revision\n'
    fi
}

issue64_run_db_filters() {
    local filter

    if [[ -z "${TEST_DATABASE_URL:-}" ]]; then
        printf 'issue64-offline-smoke: db-mode=compile-only (TEST_DATABASE_URL absent)\n'
        for filter in "${ISSUE64_DB_FILTERS[@]}"; do
            printf 'issue64-offline-smoke: db-compile-filter=%s\n' "$filter"
            cargo test --locked --offline --color never --test integration_test --no-run "$filter"
        done
        return
    fi

    issue64_validate_test_database_url "$TEST_DATABASE_URL"
    printf 'issue64-offline-smoke: db-mode=explicit-loopback-test-database\n'
    for filter in "${ISSUE64_DB_FILTERS[@]}"; do
        printf 'issue64-offline-smoke: db-filter=%s\n' "$filter"
        cargo test --locked --offline --color never --test integration_test "$filter" -- \
            --exact --test-threads=1
    done
}

issue64_smoke_usage() {
    printf '%s\n' \
        'usage: scripts/issue64-offline-smoke.sh [--static-only]' \
        '' \
        'CARGO_TARGET_DIR must be an explicit path outside the checkout.' \
        'DATABASE_URL must be unset. With no TEST_DATABASE_URL, DB tests are' \
        'compiled only. A loopback TEST_DATABASE_URL whose database name' \
        'contains "test" explicitly opts into executing the focused DB tests.'
}

issue64_smoke_main() {
    local mode="full"
    local root revision tree dirty canonical_target

    case "${1:-}" in
        "") ;;
        --static-only) mode="static-only" ;;
        -h|--help) issue64_smoke_usage; return ;;
        *) issue64_smoke_usage >&2; return 2 ;;
    esac
    (($# <= 1)) || { issue64_smoke_usage >&2; return 2; }

    root="$(issue64_repo_root)"
    revision="$(git -C "$root" rev-parse --verify 'HEAD^{commit}')"
    tree="$(git -C "$root" rev-parse --verify 'HEAD^{tree}')"
    if [[ -n "$(git -C "$root" status --porcelain=v1 --untracked-files=all)" ]]; then
        dirty="true"
    else
        dirty="false"
    fi
    printf 'issue64-offline-smoke: git-revision=%s\n' "$revision"
    printf 'issue64-offline-smoke: git-tree=%s\n' "$tree"
    printf 'issue64-offline-smoke: worktree-dirty=%s\n' "$dirty"

    issue64_run_static_tripwires "$root"
    [[ "$mode" == "full" ]] || return 0

    [[ -z "${DATABASE_URL:-}" ]] || issue64_smoke_fail \
        "DATABASE_URL must be unset; this gate never uses a runtime database"
    canonical_target="$(issue64_canonical_cargo_target_dir \
        "$root" "${CARGO_TARGET_DIR:-}")"
    export CARGO_TARGET_DIR="$canonical_target"

    export CARGO_INCREMENTAL=0
    export CARGO_NET_OFFLINE=true
    export CARGO_TERM_COLOR=never
    export LC_ALL=C
    export RUST_BACKTRACE=0
    export TZ=UTC
    cd "$root"

    printf 'issue64-offline-smoke: cargo-target-dir=%s\n' "$CARGO_TARGET_DIR"
    issue64_run_unit_filters "$root"
    issue64_run_db_filters
    printf 'issue64-offline-smoke: PASS git-revision=%s\n' "$revision"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    issue64_smoke_main "$@"
fi

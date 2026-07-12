#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" == "--repo-root" ]]; then
    (($# == 2)) || { echo "usage: $0 [--repo-root PATH]" >&2; exit 2; }
    repo_root="$(cd "$2" && pwd)"
elif (($# != 0)); then
    echo "usage: $0 [--repo-root PATH]" >&2
    exit 2
fi

fail() {
    echo "release provenance verification failed: $*" >&2
    exit 1
}

manifest="$repo_root/release-manifest.toml"
[[ -f "$manifest" ]] || fail "missing release-manifest.toml"

value() {
    local key="$1"
    sed -n "s/^${key} = \"\(.*\)\"$/\1/p" "$manifest"
}

repository="$(value repository)"
commit="$(value commit)"
[[ "$repository" =~ ^https://github\.com/BullishNode/boltz-rust\.git$ ]] \
    || fail "unexpected boltz_client.repository '$repository'"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] \
    || fail "boltz_client.commit must be a full lowercase 40-character Git SHA"

dependency_line="$(sed -n '/^boltz-client = /p' "$repo_root/Cargo.toml")"
[[ -n "$dependency_line" ]] || fail "Cargo.toml has no boltz-client dependency"
[[ "$dependency_line" == *"git = \"$repository\""* ]] \
    || fail "Cargo.toml boltz-client repository disagrees with release-manifest.toml"
[[ "$dependency_line" == *"rev = \"$commit\""* ]] \
    || fail "Cargo.toml boltz-client revision disagrees with release-manifest.toml"
[[ "$dependency_line" != *"path ="* ]] \
    || fail "Cargo.toml release dependency must not use a local path"

expected_source="git+${repository}?rev=${commit}#${commit}"
grep -Fq "source = \"$expected_source\"" "$repo_root/Cargo.lock" \
    || fail "Cargo.lock does not contain the exact pinned Boltz source"

if [[ -e "$repo_root/.cargo/config.toml" ]]; then
    fail "remove .cargo/config.toml; release/CI builds reject the local path override"
fi

metadata="$(cd "$repo_root" && cargo metadata --format-version 1 --locked)" \
    || fail "cargo metadata could not resolve the locked dependency graph"

command -v python3 >/dev/null \
    || fail "python3 is required to validate Cargo dependency provenance"
dependency_manifest="$({
    printf '%s' "$metadata" | python3 -c '
import json
import sys

expected = sys.argv[1]
document = json.load(sys.stdin)
packages = [package for package in document.get("packages", [])
            if package.get("name") == "boltz-client"]
if len(packages) != 1:
    raise SystemExit(f"expected one boltz-client package, found {len(packages)}")
package = packages[0]
actual_source = package.get("source")
if actual_source != expected:
    raise SystemExit(
        f"resolved source {actual_source!r} does not match {expected!r}"
    )
manifest = package.get("manifest_path")
if not isinstance(manifest, str) or not manifest:
    raise SystemExit("resolved boltz-client has no manifest_path")
print(manifest)
' "$expected_source"
} 2>&1)" || fail "$dependency_manifest"

[[ -f "$dependency_manifest" ]] \
    || fail "resolved boltz-client checkout is missing: $dependency_manifest"
dependency_root="$(
    git -C "$(dirname "$dependency_manifest")" rev-parse --show-toplevel 2>/dev/null
)" || fail "resolved boltz-client is not a Git checkout: $dependency_manifest"
actual_commit="$(git -C "$dependency_root" rev-parse HEAD 2>/dev/null)" \
    || fail "cannot read resolved boltz-client Git identity"
[[ "$actual_commit" == "$commit" ]] \
    || fail "resolved boltz-client checkout is at $actual_commit, expected $commit"
index_flags="$(git -C "$dependency_root" ls-files -v | grep -v '^H ' || true)"
if [[ -n "$index_flags" ]]; then
    echo "$index_flags" >&2
    fail "resolved boltz-client checkout has assume-unchanged, skip-worktree, or nonstandard index entries"
fi

# Cargo creates this sentinel in Git dependency checkouts. It is metadata, not
# dependency source; every other tracked or untracked change is a release
# provenance failure.
if git -C "$dependency_root" ls-files --error-unmatch .cargo-ok >/dev/null 2>&1; then
    fail "resolved boltz-client unexpectedly tracks Cargo's .cargo-ok sentinel"
fi
if [[ -e "$dependency_root/.cargo-ok" ]] \
    && [[ ! -f "$dependency_root/.cargo-ok" \
          || -L "$dependency_root/.cargo-ok" \
          || -s "$dependency_root/.cargo-ok" ]]; then
    fail "resolved boltz-client has an invalid .cargo-ok sentinel"
fi
dependency_status="$(
    git -C "$dependency_root" status --porcelain=v1 --untracked-files=all \
        --ignore-submodules=none -- . ':(exclude).cargo-ok'
)" || fail "cannot inspect resolved boltz-client checkout"
if [[ -n "$dependency_status" ]]; then
    echo "$dependency_status" >&2
    fail "resolved boltz-client checkout is dirty: $dependency_root"
fi
submodule_status="$(git -C "$dependency_root" submodule status --recursive)" \
    || fail "cannot inspect resolved boltz-client submodules"
if grep -Eq '^[+-U]' <<<"$submodule_status"; then
    echo "$submodule_status" >&2
    fail "resolved boltz-client has missing or divergent submodules"
fi
submodule_integrity="$(
    git -C "$dependency_root" submodule foreach --quiet --recursive '
        flags="$(git ls-files -v | grep -v "^H " || true)"
        if [ -n "$flags" ]; then
            echo "$displaypath: nonstandard index entries"
            echo "$flags"
            exit 1
        fi
        status="$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
        if [ -n "$status" ]; then
            echo "$displaypath: dirty worktree"
            echo "$status"
            exit 1
        fi
    '
)" || fail "resolved boltz-client submodule integrity failed: $submodule_integrity"

echo "release provenance verified: boltz-client $commit from $repository ($dependency_root)"

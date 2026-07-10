#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

check_clean_worktree() {
    local label="$1"
    local path="$2"

    if [[ ! -d "$path/.git" ]]; then
        echo "release preflight failed: $label git checkout not found at $path" >&2
        return 1
    fi

    local status
    status="$(git -C "$path" status --porcelain)"
    if [[ -n "$status" ]]; then
        echo "release preflight failed: $label worktree is dirty at $path" >&2
        echo "$status" >&2
        return 1
    fi
}

check_clean_worktree "bullnym" "$repo_root"
check_clean_worktree "boltz-client path dependency" "$repo_root/../boltz/boltz-rust"

# Verify the boltz-client checkout matches the release-manifest.toml pin
# (issue #70). build.rs enforces the same thing during `--release` builds;
# this gives operators the answer without waiting for a compile.
manifest="$repo_root/release-manifest.toml"
expected_commit="$(sed -n 's/^commit = "\(.*\)"/\1/p' "$manifest")"
actual_commit="$(git -C "$repo_root/../boltz/boltz-rust" rev-parse HEAD)"
if [[ "$actual_commit" != "$expected_commit" ]]; then
    echo "release preflight failed: boltz-client is at $actual_commit," >&2
    echo "release-manifest.toml pins $expected_commit" >&2
    exit 1
fi
origin_id="$(git -C "$repo_root/../boltz/boltz-rust" remote get-url origin \
    | sed -E 's#.*(github.com[:/][^/]+/[^/. ]+).*#\1#' | tr : /)"
if ! grep -qF "$origin_id" "$manifest"; then
    echo "release preflight failed: boltz-client origin $origin_id is not in release-manifest.toml allowed_remotes" >&2
    exit 1
fi

echo "release preflight passed: worktrees clean, boltz-client pinned at $expected_commit"

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

echo "release preflight passed: bullnym and boltz-client dependency are clean"

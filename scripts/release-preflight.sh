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

if ! git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "release preflight failed: Bullnym Git checkout not found at $repo_root" >&2
    exit 1
fi

index_flags="$(git -C "$repo_root" ls-files -v | grep -v '^H ' || true)"
if [[ -n "$index_flags" ]]; then
    echo "release preflight failed: Bullnym index has assume-unchanged, skip-worktree, or nonstandard entries" >&2
    echo "$index_flags" >&2
    exit 1
fi

status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)"
if [[ -n "$status" ]]; then
    echo "release preflight failed: Bullnym worktree is dirty at $repo_root" >&2
    echo "$status" >&2
    exit 1
fi

"$repo_root/scripts/verify-release-provenance.sh" --repo-root "$repo_root"

commit="$(git -C "$repo_root" rev-parse HEAD)"
echo "release preflight passed: clean Bullnym $commit with the pinned Boltz dependency"

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

npm run build -- --outDir "$tmp/dist" --emptyOutDir >/dev/null

if ! diff -qr dist "$tmp/dist" >/dev/null; then
  echo "pwa/dist does not match a clean build of the PWA source." >&2
  echo "Run: cd pwa && npm run build" >&2
  diff -qr dist "$tmp/dist" >&2 || true
  exit 1
fi

echo "pwa/dist matches a clean build"

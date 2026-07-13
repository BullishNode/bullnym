#!/usr/bin/env bash
# Exercise the pending-manifest delivery coordinator against disposable
# PostgreSQL and real S3-compatible MinIO through the shared store harness.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set +e
"$ROOT_DIR/scripts/test-swap-manifest-store-minio.sh" --cleanup-failure-probe
MINIO_CLEANUP_PROBE_STATUS=$?
set -e
if [[ "$MINIO_CLEANUP_PROBE_STATUS" != "87" ]]; then
  echo "test-swap-manifest-delivery-minio: MinIO failure-path cleanup probe did not finish cleanly" >&2
  exit 1
fi
exec "$ROOT_DIR/scripts/test-swap-manifest-store-minio.sh" --delivery-coordinator

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REQUIRE_MIGRATION_055=1 REQUIRE_MIGRATION_056=1 REQUIRE_MIGRATION_057=1 \
  REQUIRE_MIGRATION_058=1 REQUIRE_MIGRATION_059=1 \
  exec "$SCRIPT_DIR/check-migration-053-boundary.sh" "$@"

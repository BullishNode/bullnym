#!/usr/bin/env bash
# Migration 055 extends the protected migration-053 boundary with the exact
# merchant-settlement schema, ACL, journal, and zero-legacy admission checks.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUIRE_MIGRATION_055=1 exec "$SCRIPT_DIR/check-migration-053-boundary.sh" "$@"

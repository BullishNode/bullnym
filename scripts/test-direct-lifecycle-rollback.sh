#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT_DIR/scripts/check-direct-lifecycle-rollback.py"

expect_allowed() {
  "$CHECK" "$@" >/dev/null
}

expect_refused() {
  if "$CHECK" "$@" >/dev/null 2>&1; then
    echo "expected rollback refusal for: $*" >&2
    exit 1
  fi
}

expect_allowed \
  047_direct_payment_lifecycle_foundation \
  047_direct_payment_lifecycle_foundation \
  9
expect_allowed \
  046_chain_swap_tx_attempts \
  047_direct_payment_lifecycle_foundation \
  0
expect_refused \
  046_chain_swap_tx_attempts \
  047_direct_payment_lifecycle_foundation \
  1
expect_allowed \
  045_generated_donation_page_og \
  046_chain_swap_tx_attempts \
  4
expect_allowed \
  050_swap_key_lineage \
  050_swap_key_lineage \
  0
expect_allowed \
  050_swap_key_lineage \
  051_future_lineage_aware_schema \
  0
expect_refused \
  049_watcher_lane_progress \
  050_swap_key_lineage \
  0
expect_refused \
  049_watcher_lane_progress \
  051_future_lineage_aware_schema \
  0
expect_refused \
  malformed-previous-marker \
  050_swap_key_lineage \
  0
expect_refused \
  046_chain_swap_tx_attempts \
  047_direct_payment_lifecycle_foundation \
  not-a-count

echo "direct lifecycle rollback checks passed"

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
expect_allowed \
  055_merchant_settlement_lifecycle \
  055_merchant_settlement_lifecycle \
  0
expect_allowed \
  055_merchant_settlement_lifecycle \
  056_future_settlement_schema \
  0
expect_refused \
  052_manifest_delivery_journal \
  053_recovery_address_commitments \
  0
expect_refused \
  054_fee_policy_authority \
  055_merchant_settlement_lifecycle \
  0
expect_refused \
  054_fee_policy_authority \
  056_future_settlement_schema \
  0
expect_allowed \
  064_wallet_backup_blobs \
  064_wallet_backup_blobs \
  0
expect_allowed \
  064_wallet_backup_blobs \
  065_future_wallet_backup_aware_schema \
  0
expect_refused \
  063_checkout_private_memo \
  064_wallet_backup_blobs \
  0
expect_refused \
  063_checkout_private_memo \
  065_future_wallet_backup_aware_schema \
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

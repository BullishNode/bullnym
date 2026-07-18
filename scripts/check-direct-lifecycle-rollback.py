#!/usr/bin/env python3
"""Decide reviewed automatic binary rollback boundaries."""

from __future__ import annotations

import sys


SCHEMA_046 = "046_chain_swap_tx_attempts"
SCHEMA_047 = "047_direct_payment_lifecycle_foundation"
SWAP_KEY_LINEAGE_VERSION = 50
RECOVERY_COMMITMENT_VERSION = 53
MERCHANT_SETTLEMENT_VERSION = 55
WALLET_BACKUP_VERSION = 64


def schema_version(marker: str) -> int | None:
    prefix, separator, _ = marker.partition("_")
    if not separator or not prefix.isdigit():
        return None
    return int(prefix)


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: check-direct-lifecycle-rollback.py "
            "PREVIOUS_SCHEMA CURRENT_SCHEMA TRANSITION_COUNT",
            file=sys.stderr,
        )
        return 2

    previous_schema, current_schema, count_text = sys.argv[1:]
    try:
        transition_count = int(count_text)
    except ValueError:
        print("rollback check failed: transition count is not an integer", file=sys.stderr)
        return 2
    if transition_count < 0:
        print("rollback check failed: transition count is negative", file=sys.stderr)
        return 2

    if previous_schema == current_schema:
        print(f"rollback allowed: same schema marker {current_schema}")
        return 0

    previous_version = schema_version(previous_schema)
    current_version = schema_version(current_schema)
    if current_version is not None and current_version >= SWAP_KEY_LINEAGE_VERSION:
        if previous_version is None or previous_version < SWAP_KEY_LINEAGE_VERSION:
            print(
                "rollback refused: migration 050 established mandatory swap-key "
                "allocation lineage; a pre-050 binary can create unjournaled "
                "provider obligations on this schema",
                file=sys.stderr,
            )
            return 1

    if current_version is not None and current_version >= RECOVERY_COMMITMENT_VERSION:
        if previous_version is None or previous_version < RECOVERY_COMMITMENT_VERSION:
            print(
                "rollback refused: migration 053 established a stopped-writer, "
                "roll-forward-only recovery-commitment boundary",
                file=sys.stderr,
            )
            return 1

    if current_version is not None and current_version >= MERCHANT_SETTLEMENT_VERSION:
        if previous_version is None or previous_version < MERCHANT_SETTLEMENT_VERSION:
            print(
                "rollback refused: migration 055 established a roll-forward-only "
                "exact-settlement boundary",
                file=sys.stderr,
            )
            return 1

    if current_version is not None and current_version >= WALLET_BACKUP_VERSION:
        if previous_version is None or previous_version < WALLET_BACKUP_VERSION:
            print(
                "rollback refused: migration 064 advances the exact schema marker; "
                "restore the matching pre-064 database together with the older "
                "binary and PWA",
                file=sys.stderr,
            )
            return 1

    if previous_schema == SCHEMA_046 and current_schema == SCHEMA_047:
        if transition_count == 0:
            print("rollback allowed: migration 047 has no direct lifecycle history")
            return 0
        print(
            "rollback refused: migration 047 has "
            f"{transition_count} direct lifecycle transition row(s); "
            "the 046 binary is not compatible with that durable history",
            file=sys.stderr,
        )
        return 1

    # Other schema boundaries retain the deployer's existing compatibility
    # policy. The reviewed migration floors above remain in force for every
    # future schema marker.
    print(
        "rollback allowed: no migration-047-specific boundary applies "
        f"({current_schema} -> {previous_schema})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

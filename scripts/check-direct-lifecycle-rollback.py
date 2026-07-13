#!/usr/bin/env python3
"""Decide the migration-047-specific binary rollback boundary."""

from __future__ import annotations

import sys


SCHEMA_046 = "046_chain_swap_tx_attempts"
SCHEMA_047 = "047_direct_payment_lifecycle_foundation"


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

    # This helper owns only the reviewed 047 -> 046 boundary. Other schema
    # boundaries retain the deployer's existing compatibility policy.
    print(
        "rollback allowed: no migration-047-specific boundary applies "
        f"({current_schema} -> {previous_schema})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

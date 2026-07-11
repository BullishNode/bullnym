> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# ITEM-016: Concurrency And Scale

Backlog reference: `ISSUE-015` / `OPT-013`
Type: scalability risk
Priority: P2
Status: closed

## Confirmed Conclusion

The hot paths already have targeted indexes: npub invoice list, status by primary key, payment observations by invoice, active invoice scans, and swap/chain-swap invoice indexes. No missing low-risk index was confirmed from static inspection.

## Non-Goals

- Do not add speculative indexes without query plans or measured contention.
- Do not treat sequential LN storm as concurrency proof.

## Verification Result

- Static query/index review found existing indexes for the known hot paths.
- Remaining proof: `CC-*` targeted run with query timing and connection-pool telemetry.

## Closure Decision

Closed for local index/code assessment. Performance certification remains measurement-driven.

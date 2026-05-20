# ITEM-020: Error Taxonomy

Backlog reference: `ISSUE-020` / `OPT-010`
Type: observability
Priority: P3
Status: closed

## Confirmed Conclusion

The current `AppError::code()` surface gives stable machine-readable codes for auth, invoice not found, address reuse, rate limits, service unavailable, and internal errors. No high-value taxonomy split was confirmed by the evidence beyond using existing codes consistently.

## Non-Goals

- Do not churn public error codes without mobile/client coordination.
- Do not leak sensitive internal details in user-facing reasons.

## Verification Result

- Existing tests assert important error codes in integration flows.
- Remaining work is client-driven: add subcodes only when a caller needs a distinct action.

## Closure Decision

Closed for local assessment. Keep future taxonomy changes demand-driven.

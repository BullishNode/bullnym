# ITEM-012: Rate-Limit And Certification Diagnostics

Backlog reference: `ISSUE-017`
Type: security/reliability tradeoff
Priority: P2
Status: closed

## Evidence

- Test reports: broad ARS runs with rate-limit contamination and skipped `RL-*` / `INVR-*` scenarios.
- Relevant code: `src/certification.rs`, `src/rate_limit.rs`, `tests/integration_test.rs`.

## Observed Behavior

The broad certification history could not distinguish normal production rate limiting from setup contamination or certification bypass. Earlier ITEM-005 added scoped certification allowlisting and `/certification/preflight`.

## Possible Interpretations

1. Production limits are too strict.
   - Evidence for: broad ARS skipped many scenarios.
   - Evidence against: redteam/protection evidence showed production caps doing useful abuse-prevention work.

2. Certification lacked deterministic preflight and diagnostics.
   - Evidence for: skips were caused by setup/rate-limit ambiguity.
   - Evidence against: ITEM-005 now exposes source/token/scope readiness before broad runs.

## Confirmed Conclusion

No new production rate-limit bug was confirmed after ITEM-005. The server-side diagnostic gap is closed enough for deterministic certification: broad runs must call `/certification/preflight` and fail setup if source, token, or scope is not ready.

## Non-Goals

- Do not weaken production rate limits.
- Do not add broad bypasses.
- Do not run broad ARS until preflight is green.

## Fix Planner Proposal

- Minimal server change: none in this item.
- Evidence update: mark rate-limit/certification support as partial rather than blocked because scoped preflight exists.
- Verification: existing certification unit tests and ITEM-005 integration compile coverage.

## Plan Reviewer Objections

- Objection: rate-limit behavior itself is still not exhaustively certified.
  - Resolution: this item closes the operational ambiguity that blocked certification. Exact limiter boundary tests remain useful but are not a blocker for running deterministic scoped certification.

## Planner/Reviewer Resolution

Record the closure as diagnostic/preflight completion. Keep production limiter semantics unchanged.

## Implementation Summary

- Files changed:
  - `docs/product-surface-coverage.md`
  - `docs/server-improvement-from-tests/README.md`
  - this item dossier
- Behavioral change: none in this item.

## Implementation Reviewer Findings

- Finding: certification decisions require source, token, and scope; configured scopes are hidden unless source and token are valid.
- Severity: none.
- Required fix: no production code change.

## Verification Result

- `cargo test certification::tests --lib`: pass, 3 tests.

## Closure Decision

Closed for diagnostic readiness. Boundary/abuse tests should run through the scoped certification preflight, not by weakening production limits.

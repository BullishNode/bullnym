# ITEM-010: Invoice State-Machine Edges

Backlog reference: `ISSUE-014`
Type: state correctness
Priority: P1
Status: closed

## Evidence

- Test reports: broad ARS runs with skipped `SM-*` invoice state-machine scenarios.
- Scenario IDs: `SM-01` through `SM-06`.
- Relevant code: `src/db/invoices.rs`, `src/invoice.rs`, `tests/integration_test.rs`.

## Observed Behavior

The server had DB-level idempotency tests for cancel, and payment accounting tests for terminal states, but the signed HTTP cancel path did not prove terminal paid invoices remain paid when a valid owner cancel arrives later.

## Possible Interpretations

1. DB state-machine rules are sufficient but not route-certified.
   - Evidence for: `cancel_invoice` only updates rows in `unpaid`.
   - Evidence against: route behavior after auth/ownership was not tested for terminal rows.

2. A valid owner cancel could mutate a paid invoice.
   - Evidence for: signed cancel is a privileged owner action.
   - Evidence against: the DB predicate prevents non-unpaid rows from becoming cancelled.

## Confirmed Conclusion

No production-code defect was confirmed. The smallest useful improvement is route-level regression coverage proving signed cancel is a terminal no-op for a paid invoice.

## Non-Goals

- Do not introduce a new state-machine abstraction in this item.
- Do not cover every rail-specific webhook duplicate locally.
- Do not change cancel semantics for `in_progress` or partial states without a product decision.

## Fix Planner Proposal

- Minimal server change: none.
- Test change:
  - Create a paid invoice through DB payment accounting.
  - Submit a valid signed cancel through the linked HTTP route.
  - Assert the response status remains `paid`.
  - Assert the DB row remains `paid`.
- Verification: compile integration tests; execute with `TEST_DATABASE_URL` when available.

## Plan Reviewer Objections

- Objection: one terminal paid case does not close all `SM-*` cases.
  - Resolution: this item closes the highest-value terminal mutation risk locally; duplicate webhook and in-progress edge certification remain live/DB expansion candidates if product policy changes.

## Planner/Reviewer Resolution

Add the terminal paid cancel regression test. Avoid broad state-machine refactors without a confirmed defect.

## Implementation Summary

- Files changed:
  - `tests/integration_test.rs`
  - `docs/product-surface-coverage.md`
  - `docs/server-improvement-from-tests/README.md`
  - this item dossier
- Behavioral change: none.
- Migration/backfill: none.

## Implementation Reviewer Findings

- Finding: `cancel_invoice` is guarded by `status = 'unpaid'`, so paid rows are terminal against cancel.
- Severity: none.
- Required fix: no production code change.

## Verification Result

- `cargo fmt --check`: pass.
- `cargo test --test integration_test --no-run`: pass.
- `cargo test invoice::tests --lib`: pass, 18 tests.
- DB-backed execution of the new route test is blocked locally because `TEST_DATABASE_URL` is not set.

## Closure Decision

Closed for local implementation. Remaining verification is DB-backed execution of the state-machine route test.

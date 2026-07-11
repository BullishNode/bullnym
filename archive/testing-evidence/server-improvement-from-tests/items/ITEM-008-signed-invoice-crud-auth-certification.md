> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# ITEM-008: Signed Invoice CRUD/Auth Certification

Backlog reference: `ISSUE-011`
Type: auth/API reliability
Priority: P1
Status: closed

## Evidence

- Test reports: broad ARS reports with skipped `INVS-*` and related invoice control-plane cases.
- Scenario IDs: `INVS-05` through `INVS-11`, `INVN-*` family.
- Server logs: not required for local auth-boundary certification.
- DB rows: local integration tests exercise invoice rows owned by two different npubs.
- Relevant code: `src/auth.rs`, `src/invoice.rs`, `src/db/invoices.rs`, `tests/integration_test.rs`.

## Observed Behavior

The test history did not provide clean certification evidence for signed invoice create/list/cancel edge behavior. Signed happy-path invoice creation existed, but cross-npub list isolation, cancel ownership denial, forged list signatures, and cancel idempotency were not covered by route-level integration tests.

## Possible Interpretations

1. The server auth boundaries are already correct, but unproven.
   - Evidence for: `src/invoice.rs` verifies v2 Schnorr signatures and filters list queries by the signed npub.
   - Evidence against: route-level tests did not exercise list/cancel paths.

2. Cross-npub list or cancel could leak or mutate another user's invoices.
   - Evidence for: these are high-value control-plane surfaces and were skipped in ARS.
   - Evidence against: code inspection shows list filters by `npub_owner`, and cancel checks both signature and invoice ownership.

3. Cancel idempotency could be inconsistent through the signed HTTP path.
   - Evidence for: DB helper had idempotency coverage, but route-level signed behavior was not exercised.
   - Evidence against: route code delegates to the DB helper after auth and ownership checks.

## Confirmed Conclusion

No production-code auth defect was confirmed in this pass. The highest-value improvement is route-level regression coverage for signed list/cancel authorization boundaries.

## Non-Goals

- Do not run live-money signed invoice settlement scenarios.
- Do not change signed v2 wire format.
- Do not alter rate-limit policy or certification allowlisting.
- Do not redefine whether the root cancel route may cancel a linked invoice owned by the same npub; this item covers cross-npub denial and linked-route idempotency.

## Fix Planner Proposal

- Minimal server change: none.
- Test change:
  - Add signed list route coverage to the integration test router.
  - Add signed cancel route coverage to the integration test router.
  - Add helpers for signed invoice list and signed invoice cancel payloads.
  - Add cross-npub list isolation, forged list signature rejection, cross-npub cancel denial, and repeated cancel idempotency tests.
- Schema/API compatibility: no schema or API change.
- Risks: local execution needs `TEST_DATABASE_URL`; compile-only verification is weaker than DB execution.
- Rollback plan: remove the new tests and test-router routes; no production rollback required.
- Verification: compile integration test binary, run auth/invoice unit tests, run DB-backed signed invoice integration tests when `TEST_DATABASE_URL` is available.

## Plan Reviewer Objections

- Objection: tests without production code may not feel like server improvement.
  - Resolution: this is an unknown-risk certification item. The smallest high-value improvement is preserving the already-present auth boundaries with route-level tests.
- Objection: route-level tests that do not execute locally are incomplete.
  - Resolution: keep compile verification locally and mark DB-backed execution as the remaining preflight-dependent verification.

## Planner/Reviewer Resolution

Proceed with focused route-level tests. Do not broaden into live settlement, rate-limit, or API redesign.

## Implementation Summary

- Files changed:
  - `tests/integration_test.rs`
  - `archive/testing-evidence/server-improvement-from-tests/items/ITEM-008-signed-invoice-crud-auth-certification.md`
  - `archive/testing-evidence/server-improvement-from-tests/README.md`
  - `docs/product-surface-coverage.md`
- Behavioral change: none in production code.
- Migration/backfill: none.
- Observability added: none.

## Implementation Reviewer Findings

- Finding: production signed list and cancel handlers already enforce the relevant auth boundaries.
- Severity: none.
- Evidence: list verifies the signature over `npub`, page, page size, and status, then filters by that same `npub`; cancel verifies the signed action and rejects mismatched `npub_owner`.
- Required fix: no production code change.

## Implementer/Reviewer Resolution

Added route-level regression tests instead of changing production behavior.

## Verification Result

- `cargo fmt`: pass.
- `cargo test --test integration_test --no-run`: pass.
- `cargo test invoice::tests --lib`: pass, 18 tests.
- `cargo test auth::tests --lib`: pass, 15 tests.
- `cargo test --test integration_test signed_invoice`: blocked locally because `TEST_DATABASE_URL` is not set.

## Closure Decision

Closed for local implementation. Remaining verification is to run `cargo test --test integration_test signed_invoice` in an environment with `TEST_DATABASE_URL`.

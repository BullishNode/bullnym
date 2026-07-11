> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# ITEM-009: Anonymous Invoice Control-Plane

Backlog reference: `ISSUE-012`
Type: payment-page/API reliability
Priority: P1
Status: closed

## Evidence

- Test reports: broad ARS runs with skipped anonymous invoice control-plane scenarios.
- Scenario IDs: `INV-*`.
- Relevant code: `src/invoice.rs`, `tests/integration_test.rs`.

## Observed Behavior

Live payment evidence showed some payment-page money flows working, but did not prove render/status control-plane behavior such as linked route ownership, unlinked render access, and JSON status agreement after terminal payment.

## Possible Interpretations

1. The control plane is correct but unproven.
   - Evidence for: `render_payment` explicitly checks `nym_owner` against the path nym, while status is id-only and public.
   - Evidence against: previous integration router did not exercise render paths.

2. Cross-nym render could expose a linked invoice under another merchant path.
   - Evidence for: this is a common route-ownership failure mode.
   - Evidence against: production code rejects mismatched `nym_owner`.

3. Render and status could diverge after payment.
   - Evidence for: render and status build projections through different code paths.
   - Evidence against: both read the same invoice row and status helpers.

## Confirmed Conclusion

No production-code defect was confirmed. The highest-value server improvement is route-level regression coverage for linked render ownership and terminal status projection.

## Non-Goals

- Do not create anonymous invoices through the test route because checkout creation eagerly calls Boltz.
- Do not run live-money payment-page flows here.
- Do not change public status endpoint privacy semantics.

## Fix Planner Proposal

- Minimal server change: none.
- Test change:
  - Add linked and unlinked render routes to the integration test router.
  - Prove correct nym path renders.
  - Prove wrong nym path returns `InvoiceNotFound`.
  - Prove `/invoice/<id>` render still serves the invoice.
  - Prove status returns terminal paid state and no reusable Lightning PR after exact payment.
- Verification: compile integration tests; execute with `TEST_DATABASE_URL` when available.

## Plan Reviewer Objections

- Objection: not creating checkout invoices through HTTP leaves anonymous create untested.
  - Resolution: the local app uses a dead Boltz URL, so route-level create would test network failure rather than server control-plane semantics. Creation remains a live/VM certification case.

## Planner/Reviewer Resolution

Use inserted invoice rows for deterministic render/status certification. Leave live checkout creation to targeted ARS/VM tests.

## Implementation Summary

- Files changed:
  - `tests/integration_test.rs`
  - `docs/product-surface-coverage.md`
  - `archive/testing-evidence/server-improvement-from-tests/README.md`
  - this item dossier
- Behavioral change: none.
- Migration/backfill: none.

## Implementation Reviewer Findings

- Finding: linked render ownership is explicitly enforced before template rendering.
- Severity: none.
- Required fix: no production code change.

## Verification Result

- `cargo fmt --check`: pass.
- `cargo test --test integration_test --no-run`: pass.
- `cargo test invoice::tests --lib`: pass, 18 tests.
- DB-backed execution of the new route tests is blocked locally because `TEST_DATABASE_URL` is not set.

## Closure Decision

Closed for local implementation. Remaining verification is DB-backed execution plus live checkout-create coverage.

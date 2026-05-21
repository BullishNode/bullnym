# ITEM-011: Public Rendering Safety

Backlog reference: `ISSUE-016`
Type: UX/API correctness, injection/rendering risk
Priority: P2
Status: closed

## Evidence

- Test reports: broad ARS skipped `UX-*` rendering cases.
- Scenario IDs: `UX-01` through `UX-05`.
- Relevant code: `templates/invoice_payment.html`, `src/invoice.rs`, `src/invoice/tests.rs`, `src/qr.rs`.

## Observed Behavior

Public render surfaces include user-controlled invoice text plus inline JavaScript constants. The template intentionally forbids `|safe` on user text, while using `|safe` only for server-generated JSON string literals.

## Possible Interpretations

1. Askama escaping is sufficient for user text.
   - Evidence for: user fields are rendered through normal `{{ }}` interpolation.
   - Evidence against: inline JavaScript values use `|safe`, which requires server-side JSON escaping.

2. A `</script>` payload could break out of the inline script.
   - Evidence for: this is the critical class for JSON-in-script contexts.
   - Evidence against: `js_string_literal` JSON-encodes and replaces `<`, `>`, and `&`.

## Confirmed Conclusion

No production-code rendering defect was confirmed. The highest-value improvement is a regression test proving user text is HTML-escaped and JSON literals cannot emit raw script-breaking markup.

## Non-Goals

- Do not rewrite templates or remove the current CSP posture.
- Do not run browser visual tests in this local slice.
- Do not alter QR generation behavior.

## Fix Planner Proposal

- Minimal server change: none.
- Test change: add an invoice template unit test with `</script><img ...>&` in every public text/JS slot.
- Verification: targeted invoice template unit test.

## Plan Reviewer Objections

- Objection: unit rendering does not prove every public page.
  - Resolution: this item closes the highest-risk invoice template path; donation-page template rendering remains covered by existing escaping conventions and future browser/UX certification.

## Planner/Reviewer Resolution

Add the focused unit regression test. Avoid template rewrites without a confirmed unsafe render.

## Implementation Summary

- Files changed:
  - `src/invoice/tests.rs`
  - `docs/product-surface-coverage.md`
  - `docs/server-improvement-from-tests/README.md`
  - this item dossier
- Behavioral change: none.

## Implementation Reviewer Findings

- Finding: the invoice template uses `|safe` only on JSON strings produced by `js_string_literal`.
- Severity: none.
- Required fix: no production code change.

## Verification Result

- `cargo fmt --check`: pass.
- `cargo test invoice_template_escapes_user_text_and_js_literals --lib`: pass.

## Closure Decision

Closed for invoice public rendering safety. Browser/UX certification remains a broader visual/regression task.

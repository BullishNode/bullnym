# ITEM-004: Server-Owned Coverage Map

Backlog reference: `OPT-015`
Type: documentation / test efficiency / reliability governance
Priority: medium
Status: closed

## Evidence

- Test reports:
  - Broad ARS/certify reports with hundreds of skipped cases.
  - Clean live matrix `1779135713`.
  - Liquid V2 `1779151124`.
  - Invalid stale-binary Liquid run `1779153846`.
  - BTC V2 runs `1779139541` and `1779140155`.
- Scenario IDs:
  - Proven examples: clean LN/Liquid matrix, Liquid V2 happy paths, LN storm 20/90.
  - Unknown/blocked groups: `BTC-*`, `LN-*`, `INVS-*`, `INV-*`, `DCHAIN-*`, `SM-*`, `UX-*`, `CC-*`, `RL-*`, `OP-*`.
- Server logs:
  - Not needed for this documentation item.
- DB rows:
  - Not needed for this documentation item.
- External refs:
  - None.
- Relevant code:
  - `src/main.rs` route map.
  - `src/version.rs`.
  - `docs/server-improvement-from-tests/01-evidence-index.md`.
  - `docs/server-improvement-from-tests/02-scenario-classification.md`.
  - `docs/server-improvement-from-tests/06-improvement-backlog.md`.
  - `docs/server-improvement-from-tests/07-next-verification-matrix.md`.
  - `docs/server-improvement-from-tests/09-expanded-issue-and-optimization-inventory.md`.

## Observed Behavior

The evidence review showed repeated confusion between proven behavior, unknown-risk surfaces, operationally blocked tests, and invalid historical runs. Without a server-owned coverage ledger, future test runs can waste money and time repeating known-good paths while still missing areas that are unproven.

## Possible Interpretations

1. A server repo coverage ledger is enough for this item.
   - Evidence for:
     - `OPT-015` is categorized as documentation.
     - The immediate problem is planning and evidence interpretation, not runtime behavior.
   - Evidence against:
     - A machine-readable artifact could help automation later.
   - How to prove/disprove:
     - Use the map to choose the next targeted verification run; if it prevents broad reruns, it succeeds.

2. The server should expose a public coverage endpoint.
   - Evidence for:
     - The phrase "server-owned" could be interpreted literally.
   - Evidence against:
     - Coverage claims are manual and can go stale.
     - Public runtime output should not publish stale certification claims.
     - Certification allowlisting is a separate later item.
   - How to prove/disprove:
     - Revisit only after the coverage map becomes machine-maintained.

3. This belongs in `bullnym-test`, not Bullnym server.
   - Evidence for:
     - The evidence comes from test runs.
   - Evidence against:
     - The goal is to improve Bullnym server and avoid endless test-suite iteration.
     - Server maintainers need a repo-local source of truth.
   - How to prove/disprove:
     - Check whether Bullnym server planning can use the map without opening the test suite.

## Confirmed Conclusion

The smallest useful server improvement is a repo-owned coverage document. It should classify product surfaces as `proven`, `partial`, `unknown`, `blocked`, or `invalid-history`, and state which tests should not be rerun by default.

## Non-Goals

- Do not add a database table.
- Do not add a public endpoint.
- Do not add an admin UI.
- Do not rerun live-money tests just to fill the map.
- Do not add a new product claim.
- Do not treat skipped or blocked scenarios as product failures.
- Do not solve safe certification allowlisting in this item.

## Fix Planner Proposal

- Minimal server change:
  - Add `docs/product-surface-coverage.md`.
  - Add this item dossier.
- Files likely touched:
  - `docs/product-surface-coverage.md`.
  - `docs/server-improvement-from-tests/items/ITEM-004-server-owned-coverage-map.md`.
- Schema/API compatibility:
  - None.
- Risks:
  - Stale manual claims.
  - Overstating partial evidence as proven.
  - Duplicating the next verification matrix without adding durable ownership.
- Rollback plan:
  - Remove or revise docs; no runtime impact.
- Verification:
  - Markdown/content review.
  - Confirm it names known do-not-rerun surfaces and blocked preflights.
- Tests not to rerun:
  - All live-money and ARS suites.

## Plan Reviewer Objections

- Define evidence rules before writing statuses.
- Add strict status definitions.
- Skipped surfaces must not be described as failed.
- Make the rerun policy conditional, not absolute.
- Link the new coverage document into the existing evidence system.
- Keep this as a dossier/plan item, not a runtime fix item.

## Planner/Reviewer Resolution

- Added evidence rules that allow scenario outcomes from the evidence docs and route ownership from `src/main.rs` route registration/handler modules.
- Added strict status definitions in `docs/product-surface-coverage.md`.
- Changed skipped rows to say `skipped/unassessed` where relevant.
- Renamed the final table column to `Rerun policy` and made every entry conditional.
- Linked the coverage ledger from the review README, backlog, next verification matrix, and expanded inventory.
- The plan intentionally does not add runtime code, a migration, an endpoint, an admin UI, a new test run, or a new product claim.
- Any machine-readable coverage artifact is a follow-up only after certification data is produced deterministically.

## Implementation Summary

- Files changed:
  - `docs/product-surface-coverage.md`
  - `docs/server-improvement-from-tests/items/ITEM-004-server-owned-coverage-map.md`
  - `docs/server-improvement-from-tests/README.md`
  - `docs/server-improvement-from-tests/06-improvement-backlog.md`
  - `docs/server-improvement-from-tests/07-next-verification-matrix.md`
  - `docs/server-improvement-from-tests/09-expanded-issue-and-optimization-inventory.md`
- Behavioral change:
  - None.
- Migration/backfill:
  - None.
- Observability added:
  - Server maintainers now have a durable coverage ledger that distinguishes known-good, partial, unknown, blocked, invalid-history, and external-funding surfaces.

## Implementation Reviewer Findings

- Plan reviewer findings were applied directly because this is documentation-only and no runtime code was introduced.

## Implementer/Reviewer Resolution

- Coverage map now has evidence rules, strict status definitions, conditional rerun policies, skipped/unassessed wording, and links from the existing evidence system.

## Verification Result

- Documentation-only change. No code tests required.
- Local review confirms the map includes:
  - proven/smoke-only surfaces,
  - unknown-risk surfaces,
  - blocked preflight surfaces,
  - invalid stale-binary run,
  - explicit conditional rerun guidance.

## Closure Decision

- Closed for documentation implementation.

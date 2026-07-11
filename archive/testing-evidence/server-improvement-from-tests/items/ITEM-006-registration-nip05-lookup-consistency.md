> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# ITEM-006: Registration, NIP-05, And Lookup Consistency

Backlog reference: `ISSUE-003` / `OPT-008`
Type: correctness / simplification
Priority: high
Status: closed

## Evidence

- Test reports:
  - Broad ARS and certify runs.
- Scenario IDs:
  - `R10`
  - `R16`
  - related callback setup: `C01`, `C02`, `C08`
- Relevant code:
  - `src/db/users.rs`
  - `src/registration.rs`
  - `src/nostr.rs`
  - `src/lnurl.rs`
  - `src/invoice.rs`

## Observed Behavior

`R10` reported NIP-05 lookup returning `NymNotFound` after registration. `R16` reported lookup-by-npub returning empty or inactive data. The same broad run also had rate-limit contamination, so the evidence does not prove a single lookup bug. It does prove that active nym resolution was spread across multiple handlers, making targeted verification harder.

## Possible Interpretations

1. Rate-limit/setup contamination caused valid lookup scenarios to run against missing fixtures.
   - Evidence for: broad ARS had many `RateLimitedNetwork` setup failures.
   - Evidence against: `R10` and `R16` specifically point at lookup surfaces.

2. Active nym lookup semantics diverged across NIP-05, LNURL metadata, callback, reservation sync, and payment-page invoice creation.
   - Evidence for: several handlers used `get_user_by_nym` and then each checked active state locally.
   - Evidence against: most local logic was equivalent.

3. Lookup-by-npub was nondeterministic.
   - Evidence for: active query used `LIMIT 1` without `ORDER BY`.
   - Evidence against: database has a partial unique index for active npub rows, so more than one active row should not exist.

## Confirmed Conclusion

The safe server improvement is to centralize active nym lookup and make lookup-by-npub ordering explicit. This does not claim to prove the historical `R10`/`R16` root cause; it makes the next targeted rerun attributable.

## Non-Goals

- Do not claim broad ARS registration failures were all server bugs.
- Do not change registration lifecycle policy.
- Do not change inactive nym reservation semantics.
- Do not broaden certification bypasses.

## Fix Planner Proposal

- Minimal server change:
  - Add `db::get_active_user_by_nym`.
  - Use it in NIP-05, LNURL metadata, LNURL callback, reservation sync, and active payment-page invoice creation.
  - Add deterministic `ORDER BY created_at DESC` to active lookup-by-npub projection.
- Files likely touched:
  - `src/db/users.rs`
  - `src/nostr.rs`
  - `src/lnurl.rs`
  - `src/registration.rs`
  - `src/invoice.rs`
- Schema/API compatibility:
  - No schema change.
  - No API shape change.
- Risks:
  - Payment-page invoice creation now explicitly rejects inactive owners through the active helper.
- Rollback plan:
  - Restore local active checks; no migration involved.
- Verification:
  - Compile.
  - Full library tests.
  - Integration compile.
  - Targeted post-deploy rerun: `R10`, `R16`, `C01`.
- Tests not to rerun:
  - Live payment matrix.

## Plan Reviewer Objections

- Subagent review unavailable due usage limit. Local objection: this change does not prove the historical bug; docs must say it is an attribution/consistency fix.

## Planner/Reviewer Resolution

- The item explicitly treats the historical cause as ambiguous.
- The code change is intentionally small and only centralizes equivalent active lookup behavior.

## Implementation Summary

- Added `db::get_active_user_by_nym`.
- NIP-05 and LNURL metadata now use the shared active helper.
- LNURL callback now uses the shared active helper.
- Reservation sync now uses the shared active helper.
- Anonymous payment-page invoice creation now resolves the page owner through the shared active helper.
- `lookup_status_by_npub` now orders active rows explicitly before `LIMIT 1`.

## Implementation Reviewer Findings

- Local review found no blocking issue.
- Residual risk: DB-backed route behavior tests require `TEST_DATABASE_URL`; local verification compiles them but does not execute them.

## Implementer/Reviewer Resolution

- No additional code changes after local review.

## Verification Result

- `cargo fmt --check`: pass.
- `cargo check`: pass.
- `cargo test --lib`: pass, 202 tests.
- `cargo test --test integration_test --no-run`: pass.

## Closure Decision

- Closed for ITEM-006. Targeted post-deploy verification remains `R10`, `R16`, and `C01` after certification preflight passes.

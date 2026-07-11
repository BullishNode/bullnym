> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# ITEM-007: Liquid Callback Lookup And Last-Unused Semantics

Backlog reference: `ISSUE-004` / `OPT-008`
Type: correctness / funds-safety
Priority: high
Status: closed

## Evidence

- Test reports:
  - Broad ARS and certify runs.
- Scenario IDs:
  - `C01`
  - `C02`
  - `C08`
- Relevant code:
  - `src/lnurl.rs`
  - `src/db/reservations.rs`
  - `src/chain_watcher.rs`
  - `src/db/watcher.rs`

## Observed Behavior

The recorded callback scenarios failed before they reached meaningful Liquid address semantics. They reported `NymNotFound` and zero successful callback addresses. That evidence is ambiguous because broad ARS runs were contaminated by setup and rate-limit failures.

After `ITEM-006`, active nym lookup is centralized. The remaining server question was whether Liquid last-unused address semantics are correct once the callback reaches the Liquid branch.

## Facts

- `allocate_outpoint_address` is idempotent for `(nym, outpoint)`.
- It returns the original `addr_index` on cache hits.
- It does not advance `users.next_addr_idx`; the chain watcher advances that cursor when address history is observed.
- `serve_liquid` previously ignored the cached or newly allocated reservation index.
- `serve_liquid` derived the response address from the `user.next_addr_idx` value loaded before reservation handling.

## Possible Interpretations

1. Callback failures were only setup contamination.
   - Evidence for: broad ARS had many invalid setup/rate-limit results.
   - Evidence against: this does not prove last-unused semantics once callbacks succeed.

2. Last-unused behavior was correct because reservations were idempotent.
   - Evidence for: the DB helper returned the cached index.
   - Evidence against: the callback handler did not use that returned/cached index for the response.

3. Repeated callbacks could drift to a newer address after the watcher advanced `next_addr_idx`.
   - Evidence for: the response was derived from `user.next_addr_idx`, not `outpoint_addresses.addr_index`.
   - Evidence against: if the cursor did not advance between callbacks, the bug would not manifest.

## Confirmed Conclusion

The server had a real correctness bug in the Liquid callback response path. The reservation table preserved last-unused identity, but the handler could return a different address if `next_addr_idx` moved after the first reservation.

## Non-Goals

- Do not change LUD-22 proof validation.
- Do not bypass proof-of-funds for production Liquid callbacks.
- Do not change whitelisted simulator behavior; whitelisted callbacks have no proof/outpoint reservation to bind to.
- Do not change chain watcher cursor-advance policy.

## Fix Planner Proposal

- Minimal server change:
  - Capture the cached or newly allocated `addr_index` in `serve_liquid`.
  - Derive the Liquid response address from that reservation index for non-whitelisted callbacks.
  - Keep whitelisted callbacks deriving from `user.next_addr_idx`.
  - Add a small pure helper so response-index semantics can be unit tested without Electrum.
- Files touched:
  - `src/lnurl.rs`
  - `src/lnurl/tests.rs`
  - `tests/integration_test.rs`
- Schema/API compatibility:
  - No schema change.
  - No response shape change.
- Risks:
  - A cached reservation for an already fulfilled outpoint can still return the old address. That is current last-unused behavior and should be assessed separately if product policy wants spent-outpoint callbacks to hard fail after fulfillment.
- Rollback plan:
  - Restore response derivation from `user.next_addr_idx`; no migration involved.
- Verification:
  - Compile.
  - LNURL unit tests.
  - Full library tests.
  - Integration compile.
  - DB-backed reservation test when `TEST_DATABASE_URL` is available.
  - Targeted post-deploy rerun: `C01`, `C02`, `C08`.

## Plan Reviewer Objections

- Subagent review unavailable due usage limit. Local objection: a pure helper test alone would not prove the DB reservation helper keeps the original index.
- Local objection: a DB helper test alone would not prove the handler uses the reservation index.
- Local objection: changing whitelisted behavior could break certification or simulator callbacks that intentionally do not carry proof fields.

## Planner/Reviewer Resolution

- Add both a pure response-index unit test and a DB reservation integration test.
- Keep whitelisted behavior unchanged.
- Document the residual fulfilled-outpoint policy question instead of silently expanding behavior.

## Implementation Summary

- `serve_liquid` now stores the cached or newly allocated outpoint reservation index.
- Non-whitelisted Liquid responses derive from the reservation index.
- Whitelisted Liquid responses continue deriving from the active user's current cursor.
- Added `liquid_response_addr_index` unit coverage for current-cursor, reserved-index, and invalid negative-index paths.
- Added DB integration coverage proving repeated allocation of the same outpoint returns the original index after `next_addr_idx` advances.

## Implementation Reviewer Findings

- Local review found the handler still verifies proof ownership before cache lookup, preserving the existing security gate.
- Local review found rate-limit soft-fallback behavior unchanged.
- Residual risk: full callback route execution with real proof/Electrum remains a post-deploy targeted test, because local integration execution requires a configured test database and UTXO backend.

## Implementer/Reviewer Resolution

- No additional production code change after local review.
- Keep `C01`, `C02`, and `C08` in the next targeted verification batch.

## Verification Result

- `cargo fmt --check`: pass.
- `cargo check`: pass.
- `cargo test lnurl::tests`: pass, 19 tests.
- `cargo test --lib`: pass, 206 tests.
- `cargo test --test integration_test --no-run`: pass.
- DB-backed integration execution: not run locally because `TEST_DATABASE_URL` is required.

## Closure Decision

Closed for ITEM-007. The server-side last-unused response bug is fixed. Live or VM targeted verification remains required for `C01`, `C02`, and `C08`.

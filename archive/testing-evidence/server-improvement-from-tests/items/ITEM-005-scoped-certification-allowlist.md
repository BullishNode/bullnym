> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# ITEM-005: Scoped Certification Allowlist

Backlog reference: `ISSUE-008` / `ISSUE-005` / `OPT-014`
Type: operations / security / certification reliability
Priority: high
Status: closed

## Evidence

- Test reports:
  - Broad ARS/certify reports with 306+ setup skips and repeated `RateLimitedNetwork`.
  - Redteam report `docs/redteam-2026-05-07.md`.
- Scenario IDs:
  - Broad setup-gated groups: `R*`, `C*`, `BTC-*`, `LN-*`, `INVS-*`, `INV-*`, `RL-*`, `CC-*`, `UX-*`, `OP-*`.
- Relevant code:
  - `src/config.rs`
  - `src/ip_whitelist.rs`
  - `src/rate_limit.rs`
  - `src/registration.rs`
  - `src/lnurl.rs`
  - `src/invoice.rs`
  - `src/main.rs`

## Observed Behavior

Production defenses worked well enough to contaminate broad certification. Existing `rate_limit.ip_whitelist` is too broad for ARS because it bypasses all rate limits and proof requirements. That makes certification deterministic, but it can also hide real abuse-protection behavior and weaken LUD-22 proof/reservation defenses.

## Possible Interpretations

1. The server should disable rate limiting during tests.
   - Evidence for: it would reduce skips.
   - Evidence against: it would invalidate attack-protection evidence and hide real production behavior.

2. Existing `ip_whitelist` should be used for ARS.
   - Evidence for: it already exists and handlers honor it.
   - Evidence against: it bypasses proof-of-funds and unrelated route protections across the whole source.

3. The server needs a separate, scoped certification capability.
   - Evidence for: docs call for preserving protection while avoiding false negatives, and `OPT-014` calls for narrower scopes.
   - Evidence against: more route plumbing is needed.

## Confirmed Conclusion

Certification needs a separate, scoped decision path. It must require an allowed source, a secret token, and an explicit scope. It must not bypass LUD-22 proof-of-funds, pending-reservation caps, Electrum buckets, webhook caps, or global active-user ceilings by default.

## Non-Goals

- Do not globally disable rate limits.
- Do not replace production `ip_whitelist`.
- Do not bypass LUD-22 proof-of-funds in this item.
- Do not bypass webhook rate limits in this item.
- Do not solve lookup correctness (`R10`, `R16`, `C01`) here.
- Do not make broad ARS green by hiding real auth, lookup, rail, or payment bugs.

## Fix Planner Proposal

- Minimal server change:
  - Add `[certification]` config with `enabled`, `source_allowlist`, `token`, and explicit `scopes`.
  - Add `CertificationAllowlist` decision helper.
  - Add `GET /certification/preflight` so ARS can fail before moving money if scopes/source/token are wrong.
  - Add structured audit logs for scoped bypasses.
  - Wire only narrow scopes:
    - `registration_setup`
    - `metadata_lookup`
    - `invoice_create`
    - `invoice_status`
    - `live_money_offer`
- Files likely touched:
  - `src/config.rs`
  - `src/certification.rs`
  - `src/lib.rs`
  - `src/main.rs`
  - `src/registration.rs`
  - `src/lnurl.rs`
  - `src/invoice.rs`
  - `tests/integration_test.rs`
- Schema/API compatibility:
  - No database migration.
  - Additive preflight endpoint.
  - Existing `ip_whitelist` behavior remains unchanged.
- Risks:
  - Incorrect scope mapping could bypass too much.
  - Token/source config mistakes could cause preflight failure.
  - Audit logs must not expose the token.
- Rollback plan:
  - Disable `[certification].enabled`; scoped bypasses stop matching.
- Verification:
  - Unit-test source + token + scope decision.
  - Compile and run full lib tests.
  - Compile integration tests.
- Tests not to rerun:
  - Broad ARS until preflight proves configured scopes.

## Plan Reviewer Objections

- Subagent review was unavailable due usage limit, so a separate local review was performed against the same criteria.
- Finding: preflight should not expose configured scopes to callers that do not match both allowed source and token.
- Finding: docs must make clear this is not `ip_whitelist` and does not bypass LUD-22 proof/reservation/backend protections.

## Planner/Reviewer Resolution

- Preflight now returns configured scopes only when source and token are both valid.
- README documents the certification allowlist and preflight usage.
- nginx snippet excludes `/certification/preflight` from the donation HTML fallback rate-limit regex so it reaches the server route consistently.

## Implementation Summary

- Added `src/certification.rs`.
- Added `[certification]` config.
- Added `AppState.certification`.
- Added `/certification/preflight`.
- Wired scoped bypasses for registration setup, metadata lookup, invoice create, invoice status, and live money offer creation.
- Left LUD-22 proof, pending reservation caps, Electrum buckets, webhook caps, and global active-user ceilings protected.

## Implementation Reviewer Findings

- No blocking security regression found in local review.
- Confirmed certification does not alter `src/lnurl.rs::serve_liquid`, where proof-of-funds, per-pubkey, distinct-nym, pending-reservation, and Electrum bucket checks remain tied only to `ip_whitelist`, not certification.
- Confirmed webhook handlers still use only `ip_whitelist` for webhook rate-limit bypass.
- Confirmed `register` still applies `check_max_active_users` for certification callers; only broad `ip_whitelist` bypasses it.
- Nonblocking: route-level DB-backed tests for scoped bypass behavior require `TEST_DATABASE_URL` and remain compile-only locally.

## Implementer/Reviewer Resolution

- Hardened preflight scope disclosure.
- Added certification README and nginx notes.
- Kept scoped bypasses limited to registration setup, metadata lookup, invoice create, invoice status, and live money offer.

## Verification Result

- `cargo fmt --check`: pass.
- `cargo check`: pass.
- `cargo test certification::tests`: pass, 3 tests.
- `cargo test --lib`: pass, 202 tests.
- `cargo test --test integration_test --no-run`: pass.

## Closure Decision

- Closed for ITEM-005. Next valid broad ARS attempt must first pass `/version` and `/certification/preflight` with the required scopes.

> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# ITEM-001: Build And Version Provenance

Backlog reference: `ISSUE-006` / `OPT-003`
Type: operational server safety
Priority: P0
Status: closed

## Evidence

- Test reports:
  - `bullnym-run-1779153846-liquidv2.json`: Liquid V2, 22 records, 0 pass / 22 fail / 0 skip.
  - `bullnym-run-1779153895-liquidv2.json`: `LQ-01` passed after rollback.
  - `bullnym-run-1779154122-liquidv2.json`: `LQ-01` passed after correct `bullnym/main` deploy.
- Scenario IDs:
  - `LQ-01` through `LQ-22` in the invalid deploy run.
- Server logs:
  - Not captured in this repo.
- DB rows:
  - Not needed for this item. The issue is release provenance, not invoice state.
- External refs:
  - None.
- Relevant code:
  - `src/main.rs` registers `/health` and returns static `"ok"`.
  - `src/reserved_nyms.rs` blocks route-shadowing slugs but does not include `version`.
  - `README.md` documents production as local `cargo build --release` plus `scp`, with manual migrations and no in-process `sqlx::migrate!()`.

## Observed Behavior

The server can be alive and return `/health = ok` while running a stale or incompatible binary. During the invalid Liquid run, signed invoice auth and anonymous checkout behavior failed broadly. Rollback and correct deploy restored a smoke path.

## Possible Interpretations

1. Wrong or stale binary was deployed.
   - Evidence for: immediate 22/22 Liquid failure, then rollback/correct deploy smoke success.
   - Evidence against: exact wrong commit is not recorded in the repo.
   - How to prove/disprove: expose runtime build commit and compare it before live-money tests.

2. Schema drift contributed.
   - Evidence for: production migrations are manual and no `_sqlx_migrations` table exists.
   - Evidence against: the adjacent smoke pass after correct deploy suggests binary provenance was the dominant issue.
   - How to prove/disprove: expose a static server-expected schema marker and later add DB-backed schema state if needed.

3. Runtime environment/config mismatch contributed.
   - Evidence for: `/health` cannot reveal runtime mode or artifact provenance.
   - Evidence against: no direct evidence from the run reports.
   - How to prove/disprove: expose runtime mode/build metadata and deploy preflight.

4. Liquid product regression.
   - Evidence for: 22 Liquid cases failed during one run.
   - Evidence against: earlier valid Liquid run and later `LQ-01` smokes passed.
   - How to prove/disprove: do not treat the invalid run as product evidence; require `/version` before reruns.

## Confirmed Conclusion

Bullnym needs a lightweight runtime provenance endpoint. `/health` should remain cheap liveness, but it is insufficient as a deploy or certification gate.

## Non-Goals

- Do not rewrite deployment.
- Do not introduce in-process migrations.
- Do not add authenticated admin infrastructure.
- Do not make `/health` perform dependency checks.
- Do not solve all schema provenance now.

## Fix Planner Proposal

- Minimal server change:
  - Add `GET /version` returning JSON with service name, crate version, build commit, build branch, build time, runtime mode, and expected schema marker.
  - Keep `/health` unchanged as static liveness.
  - Add `version` to reserved nyms.
  - Document the endpoint and deploy preflight expectation.
- Files likely touched:
  - `src/main.rs`
  - `src/reserved_nyms.rs`
  - `src/reserved_nyms/tests.rs`
  - `README.md`
  - this item file
- Schema/API compatibility:
  - No database migration.
  - New public endpoint only.
  - Existing `/health` behavior preserved.
- Build metadata source:
  - Use `option_env!` for `BULLNYM_BUILD_COMMIT`, `BULLNYM_BUILD_BRANCH`, `BULLNYM_BUILD_TIME`, and `BULLNYM_RUNTIME_MODE`.
  - Use `env!("CARGO_PKG_VERSION")` for crate version.
  - Use a static expected schema marker matching the latest migration filename.
- Risks:
  - If build env vars are not set, endpoint returns `"unknown"` for those fields.
  - Static schema marker does not prove the DB has actually applied migrations.
- Rollback plan:
  - Remove `/version` route and reserved slug addition. No data rollback.
- Verification:
  - `cargo check`
  - `cargo test reserved_nyms`
  - If practical, a route/unit test or local run curl can be added later.
- Tests not to rerun:
  - No live-money tests.
  - No Liquid V2 suite.
  - No ARS broad run.
- Why not bigger:
  - A deploy gate only needs runtime metadata first. DB-backed schema verification and CI artifact signing can be separate items after the server exposes enough information for preflight.

## Plan Reviewer Objections

- P0: Optional build metadata is not enough. Unknown commit/build time must fail deploy preflight.
- P0: The plan needs an executable preflight contract, not just a descriptive endpoint.
- P1: Runtime mode should be runtime configuration, not compile-time build metadata.
- P1: Static schema marker should be named `expected_schema_marker`, because it does not prove DB migrations were applied.
- P1: Dirty/local builds must be distinguishable from clean committed builds.
- P2: Public `/version` exposure must be explicit and must not include secrets or dependency endpoints.
- P2: Route-level verification should be required.

## Planner/Reviewer Resolution

Accepted.

Final plan changes:

- `/version` returns `expected_schema_marker`, not `schema_version`.
- `/version` returns runtime mode from the running process environment.
- `/version` returns `build_dirty` from build metadata.
- Missing or `"unknown"` build metadata is allowed in local development but documented as a deploy/live-money preflight failure.
- README gets concrete build metadata injection and preflight comparison instructions.
- nginx snippet excludes `/version` from donation fallback rate limiting like `/health`.
- Add route-level test for `/version` JSON plus reserved-nym test.

Residual risk:

- The endpoint still cannot prove the production DB actually applied the expected migration. That remains separate follow-up work because this repo currently has manual migrations and no in-process migration table.

## Implementation Summary

- Added `src/version.rs` with `GET /version` JSON response fields:
  - `service`
  - `crate_version`
  - `build_commit`
  - `build_branch`
  - `build_time`
  - `build_dirty`
  - `runtime_mode`
  - `expected_schema_marker`
- Registered `/version` before the donation-page fallback.
- Added `version` to reserved nyms.
- Updated nginx snippet so `/version` is treated like an explicit route.
- Updated README with metadata-injected build command, runtime-mode systemd guidance, and executable `curl | jq -e` preflight.
- Added unit-level route test for the version handler and reserved-nym coverage.

## Implementation Reviewer Findings

- P1: README required non-unknown `runtime_mode` but did not document where to set `BULLNYM_RUNTIME_MODE`.
- P1: README had prose preflight checks but not an executable preflight command.
- P2: The route test uses a minimal router around the handler, not the production `build_router`.

## Implementer/Reviewer Resolution

- Fixed the runtime-mode documentation gap with a systemd `Environment=BULLNYM_RUNTIME_MODE=production` example.
- Fixed the executable preflight gap with a `curl -fsS ... | jq -e ...` command.
- Accepted the production-router test limitation as residual risk. Moving `build_router` out of the binary or constructing full `AppState` in `main.rs` tests would add more machinery than this item needs. Route registration is small and visible in `src/main.rs`; the handler itself is covered.

## Verification Result

- `cargo fmt --check`: passed.
- `cargo check`: passed.
- `cargo test version::tests::version_route_returns_public_build_metadata`: passed.
- `cargo test reserved_nyms`: passed.
- Full `cargo test` not run as closure gate because existing integration tests require `TEST_DATABASE_URL`; this item is covered by targeted unit checks.

## Closure Decision

Closed for ITEM-001. Follow-up remains for actual DB migration verification; `/version.expected_schema_marker` only states what schema the binary expects.

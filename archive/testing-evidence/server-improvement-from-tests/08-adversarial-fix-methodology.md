# 08 Adversarial Fix Methodology

This is the required method for turning each Bullnym server issue or optimization into a reviewed implementation. The goal is server improvement with evidence, not test-suite churn.

## Non-Negotiable Rules

1. No issue may be fixed until the evidence and possible interpretations are written down.
2. No fix plan may be implemented until it has been reviewed by a separate reviewer.
3. Planner and reviewer must resolve disagreements before implementation.
4. Implementation must be reviewed by a separate reviewer.
5. Implementer and reviewer must resolve disagreements before the item is closed.
6. No broad reruns unless the changed server code justifies them.
7. No silent skips in verification. A blocked precondition fails preflight.
8. No assumptions are allowed to become facts. Unknowns stay marked as unknown until proven.
9. No over-engineering. The chosen fix must be the smallest server change that resolves the confirmed behavior and leaves the system easier to reason about.
10. Test-suite changes are allowed only when needed to verify Bullnym server behavior.

## Roles

Each backlog item uses these roles. A single person can operate the process, but the outputs must remain separate.

| Role | Responsibility | Output |
| --- | --- | --- |
| Evidence analyst | Reconstructs what happened and lists all plausible interpretations. | Evidence dossier |
| Fix planner | Proposes the smallest server fix and verification scope. | Fix plan |
| Plan reviewer | Challenges the fix plan for missing evidence, bad assumptions, overreach, and risk. | Plan review |
| Implementer | Applies the agreed server change. | Patch |
| Implementation reviewer | Reviews code quality, correctness, blast radius, and verification. | Implementation review |
| Integrator | Resolves final issues, records outcome, and moves to the next backlog item. | Closure note |

## Artifact Template

Each issue or optimization gets one file under:

`docs/server-improvement-from-tests/items/`

Filename:

`ITEM-<number>-<short-name>.md`

Template:

```md
# ITEM-000: Title

Backlog reference:
Type:
Priority:
Status:

## Evidence

- Test reports:
- Scenario IDs:
- Server logs:
- DB rows:
- External refs:
- Relevant code:

## Observed Behavior

Plain English description of exactly what happened.

## Possible Interpretations

1. Interpretation A
   - Evidence for:
   - Evidence against:
   - How to prove/disprove:

2. Interpretation B
   - Evidence for:
   - Evidence against:
   - How to prove/disprove:

## Confirmed Conclusion

What we know after checking the evidence.

## Non-Goals

Things this item will not solve.

## Fix Planner Proposal

- Minimal server change:
- Files likely touched:
- Schema/API compatibility:
- Risks:
- Rollback plan:
- Verification:
- Tests not to rerun:

## Plan Reviewer Objections

- Objection:
- Evidence:
- Required change:

## Planner/Reviewer Resolution

Final agreed plan and why it is sufficient.

## Implementation Summary

- Files changed:
- Behavioral change:
- Migration/backfill:
- Observability added:

## Implementation Reviewer Findings

- Finding:
- Severity:
- Evidence:
- Required fix:

## Implementer/Reviewer Resolution

What changed after review.

## Verification Result

- Commands/tests:
- Result:
- Remaining risk:

## Closure Decision

Closed / follow-up required / reverted.
```

## Work Queue

Process items in this order unless new evidence reveals funds-at-risk or security exposure.

1. `ISSUE-006` / `OPT-003`: build/version provenance.
2. `ISSUE-001` / `OPT-001` / `OPT-006`: donation-page underpay and state-machine clarity.
3. `ISSUE-002` / `OPT-002`: BTC unconfirmed payment status.
4. `OPT-015`: server-owned coverage map for proven, unknown, blocked, and invalid surfaces.
5. `ISSUE-008` / `ISSUE-005` / `OPT-014`: safe certification allowlisting and false-negative prevention.
6. `ISSUE-003` / `OPT-008`: registration/NIP-05/lookup consistency.
7. `ISSUE-004` / `OPT-008`: Liquid callback lookup and last-unused semantics.
8. `ISSUE-011`: signed invoice CRUD/auth edge certification.
9. `ISSUE-012`: anonymous invoice/payment-page control-plane behavior.
10. `ISSUE-013`: donation-page BTC chain-swap surface.
11. `ISSUE-014` / `OPT-001` / `OPT-009`: invoice state-machine edges and status projection.
12. `ISSUE-009`: BTC edge cases after unconfirmed status is explicit.
13. `ISSUE-010`: Lightning live edge cases beyond basic sequential volume.
14. `ISSUE-015` / `OPT-013`: concurrency, list/status scale, and query/index review.
15. `ISSUE-016`: public UX/rendering safety.
16. `ISSUE-017`: rate-limit boundaries and diagnostics.
17. `ISSUE-007` / `OPT-007`: operator controls and payment journey views.
18. `ISSUE-018` / `OPT-011`: dependency outage behavior and dependency status.
19. `ISSUE-019`: webhook/reconciler/claim recovery behavior.
20. `ISSUE-020` / `OPT-010`: error taxonomy and correlation IDs.
21. `ISSUE-021`: scoped maintainability extraction when adjacent code is touched.
22. `OPT-005`: status polling performance and precision.

The first item is release provenance because every later live-money verification depends on proving that the server under test is the intended server build.

## Per-Item Procedure

### Step 1: Evidence Dossier

The evidence analyst must collect:

- exact test report names
- scenario IDs
- observed result and reason
- affected product surface
- affected rail
- relevant server code paths
- DB state if available
- logs if available
- whether the run was valid or contaminated

The dossier must explicitly separate:

- facts
- inferences
- unknowns
- rejected interpretations

Gate to continue:

- There is enough evidence to classify the item as server work, or the next action is a minimal evidence-gathering step.

### Step 2: Possible Interpretations

Every plausible interpretation must be listed before planning a fix.

Required questions:

- Could this be correct server behavior with unclear product semantics?
- Could this be rate limiting?
- Could this be wrong deployment?
- Could this be wallet funding?
- Could this be external provider latency?
- Could this be test harness logic?
- Could this be missing observability rather than broken behavior?
- Could this be a security or abuse-protection side effect?
- Could a smaller server change solve the actual problem?

Gate to continue:

- The selected interpretation is backed by evidence, and alternatives are either disproven or explicitly carried as residual risk.

### Step 3: Fix Planner Proposal

The planner proposes the smallest Bullnym server change that resolves the confirmed behavior.

The plan must include:

- current behavior
- desired behavior
- exact code areas
- database/schema impact
- API/status impact
- observability impact
- user-visible behavior
- operational impact
- compatibility risks
- verification scenarios
- scenarios that must not be rerun

The planner must also include a "why not bigger" section explaining why broader rewrites, new abstractions, or test-suite expansion are not needed.

Gate to continue:

- The plan is concrete enough that an implementer can patch the server without reinterpreting the problem.

### Step 4: Plan Review

The plan reviewer challenges:

- unsupported assumptions
- missing interpretations
- wrong code ownership
- hidden migration risks
- user-visible ambiguity
- security regressions
- over-engineering
- under-scoped verification
- unnecessary broad reruns
- test-suite work masquerading as server work

The reviewer must produce objections as actionable findings.

Gate to continue:

- All reviewer objections are either accepted into the plan or rejected with evidence.

### Step 5: Planner/Reviewer Resolution

Planner and reviewer produce a final agreed plan.

The resolution must state:

- what changed in the plan
- what objections remain
- why remaining risks are acceptable
- exact verification scope

Gate to continue:

- No unresolved blocking objection remains.

### Step 6: Implementation

The implementer applies the agreed server change.

Implementation rules:

- Keep the patch scoped to the item.
- Do not opportunistically refactor unrelated code.
- Prefer existing Bullnym patterns.
- Add comments only where they reduce real ambiguity.
- Add or update tests only for the changed server behavior.
- Preserve current public behavior unless the item explicitly changes it.

Gate to continue:

- Code builds or the build failure is recorded with a clear blocker.

### Step 7: Implementation Review

The implementation reviewer reviews the patch as code, not as intent.

Required review areas:

- correctness against agreed behavior
- state-machine safety
- DB consistency
- idempotency
- concurrency
- error handling
- observability
- security/rate-limit impact
- migration compatibility
- unnecessary complexity
- tests and verification scope

Findings must include file/line evidence where possible.

Gate to continue:

- All high and medium severity findings are fixed or explicitly deferred with rationale.

### Step 8: Implementer/Reviewer Resolution

Implementer and reviewer resolve findings.

The resolution must state:

- what was fixed
- what was not fixed
- why remaining risk is acceptable
- whether another review pass is required

Gate to continue:

- Reviewer accepts the implementation or records a precise unresolved blocker.

### Step 9: Targeted Verification

Run only verification from the agreed plan.

Verification rules:

- Start with local unit/integration tests where possible.
- Then run targeted live-money tests only if needed.
- Run one smoke per affected rail/product if the changed code is shared.
- Do not rerun stable-pass paths without code impact.
- If preflight fails, stop before moving money.

Gate to close:

- Targeted verification passes, or failure produces a new evidence dossier.

### Step 10: Closure And Move On

Close the item only after:

- evidence is recorded
- final plan is recorded
- implementation summary is recorded
- review findings are resolved
- verification result is recorded
- next rerun policy is updated

Then move to the next item in the work queue.

## Agent Prompt Templates

These prompts are used when delegating the work.

### Evidence Analyst Prompt

```text
You are the evidence analyst for <ITEM>. Your job is not to fix anything.

Read the relevant test reports, Bullnym server code, logs/DB notes if available, and existing review docs.

Produce:
1. facts
2. inferences
3. unknowns
4. all plausible interpretations
5. evidence for and against each interpretation
6. the minimum next evidence needed if classification is still blocked

Do not propose broad rewrites. Do not treat test failures as server bugs until proven.
```

### Fix Planner Prompt

```text
You are the fix planner for <ITEM>. Use the evidence dossier only.

Propose the smallest Bullnym server fix that resolves the confirmed behavior.

Include:
- current behavior
- desired behavior
- code areas
- schema/API impact
- observability impact
- risks
- non-goals
- verification scenarios
- scenarios not to rerun
- why this is not over-engineered

Do not implement.
```

### Plan Reviewer Prompt

```text
You are the plan reviewer for <ITEM>. Review the fix plan adversarially.

Find:
- unsupported assumptions
- missed interpretations
- over-engineering
- under-scoping
- migration/API risks
- security/rate-limit risks
- poor verification choices
- test-suite work masquerading as server work

Return actionable findings only. If the plan is acceptable, say so explicitly and list residual risk.
```

### Implementer Prompt

```text
You are the implementer for <ITEM>. Implement only the agreed plan.

Rules:
- touch only necessary Bullnym server files
- follow existing patterns
- avoid unrelated refactors
- add focused tests for changed behavior
- preserve compatibility unless the plan explicitly changes it
- list changed files and verification commands
```

### Implementation Reviewer Prompt

```text
You are the implementation reviewer for <ITEM>. Review the patch as code.

Prioritize:
- correctness
- state safety
- DB consistency
- idempotency
- concurrency
- security
- observability
- unnecessary complexity
- test adequacy

Lead with findings. Use file/line references. If no blocking issues remain, say so clearly.
```

## Definition Of Done

An item is done only when all are true:

- The evidence dossier exists.
- Possible interpretations are recorded.
- Fix plan exists.
- Plan review exists.
- Planner/reviewer resolution exists.
- Implementation is complete.
- Implementation review exists.
- Implementer/reviewer resolution exists.
- Verification passed or produced a clearly scoped follow-up.
- Next verification matrix is updated to avoid waste.

> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# Bullnym Server Improvement From Test Evidence

Date: 2026-05-19

This review package turns the `bullnym-test` live and ARS run history into a Bullnym server improvement backlog. The test suite is treated as evidence, not as the project being optimized.

Status note as of schema marker `031_get_paid_descriptors`: this directory is
historical evidence plus the server-improvement record. Use
`../product-surface-coverage.md`, `../payment-architecture.md`, and the root
README for current testing boundaries. In particular, bullnym-test is for
deployed server/payment-rail verification; mobile compatibility must be proven
in the Bull Bitcoin mobile repository and only then exercised against Bullnym
with targeted API/payment smokes.

## Source Evidence

The current evidence set is the tester VM report snapshot copied into:

`bullnym-tests/tmp/server-review-evidence/*.json`

The snapshot contains 18 run reports with scenario records:

| Metric | Count |
| --- | ---: |
| Scenario records | 471 |
| Pass records | 112 |
| Fail records | 50 |
| Skip records | 309 |
| Unique scenario IDs | 190 |
| Unique IDs that passed at least once | 56 |
| Unique IDs that failed at least once | 37 |
| Unique IDs that skipped at least once | 154 |

Two ARS manifest-evaluation reports were also present, but they do not contain scenario records.

## Review Artifacts

- [01 Evidence Index](01-evidence-index.md): run-by-run factual inventory.
- [02 Scenario Classification](02-scenario-classification.md): classification of failures, skips, invalid runs, and stable passes.
- [03 Server Journey Dossiers](03-server-journey-dossiers.md): reconstructed Bullnym server journeys from the evidence.
- [04 Server Issues](04-server-issues.md): confirmed or candidate server defects, ambiguous behavior, and operational problems.
- [05 Server Optimizations](05-server-optimizations.md): server improvements identified from successful and failed flows.
- [06 Improvement Backlog](06-improvement-backlog.md): prioritized combined backlog.
- [07 Next Verification Matrix](07-next-verification-matrix.md): targeted rerun plan that avoids wasting time on known-good paths.
- [08 Adversarial Fix Methodology](08-adversarial-fix-methodology.md): per-issue evidence, planning, adversarial review, implementation, review, verification, and closure process.
- [09 Expanded Issue And Optimization Inventory](09-expanded-issue-and-optimization-inventory.md): broader inventory of confirmed issues, unknown-risk server surfaces, and optimizations found after re-mining all recorded runs.
- [Product Surface Coverage](../product-surface-coverage.md): server-owned coverage ledger for proven, partial, unknown, blocked, and invalid-history surfaces.
- Item dossiers:
  - [ITEM-001 Build Version Provenance](items/ITEM-001-build-version-provenance.md)
  - [ITEM-002 Checkout Underpay Terminalization](items/ITEM-002-checkout-underpay-terminalization.md)
  - [ITEM-003 BTC Unconfirmed Status](items/ITEM-003-btc-unconfirmed-status.md)
  - [ITEM-004 Server-Owned Coverage Map](items/ITEM-004-server-owned-coverage-map.md)
  - [ITEM-005 Scoped Certification Allowlist](items/ITEM-005-scoped-certification-allowlist.md)
  - [ITEM-006 Registration NIP-05 Lookup Consistency](items/ITEM-006-registration-nip05-lookup-consistency.md)
  - [ITEM-007 Liquid Callback Last-Unused Semantics](items/ITEM-007-liquid-callback-last-unused-semantics.md)
  - [ITEM-008 Signed Invoice CRUD/Auth Certification](items/ITEM-008-signed-invoice-crud-auth-certification.md)
  - [ITEM-009 Anonymous Invoice Control-Plane](items/ITEM-009-anonymous-invoice-control-plane.md)
  - [ITEM-010 Invoice State-Machine Edges](items/ITEM-010-invoice-state-machine-edges.md)
  - [ITEM-011 Public Rendering Safety](items/ITEM-011-public-rendering-safety.md)
  - [ITEM-012 Rate-Limit And Certification Diagnostics](items/ITEM-012-rate-limit-and-certification-diagnostics.md)
  - [ITEM-013 Bitcoin Edge Surface](items/ITEM-013-bitcoin-edge-surface.md)
  - [ITEM-014 Lightning Edge Surface](items/ITEM-014-lightning-edge-surface.md)
  - [ITEM-015 Donation BTC Chain-Swap Surface](items/ITEM-015-donation-btc-chain-swap-surface.md)
  - [ITEM-016 Concurrency And Scale](items/ITEM-016-concurrency-and-scale.md)
  - [ITEM-017 Operator Controls And Journey Views](items/ITEM-017-operator-controls-and-journey-views.md)
  - [ITEM-018 Dependency Outage Behavior](items/ITEM-018-dependency-outage-behavior.md)
  - [ITEM-019 Webhook/Reconciler/Claim Recovery](items/ITEM-019-webhook-reconciler-claim-recovery.md)
  - [ITEM-020 Error Taxonomy](items/ITEM-020-error-taxonomy.md)
  - [ITEM-021 Maintainability Extraction](items/ITEM-021-maintainability-extraction.md)
  - [ITEM-022 Status Polling Performance](items/ITEM-022-status-polling-performance.md)

## Method

1. Inventory all run reports before drawing conclusions.
2. Normalize scenario IDs across repeated runs.
3. Separate valid server behavior from harness, funding, rate-limit, deploy, and external dependency contamination.
4. Reconstruct server-side journeys for meaningful failure clusters.
5. Identify both defects and optimizations.
6. Prioritize Bullnym server work by funds-at-risk, stuck-user risk, attacker usefulness, operational impact, scalability, and confidence.
7. Run only the minimum future tests needed to prove server fixes or measure optimizations.

## Important Interpretation Rules

- The Liquid `0/22` failure run from `bullnym-run-1779153846-liquidv2.json` is not treated as a product regression. It was caused by deploying a stale/incompatible binary from the wrong checkout. It is evidence for release provenance controls.
- Broad ARS runs have many skips due to rate-limit and missing preconditions. They are not proof of server correctness or incorrectness, but they are evidence that production certification needs server-side test allowlisting and stronger preflight.
- Clean live-money passes are useful optimization evidence. They show which paths can be moved to smoke-only verification unless related server code changes.
- `bullnym-test` work should now be constrained to deployed server/payment-rail
  verification. It should not be used as a substitute for mobile Flutter,
  deterministic wallet-path, signed-payload, or device-flow validation.

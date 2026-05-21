# 06 Improvement Backlog

This is the combined Bullnym server backlog from the evidence review. It includes both fixes and optimizations.

Status note as of `031_get_paid_descriptors`: the table below is the original
evidence-derived backlog. Several high-priority items have since been
implemented or partially closed. Use the product-surface coverage ledger and
next-verification matrix for current rerun decisions.

## P0: Money Safety / Users Stuck / Release Safety

| ID | Type | Title | Evidence | Server work |
| --- | --- | --- | --- | --- |
| `ISSUE-001` | Defect/ambiguity | Donation-page underpay can remain non-terminal too long | `LQ-21` | Define partial/underpay terminalization policy and implement automatic transition/events. |
| `ISSUE-006` / `OPT-003` | Operational | Runtime cannot prove correct build provenance | Invalid Liquid `0/22` run | Add `/version`; deploy gate expected commit/schema before promotion. |
| `ISSUE-002` / `OPT-002` | Reliability/observability | BTC unconfirmed payment appears as timeout | `BTC-01` | Expose unconfirmed/confirmation state, txid, and next action. |

## P1: Correctness And Reliability

| ID | Type | Title | Evidence | Server work |
| --- | --- | --- | --- | --- |
| `ISSUE-003` / `OPT-008` | Correctness | Registration/NIP-05/lookup inconsistency | `R10`, `R16` | Isolate from rate limits; centralize active nym lookup. |
| `ISSUE-004` / `OPT-008` | Correctness | Liquid callback scenarios fail at nym lookup | `C01`, `C02`, `C08` | Fix lookup path, then validate last-unused callback semantics. |
| `OPT-001` | Code reliability | State transitions are spread across modules | Underpay/BTC ambiguity; many passing Liquid edge cases | Central transition API with reasoned events. |
| `OPT-006` | Product reliability | Payment-page attempt state should be isolated from reusable page state | `LQ-21`, `LQ-10`, `LQ-22` | Make retries and bad attempts independent and visible. |

## P2: Certification, Scale, And Operator Efficiency

| ID | Type | Title | Evidence | Server work |
| --- | --- | --- | --- | --- |
| `ISSUE-005` / `OPT-004` | Operations | Rate limits contaminate certification | ARS broad/certify skips | Safe certification allowlisting with audit logs. |
| `ISSUE-008` / `OPT-014` | Operations | Broad product certification has false negatives | 309 skip records | Separate certification support from broad production bypasses. |
| `ISSUE-007` / `OPT-007` | Operations | Recovery actions are not first-class controls | OP skips, force-terminal/restart hooks | Guarded operator controls and DB/admin views. |
| `ISSUE-018` / `OPT-011` | Operations | Dependency outage behavior is not executable | OP-02 through OP-05 | Dependency health/status and precise degraded-mode errors. |
| `ISSUE-019` / `OPT-007` | Settlement reliability | Webhook/reconciler/claim recovery is playbook-only | OP-06 through OP-08 | Operator-readable swap journey and recovery scheduling state. |
| `OPT-005` | Scale/performance | Status polling should be cheaper and more precise | Live matrix, LN storm | Add polling hints, avoid external work in hot status paths, measure query/latency. |
| `ISSUE-015` / `OPT-013` | Scalability | Concurrency and scale behavior are under-assessed | CC-01 through CC-03 skipped | Query/index/concurrency review for list/status/create. |

## P3: Cleanup And Developer Experience

| ID | Type | Title | Evidence | Server work |
| --- | --- | --- | --- | --- |
| `OPT-008` | Simplification | Duplicate nym lookup semantics | Registration/LNURL/NIP-05 failures | Shared lookup helper and typed errors. |
| `OPT-001` | Simplification | State machine difficult to reason about | State spread across modules | Document transition matrix and enforce in code. |
| `ISSUE-020` / `OPT-010` | Observability | Error taxonomy may be too coarse | Invalid deploy, rate-limit contamination, internal errors | Stable subcodes and correlation IDs. |
| `ISSUE-021` | Maintainability | Large boundary-concentrated modules increase review risk | `invoice.rs`, `claimer.rs`, `config.rs`, watcher modules | Extract only status projection, transitions, signed validation, and rail offer boundaries when touched. |
| `OPT-015` | Documentation | Server-owned coverage map missing | Undercounted/unknown surfaces | Maintain proven/unknown/blocked surface map. |

Coverage ledger: [Product Surface Coverage](../product-surface-coverage.md).

## Unknown-Risk Surfaces To Assess Before Claiming Coverage

These are not automatically defects, but they must enter the adversarial item process before Bullnym can claim reliability for them.

| ID | Surface | Evidence | First server assessment |
| --- | --- | --- | --- |
| `ISSUE-009` | BTC direct and BTC edge cases | `BTC-02` through `BTC-20` skipped; `BTC-01` timeout | Start after BTC unconfirmed status is fixed. |
| `ISSUE-010` | Lightning live edge cases | LN edge cases skipped; basic storm passed | Assess Boltz/LN state mapping beyond happy path. |
| `ISSUE-011` | Signed invoice CRUD/auth edges | `INVS-*`, `INVN-*` skipped | Audit signed action validation and ownership. |
| `ISSUE-012` | Anonymous invoice/payment-page control-plane | `INV-*` control-plane skips | Check render/status/idempotency/cross-nym behavior. |
| `ISSUE-013` | Donation-page BTC chain swap | `DCHAIN-*` skipped | Check chain-swap rail visibility and status fields. |
| `ISSUE-014` | Invoice state-machine edges | `SM-*` skipped | Fold into central transition work. |
| `ISSUE-016` | Public UX/rendering safety | `UX-*` skipped | Review escaping, field limits, QR bounds, status shape. |
| `ISSUE-017` | Rate-limit boundaries and diagnostics | `RL-*`, `INVR-*` skipped/ambiguous | Clarify limiter/whitelist/certification behavior. |

## Not Server Work

| Item | Reason |
| --- | --- |
| Jungle balance exhaustion | Funding/treasury issue; not a Bullnym server defect. |
| BDK sender had 0 sats | Funding/preflight issue; not a Bullnym server defect. |
| Invalid stale-binary Liquid failures as product behavior | Excluded from product correctness; retained as release-safety evidence. |
| Repeating known-good Liquid happy paths | Waste unless server state-machine or rail code changes. |
| Repeating 90-payment LN storm by default | Waste unless LN/Boltz/settlement code changes or a scale optimization needs measurement. |

## Recommended Implementation Order

1. Completed: add `/version` and deploy provenance checks.
2. Completed/partial: fix underpay/partial terminalization semantics for
   payment-page attempts.
3. Completed/partial: expose BTC unconfirmed state through observations.
4. Completed: build the server-owned coverage map from `ISSUE-009` through
   `ISSUE-017`.
5. Completed/partial: add safe certification allowlisting and diagnostics.
6. Completed/partial: audit signed invoice CRUD/auth edges with route-level
   regression coverage.
7. Completed/partial: assess anonymous invoice/payment-page control-plane
   edges with route-level coverage.
8. Current: verify Get Paid descriptor compatibility across server, VM rails,
   and the target mobile branch.
9. Next: assess donation-page BTC chain-swap behavior with targeted VM runs.
10. Next: add operator-readable payment journey views only where recovery
    drills show repeated ambiguity.
11. Next: add dependency/recovery diagnostics where outage drills need them.
12. Next: optimize status polling after correctness states are explicit and
    measured.

# 07 Next Verification Matrix

The next test run should verify server changes, not repeat known-good evidence.

Read this with the server-owned [Product Surface Coverage](../product-surface-coverage.md) ledger. The coverage ledger states what is proven, partial, unknown, blocked, or invalid-history; this matrix states what to run next.

## Run Policy

| Policy | Meaning |
| --- | --- |
| `do-not-repeat` | Valid clean pass and unaffected by changed server code. |
| `smoke-only` | Run one representative case for confidence. |
| `targeted-rerun` | Directly proves a fix or optimization. |
| `performance-rerun` | Measures latency/query/provider-call improvement. |
| `blocked` | Do not run until preconditions are present; fail preflight instead of skipping. |
| `invalid-history` | Historical result excluded from product correctness. |

## Do Not Repeat By Default

| Scenario(s) | Policy | Reason |
| --- | --- | --- |
| Clean live matrix `1779135713` 8/8 | `do-not-repeat` | Already proved exact LN/Liquid invoice paths with real money. |
| Liquid V2 happy paths and basic edge cases that passed in `1779151124` | `do-not-repeat` | Valid broad Liquid pass evidence. |
| LN storm 20 and 90 sequential | `do-not-repeat` | Already proved repeated sequential Jungle Lightning path. |

## Smoke-Only

| Area | Scenario | When |
| --- | --- | --- |
| Lightning invoice | One Jungle exact-pay invoice | After unrelated server changes. |
| Liquid invoice | `LQ-01` | After deployment or state-machine change. |
| Payment page Liquid | One exact-pay donation/payment-page attempt | After payment-page or invoice state changes. |
| Registration | `R01` plus one metadata lookup | After unrelated server changes. |

## Targeted Reruns For Server Fixes

| Server change | Required reruns | Do not rerun |
| --- | --- | --- |
| Underpay/partial terminalization | `LQ-21`, one exact payment-page Liquid, one retry-after-underpay case | Full Liquid V2 suite unless transition code changed globally. |
| BTC unconfirmed status | `BTC-01` with low-priority fee and status assertion for unconfirmed/txid | Live matrix LN/Liquid paths. |
| `/version` provenance | Deployment preflight only, then `LQ-01` smoke | Any large live-money batch. |
| Nym lookup centralization | `R10`, `R16`, `C01`; then `C02`/`C08` only if lookup works | Live payment matrix. |
| Safe certification allowlist | ARS setup/preflight and one rate-limit abuse control | Full broad ARS until preflight proves zero setup skips. |
| Operator controls/views | `LQ-21` without raw DB mutation; one restart/reconciler path if control added | LN storm volume. |
| Status polling optimization | One live matrix smoke with timing/query/provider metrics; optional small LN batch | 90-payment storm unless measuring scale. |

## Blocked Until Preconditions Are True

| Area | Blocker | Required preflight |
| --- | --- | --- |
| Broad ARS certification | Rate-limit contamination | Server allowlist active and audited; otherwise fail before running. |
| BTC live-money suite | Funding and unconfirmed status semantics | BDK balance sufficient; server exposes unconfirmed state; mempool fee source reachable. |
| High-volume Jungle Lightning | Sender balance / return loop | Jungle balance threshold and return/accounting plan confirmed. |
| Operator outage/recovery cases | Safe controls | Explicit operator mode or audited admin commands available. |

## Certification Rule

A certification run is valid only if:

1. `/version` matches the expected Bullnym commit.
2. Migrations/schema version match the expected server build.
3. Required wallet balances are above threshold.
4. Safe certification allowlist is active if broad ARS is used.
5. No scenario silently skips. Blocked preconditions fail preflight before money moves.

## Minimal Next Run After First Server Patch

If the first patch is `/version` only:

1. Preflight `/version`.
2. `LQ-01` smoke.
3. One Jungle Lightning invoice smoke.
4. Stop.

If the first patch is underpay state-machine behavior:

1. Preflight `/version`.
2. `LQ-21`.
3. One exact payment-page Liquid payment.
4. One invoice Liquid exact payment smoke.
5. Stop.

If the first patch is BTC unconfirmed behavior:

1. Preflight `/version`.
2. `BTC-01` expecting `seen_unconfirmed` or equivalent.
3. One Liquid smoke to prove unrelated paths still work.
4. Stop.

> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# 07 Next Verification Matrix

The next test run should verify server changes, not repeat known-good evidence.

Read this with the server-owned [Product Surface Coverage](../product-surface-coverage.md) ledger. The coverage ledger states what is proven, partial, unknown, blocked, or invalid-history; this matrix states what to run next.

Current server schema marker: `031_get_paid_descriptors`.

Scope boundary: use bullnym-test for deployed server/payment-rail scenarios
only. Use the Bull Bitcoin mobile repository for mobile deterministic wallet
paths, signed payload generation, Flutter tests, and device/emulator flows.

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
| Get Paid descriptor split | Mobile contract tests locally, then targeted VM rail smokes for BDK direct BTC, LWK direct Liquid, Jungle Lightning-to-Liquid, BDK donation chain swap, and exact donation Liquid checkout | Broad LN/Liquid volume, ARS, or VM-only claims about mobile behavior. |

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
2. `/version.expected_schema_marker` is the expected marker for the build, and
   DB migrations have been independently verified.
3. Required wallet balances are above threshold.
4. Safe certification allowlist is active if broad ARS is used.
5. No scenario silently skips. Blocked preconditions fail preflight before money moves.

## Minimal Next Run For Get Paid Compatibility

After deploying a `031_get_paid_descriptors` build:

1. Preflight `/version` for expected commit, clean build, runtime mode, and
   `expected_schema_marker = "031_get_paid_descriptors"`.
2. Verify the target mobile branch locally: registration payload including
   `verification_npub`, donation-page descriptor payload, invoice create/list/cancel,
   and deterministic descriptor/address expectations.
3. Run bullnym-test VM smokes only for changed or still-partial rails:
   BDK direct BTC invoice, LWK direct Liquid invoice, Jungle Lightning offer
   settling through Boltz to LWK, BDK donation-page BTC chain swap settling to
   the page Liquid descriptor, and exact donation-page Liquid checkout.
4. Stop unless a targeted check fails or the touched code invalidates a broader
   proven surface.

# 02 Scenario Classification

This file classifies the recorded scenario results by server relevance.

## Classification Key

- `stable-pass`: valid pass; do not routinely rerun unless related server code changes.
- `server-candidate`: likely or possible Bullnym server issue; investigate/fix in server.
- `ambiguous-behavior`: server behavior exists but product semantics are unclear or risky.
- `missing-observability`: server may be correct, but status/logs/API do not show enough.
- `operational-server`: deploy, runtime, rate-limit, or operator-control problem affecting Bullnym production operation.
- `external/funding`: wallet balance, confirmation, provider, or network condition.
- `invalid-run`: do not use as product evidence.
- `blocked`: skipped or not yet meaningful due to missing preconditions.

## Stable Passes

These should move to smoke-only verification unless related code changes.

| Scenario(s) | Evidence | Classification | Notes |
| --- | --- | --- | --- |
| `INV-PAY-01`, `INV-LARGE-PAY`, `INV-FIAT-PAY`, `INV-LIQUID-PAY`, `INV-LIQUID-OVERPAY`, `INV-LIQUID-UNDERPAY`, `INVS-PAY-01`, `INVS-LIQUID-PAY-01` | Live matrix `1779124949`, `1779135713` | `stable-pass` | Clean real-money invoice matrix without BTC. |
| `T20-01` LN storm 20 | `1779127807` | `stable-pass` | One failed run preceded it; rerun passed. Treat as smoke unless LN/Boltz/Jungle code changes. |
| `T20-01` LN storm 90 | `1779128114` | `stable-pass` | Strong repeated Lightning pass at sequential concurrency 1. |
| `LQ-01`, `LQ-02`, `LQ-04`, `LQ-05`, `LQ-06`, `LQ-08`, `LQ-09`, `LQ-10`, `LQ-12` through `LQ-20`, `LQ-22` | Liquid V2 `1779151124` | `stable-pass` | Valid Liquid run. Some later failures for the same IDs came only from invalid stale-binary deploy. |
| `LQ-11` | targeted `1779153481` | `stable-pass` with runtime caveat | Restart/watcher resume works when the operator restart hook exists. Server should still gain first-class operator controls. |
| `LQ-01` rollback/correct-deploy smokes | `1779153895`, `1779154122` | `stable-pass` | Proves rollback and correct deploy restored product path. |

## Server-Candidate Findings

| Scenario(s) | Evidence | Classification | Why this matters to Bullnym server |
| --- | --- | --- | --- |
| `LQ-21` | Liquid V2 `1779151124`; targeted `1779153353` | `server-candidate` / `ambiguous-behavior` | Donation-page Liquid underpay stayed non-terminal until force-terminal path. Server must define automatic terminalization for partial/underpaid payment-page attempts. |
| `BTC-01` | Bitcoin V2 `1779140155` | `missing-observability` / `server-candidate` | Broadcast/unconfirmed BTC payment timed out from the user's perspective. Server should expose unconfirmed/seen states and tx references instead of opaque timeout behavior. |
| `R10` | ARS broad/certify | `server-candidate` | NIP-05 `nostr.json` did not resolve after registration, returning `NymNotFound`. Needs journey reconstruction against registration rows and route behavior. |
| `R16` | ARS broad/certify | `server-candidate` | Lookup active registration by npub returned empty/inactive data. Could be lifecycle, lookup, or rate-limit contamination. |
| `C01`, `C02`, `C08` | ARS broad/certify | `server-candidate` | Liquid callback/last-unused behavior returned `NymNotFound` and did not produce callback addresses. Needs server-side LNURL/Liquid callback investigation. |

## Operational Server Findings

| Scenario(s) | Evidence | Classification | Server implication |
| --- | --- | --- | --- |
| `R11`, `R12`, `R13`, `S-PRE`, `ST-06`, many setup-gated scenarios | ARS broad/certify | `operational-server` | Production rate limits blocked certification flows. Bullnym needs a safe allowlisted test identity/network mode or certification cannot run without false failures/skips. |
| Liquid `1779153846` all 22 failures | Invalid deploy run | `operational-server` / `invalid-run` | Wrong binary promotion caused auth and checkout failures. Bullnym needs `/version` and deploy provenance guardrails. |
| `OP-01` through `OP-08` | ARS broad/certify skips | `operational-server` / `blocked` | Operator-only failure modes exist but are not first-class controllable/auditable server operations. |

## External Or Funding Findings

| Scenario(s) | Evidence | Classification | Notes |
| --- | --- | --- | --- |
| `BTC-01` first failure | Bitcoin V2 `1779139541` | `external/funding` | BDK sender had 0 sats for a 6000 sat send. |
| `INV-LARGE-PAY`, `INVS-PAY-01` skips | Live matrix `1779150598` | `external/funding` | Jungle balance exhaustion. Not a Bullnym server defect. |
| Most `BTC-02` through `BTC-20` skips | ARS broad/certify | `blocked` | Skipped by missing Jungle config and rate-limit setup failures, not product evidence. |

## Invalid Run

| Run | Classification | Treatment |
| --- | --- | --- |
| `bullnym-run-1779153846-liquidv2.json` | `invalid-run` | Exclude from product correctness. Include only as evidence for deploy provenance/versioning improvements. |


> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# 09 Expanded Issue And Optimization Inventory

The first server issue list was too narrow. It captured the obvious high-signal failures, but it did not fully account for whole Bullnym server surfaces that were skipped or contaminated in broad ARS. This expanded inventory separates confirmed issues from unknown-risk surfaces and optimization opportunities.

## Evidence Pattern

The run history shows:

- `ars-contract`: 40 pass, 22 fail, 66 skip.
- `ars-payments-live`: 24 pass, 25 fail, 125 skip.
- `legacy-mixed`: 46 pass, 2 fail, 74 skip.
- `protect-deployed`: 22 skip.
- `ars-fault-window`: 16 skip.
- `ars-scale`: 6 skip.
- `protect-redteam`: 2 pass, 1 fail.

This means the issue backlog must include:

- confirmed defects,
- ambiguous server behavior,
- operational blockers,
- and major unassessed server surfaces.

An unassessed surface is not a defect by itself, but it is a server risk until proven. It becomes a fix item when the adversarial process shows the server lacks the behavior, observability, or operator control required to assess it safely.

## Expanded Server Issues

### ISSUE-008: Broad product certification is not currently possible without false negatives

Classification: operational server reliability

Evidence:

- Broad ARS/certify produced 309 total skip records across the full evidence set.
- Setup failures repeatedly returned `RateLimitedNetwork`.
- Entire surfaces were skipped: BTC live edges, Lightning live edges, signed invoice CRUD, invoice state-machine edges, rate-limit boundaries, concurrency, UX rendering, and outage playbooks.

Server interpretation:

- This is broader than `ISSUE-005`.
- The server lacks a clean certification mode that preserves attack protection while allowing deterministic assessment of known test identities and known test infrastructure.

Server work to consider:

- Safe certification allowlisting.
- Preflight endpoint or diagnostics proving what limits are active.
- Audit logs for all bypasses.
- Failure mode where certification refuses to start instead of silently skipping.

### ISSUE-009: Bitcoin server surface is mostly unproven

Classification: unknown-risk server surface, BTC reliability

Evidence:

- `BTC-01` failed twice: once funding-blocked, once broadcast/unconfirmed timeout.
- `BTC-02` through `BTC-20` skipped in broad ARS.
- Skipped BTC cases include underpay, overpay, pay-after-cancel, cancel-while-in-progress, pay-after-expiry, address reuse, donation-page BTC chain swap, mempool in-progress, second payment to terminal invoice, long expiry, and churn recovery.

Server interpretation:

- We cannot claim BTC reliability beyond partial evidence.
- The server needs explicit BTC unconfirmed/payment-observed semantics before many BTC cases can be judged fairly.

Server work to consider:

- First-class unconfirmed status.
- BTC payment event evidence exposed in status.
- Address reuse and terminal-state guards audited in BTC watcher.
- BTC chain-swap status separated from direct BTC settlement.

### ISSUE-010: Lightning live edge cases are mostly unproven despite successful basic volume

Classification: unknown-risk server surface, Lightning/Boltz reliability

Evidence:

- LN storm 20 and 90 passed after one failed 20-payment attempt.
- `LN-01` through `LN-20` style live edge cases were skipped in broad ARS due setup/rate-limit/Jungle gates.
- Skipped cases include underpay/overpay, post-cancel, post-expiry, long expiry, linked/unlinked size variants, and Lightning-only public rail behavior.

Server interpretation:

- Basic sequential Lightning works.
- Edge-case Lightning state semantics remain less proven than the happy path.

Server work to consider:

- Clarify LN/Boltz state mapping for expired, late, duplicate, and settled-after-local-failure cases.
- Improve status API to separate payer invoice settlement from merchant claim settlement.
- Add operator-readable swap state.

### ISSUE-011: Signed invoice CRUD and auth edge behavior were not certified

Classification: unknown-risk server surface, auth/API reliability

Evidence:

- `INVS-05` through `INVS-11` and related signed invoice cases skipped under ARS due registration/rate-limit setup.
- Skipped cases include signed sat/fiat create, cancel, list filter, forged signature/stale timestamp, cross-action replay, wrong field order, metadata round-trip, real Lightning/Liquid/BTC settlement, cancel idempotency, cancelled-offer suppression, expiry bounds, rail invalidity, oversized fields, cross-npub list isolation, and cross-npub cancel denial.
- Some signed live payment matrix happy paths passed.

Server interpretation:

- Signed happy-path settlement has evidence.
- Signed control-plane security and CRUD edges remain unproven in certification.

Server work to consider:

- Audit signed-action verification boundaries in `src/auth.rs` and `src/invoice.rs`.
- Ensure error taxonomy is specific and does not collapse auth, validation, and ownership failures.
- Centralize signed invoice ownership checks.

### ISSUE-012: Anonymous invoice and payment-page control-plane coverage is incomplete

Classification: unknown-risk server surface, payment-page/API reliability

Evidence:

- Many anonymous invoice control-plane cases skipped in broad ARS: sat invoice create, fiat create, offer decode, Liquid offer idempotency, HTML/JSON status agreement, cross-nym invoice access, trailing slash render, BTC chain-swap payment.
- Live matrix proved several money flows, but not all control-plane semantics.

Server interpretation:

- Real payments work for some flows.
- Page/API consistency, idempotent offer allocation, cross-nym access, and HTML/JSON agreement still need server assessment.

Server work to consider:

- Make invoice session state and reusable page state explicitly separate.
- Ensure render and JSON status use the same status projection.
- Add typed not-found/forbidden behavior for cross-nym paths.

### ISSUE-013: Donation-page BTC chain-swap surface is unproven

Classification: unknown-risk server surface, BTC/Boltz/payment-page reliability

Evidence:

- `DCHAIN-01` through `DCHAIN-04` skipped in broad ARS.
- Cases cover eligible donation invoice exposing Lightning/Liquid/BTC chain-swap rails, small donation hiding BTC when Boltz refuses, HTML JS payload initialization, and status API chain-swap fields.

Server interpretation:

- Donation-page BTC rail behavior is mostly unknown.
- This is distinct from direct BTC invoice behavior and from Liquid payment-page behavior.

Server work to consider:

- Separate direct BTC address behavior from Boltz BTC chain-swap behavior in status.
- Make chain-swap field presence deterministic.
- Ensure frontend-rendered JS payload cannot diverge from status API.

### ISSUE-014: Invoice state-machine edge cases are not certified

Classification: unknown-risk server surface, state correctness

Evidence:

- `SM-01` through `SM-06` skipped in broad ARS.
- Cases include cancel from unpaid, second cancel idempotency, cancel after paid, duplicate webhook idempotency, past expiry rejection, and in-progress cancel rejection.
- Liquid V2 did cover some analogous live cases successfully.

Server interpretation:

- Some state-machine behavior is proven for Liquid, but not fully across all invoice creation/auth/rail combinations.

Server work to consider:

- Central state-transition rules and shared status projection.
- Explicit idempotency behavior for cancel and duplicate webhook paths.
- Tests only after server transition policy is documented.

### ISSUE-015: Concurrency and scale behavior are under-assessed

Classification: scalability risk

Evidence:

- `CC-01`: 50 invoices concurrent from same npub skipped.
- `CC-02`: large list limit 100 within 5s skipped.
- `CC-03`: 30 status GETs in parallel skipped.
- LN storm sequential passed; concurrency was not meaningfully assessed.

Server interpretation:

- Sequential payment volume is not the same as concurrent API reliability.

Server work to consider:

- Query/index review for list/status endpoints.
- Concurrency review of invoice creation, address allocation, and rate-limit atomicity.
- Request-level correlation IDs to diagnose bursts.

### ISSUE-016: Public UX/rendering safety is unassessed

Classification: UX/API correctness, injection/rendering risk

Evidence:

- `UX-01` through `UX-05` skipped.
- Cases include Unicode/RTL/zero-width/emoji rendering, max-length fields, over-max rejection, QR rendering, and status field shape.

Server interpretation:

- Public render surfaces are not proven for pathological user-controlled text.

Server work to consider:

- Review Askama escaping and all raw HTML/JS injection points.
- Enforce consistent field limits at API boundaries.
- Keep QR generation bounded and failure-safe.

### ISSUE-017: Rate-limit behavior is both protective and operationally ambiguous

Classification: security/reliability tradeoff

Evidence:

- `INVR-16` skipped because no 429 after 6 requests, likely due whitelist.
- `INVR-17` gated behind noisy rate-limit mode.
- `RL-A` through `RL-E` skipped due setup contamination.
- Many unrelated tests were blocked by `RateLimitedNetwork`.

Server interpretation:

- Current rate limits protect production, but the system lacks clear introspection for whether a request was limited, whitelisted, or certification-bypassed.

Server work to consider:

- Structured rate-limit decision logs.
- Distinct error classes for burst limit, distinct-wallet network limit, purge block, and whitelist bypass.
- Operator-safe diagnostics for current source classification.

### ISSUE-018: External dependency outage behavior is not executable as server verification

Classification: operational resilience

Evidence:

- `OP-02` pricer outage, `OP-03` Boltz outage, `OP-04` Liquid Electrum outage, `OP-05` mempool outage all skipped as manual playbooks.

Server interpretation:

- The server likely contains some graceful handling, but there is no first-class way to verify outage behavior without ad hoc firewall/operator actions.

Server work to consider:

- Dependency health/status diagnostics.
- Clear `ServiceUnavailable` behavior for pricer-dependent fiat creation.
- Internal retry/backoff state surfaced for Boltz/Electrum/mempool watchers.

### ISSUE-019: Webhook/reconciler/claim recovery behavior is not executable as server verification

Classification: settlement reliability

Evidence:

- `OP-06`, `OP-07`, `OP-08` skipped as manual playbooks.
- The code has reconciler and claim retry machinery, but evidence is playbook-only.

Server interpretation:

- Settlement recovery is too important to remain manually inferred.

Server work to consider:

- Operator-readable swap journey view.
- Explicit recovery scheduling state in public/operator status.
- Safer fault injection hooks for staging only, or deterministic local integration tests.

### ISSUE-020: Error taxonomy may be too coarse for users and operators

Classification: observability/API improvement

Evidence:

- Invalid deploy produced `AuthError` and generic `InternalError`.
- Many setup failures exposed the same `RateLimitedNetwork` reason for different certification contexts.
- Cross-surface diagnosis required DB/log/test correlation.

Server interpretation:

- Error classes exist, but user/operator actionability is inconsistent.

Server work to consider:

- Add stable machine-readable subcodes.
- Include correlation IDs.
- Avoid generic `InternalError` where the failure is expected validation/config/dependency behavior.

### ISSUE-021: Server code size and boundary concentration create review risk

Classification: maintainability optimization

Evidence:

- `src/invoice.rs` is roughly 1993 lines.
- `src/claimer.rs` is roughly 1685 lines.
- `src/config.rs`, `src/db/invoices.rs`, `src/rate_limit.rs`, `src/chain_watcher.rs`, and `src/bitcoin_watcher.rs` are also large and stateful.

Server interpretation:

- This is not automatically bad, but payment state, rendering, rail offer creation, auth, and settlement projection are concentrated enough that future fixes risk collateral damage.

Server work to consider:

- Extract only real boundaries: status projection, state transitions, signed-action validation, and rail offer builders.
- Avoid a broad rewrite.

## Expanded Optimizations

### OPT-009: Add a server status projection layer

Current issue:

- HTML render, JSON status, invoice state, payment evidence, and settlement status can diverge conceptually.

Improvement:

- One projection function produces user-visible status fields from invoice/payment/swap rows.

Benefit:

- Less duplicated status logic and clearer tests.

### OPT-010: Add correlation IDs across request, invoice, payment event, swap, and logs

Current issue:

- Evidence reconstruction required manual joining across reports, DB rows, txids, and logs.

Improvement:

- Generate/accept request correlation IDs and persist them where meaningful.

Benefit:

- Faster incident response and cleaner certification reports.

### OPT-011: Add dependency health summaries without turning `/health` into a heavy endpoint

Current issue:

- `/health` is too small for provenance, but should stay cheap.
- Dependency outage behavior is hard to verify.

Improvement:

- Keep `/health` as liveness.
- Add `/version` for provenance.
- Add an operator-only or config-gated dependency status endpoint/view.

Benefit:

- Operators can distinguish alive process, correct build, and degraded dependencies.

### OPT-012: Add idempotency audit across all payment-creating endpoints

Current issue:

- Some idempotency exists for webhooks/payment events/address allocation, but not all user-facing create/retry flows have a visible idempotency contract.

Improvement:

- Document and enforce idempotency behavior for invoice create, offer allocation, callbacks, payment-page attempts, cancellation, and webhook handling.

Benefit:

- Safer retries and less duplicate state under real-world clients.

### OPT-013: Add query/index review for high-volume list/status paths

Current issue:

- Scale tests for list/status were skipped.

Improvement:

- Review `list_signed`, invoice status lookup, payment event aggregation, and watcher queries for indexes and query shape.

Benefit:

- Lower risk before high-volume user growth.

### OPT-014: Separate certification support from production bypasses

Current issue:

- Existing IP whitelist bypasses proof and rate limits broadly.

Improvement:

- Add a narrower certification capability with explicit scopes: registration setup, invoice create, status polling, live-money payment runs.

Benefit:

- Less dangerous than broad whitelisting and easier to audit.

### OPT-015: Add product-surface coverage map to server docs

Current issue:

- It is hard to see which Bullnym surfaces are proven, unknown, or blocked.

Improvement:

- Maintain a server-owned coverage map: registration, LNURL, NIP-05, anonymous invoices, signed invoices, payment pages, Lightning, Liquid, BTC, BTC chain swaps, operator recovery, rate limits, UX rendering.
- Current ledger: [Product Surface Coverage](../product-surface-coverage.md).

Benefit:

- Prevents future undercounting and avoids repeating known-good flows.

# 04 Server Issues

This file lists server issues and candidate issues identified from test evidence. It does not include pure test-suite defects except where Bullnym server needs an operational feature to support certification safely.

## ISSUE-001: Donation-page underpay can remain non-terminal too long

Classification: `server-candidate`, `ambiguous-behavior`, money-state reliability

Evidence:

- `LQ-21` in `bullnym-run-1779151124-liquidv2.json`
- Failed with: did not reach terminal status within 180 seconds.
- Targeted rerun passed only after operator force-terminal support.

Observed behavior:

- A real Liquid underpayment on a donation/payment-page attempt was observed, but the public payment journey did not reach a useful terminal state promptly.

Expected server behavior:

- Bullnym should make underpaid payment attempts deterministic.
- A user should see one of:
  - still payable with exact remaining amount and clear deadline,
  - terminal `underpaid` with retry/refund instructions,
  - operator-visible stuck state with automatic remediation scheduled.

Likely fix strategy:

- Define state-machine rules for partial payment by product surface.
- Add automatic terminalization policy for expired or stale partial payments.
- Consider shorter terminalization rules for payment-page attempts than reusable invoices.
- Emit structured transition events for partial-to-underpaid decisions.

Likely code areas:

- `src/db/invoices.rs`
- `src/gc.rs`
- `src/invoice.rs`
- `src/chain_watcher.rs`

Verification:

- Rerun `LQ-21`.
- Add one smoke for normal Liquid payment-page exact pay.
- Do not rerun the entire Liquid suite unless shared state-machine code changes broadly.

## ISSUE-002: BTC unconfirmed payments are not represented clearly enough

Classification: `missing-observability`, `server-candidate`, BTC reliability

Evidence:

- `BTC-01` in `bullnym-run-1779140155-bitcoinv2.json`
- Long timeout after broadcast/unconfirmed payment.

Observed behavior:

- From the user/test perspective, the payment did not reach terminal paid status and timed out.
- The server did not provide a sufficiently useful public state for "payment seen but awaiting confirmation".

Expected server behavior:

- Broadcast-but-unconfirmed BTC payments should be first-class.
- Status API should expose txid, observed amount, confirmation count or height, and next expected transition.

Likely fix strategy:

- Add or expose `seen_unconfirmed` / `awaiting_confirmation` semantics.
- Store observed BTC tx details separately from terminal paid state.
- Avoid marking low-fee BTC flows as generic failure just because confirmation is slow.

Likely code areas:

- `src/bitcoin_watcher.rs`
- `src/db/invoices.rs`
- `src/invoice.rs`
- invoice event migrations

Verification:

- One targeted BTC test using a low-priority fee.
- Poll should pass when server reaches `seen_unconfirmed`; terminal `paid` can remain confirmation-dependent.

## ISSUE-003: Registration lookup/NIP-05 behavior needs isolation from rate limits

Classification: `server-candidate`, registration reliability

Evidence:

- `R10`: NIP-05 `nostr.json` did not resolve after registration.
- `R16`: lookup active registration by npub returned empty/inactive result.
- Both appeared in broad ARS and certify runs.

Observed behavior:

- Earlier registration validation cases passed, but later lookup/NIP-05 cases returned missing or inactive data.

Expected server behavior:

- Once registration succeeds, LNURL metadata, NIP-05, and lookup-by-npub should agree on active nym state.

Likely fix strategy:

- Reproduce `R10` and `R16` in isolation with rate-limit allowlisting.
- Inspect active/inactive filters in `registration`, `nostr`, `lnurl`, and DB user queries.
- Add a shared lookup helper if paths have diverged.

Likely code areas:

- `src/registration.rs`
- `src/nostr.rs`
- `src/lnurl.rs`
- `src/db/users.rs`

Verification:

- Targeted registration lifecycle run only.
- Do not rerun live payment flows.

## ISSUE-004: Liquid callback tests fail before callback semantics are reached

Classification: `server-candidate`, LNURL/Liquid reliability

Evidence:

- `C01`, `C02`, `C08` failed in broad ARS and certify.
- Failure reason was `NymNotFound`, not bad last-unused behavior.

Observed behavior:

- Server did not resolve the target nym for liquid callback scenarios.

Expected server behavior:

- Registered nym should resolve consistently across metadata, callback, and NIP-05.
- Once resolved, last-unused address mode should not burn addresses on repeated unauthenticated callbacks.

Likely fix strategy:

- First isolate lookup failure from test setup/rate limit.
- Then audit last-unused address allocation under repeated callback and concurrent callback conditions.

Likely code areas:

- `src/lnurl.rs`
- `src/db/users.rs`
- `src/db/watcher.rs`
- `src/chain_watcher.rs`

Verification:

- Targeted callback lookup test.
- Then targeted repeated-callback last-unused test.

## ISSUE-005: Production rate limits block valid certification and create false failures

Classification: `operational-server`, reliability certification

Evidence:

- Broad ARS/certify runs had 306 combined skips.
- Many setup failures returned `RateLimitedNetwork`.
- `R11`, `R12`, `R13`, `S-PRE`, `ST-06`, and many setup-dependent cases were contaminated by rate limiting.

Observed behavior:

- The server protected itself, but certification could not distinguish real product failure from rate-limit denial.

Expected server behavior:

- Bullnym should keep production protection while supporting safe certification traffic.

Likely fix strategy:

- Add a server-side allowlist for signed test/certification identities and/or source IPs.
- Scope it to staging/test deployments or explicitly configured production certification windows.
- Log every bypass decision.
- Never globally disable rate limits.

Likely code areas:

- `src/rate_limit.rs`
- `src/ip_whitelist.rs`
- `src/config.rs`

Verification:

- Preflight must prove allowlist is active before broad ARS.
- Rate-limit abuse tests should still verify normal clients are limited.

## ISSUE-006: `/health` cannot detect wrong binary or schema provenance

Classification: `operational-server`, release safety

Evidence:

- Liquid run `1779153846` failed 22/22 immediately after wrong checkout deploy.
- Rollback and correct `bullnym/main` deploy restored `LQ-01`.
- `/health` only returns `ok`.

Observed behavior:

- A stale/incompatible server binary could be deployed and appear healthy.

Expected server behavior:

- Runtime endpoint should expose build commit, source branch or artifact label, build time, schema/migration version, and runtime mode.

Likely fix strategy:

- Add `/version` or expand `/health?verbose=1`.
- Embed `BULLNYM_BUILD_COMMIT`, `BULLNYM_BUILD_BRANCH`, and build timestamp at compile/deploy time.
- Have deploy scripts verify expected commit before promotion.

Likely code areas:

- `src/main.rs`
- build/deploy scripts

Verification:

- Deployment preflight checks exact expected commit before any live-money test.

## ISSUE-007: Operator-only recovery actions are not first-class server controls

Classification: `operational-server`, observability/recovery

Evidence:

- `OP-01` through `OP-08` are documented operator playbooks but skipped in ARS.
- `LQ-21` needed a force-terminal path for useful verification.
- `LQ-11` needed a restart hook to verify watcher recovery.

Observed behavior:

- Some important recovery behavior exists only as manual DB/systemctl operation.

Expected server behavior:

- Operator interventions should be guarded, auditable, and exposed as safe admin operations or runbook-backed DB views.

Likely fix strategy:

- Add audited admin commands for force-expire/force-terminalize where product policy permits.
- Add read-only operator state views for invoice/payment/swap state.
- Keep dangerous controls disabled unless an explicit operator mode is configured.

Likely code areas:

- `src/db/invoices.rs`
- `src/reconciler.rs`
- `src/claimer.rs`
- admin/deploy tooling

Verification:

- No raw DB mutation required for normal certification.

## Expanded Issue Inventory

The initial seven issues above are the highest-signal first pass. A broader re-mining of all recorded runs identified additional confirmed, candidate, and unknown-risk server surfaces. See [09 Expanded Issue And Optimization Inventory](09-expanded-issue-and-optimization-inventory.md).

Additional issues currently tracked there:

- `ISSUE-008`: Broad product certification is not currently possible without false negatives.
- `ISSUE-009`: Bitcoin server surface is mostly unproven.
- `ISSUE-010`: Lightning live edge cases are mostly unproven despite successful basic volume.
- `ISSUE-011`: Signed invoice CRUD and auth edge behavior were not certified.
- `ISSUE-012`: Anonymous invoice and payment-page control-plane coverage is incomplete.
- `ISSUE-013`: Donation-page BTC chain-swap surface is unproven.
- `ISSUE-014`: Invoice state-machine edge cases are not certified.
- `ISSUE-015`: Concurrency and scale behavior are under-assessed.
- `ISSUE-016`: Public UX/rendering safety is unassessed.
- `ISSUE-017`: Rate-limit behavior is both protective and operationally ambiguous.
- `ISSUE-018`: External dependency outage behavior is not executable as server verification.
- `ISSUE-019`: Webhook/reconciler/claim recovery behavior is not executable as server verification.
- `ISSUE-020`: Error taxonomy may be too coarse for users and operators.
- `ISSUE-021`: Server code size and boundary concentration create review risk.

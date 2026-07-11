> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# 05 Server Optimizations

Optimizations are first-class findings. They include paths that already work but can be made faster, cheaper, safer, simpler, easier to operate, or easier to reason about.

## OPT-001: Centralize invoice/payment state-machine transitions

Evidence:

- Liquid exact, overpay, cancel-after-pay, expiry, and repeated payment cases pass.
- Underpay and BTC unconfirmed behavior remain ambiguous.
- Status values appear across `src/invoice.rs`, `src/db/invoices.rs`, `src/bitcoin_watcher.rs`, `src/chain_watcher.rs`, `src/claimer.rs`, `src/reconciler.rs`, and migrations.

Current server behavior:

- State transitions are implemented across multiple modules and SQL updates.

Improvement:

- Introduce a single state-transition module or DB-facing transition API.
- Make allowed transitions explicit.
- Require reason codes for transitions.
- Emit structured events on every transition.

Expected benefit:

- Fewer inconsistent states.
- Easier underpay/late-pay/BTC behavior fixes.
- Lower risk when adding product surfaces.

Verification:

- Targeted state-machine scenarios only, plus one smoke per rail.

## OPT-002: Expose payment progress separately from settlement progress

Evidence:

- Server code already has `settlement_status`.
- Live payment flows can be paid from the payer perspective while Boltz/claim/settlement work continues.
- BTC unconfirmed showed that payer progress and terminal settlement are not the same thing.

Current server behavior:

- Public status can collapse payer payment, confirmation, claim, and settlement into too few states.

Improvement:

- Return separate fields:
  - `payment_status`
  - `confirmation_status`
  - `settlement_status`
  - `next_action`
  - external refs such as txid/payment hash/swap ID where safe.

Expected benefit:

- Users see progress instead of timeouts.
- Operators can diagnose stuck paths without DB spelunking.
- Tests can stop waiting for the wrong terminal state.

Verification:

- BTC unconfirmed targeted run.
- One LN and one Liquid exact-pay smoke.

## OPT-003: Add build/version provenance endpoint

Evidence:

- Wrong binary deploy caused an invalid 22/22 Liquid failure run.
- `/health` returns only `ok`.

Current server behavior:

- Runtime health does not prove the server is the expected artifact.

Improvement:

- Add `/version` returning commit, branch/artifact, build time, schema version, runtime mode.
- Keep `/health` cheap for load balancers.

Expected benefit:

- Prevents wasted money tests against wrong binaries.
- Reduces rollback time.
- Makes certification reports reproducible.

Verification:

- Preflight checks expected commit before tests.

## OPT-004: Safe certification allowlisting instead of global rate-limit workarounds

Evidence:

- Broad ARS/certify runs were dominated by rate-limit skips/failures.

Current server behavior:

- Production protection works, but certification traffic is indistinguishable from suspicious traffic.

Improvement:

- Support explicit allowlisted certification identities/source IPs.
- Bypass only selected limits, never all protections.
- Log bypass reason and identity.

Expected benefit:

- No false certification failures.
- Keeps production attack resistance.
- Avoids wasting time rotating IPs or retrying contaminated runs.

Verification:

- Broad preflight should fail closed if allowlisting is absent.

## OPT-005: Make status polling cheaper and more precise

Evidence:

- Live matrix and LN storm paths poll status repeatedly.
- Successful paths can be moved to smoke-only, but production users will still poll.

Current server behavior:

- Status endpoints may recompute or lazily fetch rail data during user polling.

Improvement:

- Cache immutable invoice/payment fields.
- Avoid external calls in hot status paths unless explicitly refreshing stale rail offers.
- Add `retry_after_ms` or `next_poll_after_ms` to status responses.

Expected benefit:

- Lower DB/provider load at scale.
- Better client behavior.
- Less noisy high-volume runs.

Verification:

- Measure query count/latency on one live matrix smoke and one LN storm smoke.

## OPT-006: Make reusable payment pages independent from individual payment attempts

Evidence:

- Donation/payment-page underpay showed an attempt can get stuck or need force-terminal handling.
- Successful Liquid donation-page exact/overpay paths passed.

Current server behavior:

- Payment page identity and payment attempt state can be hard to separate operationally.

Improvement:

- Ensure each payment-page attempt is a distinct invoice/payment object.
- Reusable page stays healthy even if one attempt is underpaid, late, expired, or settlement-failed.
- Public page should always offer a clean next attempt unless the page itself is disabled.

Expected benefit:

- Users are not stuck because of one bad attempt.
- Easier operator support.
- Safer high-volume donation flows.

Verification:

- Targeted payment-page underpay, retry, exact-pay-after-underpay.

## OPT-007: Add operator-readable payment journey views

Evidence:

- Several conclusions required correlating run reports, DB state, txids, and deployment state manually.
- OP scenarios are still mostly playbooks.

Current server behavior:

- Operator diagnosis requires logs and raw DB knowledge.

Improvement:

- Add DB views or internal admin queries for:
  - invoice state
  - payment observations
  - swap/chain-swap state
  - settlement attempts
  - last error and next retry

Expected benefit:

- Faster support.
- Easier evidence collection.
- Lower risk of unsafe manual DB mutation.

Verification:

- For each targeted failure, operator view should explain current state without raw joins.

## OPT-008: Reduce duplicate lookup logic for nym state

Evidence:

- `R10`, `R16`, `C01`, `C02`, and `C08` all point at nym resolution or active-state consistency.
- Code paths include registration, NIP-05, LNURL metadata, LNURL callback, and Liquid callback behavior.

Current server behavior:

- Multiple handlers resolve nyms and active status.

Improvement:

- Centralize active nym lookup into one DB/API helper with explicit use cases.
- Return typed not-found/inactive/deleted states.

Expected benefit:

- Fewer inconsistencies.
- Clearer user/API errors.
- Faster root cause analysis for registration bugs.

Verification:

- Targeted registration/NIP-05/LNURL lookup matrix.

## Expanded Optimization Inventory

The first eight optimizations are not exhaustive. A broader re-mining of the test evidence and server surfaces identified more optimization candidates. See [09 Expanded Issue And Optimization Inventory](09-expanded-issue-and-optimization-inventory.md).

Additional optimizations currently tracked there:

- `OPT-009`: Add a server status projection layer.
- `OPT-010`: Add correlation IDs across request, invoice, payment event, swap, and logs.
- `OPT-011`: Add dependency health summaries without turning `/health` into a heavy endpoint.
- `OPT-012`: Add idempotency audit across all payment-creating endpoints.
- `OPT-013`: Add query/index review for high-volume list/status paths.
- `OPT-014`: Separate certification support from production bypasses.
- `OPT-015`: Add product-surface coverage map to server docs.

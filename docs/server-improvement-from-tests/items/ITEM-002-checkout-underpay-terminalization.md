# ITEM-002: Checkout Underpay Terminalization

Backlog reference: `ISSUE-001` / `OPT-001` / `OPT-006`
Type: payment state correctness
Priority: P0
Status: closed

## Evidence

- Test reports:
  - `bullnym-run-1779151124-liquidv2.json`: `LQ-21` failed because donation-page Liquid underpay did not reach terminal status within 180 seconds.
  - `bullnym-run-1779153353-liquidv2.json`: `LQ-21` passed after operator force-terminal support.
  - Live matrix runs show `INV-LIQUID-UNDERPAY` eventually passed and should not be treated as the same failure.
- Scenario IDs:
  - `LQ-21`
  - `INV-LIQUID-UNDERPAY`
- Relevant code:
  - `src/invoice.rs`: checkout-origin invoices use `origin = "checkout"` and a 7-day outer expiry.
  - `src/db/invoices.rs`: below-target payment becomes `partially_paid` unless the invoice is already expired.
  - `src/db/invoices.rs`: expired `partially_paid` invoices become `underpaid`.
  - `src/invoice.rs`: `partially_paid` remains payable, exposes `remaining_amount_sat`, and keeps rails available.
  - `src/gc.rs`: expiry sweep runs every 10 minutes and only terminalizes after outer expiry.

## Observed Behavior

A donation/payment-page Liquid underpayment was detected as partial, but it did not become terminal within the test/user time window. It could remain `partially_paid` until the checkout invoice's 7-day expiry unless an operator forces terminal state.

## Possible Interpretations

1. Current behavior is correct because `partially_paid` means "payment detected; remaining amount still payable."
   - Evidence for: current status API exposes `remaining_amount_sat`; payment rails remain available; docs describe `partially_paid` this way.
   - Evidence against: donation-page user journey can remain unresolved for days, and `LQ-21` required operator force to finish.
   - How to prove/disprove: decide whether checkout attempts should support donor top-up for the full outer expiry.

2. Checkout/donation-page attempts need different terminalization semantics than wallet-origin invoices.
   - Evidence for: payment-page attempts are ephemeral user journeys; retrying with a fresh attempt is clearer than leaving one attempt partial for days.
   - Evidence against: a donor might be able to top up the remaining amount if the attempt remains payable.
   - How to prove/disprove: verify product preference and whether top-up UX is actually visible/usable.

3. The status API is too coarse and should expose next action rather than forcing terminal state.
   - Evidence for: `remaining_amount_sat` exists but there is no explicit `next_action`.
   - Evidence against: this alone does not satisfy the need for unattended terminalization and still leaves long-lived partial attempts.
   - How to prove/disprove: compare user support needs for "pay remaining" vs "retry/refund" flows.

## Confirmed Conclusion

The server should not change all invoice underpay behavior. Wallet-origin and reusable invoices can legitimately remain `partially_paid` and payable. The confirmed server gap is checkout-origin partial payments: they need deterministic stale terminalization so donation/payment-page journeys do not require raw DB mutation or operator force.

## Non-Goals

- Do not rewrite the full invoice state machine yet.
- Do not change wallet-origin partial payment behavior.
- Do not terminalize underpay immediately on first partial payment.
- Do not remove `partially_paid`.
- Do not add refund automation in this item.

## Fix Planner Proposal

- Minimal server change:
  - Add a checkout-only stale partial terminalization transition:
    - `origin = 'checkout'`
    - `status = 'partially_paid'`
    - latest `invoice_payment_events.created_at` is older than a configured grace period
    - transition to `underpaid`
  - Run the transition from:
    - request-time status maintenance before returning `/api/v1/invoices/:id/status`
    - existing GC sweep, so it also progresses without status polling
  - Keep wallet-origin `partially_paid` payable until ordinary expiry.
- Files likely touched:
  - `src/config.rs`
  - `src/db/invoices.rs`
  - `src/gc.rs`
  - `src/invoice.rs`
  - unit tests around DB SQL helper or status policy where feasible
  - this item file
- Schema/API compatibility:
  - No migration required.
  - Existing statuses unchanged.
  - Status API behavior changes only after grace period for checkout partials.
- Proposed config:
  - `invoice_accounting.checkout_partial_terminal_grace_secs`
  - default: `900`
- Risks:
  - A donor who intends to top up after the grace period must start a fresh attempt.
  - If the grace period is too short, slow-but-legitimate top-ups become terminal `underpaid`.
  - If the grace period is too long, the real user remains stuck.
- Rollback plan:
  - Remove request-time maintenance call and GC call; leave config field harmless or remove before release.
- Verification:
  - Unit test proving checkout partial older than grace becomes `underpaid`.
  - Unit test or SQL helper test proving wallet-origin partial does not terminalize by this rule.
  - Unit/integration coverage proving checkout `underpaid` Liquid addresses remain watcher candidates until expiry, so already-sent top-ups can still be accounted.
  - `cargo check`.
  - Targeted future live rerun: `LQ-21` only, plus one exact checkout Liquid smoke.
- Tests not to rerun:
  - Full Liquid V2 suite.
  - LN storm.
  - BTC V2.
- Why not bigger:
  - The evidence points to one product-surface policy gap, not a need to redesign every invoice transition before fixing stuck checkout underpays.

## Plan Reviewer Objections

- High: Terminalizing from latest recorded event can miss a legitimate second Liquid top-up that was sent but not yet observed, because the Liquid address scan currently excludes `underpaid` invoices.
- High: `120s` is not defensible from watcher guarantees, backlog size, Electrum outages, or the 600s GC cadence.
- Medium: GC-only progress is too coarse for a 180s user/test window.
- Medium: request-time mutation must use a single idempotent DB helper and return/re-read the post-update row.
- Medium: terminalization must avoid stomping in-flight settlement states.
- Medium: verification must cover top-up/recovery and wallet-origin exclusion.
- Low: set-based GC SQL needs a clear query shape and should avoid an unbounded expensive scan.

## Planner/Reviewer Resolution

Accepted.

Final plan changes:

- Rename the behavior from quick underpay to stale checkout partial terminalization.
- Default `checkout_partial_terminal_grace_secs` to 900 seconds, not 120 seconds. This is conservative relative to the 30s active Liquid watcher tick and avoids tuning production behavior around a single test timeout.
- Keep the value configurable under `[invoice_accounting]` so test/staging environments can choose a shorter window after they verify watcher capacity.
- Terminalize only checkout-origin partials whose latest recorded payment event is older than the grace window.
- Do not terminalize rows whose settlement state is `pending`, `claim_stuck`, or `refunded`.
- Add an idempotent single-invoice helper used by status before fetching the row, so the status response is built from post-maintenance state.
- Add a coarse GC helper for unattended progress. GC cadence remains coarse; user-visible bounded behavior comes from status-time maintenance.
- Keep direct Liquid accounting recoverable by allowing the Liquid address watcher to keep scanning `origin='checkout' AND status='underpaid'` rows until outer expiry. If a second direct Liquid top-up appears later, `record_invoice_payment` can still update the invoice to `paid` or `overpaid`.

Residual risk:

- A donor who tries to fetch fresh payment rails after terminalization will see a terminal attempt and must start a new attempt. A direct Liquid top-up already sent to the same address can still be discovered.

## Implementation Summary

- Added `invoice_accounting.checkout_partial_terminal_grace_secs`, default `900`.
- Added idempotent single-invoice DB helper `terminalize_stale_checkout_partial_invoice`.
- Added bounded set-based GC helper `terminalize_stale_checkout_partial_invoices`.
- Status endpoint now runs single-invoice maintenance before fetching the invoice, so the response uses post-maintenance state.
- GC now runs coarse unattended stale checkout partial terminalization with the configured grace.
- Liquid address watcher candidates now include `origin='checkout' AND status='underpaid'` rows until outer expiry so already-sent direct Liquid top-ups can still be discovered and accounted.
- Added migration `029_checkout_underpaid_liquid_watch` with a partial index matching the widened Liquid watcher predicate.
- Preserved terminal monotonicity: late insufficient top-ups keep terminalized checkout attempts `underpaid`; late sufficient top-ups can recover to `paid` or `overpaid`.
- Added integration coverage for checkout terminalization, wallet-origin exclusion, and underpaid checkout Liquid recovery.

## Implementation Reviewer Findings

- High: `underpaid` could reopen to `partially_paid` after a later insufficient Liquid top-up.
- Medium: widened Liquid watcher scan did not have a matching partial index.
- Medium: status-time mutation was not tested through `/api/v1/invoices/:id/status`.

## Implementer/Reviewer Resolution

- Fixed the reopen bug by preserving `underpaid` when cumulative received value is still below target/tolerance. `underpaid` can still recover to `paid` or `overpaid` if later evidence reaches the amount.
- Added migration `029_checkout_underpaid_liquid_watch` for the widened watcher predicate.
- Added endpoint-level integration coverage for status-time stale checkout partial terminalization.
- Added integration coverage for insufficient late top-up remaining `underpaid`.

## Verification Result

- `cargo fmt --check`: passed.
- `cargo check`: passed.
- `cargo test --lib`: passed, 196 tests.
- `cargo test --test integration_test --no-run`: passed.
- Added integration tests compile, but cannot execute in this environment because `TEST_DATABASE_URL` is not set:
  - `stale_checkout_partial_terminalizes_to_underpaid`
  - `stale_wallet_partial_stays_payable`
  - `checkout_underpaid_liquid_address_remains_watchable_and_recoverable`
  - `checkout_underpaid_insufficient_topup_stays_underpaid`
  - `invoice_status_terminalizes_stale_checkout_partial_before_response`

## Closure Decision

Closed for ITEM-002. Remaining production/staging validation is the targeted live rerun: `LQ-21` plus one exact checkout Liquid smoke after deploying a build whose `/version.expected_schema_marker` is `029_checkout_underpaid_liquid_watch`.

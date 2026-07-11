> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# ITEM-003: BTC Unconfirmed Payment Status

Backlog reference: `ISSUE-002` / `OPT-002`
Type: reliability / observability
Priority: high
Status: closed

## Evidence

- Test reports:
  - `bullnym-run-1779139541-bitcoinv2.json`
  - `bullnym-run-1779140155-bitcoinv2.json`
- Scenario IDs:
  - `BTC-01`
- Server logs:
  - Not present in the local evidence set for the failing run.
- DB rows:
  - Not present in the local evidence set for the failing run.
- External refs:
  - Mempool endpoint behavior is inferred from the existing `bitcoin_watcher` code path, not from a captured raw API response.
- Relevant code:
  - `src/bitcoin_watcher.rs`
  - `src/db/invoices.rs`
  - `src/invoice.rs`
  - `migrations/024_invoice_payment_events.sql`
  - `migrations/028_invoice_payment_event_evidence.sql`
  - `docs/architecture/payment-lifecycle.md`

## Observed Behavior

`BTC-01` failed once because the BDK sender wallet had no spendable funds, then failed again after the test reported a broadcast/unconfirmed Bitcoin payment but did not observe a terminal invoice status within the test window.

The server already has an internal `in_progress` state for direct BTC mempool sightings. The public status response exposes `status` and `settlement_status`, but it does not expose the observed Bitcoin txid, vout, amount, or confirmation count. That makes a real user or reliability runner see an opaque timeout instead of "payment seen, waiting for confirmations."

## Possible Interpretations

1. The direct BTC watcher observed the tx and correctly marked the invoice `in_progress`, but the API did not expose enough evidence.
   - Evidence for:
     - `bitcoin_watcher` marks invoices `in_progress` on mempool or below-threshold confirmed sightings.
     - `InvoiceStatusResponse` has no direct BTC observation fields.
   - Evidence against:
     - No raw BTC-01 status samples are available locally.
   - How to prove/disprove:
     - Rerun `BTC-01` after adding persisted observations and assert the status response includes tx evidence before confirmations.

2. The direct BTC watcher did not observe the tx during the test window.
   - Evidence for:
     - No persisted unconfirmed observation exists today, so this cannot be proven from DB state.
     - The watcher can miss a tick because of upstream lag, endpoint errors, or token-bucket pressure.
   - Evidence against:
     - The test description says broadcast/unconfirmed, but that may only mean the sender wallet saw it.
   - How to prove/disprove:
     - Persist observations when the watcher sees candidate outputs and compare test wallet txids to server observations.

3. Confirmed BTC accounting is broken.
   - Evidence for:
     - None from the current code review.
   - Evidence against:
     - Confirmed outputs are recorded with `bitcoin_direct:<txid>:<vout>` event keys after the configured confirmation threshold.
     - `invoice_payment_events` has source/rail constraints and is summed into invoice paid amount.
   - How to prove/disprove:
     - Confirmed direct BTC payment after the observation fix should advance through the existing `record_invoice_payment` path.

4. The failure was a test harness expectation bug.
   - Evidence for:
     - If the test only accepted terminal `paid`, it would incorrectly fail during a legitimate confirmation wait.
   - Evidence against:
     - Users still need actionable status; server observability is incomplete regardless of test logic.
   - How to prove/disprove:
     - Require the runner to accept an explicit server state of "seen, awaiting confirmations" before terminal settlement.

## Confirmed Conclusion

The failing run does not prove whether the server watcher saw the Bitcoin transaction. It does prove that the current server cannot preserve or expose that fact either way. The actionable server defect is missing persisted, API-visible evidence for direct BTC payments that are seen but not countable yet. This must be fixed without changing the existing accounting rule that only sufficiently confirmed BTC outputs count as paid money.

## Non-Goals

- Do not count unconfirmed BTC as paid.
- Do not use `invoice_payment_events` for unconfirmed observations.
- Do not merge direct BTC behavior with Boltz BTC chain-swap behavior.
- Do not add a broad new invoice state machine.
- Do not rerun the full BTC live matrix until `BTC-01` can distinguish "not seen" from "seen, awaiting confirmations."

## Fix Planner Proposal

- Minimal server change:
  - Add a dedicated `invoice_payment_observations` table for non-accounting payment sightings.
  - Persist direct BTC observations from `bitcoin_watcher` for mempool and below-threshold confirmed outputs.
  - Expose recent direct BTC observations in `/api/v1/invoices/:id/status`.
  - Keep `status='in_progress'` and `settlement_status='pending'` for seen-but-not-counted BTC.
- Files likely touched:
  - `migrations/030_invoice_payment_observations.sql`
  - `src/db/invoices.rs`
  - `src/bitcoin_watcher.rs`
  - `src/invoice.rs`
  - `src/version.rs`
  - `docs/architecture/payment-lifecycle.md`
  - this item file
- Schema/API compatibility:
  - Additive migration.
  - Additive JSON field on status response: `bitcoin_direct_observations`.
  - Existing clients can ignore the field.
- Risks:
  - Observation rows must not affect `paid_amount_sat`.
  - Unique keys must avoid duplicate rows while allowing confirmation counts to update.
  - Status output must not confuse direct BTC observations with Boltz chain-swap state.
- Rollback plan:
  - Stop writing observations and ignore the additive status field.
  - The table can remain inert without affecting accounting.
- Verification:
  - Unit/integration coverage for observation upsert idempotency and confirmation update.
  - Status endpoint coverage showing observations are returned without marking the invoice paid.
  - Compile `integration_test`.
  - Run `cargo test --lib`.
- Tests not to rerun:
  - Lightning, Liquid, registration, and broad ARS matrices. This item only changes direct BTC observation and status projection.

## Plan Reviewer Objections

- Blocking: the conclusion overstated the evidence because the local evidence set has no server logs, DB rows, raw mempool response, or status samples.
- Blocking: the schema/API plan was underspecified: no columns, constraints, enum values, JSON shape, ordering, retention, privacy posture, or terminal-status behavior.
- Blocking: the plan did not address stale mempool, RBF, or reorg behavior.
- Blocking: accounting separation was asserted but not enforced by design.
- Blocking: migration/index/grant risks were not specified.
- Blocking: verification did not include focused watcher/status behavior.

## Planner/Reviewer Resolution

Accepted. The revised plan is:

- Add `invoice_payment_observations` as non-accounting evidence only.
- Exact schema:
  - `invoice_id UUID REFERENCES invoices(id) ON DELETE CASCADE`
  - `rail TEXT CHECK (rail = 'bitcoin')`
  - `source TEXT CHECK (source = 'bitcoin_direct')`
  - `event_key TEXT UNIQUE`
  - `txid TEXT CHECK 64 hex chars`
  - `vout INTEGER CHECK >= 0`
  - `address TEXT`
  - `amount_sat BIGINT CHECK > 0`
  - `confirmations INTEGER CHECK >= 0`
  - `block_height INTEGER NULL`
  - `last_seen_state TEXT CHECK IN ('seen_unconfirmed','awaiting_confirmations','counted','not_seen')`
  - `first_seen_at`, `last_seen_at`
- Upsert rule:
  - Unique by `event_key`, with update allowed only for the same `invoice_id`.
  - Update amount, confirmations, block height, state, and `last_seen_at`.
- Stale/RBF policy:
  - Every successful address poll marks previously uncounted observations for that invoice as `not_seen` if their event key is absent from the current response.
  - This is evidence, not accounting reversal.
- Status API:
  - Add bounded field `bitcoin_direct_observations`, max 10, newest first.
  - Include `source`, `rail`, `txid`, `vout`, `address`, `amount_sat`, `confirmations`, `block_height`, `state`, `first_seen_at_unix`, `last_seen_at_unix`.
  - Return observations for terminal and non-terminal invoices because the status endpoint already exposes invoice-scoped payment addresses; tx evidence is useful audit context for the holder of the invoice URL.
- Accounting invariant:
  - Observations are never read by `record_invoice_payment` and never update `paid_amount_sat`, `paid_via`, `paid_at`, or terminal status.
- Verification:
  - Unit-test direct BTC observation classification.
  - Integration-test observation upsert, stale marking, status projection, and no accounting mutation.
  - Compile all integration tests and run lib tests locally.

## Implementation Summary

- Files changed:
  - `migrations/030_invoice_payment_observations.sql`
  - `src/db/invoices.rs`
  - `src/bitcoin_watcher.rs`
  - `src/invoice.rs`
  - `src/version.rs`
  - `docs/architecture/payment-lifecycle.md`
  - `tests/integration_test.rs`
- Behavioral change:
  - Direct BTC watcher persists non-accounting observations for mempool, below-threshold confirmed, and counted outputs.
  - Status API returns `bitcoin_direct_observations`.
  - Successful address polls mark previously uncounted observations `not_seen` when the outpoint disappears.
- Migration/backfill:
  - Additive table only; no backfill.
- Observability added:
  - Users/operators can distinguish no server observation, unconfirmed seen, awaiting confirmations, counted, and previously seen but now absent.

## Implementation Reviewer Findings

- Blocking: `counted` observations were originally written before the accounting event. A crash or accounting error could expose `state="counted"` without a matching `invoice_payment_events` row.
- Nonblocking: the migration validated `txid` and `vout` but did not enforce `event_key = bitcoin_direct:<txid>:<vout>`.
- Nonblocking: the plan still named the additive JSON field `payment_observations` in one section, while implementation used `bitcoin_direct_observations`.
- Nonblocking: tests do not yet mock the full watcher HTTP path.

## Implementer/Reviewer Resolution

- `record_confirmed_output` now returns whether accounting is actually present.
- The watcher writes `state="counted"` only after `record_invoice_payment` inserts the accounting event, or after a duplicate event-key no-op is proven to already exist for the same invoice.
- Added DB helper `invoice_payment_event_exists` for the duplicate-accounting case.
- Tightened the migration check and Rust validation so observation `event_key` must match `bitcoin_direct:<txid>:<vout>`.
- Updated the stale plan field name to `bitcoin_direct_observations`.
- Remaining watcher HTTP mock coverage is accepted as a follow-up because helper classification, DB invariants, status projection, and accounting isolation are covered locally; live `BTC-01` remains the final behavioral proof after deploy.

## Verification Result

- `cargo fmt --check`: pass.
- `cargo check`: pass.
- `cargo test bitcoin_watcher::tests`: pass, 3 tests.
- `cargo test --lib`: pass, 199 tests.
- `cargo test --test integration_test --no-run`: pass.
- Focused DB-backed integration execution is blocked locally because `TEST_DATABASE_URL` is not set:
  - `cargo test bitcoin_payment_observations_do_not_count_as_paid` fails at preflight with `TEST_DATABASE_URL must be set to run integration tests: NotPresent`.
- Remaining risk:
  - Watcher HTTP path is not mocked in local tests.
- Final proof requires targeted `BTC-01` rerun after deploy. On current builds,
  the preflight marker is `/version.expected_schema_marker =
  "031_get_paid_descriptors"`; the `030_invoice_payment_observations` migration
  remains the feature's schema prerequisite but is no longer the latest marker.

## Closure Decision

- Closed for ITEM-003 implementation. Follow-up verification is targeted live `BTC-01`, not a broad BTC matrix.

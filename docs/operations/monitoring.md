# Monitoring

Monitor service availability, worker progress, money-state invariants, and
dependency health separately.

## Required signals

- `/health`, `/ready`, `/version`, process restarts, and database pool pressure;
- last successful tick and duration for every worker;
- counts and maximum age by swap and invoice status;
- claim attempts, slow-recovery attempts, and next retry timestamps;
- provider, Electrum, mempool API, and price-source latency/error rates;
- `bull_bitcoin_fallback_committed` counts by category, selected rail, and
  transition; a new `ambiguous_create` fallback after schema 077 is a policy
  regression;
- `bull_bitcoin_create_ambiguous` counts split by whether a candidate order ID
  was retained, plus the depth and oldest age of `dispatch_started` rows and
  successful `bull_bitcoin_ambiguous_create_reconciled` transitions; page when
  a candidate-bearing row does not converge and alert when a row without a
  candidate emits `bull_bitcoin_create_correlation_required`;
- unfunded-provider-watch depth, oldest due age, and reconciliation delay,
  separate from funded payout-pending work;
- `money_admission_creation_circuit_changed` state/reason transitions and its
  monotonic provider-creation transition count;
- `chain_provider_limits_startup_*` and `chain_provider_limits_refresh_*`
  outcomes. Alert when the exact BTC-to-L-BTC chain snapshot remains missing,
  invalid, or stale long enough to hide Bitcoin from otherwise payable
  checkouts; do not substitute reverse-swap limits;
- Bitcoin and Liquid direct-watcher recent/historical backlog counts,
  oldest-due timestamps, and lag from each frozen lane-start log;
- descriptor allocation failures and uniqueness violations;
- invoice events missing after a claimed swap;
- funded fiat-only Bull Bitcoin rows retaining a payer instruction (must stay
  zero), and attempts to quote or reserve a second payer intent after provider
  funds are observed;
- swap-backed `provider_only` rows by reserved/dispatch/bound/funded/final
  phase, time from Boltz funding to provider binding, and any funded row whose
  immutable journal is not exactly one Bull Bitcoin vout-0 output (must stay
  zero);
- fiat-fixed Bull Bitcoin payment events without immutable quote valuation,
  split by legacy-unattributable and current-schema rows (the latter must stay
  zero);
- invoice-face credit and provider-payout credit by their own currencies; do
  not aggregate or compare those amounts across currency boundaries;
- `refunding` rows without a reconciled transaction outcome.

Page immediately on claim/refund conflict events, provider-refund incidents,
funded swaps whose recovery schedule does not advance, or disagreement between
chain evidence and recorded terminal state. Alert on sustained webhook loss,
settlement repair failures, and growing watcher backlogs.

## Targeted Liquid status refreshes

Invoice-status polling uses a bounded, invoice-keyed Liquid wake queue. It is a
latency optimization only; the scheduled recent and historical lanes remain the
completeness and recovery mechanism.

Track `liquid_watcher_targeted_wakeup_completed` separately from background
lane turns. Its stable fields include `outcome`, `latency_ms`, `request_count`,
`coalesced_requests`, `queue_depth_after_dequeue`, `queue_depth`, and
`outstanding`. The paired `invoice_status_direct_watcher_wakeup` event reports
`liquid_wait_timed_out`, `liquid_backpressured`, and whether that request was
coalesced. Alert on sustained backpressure, rising queue depth, or targeted
latency above the two-second status wait; do not interpret wake completion as
payment evidence. Payment authority remains the refreshed database projection.

Logs and metrics contain sensitive payment linkage. Restrict access, define a
retention period, and avoid exporting raw descriptors, private keys, transaction
hex, signatures, or bearer invoice URLs to third-party telemetry.

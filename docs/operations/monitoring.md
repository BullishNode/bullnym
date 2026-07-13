# Monitoring

Monitor service availability, worker progress, money-state invariants, and
dependency health separately.

## Required signals

- `/health`, `/ready`, `/version`, process restarts, and database pool pressure;
- last successful tick and duration for every worker;
- counts and maximum age by swap and invoice status;
- claim attempts, slow-recovery attempts, and next retry timestamps;
- provider, Electrum, mempool API, and price-source latency/error rates;
- Bitcoin and Liquid direct-watcher recent/historical backlog counts,
  oldest-due timestamps, and lag from each frozen lane-start log;
- descriptor allocation failures and uniqueness violations;
- invoice events missing after a claimed swap;
- `refunding` rows without a reconciled transaction outcome.

Page immediately on claim/refund conflict events, provider-refund incidents,
funded swaps whose recovery schedule does not advance, or disagreement between
chain evidence and recorded terminal state. Alert on sustained webhook loss,
settlement repair failures, and growing watcher backlogs.

Logs and metrics contain sensitive payment linkage. Restrict access, define a
retention period, and avoid exporting raw descriptors, private keys, transaction
hex, signatures, or bearer invoice URLs to third-party telemetry.

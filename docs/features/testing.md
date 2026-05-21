# Testing Boundaries

Use the smallest layer that proves the behavior being changed.

## Local Server Tests

Local Rust tests cover server-owned behavior:

- auth payload construction and verification
- request validation
- descriptor parsing and address derivation
- invoice state transitions
- accounting helpers
- route wiring
- config parsing

Useful commands:

```bash
cargo test --lib
cargo test --tests --no-run
```

DB-backed integration tests require `TEST_DATABASE_URL` and a migrated test
database.

## bullnym-test VM

The bullnym-test VM is a deployed server/payment-rail harness. It is for:

- BDK-origin Bitcoin sends to direct Bitcoin invoices
- LWK-origin Liquid sends to direct Liquid invoices and donation checkout
- Jungle or other Lightning sends to Boltz reverse-swap offers
- Boltz chain swaps for donation-page Bitcoin checkout
- Liquid Electrum watcher behavior, Bitcoin mempool-API watcher behavior,
  invoice accounting, and status polling
- donation-page checkout and address allocation

It proves that a deployed Bullnym build and payment rails handled a scenario.

It does not prove:

- Flutter UI behavior
- mobile deterministic wallet paths
- app storage
- mobile payload construction
- emulator or device flows

## Mobile Repository

Mobile compatibility must be validated in the Bull Bitcoin mobile repository.
That is where deterministic wallet derivation, signed request payloads,
repository behavior, BLoC/UI flows, and device behavior belong.

After mobile contract tests pass, bullnym-test can exercise the deployed server
against realistic payment rails.

# Bullnym

Bullnym is BULL Bitcoin's non-custodial payment coordination backend. It gives
merchant wallets public payment identities and checkout surfaces while settling
successful payments to wallet-controlled Bitcoin or Liquid destinations.

Bullnym is a Rust/Axum service with Postgres persistence, Svelte payment/POS
PWAs, Boltz swap integration, Liquid Electrum observation, and Bitcoin mempool
observation.

## Products

| Product | Public surface | Payer options | Merchant settlement |
|---|---|---|---|
| Lightning Address | `nym@domain` | Lightning; LUD-22 direct Liquid | Dedicated Lightning Address Liquid wallet |
| Payment Page | `/:nym` or `/a/:alias` | Lightning, Liquid, Bitcoin through Boltz | Dedicated Payment Page Liquid wallet |
| POS | `/:nym/pos` | Lightning, Liquid, Bitcoin through Boltz | Dedicated POS Liquid wallet |
| Invoices | `/:nym/i/:id` or `/invoice/:id` | Merchant-selected Lightning, Liquid, and direct Bitcoin | Invoice-specific wallet destinations |

The Nostr authentication public key owns server resources. A `nym` is a public
payment namespace and Lightning Address local part. Merchant clients use
dedicated deterministic wallets and descriptors so Bullnym payment activity is
separated from the merchant's primary wallets.

## Trust model

Bullnym is designed as non-custodial payment coordination software, not as a
service that accepts and transmits customer funds. Bullnym does not receive
payments into a Bullnym-owned account, maintain customer balances, pool funds,
or hold the merchant wallet's spending keys. Payers send directly over
Lightning or to Bitcoin or Liquid on-chain outputs, and successful settlement
pays an address controlled by the merchant's wallet.

For Boltz-backed payments, Bullnym creates and monitors the swap and uses
swap-specific key material to claim or recover funds to the configured merchant
destination. Users must therefore trust Bullnym to execute the swap correctly,
even though Bullnym does not take possession of customer funds for later
remittance from its own custody. These architectural properties are the
technical basis for treating Bullnym as payment coordination infrastructure
rather than a custodial money transmission service.

See [Trust Model](docs/architecture/trust-model.md) for the complete authority
and failure boundaries.

## Repository

```text
src/          Rust service
migrations/   PostgreSQL migrations
pwa/          Payment Page and POS PWA source and checked build output
templates/    Server-rendered fallback and invoice templates
tests/        Server integration tests
docs/         Maintained architecture, API, product, and operations docs
archive/      Historical plans, research, and test evidence
```

## Local development

Prerequisites:

- Rustup with the pinned toolchain from `rust-toolchain.toml`
- PostgreSQL
- Node.js/npm when changing the PWA
- Python 3.11+ for release provenance verification and records

`boltz-client` is fetched from BullishNode/boltz-rust at the exact revision in
`release-manifest.toml`, `Cargo.toml`, and `Cargo.lock`; a sibling checkout is
not required for ordinary builds.

```bash
export DATABASE_URL=postgres://postgres:postgres@localhost/bullnym
export SWAP_MNEMONIC="twelve word development mnemonic ..."

sqlx migrate run
cargo test --lib
cargo run
```

Contributors changing both repositories may explicitly activate the ignored
local path override. It is never accepted by release preflight or CI:

```bash
cp .cargo/config.local.toml.example .cargo/config.toml
# remove .cargo/config.toml before release verification
```

The server listens on `0.0.0.0:8080` by default. Copy and review `config.toml`
for non-secret runtime settings. Production secrets belong in the environment.

For PWA changes:

```bash
cd pwa
npm ci
npm test
npm run build
npm run check:dist
```

`pwa/dist` is checked in because the current Rust deployment consumes prebuilt
assets. `pwa/scripts/check-dist.sh` verifies that it matches a clean build.

## Documentation

- [Documentation index](docs/README.md)
- [API reference](docs/api/README.md)
- [Architecture](docs/architecture/overview.md)
- [Products](docs/products/)
- [Operations](docs/operations/)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

Implementation proposals live under [RFCs](docs/rfcs/README.md). Completed,
superseded, and abandoned work is retained under [archive](archive/README.md)
and is not part of the current product contract.

## Verification

```bash
cargo test --lib
cargo test --tests --no-run
scripts/check-docs.sh
scripts/test-release-provenance.sh
scripts/test-release-record.sh
scripts/release-preflight.sh
```

DB-backed integration tests require `TEST_DATABASE_URL` and a migrated test
database. Deployed payment-rail certification and mobile compatibility are
separate verification layers; see [Contributing](CONTRIBUTING.md).

Use `scripts/test-db.sh` for the self-contained database gate. It creates a
uniquely named PostgreSQL 16 container on a random loopback port, applies every
migration to both a fresh database and an upgrade-fixture database, and runs the
integration target serially against each. Cleanup is automatic even when a
migration or test fails, unless `--keep` is explicitly requested.

```bash
scripts/test-db.sh
scripts/test-db.sh --mode fresh --filter og_reconciler
scripts/test-db.sh --keep
```

Migration-specific upgrade fixtures live in `tests/migration-hooks/` as
matching `<migration>.before.sql` and `<migration>.after.sql` files.

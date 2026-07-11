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

- Rust toolchain
- PostgreSQL
- `sqlx-cli` with PostgreSQL support
- Node.js/npm when changing the PWA
- a sibling `../boltz/boltz-rust` checkout matching the pinned project revision

```bash
export DATABASE_URL=postgres://postgres:postgres@localhost/bullnym
export SWAP_MNEMONIC="twelve word development mnemonic ..."

cp config.example.toml config.toml
sqlx migrate run
cargo test --lib
cargo run
```

The example listens on `127.0.0.1:8080`. `config.toml` is ignored local runtime
state; production secrets belong in the environment or a secret manager.

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
scripts/release-preflight.sh
```

DB-backed integration tests require `TEST_DATABASE_URL` and a migrated test
database. Deployed payment-rail certification and mobile compatibility are
separate verification layers; see [Contributing](CONTRIBUTING.md).

## License

Bullnym is available under the [MIT License](LICENSE). Copyright 2026 Bull
Bitcoin.

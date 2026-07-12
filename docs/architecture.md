# Architecture

Bullnym is a Rust/Axum payment backend with Postgres as durable state and
external integrations for Boltz, Liquid Electrum, Bitcoin mempool data, and
fiat pricing.

## System Boundary

Bullnym does not custody user funds. It creates payment instructions, derives
or records settlement destinations, watches payment evidence, and drives Boltz
claim flows. Recipient keys and wallet recovery remain in the client wallet.

The server is trusted to:

- derive addresses from descriptors supplied by the wallet
- create Boltz swaps with the correct claim destination
- report payment state honestly
- avoid address reuse and descriptor-cursor corruption

The server is not trusted with:

- spending keys for recipient wallets
- recipient mnemonic material
- direct custody of Bitcoin or Liquid funds

## Runtime Shape

```text
HTTP clients
  |
  v
Axum router
  |
  +-- LNURL / NIP-05 / registration handlers
  +-- public surface handlers and render fallback
  +-- invoice handlers and public payment pages
  +-- Boltz webhook handler
  |
  v
Postgres
  |
  +-- users, donation_pages, invoices
  +-- swap_records, chain_swap_records
  +-- payment events and observations
  +-- rate-limit and idempotency tables

Background workers
  |
  +-- claimer
  +-- reconciler
  +-- Liquid watcher
  +-- Bitcoin watcher
  +-- GC and rate-limit sweeps
```

## Main Modules

| Module | Role |
|---|---|
| `main.rs` | Loads config, initializes dependencies, starts workers, builds the router. |
| `registration.rs` | Nym create/update/delete and lookup. |
| `lnurl.rs` | LNURL metadata and callback, including LUD-22 Liquid address negotiation. |
| `nostr.rs` | NIP-05 public key lookup. |
| `donation_page.rs` | Signed Payment Page/POS management. |
| `donation_render.rs` | Payment Page and POS shell rendering. |
| `invoice.rs` | Checkout creation, signed wallet-origin invoices, status, offers, cancel, list, and render. |
| `claimer.rs` | Boltz webhook handling and cooperative claim execution. |
| `reconciler.rs` | Polls Boltz to repair missed webhook state. |
| `chain_watcher.rs` | Liquid Electrum watcher for direct Liquid, LUD-22, and descriptor cursor advancement. |
| `bitcoin_watcher.rs` | Direct Bitcoin invoice watcher and observation writer. |
| `db/*` | Query helpers grouped by table or workflow. |
| `rate_limit.rs` | In-memory and DB-backed rate-limit enforcement. |
| `certification.rs` | Scoped test/certification preflight and bypass checks. |
| `config.rs` | Runtime configuration and defaults. |

## Request Flow

For signed client actions:

1. Axum routes the request to the feature handler.
2. Cheap validation runs before expensive signature or descriptor parsing.
3. The handler builds the domain-separated signing payload.
4. The server verifies the BIP-340 Schnorr signature and timestamp.
5. The handler applies rate limits and authorization checks.
6. The database write uses constraints and idempotent keys where needed.
7. The response returns the stable client contract.

For public checkout surfaces:

1. The server renders the Payment Page, POS shell, or invoice page. Rendering
   a shell does not allocate a Liquid address.
2. The payer creates a checkout invoice or refreshes payment instructions.
   Checkout invoice creation allocates one Liquid settlement address; status
   polling and page rendering do not.
3. Watchers, webhooks, and the reconciler update payment and settlement state.
4. The page polls invoice status until terminal or expired.

## Payment Flow

Lightning payments use Boltz reverse swaps:

1. Bullnym creates a reverse swap and exposes the BOLT11 invoice.
2. The payer pays Lightning.
3. Boltz locks LBTC.
4. Bullnym claims LBTC to the recipient settlement address.
5. Bullnym records accounting only after recipient-side settlement succeeds.

Direct Liquid payments:

1. Bullnym exposes a Liquid address. Public checkout addresses are allocated at
   checkout invoice creation, not at shell render time.
2. The payer broadcasts a Liquid transaction.
3. The Liquid watcher detects the matching output through Liquid Electrum
   scripthash history and raw transaction fetches.
4. Bullnym records an idempotent payment event.

Direct Bitcoin invoices:

1. Mobile supplies a Bitcoin address at invoice creation.
2. The Bitcoin watcher polls the configured mempool.space-shaped HTTP API and
   records observations while confirmations are pending.
3. Bullnym records accounting once the configured confirmation threshold is met.

Public Bitcoin checkout:

1. Bullnym creates a Boltz BTC-to-LBTC chain swap.
2. The payer sends BTC to the lockup address.
3. Bullnym claims LBTC to the checkout settlement address.
4. Bullnym records accounting after recipient-side LBTC settlement.

## Descriptor Architecture

Bullnym has descriptor-backed receive domains:

- Lightning Address descriptor: `users.ct_descriptor`, cursor
  `users.next_addr_idx`.
- Payment Page descriptor: `donation_pages.ct_descriptor` where
  `kind = 'payment_page'`, cursor `donation_pages.next_addr_idx`.
- POS descriptor: `donation_pages.ct_descriptor` where `kind = 'pos'`, cursor
  `donation_pages.next_addr_idx`.

The split prevents public checkout receives from consuming the Lightning
Address wallet path. Legacy Payment Pages without a page descriptor fall back
to the nym descriptor until migrated. POS does not fall back.

Surface cursor advancement is tied to checkout invoice creation. Plain
`GET /:nym`, `GET /:nym/pos`, and invoice status polling are non-allocating
reads.

Wallet-origin invoices do not use server-stored descriptors. Mobile supplies
concrete settlement addresses for those invoices.

## Reliability Model

The service is stateless across processes except for Postgres. Restart-safety
comes from:

- durable swap and invoice rows
- idempotent webhook event keys
- idempotent payment event keys
- startup/background scans
- Boltz reconciliation after missed webhooks
- compare-and-set updates for terminal states
- descriptor cursor updates guarded by database transactions

## Configuration Boundary

Runtime config lives in `config.toml`; secrets and connection strings come from
the environment. Important boundaries:

- `DATABASE_URL` points at Postgres.
- `SWAP_MNEMONIC` derives Boltz claim material.
- `BOLTZ_WEBHOOK_URL_SECRET` authenticates webhook delivery by URL path.
- Electrum and mempool endpoints are external data sources and must be treated
  as availability dependencies.
- Rate-limit and certification settings define whether broad test runs can
  proceed without contaminating production abuse controls.

## Documentation Map

Use this file for the system shape. Use component docs for individual
subsystems, feature docs for product behavior, and `payment-architecture.md`
for detailed cross-rail accounting semantics.

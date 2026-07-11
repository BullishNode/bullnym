# Architecture overview

Bullnym is a Rust/Axum payment coordinator backed by PostgreSQL. It serves
Lightning Address, Payment Page, POS, and invoice APIs; negotiates Boltz swaps;
watches Bitcoin and Liquid; and serves Svelte PWAs for public payment flows.

Read the [trust model](trust-model.md) before interpreting “non-custodial.”
Bullnym does not hold the merchant's wallet keys, but the server controls
payment negotiation and swap-specific recovery material.

## Runtime

```text
ordinary payer wallets             merchant client
          |                              |
          +---------- HTTPS ------------+
                         |
                    Axum server
                 /       |        \
           PostgreSQL  workers   PWA assets
                         |
              +----------+----------+
              |          |          |
            Boltz   Electrum APIs  mempool API
```

PostgreSQL is the durable coordination boundary. HTTP handlers create signed
merchant resources and public payment sessions. Background workers claim
swaps, reconcile missed provider webhooks, observe chains, repair settlement
accounting, retry stuck claims, and prune operational tables.

## Product flows

| Surface | Payer instruction | Merchant settlement |
|---|---|---|
| Lightning Address | Lightning reverse swap, or direct Liquid through LUD-22 | Liquid address derived from the nym descriptor |
| Payment Page | Lightning reverse swap, direct Liquid, or Bitcoin chain swap | Liquid address allocated from the surface descriptor |
| POS | Lightning reverse swap, direct Liquid, or Bitcoin chain swap | Liquid address allocated from the POS descriptor |
| Invoice | Lightning reverse swap, direct Liquid, or direct Bitcoin | Concrete Liquid and Bitcoin addresses supplied when the invoice is created |

Rendering a public page does not allocate an address. Checkout creation
allocates and persists the concrete destination used by all offers for that
session.

## Module map

| Module | Responsibility |
|---|---|
| `main.rs` | Dependency initialization, worker startup, router assembly |
| `registration.rs`, `nostr.rs` | Nym lifecycle and public identity discovery |
| `lnurl.rs` | LNURL-pay and LUD-22 negotiation |
| `donation_page.rs`, `donation_render.rs` | Payment Page/POS management and rendering |
| `invoice.rs` | Checkout and merchant invoice lifecycle |
| `claimer.rs` | Swap webhooks, claims, renegotiation, and chain-swap refunds |
| `reconciler.rs` | Provider polling, slow recovery, and settlement repair |
| `chain_watcher.rs`, `bitcoin_watcher.rs` | Liquid and Bitcoin observations |
| `db/` | Workflow-specific persistence and guarded state transitions |
| `config.rs`, `readiness.rs` | Runtime policy and dependency/schema checks |

## Persistence and reliability

Durable swap rows contain provider identifiers, concrete destinations,
swap-specific keys, provider responses, retry state, and transaction evidence.
Invoice payment events are idempotent accounting records. Observations describe
unconfirmed direct-Bitcoin evidence without crediting it.

The main recovery mechanisms are:

- authenticated provider webhooks plus periodic reconciliation;
- deterministic, idempotent claim retries;
- a long-backoff slow-recovery sweep for funded `claim_stuck` rows;
- settlement repair when a claim committed but the invoice flip did not;
- direct Bitcoin and Liquid chain watchers;
- guarded chain-swap renegotiation and merchant-directed emergency refunds.

These mechanisms improve crash and dependency-failure recovery. They do not
make provider state authoritative or replace confirmation monitoring. See
[Payment lifecycle](payment-lifecycle.md) and [Data and workers](data-and-workers.md).

## Configuration boundary

`config.toml` defines non-secret runtime policy. Environment variables provide
database credentials and sensitive key material. Important dependencies are
PostgreSQL, Boltz, Liquid Electrum, the Bitcoin mempool-compatible API, price
feeds, and the prebuilt PWA assets.

Production configuration must pass readiness checks for schema, required
features, and external dependencies. See [Operations](../operations/README.md).

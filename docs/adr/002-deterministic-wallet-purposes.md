# 002 Deterministic Wallet Purposes

- Status: Accepted
- Amended: 2026-07-28 — corrected to the shipping BIP85 registry (#273)
- Scope: `bullbitcoin-mobile`; Bullnym depends on the resulting descriptors

## Decision

Bull-created non-default receive wallets are deterministic BIP85 child wallets.
Each reserved product identity is a BIP39 English 12-word child mnemonic
derived at `m/83696968'/39'/0'/12'/{index}'`:

| Index | Product | Wallets materialized from the child seed |
| --- | --- | --- |
| `100'` | BTCPay | Bitcoin and Liquid |
| `101'` | Lightning Address | Liquid |
| `102'` | Payment Page | Liquid |
| `103'` | POS | Liquid |

The BIP85 path is network-neutral. The network is bound at wallet creation:
one child seed per product index yields that product's wallet on each network
it needs. BTCPay materializes both a Bitcoin and a Liquid wallet from the same
index-`100'` child seed; Lightning Address, Payment Page, and POS each
materialize one Liquid wallet.

The mobile `features/bip85_registry` static registry is the source of truth
for these reservations and their canonical deterministic aliases. The interim
development index `77` was never released and has no migration or
compatibility behavior.

Manual and developer BIP85 derivation must exclude every reserved wallet-seed
index so users cannot occupy product wallet space. The exclusion set is
derived from the registry's reservation list (currently `100'`–`103'`), so a
new wallet-seed reservation is covered automatically.

## Rationale

Lightning Address, Payment Page, POS, and BTCPay all expose descriptors or
receive addresses to external systems. Sharing one descriptor across those
products creates privacy, ownership, cursor, and recovery ambiguity. Reserved
purpose wallets give each product a deterministic receive wallet while
preserving one-seed recovery.

## Consequences

- Product wallet identity is not a label convention. Durable origin metadata
  is recorded as a derivation-proven keychain-manifest entry.
- Product classification binds the network at materialization; the reserved
  BIP85 path itself carries no network family.
- Manual BIP85 next-index allocation skips reserved indexes through the
  registry's exclusion set.
- Product wallet creation materializes the local BDK/LWK wallet(s) first, then
  records the keychain-manifest entry; remote backup publication is
  best-effort and non-blocking.

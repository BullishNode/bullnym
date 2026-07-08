# 002 Deterministic Wallet Purposes

Status: Accepted

## Decision

Bull-created non-default receive wallets are deterministic BIP85 child wallets.
Reserved product identities are defined by BIP85 index plus network family:

| Identity | Product |
| --- | --- |
| `75 + liquid` | Lightning Address |
| `102 + liquid` | Payment Page |
| `103 + liquid` | POS |
| `77 + liquid` | BTCPay |
| `77 + bitcoin` | BTCPay |

Currently not reserved:

- `75 + bitcoin`
- `102 + bitcoin`
- `103 + bitcoin`

Manual BIP85 wallet creation must block indexes `75`, `77`, `102`, and `103`
so users cannot accidentally occupy current or likely future product wallet
space.

The same BIP85 index may exist for Bitcoin and Liquid as separate wallet
identities. BTCPay intentionally uses index `77` on both networks.

## Rationale

Lightning Address, Payment Page, POS, and BTCPay all expose descriptors or
receive addresses to external systems. Sharing one descriptor across those
products creates privacy, ownership, cursor, and recovery ambiguity. Reserved
purpose wallets give each product a deterministic receive wallet while
preserving one-seed recovery.

## Consequences

- Product wallet identity is not a label convention. Durable origin metadata is
  required.
- Product classification is network-aware.
- Manual BIP85 auto-allocation starts at index `0` and skips reserved indexes.
- The "Both" manual creation mode creates BTC and LBTC wallets at the same
  index and skips an index if either side is already used or reserved.
- Product wallet creation must create the local BDK/LWK wallet first, then
  record origin metadata and publish the manifest best-effort.

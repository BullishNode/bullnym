# Bullnym Decision Repository

This directory records product and architecture decisions that span Bullnym,
Bull Bitcoin Mobile, Get Paid, and the deterministic wallet work. It is not a
development log. Each record states the current contract, why it exists, and
what future work must preserve.

Sources used for this repository:

- current Bullnym documentation and server implementation;
- Bull Bitcoin Mobile architecture notes for `bullnym`, `get_paid`,
  `payment_page`, `invoices`, `wallet_manifest`, `external_receive_wallets`,
  and `nostr_identity`;
- local session memory from the Bullnym and Bull Bitcoin Mobile work;
- `bullnym-wallet-architecture-slides.html`, the deterministic multi-wallet
  architecture presentation.

## Records

- [001 Product and Feature Boundaries](001-product-and-feature-boundaries.md)
- [002 Deterministic Wallet Purposes](002-deterministic-wallet-purposes.md)
- [003 Wallet Manifest and Recovery](003-wallet-manifest-and-recovery.md)
- [004 Nostr Identity Role Separation](004-nostr-identity-role-separation.md)
- [005 Bullnym Mobile Protocol Contract](005-bullnym-mobile-protocol-contract.md)
- [006 Payment Rails and Settlement](006-payment-rails-and-settlement.md)
- [007 Public Checkout Allocation and Rate Limits](007-donation-page-allocation-and-rate-limits.md)
- [008 BTCPay and SamRock Pairing](008-btcpay-and-samrock-pairing.md)

## Status Terms

- `Accepted`: current contract.
- `Superseded`: older decision intentionally replaced by a later contract.
- `Deferred`: agreed direction, but not required by the current server/mobile
  compatibility contract.

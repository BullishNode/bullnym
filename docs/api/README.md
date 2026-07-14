# Bullnym API Reference

**Audience:** wallet, merchant, payer-interface, and operations integrators.

This directory is the maintained external API contract. It describes the
choices exposed by Bullnym and their consequences. The Rust route table, serde
types, and contract tests remain the implementation authority:
`src/main.rs`, `src/auth.rs`, `src/registration.rs`, `src/lnurl.rs`,
`src/donation_page.rs`, and `src/invoice.rs`.

## Contents

- [Conventions, availability, and errors](conventions-and-errors.md)
- [Authentication and byte-exact signing](authentication.md)
- [Discovery, pricing, and nym lifecycle](nyms-and-discovery.md)
- [Payment Page and POS APIs](payment-pages-and-pos.md)
- [Invoices and payment state](invoices-and-payment-state.md)
- [Chain-swap recovery](chain-swap-recovery.md)
- [Utility and operations APIs](operations.md)
- [Integration choices and production checklist](integration-guide.md)

Do not duplicate field tables or signing order in product and architecture
pages. Those pages link here when an integration needs wire-level detail.

## Scope and Concepts

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

| Concept | Meaning | Important implication |
|---|---|---|
| `npub` | 64-character hex x-only secp256k1 authentication public key. Despite the field name, this is not a bech32 `npub1...`. | Possession of its private key controls registration, surfaces, and wallet invoices. Use a dedicated deterministically recoverable key. |
| `verification_npub` | Optional, separate canonical lowercase 64-character hex key published through NIP-05. | Keeping it separate prevents the server authentication identity from becoming a public social identity. |
| nym | A 1-32 character permanent public namespace and Lightning Address local part. | One per npub; offline status never releases or changes ownership. |
| alias | Optional 1-32 character permanent web name in the same namespace as nyms. | One per npub, shared by Page/POS; never cleared, renamed, or released. |
| CT descriptor | Liquid confidential descriptor from which the server derives fresh addresses. | The server can derive and unblind payments in that descriptor. Use a dedicated Bullnym wallet, not a general-purpose wallet. |
| Payment Page | Public `/<nym>` or `/a/<alias>` checkout surface. | Can use a dedicated descriptor; legacy rows may fall back to the Lightning Address descriptor. |
| POS | Public `/<nym>/pos` or `/a/<alias>` terminal. | Requires its own descriptor and never falls back to the Lightning Address descriptor. |
| wallet invoice | Signed recipient-created receivable. | Recipient supplies unique BTC/Liquid addresses; the server does not derive them from a descriptor. |
| checkout invoice | Anonymous payer-created session from Payment Page/POS. | Destination and enabled rails are controlled by the configured surface. |

All examples use `https://pay.example.com` as the base URL. Production clients
should discover or configure the operator's HTTPS origin and must not assume a
particular Bullnym deployment.

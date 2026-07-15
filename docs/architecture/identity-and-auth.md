# Authentication and Identity

Bullnym separates account ownership, public aliases, public verification keys,
and receive descriptors.

## Identities

| Term | Meaning |
|---|---|
| `npub` | Server-auth owner key. It signs Bullnym actions and owns nyms, public payment surfaces, and wallet-origin invoices. |
| `verification_npub` | Optional public NIP-05 key returned from `/.well-known/nostr.json` only when supplied at registration and NIP-05 is enabled. Omission publishes no NIP-05 record. |
| `nym` | Public payment namespace. It backs `nym@domain`, `/<nym>`, and linked invoice URLs. |
| CT descriptor | Liquid confidential descriptor used to derive fresh receive addresses. It is receive capability, not account identity. |

## Signing Format

Current signed actions use the domain-separated Bullnym message format:

```text
bullpay-la-v2\0<action>\0<npub_hex>\0<nym_or_empty>\0(<field>\0)*<timestamp>
```

The server verifies BIP-340 Schnorr signatures over `SHA-256(message)` and
rejects timestamps outside the configured window. The action and nym are part
of the signed payload so signatures cannot be replayed across product actions
or linked/unlinked invoice scopes.

## Signed Actions

| Action | Owner | Fields |
|---|---|---|
| `register` | `npub` | `nym`, Lightning Address `ct_descriptor`, optional `verification_npub`. |
| `update` | `npub` | Replacement Lightning Address `ct_descriptor`. |
| `delete` | `npub` | Take the current Lightning Address offline without changing nym ownership. |
| `donation-page-save` | `npub` | Surface fields, display currency, links, optional `pos_mode`, optional `ct_descriptor`, optional `kind`. |
| `donation-page-archive` | `npub` | Archive a surface. Optional `kind` defaults to `payment_page`. |
| `invoice-create` | `npub` | Amount, accepted rails, recipient-supplied addresses, metadata, expiry. |
| `invoice-cancel` | `npub` | Invoice id. |
| `invoice-list` | `npub` | List filters and pagination. |

## Descriptor Ownership

`users.ct_descriptor` is the Lightning Address descriptor. It is used for
LNURL Lightning claims and LUD-22 Liquid address allocation.

`donation_pages.ct_descriptor` is scoped by `(nym, kind)`. Payment Page
checkout uses `kind = 'payment_page'` with legacy fallback to
`users.ct_descriptor`. POS checkout uses `kind = 'pos'` and requires its own
descriptor. Each row has its own `donation_pages.next_addr_idx` cursor.

Wallet-origin invoices do not require server-stored descriptors. The mobile
client supplies concrete Bitcoin and/or Liquid settlement addresses at invoice
creation time.

## Permanent nym ownership

Each owner key may permanently claim one nym, which cannot be cleared, renamed,
released, reassigned, or claimed by another `npub`. Lightning Address online/
offline availability is a separate property and never changes that ownership.
The server also blocks names that would shadow explicit routes such as
`/health`, `/api`, or `/register`.

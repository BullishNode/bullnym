# Authentication and Identity

Bullnym separates account ownership, public aliases, public verification keys,
and receive descriptors.

## Identities

| Term | Meaning |
|---|---|
| `npub` | Server-auth owner key. It signs Bullnym actions and owns nyms, donation pages, and wallet-origin invoices. |
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
| `delete` | `npub` | Deactivate the current nym. |
| `donation-page-save` | `npub` | Page fields, display currency, links, optional page `ct_descriptor`. |
| `donation-page-archive` | `npub` | Archive the page. |
| `donation-page-image` | `npub` | `nym`, image kind, normalized image hash. |
| `invoice-create` | `npub` | Amount, accepted rails, recipient-supplied addresses, metadata, expiry. |
| `invoice-cancel` | `npub` | Invoice id. |
| `invoice-list` | `npub` | List filters and pagination. |

## Descriptor Ownership

`users.ct_descriptor` is the Lightning Address descriptor. It is used for
LNURL Lightning claims and LUD-22 Liquid address allocation.

`donation_pages.ct_descriptor` is the Get Paid page descriptor. Donation-page
checkout uses it when present, with legacy fallback to `users.ct_descriptor`.
It has a separate `donation_pages.next_addr_idx` cursor so page payments do not
consume Lightning Address receive path state.

Wallet-origin invoices do not require server-stored descriptors. The mobile
client supplies concrete Bitcoin and/or Liquid settlement addresses at invoice
creation time.

## Nym Reservation Rules

Deactivated nyms remain reserved to the original owner and cannot be claimed by
another `npub`. The server enforces a lifetime nym cap per owner key and blocks
reserved names that would shadow explicit routes such as `/health`, `/api`, or
`/register`.

# 004 Nostr Identity Role Separation

Status: Accepted

## Decision

Bull Bitcoin Mobile uses BIP85 Nostr application `9000`, not the older draft
application `86`.

Reserved Nostr role paths:

| Path suffix | Role |
| --- | --- |
| `9000'/1'/1'` | Wallet manifest publishing and recovery |
| `9000'/2'/1'` | Bullnym server authentication |
| `9000'/3'/1'` | NIP-05 / public nym verification |

The wallet manifest key, Bullnym auth key, and public verification key are
separate and must not be reused for each other.

Bullnym registration and authenticated updates are signed by the Bullnym auth
key. Registration stores the verification npub. NIP-05 resolves to the
verification npub. Profile publish/clear uses the verification key.

## Rationale

The same user seed can safely derive multiple Nostr keys, but those keys have
different privacy and authority properties. Reusing one key for private wallet
manifest storage, server authentication, and public NIP-05 identity would tie
unrelated activities together and make rotation harder.

## Consequences

- Mobile call sites must use role-named helpers, not raw identity/account
  integers.
- `core/nostr` remains generic; product role semantics live in
  `features/nostr_identity`.
- User-created/manual Nostr identities cannot use Bull-reserved role pairs.
- Bullnym's `verification_npub` support is part of the mobile compatibility
  contract.

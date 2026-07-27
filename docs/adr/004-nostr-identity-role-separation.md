# 004 Nostr Identity Role Separation

- Status: Accepted
- Scope: Cross-repository identity contract

## Decision

Bull Bitcoin Mobile follows the current BIP85 Nostr proposal at
`m/83696968'/128002'/{identity}'/{account_index}'`. Identity `0'` and account
`0'` are reserved by the proposal and are never used for signing keys.

Reserved Nostr role paths:

| Path suffix | Role |
| --- | --- |
| `128002'/100'/1'` | Unified wallet-backup publishing and recovery |
| `128002'/101'/1'` | Bullnym server authentication |
| `128002'/102'/1'` | NIP-05 / public nym verification |

Bull Bitcoin reserves identities `100'` through `199'` for application roles.
User-created identities start at identity `1'`, account `1'`, advance
monotonically by identity, and skip that application range.

The unified wallet-backup key, Bullnym auth key, and public verification key
are separate and must not be reused for each other. Pre-release application
numbers `86'` and `9000'` are unsupported.

Bullnym registration and authenticated updates are signed by the Bullnym auth
key. Registration stores the verification npub. NIP-05 resolves to the
verification npub. Profile publish/clear uses the verification key.

## Rationale

The same user seed can safely derive multiple Nostr keys, but those keys have
different privacy and authority properties. Reusing one key for private wallet
backup storage, server authentication, and public NIP-05 identity would tie
unrelated activities together and make rotation harder. Keeping user identities
outside the application range prevents automatic user allocation from
colliding with product roles.

## Consequences

- Mobile call sites must use role-named helpers, not raw identity/account
  integers.
- `core/nostr` remains generic; product role semantics live in
  `features/nostr_identity`.
- User-created/manual Nostr identities cannot use Bull-reserved identities.
- Bullnym's `verification_npub` support is part of the mobile compatibility
  contract.

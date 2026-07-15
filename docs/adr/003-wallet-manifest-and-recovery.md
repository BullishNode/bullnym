# 003 Wallet Manifest and Recovery

- Status: Accepted
- Superseded guidance: client-triggered recovery actions
- Scope: `bullbitcoin-mobile`

The earlier client-triggered Get Paid recovery guidance in this record is
superseded. Current chain-swap recovery is server-executed automatically
against the merchant's immutable pre-registered Bitcoin address. Clients may
register and read that policy and supervise signed lifecycle status, but cannot
choose a late destination or trigger a recovery broadcast. See
[Chain-Swap Recovery](../api/chain-swap-recovery.md).

## Decision

Wallet Manifest is a neutral mobile feature at `features/wallet_manifest`, not
a Get Paid sub-feature and not generic `core`. It stores and restores the
inventory of Bull-created, non-default, local-key BIP85 wallets.

The manifest is BIP139-shaped and extended for Liquid. Restore identity is:

```text
root_fingerprint + bip85_derivation_path + network
```

The restore source of truth is the BIP85 derivation path and network, not a
descriptor. Descriptor fields may appear as optional metadata, but a missing or
mismatched descriptor must not block restore.

Automatic seed restore fetches the encrypted manifest and recreates
manifest-listed wallets only. It does not scan reserved Get Paid paths
opportunistically. If the manifest is missing, empty, invalid, or unavailable,
automatic restore creates no Get Paid fallback wallets.

## Rationale

One Bull seed can produce multiple purpose wallets, but recovery cannot rely on
guessing all possible child wallet indexes or querying one Bullnym server. A
manifest gives an explicit wallet inventory without turning product servers into
backup authorities.

## Consequences

- Wallet Manifest owns model/codec, origin storage, encrypted Nostr
  publish/fetch, and generic restore primitives.
- It excludes default wallets, watch-only wallets, arbitrary imported
  mnemonics, imported descriptors, and imported xpubs.
- Duplicate manifest entries for the same identity collapse to one wallet;
  latest metadata wins.
- Restore creates listed wallets even without detected activity.
- Manifest publish is full-snapshot replacement, best-effort, and non-blocking.
- A partial restore must not publish a replacement snapshot that erases fetched
  entries that were not restored.
- Manifest restore does not create a client-side chain-swap execution action.
  Bullnym's signed recovery lifecycle is read-only to clients and its automatic
  executor remains responsible for existing funded obligations.

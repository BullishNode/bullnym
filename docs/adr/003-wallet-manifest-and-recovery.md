# 003 Wallet Manifest and Recovery

- Status: Accepted
- Amended: 2026-07-28 — re-specified to the shipping keychain-manifest stack (#274)
- Superseded guidance: client-triggered recovery actions; the pre-release
  `features/wallet_manifest` feature and its "BIP139-shaped" file format
- Scope: `bullbitcoin-mobile`

The earlier client-triggered Get Paid recovery guidance in this record is
superseded. Current chain-swap recovery is server-executed automatically
against the merchant's immutable pre-registered Bitcoin address. Clients may
register and read that policy and supervise signed lifecycle status, but cannot
choose a late destination or trigger a recovery broadcast. See
[Chain-Swap Recovery](../api/chain-swap-recovery.md).

## Decision

The wallet-inventory manifest ships as three neutral mobile features, none of
which is a Get Paid sub-feature or generic `core`:

- `features/keychain_manifest` owns durable local metadata for app-created
  BIP85 materializations — reserved wallet seeds and Nostr keys — plus the
  canonical `bullbitcoin.keychain_manifest.v1` file payload and import-plan
  validation. It never stores mnemonic words, seeds, private keys,
  descriptors, or Nostr secret keys.
- `features/keychain_recovery` owns local restore of supported wallet and
  verified Nostr-key materializations from validated import plans.
- `features/wallet_backup` owns the encrypted envelope
  (`bullbitcoin.wallet_backup.v1`), the BIP85 encryption key at `1642'/0'/1'`,
  the seed-derived request signer at `128002'/100'/1'`, and remote
  publish/fetch of one opaque object against Bullnym's HTTP wallet-backup API
  (`bullbitcoin-wallet-backup-v1` signing domain, single `wallet_backup`
  stream). The client never constructs or publishes Nostr events for backup;
  the Nostr-role key only signs HTTP requests.
  `features/remote_keychain_recovery` orchestrates fetch, reparse, restore,
  and product healing.

The manifest file is deterministic, whitespace-free canonical JSON. Entry
identity is:

```text
parent_fingerprint + registry-relative_bip85_path
```

Wallet materializations attach the wallet id (a descriptor-origin string),
child seed fingerprint, network, and script type to an entry; Nostr-key
materializations attach the x-only public key, key kind, and purpose. The
network is materialization metadata, not entry identity, so one entry carries
a product's wallets on every network it needs.

Restore treats file-claimed values as unverified input: the child seed
fingerprint, wallet id, and Nostr public key must be re-derived locally and
refused on mismatch. Automatic seed restore fetches the encrypted backup and
recreates manifest-listed materializations only. It does not scan reserved
product paths opportunistically. If the manifest is missing, empty, invalid,
or unavailable, automatic restore creates no Get Paid fallback wallets.

## Rationale

One Bull seed can produce multiple purpose wallets and role keys, but recovery
cannot rely on guessing all possible child paths or querying one Bullnym
server. A manifest gives an explicit inventory without turning product servers
into backup authorities, and the opaque encrypted transport keeps Bullnym
unable to read it.

## Consequences

- `keychain_manifest` owns model/codec, local origin storage, and generic
  import-plan validation; `wallet_backup` owns encryption and the remote
  lifecycle; `keychain_recovery` owns restore semantics.
- The inventory excludes default wallets, watch-only wallets, arbitrary
  imported mnemonics, imported descriptors, and imported xpubs.
- V1 decode rejects duplicate entry ids and duplicate materialization
  identities instead of collapsing them.
- Restore creates listed wallets even without detected activity. V1 restore
  currently covers BTCPay and Lightning Address wallet materializations plus
  verified Nostr keys; other reserved seeds become recoverable only when
  their owning product adds support.
- Publication is a full-snapshot, best-effort, non-blocking upload triggered
  by local record commits. Recovery-originated records emit no publication
  signal, so a remote read cannot turn into a remote write.
- Local and authenticated remote payloads are validated and merged through
  the `keychain_manifest` boundary before publication, so a partial restore
  does not publish a replacement snapshot that erases fetched entries that
  were not restored.
- Manifest restore does not create a client-side chain-swap execution action.
  Bullnym's signed recovery lifecycle is read-only to clients and its automatic
  executor remains responsible for existing funded obligations.

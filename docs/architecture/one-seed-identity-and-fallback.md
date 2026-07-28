# One Seed: Identity, Product Wallets, and the Fallback Destination

This document is the unifying picture for facts that are individually
normative elsewhere: BIP85 product wallet purposes
([ADR 002](../adr/002-deterministic-wallet-purposes.md)), Nostr identity role
separation ([ADR 004](../adr/004-nostr-identity-role-separation.md)), wallet
manifest recovery ([ADR 003](../adr/003-wallet-manifest-and-recovery.md)), and
the chain-swap recovery contract
([chain-swap-recovery.md](../api/chain-swap-recovery.md)). Where this document
and those disagree, those win.

## The derivation tree

Every key material a Get Paid merchant uses — spending, identity, backup, and
the failure-path destination — derives from one master seed:

```text
master seed (the default wallet)
│
├── default Bitcoin wallet (mainnet)
│     └── recovery / fallback address ── one fresh receive address,
│                                        committed to Bullnym before
│                                        the first chain swap exists
│
├── BIP85 child wallet seeds (ADR 002; each child is its own seed
│   with its own master fingerprint)
│     ├── 75'  + liquid   → Lightning Address wallet (CT descriptor)
│     ├── 102' + liquid   → Payment Page wallet      (CT descriptor)
│     ├── 103' + liquid   → POS wallet               (CT descriptor)
│     └── 77'  + liquid & bitcoin → BTCPay wallets
│
└── BIP85 Nostr keys, m/83696968'/128002'/{identity}'/{account}' (ADR 004)
      ├── 100'/1' → unified wallet-backup key   (wallet_backup stream)
      ├── 101'/1' → Bullnym server auth key     (this key's npub is the
      │                                          identity Bullnym sees)
      └── 102'/1' → NIP-05 public verification key
```

Consequences:

- **One backup recovers everything.** Restoring the master seed re-derives the
  spending wallets, every product wallet, the Nostr role keys — and therefore
  the npub — and the wallet that owns the committed recovery address. Nothing
  the server stores is required to reconstruct ownership; server state is
  re-adopted, not trusted (see the readback rules below).
- **Derivation is one-way.** A BIP85 child seed (for example the POS wallet's)
  yields that wallet and nothing above it: not the master, not the npub, not
  the recovery wallet. Compartments below the root are real.
- **The role keys are deliberately distinct.** Backup, server auth, and public
  verification never share a key, so private backup activity, authenticated
  API traffic, and public identity cannot be linked through key reuse
  (ADR 004).

## Happy path versus failure path

The product CT descriptors are **happy-path** settlement destinations:
Lightning Address, Payment Page, and POS invoices settle into their product
wallets.

The **failure path** has exactly one destination, shared by all products: a
single plain Bitcoin mainnet address from the merchant's default Bitcoin
wallet, registered ahead of time. When a funded BTC-to-LBTC chain swap cannot
complete, the payer's coins sit in the lockup until Bullnym's automatic
executor recovers them to that pre-committed address. Nothing is derived per
product or per descriptor for recovery.

## Registration: what, when, how

**What.** One canonical Bitcoin mainnet address — not a BIP21 URI, not a
descriptor, not per-product.

**When.** Proactively, before any payment can get stuck. The mobile client
runs an ensure flow when the Get Paid hub loads and a wallet-owned nym exists;
the server will not create a chain swap for a merchant without a registered
recovery policy. By the time payer money exists, its exit route is already
fixed — the *bound before payer exposure* property.

**How (client ceremony).** The mobile client treats this write as
irreversible and is deliberately paranoid about it:

1. **Read first** — an authenticated lookup (`recovery-address-get`); an
   existing commitment is adopted, never overwritten.
2. **Prove ownership** — the fresh candidate address is verified to belong to
   the default wallet before anything else happens.
3. **Label locally** — a pending system label is recorded so a crash or an
   ambiguous network failure retries the *same* address instead of minting a
   second one.
4. **Register** — signed `PUT /api/v1/recovery-address`
   (`recovery-address-set`, identity-wide empty-nym domain).
5. **Read back** — the write counts as done only after an authenticated
   readback returns the exact same address. A mismatch is an integrity
   failure for supervision, never silently patched.

## Cardinality and rotation

| Thing | Cardinality |
| --- | --- |
| Recovery address policy | one **current** commitment per npub, versioned append-only |
| Destination of a given stuck swap | frozen per swap at swap creation |
| Product wallets / CT descriptors | many per npub; happy path only, uninvolved in recovery |

The server permits rotation: a new valid signed write appends a new commitment
version that governs *future* swaps only. Rotation never rewrites a swap
already bound to an earlier commitment. The mobile client, by its own
invariant, never rotates — not even when the default wallet changes — so in
practice an app user's identity carries one address, written once. On seed
restore the client verifies the committed address belongs to the re-derived
default wallet and recreates its local label; it must not register a
replacement merely because local state was lost.

## Threat model, in one paragraph

The immutable commitment defends against **session-level** compromise: a
stolen auth token, a hijacked phone session, or a malicious later request
cannot redirect stuck funds, because the destination predates the money and
existing swaps never rebind. It deliberately does not defend against
**master-seed** compromise — an attacker with the seed already owns the
destination wallet (and the npub, and every product wallet), so there is
nothing left to redirect. Seed custody is the root assumption of the entire
model, which is why client-side backup health is a first-class concern rather
than an accessory feature.

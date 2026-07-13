# Chain-swap recovery manifest v1

Issue #87 needs evidence outside the operational database so a complete stale
database restore cannot make an already exposed swap disappear. This document
freezes the first format package. It does not yet choose an object store, wire
the export into swap creation, or reconstruct database rows.

## Encoding and cryptography

The encoded object is compact JSON whose object keys are recursively sorted.
Readers reject whitespace, alternate key order, duplicate/unknown fields, and
unsupported versions instead of normalizing them.

The manifest payload is signed first:

1. Canonically encode the version-1 payload.
2. Calculate `SHA256(payload)` for the signed packet's diagnostic digest.
3. Calculate the BIP340 message digest as
   `SHA256("bullnym-chain-swap-manifest\0v1\0payload" ||
   be64(payload_length) || payload)`.
4. Sign that digest with the configured secp256k1 manifest-signing key. The
   XChaCha nonce, domain-separated and hashed to 32 bytes, supplies BIP340
   auxiliary randomness. A fixed injected nonce is used only for deterministic
   protocol fixtures.
5. Canonically encode `{manifest, manifest_sha256, signature_hex}`.

That signed packet is encrypted with XChaCha20-Poly1305 and a fresh random
192-bit nonce. The canonical envelope header is the AEAD associated data and
contains:

- format and version;
- encryption and signature algorithm identifiers;
- a non-secret encryption-key identifier;
- the x-only signing public key;
- the nonce.

The outer envelope adds only lowercase-hex ciphertext. Restore code must supply
the expected encryption-key identifier and expected signing public key; it must
not accept the signer embedded in an untrusted object as its trust root.
Possession of the storage-encryption key therefore does not by itself permit a
valid manifest forgery.

## Signed payload

Version 1 contains closed typed fields, with no extension map:

- restore identity: manifest UUID, chain-swap UUID, Boltz swap ID, and creation
  time;
- derivation lineage: root fingerprint, key epoch, scheme version, and the
  allocation UUID/index/purpose/public key for both claim and refund keys;
- the claim preimage **hash**, never the preimage;
- immutable creation evidence: lockup address, locally constructed BIP21,
  payer and merchant amounts, canonical provider response, pinned canonical
  pair quote, response and four script hashes, both timeout heights, networks,
  Liquid asset, and immutable merchant destinations;
- merchant policy references: invoice UUID, merchant nym, exact Liquid
  destination, and the optional append-only emergency-Bitcoin commitment UUID
  plus exact address.

Readers cross-check the provider ID, lockup address, both amounts, pair hash,
BIP21 address/amount, response digest, and duplicated policy destinations.
Claim/refund allocation identities must be distinct and valid compressed
secp256k1 public keys.

The payload has no preimage, claim private key, refund private key, seed,
descriptor, xprv, or arbitrary caller-defined field. The canonical provider
response is the already validated non-secret response stored by issue #80.

## Bounds and failure behavior

- Encoded envelope: at most 1 MiB, checked before JSON parsing.
- Ciphertext: 16 bytes through 512 KiB, checked in hex form before decoding.
- Canonical provider response: at most 256 KiB.
- Canonical pair quote: at most 64 KiB.

Wrong keys, ciphertext/nonce/header tampering, and ciphertext truncation fail
AEAD authentication. A caller with the encryption key but not the signing key
can create valid ciphertext but cannot create a valid signed payload. Restore
must halt on any such failure; it must never silently advance a derivation
sequence or treat a malformed record as an absent obligation.

## Integration boundary left to the next package

Before a payer instruction is exposed, creation must durably write this exact
record to configured off-host storage and record delivery evidence. Later
restore work must reconcile database, manifest, chain, and validated Boltz xpub
restore evidence. This format package alone does not claim either guarantee.

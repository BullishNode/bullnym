# LUD-22 Liquid Payment Negotiation

This document specifies the LUD-22 extension implemented by Bullnym. It extends
LUD-06 without changing the default Lightning flow. The server implementation
is in `src/lnurl.rs`; proof verification is in `src/utxo.rs`.

## Metadata Advertisement

The normal LUD-06 metadata response adds `payment_methods`:

```json
{
  "tag": "payRequest",
  "callback": "https://pay.example.com/lnurlp/callback/alice",
  "minSendable": 100000,
  "maxSendable": 25000000000,
  "metadata": "[[\"text/identifier\",\"alice@pay.example.com\"],[\"text/plain\",\"Sats for alice\"]]",
  "commentAllowed": 144,
  "payment_methods": ["L-BTC"]
}
```

`payment_methods` advertises alternate methods only. Lightning remains the
implicit default and is used when the payer omits `payment_method`.

## Callback Request

The callback remains an HTTP GET. All requests include:

| Query field | Format | Meaning |
|---|---|---|
| `amount` | unsigned decimal integer | Millisatoshis; must be within the advertised limits and divisible by 1,000. |
| `comment` | optional UTF-8 string | LUD-06 comment. The server rejects more than `commentAllowed` Unicode characters. |
| `payment_method` | optional comma-separated string | Include `L-BTC` to request direct Liquid. Omit it for Lightning. |

A public client requesting `L-BTC` also supplies every Approach B proof field:

| Query field | Format | Meaning |
|---|---|---|
| `outpoint` | `<64-hex-txid>:<u32-vout>` | Confirmed or mempool Liquid output being proved. |
| `pubkey` | compressed secp256k1 public key hex | Key whose P2WPKH script must exactly match the proved output. |
| `sig` | hex DER ECDSA signature | Ownership signature defined below. |
| `value` | unsigned decimal integer | Clear L-BTC output value in sats. |
| `value_bf` | 32-byte display-order hex | Elements value blinding factor. |
| `asset_bf` | 32-byte display-order hex | Elements asset blinding factor. |

`value_bf` and `asset_bf` use Elements display order, exactly as
`TxOutSecrets::to_string()` emits them. They are not raw internal byte-order
hex. Legacy `blinding_key` and `asset` query fields are accepted but ignored;
they do not replace any required Approach B field.

Configured IP-whitelisted callers bypass proof and rate-limit gates. Public
wallet integrations must never rely on that operator-only exception.

## Ownership Signature

The proof uses ECDSA, not the BIP-340 authentication scheme used by Bullnym's
management APIs.

Build the 32-byte digest with no separators:

```text
SHA256(UTF8(message_tag) || UTF8(nym) || UTF8(outpoint))
```

`message_tag` is operator-configured as `proof.message_tag` and defaults to
`bullpay-lnurlp-v1`. Sign the digest with the private key corresponding to
`pubkey`, DER-encode the ECDSA signature, then hex-encode those DER bytes into
`sig`.

The proved output script must be native P2WPKH for that compressed public key.
Other scripts do not qualify even if the payer can otherwise prove ownership.

## Commitment Verification

Bullnym fetches the raw Liquid transaction and verifies that the outpoint is
currently unspent. It does not unblind through ECDH and does not receive a
blinding private key. Instead, it cryptographically rebinds the payer-supplied
secrets to the on-chain commitments:

1. Reconstruct the confidential asset generator from the Liquid Bitcoin asset
   ID and `asset_bf`; require equality with the output asset commitment.
2. Reconstruct the confidential value commitment from `value`, `value_bf`, the
   Liquid Bitcoin asset ID, and `asset_bf`; require equality with the output
   value commitment.
3. Require `value >= proof.min_proof_value_sat` (default 1,000 sats).

Explicit-value or explicit-asset outputs fail because they cannot equal the
required confidential commitments. A false value, wrong asset, or wrong
blinding factor also fails to bind.

## Responses

Successful Liquid negotiation returns:

```json
{
  "L-BTC": {
    "address": "lq1..."
  }
}
```

The requested `amount` is not repeated in the response. The payer uses the
original callback amount and returned confidential address.

The default or fallback Lightning response is the standard Bullnym LUD-06
shape:

```json
{
  "pr": "lnbc...",
  "routes": [],
  "disposable": false,
  "successAction": {
    "tag": "message",
    "message": "Payment received to alice@pay.example.com"
  }
}
```

Invalid/missing proof data produces Bullnym's coded LNURL error envelope. A
Liquid-specific rate-limit or backend-throttle class can instead fall back
transparently to Lightning. Callers must discriminate by response shape rather
than assume an `L-BTC` request always returns Liquid.

## Allocation and Retry Semantics

The server caches `(nym, outpoint) -> address_index`. A new unpaid reservation
uses the nym's current `next_addr_idx` without incrementing it, so different
unpaid reservations can return the same address. Repeating the same proof for
the same nym reuses its cached index. The chain watcher advances the cursor only
after it observes a confirmed payment to the reserved index. Mempool-only
history is not durable cursor evidence because it may be evicted. The returned
address is not an exclusive per-request allocation.

The same outpoint is subject to configured distinct-nym fan-out, per-source,
and pending-reservation limits. Periodic GC deletes unfulfilled reservation
rows after their TTL, releasing pending-state capacity without rewinding the
descriptor cursor. A later request for a deleted mapping uses the then-current
index.

The cache stores an index, not a concrete address. If the recipient replaces
the nym descriptor, the cached index is derived from the new descriptor and a
repeat request can return a different address. Wallets should finish in-flight
payments before descriptor rotation and retain scanning access to addresses
already returned under the old descriptor.

## Privacy and Security Implications

The proof reveals to Bullnym that one public key controls one Liquid outpoint
and is requesting a payment address for a particular nym. `value`, `value_bf`,
and `asset_bf` also reveal that output's asset and amount to the server. Reusing
an outpoint across recipients makes those requests linkable.

The proof prevents cost-free descriptor-index enumeration; it is not payer
authentication for the eventual transfer and does not reserve the returned
address exclusively for a transaction.

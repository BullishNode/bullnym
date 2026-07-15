# Discovery and Pricing

## `GET /.well-known/lnurlp/:nym`

Returns LUD-06 metadata:

```json
{
  "tag": "payRequest",
  "callback": "https://pay.example.com/lnurlp/callback/alice/0000000000000000000000000000000000000000000000000000000000000000",
  "minSendable": 100000,
  "maxSendable": 25000000000,
  "metadata": "[[\"text/identifier\",\"alice@pay.example.com\"],[\"text/plain\",\"Sats for alice\"]]",
  "commentAllowed": 120,
  "payment_methods": ["L-BTC"]
}
```

Amounts are millisatoshis. The numbers above are the shipped defaults and may
be changed by the operator, so treat the returned limits as authoritative.
`payment_methods` lists alternate methods and therefore contains `L-BTC`, not
the implicit default Lightning method. Generic LNURL clients can ignore the
extension and use Lightning.

## `GET /lnurlp/callback/:nym/:comment_intent`

Use the complete opaque callback URL returned by metadata. The final path
component gives an exact retry the same private intent identity. The legacy
`/lnurlp/callback/:nym` route remains available for no-comment payments, but
fails closed if a `comment` is supplied.

Common query fields:

| Field | Required | Meaning |
|---|---|---|
| `amount` | yes | Requested millisatoshis, within metadata limits and divisible by 1,000 (whole sats). |
| `comment` | no | Private LNURL comment. The server preserves at most 120 user-visible Unicode characters and 512 UTF-8 bytes exactly. |
| `payment_method` | no | Omit for Lightning; `L-BTC` requests direct Liquid through LUD-22. |

The default response is:

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

This creates a Boltz reverse swap. The recipient settles to a freshly derived
Liquid address. It works with standard LNURL wallets but incurs swap/network
fees and trusts Bullnym to supply the correct destination.

LUD-22 also requires `outpoint`, `pubkey`, `sig`, `value`, `value_bf`, and
`asset_bf`. These prove ownership and rebind the supplied clear value and
blinding factors to a confidential, unspent L-BTC output meeting the configured
minimum (default 1,000 sats). The exact proof
format is specified in [LUD-22 Currency Negotiation](../protocols/lud-22.md).
Successful LUD-22 returns a direct Liquid address instead of a BOLT11:

```json
{ "L-BTC": { "address": "lq1..." } }
```

Choose LUD-22 when the payer can send Liquid: it avoids two swaps and their
fees. The proof reveals one payer UTXO and blinding material to Bullnym, so it
has a larger privacy surface. Mapping `(nym, outpoint)` is idempotent; a UTXO
can target only a bounded number of distinct nyms. On rate-limit/backend
throttle errors the implementation may fall back to Lightning, so clients must
inspect the response type rather than assume the requested rail was selected.
Comments are currently bound only on the Lightning path. A callback combining
`comment` with `payment_method=L-BTC` fails closed instead of dropping private
text during direct-Liquid creation or fallback.

## `GET /.well-known/nostr.json?name=:nym`

Returns `{ "names": { "alice": "<verification key hex>" } }`. It exists only
when NIP-05 is enabled and the nym opted in with a separate
`verification_npub`. Missing names do not fall back to the authentication key.

## Pricing

`GET /api/v1/supported-currencies` returns:

```json
{ "currencies": [{ "code": "USD", "precision": 2 }, { "code": "CRC", "precision": 0 }] }
```

`GET /api/v1/rate?currency=USD` returns:

```json
{
  "base_currency": "BTC",
  "currency": "USD",
  "minor_per_btc": 6500000,
  "precision": 2,
  "source": "bullbitcoin-pricer:indexPrice",
  "observed_at_unix": 1760000000,
  "fetched_at_unix": 1760000001,
  "expires_at_unix": 1760000300,
  "last_known_rate": false
}
```

`minor_per_btc` uses the currency's minor unit. Convert sats with
`sats * minor_per_btc / 100000000`. Currency input is normalized to an
uppercase code from the explicit supported-currency response. An optional
`base=BTC` is accepted; every other base is rejected. Upstream base, quote, and
price-currency fields must exactly match the requested `BTC` pair.

`observed_at_unix` is the upstream observation, `fetched_at_unix` is when
Bullnym completed the fetch, and `expires_at_unix` is the exclusive freshness
boundary capped from both timestamps. `last_known_rate: true` means a failed
refresh reused a cached but still-unexpired observation. Bullnym never emits
zero, malformed, mismatched,
future-dated, or expired rates: unsupported inputs return `InvalidAmount`, and
absence of a valid current observation returns HTTP 503 `ServiceUnavailable`.
The public endpoints have a dedicated per-source throttle, while a short cache
and per-currency request coalescing bound upstream work without consuming
payment, status, settlement, or recovery limits.

## Permanent nym ownership and Lightning Address availability

## `POST /register`

```json
{
  "nym": "alice",
  "ct_descriptor": "ct(...)#checksum",
  "verification_npub": "<optional canonical lowercase 64 hex>",
  "npub": "<64 hex auth key>",
  "timestamp": 1760000000,
  "signature": "<128 hex>"
}
```

Nyms allow lowercase ASCII letters, digits, and internal hyphens. Reserved
route/product names are rejected. A key may claim exactly one permanent nym.
This cap is a product and database invariant, not an operator-configurable
limit. The claim never becomes inactive and is never cleared, renamed,
released, or reassigned. `users.is_active` controls only whether the Lightning
Address is online. Registering the exact nym already owned by an offline wallet
brings that Lightning Address online; trying to register a different name is a
conflict.

Response (`201`):

```json
{
  "nym": "alice",
  "lightning_address": "alice@pay.example.com",
  "nip05": "alice@pay.example.com",
  "quota": { "used": 1, "cap": 1, "remaining": 0 }
}
```

`nip05` is null unless both client opt-in and server feature flag are present.
Sending a CT descriptor gives the server the ability to derive and unblind all
payments for this purpose wallet. It does not give the server spend keys.

## `PUT /register`

Body fields are `npub`, `nym`, `ct_descriptor`, `timestamp`, and `signature`.
It changes the descriptor used for future derivations, including unresolved
work that stores only an address index or has not allocated a destination yet:

- A repeated LUD-22 reservation lookup derives its cached index from the new
  descriptor, so it can return a different address after rotation.
- A Lightning Address reverse swap with no persisted claim address derives
  from the new descriptor when it is claimed.
- A swap whose concrete destination is already persisted keeps that address.

Treat rotation as a coordinated wallet migration. Keep scanning the old wallet
for addresses already handed to payers, ensure the new descriptor is controlled
and recoverable, and avoid rotating while payments are in flight.

Response: `{ "nym": "alice", "lightning_address": "alice@pay.example.com" }`.

## `DELETE /register`

```json
{
  "npub": "<64 hex>",
  "nym": "alice",
  "purge": false,
  "timestamp": 1760000000,
  "signature": "<128 hex>"
}
```

Omit/false `purge` to take the Lightning Address offline (`delete` action). It
stops new Lightning Address payment instructions but preserves history and
permanent name ownership; Page and POS availability remain independent.
`purge: true` uses the `purge` action and deletes swap/reservation state only
when no payment is in flight. Neither operation releases the nym, changes its
owner, or permits the wallet to claim another name.

Response: `{ "quota": { "used": 1, "cap": 1, "remaining": 0 } }`.

## `GET /register/lookup?npub=<64-hex>`

Public and rate-limited. A successful response is:

```json
{
  "nym": "alice",
  "lightning_address_online": false,
  "alias": "coffee",
  "public_name_policy": "permanent_names_v1",
  "quota": { "used": 1, "cap": 1, "remaining": 0 }
}
```

`nym` is always the canonical permanent nym. `lightning_address_online`
reports only Lightning Address availability; it does not describe nym or alias
ownership. `alias` is the canonical permanent owner alias, or `null` when none
has ever been claimed. Clients must require
`public_name_policy == "permanent_names_v1"` before enabling permanent-name or
alias UX. `quota` is the authoritative permanent-nym ownership quota. Because
lookup is public, an authentication key is linkable to its Bullnym names;
clients needing identity separation should use a dedicated auth key.

## `GET /api/reservations/:nym`

Query: `npub`, `timestamp`, and `signature`. Sign the `reservation-list`
action with the route nym in the nym slot and zero payload fields, as defined
in [Authentication](authentication.md). Returns
`{ "reservations": [{ "outpoint", "addr_index", "fulfilled" }],
"next_addr_idx": 42 }`. This is an owner diagnostics API, not a
payment-status API. It remains available to the authenticated permanent owner
while Lightning Address is offline. GC can delete an unfulfilled reservation after its TTL even
though expiry is not exposed in this view. Deletion releases pending-state
capacity; it does not rewind `next_addr_idx`. A later proof creates a new mapping
at whatever descriptor index is current then.

# Discovery and Pricing

## `GET /.well-known/lnurlp/:nym`

Returns LUD-06 metadata:

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

Amounts are millisatoshis. The numbers above are the shipped defaults and may
be changed by the operator, so treat the returned limits as authoritative.
`payment_methods` lists alternate methods and therefore contains `L-BTC`, not
the implicit default Lightning method. Generic LNURL clients can ignore the
extension and use Lightning.

## `GET /lnurlp/callback/:nym`

Common query fields:

| Field | Required | Meaning |
|---|---|---|
| `amount` | yes | Requested millisatoshis, within metadata limits and divisible by 1,000 (whole sats). |
| `comment` | no | LNURL comment. The server rejects more than `commentAllowed` Unicode characters. |
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
{ "minor_per_btc": 6500000, "last_known_rate": false }
```

`minor_per_btc` uses the currency's minor unit. Convert sats with
`sats * minor_per_btc / 100000000`. A value of `0` means no rate is available.
`last_known_rate: true` means the upstream is unavailable and the response is
stale. Display it cautiously. Invoice creation locks the selected rate, but it
may accept a last-known cached rate for up to 300 seconds after an upstream
failure; older stale rates cause `ServiceUnavailable`. Merchants therefore
retain bounded short-term exchange-rate exposure during a pricer outage.

## Nym lifecycle

## `POST /register`

```json
{
  "nym": "alice",
  "ct_descriptor": "ct(...)#checksum",
  "verification_npub": "<optional 64 hex>",
  "npub": "<64 hex auth key>",
  "timestamp": 1760000000,
  "signature": "<128 hex>"
}
```

Nyms allow lowercase ASCII letters, digits, and internal hyphens. Reserved
route/product names are rejected. A key may have only one active nym and a
configured lifetime quota (default deployment value: three). Deactivation does
not restore quota. Registering a formerly owned nym reactivates it.

Response (`201`):

```json
{
  "nym": "alice",
  "lightning_address": "alice@pay.example.com",
  "nip05": "alice@pay.example.com",
  "quota": { "used": 1, "cap": 3, "remaining": 2 }
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

Omit/false `purge` for normal soft deactivation (`delete` action). It stops new
payments but preserves history and allows reactivation. `purge: true` uses the
`purge` action and deletes swap/reservation state only when no payment is in
flight. Purge never makes the nym claimable by another identity and does not
restore lifetime quota.

Response: `{ "quota": { "used": 2, "cap": 3, "remaining": 1 } }`.

## `GET /register/lookup?npub=<64-hex>`

Public and rate-limited. A successful response is:

```json
{
  "nym": "alice",
  "active": false,
  "lightning_address_online": false,
  "alias": "coffee",
  "public_name_policy": "permanent_names_v1",
  "quota": { "used": 1, "cap": 1, "remaining": 0 },
  "previous_nyms": [
    { "nym": "alice", "created_at": "2026-07-09T12:00:00Z" }
  ],
  "lifetime_nyms_used": 1,
  "lifetime_nyms_cap": 1
}
```

`nym` is always the canonical permanent nym. `lightning_address_online`
reports only Lightning Address availability and exactly matches the legacy
`active` field. `alias` is the canonical permanent owner alias, or `null` when
none has ever been claimed. Clients must require
`public_name_policy == "permanent_names_v1"` before enabling permanent-name or
alias UX. While the Lightning Address is offline, `previous_nyms` retains the
canonical nym for older clients; it is empty while online. The two
`lifetime_*` fields are legacy; new clients use `quota`. Because lookup is
public, an authentication key is linkable to its Bullnym names; clients needing
identity separation should use a dedicated auth key.

## `GET /api/reservations/:nym`

Query: `npub`, `ts`, and legacy `sig`. Returns
`{ "reservations": [{ "outpoint", "addr_index", "fulfilled" }],
"next_addr_idx": 42 }`. This is an owner diagnostics API, not a
payment-status API. GC can delete an unfulfilled reservation after its TTL even
though expiry is not exposed in this view. Deletion releases pending-state
capacity; it does not rewind `next_addr_idx`. A later proof creates a new mapping
at whatever descriptor index is current then.

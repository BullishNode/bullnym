# RFC 004: Bull Bitcoin fiat settlement

- Status: Reviewed; implementation ready
- Owner: Bull Bitcoin / Bullnym
- Affected repositories: `bullnym`, the scoped-key compatibility change in
  `API-Orders`, a temporary `boltz-rust` fork, and `bullnym-tests`; later client
  wiring in `bullbitcoin-mobile`
- Prerequisites: the scoped Bull Bitcoin API-key stack and SatoshiPortal `boltz-rust` PR #162
- Written against: Bullnym `d9f6443`, `boltz-rust` PR #162 head `d3b8520`,
  BullishNode covenant commit `c20511854bbd996a74f914fa0327d4601b5d4f62`,
  and reviewed 0.3 backport `bbf3ee8048b638a80c23e1bcecff77ee3dc89ec3`
- Last updated: 2026-07-18

## 1. Objective

Let a merchant choose, independently for each Bullnym product, to receive a
payment as:

1. 100% Bitcoin through the existing Bullnym flow;
2. 100% fiat credited to the merchant's selected Bull Bitcoin balance; or
3. a percentage in Bitcoin and the remainder as fiat.

Bullnym calls only two scoped Bull Bitcoin API methods:

- `sellToBalance`, always with a Bitcoin amount; and
- `getSellToFiatBalanceOrder`, only for an exact order ID created by that same
  API key.

The feature must retain enough evidence to show the merchant how each payment
settled, but no Bull Bitcoin profile data. Bullnym must never request or store a
name, Bull Bitcoin user number, KYC data, recipients, withdrawal methods,
balance history, or general order history.

This is a settlement feature, not a second Bull Bitcoin account client inside
Bullnym.

## 2. Locked product decisions

These are implementation requirements, not open questions.

- Settings are per product: `lightning_address`, `payment_page`, `pos`, and
  `invoice`.
- A missing setting means 100% Bitcoin and preserves current behavior.
- Fiat percentage is an integer from 0 through 100. Zero is Bitcoin-only, 100
  is fiat-only, and 1 through 99 is mixed settlement.
- A fiat-enabled setting selects exactly one of `ARS`, `CAD`, `COP`, `CRC`,
  `EUR`, `MXN`, or `USD`.
- Bullnym sends `bitcoinAmount`, never `fiatAmount`, when it creates a Bull
  Bitcoin order.
- Fiat-only settlement uses the payer's selected source rail directly:
  Bitcoin/Payjoin, Lightning, or Liquid.
- Mixed settlement always converts the fiat share from an L-BTC output of the
  Bullnym Boltz claim. A Lightning payer uses a reverse swap and a Bitcoin
  payer uses a chain swap. Direct Liquid is not offered for mixed settlement.
- The merchant's Bitcoin output is the primary/remainder claim output. The Bull
  Bitcoin L-BTC output is one fixed additional output.
- Split percentages apply to the net amount available to settle after the
  exact current two-confidential-output claim fee. Payer quotes and the
  Bitcoin-only one-output path remain unchanged: Bullnym does not pre-create a
  Bull Bitcoin order merely to predict a future claim fee.
- Integer rounding favors the Bitcoin output:
  `fiat_sat = floor(net_settlement_sat * fiat_percent / 100)` and the primary
  Bitcoin output receives the remainder.
- If the intended Bull Bitcoin share is below Bull Bitcoin's minimum, or if
  either mixed output would be invalid/dust, the split is overridden and the
  full net amount goes to the merchant's Bitcoin destination.
- A Bull Bitcoin failure before a payment instruction or claim destination is
  committed also falls back to 100% Bitcoin. Once a Bull Bitcoin instruction
  has been exposed or its output has been committed, Bullnym never redirects
  that payment.
- Bull Bitcoin already owns underpayment and overpayment handling. Bullnym
  records the actual Bitcoin amount received and exact fiat amount credited
  when the scoped order response supplies them; it does not create a
  compensating order.
- Settings changes affect new payment intents only. An invoice, provider swap,
  or payer instruction keeps the settlement policy it captured when it was
  created.
- Removing the credential from Bullnym does not revoke it at Bull Bitcoin.
  Revocation remains an independent Bull Bitcoin account operation.
- The credential is never returned by a Bullnym read endpoint, rendered in a
  Bullnym page, included in a log/error, or exposed in merchant settlement
  details.
- First-party Bullnym and mobile code provides no copy, export, log, analytics,
  deep-link, or debug surface for the credential. A bearer credential cannot be
  made literally non-extractable on a user-controlled device; the security
  boundary is that supported software never exposes it and Bull Bitcoin limits
  what an extracted credential can do.
- A wallet-origin mixed invoice must contain a valid confidential Liquid
  destination even when the payer rail is Bitcoin. If it does not, that invoice
  is Bitcoin-only; Bullnym never invents or takes custody of a merchant
  destination.

## 3. Terms and currency disclosures

Bitcoin-only use has no Bull Bitcoin terms acceptance. Enabling any nonzero
fiat percentage requires an explicit, signed acceptance of one versioned terms
contract. The version binds both the disclosure copy below and a canonical Bull
Bitcoin terms URL/identifier maintained in server configuration. Bullnym
exposes them from a public, static endpoint so mobile does not invent or
silently drift the wording.

The common disclosure states that:

- fiat conversion is subject to Bull Bitcoin's terms and conditions;
- withdrawals can be made only to an account in the merchant's own name;
- the merchant is bound to the withdrawal methods for the selected currency;
  and
- if the full or partial conversion is below Bull Bitcoin's minimum, Bullnym
  overrides the conversion and sends the whole settlement to the Bitcoin
  wallet.

Currency copy:

| Currency | Disclosure |
|---|---|
| CAD | When converting funds to CAD, you will be able to withdraw your CAD balance to your own bank account via Interac e-Transfer, EFT, or Domestic Wire Transfer. |
| EUR | When converting funds to EUR, you will be able to withdraw your EUR balance to your own bank account via SEPA. |
| MXN | When converting funds to MXN, you will be able to withdraw your MXN balance to your own Mexican bank account via SPEI. |
| CRC | When converting funds to CRC, you will be able to withdraw your CRC balance to your own Costa Rican bank account via SINPE bank transfer or SINPE Móvil. |
| COP | When converting funds to COP, you will be able to withdraw your COP balance to your own Colombian bank account or Nequi account. |
| ARS | When converting funds to ARS, you will be able to withdraw your ARS balance to your own Argentine bank account via CBU/CVU bank transfer. |
| USD | You can only withdraw USD to a Costa Rican bank account via SINPE or to a Canadian bank account via Domestic Wire Transfer. Do not select USD if you do not agree to these withdrawal options. If you select USD and cannot use these withdrawal options, you can still convert your USD balance to Bitcoin. |

The server stores only the accepted terms version, currency, acceptance time,
and signed setting. It does not store a second copy of the prose per user.

## 4. Product and rail matrix

The existing Bitcoin-only column is a regression boundary: its routes,
destinations, provider calls, and accounting remain unchanged.

| Product / payer rail | Bitcoin-only | Fiat-only | Mixed |
|---|---|---|---|
| Lightning Address / Lightning | Existing Boltz reverse claim to the LA descriptor | Bull Bitcoin Lightning sell order; return its BOLT11 | Existing Boltz reverse swap; at claim time pay descriptor remainder plus fixed Bull Bitcoin L-BTC output |
| Lightning Address / L-BTC (LUD-22) | Existing descriptor allocation | Bull Bitcoin Liquid sell order; preserve existing proof/rate-limit gates and return its confidential address | Not advertised; a stale explicit request is rejected without allocating an address |
| Payment Page or POS / Lightning | Existing Boltz reverse claim | Bull Bitcoin Lightning sell order | Boltz reverse claim with two L-BTC outputs |
| Payment Page or POS / Bitcoin | Existing Boltz chain swap | Bull Bitcoin Bitcoin sell order; return its address/BIP21 and request Payjoin support | Boltz chain claim with two L-BTC outputs |
| Payment Page or POS / Liquid | Existing direct descriptor address | Bull Bitcoin Liquid sell order | Not offered |
| Wallet invoice / Lightning | Existing Boltz reverse claim to the supplied Liquid address | Bull Bitcoin Lightning sell order | Boltz reverse claim to supplied Liquid address plus Bull Bitcoin output |
| Wallet invoice / Bitcoin | Existing direct supplied Bitcoin address | Bull Bitcoin Bitcoin sell order; return its address/BIP21 and request Payjoin support | Supported only when the wallet also supplied a confidential Liquid destination; route through a Boltz chain swap, then make the two-output L-BTC claim |
| Wallet invoice / Liquid | Existing supplied Liquid address | Bull Bitcoin Liquid sell order | Not offered |

Fiat-enabled invoices use the existing payer-demand `POST` boundary to create
an instruction. A public read-only status request must not create a Bull
Bitcoin order. The PWA requests the selected rail, then renders the returned
instruction just as it does for lazy Boltz offers.

The invoice snapshots its allowed rails with the settlement policy. A later
settings update or a payer request cannot turn an unsupported rail into a mixed
route. Mobile must supply the Liquid destination when it creates a wallet
invoice that permits mixed settlement; otherwise the server captures
Bitcoin-only for that invoice.

For mixed settlement, the Bull Bitcoin L-BTC order is deliberately created at
claim time, not checkout time. This avoids expiring the Bull Bitcoin order
while a payer is deciding, while a Bitcoin source waits for confirmations, or
while Boltz prepares the server lock. It also lets the minimum decision use the
actual net claim value.

## 5. Minimal architecture

### 5.1 One narrow Bull Bitcoin adapter

Add one `bull_bitcoin` module with a small trait used by handlers and the
worker:

```text
create_sell_to_balance(key, currency, network, bitcoin_sat, use_payjoin)
get_created_order(key, order_id)
```

The production implementation uses JSON-RPC 2.0 at the configured
`/ak/api-orders` endpoint with `X-API-Key`. It has bounded connect/request
timeouts and no automatic retry of `sellToBalance`. Reads may retry with
bounded backoff.

The adapter deserializes only the fields Bullnym needs:

- order ID;
- order, pay-in, and payout statuses;
- requested/actual Bitcoin amount;
- credited fiat amount and currency;
- the one payer instruction appropriate to the requested network; and
- confirmation/payment expiry needed to decide whether an unexposed order can
  still be used.

It ignores all other `OrderSummary` fields and never stores or logs a raw
response. JSON decimal values are converted exactly: BTC supports at most eight
decimal places and every supported fiat balance uses minor units. No monetary
decision passes through `f64`.

Before implementation is accepted, a live no-money contract test must confirm
that the exact-order response remains readable after account-side archival and
that its payout amount is the amount actually credited after underpayment or
overpayment. The scoped API lookup must therefore omit the current
`isArchived: false` predicate while retaining all of its existing user ID, API
key ID, order ID, sell-order, and balance-payout predicates. If the current
`payoutAmount` is not the actual credited amount, `API-Orders` must expose that
single normalized value on this exact-order method; Bullnym must not infer it
from a rate or requested amount.

The create request always contains exactly one amount field:

```json
{
  "bitcoinAmount": 0.00123456,
  "bitcoinNetwork": "bitcoin|lightning|liquid",
  "fiatCurrency": "CAD",
  "usePayjoin": true
}
```

`usePayjoin` is present only for a fiat-only Bitcoin order. Bullnym accepts the
returned BIP21 whether the account is Payjoin-eligible or the API returns a
normal on-chain instruction.

### 5.2 Encrypted credential capability

Use a dedicated 32-byte deployment secret, separate from the swap mnemonic and
database credentials, to encrypt scoped keys with XChaCha20-Poly1305. A fresh
24-byte nonce is generated for each write. Associated data binds the
credential row ID, canonical owner npub, and format version.

The secret enters only through the process environment. Configuration and
secret-bearing value types implement redacted `Debug`; plaintext key buffers
are zeroized after use. Startup refuses to enable new fiat settlement if the
encryption secret is absent or malformed. Existing-order reconciliation stays
available whenever the secret is valid, even when new-order admission is
disabled.

Before signature verification or persistence, Bullnym requires the current
scoped-key wire format, `^bbak-[0-9a-f]{64}$`; embedded NUL/control characters
and every other shape are rejected. This matters because signed request fields
are NUL-delimited. No endpoint accepts an arbitrary bearer token shape.

There is one credential admitted for new orders per owner npub in the MVP. Each
import receives a new opaque credential row ID, and every settlement leg that
needs reconciliation binds that exact row. Replacement is rejected while the
old credential has an exposed or funded obligation. If Bull Bitcoin proves the
old key invalid, those obligations become `unavailable`, its ciphertext is
erased, and a later import may create a fresh row. Supporting two simultaneously
active credentials is deferred.

### 5.3 Persistence

Migrations 067 through 069 add the following feature-owned state. Migration 067
is the adapter/settings/order foundation, migration 068 adds crash-recoverable
invoice accounting and funding commitment, and migration 069 adds the narrow
mixed-output evidence extension. Splitting them keeps each reviewable without
weakening the final constraints.

`bull_bitcoin_credentials`

- opaque credential-generation ID and canonical owner npub;
- ciphertext, nonce, and encryption format version;
- whether it is admitted for new orders, creation time, and optional
  deletion-request time;
- a partial unique index permits only one admitted credential per npub.

`fiat_settlement_settings`

- owner npub plus product (unique pair);
- fiat percentage, currency, terms version, acceptance time, update time;
- no row represents Bitcoin-only.

`invoice_fiat_settlement_policies`

- one immutable, optional row per invoice; absence means Bitcoin-only;
- invoice ID, owner npub, product, percentage, currency, terms version, and the
  captured allowed-rail mask;
- a wallet invoice that lacks the Liquid destination needed by a mixed route
  does not receive a mixed policy.

`bull_bitcoin_settlements`

- one row per payer instruction or mixed claim leg, so an invoice may have
  several partial settlements without overwriting history;
- owner npub, optional invoice ID, product, captured percentage/currency/terms,
  purpose (`fiat_only` or `mixed`), payer rail, and optional reverse/chain swap
  binding;
- one durable local request key, unique within its owner/invoice or Lightning
  Address intent, and the exact credential-generation ID while reconciliation
  still needs it;
- a monotonic provider state: `reserved`, `dispatch_started`, `bound`, or
  `abandoned`; only `bound` has an order ID;
- a separate immutable funding route once decided: `bull_bitcoin` or
  `bitcoin_fallback`. A fallback has a category, and a known mixed order may be
  left unfunded if the split becomes invalid before claim commitment;
- requested Bitcoin satoshis and selected fiat currency;
- Bull Bitcoin order ID when bound, unique and immutable;
- normalized order/pay-in/payout state;
- actual received satoshis and exact credited fiat minor units when known;
- the payer instruction only while it is needed for replay of a nonterminal
  offer;
- last checked, provider-final, deletion-retention, and terminal timestamps;
- optional fallback category (`below_minimum`, `invalid_split`,
  `conversion_unavailable`, or `ambiguous_create`), never raw upstream text.

The settlement row never contains a Bull Bitcoin user ID, user number, name,
recipient, withdrawal destination, balance, complete API response, generic
transaction history, or API key.

`bull_bitcoin_claim_outputs`

- exactly two immutable rows for each bound mixed claim transaction, with role
  `merchant` or `bull_bitcoin`;
- settlement-leg/order binding, reverse- or chain-swap binding, transaction ID,
  vout, destination script, confidential value/asset commitments and proof
  hashes, authorized L-BTC satoshis, and role;
- original journal transaction ID and optional allowed replacement parent;
- constraints require one output per role and preserve both destinations,
  assets, and amounts across any replacement already supported by Bullnym.

This table is deliberately not a generic split-output facility. Claim bytes
remain in the existing `swap_records`/`chain_swap_tx_attempts` journals. Before
broadcast and again before accounting, Bullnym decodes the bytes, unblinds the
merchant output, verifies the fee and Elements proofs/commitments, and proves
both scripts and immutable commitments match the feature evidence. Bullnym
cannot unblind the Bull Bitcoin output because a confidential address does not
give the sender its recipient blinding private key. Its exact production
evidence is therefore (a) the fixed amount passed to the locally trusted
builder and committed before signing and (b) the scoped API's later actual
received amount. The Bull Bitcoin address itself is cleared with the payer
instruction; the output script/commitments are sufficient retained evidence. A
mixed replacement that cannot preserve both roles enters the existing
integrity-hold path and is never broadcast.

`invoices` gains one `fiat_settlement_status` component with the same small
state vocabulary as its direct and swap components. It is an aggregate reduced
over every value-bearing settlement leg, not a claim that the invoice has only
one fiat order. Unfunded offers and fallback rows do not make it pending. The
existing composed `settlement_status` becomes the conservative composition of
all three components. This prevents a mixed merchant output from marking the
invoice settled while a funded fiat credit is pending.

`invoice_payment_events` accepts two narrow sources. `bull_bitcoin_fiat` binds
the provider-final actual Bitcoin received for a fiat-only order;
`bull_bitcoin_mixed_output` binds the verified vout=1 amount sent to Bull
Bitcoin by a mixed claim. Together they keep received/remaining/overpaid
accounting in Bitcoin while the settlement row owns the separate fiat
projection. Neither source puts fiat value into a Bitcoin accounting column.

The mixed accounting invariant is strict: after the claim is verified there
are exactly two active Bitcoin-value events, one for the merchant output and one
for the Bull Bitcoin output, and their sum equals the claim's net settlement.
The existing full-value `lightning_boltz_reverse` event is replaced on the mixed
path by its exact merchant-output amount; it must not coexist with that pair.
The current Bitcoin-only reverse and chain paths remain byte-for-byte and
accounting-for-accounting unchanged.

All new tables use explicit runtime grants and schema/readiness checks matching
the current privileged-owner migration convention. Feature rows are not
cascade-deleted with a user or invoice while they represent a nonterminal or
completed financial event.

### 5.4 Signed merchant API

Use the existing `bullpay-la-v2` authentication and canonical owner npub.

- `GET /api/v1/fiat-settlement/options` returns the static terms version,
  canonical terms reference, common disclosure, and seven currency
  disclosures. It contains no user state.
- `PUT /api/v1/fiat-settlement/:product` atomically imports or replaces the
  scoped key when supplied and enables one product setting. Its signature
  binds product, percentage, currency, terms version, optional key, and
  timestamp.
- `DELETE /api/v1/fiat-settlement/:product` immediately restores Bitcoin-only
  behavior for future intents. It does not revoke or necessarily delete a key
  still used by another product.
- `GET /api/v1/fiat-settlement` is signed and returns configured products,
  currency, percentage, terms version, and credential/deletion status. It
  never returns the key.
- `DELETE /api/v1/bull-bitcoin-credential` disables all new fiat intents and
  requests encrypted-key deletion. It never calls Bull Bitcoin revocation.
- `GET /api/v1/fiat-settlements?npub=...` is signed and paginated. It exists
  for Lightning Address settlements, which have no invoice row, and returns
  only the same minimal leg projection approved for signed invoice reads. It
  is not a proxy for Bull Bitcoin history and reads only local rows.

All mutating requests use tight body limits, `deny_unknown_fields`, canonical
currency/product names, fresh timestamps, and signatures covering every
logical field. Private responses use `Cache-Control: no-store` and the same
privacy headers as existing signed invoice reads. Existing per-npub admission
limits are extended to settings mutations, credential import/delete, signed
configuration reads, and signed settlement-list reads.

The client-actionable activation errors are part of the version-one wire
contract. A missing key uses `FIAT_CREDENTIAL_REQUIRED`, a rejected key uses
`FIAT_CREDENTIAL_INVALID`, and an ineligible account uses
`FIAT_CONVERSION_KYC_REQUIRED`. The canonical HTTP envelopes are pinned in
[`../api/fixtures/fiat-settlement-errors-v1.json`](../api/fixtures/fiat-settlement-errors-v1.json).
Clients must branch on `code`, not parse the human-readable `reason`.

### 5.5 Credential deletion

Immediate ciphertext deletion and complete settlement supervision cannot both
be guaranteed while an exposed or funded payment still depends on the key:
only the key that created an order can query it. The MVP therefore makes the
smallest explicit compromise:

1. immediately delete every product setting, stop capturing new fiat policies,
   mark the credential unavailable for new orders, and set
   `deletion_requested_at`;
2. convert every unexposed and unfunded `reserved` leg to immutable
   full-Bitcoin fallback, releasing its credential dependency;
3. retain the encrypted key only for an already exposed Boltz instruction that
   may later need its mixed order, a funded swap, or a bound Bull Bitcoin order;
4. erase ciphertext when all dependencies are provider-final or when the
   configured, provider-validated late-payment retention window ends; any
   unresolved leg then becomes `unavailable` rather than being guessed.

Displayed `Expired` or account-side archival alone is not provider-final. The
retention window must be set from Bull Bitcoin's documented/live-validated
late-payment behavior before rollout. A credential-generation row cannot be
replaced while it is draining. If Bull Bitcoin proves the key invalid, Bullnym
stops retrying, preserves the last minimal projection as `unavailable`, erases
the unusable ciphertext, and permits a fresh import. The settings response
reports only `deletion_pending`; deletion never revokes the key at Bull Bitcoin.

## 6. Money-path behavior

### 6.1 Policy capture

- A Payment Page, POS, or wallet invoice snapshots the current per-product
  setting and allowed rails in its optional invoice policy row when the invoice
  is created.
- A Lightning Address payment has no invoice policy row. Its settlement leg
  snapshots the current setting when the callback accepts that specific
  amount.
- Every payer instruction or mixed swap receives its own stable settlement leg.
  A later partial payment uses a new leg and request key; an exact retry reuses
  the old one.
- A setting update cannot rewrite an invoice policy, a settlement leg, or an
  already exposed instruction. Credential deletion follows the explicit drain
  rules in section 5.5.
- If no valid credential is available at snapshot time, the payment is
  Bitcoin-only.

### 6.2 Fiat-only instruction

Under the existing per-invoice/intent session advisory lock, with no database
transaction held across HTTP:

1. re-read payability, policy, current quote/remaining Bitcoin amount, and the
   canonical request key;
2. return the already-bound instruction for an exact retry, or the existing
   Bitcoin instruction for a row routed to fallback;
3. otherwise insert/reuse `reserved` and commit it;
4. atomically advance it to `dispatch_started` and commit **before** the one
   `sellToBalance` call;
5. validate a successful response's order ID, network-specific instruction,
   amount, and currency;
6. in a short transaction, revalidate the invoice/intent and bind the exact
   response before returning it;
7. on deterministic failure, timeout, cancellation, or a surviving
   `dispatch_started` row without an order binding, irreversibly mark the
   provider attempt abandoned, choose the fallback route, and execute the
   existing Bitcoin path.

A timeout after Bull Bitcoin accepted the create call may leave an unfunded
orphan order. Bullnym does not retry the ambiguous create and does not list
orders to find it. Because no instruction was exposed, the orphan cannot
receive this payment. This is safer and much smaller than adding cross-system
idempotency to the MVP.

Every `bound` row is treated as potentially exposed, including a server crash
after commit but before socket delivery. It is never replaced or redirected.
A new partial instruction is allowed only under a new current quote/remaining
amount and therefore a new request key. Public status reads never enter this
state machine.

### 6.3 Mixed claim

The settlement leg is reserved when Bullnym exposes the corresponding Boltz
instruction. Order creation then has two phases.

**Phase A — prepare conversion before claim construction:**

1. under a per-swap session advisory lock, re-read the funded swap, captured
   policy, credential dependency, and exact current two-output claim fee;
2. derive net settlement, fixed fiat share, and Bitcoin remainder;
3. if the merchant output is zero/dust or the split is otherwise locally
   invalid, commit the full-Bitcoin route without calling Bull Bitcoin;
4. otherwise commit `dispatch_started`, release any database transaction, and
   call `sellToBalance` once for a `liquid` order with the fixed fiat share;
5. on a minimum/policy failure or unusable response, mark the attempt abandoned
   and commit the full-Bitcoin route; on success, revalidate the same funded
   swap and commit `bound`;
6. release the session lock. A restart that finds `dispatch_started` without a
   binding marks it abandoned with `ambiguous_create`, chooses Bitcoin, and
   never dispatches again.

**Phase B — construct and journal the claim:**

1. enter the existing claim transaction/lock and reload the committed leg;
2. for the Bitcoin route, construct the existing single-output claim for the
   whole net amount;
3. for bound, construct the merchant destination as the primary remainder and
   `[(bull_bitcoin_confidential_address, fiat_sat)]` as its sole additional
   output;
4. atomically persist the existing raw-transaction journal plus both immutable
   output-evidence rows, unblind/verify the merchant output and verify the Bull
   Bitcoin script, fixed-amount construction authority, and confidential
   commitments, then broadcast through the existing recovery lifecycle.

No Bull Bitcoin network call occurs inside the claim transaction. A crash after
binding reuses the bound order. If fee revalidation makes a mixed output invalid
after binding but before claim journaling, Bullnym may choose Bitcoin and leave
that known order unfunded; after journaling it cannot. A crash after an
ambiguous create falls back to Bitcoin, leaving only an unfunded unknown
provider order. Once the two-output transaction is journaled, no fallback or
settings/deletion action can redirect either output.

The existing transaction journal remains the raw-byte authority. The two
feature evidence rows make its merchant and Bull Bitcoin outputs independently
accountable without generalizing Bullnym into arbitrary split recipients.

### 6.4 Payment and settlement accounting

Payment amount and settlement destination remain separate concepts.

- Fiat-only: when the scoped API reports received value, maintain one active
  `bull_bitcoin_fiat` event per settlement leg for the actual received
  satoshis. If the provider later increases that amount, use Bullnym's existing
  immutable supersession pattern; never mutate or add a second active copy.
  The exact credited fiat minor amount comes only from the completed payout.
- Mixed: at the current path-specific settlement-evidence boundary, the
  verified merchant output contributes the Bitcoin share and the verified Bull
  Bitcoin claim output contributes the fiat share. These exactly replace the
  legacy full-value event on the mixed reverse path. The fiat component remains
  pending until the scoped API confirms the balance credit.
- Underpayment and overpayment use the same invoice-wide tolerance and status
  reducer as existing rails, based on actual Bitcoin received. Bullnym does
  not pretend that the requested amount arrived.
- A completed fiat component requires an exact matching order ID and currency,
  completed pay-in/payout, and a positive representable fiat amount. A
  mismatch is an integrity error, not a guessed settlement.
- Existing direct/swap finality thresholds remain unchanged. The aggregate fiat
  reducer ignores unfunded offers and fallbacks, is pending if any
  value-bearing leg is pending, is unavailable if a value-bearing leg can no
  longer be supervised, and is settled only when every value-bearing fiat leg
  is settled. The invoice is `settled` only when every active component is
  settled.

For a mixed claim, a discrepancy between the locally verified L-BTC output and
the API's eventual received Bitcoin amount is retained as an integrity state
and surfaced to operations. It is never silently reconciled by changing the
invoice value.

## 7. Settlement reconciliation worker

One small supervised worker polls only `bound` local settlement rows with a
known Bull Bitcoin order ID. It never calls an order-list endpoint.

- bounded batch size and cadence;
- per-order exponential backoff with a cap for transport/5xx failures;
- no retry storm on authentication or schema errors;
- decrypt the key only for the duration of one request;
- require the response order ID and fiat currency to match the binding;
- atomically update the minimal projection and idempotent payment event;
- clear the no-longer-needed BOLT11/address/BIP21 when the order becomes
  terminal;
- treat canceled, rejected, archived-readable, and not-found results according
  to the exact-order contract instead of silently treating them as unpaid;
- reduce invoice fiat status over all value-bearing legs after each change;
- finalize pending credential deletion when its last exposed/funded dependency
  is resolved or reaches the configured retention boundary.

The global feature flag gates new settings and new orders, not reconciliation
of existing obligations. Disabling rollout must not abandon a funded order.

## 8. Merchant visibility and payer privacy

Bull Bitcoin settlement details are returned with their payment through the
Schnorr-authenticated `GET /api/v1/get-paid/transactions` projection. The MVP
does not invent a separate signed invoice-detail route. The history projection
normalizes Lightning Address, invoice, Payment Page, and Point of Sale receipts
to the contract in `docs/api/get-paid-transaction-history.md`. Details are
excluded from public invoice status, persisted payer PWA state, HTML metadata,
URLs, logs, and analytics. The selected-rail payer `POST` response necessarily
contains its one payment address/BOLT11/BIP21, but no later public read repeats
that provider instruction.

Bitcoin-only invoices retain the current response shape and flow.

Fiat-only merchant projection. The array has one entry per value-bearing
partial payment, so each amount remains attributable to its order ID:

```json
{
  "kind": "fiat",
  "fiat": [
    {
      "amount_minor": 12345,
      "currency": "CAD",
      "order_id": "...",
      "status": "pending|settled|unavailable"
    }
  ]
}
```

It intentionally omits the API key, Bull Bitcoin pay-in address/invoice,
Bitcoin amount, transaction ID, rate, order number, and account identity.

Mixed merchant projection:

```json
{
  "kind": "mixed",
  "bitcoin": [
    {
      "amount_sat": 75000,
      "network": "liquid",
      "status": "pending|settled|problem"
    }
  ],
  "fiat": [
    {
      "amount_minor": 1234,
      "currency": "CAD",
      "order_id": "...",
      "status": "pending|settled|unavailable"
    }
  ]
}
```

The Bitcoin amount is the sum of verified merchant outputs for the invoice;
the fiat entries retain per-order attribution. The ordinary invoice
`paid_amount_sat` remains authoritative for total received/remaining and
under/overpayment rather than recomputing Bitcoin value from fiat.

When conversion was overridden before any Bull Bitcoin destination was
committed, the ordinary Bitcoin settlement remains authoritative and the
merchant-only detail may add only `fiat_conversion: {"status":"overridden",
"reason":"below_minimum|invalid_split|conversion_unavailable"}`.

## 9. Security and privacy invariants

1. **Least authority:** Bullnym can create only Bitcoin-to-fiat-balance sell
   orders and read only exact order IDs created by the same key.
2. **No identity lookup:** no Bull Bitcoin profile, user, balance, recipient,
   withdrawal, list-orders, websocket, or history API is called.
3. **No first-party key exfiltration surface:** reads and views never return the
   key; secret-bearing types, HTTP middleware, and error paths are
   redaction-tested. Least-authority scope limits the unavoidable bearer risk.
4. **Write ahead, then persist before exposure:** dispatch intent commits before
   provider mutation; an instruction or second claim output is never
   exposed/used before its exact order binding commits.
5. **Known-order reads only:** reconciliation starts from a local order ID and
   cannot enumerate account activity.
6. **Immutable routing:** after exposure/commitment, settings changes, invoice
   cancellation, retries, or provider errors cannot redirect funds.
7. **Actual-value accounting:** exact received Bitcoin and credited fiat are
   never inferred from a requested amount or exchange rate; a mixed claim has
   exactly two active component events and no legacy full-value duplicate.
8. **Recovery outlives admission:** feature disablement stops new conversion,
   not supervision of existing orders or claims.
9. **Merchant-only accounting:** order ID and fiat result never enter the
   unsigned payer projection.
10. **Minimal retention:** raw upstream responses are never persisted; payer
    instructions are cleared at terminal state; encrypted keys are removed
    when no exposed/funded dependency or setting requires them, subject only to
    the explicit bounded deletion drain.

## 10. Edge-case policy

| Edge | Required behavior |
|---|---|
| Unsupported product/currency/percentage or stale terms | Reject before storing the key or setting. |
| Scoped key has the wrong shape, a control character, or embedded NUL | Reject before signature canonicalization/persistence; never echo it. |
| Percentage 0 | Delete the product setting; use current Bitcoin flow; no terms required. |
| Percentage 100 | Direct Bull Bitcoin order on the payer-selected rail; no Boltz merely for splitting. |
| Wallet Bitcoin invoice is mixed but has no confidential Liquid destination | Capture Bitcoin-only for that invoice; never derive or custody a destination server-side. |
| Payer asks for direct Liquid on a mixed policy | Do not advertise it; reject a stale explicit request without allocating an address/order. |
| Mixed share below Bull Bitcoin minimum | Override to full Bitcoin before the claim is built. |
| Bitcoin remainder is dust/zero | Override to full Bitcoin without creating a Bull Bitcoin order. |
| Fee changes after a mixed order binds but before claim journal | If the pair is no longer valid, leave the known order unfunded and atomically choose full Bitcoin; after journal commit, never redirect. |
| Bull Bitcoin maximum or policy rejection before exposure | Full-Bitcoin fallback, categorized without persisting raw error text. |
| API timeout/cancellation during create | Never retry a `dispatch_started` create; mark it abandoned and choose Bitcoin. The unknown order stays unfunded. |
| Crash after API response but before binding commit | Restart sees `dispatch_started`, never dispatches again, and chooses Bitcoin; the provider order is an unfunded orphan. |
| Crash after binding commit but before response/claim | Retry reuses the persisted order; it is treated as potentially exposed. |
| Duplicate payer/claim requests | Existing session advisory lock plus a unique local request key returns one binding/routing decision. |
| Bound fiat instruction expires before/after socket delivery | Treat it as potentially exposed; do not replace or redirect it. A later partial instruction requires a new request key. |
| Order is archived in the Bull Bitcoin account | Exact same-key lookup still works; archive is not authorization and does not hide Bullnym's own settlement. |
| Order displays expired after exposure | Do not assume irreversible finality. Reconcile through the validated late-payment retention boundary. |
| Invoice cancellation/expiry after payment evidence | Preserve and attribute late settlement using current Bullnym lifecycle rules. |
| Underpayment/overpayment | Supersede one active actual-sat event when needed and record the provider-credited fiat; never create a compensating order. |
| Multiple partial payments | One leg/order per committed payer instruction; active events sum actual sats once and merchant projection lists each order. |
| Settings change during an invoice | Existing invoice policy is immutable; new invoices use the new setting. |
| Key replacement with an exposed/funded old-key dependency | Reject until its drain completes; never strand the only read capability. |
| Credential deletion | Disable immediately; fallback only unexposed/unfunded legs; drain exposed/funded dependencies, then erase without revocation. |
| Key revoked or rejected while polling | Stop new conversion, mark affected fiat projection unavailable, erase unusable key, retain minimal order evidence. |
| Malformed response, wrong order ID/currency, impossible amount | Integrity state; never mark settled or expose a guessed value. |
| Exact API response lacks actual credited fiat semantics | Compatibility gate fails; extend the exact-order DTO before enabling money movement. |
| API/worker outage after funds were sent | Remain pending and retry; never fall back to a different destination. |
| Bullnym database restored without encryption key | Fiat admission stays closed; existing rows remain visibly unreconciled. |
| Bull Bitcoin/Bullnym quote rates differ | Display the exact credited fiat result; do not rewrite it to Bullnym's display quote. |
| Payjoin not enabled for the account | Use the valid non-Payjoin Bitcoin instruction returned by Bull Bitcoin. |
| Mixed claim reorg/replacement | Existing exact claim lifecycle remains authoritative; both role-tagged outputs must preserve order binding, asset, amount, and destination in any allowed replacement. |

## 11. Dependency strategy

The scoped Bull Bitcoin API prerequisite is accepted only after two focused
compatibility checks:

1. `getSellToFiatBalanceOrder` keeps its exact `userId + createdByApiKeyId +
   orderId + SELL + balance payout` authorization but does not hide an order
   merely because account UI archived it;
2. its normalized response is live-tested to prove which field is the actual
   credited balance amount after underpayment/overpayment. If necessary, add
   only that exact field and no list/history capability.

Bullnym cannot pin PR #162 alone because current main also depends on the
unmerged `claim_covenant` field at BullishNode commit `c205118...`. Before any
Bullnym money-path change:

1. create one clean temporary fork branch by applying PR #162's four commits on
   top of `c205118...`;
2. retain boltz-client 0.3.1 and Bullnym's current LWK/Elements boundary rather
   than pulling the PR's unrelated 0.4.1 dependency/API changes; resolve only
   the `claim_covenant` request-struct compatibility;
3. run the PR's unit, transaction, and multi-output tests;
4. add a Bullnym compile test using `TransactionOptions::with_additional_outputs`;
5. push and pin one immutable fork commit in both `Cargo.toml` and
   `release-manifest.toml`.

No local path override is allowed in a deployable artifact. Upstreaming and
eventual repinning to a merged SatoshiPortal commit is a later dependency-only
change.

## 12. Implementation order and reviewable commits

1. **Scoped API compatibility:** remove the archive-only blind spot, retain the
   same-key exact-order predicates, and lock the minimal credited-amount
   contract with API-Orders tests.
2. **Dependency compatibility:** produce and pin the immutable `boltz-rust`
   fork commit; no Bullnym behavior change.
3. **Contract foundation:** add migration 067, exact money types, encrypted
   credential capability, terms/settings signed API, feature flag, readiness,
   and adapter trait with a fake implementation. No payment route calls Bull
   Bitcoin yet.
4. **Order lifecycle:** implement the JSON-RPC adapter, write-ahead create/read
   state machine, deletion behavior, and reconciliation worker. Exercise it
   only through tests.
5. **Fiat-only vertical slice:** route lazy payer instructions through Bull
   Bitcoin for all three source networks while preserving each product's
   existing fallback and abuse gates.
6. **Mixed vertical slice:** add migration 069, reserve one leg per exposed
   swap, prepare the L-BTC order before claim construction, add the one fixed
   output, prove both output roles, replace the legacy full-value accounting on
   this path, and compose Bitcoin plus fiat settlement status.
7. **Merchant projection and PWA:** expose the minimal signed settlement
   breakdown, keep public status private, disable direct Liquid for mixed
   settlement, and make the PWA request fiat-enabled payer instructions via
   POST.
8. **Maintained docs and external harness:** update API/auth/payment/deployment
   docs and add `bullnym-tests` scenarios.

Each commit must compile and preserve the default-off Bitcoin-only behavior.
The mixed commit is not accepted until controlled tests unblind both outputs
and assert their exact amounts, while production replay tests prove the
merchant output and the immutable Bull Bitcoin script/commitment authority
without pretending to own Bull Bitcoin's blinding key.

## 13. Verification plan

### 13.1 Bullnym unit and component tests

- exact sat-to-BTC JSON encoding and fiat-decimal-to-minor conversion;
- all seven currencies and all three Bull Bitcoin input networks;
- JSON-RPC request method, `X-API-Key`, Bitcoin-only amount, Payjoin flag, and
  same-order read shape;
- minimum, maximum, authentication, malformed, wrong-ID, wrong-currency,
  timeout, and 5xx classification;
- encryption round trip, associated-data binding, corruption failure,
  zeroization/redacted `Debug`, and absence of key text in errors;
- signed settings payload order, replay/stale timestamp, ownership, terms,
  defaults, exact key grammar/NUL rejection, and key-never-returned tests;
- split rounding, minimum fallback, primary dust fallback, 100% boundary, and
  no destination mutation after commitment;
- write-ahead state transitions including ambiguous crash fallback;
- worker retry/backoff, idempotent/superseding completion, credential drain,
  retention boundary, and key replacement conflict.

### 13.2 Bullnym PostgreSQL integration tests

- migrations 067/068/069 constraints, runtime grants, readiness marker, and
  additive upgrade from schema 066;
- concurrent create requests commit one usable order;
- crash-boundary simulations before dispatch, after dispatch, after provider
  response, after binding, and after claim-journal commit;
- only known order IDs are selected for polling;
- direct fiat payment records actual underpayment/overpayment once;
- two partial direct payments retain distinct orders and sum active events;
- mixed payment counts merchant plus fiat Bitcoin components exactly once and
  proves that no legacy full-value reverse event coexists;
- invoice settlement stays pending until both required components settle;
- settings deletion cannot rewrite old policies;
- credential deletion falls back only unexposed/unfunded legs and drains every
  exposed/funded dependency;
- public invoice status contains no order ID, fiat credit, API key, or provider
  instruction; the signed invoice list and signed Lightning Address settlement
  list contain only the approved projection.

### 13.3 Multi-output tests

- compile against the pinned fork with no path override;
- construct cooperative and script-path reverse and chain claims;
- with a controlled test recipient blinding key, unblind the primary and Bull
  Bitcoin outputs and assert destination, asset, and exact amount;
- without that recipient key, prove production replay still rejects a changed
  script, vout, commitment, proof, role, order binding, or authorized amount;
- prove mixed order sizing uses the exact two-payment-output fee while the
  existing payer quote and Bitcoin-only claim path remain unchanged;
- assert primary remainder plus fixed output plus fee equals the verified
  input;
- replacement preserves both role bindings, destinations, assets, and amounts;
- fallback constructs byte-equivalent single-output policy to the existing
  path;
- run the upstream PR #162 unit/regtest suite that does not require funded
  external infrastructure.

### 13.4 External `bullnym-tests`

Create a dedicated typed scenario family, not additions to the legacy `all`
command:

- no-money signed settings/import/read/delete contract against a deployed
  server and a controlled fake Bull Bitcoin JSON-RPC endpoint;
- fiat-only instruction matrix for Bitcoin, Lightning, Liquid, Payjoin
  fallback, and seven currencies;
- minimum fallback proves the payer receives the ordinary Bullnym Bitcoin
  instruction and no Bull Bitcoin order is funded;
- mixed reverse and chain claims prove two outputs from raw transaction bytes
  and merchant-only settlement projection, with no full-value duplicate event;
- two partial fiat-only payments produce two attributable order entries and one
  correct invoice received total;
- underpayment and overpayment assert actual credited fiat from the API;
- key A cannot read an order made by key B (same Bull Bitcoin user included),
  using the API-stack prerequisite test environment;
- restart/reconciliation and deletion-pending scenarios;
- report provenance without keys, addresses, BOLT11s, npubs, order IDs, or raw
  API bodies.

### 13.5 Real integration sequence

After local review and all deterministic tests pass:

1. deploy to a dedicated disposable LunaNode **application/database staging
   environment**, never the `pay2` production application VM. The existing
   `bullnym-tests` VM remains a harness/report host and, per the repository
   runbook, does not run Bullnym or reuse production secrets. If no separate
   staging application host exists, provisioning it is a hard deployment gate;
2. back up PostgreSQL, install schemas 067 through 069 with a distinct
   privileged owner, install a fresh staging-only encryption secret, and keep
   new fiat admission disabled;
3. verify `/health`, `/ready`, `/version`, worker startup, binary digest, schema
   marker, and unchanged Bitcoin-only smoke tests;
4. enable the feature for a test npub and use a real scoped key;
5. create and query unfunded sell orders on Bitcoin, Lightning, and Liquid to
   prove the live API contract without moving money, including same-key access
   after archival and denial with a different scoped key;
6. run minimum-fallback and restart tests;
7. run the complete funded path first against the controlled fake API and
   local/regtest chain fixtures from `bullnym-tests`;
8. only with a separately approved mainnet sat budget and an operator-approved
   execution host, run one small fiat-only payment and one small mixed payment,
   then verify the exact Bull Bitcoin balance credit and both mixed claim
   outputs. The harness-only test VM must not hold or spend mainnet funds;
9. test live under/overpayment only with separately approved, bounded
   purpose-built amounts and retain redacted evidence;
10. disable new fiat admission while leaving reconciliation active and verify
   every created order reaches a known terminal or explicitly unavailable
   state.

## 14. Acceptance criteria

- Default/off and absent-setting behavior is indistinguishable from current
  Bullnym in tests.
- Every supported product can select Bitcoin-only, fiat-only, or mixed subject
  to the rail matrix.
- Every Bull Bitcoin create request carries an exact Bitcoin amount and one of
  the seven supported balance currencies.
- A below-minimum full or partial conversion settles entirely to the existing
  Bitcoin destination.
- A mixed claim has exactly one merchant remainder output, one fixed Bull
  Bitcoin confidential output, and the fee output; both payment outputs are
  verified before accounting.
- Fiat-only merchant detail shows only exact fiat amount, currency, order ID,
  and status per partial leg. Mixed detail additionally shows the verified
  Bitcoin settlement.
- No public/payer response or log contains a key, order ID, or fiat settlement
  detail.
- Bullnym stores no Bull Bitcoin account identity or general history and never
  lists orders.
- Credential deletion never revokes at Bull Bitcoin, never redirects a
  committed destination, and drains exposed/funded dependencies through the
  validated retention policy before erasure.
- Local, database, multi-output, external no-money, and guarded VM tests pass
  with clean source and pinned provenance.

## 15. Rollout and rollback

The feature flag defaults off. It gates settings/import and new Bull Bitcoin
orders, while the order worker continues for existing rows. Enable only test
npubs first through their explicit signed settings; there is no global
automatic backfill of Bullnym settings or credentials.

Migrations 067 through 069 are additive but advance Bullnym's exact schema
marker. The safe rollback is therefore a feature-off schema-069 binary. Rolling
back to a schema-066 binary requires stopping writers and restoring the paired
schema-066 database backup, binary, PWA, and release record. Never drop
settlement rows to force an old readiness marker and never disable
reconciliation while a known order is nonterminal.

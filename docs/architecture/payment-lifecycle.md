# Bullnym Payment Architecture

This document is the payment contract for Lightning Address, Payment Page,
POS, and wallet-origin invoices. It keeps product semantics separate from the
shared rail machinery: invoices, payment events, watchers, Boltz swaps, and
settlement state.

## Goals

- Preserve the existing Lightning Address product behavior.
- Make Payment Page and POS payer-created checkout flows with Lightning,
  Liquid, and Bitcoin-via-Boltz payment instructions.
- Make Invoices merchant-created receivables with strict accounting.
- Use fixed-sat accounting for every payment session. Fiat amounts are
  converted once at creation and stored as metadata.
- Record accounting from idempotent payment events, not from one-shot status
  flips.
- Keep payer payment state distinct from merchant settlement state.

## Product Matrix

| Product | Payment methods | Settlement destination | Notes |
|---|---|---|---|
| Lightning Address | Lightning via Boltz reverse swap; Liquid via LUD-22 | Derived from the active nym CT descriptor | Mostly unchanged. No invoice partial/under/over semantics. |
| Payment Page | Lightning via Boltz reverse swap; Liquid direct; Bitcoin via Boltz chain swap | Derived from the Payment Page CT descriptor when present, otherwise the active nym CT descriptor for legacy pages | Payer enters amount at `/:nym`. |
| POS | Lightning via Boltz reverse swap; Liquid direct; Bitcoin via Boltz chain swap | Derived from the POS CT descriptor | Cashier enters amount at `/:nym/pos`. POS has no Lightning Address fallback. |
| Invoices | Lightning via Boltz reverse swap; Liquid direct; Bitcoin direct | Merchant supplied Liquid/BTC addresses | Merchant receivable. No BTC-to-LBTC Boltz chain swap in v1 invoices. |

## Identity Model

`npub` is the owner/authentication identity. It signs Bullnym actions and owns
nyms and invoices.

`verification_npub` is the public NIP-05 key exposed by
`/.well-known/nostr.json` only when it is explicitly supplied at registration
and NIP-05 is enabled. Registrations that omit it publish no NIP-05 record;
the server never falls back to the auth `npub`.

`nym` is a public alias and route namespace owned by one `npub`.

An active nym has one Lightning Address CT descriptor in `users.ct_descriptor`
(mobile path 75). Public checkout surfaces have independent Get Paid CT
descriptors in `donation_pages.ct_descriptor`: Payment Page uses mobile path
102 and POS uses mobile path 103. Each `(nym, kind)` row has its own
`donation_pages.next_addr_idx` cursor. Legacy Payment Pages without a page
descriptor fall back to the nym descriptor; POS does not.

Nym lifecycle invariants:

- Active nym: owned by one `npub`, has one Lightning Address CT descriptor,
  payable.
- Deactivated nym: not payable for new Lightning Address, Payment Page, or
  POS sessions; existing sessions and swaps must still settle.
- Purged nym: reserved but not payable; descriptor material is scrubbed.

CT descriptors are not account identities. They are receive capabilities.
Payment sessions should store their concrete settlement destination rather than
implicitly resolving through a mutable nym or surface row at settlement time.

## Payment Sessions

A payment session is a finite-lived attempt to collect a fixed sat amount
through one or more payment instructions.

The `invoices` table backs both public checkout sessions and merchant
invoices:

- `origin = 'checkout'`: Payment Page or POS checkout session.
- `origin = 'wallet'`: merchant invoice.

Conceptual session fields:

- owner `npub`
- linked `nym`, nullable
- product type / origin
- target `amount_sat`
- fiat metadata, nullable
- accepted payment instructions
- concrete settlement destinations
- `pricing_mode`
- `payment_status`
- `settlement_status`
- expiry
- cumulative paid amount

Public checkout no longer uses the legacy
`/lnurlp/donate-callback/:nym` and `/lnurlp/donate-status/:nym` endpoints.
The Payment Page creates an invoice session with `POST /<nym>/invoice`; POS
uses `POST /<nym>/pos/invoice`. Both poll
`/api/v1/invoices/<invoice_id>/status`.
The old cookie-pinned Liquid allocation table was dropped by migration 019;
new checkout sessions reserve concrete payment addresses through the invoice
payment-address ledger.

## Settlement Destinations

Each payment session must have explicit settlement destinations.

Lightning Address:

- Lightning claims and Liquid receive addresses are derived from the nym CT
  descriptor.

Public checkout surfaces:

- Payment Page derives a Liquid address from the Payment Page CT descriptor
  when present, otherwise from the active nym CT descriptor for legacy pages.
- POS derives a Liquid address from the POS CT descriptor and has no fallback.
- Lightning reverse swaps claim to that session Liquid address.
- Direct Liquid pays that session Liquid address.
- BTC-to-LBTC chain swaps claim to that session Liquid address.

Invoices:

- Direct BTC pays a merchant-supplied Bitcoin address.
- Direct Liquid pays a merchant-supplied Liquid address.
- Lightning reverse swaps claim to the merchant-supplied Liquid address.
- Invoices do not expose BTC-to-LBTC Boltz chain swaps in this phase.

## Payment Instructions

The product surface should think in payment instructions, not raw rails.

Instruction kinds:

- `lightning_boltz_reverse`: payer pays BOLT11, merchant receives LBTC through
  a Boltz reverse swap claim.
- `liquid_direct`: payer pays a Liquid address directly.
- `bitcoin_direct`: payer pays a merchant Bitcoin address directly. Invoices
  only.
- `bitcoin_boltz_chain`: payer pays a Boltz Bitcoin lockup address, merchant
  receives LBTC through a Boltz chain swap. Payment Page and POS only.

Do not expose two ambiguous "Bitcoin" options on invoices. For invoices,
Bitcoin means merchant-supplied direct BTC settlement.

## Amount Model

`amount_sat` is the canonical settlement target.

Sat-denominated sessions store only `amount_sat`.

Fiat-denominated sessions resolve fiat to sats once at creation:

- store original fiat amount and currency
- store `rate_minor_per_btc`
- store computed `amount_sat`
- do not refresh or float the invoice rate after creation

`pricing_mode` is `sat_fixed` for sat-denominated sessions and `fiat_fixed`
for fiat-denominated sessions whose BTC rate was locked at creation.

Exchange-backed settlement would require a separate settlement mode. Direct
Bitcoin merchant receive flows do not need floating fiat rates.

## Payment Events

All accounting comes from idempotent, countable payment events. Migration 047
keeps inactive and superseded direct evidence in the same table for audit, but
only `active` and rollout-compatible `legacy_unverified` rows contribute value.
Migration 048 makes cancellation an instruction-closure marker rather than an
accounting blind spot: a late payment event is still recorded and projected,
while the invoice remains `cancelled` and cannot issue new payment details.

Event fields:

- session/invoice id
- instruction kind or rail
- event key
- amount in sats
- created/detected timestamp

Event keys must identify the payment evidence, not only the transaction:

- `bitcoin_direct:<txid>:<vout>`
- `liquid_direct:<txid>:<vout>`
- `lightning_boltz_reverse:<boltz_swap_id>`
- `bitcoin_boltz_chain:<boltz_swap_id>`

Never use `bitcoin:<txid>` for direct BTC accounting. One Bitcoin transaction
can pay multiple sessions in different outputs.

Accounting:

```text
received_sat = SUM(payment_events.amount_sat)
  WHERE accounting_state IN ('active', 'legacy_unverified')
remaining_sat = max(amount_sat - received_sat, 0)
```

## Payment Observations

Payment observations are non-accounting evidence. They exist so users and
operators can distinguish "nothing seen" from "payment seen, waiting for
confirmations."

Current observation scope covers exact direct Bitcoin and Liquid invoice
outputs:

- sources: `bitcoin_direct` and `liquid_direct`
- rails: `bitcoin` and `liquid`
- event keys: `<source>:<txid>:<vout>`

Observation states:

- `seen_unconfirmed`: the output is in mempool and has zero confirmations.
- `awaiting_confirmations`: the output has at least one confirmation, activates
  its exact accounting event, and remains below configured finality.
- `counted`: the same active accounting event reached configured finality.
- `resolution_pending`: explicit authoritative regression invalidated prior
  evidence and requires visible resolution.

The live watchers do not create a `not_seen` transition from address-history
omission, tx 404, timeout, incomplete data, cancellation, or failover. Legacy
rows can retain that historical token, but ambiguous absence awaits its
separately approved policy.

Observations must never be summed into `paid_amount_sat`, must never set
`paid_via`, and must never set `paid_at`. They are status evidence only.

## Payment Status

Payment status is the product/accounting state of the session.

- `unpaid`: no payment evidence counted.
- `in_progress`: payment evidence has been seen but is not countable yet.
- `partially_paid`: counted payments exist, but the target is not met and the
  session is still payable.
- `paid`: counted payments meet the target within tolerance.
- `underpaid`: the session expired after receiving some value below the target.
- `overpaid`: counted payments exceed the target.
- `expired`: the session expired with no counted payments.
- `cancelled`: merchant cancelled before payment evidence.

Payment Page and POS can present simpler copy, but they should not discard the
underlying accounting state.

`presentation_status` is an independent server-computed money projection:
`unpaid`, `partial`, `payment_received`, or `overpaid`. It combines active and
verified provisional value using server tolerances. Clients must not reproduce
the amount or tolerance calculation. Unknown/null rollout values hide payment
instructions, disable cancellation, remain non-final, and continue detail
polling.

Lightning Address does not expose invoice payment statuses.

## Settlement Status

Settlement status is separate from payment status because Boltz can introduce a
gap between payer payment and merchant receipt.

- `none`: no settlement workflow is active or needed.
- `pending`: payment is detected and a claim/settlement workflow is in flight.
- `settled`: a direct payment reached configured finality, or a swap reached
  its separately documented current settlement boundary.
- `resolution_pending`: explicit durable direct-payment evidence regressed and
  the outcome is visibly being resolved.
- `claim_stuck`: the fast claim retry budget was exhausted. Slow recovery
  continues for funded swaps; operators must still alert and investigate.
- `refunded`: Boltz refunded the lockup before merchant claim; incident.
- `failed`: unrecoverable or explicitly failed settlement path.

Direct Bitcoin and Liquid activate accounting at exactly one confirmation and
reach finality at configurable nonzero thresholds (defaults three and two).
Boltz claim paths still mark settlement after successful broadcast, before
confirmation. These distinct boundaries must not be described as equivalent.

## Tolerance Policy

Shortfall tolerance must be configurable and wired into all accounting paths.

Initial defaults:

- BTC direct: 300 sats
- Liquid direct: 60 sats
- Lightning Boltz reverse: 1 sat
- Bitcoin Boltz chain: 300 sats unless a tighter Boltz-delivered amount can be
  proven

For each invoice, select the strictest configured tolerance among every enabled
rail and cap it at one percent of the invoice amount. That one advertised
invoice-wide threshold drives both confirmed accounting and provisional
presentation, independent of the credited event's rail or mixed-rail arrival
order. Tiny underpayments within that threshold become `paid`; overpayments
remain `overpaid` for auditability.

Confirmation and finality policy remains rail-specific. Direct Bitcoin and
Liquid both activate accounting at one confirmation, then reach settlement at
their separately configured nonzero finality depths.

## Boltz Reverse Swaps

Boltz reverse swaps are the Lightning instruction type.

Applies to:

- Lightning Address
- Payment Page
- POS
- Invoices

Lifecycle mapping:

- `swap.created`: instruction exists; no product state change.
- `invoice.expired`: BOLT11 unusable; create a replacement only if the session
  remains payable.
- `transaction.mempool`: `payment_status = in_progress`.
- `transaction.confirmed`: `settlement_status = pending`; claim scheduled.
- successful claim broadcast or recovered successful outspend: record
  `lightning_boltz_reverse:<swap_id>` payment event.
- `claim_stuck`: `settlement_status = claim_stuck`; no false merchant
  settlement.
- `transaction.refunded`: `settlement_status = refunded`; incident.

Accounting event rule:

Do not record a Lightning payment accounting event before the merchant-side
claim broadcast succeeds or an already-successful outspend is recovered. The
public UX may show "payment detected" while settlement is pending. A successful
broadcast is the current accounting boundary; confirmation monitoring remains
a reliability improvement rather than current behavior.

## Boltz Reverse Swap Refresh

Session expiry and BOLT11 expiry are separate clocks.

Rules:

- Create the initial reverse swap when a public checkout session or
  Lightning-enabled invoice is created.
- Reuse a BOLT11 only when it matches the current remaining amount and is not
  close to expiry.
- Create a replacement when the previous BOLT11 expired or the remaining amount
  changed.
- Never create a replacement after session expiry.
- Never extend session expiry because of Boltz.
- Refresh must be single-flight per session and instruction kind.

Preferred API shape:

- `POST /api/v1/invoices/:id/lightning` may create or refresh.
- `GET /api/v1/invoices/:id/status` should avoid side effects when possible.

If status-side refresh is retained, it must hold a per-session lock around
latest-swap lookup and swap creation.

## Boltz Chain Swaps

BTC-to-LBTC chain swaps are for Payment Page and POS checkout only.

They are not part of Lightning Address and not part of merchant invoices.

Public checkout behavior:

- expose the Bitcoin instruction only if the remaining amount is above Boltz
  minimum and below Boltz maximum for BTC-to-LBTC
- fetch and pin the exact BTC-to-LBTC pair hash before creation; reject stale
  quotes and independently recompute the payer gross-up
- validate both returned Taproot trees byte-for-byte, including leaf versions,
  local hashlock, key roles, mainnet address families, amounts, and cross-chain
  timeout ordering
- ignore the provider BIP21 and build the payer URI locally from the validated
  Bitcoin address, exact payer amount, and Bullnym checkout URL
- copy the canonical session Liquid address into immutable per-swap creation
  terms and use that copy—not a later invoice lookup—as the LBTC claim
  destination
- commit the canonical provider response, response digest, pair quote, script
  digests, networks, L-BTC asset, timeouts, key lineage, and merchant
  destination atomically before returning either the address or BIP21
- single-flight chain swap creation per session and remaining amount
- do not create a new chain swap after session expiry

Rows created before schema 051 have no creation packet and retain an explicit
legacy claim fallback. Every post-051 insert must contain the complete packet;
the database rejects partial packets and freezes both the evidence packet and
its bound payer instruction, amounts, provider response, ownership, and key
material. The canonical response digest is rechecked before Liquid claim or
Bitcoin recovery signing. Emergency Bitcoin commitment remains nullable until
its signed registration issue is deployed; those rows are therefore not yet
fully recovery-v3 compliant.

Product copy must make settlement clear:

```text
Pay with Bitcoin on-chain. Settles to Liquid through Boltz.
```

Chain swap accounting event:

- record `bitcoin_boltz_chain:<swap_id>` after the LBTC claim is successfully
  broadcast or a successful outspend is recovered.

Wrong amount, expired lockup, renegotiation, and refund behavior must stay
explicitly tested because this rail crosses both Bitcoin and Liquid settlement
systems.

## Direct Liquid

Public checkout surfaces:

- server derives the Liquid address and blinding key from the selected surface
  descriptor; legacy Payment Pages may fall back to the nym descriptor.

Invoices:

- client supplies a Liquid address
- client must supply the matching single-address blinding key when direct
  Liquid is accepted
- server validates the key matches the address

Clients must use invoice-scoped Liquid addresses. Address reuse is a client
hygiene issue, but server documentation and tests should make the expected
usage clear.

The Liquid watcher preserves signed Electrum height and canonical block
identity, decodes and unblinds the exact matching L-BTC output, and retains a
durable reversible observation. A verified mempool output contributes only to
presentation; one confirmation activates exact accounting; the configurable
nonzero threshold (two by default) controls finality.

## Direct Bitcoin

Direct Bitcoin is Invoices only.

Requirements:

- merchant supplies the Bitcoin address
- watcher processes every matching output
- event key includes txid and vout
- one tx can pay multiple invoices
- multiple txs can pay one invoice
- duplicate old events must not block later events
- mempool sightings can mark `in_progress`
- zero-confirmation evidence contributes only to presentation
- one confirmation activates the exact payment event
- the configurable nonzero threshold (three by default) controls finality

## Cancellation

Lightning Address:

- deactivation stops new payment instructions
- existing swaps must still settle

Payment Page and POS:

- archiving the surface stops new sessions
- existing sessions expire naturally
- no separate user-facing cancellation required initially

Invoices:

- merchant can cancel only while `unpaid`
- do not cancel `partially_paid`
- safest initial rule: do not cancel once `in_progress`
- terminal statuses are not cancellable

## Testing Contract

Tests should be product-oriented and rail-oriented:

- Lightning Address regression
- Payment Page checkout
- POS checkout
- Merchant Invoices
- BTC direct watcher
- Liquid exact accounting
- Boltz reverse swaps
- Boltz chain swaps
- security and authorization
- operational recovery

Use the bullnym-test VM for deployed server/payment-rail certification:
BDK-origin Bitcoin sends, LWK-origin Liquid sends, Boltz reverse swaps,
Boltz chain swaps, invoice accounting, public checkout, and address
allocation. Do not treat a VM pass as mobile validation. Mobile-owned behavior
belongs in the Bull Bitcoin mobile repository: deterministic key/path
derivation, signed payload generation, local storage, Flutter flows, and
device/emulator checks.

Tests must assert one expected behavior. Avoid "paid or underpaid is okay"
style assertions unless a test is intentionally documenting a transition period.

Minimum scenario coverage:

- duplicate payment event idempotency
- partial then completion
- partial then expiry
- overpayment
- mixed rails
- BTC one tx to multiple sessions
- BTC multiple txs to one session
- Liquid non-LBTC ignored
- reverse swap refresh by remaining amount
- reverse swap duplicate webhook
- reverse swap missed webhook reconciled
- claim stuck does not mark merchant settled
- chain swap only exposed for Payment Page/POS and within Boltz limits

# Bullnym Payment Architecture

This document is the implementation contract for the Donation Page and
Invoices rearchitecture. It keeps Lightning Address stable, makes Boltz a
first-class subsystem, and separates product semantics from shared payment
rail machinery.

## Goals

- Preserve the existing Lightning Address product behavior.
- Make Donation Page a payer-created checkout flow with Lightning, Liquid,
  and later Bitcoin-via-Boltz payment instructions.
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
| Donation Page | Lightning via Boltz reverse swap; Liquid direct; Bitcoin via Boltz chain swap later | Derived from the active nym CT descriptor | Payer enters amount. Public page defaults to Lightning and exposes Liquid immediately. Bitcoin chain swap is Donation Page only. |
| Invoices | Lightning via Boltz reverse swap; Liquid direct; Bitcoin direct | Merchant supplied Liquid/BTC addresses | Merchant receivable. No BTC-to-LBTC Boltz chain swap in v1 invoices. |

## Identity Model

`npub` is the owner/authentication identity. It signs Bullnym actions and owns
nyms and invoices.

`nym` is a public alias and route namespace owned by one `npub`.

An active nym has exactly one CT descriptor. That descriptor is the default
Liquid receive capability for nym-based products.

Nym lifecycle invariants:

- Active nym: owned by one `npub`, has one CT descriptor, payable.
- Deactivated nym: not payable for new Lightning Address or Donation Page
  sessions; existing sessions and swaps must still settle.
- Purged nym: reserved but not payable; descriptor material is scrubbed.

The CT descriptor is not the account identity. It is receive capability. Payment
sessions should store their concrete settlement destination rather than
implicitly resolving through a mutable nym at settlement time.

## Payment Sessions

A payment session is a finite-lived attempt to collect a fixed sat amount
through one or more payment instructions.

The current implementation may use the `invoices` table as the backing table
for both Donation Page checkout sessions and merchant invoices:

- `origin = 'checkout'`: Donation Page payment session.
- `origin = 'wallet'`: merchant invoice.

Long-term, this can be split into explicit `payment_sessions`,
`payment_events`, and `invoices` tables. Do not do that split until the rail
semantics are stable.

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

Donation Page checkout no longer uses the legacy
`/lnurlp/donate-callback/:nym` and `/lnurlp/donate-status/:nym` endpoints.
The public page creates an invoice session with `POST /<nym>/invoice`, renders
`/<nym>/i/<invoice_id>`, and polls `/api/v1/invoices/<invoice_id>/status`.
The old cookie-pinned Liquid allocation table was dropped by migration 019;
new checkout sessions reserve concrete payment addresses through the invoice
payment-address ledger.

## Settlement Destinations

Each payment session must have explicit settlement destinations.

Lightning Address:

- Lightning claims and Liquid receive addresses are derived from the nym CT
  descriptor.

Donation Page:

- The session derives a Liquid address from the active nym CT descriptor.
- Lightning reverse swaps claim to that session Liquid address.
- Direct Liquid pays that session Liquid address.
- Future BTC-to-LBTC chain swaps claim to that session Liquid address.

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
  receives LBTC through a Boltz chain swap. Donation Page only, later stage.

Do not expose two ambiguous "Bitcoin" options on invoices. For invoices,
Bitcoin means merchant-supplied direct BTC settlement.

## Amount Model

`amount_sat` is the canonical settlement target.

Sat-denominated sessions store only `amount_sat`.

Fiat-denominated sessions resolve fiat to sats once at creation:

- store original fiat amount and currency
- store `rate_minor_per_btc`
- store computed `amount_sat`
- do not refresh or float the invoice rate in this MVP

`pricing_mode` is `sat_fixed` for sat-denominated sessions and `fiat_fixed`
for fiat-denominated sessions whose BTC rate was locked at creation.

Future exchange-backed settlement can add a new settlement mode. Direct Bitcoin
merchant receive flows do not need floating fiat rates.

## Payment Events

All accounting comes from idempotent payment events.

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
remaining_sat = max(amount_sat - received_sat, 0)
```

## Payment Observations

Payment observations are non-accounting evidence. They exist so users and
operators can distinguish "nothing seen" from "payment seen, waiting for
confirmations."

Current observation scope:

- direct Bitcoin invoice outputs only
- source: `bitcoin_direct`
- rail: `bitcoin`
- event key: `bitcoin_direct:<txid>:<vout>`

Observation states:

- `seen_unconfirmed`: the output is in mempool and has zero confirmations.
- `awaiting_confirmations`: the output is confirmed but below the configured
  confirmation threshold.
- `counted`: the watcher saw enough confirmations and recorded the accounting
  event through `invoice_payment_events`.
- `not_seen`: a later watcher poll no longer saw a previously uncounted output.

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

Donation Page can present simpler copy, but it should not discard the underlying
accounting state.

Lightning Address does not expose invoice payment statuses.

## Settlement Status

Settlement status is separate from payment status because Boltz can introduce a
gap between payer payment and merchant receipt.

- `none`: no settlement workflow is active or needed.
- `pending`: payment is detected and a claim/settlement workflow is in flight.
- `settled`: merchant-side funds are received or recoverably proven.
- `claim_stuck`: claim retry budget exhausted; operator action required.
- `refunded`: Boltz refunded the lockup before merchant claim; incident.
- `failed`: unrecoverable or explicitly failed settlement path.

Direct BTC and direct Liquid can usually collapse detection and settlement once
their configured confirmation policy is satisfied. Boltz paths must not.

## Tolerance Policy

Shortfall tolerance must be configurable and wired into all accounting paths.

Initial defaults:

- BTC direct: 300 sats
- Liquid direct: 60 sats
- Lightning Boltz reverse: 1 sat
- Bitcoin Boltz chain: 300 sats unless a tighter Boltz-delivered amount can be
  proven

Tiny underpayments within tolerance become `paid`. Overpayments remain
`overpaid` for auditability.

If mixed rails are used, apply the tolerance of the event that crosses the
threshold. If implementation starts with a simpler invoice-level tolerance, it
must be documented and tested.

## Boltz Reverse Swaps

Boltz reverse swaps are the Lightning instruction type.

Applies to:

- Lightning Address
- Donation Page
- Invoices

Lifecycle mapping:

- `swap.created`: instruction exists; no product state change.
- `invoice.expired`: BOLT11 unusable; create a replacement only if the session
  remains payable.
- `transaction.mempool`: `payment_status = in_progress`.
- `transaction.confirmed`: `settlement_status = pending`; claim scheduled.
- claim success or recovered successful outspend: record
  `lightning_boltz_reverse:<swap_id>` payment event.
- `claim_stuck`: `settlement_status = claim_stuck`; no false merchant
  settlement.
- `transaction.refunded`: `settlement_status = refunded`; incident.

Accounting event rule:

Do not record a Lightning payment accounting event until merchant-side claim
succeeds or is recovered as successful. The public UX may show "payment
detected" while settlement is pending.

## Boltz Reverse Swap Refresh

Session expiry and BOLT11 expiry are separate clocks.

Rules:

- Create the initial reverse swap when a Donation Page session or
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

BTC-to-LBTC chain swaps are Donation Page only.

They are not part of Lightning Address and not part of merchant invoices in
this phase.

Donation Page behavior:

- expose the Bitcoin instruction only if the remaining amount is above Boltz
  minimum and below Boltz maximum for BTC-to-LBTC
- use the session Liquid address derived from the nym CT descriptor as the
  LBTC destination
- single-flight chain swap creation per session and remaining amount
- do not create a new chain swap after session expiry

Product copy must make settlement clear:

```text
Pay with Bitcoin on-chain. Settles to Liquid through Boltz.
```

Chain swap accounting event:

- record `bitcoin_boltz_chain:<swap_id>` only after LBTC is successfully
  claimed or recovered as received.

Wrong amount, expired lockup, renegotiation, and refund behavior must be
explicit before enabling this instruction. It is a later phase after reverse
swap accounting is stable.

## Direct Liquid

Donation Page:

- server derives the Liquid address and blinding key from the nym CT
  descriptor.

Invoices:

- client supplies a Liquid address
- client must supply the matching single-address blinding key when direct
  Liquid is accepted
- server validates the key matches the address

Clients must use invoice-scoped Liquid addresses. Address reuse is a client
hygiene issue, but server documentation and tests should make the expected
usage clear.

Liquid confirmation policy must be explicit. If direct Liquid is accepted at
0-conf, tests must assert that behavior. If confirmation is required, the
watcher must model `in_progress` before recording the payment event.

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
- configured confirmations are required before recording payment events

## Cancellation

Lightning Address:

- deactivation stops new payment instructions
- existing swaps must still settle

Donation Page:

- archiving a page stops new sessions
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
- Donation Page checkout
- Merchant Invoices
- BTC direct watcher
- Liquid exact accounting
- Boltz reverse swaps
- Boltz chain swaps
- security and authorization
- operational recovery

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
- chain swap only exposed for Donation Page and within Boltz limits

## Phasing

1. Architecture freeze.
2. Event accounting foundation.
3. Direct Bitcoin watcher correctness.
4. Direct Liquid exact accounting.
5. Boltz reverse swap lifecycle and refresh.
6. Donation Page Lightning + Liquid.
7. Merchant Invoices.
8. Donation Page BTC-to-LBTC Boltz chain swaps.
9. Full certification pass.

Each phase requires implementation, focused tests, bullnym-tests updates when
external behavior changes, VM validation when relevant, code review,
architecture review, and an explicit go/no-go before continuing.

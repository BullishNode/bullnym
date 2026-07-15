# Bullnym User Manual

Bullnym lets a merchant receive payments through a Lightning Address, a public
Payment Page, a point-of-sale page, and individual invoices. Payments can use
Lightning, Liquid, or Bitcoin depending on the product and what is available.

Bitcoin, Liquid, and Lightning payments can be irreversible. Check the
recipient, amount, network, fee breakdown, and payment status before approving
a payment. Never send a second payment just because a page is slow to update.

## Release status

This manual was first checked against the public service at
`https://pay2.bull-wallet.com` on 2026-07-15 04:23–04:26 UTC. That deployed
baseline reported clean build
`512fb32b9fec31702b1260314427df4420f8e27c`, schema
`060_lnurl_private_comment_intents`, and permanent-name policy
`permanent_names_v1`.

The complete server/PWA behavior described below is current release source
`e17c465939ccf766ebf77b7d9bd7dbfb776c395d`, tree
`93f9f06f10d58520547a8d4d9ac85064c822fa07`, with expected schema
`062_invoice_quote_provider_attempts`. It was reviewed at PR #177 head
`01fb3f08aeb69e44d1ce71dfd2111ecd63e23253` with the same tree. It includes:

- a fixed 30-day outer invoice lifetime and five-minute payer-demand quotes;
- one stable Liquid destination per invoice and first-observation fiat
  valuation;
- atomic browser quote replacement and the PoS Bitcoin warning;
- product-correct Bitcoin behavior and durable provider recovery/holds;
- permanent names, independent public products, and current-only APIs.

At 2026-07-15 08:03 UTC, the server completed a fresh schema-062 cutover and
installed that exact release. The installed and running binary SHA-256 was
`21628acc96d20475662898bbed851a48b4762c5d2b70b92ecc08910c46cd4873`;
the server-hosted PWA content SHA-256 was
`c193bf22ed5b7fbc0e0463cd8ea90b4154fdad660a77ea74ec0b6ec1e526d09c`.
Public `/health`, `/ready`, and `/version` probes matched the installed commit
and schema.

The read-only deployment certification passed, and the current recovery
generation reconciled with all-zero startup counts. On the exact deployed
restart, direct Bitcoin, reverse Lightning, direct Liquid, and Bitcoin chain
swap admission all opened after their normal startup checks. This is a point-
in-time result, not a promise that every method will always remain available:
`/ready` does not report every rail, and a rail closes if its own safety
foundation degrades. Use only the methods the current page offers. The
schema-062 no-funds smoke later failed when a valid private Page checkout note
reached an obsolete database constraint; the funds gate stayed closed and no
funds moved. The bounded live-money journey was therefore not started.

PR #179 proposes schema `063_checkout_private_memo` and a fee-refresh handoff
fix. At the observed candidate head
`47005c63291d9e37567ae93b70f7dd6e2e273f59`, tree
`1489239cd96ee7554ff8837991c1a17945f718b9`, this is source behavior only. This
manual does not claim that candidate is merged, deployed, migrated, or
journey-certified. This release line changes the server-hosted PWA; it does not
include a mobile-wallet release.

## Nyms, aliases, and permanent ownership

A **nym** is your permanent public Bullnym name. It can appear in your
Lightning Address and web links. One Bullnym identity can claim exactly one
nym.

An **alias** is an optional permanent web name shared by your Payment Page and
PoS. You can have at most one. Nym and alias use one shared namespace, so no
one can claim an alias that conflicts with any nym, or vice versa.

Names are permanent:

- they cannot be renamed, cleared, released, reassigned, or transferred to a
  different identity;
- taking a product offline does not release either name;
- deleting local app data does not release a name;
- changing a wallet or descriptor does not change name ownership.

Choose a name as carefully as you would choose a permanent payment address.
If the app shows a server-returned public URL, share that exact URL rather than
building one yourself.

## Three independent public products

Lightning Address, Payment Page, and PoS availability are independent.

- Turning the Lightning Address offline stops new Lightning Address payment
  instructions. It does not take the Payment Page or PoS offline.
- Archiving or disabling a Payment Page does not release the nym or alias and
  does not take the PoS or Lightning Address offline.
- Archiving or disabling PoS affects only PoS.
- Existing invoices, issued payment instructions, swaps, and recovery work
  remain supervised after a product goes offline.

Without an alias, Payment Page and PoS use nym routes. After an alias is
claimed, the alias can be the preferred public web link while nym routes remain
valid.

## Lightning Address

A Lightning Address looks like `name@domain`. A standard payer wallet resolves
it and receives a Lightning invoice. Bullnym uses a provider swap so the
merchant receives Liquid.

A compatible wallet can request direct Liquid through the LUD-22 extension.
That path asks the payer to prove ownership of a Liquid UTXO. It avoids the
Lightning swap but reveals that UTXO and its blinding information to Bullnym,
so it has a different privacy tradeoff.

Taking the Lightning Address offline prevents new instructions but does not
cancel a payment already in progress. Permanent name ownership and private
received-payment history remain available to the owner.

## Payment Page and PoS

A Payment Page lets the payer enter an amount. PoS is a cashier-oriented page
for in-person payments. They use separate Liquid receive descriptors and
cursors, so their payment activity does not share one receive stream.

The payer can usually choose among:

- Lightning through a provider reverse swap;
- direct Liquid;
- Bitcoin through a Bitcoin-to-Liquid provider chain swap.

Opening or refreshing the public page does not by itself allocate a payment
address. Creating the checkout does. A rail may be temporarily absent if its
provider, live fee evidence, recovery commitment, or watcher is not ready.
That is a safety refusal; it does not mean the other independent rails are
unavailable.

PoS stores receipt history in the local browser. Clearing browser data can
erase that local list, but it does not change the server's invoice or payment
records.

Page and PoS checkout may include an optional note. Under the schema-063
contract it is trimmed, stored as the invoice's private memo, and returned only
through the merchant's signed invoice history. It is not shown on public status
or invoice pages. Recipient label, public description, and invoice number are
wallet-origin invoice fields; checkout cannot supply them as public metadata.

In the merged release, PoS shows this warning before it reveals a Bitcoin
instruction or asks the provider to create one:

> For in-person payments, Lightning network is recommended. Bitcoin on-chain
> payments can be cancelled by the sender for up to a few hours, and should not
> be considered safe until confirmed.

The confirmation button reads **I understand**. Acknowledgement belongs only to
that invoice in the current browser-tab session; a new invoice requires a new
decision. Going back selects a safer available rail. Payment Page and
wallet-origin invoices do not show this PoS-specific dialog. Regardless of the
dialog, merchants still choose their own confirmation policy for in-person
Bitcoin payments.

## Creating an invoice

An invoice is a receivable with an amount, description, deadline, accepted
payment methods, and merchant-controlled settlement destinations. Depending on
the client, it may be linked to a nym or shared through a generic private URL.
Anyone with the invoice URL can read its public payment details, so share it
only with the intended payer.

When creating an invoice:

1. Choose sats or a supported fiat currency.
2. Enter a clear description and, if useful, your internal invoice number.
3. Enable only the rails you can reconcile.
4. Review the deadline returned by the server.
5. Share the exact returned URL.

Direct Bitcoin needs a merchant Bitcoin address. Direct Liquid and Lightning
settlement need a merchant Liquid destination; direct Liquid also needs the
matching blinding information. The merchant wallet should use invoice-scoped
receive addresses and retain the keys needed to recognize and spend them.

The merged release defaults to 30 days and rejects a deadline more than
30 days in the future. A shorter caller-selected deadline must be at least
60 seconds in the future when the server processes it. A five-minute payer
quote never extends that outer deadline.

## Sat-fixed and fiat-fixed invoices

A **sat-fixed** invoice asks for a fixed number of sats. Exchange-rate movement
does not change its face amount.

A **fiat-fixed** invoice asks for a fixed amount such as USD 25.00. In the
merged release, the merchant's exact fiat minor-unit amount and currency
remain the invoice face value for up to 30 days. Invoice creation does not
freeze a sat amount and does not create a provider obligation.

The payer-facing conversion is an immutable five-minute quote for one selected
rail. The server reuses the same live quote version when possible; after its
exclusive expiry, the PWA retires all old instruction fields and requests a new
version for the selected rail. It replaces the amount, cost breakdown, QR,
copy text, Lightning invoice, or Bitcoin URI together. Copy and payment actions
stay disabled while no complete current instruction exists, and a slow response
from an older request cannot replace a newer version.

Public status and other GET requests remain read-only projections. The PWA's
initial selection, rail selection, manual refresh, or expiry timer makes the
explicit payer-demand POST. A crawler cannot create a provider obligation by
loading the page.

## Stable Liquid invoice address

One checkout invoice uses one concrete Liquid settlement destination. The
address is not resolved again from mutable profile data during settlement.

In the merged release, that same Liquid address remains stable for the
entire outer invoice lifetime, up to 30 days, across partial payments and every
five-minute quote refresh. Only the amount, valuation, QR, and copy payload
change. Lightning and Payment Page/PoS Bitcoin provider swaps also settle to
this invoice-scoped Liquid destination.

Always compare the whole current instruction, not only the address. A familiar
address does not prove that a copied amount or old QR still has a valid rate.

## Why payer amounts can differ by rail

The merchant's face value and the payer's send amount are not always the same.
For a fixed checkout, the payer covers applicable provider and payment-network
costs so the merchant can receive the face value.

- Direct Liquid generally asks for the merchant remainder. The payer wallet
  can add its own Liquid network fee.
- Lightning can include provider/settlement cost in the Lightning invoice. The
  payer wallet can add its own routing fee.
- Payment Page/PoS Bitcoin can ask for more than the merchant face value because
  it funds a Bitcoin-to-Liquid swap and recovery budget. The payer's Bitcoin
  wallet adds the source transaction fee on top.
- A wallet-origin direct Bitcoin invoice asks for the merchant output amount;
  the payer wallet adds its Bitcoin transaction fee.

These Bitcoin products are intentionally different. Requesting a wallet-origin
direct Bitcoin fiat quote returns the invoice's merchant Bitcoin address and
does not contact Boltz. Payment Page and PoS Bitcoin requests create or recover
a Boltz BTC-to-LBTC chain offer; PoS does so only after the invoice-scoped risk
acknowledgement.

The page should display a typed amount for each available rail. Use that amount
and the complete QR or copy payload. Do not rebuild a Bitcoin URI from the
smaller headline amount.

Lightning Address is different: the sender chooses the amount through LNURL.
It is not a merchant-declared fixed-price checkout and is outside this gross-up
rule.

## Underpayment, partial payment, and overpayment

If less than the amount due arrives, the invoice normally remains partial and
shows a remaining balance. A small configured tolerance can count a slight
shortfall as paid; the server owns that calculation. Do not calculate it from
the screen yourself.

If more arrives, the overpayment remains recorded. Bullnym does not
automatically refund an overpayment. The merchant should compare the invoice,
actual received value, rail, and settlement status before deciding what to do.

For a merged-release fiat invoice, each payment event receives fiat credit
from its own authoritative rate evidence. Sats first durably observed before a
quote expires keep that quote's rate, but only for the sats actually observed.
An underpayment does not lock the old rate for the unpaid balance.

Sats first observed at or after expiry will require a trustworthy rate snapshot
covering the observation time. If none exists, the money remains visible but
unvalued and cannot complete the invoice. Bullnym will not guess with a later
unrelated market rate. A later payment therefore uses the rate authoritative at
its own first observation, not the first partial payment's rate.

After valued partial payments, the next quote covers only the remaining fiat
face value. It does not reprice fiat credit already committed to earlier
payment events.

## Quote expiry, stale QR codes, and repeated clicks

Under the merged-release contract, the invoice and its five-minute quote are
separate clocks. A copied Lightning invoice or Bitcoin swap instruction may
expire before the 30-day outer invoice. Bullnym refuses to create a new quote
when the outer invoice has less than a complete five-minute window remaining.

When a quote expires:

- do not pay a QR after its countdown expires;
- wait until the page replaces every instruction field;
- do not copy or pay while refresh is pending;
- an old provider instruction can still receive money, so Bullnym will continue
  supervising it even after a new one appears;
- a direct Liquid payment will be valued from its durable observation time,
  not from a guessed old QR version.

Repeated clicks or reloads should converge on one current instruction. If the
page is uncertain, check status before trying again. A second successful send
is a second payment, not a harmless retry.

## Payment received versus settlement pending

“Payment received” describes what the merchant can see now. “Settlement
pending” means the final merchant-side outcome is still being confirmed or
completed.

For direct Bitcoin and Liquid, verified zero-confirmation evidence can be shown
immediately. Accounting activates at one confirmation, and the default
operational finality is three Bitcoin confirmations or two Liquid
confirmations. A conflict or reorg can demote the evidence without erasing the
history.

Provider-backed Lightning and Bitcoin payments also have a separate settlement
step. The payer can complete their side while Bullnym still claims Liquid or,
in an exceptional chain-swap failure, supervises Bitcoin fallback.

Do not release high-value or irreversible goods merely because a calm paid
screen appeared. Decide what confirmation or settlement level your business
requires. Bullnym does not provide a financial guarantee against every
double-spend, reorg, provider, server, or backup failure.

## Cancellation, expiry, and archive

**Cancel payment request** stops the invoice from issuing new payment
instructions. It cannot revoke a QR, address, Lightning invoice, or provider
offer already copied by a payer.

If money arrives after cancellation or expiry, Bullnym keeps it attached to the
original invoice as a late payment. The request remains closed. The payment is
not hidden and is not automatically refunded.

Archive has a different meaning:

- archiving a Payment Page or PoS controls that public surface;
- existing checkout invoices remain supervised;
- archive is presentation-only; the merged release does not define a
  separate public invoice-archive action.

A late, partial, overpaid, failed, or reorged payment remains part of the
invoice history. Clearing a notification may clear attention, never the money
record.

## Automatic Bitcoin recovery

Bitcoin-to-Liquid chain swaps are used by Payment Page and PoS. If the normal
Liquid settlement path cannot complete, Bullnym can recover the payer-funded
Bitcoin to one address previously committed by the merchant.

That address comes from the merchant's default Bitcoin wallet. Bullnym receives
the address and authorization, not the wallet private key. Each swap keeps the
exact commitment version it received before the payer saw an instruction.
Changing the default wallet later does not redirect an existing swap.

Recovery is automatic. The phone does not choose an address after failure and
does not need a “Recover” button. Bullnym first prefers normal Liquid
settlement, then safe wrong-amount renegotiation. Missing, delayed, or
conflicting evidence waits or enters review; it must not trigger an eager
Bitcoin transaction.

The merged release requires the complete current recovery contract before
automatic recovery may contact the provider or either chain. Every recorded
Bitcoin recovery transaction must also retain the exact fee evidence that
authorized its construction. A missing or disputed contract, or incomplete
transaction authority, stays on hold rather than using an older compatibility
path.

Quote-scoped provider creation is also crash-aware. Bullnym records the exact
request before sending it, then records dispatch and completion as durable
one-way evidence. After an ambiguous timeout or restart it does not blindly
send the provider request again. It validates a recoverable chain-swap result,
or leaves the attempt in an integrity hold when the provider cannot prove a
complete matching result. A held instruction may be temporarily unavailable;
that is safer than creating a second irreversible obligation.

On wallet restore, verify that the committed address belongs to the restored
default Bitcoin wallet and restore its local label. Do not register a new
address merely because a label was lost. A broadcast recovery transaction is
still settlement pending until its chain evidence confirms.

## Privacy and payer comments

Invoice URLs reveal payment addresses and status to anyone who has the URL.
Treat them as private share links. A nym or readable alias is publicly
enumerable and links the payment surface to that name.

A payer can add a Lightning Address comment of up to 120 user-visible Unicode
characters, with a defensive 512-byte limit. Bullnym stores the accepted text
privately before returning the Lightning instruction and associates it with the
eventual payment.

The server exposes a comment only after payment evidence exists and only in an
authenticated merchant history request. The deployed baseline supports this
private history API and the merged release preserves it; whether a separate
client release displays it depends on that client. Comments are not supposed
to appear in public pages, anonymous status, Open Graph previews, provider
descriptions, logs, or metric labels. Direct-Liquid comments fail closed rather
than being silently dropped.

Treat comments as untrusted plain text. A comment is not customer identity,
proof of purchase, or permission to change the payment amount or destination.

## Common payer mistakes

| Mistake | What can happen | What to do |
|---|---|---|
| Wrong amount | Partial payment, overpayment, or failed provider swap | Stop and check invoice status; contact the merchant before another send |
| Duplicate payment | Two real payments can arrive | Do not click/pay again until status is checked |
| Old QR or Lightning invoice | Instruction can be expired while the outer invoice remains open | Reload and use the current complete instruction |
| Wrong rail or network | Funds may not reach the intended script/address | Verify Lightning, Bitcoin mainnet, or Liquid before approving |
| Insufficient wallet balance | Wallet may reject or send less than required | Include displayed amount plus wallet fee headroom |
| Browser reload during payment | The page may briefly show stale local state | Preserve the invoice URL and wait for authoritative status |
| Payment after cancel/expiry | Merchant can still receive a late payment | Contact the merchant; do not expect an automatic refund |
| Abandon and reopen | An old provider instruction may still exist | Use the same invoice URL and compare the current payload before paying |

Malformed addresses should be rejected before an instruction is created. If a
wallet accepts a payload that looks wrong, do not send and report the complete
error code without sharing keys, seeds, signatures, or a full private invoice
URL.

## When payment is delayed or needs review

For a payer:

1. Keep the invoice URL and your wallet's transaction or payment identifier.
2. Do not send again.
3. Wait for the page to refresh and check whether it says payment received,
   partial, settlement pending, expired, or cancelled.
4. Contact the merchant with the minimum identifier needed to locate the
   payment. Never send a seed, private key, signature, or wallet backup.

For a merchant:

1. Open the original invoice, not only the generic wallet transaction.
2. Compare face amount, actual paid amount, rail, time, payment event, and
   settlement state.
3. Preserve a late-payment or resolution warning until it is reconciled.
4. If automatic fallback is in progress, wait; do not derive or submit another
   destination.
5. Escalate a payment that remains pending beyond the normal rail time with the
   invoice identifier, redacted transaction/provider identifier, approximate
   time, and the server version. Do not publish private comments or payment
   secrets.

Unsafe ambiguity is intentionally visible as pending, reconciling, or an
integrity hold. That can be slower than guessing, but it prevents Bullnym from
choosing two conflicting irreversible outcomes.

## Evidence sources

Historical baseline behavior was checked against the first deployed probe
above. Current-release behavior was checked against Bullnym source and tests at
`e17c465939ccf766ebf77b7d9bd7dbfb776c395d`, whose reviewed PR #177 head was
`01fb3f08aeb69e44d1ce71dfd2111ecd63e23253` with the same tree, plus the
product/API/architecture documents in this repository and the locked
completion-plan, rationale, and server/PWA gap-audit records maintained outside
this repository.

The later public probes, artifact digests, and read-only certification prove
deployment identity and public readiness. Exact deployed startup evidence also
proved the current recovery generation and observed all four private rails
open on that restart. The Operator Manual records that evidence and its
limits. The schema-062 no-funds smoke failure and its zero-funds boundary are
recorded there. Candidate schema-063 behavior was checked at observed PR #179
head `47005c63291d9e37567ae93b70f7dd6e2e273f59`; the schema-063 no-funds rerun
and bounded live-money journey remain separate outstanding certification work.

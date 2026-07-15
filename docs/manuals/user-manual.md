# Bullnym User Manual

Bullnym lets a merchant receive payments through a Lightning Address, a public
Payment Page, a point-of-sale page, and individual invoices. Payments can use
Lightning, Liquid, or Bitcoin depending on the product and what is available.

Bitcoin, Liquid, and Lightning payments can be irreversible. Check the
recipient, amount, network, fee breakdown, and payment status before approving
a payment. Never send a second payment just because a page is slow to update.

## What is available now

This manual was checked against the public service at
`https://pay2.bull-wallet.com` on 2026-07-15 04:23–04:26 UTC. The deployed
server reported clean build
`512fb32b9fec31702b1260314427df4420f8e27c`, schema
`060_lnurl_private_comment_intents`, and permanent-name policy
`permanent_names_v1`.

The server source has moved ahead of production. This matters for invoice
lifetimes and fiat quotes:

| Behavior | Status at the time of writing |
|---|---|
| Permanent nym ownership, independent Lightning Address/Page/PoS availability, private Lightning payer comments, automatic recovery supervision | Deployed |
| 30-day invoice outer lifetime, quote database foundation, and stricter automatic-recovery safety checks | Merged in source `9c7c595906c9b0341bbd7735a6d3785890c3bbbe`, not deployed |
| Five-minute payer-demand fiat quotes, observation-time fiat credit, atomic browser refresh, and PoS Bitcoin warning | Locked behavior with unmerged implementation branches; not deployed |

Production still uses a maximum seven-day invoice lifetime and converts a fiat
price once when an invoice is created. Do not expect a five-minute quote
countdown or 30-day deadline until `/version` and release notes confirm that the
complete quote release is deployed.

Sections marked **Locked next behavior** explain the approved contract without
pretending it is live.

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

**Locked next behavior:** Before PoS reveals a Bitcoin instruction, it will show
this warning:

> For in-person payments, Lightning network is recommended. Bitcoin on-chain
> payments can be cancelled by the sender for up to a few hours, and should not
> be considered safe until confirmed.

The button will read **I understand**. This warning is not present on the
deployed SHA, so merchants must currently apply their own confirmation policy
for in-person Bitcoin payments.

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

The deployed server defaults to seven days and rejects a deadline later than
seven days. Source main changes that outer limit to 30 days, but production has
not adopted it yet.

## Sat-fixed and fiat-fixed invoices

A **sat-fixed** invoice asks for a fixed number of sats. Exchange-rate movement
does not change its face amount.

A **fiat-fixed** invoice asks for a fixed amount such as USD 25.00. On the
deployed server, that fiat amount is converted once at invoice creation and the
resulting sat amount stays fixed for the invoice's seven-day life. This is the
older behavior and creates exchange-rate exposure.

**Locked next behavior:** The merchant's fiat minor-unit amount and currency
will remain the face value for a 30-day invoice. A payer-facing conversion will
last five minutes. Reloads inside that window will reuse the same quote. After
expiry, an explicit payer-demand refresh will replace the amount, cost
breakdown, QR, copy text, Lightning invoice, and Bitcoin URI together.

A read-only page load, status request, crawler, or background timer must not
create a provider obligation. The full five-minute behavior is not available
until the quote runtime and browser changes are deployed together.

## Stable Liquid invoice address

One checkout invoice uses one concrete Liquid settlement destination. The
address is not resolved again from mutable profile data during settlement.

**Locked next behavior:** The same Liquid address will remain stable for the
entire 30-day invoice across partial payments and every five-minute quote
refresh. Only the amount, valuation, QR, and copy payload change. The deployed
server has no quote refresh, so the across-refresh guarantee cannot yet be
exercised in production.

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

**Locked next behavior for fiat:** Each payment event receives fiat credit from
its own authoritative rate evidence. Sats first durably observed before a quote
expires keep that quote's rate, but only for the sats actually observed. An
underpayment does not lock the old rate for the unpaid balance.

Sats first observed at or after expiry will require a trustworthy rate snapshot
covering the observation time. If none exists, the money remains visible but
unvalued and cannot complete the invoice. Bullnym will not guess with a later
unrelated market rate. This accounting is not deployed yet.

## Quote expiry, stale QR codes, and repeated clicks

On the deployed server, fiat is converted once and there is no five-minute
quote refresh. The invoice and provider payment instructions can still have
different expiry times. A copied Lightning invoice or Bitcoin swap instruction
may expire before the outer invoice.

When the five-minute quote system ships:

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
- the locked invoice model treats archive as presentation-only, but a separate
  invoice-archive action is not documented as available on the deployed
  server.

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

Newer source code, not yet deployed, tightens this rule: automatic recovery
must have the complete current recovery contract and recorded fee evidence
before it may contact the provider or either chain. Missing or disputed
authority stays on hold rather than using an older compatibility path.

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
authenticated merchant history request. The deployed server supports this
private history API; whether a particular client release displays it in the app
depends on that client. Comments are not supposed to appear in public pages,
anonymous status, Open Graph previews, provider descriptions, logs, or metric
labels. Direct-Liquid comments currently fail closed rather than being silently
dropped.

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

Current behavior was checked against the deployed probe above, Bullnym source
and tests at `9c7c595906c9b0341bbd7735a6d3785890c3bbbe`, the product/API/
architecture documents in this repository, and these read-only authority
records:

- `/home/francis/bull-bitcoin-workspace/bullnym-client-server-completion-plan.md`;
- `/home/francis/bull-bitcoin-workspace/bullnym-rationale-review-record.md`;
- `/home/francis/bull-bitcoin-workspace/server-pwa-locked-plan-gap-audit-20260715.md`.

The full unmerged quote/PWA/PoS branch revisions are listed in the Operator
Manual. Their presence is implementation evidence only, not proof that the
feature is safe, merged, or available.

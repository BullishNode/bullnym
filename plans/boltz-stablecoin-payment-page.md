# Boltz Stablecoin Payment Page Integration Plan

Status: **ARCHITECTURE BLOCKED AT GATE 0**

Prepared: 2026-07-09

Scope: Bullnym Payment Pages only, including nym and alias Payment Page
surfaces. POS, wallet-created invoices, Lightning Addresses, and merchant
stablecoin custody are out of scope.

Target outcome: a payer selects a stablecoin on a Bullnym Payment Page, uses
Boltz's official web tool to pay, and the recipient receives L-BTC at the
invoice's existing descriptor-derived Liquid address.

## 1. Executive Decision

The leading candidate is to use the official hosted Boltz Web App as the
payer-controlled stablecoin swap client. Do not add raw stablecoin REST calls
to Bullnym's Rust backend, copy the Boltz wallet stack into the Bullnym PWA, or
make Bullnym hold payer EVM refund keys.

The candidate production path, if Gate 0 passes, is:

```text
Bullnym Payment Page invoice
  -> fresh, amount-locked Bullnym BOLT11
  -> official Boltz Web App (payer-controlled stablecoin swap)
  -> BOLT11 is paid
  -> Bullnym's existing Lightning-to-Liquid reverse swap settles
  -> recipient receives L-BTC at invoice.liquid_address
```

This would deliberately reuse Bullnym's current recipient-side settlement
system. The new integration would be a payer handoff, not a second server-side
swap engine.

The staged delivery is:

1. **External handoff first.** The Stablecoin rail opens a top-level
   `https://boltz.exchange` page in a new tab. This keeps the payer on Boltz's
   first-party origin and works without changing Boltz's current framing
   policy. Recovery after storage or tab loss is not assumed; Gate 0 must prove
   it or define the loss state as a no-go.
2. **Hosted iframe second.** Embed the same tool only after Boltz allowlists the
   exact Bullnym origins, the required browser recovery matrix passes, and the
   parent treats `postMessage` only as a refresh hint.
3. **Direct stablecoin-to-L-BTC later, if warranted.** Evaluate a direct route
   only after Boltz supports and documents immutable Liquid destination and
   amount parameters for merchant use. The reviewed web app currently applies
   `lockOutput=true` only to a decoded BOLT11, not to a Liquid address plus a
   separate amount.

No durable Bullnym schema, API, or UI work should start until Gate 0 proves that
a Boltz stablecoin-to-Lightning swap can be created for and pay the BOLT11 of a
Bullnym reverse swap on the same Boltz deployment. Boltz documents a `409` when
a swap already exists for an invoice or preimage hash; the reverse swap already
owns the BOLT11 payment hash, so duplicate-hash scope may reject the candidate
source swap before funding. The same-node/cross-node payment path and timeout
ordering are also unproven. These are existential architecture questions, not
implementation details. Verify against the current
[REST API v2 contract](https://api.docs.boltz.exchange/api-v2.html) and written
Boltz guidance rather than inferring scope from an error string.

## 2. Why This Boundary Is Required

Boltz's official API documentation says integrations must use an officially
supported client, SDK, or library rather than hand-written REST integration.
It also says Boltz integrations should be client-side so the end user controls
swap and refund material. See:

- [Boltz API introduction](https://api.docs.boltz.exchange/)
- [Clients, SDKs and libraries](https://api.docs.boltz.exchange/libraries.html)
- [Common integration mistakes](https://api.docs.boltz.exchange/common-mistakes.html)
- [Claims and refunds](https://api.docs.boltz.exchange/claiming-swaps.html)

The supported library matrix matters:

| Library/client | Stablecoin support | Suitable Bullnym role |
|---|---:|---|
| Boltz Client, server-side | No; LN/BTC/LBTC | Existing recipient settlement only |
| Breez SDK, client-side | No; LN/BTC/LBTC | Not a stablecoin solution |
| Boltz Rust | No; LN/BTC/LBTC | Existing Bullnym swap code only |
| Boltz Core, TypeScript | Yes; includes USDT/USDC | Low-level browser implementation, high integration cost |
| Boltz Web App | Yes | Recommended payer-controlled tool |

The official stablecoin product is a routed browser flow, not a direct
stablecoin pair that Bullnym can safely create with one Rust request. Boltz
describes the route as a DEX leg joined to a Boltz swap leg through tBTC on
Arbitrum. The current web app also has extensive wallet, approval, Permit2,
commitment, bridge, retry, claim, refund, and rescue logic. See:

- [Boltz routed-swap explanation](https://blog.boltz.exchange/p/introducing-usdt-swaps-from-sats)
- [Commitment swaps](https://api.docs.boltz.exchange/commitment-swaps.html)
- [Boltz Web App repository](https://github.com/BoltzExchange/boltz-web-app)

Reviewed upstream snapshot:

- Repository: `BoltzExchange/boltz-web-app`
- Commit: [`a340ec381d48dacf02b54e4a3d267c1c74a747f3`](https://github.com/BoltzExchange/boltz-web-app/commit/a340ec381d48dacf02b54e4a3d267c1c74a747f3)
- Reviewed on: 2026-07-09

This commit is a source reference, not proof of what the hosted origin deploys.
The hosted response observed that day reported an older `Last-Modified` date.
Production behavior must be identified and smoke-tested independently.

At that snapshot, canonical `USDT0` and `USDC` are six-decimal ERC-20 assets on
Arbitrum and route through `TBTC`. The web app also supports many bridged
variants, but those introduce separate OFT, CCTP, Solana, or Tron state
machines. See the
[pinned mainnet preset](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/packages/boltz-swaps/src/presets/mainnet.ts#L160-L217).

## 3. Product Scope

### 3.1 Included in v1

- Nym Payment Pages at `/<nym>`.
- Payment Page aliases at `/a/<slug>` when the alias resolves to
  `kind = 'payment_page'`.
- The PWA payment flow at `#/pay/<invoice_id>`.
- The canonical server-rendered invoice at `/<nym>/i/<invoice_id>` or
  `/a/<slug>/i/<invoice_id>`.
- Stablecoin as a payment rail after the sat amount has been fixed.
- Hosted Boltz Web App handoff.
- `USDT0` and `USDC` as the initially advertised choices, defaulting to their
  canonical Arbitrum variants.
- Existing Bullnym Lightning-to-Liquid settlement and accounting.

### 3.2 Explicitly excluded from v1

- POS, including POS aliases.
- Wallet-created linked and unlinked invoices.
- Stablecoin as an amount denomination.
- Bullnym stablecoin balances, deposit addresses, sweeping, or custody.
- Bullnym EVM RPC, WalletConnect, Permit2, token approval, bridge, or refund
  code.
- Raw Boltz stablecoin REST integration in Rust.
- A Bullnym-owned `stablecoin_swap_records` state machine.
- Server storage of payer wallet addresses, stablecoin transaction hashes,
  rescue mnemonics, refund keys, or browser swap metadata.
- Advertising non-Arbitrum networks during the initial rollout.
- Treating an iframe message or Boltz status as proof that Bullnym was paid.

### 3.3 Merchant configuration

MVP is operator-controlled and canary-scoped. It does not change the signed
mobile donation-page management contract.

If merchant opt-in is later required, add it through a new versioned, fixed
field signing action coordinated with Bull Bitcoin Mobile. Do not append
another ambiguous optional boolean to the existing donation-page save payload.

## 4. Candidate Payment Flow

This section is conditional. It becomes the selected flow only after Gate 0
proves that Boltz permits the nested payment hash and supports every production
Lightning-node assignment.

### 4.1 Invoice creation

1. The payer enters a fiat, BTC, or sat amount on the Payment Page.
2. Bullnym creates the checkout invoice through the existing
   `create_anonymous_for_kind` path.
3. Bullnym allocates and persists the invoice's unique confidential Liquid
   address and blinding key from the Payment Page descriptor.
4. Bullnym creates or can lazily create the existing amount-specific BOLT11.
5. The invoice snapshots `checkout_surface_kind = 'payment_page'` so an id-only
   status request cannot confuse it with a POS invoice.

No stablecoin swap exists at this point.

### 4.2 Stablecoin handoff

1. The payer selects the Stablecoin rail.
2. The client requests a click-time handoff from Bullnym. That write endpoint
   rechecks eligibility and obtains a purpose-specific BOLT11 with enough
   invoice and offer lifetime.
3. Bullnym constructs the Boltz Web App URL on the server from a fixed
   operator-configured origin and a strict parameter allowlist.
4. Once preparation succeeds, the client renders a real external link. A
   second explicit payer gesture opens it in a new top-level tab with no opener
   or referrer, avoiding popup blocking after asynchronous work.
5. The payer connects a wallet and approves the stablecoin transaction inside
   the Boltz origin. Bullnym never receives wallet permissions.
6. The official tool owns stablecoin quoting, wallet/network selection,
   approval, transaction submission, retries, and payer refunds. Recovery from
   lost browser state is a Gate 0 requirement, not an assumed capability.
7. The original Bullnym tab continues polling the invoice status.

### 4.3 Recipient settlement

1. Boltz's stablecoin swap pays the locked Bullnym BOLT11.
2. Bullnym's existing reverse-swap state moves to settlement progress.
3. The existing Bullnym claimer claims L-BTC to the persisted
   `invoice.liquid_address`.
4. Existing invoice payment accounting records the recipient-side settlement.
5. The Payment Page renders paid, partial, overpaid, or a settlement failure
   from Bullnym's own status response.

The stablecoin source swap and the recipient Lightning-to-Liquid swap have
different recovery owners:

| Operation | Owner |
|---|---|
| Stablecoin wallet approval and funding | Payer in Boltz Web App |
| Stablecoin refund or rescue | Payer in Boltz Web App |
| Paying the destination BOLT11 | Boltz stablecoin flow |
| Claiming recipient L-BTC | Existing Bullnym server flow |
| Invoice accounting | Bullnym |

## 5. Accounting Invariants

Keep these amounts distinct:

| Value | Meaning |
|---|---|
| `invoice_face_sat` | The Bullnym amount the payer is asked to satisfy. |
| `stablecoin_input_atomic` | Token base units the payer authorizes after Boltz's live quote, fees, and slippage. |
| `reverse_server_lock_sat` | L-BTC Boltz locks for Bullnym's existing reverse swap after provider economics. |
| `merchant_net_lbtc_sat` | Actual unblinded L-BTC output at `invoice.liquid_address` after the Liquid claim fee. |

V1 explicitly preserves Bullnym's current merchant-fee contract:

```text
BOLT11 face amount = remaining_amount_sat = invoice credit amount
merchant_net_lbtc_sat = reverse_server_lock_sat - Liquid claim transaction fee
```

The merchant therefore receives less physical L-BTC than the invoice face
amount by the existing reverse-swap and Liquid claim economics. Gate 0 must
measure, document, and obtain product acceptance for that formula. UI and API
copy must not claim exact net L-BTC settlement.

If the product instead requires `merchant_net_lbtc_sat >= invoice_face_sat`,
stop this plan and design separate `bolt11_gross_sat` and `invoice_credit_sat`
semantics. That larger change must persist both amounts, validate the BOLT11
against the gross formula, and credit only verified merchant output without
using the gross BOLT11 face as invoice evidence. It is not silently folded into
this v1 integration.

1. **Bullnym status is authoritative.** A wallet signature, token approval,
   EVM transaction, bridge completion, Boltz quote, source-swap status, or
   `postMessage` never marks the invoice paid.
2. **The BOLT11 fixes the Lightning face amount.** Do not pass `sendAmount` or
   `receiveAmount`; the decoded BOLT11 amount takes precedence and
   `lockOutput=true` locks the receive side in the reviewed tool.
3. **Settlement remains L-BTC.** The recipient destination and blinding key are
   the existing invoice fields. Never rederive the destination after invoice
   creation and never send the blinding key to Boltz.
4. **No false stablecoin attribution.** Bullnym can prove that its BOLT11 was
   paid and L-BTC settled. It cannot prove which token the payer ultimately
   selected in an external tool. Keep `paid_via` and accounting evidence on
   the existing Lightning/Liquid settlement vocabulary.
5. **A handoff is not a reservation.** Opening Boltz must not set the invoice
   to `in_progress`. Only existing money evidence can change server state.
6. **Mixed-rail overpayment remains possible.** If another rail settles while
   a stablecoin swap is already committed, the later payment must still be
   recorded. Never discard real settlement to preserve a UI expectation.
7. **The handoff endpoint is the launch gate.** Feature disablement makes new
   click-time handoff requests fail closed. Existing BOLT11s, reverse swaps,
   claims, reconciliation, and payer recovery remain usable. A payer can always
   paste a public BOLT11 into another wallet manually; the flag controls only
   Bullnym-originated handoffs.
8. **Unknown states fail closed.** The payer sees waiting or a generic failure;
   no browser-only event can force a success state.

The receipt may use non-accounting copy such as "Started with Stablecoin" only
in the same local browser session. It must not change merchant reporting to
"paid by stablecoin" without authoritative evidence.

## 6. Gate 0: Vendor and End-to-End Contract

Owners: Bullnym technical lead and Boltz engineering/support

Code allowed before this gate passes: documentation and disposable proof
fixtures only. Do not land durable invoice migrations, public APIs, config, or
UI for a route that Boltz may reject at creation.

### 6.1 Prove the nested Boltz flow

Build an automated Boltz regtest/Anvil scenario that performs all of the
following on one Boltz deployment:

1. Create an LN-to-L-BTC reverse swap, producing the BOLT11 Bullnym would
   expose.
2. Attempt to create a canonical Arbitrum USDC-to-LN or USDT0-to-LN routed swap
   whose destination is that exact BOLT11. Capture whether Boltz returns the
   documented duplicate invoice/preimage-hash `409`, and obtain a written
   statement of whether uniqueness is global or scoped by swap type.
3. Fund the stablecoin route from a payer-controlled EVM wallet.
4. Confirm that the source swap pays the BOLT11 rather than rejecting a
   same-instance/self-issued invoice.
5. Confirm that the reverse swap locks L-BTC.
6. Claim the L-BTC to a confidential Liquid address.
7. Verify the actual output asset, amount, destination, and invoice status.
8. Repeat with source WebSocket disconnect, REST polling outage, tab
   suspension, out-of-order status, browser restart after funding, and Bullnym
   restart before the L-BTC claim.
9. Exercise payer rejection/refund before the destination BOLT11 is paid.
10. Exercise same-node and every supported cross-node assignment between the
    source Submarine Swap payment and destination Reverse Swap hold invoice.
11. Test reorg and delayed settlement near every source refund, Lightning
    invoice, reverse lockup, and Liquid claim/refund deadline.
12. Prove the v1 merchant-fee contract using `invoice_face_sat`, payer token base
    units, reverse server lock, Liquid claim fee, and actual unblinded merchant
    output as separate assertions.
13. Prove outer-invoice expiry before source funding, while the Lightning HTLC
    is pending, and after L-BTC lockup but before claim.
14. Drop the response to reverse-swap creation after Boltz accepts it, restart
    Bullnym, and recover the original provider swap without creating another.

Then run a capped mainnet canary with Boltz's written approval. Public Boltz
testnet is deprecated; local regtest plus a low-value mainnet canary is the
required progression.

### 6.2 Lock the hosted-tool contract

Obtain written confirmation for:

- Production stablecoin-to-Lightning support, including USDC and USDT0 send
  directions.
- Whether an existing Reverse Swap and a new Submarine Swap may reference the
  same BOLT11/payment hash, despite the documented duplicate-hash `409`.
- A guarantee covering every production Lightning-node pairing: self-payment,
  circular routing, hold-invoice behavior, anti-loop policy, and node failover.
- A safe timeout ladder in which source EVM refund, destination BOLT11 expiry,
  reverse L-BTC lock/refund, Bullnym claim, and outer invoice expiry cannot
  strand payer or recipient funds.
- A supported idempotency key or authoritative lookup that recovers an accepted
  Reverse Swap after the create response is lost. Duplicate-hash `409` without
  the original swap ID and response is not sufficient recovery.
- Whether `https://boltz.exchange` or a distinct stable production origin is
  the supported merchant handoff.
- The vendor-supported focused-tool pathname. The reviewed source renders the
  marketing Hero at `/` in external mode and the focused creator at `/swap`;
  Bullnym must not guess which path is a stable contract.
- Stability and versioning of `destination`, `sendAsset`, `receiveAsset`,
  `lockOutput`, `embedded`, `parentOrigin`, `theme`, and `ref`.
- The guarantee that `lockOutput=true` with an amount-bearing BOLT11 prevents
  edits to the destination, receive amount, direction, and receive asset.
- Whether the send asset/network remains intentionally selectable.
- Minimum remaining BOLT11 lifetime required before stablecoin funding starts.
- Combined limits and fee behavior for stablecoin-to-LN followed by
  LN-to-L-BTC on the same deployment.
- Behavior when the BOLT11 expires after stablecoin funding but before
  payment.
- Payer rescue behavior after browser close, storage loss, account change, or
  commitment rejection.
- A safe resume/history URL or creation callback that reopens an existing
  source attempt and cannot silently create a second attempt for the same
  single-use BOLT11.
- Successful refund/recovery after loss of existing Boltz-origin browser
  storage. The reviewed EVM-source route does not necessarily force a rescue
  mnemonic backup. Production requires either verified recovery after cleared
  storage or a mandatory, verified pre-funding backup flow. Otherwise launch
  is blocked.
- A way to identify the hosted build/version, plus a supported deployed-build
  smoke test for URL parsing, USDC/USDT0-to-LN, `lockOutput`, and recovery.
- Partner/referral ID, support expectations, incident contact, and change
  notification process.

### 6.3 Lock the iframe contract

Iframe rollout additionally requires:

- Boltz adding each exact Bullnym production and staging origin to its
  `frame-ancestors` policy.
- A documented `postMessage` schema and status stability policy.
- Recommended iframe `sandbox` and Permissions Policy attributes for desktop
  and mobile wallets.
- Confirmation that third-party storage partitioning does not make recovery
  materially worse, or a tested rescue procedure that covers it.

On 2026-07-09 local time, the hosted response allowed only:

```text
frame-ancestors 'self' https://pwa.thebitcoincompany.com https://app.thebitcoincompany.com
```

Bullnym therefore cannot embed the hosted production tool today. External
top-level navigation is not affected by that policy.

### 6.4 Gate outcomes

- **Pass:** duplicate-hash creation is supported, all node/timelock cases pass,
  nested stablecoin-to-BOLT11-to-L-BTC succeeds, the v1 merchant-fee formula is proven,
  safe resume/refund recovery is demonstrated, and hosted parameters are
  supported.
- **External-only pass:** every non-frame gate, including safe top-level
  recovery, passes, but framing or third-party-storage recovery is not
  approved. Ship only the new-tab handoff.
- **No-go:** same-provider BOLT11 payment is unsupported or unreliable. Do not
  ship a hidden raw-REST substitute. Move to the alternatives in section 18.

## 7. Upstream URL Contract

The official URL documentation says:

- `destination` prefills the invoice/address and its inferred asset wins over
  `receiveAsset`.
- `sendAsset` and `receiveAsset` choose assets.
- An amount-bearing Lightning invoice overrides separate amount parameters.
- `embedded=true` plus `parentOrigin` enables a final-status message to the
  parent.

See [Boltz Web App URL parameters](https://web.docs.boltz.exchange/urlParams.html).

The reviewed source also implements and tests `lockOutput`:

- [`UrlParam.LockOutput`](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/src/consts/Enums.ts#L11-L25)
- [BOLT11 output lock](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/src/context/Create.tsx#L203-L234)
- [Output-lock browser tests](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/e2e/urlParams.spec.ts#L404-L455)

### 7.1 External URL

After Gate 0 confirms the focused pathname, build this on the Bullnym server
with Rust's structured URL API:

```text
https://boltz.exchange/<vendor-confirmed-tool-path>?
  destination=<url-encoded amount-bearing BOLT11>
  &sendAsset=USDC
  &receiveAsset=LN
  &lockOutput=true
  [&ref=<operator-configured referral id>]
```

The actual URL is one line. It must not include whitespace.

Rules:

- Never concatenate raw query strings and never build the money URL in inline
  template JavaScript.
- Never accept the tool origin, asset ID, destination, or referral ID from a
  public request.
- Only use a BOLT11 returned by Bullnym for this invoice and its current
  remaining amount.
- Do not pass `sendAmount` or `receiveAmount`.
- Do not pass the invoice memo, payer note, nym, npub, source IP, Liquid
  address, Liquid blinding key, or a second invoice identifier.
- After asynchronous preparation, render an anchor using `target="_blank"` and
  `rel="noopener noreferrer"`. Do not rely on a delayed `window.open`.
- Default `sendAsset` to canonical `USDC` or `USDT0`. Treat the hosted tool as
  authoritative for what it can actually quote at launch time.

### 7.2 Embedded URL

After the iframe gate passes, add:

```text
embedded=true
parentOrigin=<exact window.location.origin>
theme=light
```

Do not use `parentOrigin=*`. The Boltz source explicitly refuses wildcard
notification targets.

### 7.3 Pure URL builder

Add one pure Rust URL builder used by the click-time handoff endpoint. Both the
PWA and Askama page consume the returned `handoff_url`; they do not duplicate
operator URL/referral policy. The builder inputs are:

```text
toolOrigin and vendor-confirmed pathname
bolt11
sendAsset
mode: external | embedded
parentOrigin?: exact origin
referralId?: configured identifier
```

It returns a validated URL string, not an HTML fragment. Tests must assert the
exact parameter set and absence of every disallowed parameter. Client code may
parse the response into a `URL` for defense-in-depth origin comparison, but it
must not add or rewrite money parameters.

## 8. Bullnym Data and Eligibility Changes

### 8.1 Persist checkout surface kind

Payment Page, POS, and aliases all converge on `create_anonymous_for_kind`, but
the current invoice stores only `origin = 'checkout'`. An id-only status call
cannot tell whether the invoice came from Payment Page or POS.

Add a migration:

```sql
ALTER TABLE invoices
  ADD COLUMN checkout_surface_kind TEXT
  CHECK (checkout_surface_kind IN ('payment_page', 'pos'));
```

Rules:

- Set the field from the canonical `kind` already passed to
  `create_anonymous_for_kind`.
- Wallet-created invoices use `NULL`.
- Historical rows remain `NULL` and fail closed for stablecoin eligibility.
- Do not infer historical kind from nym, alias, or the current
  `donation_pages` row.
- Add a stronger origin/kind coherence constraint only after verifying that
  legacy rows can satisfy it.

Update:

- `src/db/invoices.rs`: `Invoice`, `INVOICE_COLUMNS`, `NewInvoice`, insert
  columns, binds, and test fixtures.
- `src/invoice.rs`: checkout insert passes `kind`; wallet inserts pass `None`.
- Data-model and API documentation.

### 8.2 Public capability field

Add these fields to `InvoiceStatusResponse` and the PWA type:

```text
stablecoin_available: bool
stablecoin_send_assets: string[]
stablecoin_default_send_asset: string | null
```

The asset list is empty and default is null when unavailable. Availability is
computed server-side and is true only when all are true:

- `features.payment_page_stablecoins` is enabled.
- The deployed-hosted-contract synthetic is passing and fresh.
- The invoice is `origin = 'checkout'`.
- `checkout_surface_kind = 'payment_page'`.
- The invoice's nym is in the canary cohort, unless global rollout is enabled.
- The invoice accepts Lightning and has its recipient Liquid destination.
- The invoice is unpaid or partially paid and settlement state permits a new
  payment.
- `remaining_amount_sat > 0`.
- The outer invoice has at least the vendor-approved source-plus-settlement
  lifetime remaining.
- The remaining amount is below the operator rollout ceiling.

The field does not promise that the current Boltz route has liquidity. The
hosted tool performs the authoritative live quote and limit check.

Add the three capability fields to `CreateInvoiceResponse` if avoiding a
one-poll delay is useful, but PaymentScreen must still adopt the latest status
values once polling starts.

`stablecoin_available` is a presentation hint, not launch authorization. A
cached true value cannot bypass the click-time endpoint below.

### 8.3 Click-time handoff endpoint

Add a purpose-specific write endpoint:

```text
POST /api/v1/invoices/:id/stablecoin-handoff
{"send_asset":"USDC"}

200
{
  "handoff_url":"https://boltz.exchange/<confirmed-path>?...",
  "handoff_expires_at_unix":1234567890,
  "integration_mode":"external",
  "safe_resume_url":null
}
```

The endpoint may create a fresh existing Bullnym reverse swap, so it must:

1. Apply a dedicated per-source and per-invoice rate limit.
   Keep the JSON body cap at 1 KiB or lower and return `Cache-Control: no-store`.
2. Parse the invoice ID and acquire the same transaction-scoped per-invoice
   advisory lock used for Lightning offer creation.
3. Inside the lock, refetch the invoice and recheck feature flag, cohort,
   surface snapshot, live state, remaining amount, rollout ceiling, outer
   lifetime, hosted-contract check freshness, Lightning acceptance, and Liquid
   destination.
4. Validate `send_asset` against the operator allowlist.
5. Reuse an amount-matching BOLT11 only when it meets the stablecoin-specific
   minimum lifetime, which is longer than the ordinary 120-second reuse margin.
6. Force creation of one replacement reverse offer when the current offer is
   too short. Recheck after the lock so concurrent requests converge.
7. Reject the handoff if a newly returned provider BOLT11 is still too short,
   outlives the Bullnym outer invoice, has the wrong network or amount, or
   cannot be decoded.
8. Enforce a maximum outstanding reverse-offer count and the durable
   reverse-offer creation journal below before allowing another create.
9. Construct and validate the complete hosted URL on the server. Embedded
   `parentOrigin` comes from Bullnym's configured public origin, never an
   untrusted `Host`, forwarded header, or request body.
10. Return no wallet, EVM, Liquid blinding, or provider source-swap material.

The response expiry is the decoded BOLT11 expiry, named distinctly from the
outer invoice's existing `expires_at_unix`. A `safe_resume_url` is returned only
if Gate 0 establishes a vendor-supported URL that cannot create a second source
attempt. Do not synthesize one from a prefilled creation URL.

The endpoint is the authoritative kill switch for Bullnym-originated launches.
Turning the flag off makes new calls fail immediately even if an old client
cached `stablecoin_available = true`.

#### Ambiguous reverse-offer creation

Current Bullnym persists a complete `swap_records` row only after Boltz returns
the swap ID, BOLT11, keys, and response. A timeout after provider acceptance can
therefore leave an untracked Reverse Swap and permit another creation after
retry or restart. The longer-lived handoff policy must not reuse that gap.

After Gate 0 supplies provider idempotency or authoritative lookup, add a
shared reverse-offer creation journal, not a stablecoin source-swap table:

```text
reverse_offer_creation_attempts
  local_attempt_id
  invoice_id
  amount_sat
  purpose
  deterministic_provider_request_id / request fingerprint
  persisted preimage and claim material required for recovery
  state: creating | created | ambiguous | failed
  provider_swap_id nullable
  created_at / updated_at / last_error
```

Creation order:

1. Under the per-invoice lock, validate policy, generate deterministic request
   material, insert the attempt, and commit it before the provider call.
2. A partial unique constraint allows only one nonterminal creation attempt for
   an invoice/amount. Both ordinary `/lightning` and stablecoin handoff helpers
   consult it so one path cannot bypass the other.
3. Call Boltz with the Gate 0-approved idempotency/recovery identifier.
4. On success, atomically insert/promote the existing `swap_records` data and
   mark the attempt `created`.
5. On a lost or ambiguous response, mark `ambiguous`, fail future creates
   closed, and let a reconciler recover the original provider response.
6. Never turn a bare duplicate-hash `409` into success without retrieving and
   validating the original swap.
7. Delete/archive the marker only after the provider state is authoritatively
   resolved and no late payment can exist.

Persist recovery secrets under the same protection and access policy as the
existing reverse-swap material. This journal hardens Bullnym's recipient-side
offer creation; it does not store or control the payer's hosted stablecoin
swap.

### 8.4 No stablecoin swap table

Do not add stablecoin attempt rows in this architecture. Bullnym neither creates
nor recovers the payer's stablecoin swap. Its durable records remain:

- The Bullnym invoice.
- The existing Lightning reverse-swap record.
- The invoice Liquid destination and blinding key.
- Existing recipient-side settlement evidence.

This is both smaller and more correct than storing a partial copy of browser
state that Bullnym cannot safely use to refund the payer.

## 9. Configuration

Add a default-off operator section along these lines:

```toml
[features]
payment_page_stablecoins = false

[stablecoins]
tool_origin = "https://boltz.exchange"
tool_path = "/swap" # placeholder until Gate 0 confirms the hosted contract
integration_mode = "external"
advertised_send_assets = ["USDC", "USDT0"]
default_send_asset = "USDC"
canary_nyms = []
global_rollout = false
max_invoice_sat = 100000
minimum_bolt11_lifetime_secs = 0 # Gate 0 value required before enablement
minimum_outer_lifetime_secs = 0 # Gate 0 timeout-ladder value
max_outstanding_reverse_offers = 0 # Gate 0 operational value
hosted_contract_check_max_age_secs = 0 # fail closed until synthetic is fresh
# referral_id = "..."
```

Validation requirements:

- Production `tool_origin` is HTTPS and exactly allowlisted.
- The configured origin has no username, password, path, query, or fragment;
  `tool_path` is a separate absolute path with no query or fragment.
- `integration_mode` is `external` unless the iframe readiness gate is
  explicitly satisfied.
- Assets are a compile-time allowlist of identifiers supported by the hosted
  tool. Reject arbitrary strings.
- The default asset appears in the advertised list.
- Canary nyms are normalized with existing nym validation.
- The rollout ceiling is positive and within the invoice integer domain.
- Both minimum lifetimes come from Gate 0, not guesswork. Enabling the feature
  with either value zero is a configuration error.
- The outstanding-offer and hosted-contract freshness values are nonzero
  before enablement; handoff fails closed when either policy cannot be met.
- A referral ID is sent only after Boltz assigns and documents it.

`advertised_send_assets` controls Bullnym's choices and defaults, not the
hosted tool's full wallet UI. If product or compliance requires a strict payer
network/token allowlist, obtain an upstream parameter that enforces it before
rollout; do not claim Bullnym can enforce a choice inside another origin.

Keep tool origin, path, and referral policy server-side. The PWA config needs
only its existing surface mode; current invoice eligibility and advertised
asset IDs come from status, and the complete money URL comes from the handoff
endpoint. This avoids two security-sensitive URL implementations in
`PwaConfigView`, `BullnymConfig`, and the Askama template.

## 10. Lightning Offer Lifetime

The stablecoin route needs more time than a normal wallet scanning and paying a
BOLT11. A two-minute reuse margin is not a sufficient merchant contract by
itself, and the current `/lightning` endpoint cannot force a replacement while
an amount-matching offer still clears that ordinary margin.

Plan:

1. Keep the ordinary `/lightning` endpoint and its current semantics unchanged.
2. Put the longer reuse threshold in the purpose-specific stablecoin handoff
   endpoint. Refactor the internal locked helper to accept a caller-selected
   reuse margin, rather than letting the public client request an arbitrary
   lifetime.
3. Decode and validate the selected BOLT11 server-side. Return its expiry as
   `handoff_expires_at_unix`; do not overload the outer invoice field.
4. Require the Bullnym outer invoice to remain live beyond the entire
   vendor-approved source and recipient settlement budget. Require the BOLT11
   to expire no later than that outer deadline unless late-settlement semantics
   are explicitly redesigned.
5. Freeze the chosen BOLT11 for that browser handoff. Do not replace an active
   iframe or external session merely because later invoice polling sees a new
   offer.
6. Existing 1:N reverse-swap records continue watching old offers. A stale
   offer remains recoverable under existing Bullnym behavior.
7. If no sufficiently long offer can be obtained, show the stablecoin rail as
   temporarily unavailable and leave the other rails usable.

Do not add a general `force=true` knob to the existing public Lightning
endpoint. The handoff endpoint owns the stronger policy, rate limit, URL
construction, and launch-time kill-switch check.

Expiry precedence must be explicit:

- Before any Bullnym money evidence, the outer invoice deadline prevents new
  handoffs and the destination BOLT11 must not remain payable past it.
- Once the destination BOLT11 is paid or recipient settlement has started,
  funded settlement and recovery continue even if wall-clock outer expiry
  passes. Expiry must never erase real money evidence.
- A payer-funded source attempt that has not yet paid the BOLT11 is invisible
  to Bullnym. The safe timeout ladder must give it enough time to pay or refund
  before the destination and outer deadlines.

## 11. Payment Page UI

### 11.1 Shared PWA

The shared `PaymentScreen.svelte` is used by Payment Page and POS. Add
`stablecoin` to its rail type, but require both:

- `config.mode === 'donation'`
- `latest.stablecoin_available === true`

This keeps POS out at the presentation layer while the server-side invoice
snapshot remains the real authorization boundary.

The Stablecoin panel should contain:

- A stablecoin selector using recognizable USDC/USDT choices.
- A `Prepare stablecoin payment` action that calls the handoff endpoint.
- A preparation state while Bullnym obtains a purpose-specific BOLT11.
- After preparation, a real `Continue with Boltz` anchor requiring a second
  explicit tap. Do not call `window.open` after awaiting network work; that is
  popup-blocked on common mobile browsers.
- A waiting state after launch while the existing invoice poller runs.
- No retry/resume claim that Bullnym cannot substantiate. A new handoff remains
  locally blocked after launch until the payer explicitly confirms the prior
  Boltz attempt was never funded or is resolved.
- A distinct `Resume/Recover at Boltz` action only when Gate 0 supplies a safe
  history/resume URL that cannot create a second source attempt.

Do not add EVM wallet controls to Bullnym. The Boltz origin renders the wallet,
approval, quote, fees, recovery, and refund UI.

Use a stable panel height and responsive constraints so switching between QR
rails and Stablecoin does not shift or overlap the surrounding payment view.
The original Bullnym tab must remain useful on desktop and mobile while the
Boltz tab is open.

### 11.2 Server-rendered invoice

Add the same Stablecoin rail to `templates/invoice_payment.html` only when the
server-computed eligibility is true. Phase 2 uses the shared server handoff
endpoint and an external link. This makes
canonical invoice links feature-complete even when the user is not inside the
Payment Page PWA shell.

Do not expose the Stablecoin rail on `/invoice/<id>` wallet-created invoices,
even if they accept Lightning.

### 11.3 Alias privacy

Eligibility is calculated before rendering and does not expose the alias's
owning nym. The BOLT11 already contains Bullnym's public payment description
contract; no extra nym or invoice metadata is added to the handoff URL.

### 11.4 Client persistence

At most store non-secret UI state under the existing invoice/page namespace:

```text
selected stablecoin
handoff launched timestamp
integration mode
safe vendor resume URL, only if Gate 0 approves it
```

Do not store the Boltz rescue mnemonic, refund key, wallet address, token
allowance, transaction hash, or provider swap response in Bullnym storage.
Boltz's origin owns its own durable swap history.

Retain the local launch/recovery marker for the longest vendor source refund
window plus an operational margin. Hiding new handoffs because the feature was
disabled or the canary changed must not hide an already approved safe recovery
link. If no safe re-entry contract exists, production external handoff does not
pass Gate 0.

## 12. Embedded Mode

Embedded mode is a later delivery, not a prerequisite for external handoff.

### 12.1 Framing policy

After Boltz allowlists Bullnym, add only this narrow parent policy:

```text
frame-src https://boltz.exchange
```

Apply it to the Payment Page PWA CSP and the server-rendered invoice CSP where
embedding is enabled. Do not widen `connect-src` to arbitrary HTTPS: the child
frame makes its own network connections under its own CSP.

Keep Bullnym's own `frame-ancestors 'none'` and `X-Frame-Options: DENY`; those
prevent Bullnym from being framed and do not prevent Bullnym from hosting a
child frame.

### 12.2 Message handling

The documented final message has this shape:

```json
{
  "type": "boltz-swap-status",
  "swapId": "abc123",
  "status": "invoice.settled"
}
```

The parent listener must require all of:

- `event.origin === configuredBoltzOrigin`
- `event.source === iframe.contentWindow`
- Plain-object message with the exact `type`.
- Bounded string fields.
- Status in a pinned allowlist, or unknown status treated as a generic refresh.

The only allowed effect is:

1. Request an immediate Bullnym invoice status refresh.
2. Optionally update non-accounting local UI copy.

It must not set paid, partial, failed, refunded, or settlement status directly.
See the
[pinned notifier](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/src/utils/notifyParent.ts#L6-L30)
and
[pinned final-status sender](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/src/components/SwapChecker.tsx#L80-L90).

### 12.3 Browser recovery gate

Test at minimum:

- Chrome desktop with an injected wallet.
- Android Chrome with WalletConnect/deep-link return.
- iOS Safari with a mobile wallet.
- Safari desktop.
- Installed Bullnym PWA mode.
- Private browsing and storage-denied behavior.
- Parent reload after approval, after funding, and while waiting for the
  BOLT11 payment.
- Third-party cookie/storage partitioning.
- Popup, clipboard, WebHID, and Permissions Policy requirements.

If recovery in an iframe is weaker than top-level Boltz, retain external mode.
Embedding is an ergonomic improvement, not a correctness requirement.

## 13. Status and Failure Model

| Event | Bullnym invoice behavior | Payer action/owner |
|---|---|---|
| Stablecoin rail selected | Still unpaid | Bullnym prepares BOLT11 |
| Boltz tool opened | Still unpaid | Payer connects wallet |
| Approval requested/rejected | Still unpaid | Payer/Boltz UI |
| Stablecoin tx submitted | Still unpaid | Boltz monitors/retries |
| Commitment or bridge pending | Still unpaid | Boltz resumes from its state |
| Destination BOLT11 paid | Existing reverse swap progresses | Bullnym settlement starts |
| L-BTC server lock seen | Existing settling state | Bullnym claims |
| Recipient L-BTC recorded | Paid/partial/overpaid | Bullnym status wins |
| Stable source swap fails in Boltz | Still unpaid unless other money arrived; external Bullnym tab cannot observe the failure | Payer refunds in Boltz |
| BOLT11 expires before payment | Still unpaid | Boltz refund/retry; fetch new offer |
| Bullnym L-BTC claim is stuck | Existing settlement failure/review state | Existing operator recovery |
| Another rail pays first | Paid, later payment can overpay | Record all real money |
| Feature flag turns off | Reject new handoff endpoint calls; preserve approved safe recovery affordance | In-flight paths continue |

The Bullnym page should not try to reproduce Boltz's detailed bridge or EVM
state machine. In external mode, `noopener` means Bullnym receives no source
attempt status at all. It cannot know pending from failed, refunded, or merely
closed. A concise waiting state is appropriate; a link back is safe only when
the vendor provides a non-creating history/resume contract.

## 14. Security and Privacy

### 14.1 Trust boundaries

- Bullnym trusts only its own invoice database and settlement evidence for
  accounting.
- The payer trusts the configured Boltz origin for the stablecoin swap.
- Boltz never receives Bullnym's Liquid blinding key.
- Bullnym never receives a payer stablecoin private key, rescue key, wallet
  connection, or token approval.
- Boltz is able to correlate both legs. It issued the destination reverse-swap
  BOLT11 and operates the stablecoin source swap, so the shared payment hash
  can join payer wallet/chain activity to the Bullnym reverse swap, the public
  invoice description/URL encoded in that BOLT11, and eventual Liquid
  settlement. `noreferrer` does not prevent provider-level correlation.

### 14.2 Handoff validation

- Validate the BOLT11 parses, is mainnet, has an amount, matches current
  `remaining_amount_sat`, and meets the minimum lifetime before building the
  URL.
- Allowlist exact scheme, host, port, and pathname rules for the tool origin.
- Reject control characters and unsupported asset identifiers.
- Construct the URL using structured APIs.
- Add no secrets to query parameters.
- Use `noreferrer` in external mode.
- Never log the full handoff URL or BOLT11.
- Decode a fixture for nym and alias Payment Pages during Gate 0 and document
  exactly which public Bullnym URL, alias, description, and invoice ID fields
  Boltz can observe from the BOLT11.

### 14.3 Iframe validation

- Pin `frame-src` to the exact origin.
- Pin `parentOrigin` to `window.location.origin`.
- Validate both message origin and window source.
- Tear down listeners on component unmount.
- Do not use wildcard messages.
- Do not grant camera, microphone, location, or other unrelated permissions.
- Add only vendor-documented wallet/clipboard permissions proven necessary in
  the browser matrix.

### 14.4 Stablecoin-specific implications

The payer is exposed to risks that a pure Bitcoin/Liquid payment does not have:

- Issuer freeze, blacklist, redemption, and depeg risk.
- Arbitrum and smart-contract risk.
- tBTC and DEX liquidity risk.
- Token approval and Permit2 risk.
- Quote movement and slippage.
- Bridge and messaging risk if the payer changes to a non-Arbitrum source.
- Wallet phishing and wrong-network risk.
- Third-party hosted-tool availability.

Boltz's UI should present the actionable quote, approval, and recovery details.
Bullnym should clearly identify the handoff as provided by Boltz, but must not
copy rapidly changing fee or network claims into static UI text.

Product/legal must accept [Boltz's current terms](https://boltz.exchange/terms)
and the implications of stablecoin issuers, DEXs, tBTC, and optional bridges
before global rollout. That acceptance must also cover the cross-leg provider
correlation above.

## 15. Limits, Fees, and Quotes

Do not hardcode live Boltz limits, miner fees, DEX prices, stablecoin amounts,
or routes in Bullnym. They are dynamic and the official tool quotes them at
execution time.

The stablecoin payer input is not the invoice amount expressed at a fixed
exchange rate. It includes the stablecoin-to-Lightning route. Recipient-side
reverse-swap and Liquid claim economics separately determine
`merchant_net_lbtc_sat`; they must follow the v1 merchant-fee contract in
section 5. The payer must see the source quote inside Boltz before approving,
and the merchant settlement formula must be independently testable in
Bullnym.

Bullnym may apply an operator rollout ceiling to reduce canary exposure, but
that is a safety policy, not a claim about provider liquidity.

The initial rollout advertises canonical Arbitrum USDC and USDT0 because they
avoid a separate source bridge. The hosted tool may expose other source
networks; Bullnym does not advertise them until each bridge family has passed
the recovery matrix.

## 16. Test Plan

### 16.1 Rust and SQL

- Migration accepts `payment_page`, `pos`, and `NULL`; rejects unknown values.
- New Payment Page invoice snapshots `payment_page`.
- Nym POS and POS alias snapshot `pos`.
- Payment Page alias snapshots `payment_page` without exposing its nym.
- Wallet-created and legacy invoices remain `NULL`.
- Feature on plus eligible Payment Page returns
  `stablecoin_available = true`.
- Feature off, POS, POS alias, wallet invoice, legacy null kind, expired,
  cancelled, paid, zero remaining, rejected settlement state, missing Liquid
  destination, disabled Lightning, over-ceiling, and non-canary invoices return
  false.
- Handoff expiry is decoded correctly, named separately from outer invoice
  expiry, and never extends the provider BOLT11.
- Stablecoin capability checks never create a swap during a read-only status
  poll.
- Handoff endpoint rechecks all eligibility after acquiring the invoice lock;
  a cached true capability cannot bypass a disabled flag or changed invoice.
- Ordinary Lightning reuse keeps its existing margin; stablecoin handoff uses
  the longer configured margin and forces at most one replacement.
- Concurrent and retried handoff requests converge on one eligible reverse
  offer and never exceed the outstanding-offer cap.
- Per-source and per-invoice handoff rate limits reject abusive provider/DB
  churn.
- Ambiguous reverse-offer creation never blindly creates a second provider
  swap.
- A simulated accepted create with a dropped response leaves a durable
  `ambiguous` journal row across restart; ordinary and stablecoin offer paths
  fail closed until the reconciler retrieves and validates the original swap.
- Successful recovery promotes exactly one existing `swap_records` row and
  clears the creation fence without changing preimage/key material.
- BOLT11 expiry cannot exceed outer invoice expiry, and both meet their minimum
  remaining lifetime.
- Askama template renders no stablecoin controls for ineligible invoices.
- Existing invoice accounting and chain-watcher tests remain unchanged and
  pass.

### 16.2 URL, API, and PWA unit tests

- Server URL builder emits only `destination`, `sendAsset`, `receiveAsset`,
  `lockOutput`, and optional approved integration parameters.
- BOLT11 is encoded once and round-trips exactly.
- No separate amount is included.
- Invalid origin, path, asset, BOLT11, amount, network, or lifetime fails
  closed.
- Handoff response is consumed identically by PWA and Askama clients; neither
  reconstructs or mutates query parameters.
- Stablecoin tab appears for Payment Page only.
- Loading a POS invoice ID inside a Payment Page shell remains ineligible from
  the server status field.
- Stablecoin tab prepares a click-time handoff and requires a second explicit
  anchor click after the response.
- Selecting another rail does not destroy invoice polling.
- External launch uses no opener/referrer.
- Popup-blocked, mobile Safari, and installed-PWA flows keep preparation state
  recoverable and never lose money parameters.
- A locally launched handoff blocks accidental duplicate launches until payer
  confirmation or a vendor-approved safe resume action.
- Disabling new handoffs does not remove an existing safe recovery affordance.
- A launch never changes the local invoice to paid.
- Final iframe message triggers a poll only after strict origin/source/schema
  validation.
- Malformed, wildcard-origin, wrong-window, duplicate, unknown, and oversized
  messages are ignored or reduced to a safe poll.
- Existing Lightning, Liquid, Bitcoin, Bolt Card, and POS tests remain green.

### 16.3 Browser tests

- Desktop and mobile layouts have no overlap, blank panel, horizontal
  overflow, or rail-induced layout shift.
- External tab opens the exact supported Boltz origin.
- Destination BOLT11, receive asset, direction, and amount are locked in the
  hosted tool.
- The payer can select and fund canonical Arbitrum USDC and USDT0.
- Closing and reopening top-level Boltz uses a vendor-supported history/resume
  route and cannot create another source attempt.
- Loss of existing Boltz-origin storage either recovers by the Gate 0 contract
  or fails the production gate.
- Original Bullnym page reaches paid only after its status endpoint does.
- Partial and mixed-rail payments rebuild a new handoff from the latest
  remaining amount before launch.
- A stablecoin swap already in flight plus another rail produces the existing
  overpayment behavior rather than losing an event.
- Embed phase passes the full browser recovery matrix in section 12.3.
- A pre-enable and continuous deployed-origin smoke test verifies the live
  hosted build still honors assets, destination parsing, and immutable output
  controls. Failure automatically disables new handoffs.

### 16.4 End-to-end money tests

- Duplicate payment-hash creation scope: expected supported creation, not
  undocumented `409` behavior.
- Same-node and every supported cross-node nested path.
- Regtest nested swap success using the v1 merchant-fee formula.
- Source stablecoin approval rejection.
- Source funding replacement/ambiguous broadcast.
- Source commitment rejection and payer refund.
- BOLT11 expiry before source payment.
- Outer invoice expiry before source funding, during the Lightning HTLC, and
  after L-BTC lockup but before claim.
- Source refund, BOLT11, reverse lock/refund, and claim timeout boundary and
  reorg cases.
- Browser close after approval and after funding.
- Bullnym restart before BOLT11 settlement.
- Bullnym restart after BOLT11 settlement but before L-BTC claim.
- Lost/duplicate/out-of-order Boltz webhook on the existing reverse swap.
- Recipient L-BTC claim retry and reconciliation.
- Exact, partial, and overpaid invoice outcomes.
- Low-value mainnet USDC and USDT0 canaries with captured runbooks.

## 17. Observability and Operations

### 17.1 Metrics

Reuse existing invoice and reverse-swap settlement metrics. Add only coarse,
non-sensitive integration metrics where useful:

- Stablecoin rail eligible renders.
- External handoff clicks or iframe starts.
- Lightning-offer preparation failures for a stablecoin handoff.
- Time from handoff to existing BOLT11 settlement, when locally correlatable.
- Iframe final messages by broad success/failure class.
- Iframe origin/schema rejections.
- Feature/canary eligibility denials by reason.

Do not label an existing Lightning payment as stablecoin revenue based only on
a click. Do not log the full BOLT11, handoff URL, wallet, swap ID, or token
transaction.

### 17.2 Alerts

- Sudden Lightning offer failure increase on canary Payment Pages.
- Existing reverse swaps paid but L-BTC claim remains stuck.
- Hosted Boltz origin or required parameter smoke test fails.
- Hosted iframe `frame-ancestors` no longer includes Bullnym after embed launch.
- Rejected parent messages increase.
- Canary overpayment rate increases after stablecoin enablement.

Run a scheduled browser synthetic against the deployed hosted origin using a
nonpayable fixture BOLT11. It must verify parsing plus immutable destination,
direction, receive asset, and amount controls. Feed its freshness/result into
the deployment control plane; the handoff feature is disabled when the result
fails or becomes stale. A pinned source-code test alone cannot certify a hosted
build Bullnym does not deploy.

### 17.3 Runbook

The operator runbook must distinguish:

- Payer-side stablecoin problem: payer uses the Gate 0-approved Boltz
  resume/refund path; Bullnym does not possess the recovery key. If that path
  is unexpectedly unavailable after storage loss, escalate through the vendor
  incident runbook rather than creating another attempt; this state must have
  been blocked in pre-production testing.
- Destination BOLT11 not paid: Bullnym remains unpaid and can issue a fresh
  offer after the payer's source attempt is resolved.
- BOLT11 paid but recipient settlement pending: use the existing Bullnym
  reverse-swap reconciliation and claim runbook.
- Recipient paid but browser still waiting: force Bullnym status refresh; do
  not manipulate the Boltz source swap.

## 18. Rejected and Future Alternatives

### 18.1 Rejected: raw Rust stablecoin REST integration

This conflicts with Boltz's integration guidance and would require Bullnym to
reimplement wallet approvals, EVM contracts, DEX quote execution, commitments,
claiming, payer refunds, bridge recovery, browser resumption, and response
verification without a supported Rust stablecoin SDK.

### 18.2 Rejected for v1: copying or self-hosting the full web app

The current app includes a large, fast-moving wallet and cross-chain stack.
Self-hosting also creates update, origin persistence, CSP, WalletConnect,
security-response, and licensing obligations. The workspace package is early
versioned, and repository/package license boundaries need confirmation before
copying source.

If self-hosting is later selected, make it a separate architecture decision:

- Obtain written licensing and support confirmation.
- Pin a commit and lockfile.
- Preserve a stable origin forever for payer history and recovery.
- Automate upstream security and contract-address diff review.
- Run the full Boltz E2E wallet/refund suite.
- Keep the hosted/external path as an emergency recovery entry point.

### 18.3 Deferred: direct stablecoin-to-L-BTC handoff

Direct stablecoin-to-L-BTC avoids the second Lightning-to-Liquid swap and may
reduce fees. It is not the initial plan because the reviewed hosted app:

- Locks output only when `destination` is an amount-bearing BOLT11.
- Leaves a Liquid address plus `receiveAmount` editable despite
  `lockOutput=true`.
- Makes the payer browser responsible for coordinating the recipient L-BTC
  claim and source refund state.

Revisit after Boltz provides a merchant contract that:

- Locks a confidential Liquid destination, exact L-BTC amount, direction, and
  receive asset.
- Defines who retains the L-BTC claim key and who can complete a claim after the
  payer browser closes.
- Preserves payer-owned EVM refunds.
- Supports a stable hosted/deep-link or official SDK interface.

### 18.4 Fallback if nested BOLT11 flow fails

If Gate 0 proves same-provider BOLT11 settlement unreliable, choose one of:

1. Ask Boltz to support immutable direct Liquid merchant outputs in the hosted
   tool, then use direct stablecoin-to-L-BTC.
2. Ask Boltz for a supported merchant integration that splits payer EVM refund
   authority from Bullnym's Liquid claim authority.
3. Build a pinned browser-side TypeScript adapter with Boltz engineering
   involvement and a separate security review.

Do not silently fall back to an unreviewed Rust REST client.

## 19. Phased Delivery

### Phase 0: Contract and proof

- Complete every Gate 0 item.
- Pin the Boltz web app commit used for fixtures.
- Prove duplicate-hash scope, every production node pairing, timeout ordering,
  outer-expiry behavior, and the v1 merchant-fee formula.
- Produce successful and refunded nested-swap evidence.
- Obtain hosted parameter, focused path, build identification, safe resume, and
  origin support in writing.
- Decide external-only versus external-plus-iframe release.

Exit: nested flow is proven and payer recovery has an owner for every funded
state.

### Phase 1: Eligibility and configuration

- Add `checkout_surface_kind` migration and domain fields.
- Add the shared durable reverse-offer creation journal and ambiguous-create
  reconciler proven by Gate 0.
- Add default-off config, canary cohort, and rollout ceiling.
- Add server-computed `stablecoin_available`.
- Add the rate-limited, lock-protected stablecoin handoff endpoint and
  stablecoin-specific Lightning lifetime policy.
- Add the one server-side hosted URL builder and deployed-build smoke gate.
- Update API/data-model docs and fixtures.

Exit: POS and wallet invoices fail closed at the server boundary; no stablecoin
control is visible.

### Phase 2: External hosted handoff

- Add the Payment Page-only PWA rail.
- Add the server-rendered invoice rail.
- Prepare and freeze a sufficiently long BOLT11 through the handoff endpoint.
- Render a second-gesture top-level Boltz link with `noopener noreferrer`.
- Preserve only the vendor-approved safe resume/recovery affordance after
  launch or feature disablement.
- Keep Bullnym polling authoritative.
- Build PWA dist and service-worker artifacts through the existing process.

Exit: canary users can complete a top-level hosted stablecoin payment and the
recipient receives L-BTC through the existing Bullnym flow.

### Phase 3: Canary rollout

- Enable one internal/canary Payment Page.
- Start with low caps and canonical Arbitrum defaults.
- Exercise USDC success, USDT0 success, payer refund, browser restart, Bullnym
  restart, expired BOLT11, and mixed-rail overpayment.
- Review support tickets and claim latency before widening the cohort.

Exit: agreed success/recovery thresholds pass for a fixed observation window.

### Phase 4: Hosted iframe

- Obtain Boltz `frame-ancestors` allowlisting.
- Add narrow `frame-src` CSP.
- Add strict parent message validation.
- Pass desktop/mobile/PWA storage and wallet recovery tests.
- Retain external mode as a runtime fallback.

Exit: iframe recovery is no worse than the accepted product threshold and a
one-flag rollback to external mode works.

### Phase 5: Broader assets and networks

- Add one source-network family at a time only after its wallet, gas, bridge,
  ambiguous-broadcast, and refund flows pass.
- Treat USDT0/OFT, USDC/CCTP, Solana, and Tron as separate risk releases.
- Never derive the advertised list from an unversioned source-code registry at
  runtime.

Exit: each advertised network has a tested recovery runbook.

## 20. Small Pull Request Sequence

1. `proof: resolve Boltz duplicate-hash, node, timeout, value, and recovery gates`
2. `db: snapshot checkout surface kind on invoices`
3. `swaps: journal and reconcile ambiguous reverse-offer creation`
4. `config: add default-off Payment Page stablecoin rollout policy`
5. `api: expose stablecoin eligibility and click-time handoff preparation`
6. `server: add tested Boltz hosted URL and lifetime policy`
7. `pwa: add Payment Page-only external stablecoin rail`
8. `invoice-ui: add external stablecoin rail to canonical render`
9. `tests: add nested Boltz regtest and capped mainnet canary harness`
10. `ops: add stablecoin handoff metrics, alerts, and runbook`
11. `embed: add allowlisted hosted iframe and strict status refresh bridge`

Each pull request must leave the feature default-off. Database changes land
before status fields; status fields land before clients rely on them. Old PWA
clients must tolerate the additive API fields, and new clients must treat a
missing field as false during rolling deployment.

## 21. Rollout and Rollback

Rollout order:

1. Development with mock hosted tool.
2. Boltz regtest/Anvil nested flow.
3. Internal mainnet Payment Page, low cap.
4. Small explicit nym cohort.
5. External-mode general availability.
6. Optional iframe cohort.
7. Optional broader stablecoin networks.

Rollback:

- Set `payment_page_stablecoins = false` so the handoff endpoint rejects every
  new Bullnym-originated launch, including stale clients.
- Or switch `integration_mode = 'external'` if iframe behavior regresses.
- Keep any vendor-approved safe resume/recovery link visible for a locally
  recorded in-flight launch until the maximum refund window elapses.
- Do not cancel BOLT11s, reverse swaps, claims, or reconciliation workers.
- Do not remove the Boltz origin before payer recovery windows have elapsed.
- Payments already sent to a BOLT11 continue through normal Bullnym
  settlement even after the rail is hidden.

## 22. Definition of Done

The integration is complete only when:

- Gate 0 has written approval and reproducible evidence for duplicate-hash
  scope, every node assignment, timeout ordering, outer expiry, and recovery.
- Payment Page, POS, alias, wallet, and legacy invoice eligibility is enforced
  server-side.
- The handed-off BOLT11 has the selected face amount, is sufficiently fresh,
  does not outlive the outer invoice, and is output-locked.
- The v1 `invoice_face_sat` to `merchant_net_lbtc_sat` formula is explicit
  and verified from the actual unblinded recipient output.
- Bullnym sends no payer secret or private invoice note to Boltz.
- Payer stablecoin/refund state remains entirely payer-controlled in Boltz.
- Bullnym continues to receive L-BTC through its existing settlement path and
  accounts it with the v1 merchant-fee formula.
- No browser message can mark an invoice paid.
- External top-level recovery works across the supported browser matrix.
- A safe resume/history path cannot create a duplicate payer attempt, and
  cleared browser storage is recoverable either directly or through a verified
  mandatory pre-funding backup.
- Iframe mode, if enabled, passes CSP, storage, wallet, message, and recovery
  tests and can be rolled back independently.
- POS and wallet-created invoices never expose the stablecoin rail.
- Existing Lightning, Liquid, Bitcoin, Bolt Card, invoice accounting, claim,
  and recovery suites pass.
- Success, expiry, refund, restart, webhook-loss, partial, mixed-rail, and
  overpayment cases have end-to-end evidence.
- Operator disablement prevents new handoffs without stranding settlement or
  payer recovery.
- A continuous deployed-origin canary fails closed when the hosted build stops
  honoring destination, direction, receive asset, amount, or `lockOutput`.

## 23. Source Index

Official Boltz documentation:

- [API introduction](https://api.docs.boltz.exchange/)
- [REST API v2 and create errors](https://api.docs.boltz.exchange/api-v2.html)
- [SDKs and libraries](https://api.docs.boltz.exchange/libraries.html)
- [Common mistakes](https://api.docs.boltz.exchange/common-mistakes.html)
- [Claims and refunds](https://api.docs.boltz.exchange/claiming-swaps.html)
- [Commitment swaps](https://api.docs.boltz.exchange/commitment-swaps.html)
- [Web App URL parameters](https://web.docs.boltz.exchange/urlParams.html)
- [Routed stablecoin architecture](https://blog.boltz.exchange/p/introducing-usdt-swaps-from-sats)
- [Boltz terms](https://boltz.exchange/terms)

Pinned Boltz Web App implementation:

- [Mainnet stablecoin assets](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/packages/boltz-swaps/src/presets/mainnet.ts#L160-L217)
- [URL parameter handling](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/src/context/Create.tsx#L183-L249)
- [Output-lock tests](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/e2e/urlParams.spec.ts#L404-L455)
- [Parent notification](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/src/utils/notifyParent.ts#L6-L30)
- [Final-status message](https://github.com/BoltzExchange/boltz-web-app/blob/a340ec381d48dacf02b54e4a3d267c1c74a747f3/src/components/SwapChecker.tsx#L80-L90)

Bullnym implementation seams:

- `src/invoice.rs`: anonymous surface creation, current Lightning offers,
  public status, canonical invoice render, remaining amount, and BOLT11 reuse.
- `src/db/invoices.rs`: invoice projection, inserts, and payment evidence.
- `src/donation_render.rs`: Payment Page/POS PWA config and CSP.
- `pwa/lib/components/PaymentScreen.svelte`: shared rail UI and authoritative
  status polling.
- `pwa/lib/components/PayFlow.svelte`: Payment Page/POS shared pay lifecycle.
- `pwa/lib/api/client.ts`: public invoice and Lightning offer contracts.
- `pwa/lib/config.ts`: injected surface mode and rollout config.
- `templates/invoice_payment.html`: canonical server-rendered payment page.

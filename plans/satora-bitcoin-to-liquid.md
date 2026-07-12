# Satora Bitcoin-to-Liquid Integration Plan

Status: **BLOCKED AT VENDOR CAPABILITY GATE**

Prepared: 2026-07-09

Scope: Bullnym wallet invoices, Payment Pages (the `donation_pages` payment-page
kind), and POS checkout

Target outcome: the payer sends Bitcoin on-chain and the recipient receives the
invoice amount as Liquid Bitcoin (L-BTC)

This is a conditional implementation plan. It deliberately does not invent a
Satora Liquid endpoint that is absent from Satora's published contract.

## 1. Executive Decision

Bullnym cannot implement the requested settlement path against Satora's current
documented API.

As of this plan:

- Satora OpenAPI version `0.2.49` has a core `Chain` enum containing `Bitcoin`,
  `Lightning`, `Arkade`, and EVM chain IDs `1`, `137`, and `42161`. Satora also
  documents optional bridge destinations, but neither the core enum nor those
  bridge destinations define Liquid, Elements, or L-BTC. See the
  [official OpenAPI specification](https://docs.satora.io/openapi.json),
  [supported-pairs endpoint](https://docs.satora.io/api-reference/swap-pairs),
  and [supported tokens](https://docs.satora.io/quotes-rates/supported-tokens).
- The published quote endpoint is for BTC to/from EVM tokens, not L-BTC. See
  [Satora quote reference](https://docs.satora.io/api-reference/quote).
- Satora states that its REST API is not intended for direct production use and
  may change without notice; it recommends its TypeScript SDK. See
  [API, SDK and iframe](https://docs.satora.io/api-sdk).
- Satora warns that a backend-managed integration introduces custody tradeoffs
  and asks backend integrators to contact them. See the
  [integration FAQ](https://docs.satora.io/faq/integration).

Therefore:

1. **Do not start a Satora implementation until Gate 0 passes.**
2. **Keep the existing Boltz BTC-to-LBTC path enabled for Payment Page and POS.**
3. **Do not substitute Arkade BTC, WBTC, tBTC, or an EVM two-hop route for
   Liquid Bitcoin.** They are different assets and settlement systems.
4. If Satora cannot supply a production-supported native Bitcoin-to-Liquid
   contract, close this integration as a no-go and continue using Boltz for the
   requested outcome.

## 2. Current Bullnym Baseline

| Surface | Payer's Bitcoin rail today | Recipient settlement today | Required change |
|---|---|---|---|
| Payment Page / Donation | Boltz BTC-to-LBTC chain swap | Descriptor-derived Liquid address | Make the BTC-to-LBTC provider selectable; preserve Boltz until Satora passes all gates. |
| POS | Boltz BTC-to-LBTC chain swap | POS descriptor-derived Liquid address | Same provider selection, with an independent rollout flag. |
| Linked wallet invoice | Direct BTC to merchant-supplied Bitcoin address | BTC | Add an explicit BTC-to-LBTC settlement mode using the invoice's Liquid address. |
| Unlinked wallet invoice | Direct BTC to merchant-supplied Bitcoin address | BTC | Add only after an npub-scoped recovery design is proven. |

Verified implementation points:

- Payment Page, POS, and alias checkout all enter
  `create_anonymous_for_kind` in `src/invoice.rs`.
- Checkout allocates one concrete Liquid address, stores an
  `origin = "checkout"` invoice, and independently attempts Lightning and
  Bitcoin offers. A provider outage does not remove the direct Liquid rail.
- `create_bitcoin_chain_offer` in `src/invoice.rs` creates the current Boltz
  chain swap.
- `chain_swap_records` and `src/db/chain_swaps.rs` are Boltz-specific. Their
  required fields include a Boltz ID, preimage, claim key, refund key, and raw
  Boltz response.
- The chain-swap claimer records invoice accounting only after L-BTC has been
  claimed to the merchant address. A payer-side BTC lockup is progress, not
  payment completion.
- Wallet invoice `accept_btc` currently means direct Bitcoin and requires
  `bitcoin_address`. Wallet invoice creation only creates a Lightning swap; it
  does not create a BTC-to-LBTC offer.
- The signed `invoice-create` action has a fixed 13-field payload shared with
  Bull Bitcoin Mobile. Its ordering is a wire contract.
- Public status is read-only. It exposes an existing
  `bitcoin_chain_address`/`bitcoin_chain_bip21`; it does not create or refresh
  an expired chain offer.
- Current merchant chain-swap recovery is linked-nym-only and default-off.
  Unlinked invoices cannot safely reuse it.

The existing payment and settlement separation is correct and must remain:

```text
BTC funding seen       -> invoice in_progress, settlement pending
L-BTC recipient proof  -> idempotent payment event, invoice paid/overpaid
funded swap fails      -> recovery/refund state, never paid
```

## 3. Non-Negotiable Product and Money Invariants

These decisions apply to every provider.

1. **Exact recipient output.** `invoices.amount_sat` is the net L-BTC amount the
   recipient is owed. The quote is exact-output. The payer's BTC amount is
   grossed up for protocol and network fees. Verified settlement must be at
   least the recorded recipient amount; excess is accounted as overpayment and
   any short payout remains partial/manual-review rather than passing through a
   shortfall tolerance.
2. **No false settlement.** Quote creation, a BTC address, BTC mempool sighting,
   BTC confirmation, or a provider callback is not accounting evidence. Credit
   the invoice only after Bullnym verifies recipient-side L-BTC settlement.
3. **Provider policy is immutable per invoice/payment session.** Snapshot the
   BTC-to-LBTC provider before the first offer can be exposed and persist it on
   the invoice or an invoice-level policy row. Every later offer generation for
   that invoice uses the same provider. Configuration changes apply only to new
   invoices/payment sessions.
4. **No active-offer failover.** Once a Bitcoin address has been exposed, never
   mutate or reinterpret that offer and never create a concurrent replacement
   for the same invoice, even under a different payer capability or recovery
   scope. A later offer generation is allowed only after the prior offer expired
   and both provider state and Bitcoin evidence prove it unfunded at the
   replacement decision. The old attempt still keeps its original
   worker/recovery path because late funding remains possible.
5. **Payer and recipient amounts remain distinct.** Store both. A Bitcoin QR
   must encode the payer BTC amount, never the invoice's net L-BTC amount.
6. **One Bitcoin choice per wallet invoice.** Direct BTC and BTC-to-LBTC are
   settlement modes of the Bitcoin rail, not two indistinguishable tabs.
7. **Unknown provider states fail closed.** They produce an alert and
   `manual_review`; they never mark an invoice paid or initiate an unsafe
   refund.
8. **Every funded state has a recovery owner.** Production enablement is
   prohibited until the responsible party, key material, destination, and
   runbook are defined for every failure state.
9. **Flags stop creation, not recovery.** Disabling Satora must stop only new
   offers. Reconciliation, settlement verification, and refund workers continue
   until all in-flight attempts are terminal.
10. **Provider settlement and direct Liquid cannot double count.** If the
    existing Liquid watcher observes the same payout transaction, the provider
    payment event must atomically replace/deduplicate that direct-Liquid event by
    transaction evidence.

## 4. Gate 0: Obtain a Real Satora BTC-to-LBTC Contract

Owner: Bullnym technical lead plus Satora engineering/support

Code changes allowed in this phase: documentation and disposable contract
fixtures only

Ask Satora for a written, versioned backend integration contract covering all
of the following.

### 4.1 Asset and network support

- Native Bitcoin mainnet source and Liquid mainnet L-BTC target identifiers.
- Liquid testnet/regtest or a vendor sandbox that exercises the same protocol.
- The canonical L-BTC asset ID and explicit rejection of non-L-BTC assets.
- Confidential Liquid address support. Confirm whether unconfidential addresses
  are supported or rejected.
- Whether Satora pays directly to the recipient address or Bullnym must claim a
  Liquid HTLC.

### 4.2 Quote contract

- Exact-output quote support where the requested output is denominated in L-BTC
  satoshis.
- A bindable `quote_id` or equivalent, `expires_at`, input amount, output
  amount, fee breakdown, and minimum guaranteed output.
- Which provider/server fees are included in the quoted Bitcoin deposit amount.
- The BIP21 amount is the deposit-output value; confirm separately that the
  payer's wallet pays its own Bitcoin transaction mining fee in addition to
  that output amount.
- Minimum and maximum amounts, rounding rules, and integer widths.
- Behavior if the quote changes between quote and create.
- Rules for partial, low, high, multiple, late, and replacement (RBF) funding
  transactions.

The current public `/quote` response has no quote ID or expiry. That is not
sufficient for a fixed-output invoice contract.

### 4.3 Create and idempotency contract

- A production-supported create operation accepting the exact L-BTC output and
  recipient Liquid address.
- A client-generated idempotency key with deterministic replay behavior.
- A recovery lookup for an ambiguous create timeout. It must return the
  original swap and Bitcoin deposit address rather than create a second swap.
- Bitcoin address type, exact BIP21, deposit expiry, required confirmations,
  and network validation fields.
- Structured errors with stable machine-readable codes.
- Defined retry behavior for `409`, `429`, transport failures, `5xx`, and
  timeouts, including `Retry-After` where relevant.

The current OpenAPI does not document create idempotency. A duplicate hash may
return `409`, but that does not reliably recover a lost create response.
Satora does publish `POST /swap/recover`, which scans deterministic `user_id`
derivations from an xpub. Gate 0 must establish whether that endpoint is a
supported, deterministic way to resolve an ambiguous backend create, including
its gap limit and response-loss behavior, or whether Satora will provide a
dedicated idempotency lookup. See the
[recovery endpoint](https://docs.satora.io/api-reference/swap/recover).

The current documentation also conflicts on the Bitcoin deposit output type:
one create schema describes `btc_htlc_address` as P2WSH while the HTLC/refund
guides describe Taproot/P2TR. Satora must resolve this and provide script/address
validation fixtures before Gate 0 can pass. See the
[Bitcoin-to-EVM create reference](https://docs.satora.io/api-reference/swap/bitcoin/evm)
and [on-chain refund guide](https://docs.satora.io/handle-failures/refund-onchain-htlc).

### 4.4 Lifecycle and settlement proof

- Exhaustive states and legal transitions for Bitcoin-to-Liquid specifically.
- Explicit handling for every published state. In particular, the current
  OpenAPI includes `serverwontfund`, but the published state-machine guide does
  not explain or classify it.
- Which state means the L-BTC payout transaction has been broadcast and which
  state is final.
- Liquid payout transaction ID, output index if available, asset, amount,
  destination, confirmation count, and reorg behavior.
- A signed webhook contract with event ID, raw-body signature, timestamp,
  replay window, ordering, retry policy, and secret rotation, or a supported
  polling/SSE/WebSocket contract with equivalent operational guarantees.
- An authoritative read endpoint used to reconcile dropped or duplicated
  events.

Satora's current generic state machine says `serverredeemed` is final for its
published atomic-swap flows, but a future Liquid flow must be documented rather
than inferred from that model. See the
[published state machine](https://docs.satora.io/advanced/state-machine).

### 4.5 Refund, custody, and recovery

- Who holds the BTC refund key and any L-BTC claim key.
- Who can trigger each cooperative and unilateral recovery path.
- Exact timelocks and fee ownership.
- Safe resolution of settlement-vs-refund races.
- How a backend operator recovers after database loss from deterministic key
  material.
- Whether the original payer can receive a refund directly, or whether Bullnym
  becomes the temporary custodian and must forward it.

Satora's current on-chain guide requires a locally held key and a refund
transaction after the HTLC locktime. See the
[on-chain refund guide](https://docs.satora.io/handle-failures/refund-onchain-htlc).

### 4.6 Production support

- Stable REST contract suitable for a Rust service, or a supported alternative
  with a committed compatibility policy.
- Authentication/organization attribution, rate limits, quotas, SLA, incident
  channel, data retention, and API/version deprecation policy.
- Reconcile the current authentication terminology: setup documents optional
  `X-Org-Code` attribution, the FAQ separately mentions an optional API key,
  and OpenAPI declares no security scheme. An organization code is attribution,
  not a credential, unless Satora contracts otherwise.
- Sandbox credentials and deterministic test fixtures.

Bullnym should prefer a vendor-supported REST contract implemented with the
existing Rust `reqwest` stack. A Node/TypeScript SDK sidecar adds a new runtime,
key store, deployment unit, and failure boundary. Add one only through a
separate architecture decision if Satora will not support Rust/REST.

### Gate 0 exit criteria

All items below are required:

- The Satora contract names Liquid/L-BTC explicitly.
- Contract fixtures and a sandbox are available.
- Exact-output and idempotent create semantics are testable.
- Settlement transaction evidence and recovery behavior are documented.
- A backend custody model is approved.
- A low-value sandbox/testnet BTC-to-LBTC success and refund have both been
  demonstrated outside Bullnym.

If any item fails, stop. Do not build a two-hop workaround.

## 5. Target Architecture After Gate 0

### 5.1 Keep the provider boundary narrow

Add a `bitcoin_liquid` domain module. It owns offer orchestration and canonical
status, but it does not pretend that all providers claim or refund the same way.

Suggested layout:

```text
src/bitcoin_liquid/mod.rs          domain types and orchestration
src/bitcoin_liquid/provider.rs     quote/create/status capability trait
src/bitcoin_liquid/satora.rs       Satora HTTP adapter and validation
src/bitcoin_liquid/worker.rs       polling/reconciliation dispatcher
src/db/bitcoin_liquid_swaps.rs     Satora/common persistence facade
```

The narrow interface should represent only semantics Bullnym can enforce:

```rust
#[async_trait]
trait BitcoinToLiquidProvider {
    async fn capabilities(&self) -> Result<Capabilities, ProviderError>;
    async fn quote_exact_output(
        &self,
        request: ExactOutputQuoteRequest,
    ) -> Result<BoundQuote, ProviderError>;
    async fn create_offer(
        &self,
        request: CreateOfferRequest,
    ) -> Result<CreatedOffer, ProviderError>;
    async fn get_status(
        &self,
        external_id: &str,
    ) -> Result<ProviderSwapStatus, ProviderError>;
}
```

Provider-specific claim, cooperative recovery, unilateral refund, and key
derivation stay in provider-specific code. Boltz's local Liquid claim and BTC
refund machinery must not be forced into a Satora-shaped abstraction.

### 5.2 Preserve active Boltz storage

Do not initially generalize or rewrite `chain_swap_records`. Its schema and
claimer encode live Boltz invariants. Making all its key fields nullable to fit
an unknown provider would weaken those invariants and put active recovery at
risk.

After Gate 0, add a parallel `bitcoin_liquid_swap_attempts` table for new
Satora attempts. Do not use that provider-specific table alone to coordinate
offer creation. Add a provider-neutral `bitcoin_liquid_offer_slots` table that
every new Boltz and Satora offer must acquire before an address can be exposed.
There is exactly one active slot per invoice, regardless of provider, output
amount, or recovery scope. The recipient output amount and recovery scope
(merchant-global or hashed payer capability) are stored on the slot, so a
partial payment or a second capability cannot open another full-value offer.
The slot stores the immutable invoice provider policy, attempt reference,
generation, exposure time, funding-seen time, and release/replacement proof.
Creation must also query/backfill any pre-existing pending Boltz attempt so a
deployment cannot expose Satora beside a live legacy offer. Switching an
invoice from the legacy global Boltz-offer model to payer-scoped Satora is
prohibited until the legacy offer is expired and authoritatively unfunded.

Common Satora attempt columns should include:

```text
id UUID primary key
invoice_id UUID foreign key
provider TEXT                         -- "satora"
external_id TEXT nullable until create returns
idempotency_key UUID unique
quote_id TEXT
recipient_liquid_address TEXT         -- immutable snapshot
payer_btc_address TEXT
payer_btc_bip21 TEXT
payer_amount_sat BIGINT
recipient_amount_sat BIGINT
protocol_fee_sat BIGINT
network_fee_sat BIGINT
total_fee_sat BIGINT
other_fee_sat BIGINT
fee_breakdown_json JSONB                 -- typed/validated, non-secret
offer_expires_at TIMESTAMPTZ
refund_locktime TIMESTAMPTZ nullable
canonical_status TEXT
provider_status TEXT
btc_funding_txid TEXT nullable
liquid_settlement_txid TEXT nullable
liquid_settlement_vout INTEGER nullable
refund_address TEXT nullable
refund_txid TEXT nullable
create_attempts INTEGER
reconcile_attempts INTEGER
last_error_code TEXT nullable
last_error_sanitized TEXT nullable
last_reconciled_at TIMESTAMPTZ nullable
created_at / updated_at TIMESTAMPTZ
```

Required constraints and indexes:

- Unique `(provider, external_id)` when `external_id` is non-null.
- Unique idempotency key.
- Positive payer and recipient amounts.
- Non-negative normalized fee fields; `total_fee_sat` must equal the validated
  sum of all same-unit fee components. The typed breakdown must preserve every
  contract-defined category instead of assuming only protocol/network fees.
- Payer amount greater than or equal to recipient amount unless the vendor's
  reviewed fee contract proves otherwise.
- The provider-neutral slot, not a provider column, enforces active-offer
  uniqueness with a partial unique constraint on `invoice_id` while the slot is
  active. Recovery scope and capability hash are attributes, not part of the
  uniqueness key.
- The same payer capability may retrieve its active offer after a lost response.
  A different capability receives a non-revealing conflict and cannot see or
  replace the existing offer.
- Releasing a slot requires provider-terminal unfunded state plus authoritative
  Bitcoin evidence that no funding was seen. Provider wall-clock expiry alone
  is insufficient. A replacement gets a new generation; the prior attempt
  remains monitored for late funding.
- Index nonterminal attempts by `last_reconciled_at` for bounded polling.
- Canonical-state check constraint.
- Immutable provider, invoice, destination, quote amounts, and recovery owner
  after an offer is exposed.

Store provider-specific protocol material in a separate
`satora_swap_material` table or derive it from a dedicated, domain-separated
master key and stored sequence index. Never place credentials, mnemonics,
private keys, preimages, raw signed payloads, or refund secrets in a generic raw
JSON column or logs.

Persist the create intent, idempotency key, key index, invoice link, quote, and
destination before making the external create request. This is required to
recover a response lost after Satora accepted the request.

### 5.3 Canonical state machine

Use a Bullnym state machine that reflects the product, not Satora's spelling:

```text
creating
awaiting_btc
btc_seen
btc_confirmed
lbtc_pending
lbtc_seen
settled
expired_unfunded
refund_due
refunding
refunded
failed_unfunded
manual_review
```

Rules:

- State movement is forward-only except a separately modeled reorg observation.
- `btc_seen` sets invoice payment status to `in_progress` and settlement status
  to `pending`.
- `settled` requires verified Liquid evidence and an idempotent payment event.
- A funded failure enters `refund_due` or `manual_review`, never an unfunded
  terminal state.
- Refund and settlement transitions use a per-attempt advisory lock/CAS so they
  cannot both pay out.
- Every vendor status is mapped exhaustively in tests. Unknown statuses alert
  and map to `manual_review` without executing a monetary action.

## 6. Configuration and Provider Selection

Add configuration only after the Satora contract is known:

```toml
[bitcoin_to_liquid]
default_provider = "boltz"
satora_create_enabled = false
satora_payment_pages_enabled = false
satora_pos_enabled = false
satora_linked_invoices_enabled = false
satora_unlinked_invoices_enabled = false
poll_interval_secs = 30
max_per_tick = 100
max_inflight_value_sat = 0

[satora]
api_url = "https://api.satora.io"
request_timeout_ms = 10000
organization_code = ""
```

Requirements:

- `api_url` is an operator-controlled fixed HTTPS origin, never request input.
- Validate environment/network capabilities at startup and periodically.
- Missing Liquid capability disables only new Satora offers and raises an
  operator alert. It must not take down Lightning, direct Liquid, status, or
  in-flight recovery.
- Snapshot the provider policy on the invoice/payment session and copy it onto
  each attempt. Workers dispatch from persisted state, not the current global
  default.
- Authentication secrets, if the approved contract introduces them, are
  sourced from environment/deployment secret storage and redacted from
  `Debug`, logs, and readiness output. Optional organization attribution is
  configured separately and is not treated as authentication.
- Startup permits create flags only when the required polling/recovery workers
  are enabled.

Touch points: `src/config.rs`, config validation/tests, `src/lib.rs::AppState`,
startup in `src/main.rs`, sample `config.toml`, readiness, and deployment
configuration.

## 7. Invoice and Public API Contract

### 7.1 Wallet invoice signing compatibility

Do not silently change existing `accept_btc`. Its legacy meaning remains direct
BTC when no new field is present.

Add one optional trailing signed field:

```text
bitcoin_settlement_mode = "none" | "direct_btc" | "liquid_btc"
```

Signature rules:

- The original 13 fields remain byte-for-byte unchanged.
- The signed enum is `"none" | "direct_btc" | "liquid_btc"`.
- When `bitcoin_settlement_mode` is absent, verify the legacy 13 fields and map
  `accept_btc=true` to `direct_btc`, otherwise to `none`.
- When present, append it after `expires_at_unix` and verify 14 fields.
- New mobile clients always send and sign the field.
- A stripped or modified field fails verification.
- Update Bull Bitcoin Mobile's `bullpay_la_v2_signing.dart`, server/mobile
  golden vectors, `docs/compatibility-ledger.md`, ADR-005, and the API reference
  in lockstep.

Validation:

| Mode | Required | Rejected |
|---|---|---|
| `direct_btc` | `accept_btc=true`, canonical unique mainnet `bitcoin_address` | Missing Bitcoin address |
| `liquid_btc` | `accept_btc=true`, canonical mainnet `liquid_address`, matching blinding key | Merchant Bitcoin address as settlement destination |
| `none` | `accept_btc=false` | Bitcoin address or another Bitcoin settlement mode |

The blinding key is required for `liquid_btc` even when `accept_liquid=false`,
because Bullnym must independently verify the settlement asset, destination,
and amount.

Add a wallet-only database settlement-mode column and constraints. Do not
rewrite old invoice semantics:

- Existing wallet rows with `accept_btc=true` backfill to `direct_btc`.
- Existing rows without direct BTC backfill to `none`.
- Checkout keeps its provider offer represented by swap-attempt records; its
  legacy `accept_btc=false` behavior remains compatible.
- The direct Bitcoin watcher continues selecting only rows in `direct_btc`
  mode with a non-null Bitcoin address.
- The migration explicitly replaces `invoices_btc_pair_chk` so
  `liquid_btc` does not require `bitcoin_address`, and updates
  `invoices_at_least_one_rail_chk`, `invoices_ln_or_liquid_addr_chk`, and the
  direct-Bitcoin watcher index/query to include the settlement-mode rules.
- Add a nullable invoice/payment-session provider-policy field (or an
  invoice-level policy row) for BTC-to-LBTC. Set it at invoice creation from
  the surface flag/default and never recalculate it from live configuration.

### 7.2 Idempotent Bitcoin offer endpoint

Add an endpoint analogous to lazy Lightning offer creation:

```text
POST /api/v1/invoices/:id/bitcoin
```

Responsibilities:

1. Load the invoice and current `remaining_amount_sat`.
2. Confirm the invoice is payable and its surface/mode permits BTC-to-LBTC.
3. Reuse a still-valid offer for the same remaining output amount only inside
   the same provider-neutral offer slot and, for payer-bound recovery, the same
   capability. A different capability cannot create a concurrent offer.
4. Serialize concurrent requests using an invoice/amount creation lease or
   advisory lock.
5. Create a new exact-output quote and offer only when no reusable offer exists.
6. Persist intent before the provider call and recover ambiguous responses by
   idempotency key.
7. Return a definite failure without blind retry if create acceptance is
   unknown.
8. Apply existing public invoice rate limits and a tight body limit.

`GET /api/v1/invoices/:id/status` remains read-only. A status poll must never
create a billable provider object.

The endpoint shape is finalized with the per-surface recovery decision in
Section 9. Under a payer-bound model, the caller generates a 256-bit random
capability, submits it with a refund address over TLS, and retains it locally.
Bullnym atomically claims the invoice-global offer slot and stores only the
capability hash plus immutable refund address before provider creation.
Repeating the same capability recovers an offer after a lost response;
a different capability receives a non-revealing `offer_in_use` conflict until
the active slot can be safely released. Offer status is polled through the same
capability. Public invoice status reports only aggregate invoice state. Under a
merchant-recovery model the current globally reusable offer shape can remain.

### 7.3 Response fields

Keep the current fields for client compatibility:

```json
{
  "bitcoin_chain_address": "bc1...",
  "bitcoin_chain_bip21": "bitcoin:bc1...?amount=..."
}
```

Add:

```json
{
  "bitcoin_chain_payer_amount_sat": 101234,
  "bitcoin_chain_recipient_amount_sat": 100000,
  "bitcoin_chain_fee_sat": 1234,
  "bitcoin_chain_expires_at_unix": 1780000000,
  "bitcoin_chain_status": "awaiting_btc"
}
```

Contract rules:

- `bitcoin_chain_bip21` must encode `bitcoin_chain_payer_amount_sat`.
- The PWA may construct a fallback BIP21 only from that payer amount. It must
  never substitute `remaining_amount_sat` under gross-up pricing.
- These offer fields are returned by create/reuse and capability-scoped status.
  They may also appear in public invoice status only under the approved
  merchant-recovery model. The payer-bound model keeps them out of public
  invoice status.
- Any public `bitcoin_chain_status` is a coarse projection such as
  `awaiting_btc`, `payment_detected`, or `settling`; it never exposes
  `refund_due`, refund ownership, or operator-review details.
- Public responses never expose provider IDs, raw provider states, refund
  addresses, keys, preimages, operator errors, or recovery eligibility.
- Provider identity remains internal unless support requirements justify a
  separate non-sensitive reference.

Touch points: response structs and handlers in `src/invoice.rs`,
`pwa/lib/api/client.ts`, `pwa/lib/rails.ts`, `pwa/lib/payloads.ts`, shared
`PaymentScreen.svelte`, and their tests.

### 7.4 Surface behavior

Payment Page and POS continue to work if Satora is unavailable:

- Invoice creation still allocates the Liquid address first.
- Lightning and direct Liquid remain available independently.
- Satora offer creation is best effort when those other rails exist.
- The Bitcoin tab shows a retryable unavailable state if the selected provider
  cannot create an offer.
- An invoice configured with only BTC-to-LBTC must not be reported as fully
  payable until an offer can be created. Return a clear retryable service error
  to the creating wallet or show a retry control on the shared payment page.
- Offer expiry is separate from invoice expiry. The UI refreshes an unfunded
  expired offer and never refreshes one after BTC funding evidence.
- After partial payment on another rail, an old offer for the prior amount is
  no longer presented as current. Bullnym must not create a replacement for the
  new remaining amount until the old offer expires and provider plus Bitcoin
  evidence proves it unfunded. Until then the Bitcoin rail is temporarily
  unavailable. The old attempt remains monitored for late funding even after a
  later generation is exposed.
- If another rail pays the invoice while a Bitcoin offer is exposed, hide that
  offer from new UI loads and cooperatively cancel it only if Gate 0 defines a
  safe unfunded-cancel operation. Continue monitoring the address because the
  capability holder may still fund it; any resulting L-BTC is recorded as
  actual overpayment, not discarded.

Lightning stays on the current Boltz reverse-swap implementation. This plan
changes only the on-chain Bitcoin-to-Liquid rail.

## 8. Events, Polling, and Settlement Verification

### 8.1 Webhook/event inbox

If Gate 0 supplies signed webhooks:

- Add a provider-specific route with a small body cap.
- Verify the raw body signature, timestamp, replay window, and configured
  secret before JSON parsing.
- Persist the event before acknowledging it.
- Uniquely key events by provider event ID, or a documented canonical digest if
  no ID exists.
- Namespace all keys by provider.
- Treat event payloads as hints. Refetch authoritative swap state when the
  event does not contain sufficient settlement proof.
- Accept duplicate and out-of-order delivery idempotently.
- Support current/previous secrets during a bounded rotation window.

Satora's SDK documents a `subscribeToSwaps` WebSocket helper, but not the wire
URL/schema, reconnect behavior, ordering, heartbeat, authentication, or
delivery guarantees needed by a Rust backend. Polling is therefore the only
fully documented backstop for a Rust REST adapter unless Gate 0 gives Bullnym a
supported contract for that WebSocket mechanism or another event channel.
See the [BTC-to-EVM guide](https://docs.satora.io/create-swaps/btc-to-evm).

### 8.2 Polling reconciler

Add a Satora reconciliation worker that:

- Selects nonterminal attempts oldest/least-recently-polled first.
- Uses bounded concurrency, per-request timeouts, jitter, backoff, and a
  `max_per_tick` cap.
- Uses DB leases, `FOR UPDATE SKIP LOCKED`, or advisory locks so multiple web
  instances do not process the same attempt concurrently.
- Retries idempotent reads only.
- Maps provider state through the same handler used by webhooks.
- Continues running when Satora create flags are disabled.
- Has a bounded settlement-repair pass for terminal provider rows missing an
  invoice payment event.

The existing `src/reconciler.rs` is directly coupled to Boltz. Keep it intact;
add a new worker or provider dispatcher rather than risking active Boltz swaps.

### 8.3 Independent Liquid proof

Before recording a Satora payment event, verify through Bullnym's Liquid
backend:

1. The provider-reported payout transaction exists.
2. It pays the immutable invoice Liquid address.
3. The output unblinds with the stored blinding key.
4. The asset is the canonical mainnet L-BTC asset.
5. The net amount is at least the recorded recipient output. BTC-to-LBTC exact
   output uses zero shortfall tolerance: a smaller payout is actual partial
   value/manual review, never paid. Actual excess is recorded for overpayment.
6. The agreed confirmation/finality policy is satisfied.
7. Any reorg before final accounting is represented as an observation, not a
   contradictory payment event.

Add structured accounting evidence:

```text
source    = bitcoin_satora_chain
rail      = bitcoin
event_key = bitcoin_to_liquid:satora:<external_id>
txid      = verified Liquid settlement txid
vout      = verified recipient output index
```

Extend `invoice_payment_events` with generic `provider` and
`provider_external_id` evidence fields or Satora-specific constrained fields.
Keep historical `bitcoin_boltz_chain:*` keys unchanged.

The current accounting helper derives shortfall tolerance from `rail` alone,
which would apply the direct-Bitcoin tolerance to this event. Make tolerance
source-aware (or add a constrained settlement policy) so
`bitcoin_satora_chain` uses zero shortfall tolerance.

Generalize the existing direct-Liquid-vs-Boltz transaction deduplication so a
Satora payout observed by `chain_watcher` cannot also remain credited as
`liquid_direct`. Match the verified `txid:vout` where available rather than
assuming the entire provider transaction belongs to one invoice; Satora may
batch outputs. The reconciliation must happen in the same transaction that
inserts the provider-attributed event and recomputes invoice totals.

## 9. Refund and Recovery Design

This is a release gate, not a post-launch enhancement.

### 9.1 Decision required

Choose and document a model per surface before implementation. Remote Payment
Pages and shared invoices normally need payer-bound recovery; an attended POS
may deliberately use merchant recovery if the custody and out-of-band payer
compensation policy is approved.

**Payer-bound recovery**

- Have the payer generate a high-entropy capability and bind its hash plus a
  payer-provided mainnet BTC refund address before exposing the funding
  address. The clear capability is never logged or stored server-side.
- Keep the refund address out of public invoice status.
- Prevent another viewer of a shared invoice from replacing the recovery
  destination.
- Bullnym derives/holds only the protocol key needed to execute the committed
  refund and sends it to the bound payer destination.

**Alternative: merchant recovery with explicit custody**

- Preserve today's POS-style model in which the merchant receives recovered
  BTC and compensates the payer out of band.
- Document the custody/trust implication in the product and runbook.
- Add npub-scoped recovery for unlinked invoices; the current nym-only route is
  insufficient.

Do not expose a globally reusable public offer whose refund destination can be
set first-write-wins by any viewer of the invoice URL.

### 9.2 Recovery implementation requirements

- Provider-specific recovery code and keys remain separate from Boltz.
- Use a per-attempt advisory lock and compare-and-set transition from
  `refund_due` to `refunding` before any broadcast.
- Settlement workers exclude `refunding`; refund workers exclude settlement
  states that can still pay the recipient.
- A broadcast timeout is resolved by transaction lookup before rebroadcast.
- Refund destination is immutable after exposure/funding.
- Fee rate and net refund amount are stored for audit.
- A stale `refunding` backstop safely returns to `refund_due` only after proving
  no transaction was broadcast.
- Recovery discovery is signed and owner-scoped. Public status remains coarse.
- A deterministic key-recovery drill proves database restoration does not lose
  funded swaps.

Linked invoices may ship before unlinked invoices. Unlinked enablement requires
the npub-scoped recovery path and a successful end-to-end recovery test.

All Satora creation flags remain operationally ineligible until the selected
recovery model for that surface is implemented and has passed a real refund
test. No Satora deposit address may be returned before its recovery owner and
immutable destination/capability are committed.

## 10. Failure Semantics

The adapter and domain tests must cover every row below.

| Condition | Bullnym behavior |
|---|---|
| Quote/create unavailable, no external acceptance | Leave other rails payable; allow explicit retry. |
| Create response lost | Resolve by idempotency key/recovery lookup; never blind-create. |
| Offer expires unfunded | Mark `expired_unfunded`; permit a new offer for the current remaining amount. |
| BTC seen | Set invoice `in_progress` and settlement `pending`; stop refreshing that offer. |
| BTC RBF/reorg before required confirmations | Update observation; do not settle or refund prematurely. |
| Wrong/partial/over/late BTC amount | Follow the vendor's approved recovery mapping; never infer a happy path. |
| Satora funded/payout pending | Continue polling; do not record payment. |
| Verified L-BTC below required output | Record actual value as partial evidence/manual review with zero shortfall tolerance; never mark the invoice paid or credit the quoted amount. |
| Verified exact/over L-BTC output | Record actual recipient value idempotently and settle/overpay normally. |
| Provider says success but payout is absent/mismatched | `manual_review`, high-priority alert, no payment event. |
| Unknown provider status | `manual_review`, alert, no monetary action. |
| Funded swap fails | `refund_due`; no payment event. |
| Settlement and refund race | Advisory lock/CAS permits only one monetary path. |
| Satora outage during in-flight swap | Keep polling/recovery active; do not switch provider. |
| Operator disables Satora | Stop new offers only; drain existing attempts. |

## 11. Security and Privacy Requirements

- Validate all BTC and Liquid addresses with network-aware parsers, not string
  prefixes.
- Check every response network, asset, amount, destination, timestamp, and
  identifier before persistence or display.
- Use bounded HTTP timeouts and body sizes.
- Retry only documented idempotent operations.
- Do not log full npubs, confidential addresses unless operationally necessary,
  BIP21 values, keys, preimages, signatures, credentials, raw provider bodies,
  or refund capabilities.
- Store only a sanitized allowlist of provider response fields. If a raw audit
  blob is required, encrypt it and apply retention limits.
- Namespace webhook and accounting idempotency keys by provider.
- Rate-limit quote/offer creation independently from status polling.
- Keep the Satora origin fixed in configuration to avoid SSRF.
- Treat public invoice IDs as bearer-visible. Recovery, provider diagnostics,
  and internal failure details require signed owner authentication or a
  payer-scoped high-entropy capability.
- Review Satora terms/data handling before sending recipient addresses or
  identifiers.

## 12. Test Plan

### 12.1 Contract and unit tests

- Pin the approved Satora OpenAPI/contract fixture and version.
- Capability test fails closed when Liquid/L-BTC is absent.
- Exact-output arithmetic, all fee components, integer overflow, rounding, min,
  max, and expiry.
- Strict response validation for wrong network, asset, destination, amount, and
  malformed BIP21.
- Exhaustive provider-status mapping; an unknown fixture maps to
  `manual_review`.
- Error classification/redaction and retry eligibility.
- Legacy 13-field and new 14-field invoice signature golden vectors.
- Direct-BTC and liquid-BTC validation combinations.
- Provider-scoped idempotency/event-key tests.

### 12.2 Database and concurrency tests

- Duplicate create and ambiguous-response recovery.
- Two simultaneous Bitcoin-offer requests produce/reuse one active offer.
- Two distinct payer capabilities racing on one invoice produce one active
  offer; the loser receives a non-revealing conflict and no offer details.
- Duplicate, replayed, and out-of-order webhooks.
- Webhook/poller and poller/poller races.
- Provider status advances while operator flips the default provider.
- Crash after intent persistence, after external create, after payout detection,
  after payment-event insert, and during refund broadcast.
- Direct Liquid watcher and provider settlement see the same txid without
  double credit.
- Partial payment changes `remaining_amount_sat`; the next offer uses the new
  exact output and does not reuse the stale amount.
- Refund-vs-settlement mutual exclusion.
- Flags disabled while in-flight workers continue.

### 12.3 HTTP and PWA tests

- Payment Page, alias Payment Page, and POS create/display Satora offers only
  under their own flags.
- Linked wallet invoice selects `liquid_btc` without a merchant BTC address.
- Legacy wallet client remains direct BTC with byte-identical signing.
- Unlinked mode is rejected while its recovery flag is off.
- Bitcoin QR uses payer amount and provider BIP21.
- Offer-expired, provider-unavailable, BTC-seen, settlement-pending, paid,
  refund-required, and manual-review UI states.
- No private provider/recovery data in anonymous status or rendered HTML.
- Lightning and direct Liquid remain usable during Satora failure.

### 12.4 Real network gates

Before any production enablement:

1. Sandbox/testnet exact-output success.
2. Sandbox/testnet create response-loss recovery.
3. Sandbox/testnet late/invalid funding recovery.
4. Real low-value mainnet BTC-to-LBTC settlement to a Bullnym-derived
   confidential address.
5. Real low-value mainnet refund to the approved recovery owner.
6. Restart Bullnym at each lifecycle stage and prove reconciliation.
7. Reconcile Satora records, Bitcoin inputs, Liquid outputs, and invoice events
   to zero unexplained satoshi delta.

## 13. Observability and Runbooks

Metrics, all tagged by provider and surface without sensitive identifiers:

- quote/create success, error class, and latency
- active attempts by canonical state, age, count, and value
- BTC-seen to BTC-confirmed and BTC-confirmed to L-BTC-settled latency
- quote/input/output/verified-amount mismatch count and sats
- last successful provider poll and oldest unreconciled attempt
- webhook accepted, invalid, duplicate, and processing failure counts
- settlement repair count
- refund due/refunding/refunded count, age, and value
- manual-review count and total value at risk
- outstanding provider exposure versus configured caps

Alerts:

- any unknown provider status
- provider success without verifiable Liquid payout
- funded attempt past its expected settlement deadline
- polling freshness beyond two intervals
- refund approaching timelock/action deadline
- settlement/refund amount mismatch
- repeated create ambiguity or idempotency failure
- exposure cap reached

Required runbooks:

- Satora outage and create-disable procedure
- unknown/malformed provider response
- payout missing or wrong asset/address/amount
- stuck funded swap
- settlement-vs-refund race investigation
- deterministic key recovery and database restore
- webhook credential rotation
- Satora contract/version upgrade
- provider rollback while draining in-flight swaps

## 14. Rollout and Rollback

Rollout order:

1. Contract tests and fake provider only.
2. Sandbox/testnet behind all flags off by default.
3. Internal merchant allowlist on one Payment Page with strict per-swap, daily,
   and total in-flight value caps.
4. Internal POS.
5. Small linked-invoice cohort.
6. Wider Payment Page/POS cohort after a soak window and balance reconciliation.
7. Unlinked invoices last, only after npub/payer recovery is proven.
8. Consider changing the default provider only after sustained operational and
   financial reconciliation; keep Boltz available for operator-selected new
   offers.

Promotion gates at every step:

- zero unexplained accounting delta
- no unknown provider states
- no settlement/refund double action
- no unresolved create ambiguity
- recovery drill passed
- polling and alert freshness within target
- value-at-risk below configured limits

Rollback:

- Turn off the relevant Satora create flag.
- Do not delete routes, credentials, keys, rows, or workers needed by in-flight
  attempts.
- Do not move an exposed offer to Boltz.
- Keep polling, settlement verification, repair, and refund processing active.
- Switch the operator default to Boltz only for newly created invoices/payment
  sessions.
- Close the incident only after every Satora attempt is `settled`,
  `expired_unfunded`, `refunded`, or explicitly resolved from `manual_review`.

## 15. Implementation Sequence by Small Pull Request

No PR after PR 1 starts until Gate 0 passes.

1. **Capability ADR and fixtures**: record the approved Satora contract,
   exact-output/recovery decisions, pinned fixture, and no-go behavior.
2. **Domain types and fake provider**: canonical amounts/status/errors with no
   production Satora calls.
3. **Persistence migration**: attempt/material tables, constraints, queries,
   concurrency tests, and rollback-safe migration notes.
4. **Satora adapter**: stable Rust client, strict validation, capability probe,
   idempotent create recovery, and fixture tests.
5. **Config and worker wiring**: default-off flags, AppState client, polling,
   leases, metrics, and shutdown behavior.
6. **Settlement verifier and accounting**: Liquid proof, Satora evidence source,
   direct-Liquid dedup, and settlement repair.
7. **Recovery and offer-slot foundation**: per-surface recovery contract,
   provider-neutral offer slots, payer capability or merchant ownership,
   CAS/refund worker, and the real refund gate. Creation flags remain
   inoperable.
8. **Checkout offer service**: provider selection, lazy/reusable offer endpoint,
   payer amount/fee/expiry fields, Payment Page integration, and failure tests.
9. **POS enablement**: separate flag, POS recovery policy/regression tests, and
   operator limits.
10. **Wallet protocol extension**: optional trailing signed settlement mode,
   mobile/server golden vectors, database constraints, linked invoices, and
   API documentation.
11. **Unlinked invoice enablement**: npub-scoped recovery, privacy tests, and a
    dedicated flag.
12. **Production canary**: deployment config, dashboards, alerts, runbooks,
    mainnet settlement/refund, reconciliation report, and explicit go/no-go.

## 16. Definition of Done

The integration is complete only when:

- A payer can select Bitcoin on each enabled surface and receives a valid
  mainnet Bitcoin BIP21 for the exact gross payer amount.
- The stored invoice amount is the exact net L-BTC target.
- The recipient receives and Bullnym independently verifies that L-BTC at the
  immutable invoice Liquid address.
- Only the verified recipient amount is credited to the invoice.
- Duplicate events, restarts, response loss, reorgs, and mixed-rail observation
  cannot double count or falsely settle.
- Every funded failure has a tested refund path and known recovery owner.
- Legacy direct-BTC wallet invoices and their 13-field signatures still work.
- Lightning and direct Liquid behavior are unchanged.
- Disabling Satora stops new exposure while all existing attempts continue to
  settlement or refund.
- A production canary completes both a real settlement and a real refund with
  zero unexplained satoshi delta.

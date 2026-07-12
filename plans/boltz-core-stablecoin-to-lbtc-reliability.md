# Boltz Stablecoin-to-LBTC Reliability Architecture

Status: **PRODUCTION BLOCKED ON BOLTZ REVIEW, EXACT-LOCK ROUTER, AND CLAIM-POLICY GATES**

Prepared: 2026-07-09

Scope: wallet invoices, Payment Pages (the `payment_page` donation-page kind),
Payment Page aliases, and POS checkout. The payer sends canonical USDC or USDT0
on Arbitrum. The merchant receives L-BTC at the immutable Liquid destination
already assigned to the Bullnym invoice.

This document supersedes the hosted Boltz Web App and nested-BOLT11 candidate in
`plans/boltz-stablecoin-payment-page.md`. It analyzes a direct routed chain swap:

```text
USDC or USDT0 on Arbitrum
  -> atomic DEX execution
  -> exact TBTC lock in Boltz's Arbitrum ERC20Swap contract
  -> Boltz TBTC-to-L-BTC Chain Swap
  -> policy-constrained Liquid claim
  -> invoice.liquid_address
```

## 1. Executive Decision

Do not run the current Boltz Web App flow unchanged in a server sidecar. Do not
put payer EVM private keys or a Bullnym-controlled payer refund key in the
sidecar. Do not let normal Bullnym application code hold an exportable preimage
or Liquid claim key.

The strongest candidate architecture is:

1. Bullnym Rust remains the invoice, public API, and accounting authority.
2. A TypeScript coordinator uses pinned `boltz-swaps` and `boltz-core` code for
   quoting, swap validation, EVM and Liquid transaction construction, and Boltz
   protocol interaction.
3. A small, immutable, independently audited exact-lock router atomically swaps
   the payer's stablecoin, locks an exact TBTC amount under the real preimage
   hash, returns every surplus token to the payer, and sets the payer wallet as
   the immutable EVM refund address.
4. A separate policy claim executor owns the preimage and Liquid claim key. It
   verifies the Boltz Liquid lock independently and will only construct and
   broadcast a claim paying the invoice's immutable merchant script.
5. An independent EVM refund watchtower can call the permissionless refund path
   and pay gas. The Boltz contract sends the TBTC directly to the payer's
   immutable refund address; the watchtower cannot redirect it.
6. Bullnym records payment only after Rust independently verifies a confirmed
   L-BTC output at the invoice destination.

This exact-lock design is preferable to Boltz Web App's current commitment
flow because it removes the post-funding EIP-712 signature. After the payer
signs the one-time Permit2 intent, the payer can close the browser and the
coordinator can finish the authorized transaction. If settlement fails, any
watchtower can return the locked TBTC to the payer after the contract timelock.

It is not ready to implement blindly. Production is blocked until Boltz reviews
and supports this use of its API and contracts, the exact-lock router has an
independent smart-contract audit, and the policy claim executor prevents an
ordinary Bullnym compromise from exporting the preimage or redirecting the
merchant claim.

## 2. Honest Reliability Claim

An absolute statement that funds can never be stuck is not technically honest.
No Bullnym design can force progress during all of the following:

- an Arbitrum or Liquid halt;
- a stablecoin issuer freeze or token pause;
- a TBTC or DEX contract failure;
- censorship by every available RPC, sequencer, or Liquid broadcaster;
- compromise or destruction of every signer and recovery copy;
- a catastrophic finality failure or unexpected consensus change.

The defensible protocol guarantee is:

> Under the pinned-contract, chain-liveness, token-liveness, Boltz-protocol,
> and recovery-key assumptions in this document, every confirmed TBTC source
> lock has two independently executable outcomes: a policy-constrained L-BTC
> claim to the immutable merchant address, or a permissionless TBTC refund to
> the immutable payer address. A funded attempt is never abandoned merely
> because retries or an operator-attention threshold were exhausted.

Formally, for a confirmed source lock:

```text
eventually merchant_lbtc_confirmed XOR payer_tbtc_refund_confirmed
```

The refund asset is **TBTC**, not the payer's original USDC or USDT0. The DEX
trade happens before the Boltz lock, so the original stablecoin no longer
exists in the swap state. Automatically converting a refund back to the
original stablecoin requires a second DEX authorization and creates new
slippage, liquidity, and contract risks. V1 must return TBTC directly to the
payer. A separately authorized TBTC-to-stablecoin conversion can be considered
later, but it must never block or replace the unconditional TBTC refund.

If Bullnym wants to promise the merchant payment after a payer's source lock is
accepted, rather than merely promise one of settlement or refund, cryptography
is not enough. Bullnym must maintain an automatically callable make-whole
reserve sized above all outstanding exposure. The reserve pays the merchant
when a qualifying funded attempt breaches the settlement SLO while payer
refund automation continues. Per-token, per-merchant, daily, and global
admission caps must be derived from that reserve.

## 3. What `boltz-core` Does and Does Not Provide

The implementation should not be described as "run boltz-core". There is no
Boltz Core daemon that owns this lifecycle.

At the reviewed upstream snapshot:

- `boltz-core` is the MIT TypeScript reference library for Taproot swap trees,
  MuSig2, UTXO claim/refund transaction construction, and the EVM contracts and
  ABIs. The repository head reviewed here is version `5.0.0`.
- `boltz-swaps` is an MIT package inside the Boltz Web App monorepo. Version
  `0.0.9` exposes the API client, pair data, status sources, UTXO claim helpers,
  EVM contracts, commitment helpers, bridge code, and route primitives. The
  reviewed web app currently depends on `boltz-core ^4.0.5`.
- The full stablecoin-source route is not a single exported `boltz-core` call.
  In web-app commit
  [`a340ec381d48dacf02b54e4a3d267c1c74a747f3`](https://github.com/BoltzExchange/boltz-web-app/commit/a340ec381d48dacf02b54e4a3d267c1c74a747f3),
  source-side stablecoin route planning still lives in `src/utils/Pair.ts`, and
  payer lock orchestration still lives in `src/components/LockupEvm.tsx` and
  `src/components/SwapExecutionWorker.tsx`.
- The generic `packages/boltz-swaps/src/route.ts` planner looks for a direct
  pair from the source to the target, then applies `routeVia` to the target.
  That covers the opposite direction well, but it does not reproduce the web
  app's source-USDC/USDT0 -> TBTC -> L-BTC route by itself.
- `boltz-client` is the recommended server-side daemon but currently supports
  LN, BTC, and L-BTC, not this stablecoin route.
- `boltz-rust`, already used by Bullnym, supports LN, BTC, and L-BTC, not the
  stablecoin, DEX, Permit2, and EVM commitment lifecycle.

Therefore the sidecar should use a vendor-reviewed, pinned `boltz-swaps` plus
`boltz-core` build. Gate 0 must end with one of these outcomes:

1. Boltz exports and supports the stablecoin-source route through
   `boltz-swaps` and reviews the exact-lock extension; or
2. Boltz reviews a narrowly extracted Bullnym route module derived from the
   pinned web-app source and commits to a compatibility process.

Copying the whole web app into a server process is not acceptable. React/Solid
components, browser persistence, WalletConnect UI, bridge support, and rescue
file behavior are not server abstractions.

Relevant official guidance:

- [Clients, SDKs and libraries](https://api.docs.boltz.exchange/libraries.html)
  warns that a custom API integration is complex and unsupported unless Boltz
  is involved.
- [Common mistakes](https://api.docs.boltz.exchange/common-mistakes.html) says
  integrations should be client-side and end-user controlled. This proposal is
  an intentional deviation and therefore requires written Boltz review.
- [Claims and refunds](https://api.docs.boltz.exchange/claiming-swaps.html)
  requires clients to persist recovery state and implement cooperative and
  unilateral paths.
- [Do not trust, verify](https://api.docs.boltz.exchange/dont-trust-verify.html)
  requires local verification of provider responses, scripts, amounts, and
  contracts.

## 4. Current Boltz Stablecoin Flow

The current web app supports direct stablecoin-to-L-BTC as a routed chain
swap. For canonical Arbitrum assets, the route is:

```text
USDC or USDT0 -> DEX -> TBTC -> Boltz Chain Swap -> L-BTC
```

At the reviewed mainnet preset:

| Asset | Arbitrum token | Decimals | Route |
|---|---|---:|---|
| USDT0 | `0xFd086bC7CD5C481DCC9c85ebE478A1C0b69FCbb9` | 6 | via TBTC |
| USDC | `0xaf88d065e77c8cC2239327C5EDb3A432268e5831` | 6 | via TBTC |
| TBTC | `0x6c84a8f1c29108F47a79964b5Fe888D4f4D0dE40` | 18 | Boltz source asset |

These addresses are evidence from the reviewed snapshot, not configuration to
hardcode forever. Startup admission must compare the pinned policy against the
current chain ID, token bytecode, Boltz contracts response, and deployed
bytecode hashes. A mismatch pauses new attempts while all recovery workers
continue.

### 4.1 Why the web app uses a commitment

The DEX result can vary because of price movement and positive slippage. The
web app therefore cannot know the exact TBTC lock amount before the DEX call.
It:

1. gets a TBTC-to-L-BTC Chain Swap;
2. signs a Permit2 witness for the stablecoin input and the encoded DEX calls;
3. executes the DEX and locks all TBTC left in Boltz's router under
   `bytes32(0)` rather than the real preimage hash;
4. reads the actual TBTC amount from the EVM `Lockup` event;
5. asks the `refundAddress` signer for an EIP-712 `Commit` signature that binds
   the actual amount, TBTC token, Boltz claim address, refund address, timelock,
   and real preimage hash;
6. posts that signature to Boltz so Boltz can claim the commitment when the
   preimage is revealed.

The official [commitment-swap documentation](https://api.docs.boltz.exchange/commitment-swaps.html)
confirms that the commitment must be signed by `refundAddress` after the actual
amount is known.

### 4.2 The browser-closure problem

If the payer wallet is `refundAddress`, the payer is protected from Bullnym
redirecting a refund. But the wallet must sign again after the source lock is
confirmed. If the browser closes in that window, merchant settlement cannot
continue. The safe outcome is a later TBTC refund.

If a Bullnym-derived gas signer is `refundAddress`, the sidecar can sign the
commitment without the browser. But a refund is first paid to a Bullnym-held
EOA, after which Bullnym can transfer it anywhere. That achieves unattended
execution by introducing payer custody and an avoidable theft path.

The web app avoids handing that signer to Boltz by deriving it from the user's
rescue mnemonic. A server-side clone would instead make Bullnym the holder of
that rescue authority. This is not an acceptable default.

### 4.3 Useful contract property

The current Arbitrum `ERC20Swap` explicit refund overload is permissionless.
After timeout, any account can call `refund` with the exact lock tuple. The
contract transfers the tokens to the tuple's immutable `refundAddress`, not to
the caller. A cooperative refund has the same destination property after a
valid Boltz claim-address signature is supplied.

This means a gas-funded watchtower does **not** need the payer's key. The payer
refund address and full recovery tuple are also emitted in EVM logs. The hard
problem is the post-lock commitment signature, not refund transaction gas.

## 5. Strategy Comparison

| Strategy | Merchant autonomy | Payer protection from Bullnym | Refund without payer online | Main problem | Decision |
|---|---:|---:|---:|---|---|
| Hosted Boltz Web App/browser owns everything | Low | High | Eventually, if browser recovery works | Merchant claim depends on payer tab/client; recovery UX is external | Reject for merchant reliability |
| Sidecar copies commitment flow; payer EOA is refund signer | Medium | High | Timeout refund yes | Payer must sign the post-lock commitment | Safe fallback, not the target |
| Sidecar owns commitment/refund EOA | High | Low | Yes | Bullnym can capture refunded TBTC | Reject |
| Exact-TBTC normal lock plus policy claim executor | High | High | Yes | Requires audited router and policy signer | Recommended candidate |
| Boltz chain-swap claim covenant binding merchant output | Highest | Highest | Yes | Not currently documented for this route | Preferred vendor extension |

### 5.1 Fallback if exact-lock is rejected

If Boltz will not support the exact-lock router, the only noncustodial fallback
is the payer-owned commitment flow:

- payer EOA is the on-chain `refundAddress`;
- Bullnym stores and verifies the post-lock commitment signature;
- checkout is not considered fully submitted until Boltz accepts it;
- if the payer disappears before signing, the watchtower automatically refunds
  TBTC at timeout;
- Bullnym must not advertise guaranteed merchant completion after the first
  wallet transaction.

This fallback protects funds, but it does not satisfy the stated merchant
reliability objective. Bullnym-owned refund keys are not an acceptable way to
paper over that limitation.

## 6. Exact-Lock Router

Boltz's current router locks its entire TBTC balance. That makes the lock amount
unknown until the DEX transaction executes and forces the commitment flow. The
proposed router changes the invariant from "lock all" to "lock exactly the
amount authorized for this swap and return everything else."

The function is conceptually:

```solidity
executeExactOutputAndLock(
    Intent intent,
    Call[] dexCalls,
    PermitTransferFrom permit,
    address owner,
    bytes permitSignature
)
```

The signed intent must bind at least:

```text
chain_id
router address and code-policy version
invoice/attempt commitment
stablecoin token
maximum stablecoin input
TBTC token
exact TBTC lock amount
nonzero real preimage hash
Boltz claim address
payer refund address == Permit2 owner
Boltz source timelock
hash of every DEX call
Permit2 nonce and deadline
surplus recipient == payer
```

The router must:

1. be non-upgradeable and contain no owner withdrawal path;
2. accept only canonical Arbitrum USDC and USDT0 as source tokens in v1;
3. require canonical TBTC as output;
4. require `refundAddress == owner` and `surplusRecipient == owner`;
5. require a nonzero preimage hash;
6. constrain the timelock to the verified Boltz response and a safe policy
   range, preventing either an immediately refundable or unreasonably long
   lock;
7. pull exactly `maxStablecoinInput` through Permit2, never an unlimited
   signature transfer;
8. execute only immutable allowlisted DEX targets and selectors;
9. measure per-call balance deltas rather than trusting a global router
   balance;
10. revert unless the transaction produced at least `exactTbtcLockAmount`;
11. approve and call the pinned Boltz `ERC20Swap.lock` with the real preimage
    hash and exact TBTC amount;
12. return all remaining stablecoin and positive-slippage TBTC to the payer;
13. revoke temporary token approvals and finish with no attempt-owned token
    balance;
14. emit an event containing the immutable intent digest and Boltz lock tuple.

Using an exact-output DEX quote is not by itself sufficient. Positive slippage
can still produce more TBTC than requested. The contract, not an off-chain
calculation, must enforce the exact locked amount and payer surplus return.

The payer's ERC20 approval to canonical Permit2 should also be the exact maximum
input, not `uint256.max`. The router pulls that amount, uses what the exact-output
trade consumes, and returns the rest. If the atomic transaction reverts, the
Permit2 signature remains bounded by its short deadline and unique nonce. The
UI should still offer to revoke any remaining ERC20-to-Permit2 allowance.

The router must be audited against arbitrary calldata, approval persistence,
fee-on-transfer/rebasing token behavior, reentrancy, donated balances, malicious
DEX return values, proxy upgrades at call targets, and positive/negative
slippage. V1 should reject fee-on-transfer and rebasing assets entirely.

## 7. Recommended Component Boundaries

```text
Payer wallet / independent wallet verifier
  | exact ERC20 approval + exact Permit2 intent
  v
Bullnym Rust API and invoice authority
  | transactional commands; no sidecar accounting writes
  v
TypeScript Boltz coordinator (2+ replicas)
  | pinned boltz-swaps + boltz-core; no exportable preimage
  +--> restricted EVM gas relayer
  +--> Boltz API/status source
  +--> independent EVM and Liquid read nodes
  v
Policy claim executor
  | owns preimage and Liquid claim key
  | validates and directly broadcasts merchant-only claim
  v
Liquid network -> invoice.liquid_address

Independent refund watchtower
  | scans ERC20Swap logs; owns gas only
  v
Arbitrum ERC20Swap refund -> payer EOA (TBTC)
```

### 7.1 Bullnym Rust

Rust owns:

- invoice eligibility, remaining amount, expiry, and cancellation locks;
- the immutable merchant destination snapshot;
- public attempt creation, authorization, and status APIs;
- durable command and event transactions;
- independent Liquid settlement verification;
- `invoice_payment_events` and all invoice status/accounting changes;
- feature admission and readiness.

Rust must never accept "paid" from the sidecar. It must not give the sidecar
`UPDATE` access to `invoices` or `invoice_payment_events`.

### 7.2 TypeScript coordinator

The coordinator owns:

- current pair/fee/limit and DEX quote acquisition;
- deterministic attempt preparation;
- Boltz Chain Swap creation and response verification;
- exact-lock intent and calldata construction;
- source transaction persistence, broadcast, and reconciliation;
- status polling/WebSocket hints;
- destination-lock discovery;
- commands to the policy claim executor;
- cooperative and timeout refund scheduling;
- normalized attempt events back to Rust.

It is a stateful worker, not a public arbitrary-transaction or arbitrary-sign
service. Its public network surface should be private mTLS or a Unix socket
behind Rust. Every command is versioned and idempotent.

### 7.3 Policy claim executor

The coordinator cannot safely hold the preimage. In a chain swap, revealing the
preimage lets Boltz claim the payer's TBTC. A compromised coordinator that also
controls the Liquid claim can reveal the preimage while redirecting or
withholding the merchant output.

The claim executor must:

- generate or deterministically derive the preimage and claim key;
- return only `preimageHash`, `claimPublicKey`, a key version, and a recovery
  readiness attestation during preparation;
- keep raw secrets out of coordinator memory, PostgreSQL, logs, crash dumps,
  metrics, traces, and support endpoints;
- independently obtain and verify the Boltz swap response and Liquid lock;
- construct the complete claim transaction internally;
- enforce the immutable merchant script, minimum L-BTC amount, maximum fee,
  expected lock outpoint, and allowed change policy;
- run the Boltz MuSig interaction itself and fall back to a script-path claim
  without exporting the preimage;
- broadcast through independent Liquid backends and return only public
  transaction evidence;
- create an encrypted recovery capsule for the merchant or recovery quorum
  before funding is enabled.

A generic KMS call that signs arbitrary secp256k1 messages is not enough. The
security boundary has to inspect the Liquid transaction policy. A dedicated
enclave, restricted signer service, or reviewed MPC implementation is more
appropriate. The preferred long-term answer is a Boltz-supported Liquid claim
covenant for Chain Swaps that binds the claim to the merchant output on-chain.

### 7.4 Refund watchtower

Run a minimal watchtower in a separate account, region, and preferably cloud
provider. It needs only:

- pinned Arbitrum contract addresses and ABIs;
- public attempt manifests or on-chain event discovery;
- multiple RPC providers;
- an ETH gas key and fee reserve.

It never receives the refunded TBTC. It calls the explicit refund overload,
which transfers TBTC to the payer address committed in the lock tuple. It tries
a cooperative refund when Boltz supplies a valid claim-address signature and
otherwise broadcasts at the first timeout-eligible block.

### 7.5 Independent wallet verifier

A JavaScript verifier served by Bullnym cannot protect a payer from a fully
malicious Bullnym deployment, because that same deployment can replace the
verifier. The strongest v1 is a Bull Bitcoin Mobile wallet/deep-link or wallet
plugin that independently knows:

- chain and token allowlists;
- Permit2 and exact-lock router addresses and code hashes;
- the typed intent schema;
- allowed DEX call targets/selectors;
- the payer refund-address invariant;
- amount, slippage, and deadline limits.

Generic browser wallets may be supported only if the remaining trust in the
served page and wallet simulation is explicitly accepted. Reproducible static
builds, CSP, SRI, signed release manifests, and a transparency log are useful
defense in depth, but they are not equivalent to independent wallet validation.

## 8. Current Bullnym Baseline

The integration should extend Bullnym's existing payment architecture rather
than create a second invoice system.

### 8.1 Existing invoice and surface behavior

Bullnym currently uses the `invoices` table for merchant-created invoices and
anonymous Payment Page/POS checkout sessions.

- Payment Page, alias Payment Page, and POS all enter
  `create_anonymous_for_kind` in `src/invoice.rs`.
- An anonymous checkout allocates and persists one concrete confidential
  Liquid address before inserting the invoice.
- Payment Page uses its own descriptor when present and has a legacy nym
  descriptor fallback. POS requires its separate descriptor and never falls
  back to the Lightning Address wallet.
- Lightning, direct Liquid, and checkout BTC-to-L-BTC claims all settle to the
  invoice's persisted `liquid_address`.
- Wallet invoices use merchant-supplied Bitcoin and Liquid destinations. The
  current signed invoice creation action is a fixed wire contract shared with
  Bull Bitcoin Mobile.
- `payment_status` and `settlement_status` are already separate, which is the
  correct foundation for a routed stablecoin payment.
- `invoice_payment_events` are the accounting source of truth, and
  `record_invoice_payment` already serializes an insert plus cumulative invoice
  recomputation under a row lock.

Stablecoin eligibility should be:

| Surface | Eligibility | Merchant L-BTC destination |
|---|---|---|
| Payment Page | Page enabled, stablecoins enabled, payable invoice | Existing descriptor-derived `invoice.liquid_address` |
| Payment Page alias | Same page policy, alias ownership verified | Same stored address; alias never changes settlement |
| POS | POS enabled, stablecoins enabled, payable invoice | POS descriptor-derived stored address |
| Linked wallet invoice | Merchant enabled rail and supplied valid Liquid destination | Stored merchant Liquid address |
| Unlinked wallet invoice | Same, plus recovery manifest can be delivered without a nym route | Stored merchant Liquid address |

Do not overload `accept_liquid`. Direct Liquid and stablecoin-to-L-BTC have
different fees, payer requirements, and failure states. Add an explicit,
versioned `accept_stablecoin` invoice/surface capability through the mobile
protocol contract. Do not append an ambiguous optional boolean to an existing
signed field list.

### 8.2 Existing strengths to reuse

- Concrete settlement destinations are snapshotted on invoices.
- Direct provider status does not by itself count as payment.
- Reconciliation exists independently of webhook delivery.
- Payment evidence inserts are idempotent.
- Descriptor cursors allocate unique Liquid destinations.
- Existing claim code has cooperative and script-path concepts.
- Existing chain-swap recovery code uses advisory locking around claim/refund
  ownership and treats a funded refund-due state as recoverable rather than
  silently expiring it.

### 8.3 Existing patterns that do not meet this reliability target

The stablecoin rail must not copy these behaviors:

1. `src/invoice.rs` currently creates a Boltz chain swap before
   `chain_swap_records` is durably inserted. A timeout after the provider create
   can leave an ambiguous attempt. Stablecoin preparation must persist key
   references and an operation journal first.
2. `chain_swap_records` stores `preimage_hex`, `claim_key_hex`, and
   `refund_key_hex` as plaintext application data. Stablecoin preimages and
   claim keys belong in the policy executor, not PostgreSQL.
3. `record_chain_swap_claim_failure` eventually changes a funded swap to
   terminal `claim_stuck`. A funded stablecoin attempt may raise operator
   attention and reduce retry frequency, but recovery work never terminates.
4. Current webhook deduplication inserts the event ID before the handler
   completes. A handler failure can suppress a later redelivery permanently.
   Stablecoin webhooks are wakeups only, or inbox receipt and state transition
   commit atomically with a retryable processing status.
5. Background workers can be disabled while HTTP payment routes remain active.
   Stablecoin initiation must fail closed unless claim, refund, reconciliation,
   chain-read, signer, and backup health all satisfy admission policy.
6. `/ready` currently checks database and schema only. It is not sufficient to
   authorize a new funded cross-chain attempt.
7. The Liquid invoice watcher records matching L-BTC outputs from script
   history without a confirmation-depth gate. A merchant reliability claim
   requires a targeted confirmed-settlement proof.
8. Liquid invoice scanning samples a bounded candidate set. Stablecoin attempts
   need deterministic `next_action_at` scheduling and a maximum reconciliation
   lag, never probabilistic discovery.
9. The public status response is invoice-wide. It cannot safely carry payer
   wallet details, Permit2 signatures, exact source evidence, or recovery
   capabilities.
10. Current event keys differ between direct Liquid and Boltz settlement, so
    the same Liquid output could be counted once by the direct watcher and once
    by the stablecoin worker. Cross-source outpoint uniqueness is required.

### 8.4 Changes to current eager checkout creation

Anonymous checkout currently attempts Lightning and Bitcoin chain offers during
invoice creation. Stablecoin attempts must be click-time only because they bind
a payer wallet, short DEX quote, Permit2 nonce, live contract policy, and one
specific invoice remainder.

Creating an invoice must remain available when the stablecoin service is down.
The invoice/status response may advertise a stablecoin capability only when
admission health is good, but no Boltz stablecoin swap is created until the
payer selects the rail and connects a wallet.

## 9. Trust and Authority Matrix

| Item | Owner | Ordinary Bullnym API access | Recovery rule |
|---|---|---|---|
| Payer EVM private key | Payer wallet | Never | Wallet seed/recovery only |
| Stablecoin ERC20 approval | Payer | On-chain fact only | Exact amount; payer may revoke |
| Permit2 authorization | Payer | Persisted signature and digest | One nonce, amount, call hash, short deadline |
| Source refund address | Payer EOA | Immutable public value | Contract pays only this address |
| Refund transaction gas key | Independent watchtower | Never | Gas only; cannot receive TBTC |
| Invoice Liquid destination | Merchant-signed invoice or descriptor policy | Immutable public address/script | Reconstruct from signed merchant material |
| Destination blinding/view material | Merchant and existing Bullnym invoice path | Minimum required by Rust proof worker | Encrypted at rest; never sent to Boltz |
| Preimage | Policy claim executor | Hash only | Encrypted merchant/quorum capsule |
| Liquid claim private key | Policy claim executor | Public key only | Encrypted merchant/quorum capsule |
| Boltz response/swap tree | Coordinator and Rust verifier | Normalized verified data | WORM attempt manifest plus database |
| Exact-lock gas transaction key | Restricted relayer | Command only | Nonce-journaled; cannot spend payer tokens without permit |
| Invoice accounting | Bullnym Rust | Exclusive | Rebuilt from confirmed Liquid evidence |

No single normal Bullnym web or coordinator compromise should be able to both
take payer funds and redirect the L-BTC. No Bullnym component should need the
payer's EVM private key. A refund watchtower compromise can waste its gas, but
cannot change the refund recipient.

The policy executor remains a high-value boundary. Until a claim covenant is
available, a compromise of every policy/recovery domain can redirect a claim.
Minimize that residual risk through independent administration, non-exportable
secrets, transaction-policy enforcement, signed deployments, value caps, and a
make-whole reserve.

## 10. End-to-End Flow

### 10.1 Merchant destination preparation

1. Wallet invoices persist the exact merchant-signed Liquid address and
   blinding material already supplied at invoice creation.
2. Payment Page and POS persist the descriptor, purpose, address index, derived
   address, and merchant-signed descriptor-policy digest used for the checkout.
3. Rust validates correct network, confidential address encoding, derivation,
   and view key before stablecoin eligibility is exposed.
4. The destination snapshot becomes immutable for the life of the invoice and
   all late recovery.
5. A `merchant_settlement_commitment` digest covers invoice ID, amount/remainder
   generation, address script, Liquid network, descriptor purpose/index, and
   merchant policy epoch.

### 10.2 Attempt reservation

The payer calls a click-time stablecoin attempt endpoint with the selected
canonical asset and payer EOA.

In one Rust transaction:

1. lock the invoice row;
2. re-read the current remaining amount and payable state;
3. reject cancellation, expiry without an allowed late-payment policy, or a
   conflicting funded reservation;
4. allocate an attempt generation and random polling capability;
5. insert immutable invoice/destination/token facts;
6. insert `prepare_attempt` in the transactional outbox;
7. commit before any key derivation or Boltz request is attempted.

Only one signable or funded attempt may exist for one invoice remainder. An
unfunded reservation has a short lease. A new attempt is allowed only after the
old permit expired and both EVM/provider evidence prove it unfunded.

### 10.3 Claim-policy preparation

The policy executor:

1. deterministically allocates a never-reused claim-key index;
2. derives the L-BTC claim public key and preimage hash inside its boundary;
3. seals raw recovery material;
4. encrypts a recovery capsule to the merchant's purpose-specific recovery key
   and to an independent recovery quorum;
5. writes the capsule and signed attempt manifest to two independent append-only
   stores;
6. returns public values, integrity digests, and recovery-readiness attestations.

Bullnym must verify storage quorum and executor attestation before continuing.
"Database backup enabled" is not sufficient; the exact attempt manifest must
be durably observable in the backup domain before funding is possible.

### 10.4 Quote and Boltz swap creation

The coordinator fetches current Boltz chain pairs and requests an exact merchant
outcome. Amounts must remain distinct:

| Amount | Meaning |
|---|---|
| `invoice_credit_sat` | Remaining invoice value Rust will credit after proof |
| `merchant_min_lbtc_sat` | Minimum actual L-BTC at the invoice output |
| `server_lock_gross_sat` | L-BTC Boltz must lock, including claim fee reserve |
| `tbtc_exact_lock_atomic` | Exact TBTC base units locked on Arbitrum |
| `stablecoin_max_input_atomic` | Maximum USDC/USDT0 base units authorized by payer |
| `liquid_claim_fee_reserve_sat` | Conservative fee budget not credited to invoice |

V1 is exact merchant output. Payer input is grossed up for DEX slippage, Boltz
fees, EVM gas policy, and Liquid claim fee reserve. Bullnym does not silently
apply today's invoice underpayment tolerance to a planned provider shortfall.

Before creating the swap, the coordinator verifies:

- current TBTC-to-L-BTC pair hash and limits;
- all fee calculations in integer units;
- `server_lock_gross_sat >= merchant_min_lbtc_sat + claim_fee_reserve`;
- no stale or conflicting attempt;
- key/recovery readiness;
- contract and chain-policy readiness.

It then creates one TBTC-to-L-BTC Chain Swap using the preimage hash, claim
public key, immutable Liquid destination, exact source amount, and current pair
hash.

Creation has no documented general idempotency header. The operation journal
must therefore enter `create_pending` before the request. An ambiguous timeout
must be resolved through a Boltz-supported deterministic lookup/restore
contract before any payer authorization is exposed. Never issue a second
create request merely because the first response was lost.

### 10.5 Provider-response verification

Treat the Boltz response as untrusted input. Reconstruct and verify:

- provider swap ID uniqueness;
- source/target asset direction exactly TBTC -> L-BTC;
- returned server public keys and serialized Taproot trees;
- source lock contract, token, claim address, refund-address semantics, amount,
  and timelock;
- destination lock script/address from the claim key, Boltz key, and tree;
- destination amount and claim-fee reserve;
- timeout ordering in wall-clock estimates across Arbitrum and Liquid;
- confidential lockup blinding data where required;
- current pair hash and response schema version.

Persist the raw response encrypted for forensic recovery, plus a normalized
verified projection and digest. A verification failure permanently prevents
that attempt from becoming signable.

### 10.6 Payer intent and authorization

Rust returns a signed, short-lived payment intent through a capability-scoped
attempt endpoint. The independent wallet verifier must compare it with the
actual Permit2 typed data and proposed router call.

The human-readable authorization must show:

- selected token and Arbitrum;
- maximum token debit;
- expected merchant L-BTC amount;
- all Bullnym/Boltz/DEX fees or their maximums;
- expiry/deadline;
- payer address and that failures refund TBTC to that address;
- no claim that USDC/USDT0 itself is refundable after conversion.

The signed data binds the fields in Section 6. The Permit2 nonce is globally
unique, never reused, and covered by a database unique constraint. The permit
deadline should be minutes, not the protocol timelock.

If the source token lacks sufficient ERC20 allowance to Permit2, request an
exact `approve(Permit2, stablecoin_max_input_atomic)`. Never request an
unlimited approval. Tokens requiring zero-first approval receive a separate
zero approval followed by the exact approval.

### 10.7 Durable authorization before broadcast

The browser submits the signed intent and Permit2 signature to Rust. Before any
EVM transaction is broadcast:

1. locally recover the signer and require it equals payer/refund address;
2. decode and re-hash all typed fields and router calldata;
3. verify token, amounts, nonce, deadline, call targets/selectors, destination,
   preimage hash, Boltz claim address, timelock, and contract code policy;
4. lock the invoice and confirm the same remainder is still reserved;
5. persist the signature, intent digest, expected EVM event, and a
   `broadcast_source` outbox command atomically;
6. replicate the updated attempt manifest;
7. return an independently signed payer recovery receipt.

Only then may the relayer sign its gas transaction. Persist the signed raw EVM
transaction, transaction hash, sender, nonce, fee policy, and replacement rules
before first broadcast. An ambiguous broadcast is retried with the same raw
transaction or an explicit same-nonce replacement, never a newly interpreted
payment action.

### 10.8 Atomic DEX and exact source lock

The exact-lock router atomically:

1. consumes the one-time Permit2 authorization;
2. performs the allowlisted DEX calls;
3. reverts if less than the exact TBTC amount is available;
4. calls the verified Boltz ERC20Swap normal lock with the real preimage hash;
5. fixes the payer EOA as refund address;
6. returns stablecoin input remainder and TBTC positive slippage to the payer;
7. emits the attempt-intent digest.

If any step fails, the whole transaction reverts. The payer loses only EVM gas
they explicitly agreed to pay, if any; no swap funds move. There is no
commitment post, no second wallet signature, and no browser recovery file.

### 10.9 Source confirmation and target lock

Browser-supplied hashes are hints only. The coordinator and Rust chain verifier
independently discover and parse the receipt through at least two RPC views.
Require:

- successful receipt on chain ID 42161;
- expected router and ERC20Swap bytecode policy;
- exactly one matching Boltz `Lockup` event;
- real expected preimage hash, not zero;
- canonical TBTC token and exact amount;
- verified Boltz claim address;
- payer EOA refund address;
- exact approved timelock;
- unique transaction hash/log index/block hash;
- required source finality and no RPC disagreement.

Boltz status/WebSocket/webhook events only wake reconciliation. Chain evidence
is authoritative.

When Boltz broadcasts its L-BTC server lock, the policy executor independently
fetches the raw Liquid transaction and validates the expected Taproot outpoint,
unblinded L-BTC asset, gross amount, timeout, and unspent state.

### 10.10 Merchant claim

The claim executor constructs a transaction that:

- spends only the verified Boltz server-lock outpoint plus explicitly allowed
  fee inputs, if the reviewed builder supports them;
- sends at least `merchant_min_lbtc_sat` to the immutable invoice script;
- uses only L-BTC;
- pays no unapproved output;
- stays below the maximum fee or uses the reserved/subsidized fee policy;
- enables the approved RBF/fee-recovery behavior.

It obtains the cooperative MuSig2 contribution and broadcasts. If Boltz refuses
or is unavailable, it constructs and broadcasts the preimage script-path claim.
The executor never returns the preimage or a redirectable signature to the
coordinator.

Persist the exact transaction before broadcast and send through multiple
Liquid backends. Continue deterministic rebroadcast and fee recovery until the
expected outpoint is spent. If an outspend already exists, parse it and accept
only the expected merchant output as success.

### 10.11 Rust settlement proof and accounting

Rust credits the invoice only after its targeted proof worker verifies:

1. raw transaction hashes to the reported txid;
2. it spends the attempt's verified Boltz server-lock outpoint;
3. the expected output script equals the immutable invoice script;
4. the output unblinds as L-BTC;
5. actual amount is at least `merchant_min_lbtc_sat`;
6. configured Liquid confirmations are present and independent backends agree.

Suggested evidence:

```text
rail       = liquid
source     = stablecoin_boltz_chain
event_key  = stablecoin_boltz_chain:<attempt_id>:<txid>:<vout>
```

Add a chain-wide uniqueness constraint on `(network, txid, vout)` for monetary
evidence. If the generic Liquid watcher observed the same output first, the
stablecoin worker must atomically attach provider provenance to that evidence,
not insert a second payment.

### 10.12 Automatic payer refund

If Boltz does not create a valid target lock, the target lock is no longer
claimable, or policy selects the refund branch before any claim/preimage
release, the watchtower:

1. obtains and verifies a cooperative refund signature when available;
2. otherwise prebuilds the timeout refund from the canonical EVM log;
3. broadcasts at the first eligible block through multiple RPCs;
4. fee-bumps with the same immutable call tuple as necessary;
5. verifies the `Refund` event, TBTC transfer to payer, and cleared swap state;
6. emits public terminal evidence to Bullnym.

The refund destination is not an API parameter at recovery time. It was fixed
before funding and is part of the EVM lock hash. Operators cannot edit it.

The payer receives TBTC automatically even if Bullnym's main API, browser, and
coordinator are unavailable, provided one independent watchtower and Arbitrum
remain live. The payer recovery receipt also contains enough public data for a
separate wallet/recovery site to call the same refund path.

## 11. Non-Negotiable Invariants

These invariants are production requirements, not monitoring preferences.

1. A quote, approval, Permit2 signature, EVM transaction, Boltz status,
   webhook, source lock, or target lock never marks an invoice paid.
2. `merchant_settled` is true only after independent Rust verification of a
   confirmed L-BTC output at the immutable invoice script for the required net
   amount.
3. No source transaction becomes signable until claim secrets, merchant
   recovery capsule, payer refund tuple, provider response, and operation
   manifest are durably recoverable outside the primary database.
4. Payer EOA equals Permit2 owner, exact-lock surplus recipient, and on-chain
   refund address.
5. Refund address, merchant script, asset, amount, preimage hash, claim key,
   contract tuple, and timelock are immutable after payer authorization.
6. The source lock uses a nonzero real preimage hash and exact TBTC amount. A
   zero-hash commitment is not permitted in the recommended production mode.
7. The ordinary Rust API, TypeScript coordinator, database, and support tools
   never possess an exportable preimage or Liquid claim private key.
8. The policy executor releases the preimage only as part of a fully validated
   claim to the immutable merchant output.
9. Once a preimage is released to Boltz or a network, the resolution path can
   never switch to payer-refund. Merchant claim and make-whole automation must
   continue indefinitely.
10. Before preimage release, the payer-refund path may be selected only after
    independent evidence shows the target is absent, invalid, refunded, or no
    longer safely claimable.
11. Every funded, nonterminal attempt has a durable `next_action_at` and at
    least two recovery executors capable of discovering it.
12. `operator_attention`, `degraded`, retry exhaustion, and incident status are
    overlays. None is a terminal funds state.
13. Only one potentially fundable stablecoin attempt may exist for one invoice
    remainder generation.
14. New attempts are never created to resolve an ambiguous provider create,
    source broadcast, claim broadcast, or refund broadcast.
15. Disabling or rolling back the feature stops new attempts only. It never
    stops polling, chain scans, claims, refunds, fee bumps, recovery APIs, or
    key retention for funded attempts.
16. Chain state overrides database and provider projections. A database state
    may be repaired from evidence but cannot make an on-chain fact disappear.
17. Operators cannot manually change a monetary destination or secret. A
    correction creates a new unfunded generation after the old one is proven
    unfunded.
18. Unknown provider states fail closed for new actions while reconciliation
    and safe refund/claim deadlines continue.
19. A source `Claim` observed before an approved merchant claim/preimage release
    is a severity-zero invariant breach.
20. A funded attempt with no scheduled action, unavailable recovery quorum, or
    breached timeout margin is a severity-zero incident and halts new funding.

The logical `resolution_path` is exclusive inside Bullnym. Cross-chain reality
can still produce both a merchant claim and payer refund if Boltz fails to claim
the source before its longer timeout. That would be a Boltz loss, not a payer or
merchant loss. Bullnym must record both facts without double-crediting the
invoice or trying to reverse either valid chain transaction.

## 12. Timeout and Preimage Policy

Timeouts on Arbitrum and Liquid use different clocks. Never compare raw block
heights. Convert each to a conservative wall-clock interval using current and
stressed block production assumptions.

Before payer authorization require:

```text
source_refund_earliest_time
  >= target_refund_earliest_time
     + target_confirmation_budget
     + claim_construction_budget
     + repeated_broadcast_budget
     + reorg_budget
     + incident_response_buffer
```

The coordinator must refuse new funding if the live margin is below policy,
even if Boltz accepts the swap. Re-evaluate the margin continuously after
funding and page before it becomes critical.

The preimage has three monotonic states:

| State | Meaning | Allowed next state |
|---|---|---|
| `sealed` | Exists only inside claim executor/recovery capsule | `claim_authorized` |
| `claim_authorized` | Target lock and exact claim tx validated; merchant branch fenced | `exposed` |
| `exposed` | Sent to Boltz or published in claim transaction | terminal; never returns |

Cooperative MuSig is not considered harmless preparation. Boltz receives the
preimage during the cooperative chain claim interaction before the payer's
client can prove deep Liquid confirmation. Transition to `exposed` before that
API call, persist it in the append-only manifest, and activate merchant
make-whole coverage.

Prefer a valid, conservatively fee-funded transaction that can be rebroadcast
or replaced indefinitely. If the executor chooses script path, the mempool
transaction itself reveals the preimage. It must persist the raw transaction
before first broadcast and use multiple broadcasters immediately.

## 13. State Model

Do not represent this protocol with one mutable status string. Persist
orthogonal evidence axes and derive the payer/merchant projection.

### 13.1 Funding state

```text
reserved
prepared
signable
authorized
broadcast_pending
broadcast
confirmed
reverted
expired_unfunded
```

### 13.2 Target state

```text
not_seen
lock_mempool
lock_confirmed
claim_authorized
claim_broadcast
claim_confirmed
target_refunded
target_invalid
```

### 13.3 Refund state

```text
not_selected
selected
cooperative_available
waiting_timelock
refund_broadcast
refund_confirmed
```

### 13.4 Resolution and attention

```text
resolution_path: undecided | merchant | payer
preimage_state: sealed | claim_authorized | exposed
attention: normal | degraded | operator_attention | incident
```

Terminal business projections are:

- `merchant_settled`: confirmed, independently verified L-BTC output;
- `payer_refunded`: confirmed TBTC transfer to the immutable payer EOA;
- `unfunded`: no source lock exists and every authorization is expired;
- `compensated`: merchant make-whole payment independently confirmed.

Provider status is stored as observed evidence with timestamp and raw digest,
not used as the attempt's primary state.

### 13.5 Core automatic transition rules

| Evidence state | Required automatic action |
|---|---|
| Authorized, not broadcast, invoice still reserved | Persist and broadcast the exact relayer transaction |
| Authorized, invoice paid elsewhere before broadcast | Cancel outbox, let permit expire, prove unfunded |
| Source transaction pending | Track relayer sender/nonce and replacement lineage, not only tx hash |
| Source reverted | Mark unfunded; return/revoke allowance guidance |
| Source confirmed, target absent | Poll Boltz and both chains; preserve refund schedule |
| Valid target lock with safe margin, preimage sealed | Fence merchant branch and ask policy executor to claim |
| Claim raw tx persisted | Multi-broadcast, probe outspend, RBF/fee-recover until confirmed |
| Target absent/invalid/refunded before preimage release | Fence payer branch; cooperative then timeout refund |
| Source refund eligible | Watchtower broadcasts immutable refund call |
| Claim confirmed | Rust verifies output and records one payment event |
| Refund confirmed | Rust projects payer-refunded; invoice receives no payment event |
| Both valid chain outcomes observed | Record provider-loss anomaly; do not reverse user outcomes |

## 14. Claim-versus-Refund Fencing

Claim and refund occur on different chains, so database locking alone does not
make them mutually exclusive. Use both database fencing and irreversible chain
evidence.

Before choosing `resolution_path = merchant`, the executor proves:

- valid target outpoint is present and unspent;
- source lock is confirmed and not refunded;
- exact merchant claim is constructible;
- timeout margin remains above policy;
- fee reserve and broadcasters are ready;
- no payer-refund transaction has confirmed;
- no other invoice rail has already satisfied the remainder unless overpayment
  policy explicitly selects merchant settlement.

The transition to merchant runs under a row lock and state-version compare-and-
set, then writes `claim_authorized` plus a claim command in one transaction.

Before choosing `resolution_path = payer`, prove:

- `preimage_state = sealed`;
- no claim transaction or cooperative claim request was emitted;
- target outpoint is absent after the provider deadline, invalid, already
  refunded, or outside the safe claim window;
- the refund tuple exactly matches the confirmed source log.

Once either branch is chosen, ordinary operators cannot switch it. An
independent recovery process may repair a projection when chain evidence proves
the recorded branch was never actually initiated, but that repair requires a
signed incident record and the same safety predicates.

## 15. Failure Analysis

| Failure point | Funds location | Automatic owner/action | Merchant outcome | Payer outcome |
|---|---|---|---|---|
| Quote/create fails before authorization | Payer stablecoin wallet | Expire reservation | Unpaid | No value moved |
| Boltz create response lost | Payer stablecoin wallet | Resolve by deterministic lookup; never duplicate | Unpaid | No value moved |
| ERC20 approval succeeds, no Permit2 signature | Payer wallet; allowance exists | Expire attempt; prompt/revoke exact allowance | Unpaid | Funds remain in wallet |
| Permit signed, relayer dies before broadcast | Payer wallet | Secondary relayer uses persisted command or permit expires | Unpaid until retry | No value moved |
| EVM broadcast response lost | Pending/confirmed atomic transaction | Re-broadcast same raw tx; scan sender/nonce and lock logs | Continues | No duplicate debit |
| DEX output below exact TBTC | Transaction reverts | Requote only after unfunded proof | Unpaid | Stablecoin remains; gas may be spent |
| DEX returns positive slippage | Exact TBTC locked; surplus | Router returns surplus to payer atomically | Continues | Receives surplus |
| Browser closes after Permit signature | Exact authorization persisted | Coordinator completes without browser | Continues | Refund still bound to payer |
| Bullnym API crashes after source lock | TBTC in ERC20Swap | Independent coordinator/watchtower discovers log | Claim or reserve | Timeout refund available |
| Coordinator database lost | TBTC lock and/or L-BTC target lock | Restore manifests, xpub/key derivation, EVM/Liquid scans | Continues | Refund tuple on-chain |
| Boltz never locks L-BTC | TBTC in ERC20Swap | Cooperative refund, then timeout watchtower | Unpaid or reserve policy | TBTC returned |
| Boltz target lock malformed/short | TBTC in ERC20Swap | Reject claim; payer branch before preimage | Unpaid or reserve policy | TBTC returned |
| Boltz API unavailable after valid target lock | L-BTC target UTXO; TBTC source | Policy executor uses script-path claim | L-BTC claimed | Boltz claims source from preimage |
| Cooperative claim refused | L-BTC target UTXO | Script-path claim | L-BTC claimed | Source completes |
| Claim broadcast ambiguous | L-BTC target UTXO/mempool | Persisted tx rebroadcast and outspend scan | Continues | Source must not be refunded by Bullnym |
| Claim fee rejected | L-BTC target UTXO | RBF/rebuild within policy; subsidized fee path | Continues | Source branch remains merchant |
| Target lock refunded before preimage | TBTC source lock | Payer branch and refund watchtower | Unpaid or reserve policy | TBTC returned |
| Preimage leaked before approved claim | Boltz may claim TBTC | P0; make-whole merchant; investigate executor | Reserve pays merchant | Potential payer loss is compensated by policy |
| Malicious Bullnym changes refund address | Pre-funding attempt | Wallet/router invariant rejects | Unpaid | No value moved |
| Malicious Bullnym changes merchant output | Target claim request | Policy executor rejects | Valid destination preserved | Source eventually settles/refunds |
| Main Bullnym deployment disappears | Chain contracts/target UTXO | Independent claim and refund domains continue | Claim/recovery capsule | Permissionless refund |
| All Bullnym recovery domains disappear | Chain contracts/target UTXO | Merchant capsule and public payer receipt | Merchant self-rescue | Payer/self-hosted refund |
| USDC/USDT0 freezes before DEX | Payer wallet or reverted tx | No protocol workaround | Unpaid | Issuer-dependent |
| TBTC freezes after source lock | ERC20Swap | Retry after token resumes; incident/reserve | May require reserve | Refund blocked until token permits transfer |
| Arbitrum halts | ERC20Swap/pending tx | Retain state and rebroadcast after recovery | Delayed | Refund delayed |
| Liquid halts | Target UTXO/mempool | Retain state and rebroadcast after recovery | Delayed/reserve policy | Source timeout margin monitored |
| Invoice paid by another rail before source broadcast | Payer wallet | Cancel stablecoin broadcast | Paid by other rail | No stablecoin debit |
| Invoice paid by another rail after source confirm, before preimage | TBTC source lock | Prefer payer refund unless merchant accepts overpay | Already paid | TBTC returned |
| Other rail settles after preimage release | Both settlements in flight | Finish merchant claim and record overpayment | Overpaid | Stablecoin payment completes |

No row may end in a state equivalent to the current `claim_stuck` terminal.
Escalation changes alerting and retry cadence; it never removes the next action.

## 16. Durable Data Model

Use the existing PostgreSQL cluster for atomic invoice reservation and outbox
writes, but separate privileges by schema/role:

- Rust owns invoice and accounting tables.
- Rust and coordinator have narrowly defined procedures for the shared attempt
  projection and command/event inboxes.
- The coordinator cannot update invoice monetary state.
- The policy executor has no general database credentials. It receives signed
  manifests and returns attestations/public evidence.
- The refund watchtower can operate from a replicated public manifest and chain
  logs without primary-database access.

### 16.1 `stablecoin_attempts`

Persist at least:

```text
id UUID
invoice_id UUID
generation BIGINT
capability_hash BYTEA
surface_kind TEXT
coordinator_protocol_version TEXT
router_policy_version TEXT
state_version BIGINT

invoice_credit_sat BIGINT
merchant_min_lbtc_sat BIGINT
server_lock_gross_sat BIGINT
liquid_claim_fee_reserve_sat BIGINT
merchant_liquid_address TEXT
merchant_liquid_script BYTEA
merchant_settlement_commitment BYTEA
merchant_policy_epoch TEXT

source_chain_id BIGINT
source_asset TEXT
source_token_address BYTEA
source_token_decimals SMALLINT
payer_address BYTEA
refund_address BYTEA
stablecoin_max_input_atomic NUMERIC(78,0)
tbtc_exact_lock_atomic NUMERIC(78,0)

boltz_swap_id TEXT
boltz_pair_hash BYTEA
boltz_response_digest BYTEA
preimage_hash BYTEA
claim_public_key BYTEA
claim_key_epoch TEXT
claim_key_index BIGINT
recovery_capsule_digest BYTEA
recovery_attestation JSONB

permit2_address BYTEA
permit_nonce NUMERIC(78,0)
permit_deadline TIMESTAMPTZ
intent_digest BYTEA
route_digest BYTEA
router_address BYTEA
erc20_swap_address BYTEA
boltz_claim_address BYTEA
source_timelock BIGINT
target_timelock BIGINT

source_tx_hash BYTEA
source_tx_log_index INTEGER
source_block_hash BYTEA
source_confirmations INTEGER
target_lock_txid BYTEA
target_lock_vout INTEGER
target_lock_amount_sat BIGINT
claim_txid BYTEA
claim_vout INTEGER
refund_tx_hash BYTEA

funding_state TEXT
target_state TEXT
refund_state TEXT
resolution_path TEXT
preimage_state TEXT
attention_state TEXT
next_action_at TIMESTAMPTZ
last_reconciled_at TIMESTAMPTZ
last_error_code TEXT
last_error_digest BYTEA
created_at TIMESTAMPTZ
updated_at TIMESTAMPTZ
```

Critical monetary fields become immutable through a database trigger after
`funding_state = 'authorized'`. The trigger rejects operator SQL just as the
application does. Store large EVM values in integer numeric form, never float
or JavaScript `number`.

Required uniqueness includes:

- `(invoice_id, generation)`;
- `boltz_swap_id` when non-null;
- `preimage_hash`;
- `(claim_key_epoch, claim_key_index)`;
- `claim_public_key`;
- `(source_chain_id, permit_nonce)`;
- `(source_chain_id, source_tx_hash, source_tx_log_index)`;
- `(target_lock_txid, target_lock_vout)`;
- `claim_txid` and `refund_tx_hash` when non-null;
- one authorized/funded unresolved stablecoin attempt per invoice generation,
  enforced with a partial unique index.

### 16.2 Authorization table

Store signed payer material separately with the narrowest access role:

```text
stablecoin_payer_authorizations
  attempt_id
  signer_address
  intent_digest
  permit_nonce
  permit_deadline
  encrypted_permit_signature
  calldata_digest
  decoded_policy_json
  verified_at
  consumed_tx_hash
```

The signature is sensitive capability material until consumed or expired.
Encrypt it with a short-lived data key, omit it from logs/backups that do not
need execution recovery, and cryptographically erase it after terminal
retention rules permit. Keep the digest and decoded audit record.

### 16.3 Immutable events and operation journal

Use append-only tables:

```text
stablecoin_attempt_events
  event_id UUID
  attempt_id UUID
  source TEXT
  source_event_key TEXT
  observed_at TIMESTAMPTZ
  raw_digest BYTEA
  normalized_kind TEXT
  normalized_payload JSONB
  processing_state TEXT
  processing_attempts INTEGER
  next_processing_at TIMESTAMPTZ

stablecoin_operations
  operation_id UUID
  attempt_id UUID
  action_kind TEXT
  revision INTEGER
  action_key BYTEA
  request_digest BYTEA
  status TEXT
  signed_artifact BYTEA
  transaction_identity JSONB
  response_digest BYTEA
  created_at TIMESTAMPTZ
  completed_at TIMESTAMPTZ
```

`source_event_key` is unique per source. An event is not treated as processed
until its state transition commits. Failed processing remains retryable.

Every external action uses:

```text
action_key = SHA256(
  "bullnym:stablecoin:action:v1" ||
  attempt_id || action_kind || revision
)
```

Write the operation row and state transition before the external request.
Persist signed transaction bytes before broadcast. Keep every same-nonce or
RBF replacement in the operation lineage.

### 16.4 Transactional command/event bridge

Suggested coordinator commands:

```text
prepare_attempt
create_boltz_swap
build_payer_intent
accept_authorization
broadcast_source_lock
reconcile_source
reconcile_provider
verify_target_lock
request_merchant_claim
request_payer_refund
reconcile_terminal_evidence
cancel_unfunded
```

Suggested coordinator events:

```text
attempt_prepared
swap_created_verified
payer_intent_ready
source_tx_persisted
source_lock_observed
source_lock_confirmed
target_lock_observed
target_lock_verified
preimage_exposed
claim_transaction_observed
refund_transaction_observed
provider_anomaly
recovery_degraded
```

Commands and events have UUID, sequence, schema version, expected attempt state
version, and payload digest. Consumers are idempotent and use
`FOR UPDATE SKIP LOCKED` leases. A lease expiry returns work to the queue; it
never dead-letters a funded attempt.

### 16.5 Chain evidence and payment evidence

Add a canonical monetary outpoint key to invoice payment evidence:

```text
evidence_network
evidence_txid
evidence_vout
```

Enforce uniqueness across every payment-event source. Direct Liquid and
stablecoin settlement can attach multiple provenance records to one evidence
row, but only one amount contributes to invoice accounting.

## 17. API Contract

Expose wallet operations through same-origin Rust. The sidecar remains private.

### 17.1 Public invoice capability

The ordinary invoice status may include only presentation-safe capability:

```json
{
  "stablecoin": {
    "available": true,
    "assets": ["USDC_ARB", "USDT0_ARB"],
    "refund_asset": "TBTC_ARB"
  }
}
```

`available` is a hint. Attempt creation re-runs the full admission gate. Do not
place payer addresses, attempt IDs, provider IDs, permits, tx hashes, recovery
tuples, or error internals on the public invoice status endpoint.

### 17.2 Attempt creation

```text
POST /api/v1/invoices/:invoice_id/stablecoin/attempts
```

Request:

```json
{
  "asset": "USDC_ARB",
  "payer_address": "0x...",
  "client_intent_nonce": "random-128-bit-value"
}
```

Response is initially `preparing` with:

- attempt ID;
- one random capability token returned once;
- expiry;
- poll URL;
- no signable transaction until preparation and backup quorum complete.

Require an HTTP idempotency key scoped to invoice, payer, and client intent.
Replay returns the same attempt. A different payload under the same key is a
conflict.

### 17.3 Attempt status

```text
GET /api/v1/stablecoin/attempts/:attempt_id
Authorization: Bearer <attempt-capability>
```

Return payer-safe projection:

```text
preparing
ready_to_approve
ready_to_authorize
submitting
source_confirming
settling
paid
refunding_tbtc
refunded_tbtc
unfunded_expired
```

Include human amounts, deadlines, confirmation progress, and public tx links.
Never return secrets or raw provider responses.

### 17.4 Authorization

```text
POST /api/v1/stablecoin/attempts/:attempt_id/authorize
Authorization: Bearer <attempt-capability>
```

Body carries the signed Bullnym intent and exact Permit2 signature. Rust and
the coordinator independently decode and verify it. On success, the server
atomically reserves the invoice and queues the persisted broadcast. The API
returns `202`, not a claim that payment succeeded.

The exact-lock mode has no post-lock commitment-signature endpoint. If the
fallback commitment mode is ever exposed, it must be a separate versioned
protocol and cannot share the stronger reliability claim.

### 17.5 Cancellation

```text
POST /api/v1/stablecoin/attempts/:attempt_id/cancel
```

Cancellation succeeds only when no source transaction has been broadcast and
the permit is expired, revoked, or durably removed from every execution queue.
After broadcast, the endpoint returns the current recovery path and cannot
pretend to cancel chain state.

### 17.6 Wallet-based recovery

```text
POST /api/v1/stablecoin/recovery/challenge
POST /api/v1/stablecoin/recovery/search
```

The payer signs a domain-separated challenge containing domain, chain ID,
wallet address, random nonce, issued time, and short expiry. The search returns
attempts whose immutable refund address matches that wallet. This enables
cross-device recovery without a downloaded file.

The payer recovery receipt must also be sufficient without Bullnym:

```text
attempt manifest digest
chain ID
TBTC token
ERC20Swap address and verified code hash
preimage hash
exact amount
Boltz claim address
payer refund address
timelock
source tx hash and log index, once known
ABI/version needed for refund
independent recovery/watchtower URLs
Bullnym signature and transparency-log inclusion proof
```

No private key is needed for the permissionless timeout refund. The payer's
wallet address is the recipient, not the caller.

### 17.7 Merchant recovery surface

Extend the signed merchant recovery list with stablecoin attempt projections:

- invoice and attempt ID;
- source token and maximum input;
- target L-BTC amount;
- public source/target/claim/refund transactions;
- recovery/attention state;
- encrypted recovery capsule availability and digest;
- whether automatic claim/refund workers are healthy.

Never return preimages, raw claim keys, Permit2 signatures, or unredacted
provider responses through the ordinary merchant API.

## 18. UI Integration

### 18.1 Shared Payment Page/POS PWA

Extend the current rail union in `pwa/lib/components/PaymentScreen.svelte` with
`stablecoin`. Do not model it as a QR-only rail. It requires:

- USDC/USDT0 selector with network fixed to Arbitrum;
- connect-wallet or Bull Bitcoin Mobile handoff;
- exact approval step when needed;
- review screen sourced from independently verified intent data;
- submit, source confirmation, merchant settlement, and TBTC refund states;
- public transaction links and recovery status;
- an explicit statement before authorization that failure refunds TBTC.

POS must not print or show a paid receipt until Rust reports confirmed merchant
settlement. A risk-tiered early-acceptance mode would be a separate merchant
policy and cannot be called full reliability.

The current persisted rail selection can store `stablecoin`, but no signature,
permit, payer address, or recovery secret belongs in local storage. The server
capability token may be stored in IndexedDB with normal browser protections;
wallet-signature recovery remains the cross-device fallback.

### 18.2 Server-rendered wallet invoice

Add the same attempt APIs and wallet component to the canonical invoice
template. It may reuse the compiled stablecoin UI module, but it must preserve
the server-rendered invoice privacy and alias rules. An alias route must never
leak the underlying nym through API URLs, metadata, WalletConnect descriptions,
or analytics.

### 18.3 Content security policy

Bullnym's current public-page CSP is intentionally narrow. Prefer same-origin
Rust proxy endpoints and direct injected-wallet APIs. If WalletConnect is used,
enumerate only required origins and test CSP on every surface. Do not add broad
`connect-src *`, `unsafe-eval`, or arbitrary frame permissions.

### 18.4 User-visible truth

Use these concepts consistently:

- **Authorized**: payer signed a bounded intent; no payment proof yet.
- **Converting**: EVM transaction is pending.
- **Payment detected**: exact TBTC lock confirmed; merchant not paid yet.
- **Settling**: valid L-BTC target/claim workflow is active.
- **Paid**: confirmed L-BTC verified by Bullnym Rust.
- **Refunding TBTC**: merchant path was not selected; watchtower is active.
- **Refunded TBTC**: TBTC arrived at payer address.

Never display "USDC refunded" when the recovered asset is TBTC.

## 19. Invoice Accounting and Races

### 19.1 Accounting proof

Credit the actual verified merchant output, not:

- quoted L-BTC;
- requested TBTC;
- confirmed source TBTC;
- Boltz's `transaction.claimed` status;
- sidecar-reported amount;
- preimage exposure;
- a claim txid without raw transaction verification.

For the exact-output policy, the actual merchant output should equal the invoice
remainder. If it is below `merchant_min_lbtc_sat`, do not apply a normal rail
tolerance to hide the shortfall. Record the actual amount as partial evidence,
raise an invariant breach, and trigger automatic reserve compensation for the
missing amount.

`paid_via` can remain `liquid` because that is the asset the merchant received.
Stablecoin source attribution belongs in event provenance and merchant history:

```text
rail = liquid
source = stablecoin_boltz_chain
source_asset = USDC_ARB | USDT0_ARB
```

### 19.2 Direct Liquid deduplication

The generic Liquid watcher scans the same invoice address and may see the
stablecoin claim output. Before enabling this rail, implement one of:

1. canonical outpoint evidence with unique `(liquid, txid, vout)` and multiple
   provenance rows; preferred; or
2. a registered-claim exclusion in the generic watcher followed by targeted
   stablecoin proof.

The first option repairs the general data model and handles crash races. A
stablecoin worker and direct watcher may race to insert, but only one outpoint
amount is counted.

### 19.3 Confirmation policy

The current Liquid watcher records script history without an explicit
confirmation threshold. Stablecoin settlement must use a configured, targeted
confirmation policy and distinguish:

```text
claim_mempool
claim_confirmed
claim_deep_finality
```

The PWA may show settling from mempool evidence. Merchant accounting and a paid
POS receipt use the configured confirmed state. Large amounts may require more
confirmations based on risk tier.

### 19.4 Cancellation and expiry

Authorization and invoice cancellation must serialize on the invoice row.

- Before `broadcast_source` is committed, merchant cancellation wins and the
  stablecoin permit is discarded/allowed to expire.
- Once a source broadcast operation is committed, cancellation is rejected as
  "payment in progress" until the attempt settles or refunds.
- Invoice wall-clock expiry stops new attempts. It never stops an already
  authorized or funded attempt.
- GC must exclude every invoice with an authorized/funded unresolved attempt
  from terminal cleanup or deletion.
- A valid late merchant claim after invoice expiry still records real monetary
  evidence and recomputes paid/overpaid state.

### 19.5 Concurrent payers and mixed rails

Only one stablecoin signing reservation exists for an invoice remainder. Other
rails can still be paid concurrently, so resolve races deliberately:

- If other evidence satisfies the invoice before stablecoin source broadcast,
  cancel the stablecoin outbox.
- If source confirms but the preimage is still sealed, prefer TBTC refund when
  the merchant is already fully paid, unless an explicit merchant overpayment
  policy selected settlement before payer authorization.
- After preimage exposure, finish the merchant claim. Any other payment makes
  the invoice overpaid and remains visible.
- Never discard a real output to preserve a single-payment UI expectation.

### 19.6 Reorgs

Persist block hash and confirmation depth for both chains. A reorg rolls back
the relevant observation, not immutable history. If accounting confirmation is
reorged out, move the invoice to an incident projection and continue scanning;
do not silently delete the event audit trail. If the source lock reorgs before
Boltz acts, the target path should not start. If it reorgs after preimage
exposure, this is provider risk and must not stop the merchant claim.

## 20. Admission Control

The attempt endpoint returns unavailable unless all applicable checks pass at
the moment of preparation and again before authorization acceptance.

### 20.1 Protocol and contract checks

- exact supported chain ID and canonical token addresses;
- pinned Permit2, exact-lock router, ERC20Swap, and TBTC bytecode hashes;
- required ERC20Swap ABI/version and features;
- no unexpected proxy implementation or admin change;
- current Boltz pair direction, hash, fee structure, and limits;
- locally reconstructed swap tree and contract tuple;
- sufficient source-to-target timeout margin;
- DEX target/selector/path allowlist and simulation success;
- exact-lock router invariant simulation produces exact lock and payer surplus;
- quote and permit deadlines remain above minimum submission time.

### 20.2 Service-health checks

- primary database and schema healthy;
- transactional outbox lag below threshold;
- two coordinator replicas heartbeating;
- policy claim executor plus recovery domain ready;
- recovery manifest stores acknowledge the current attempt epoch;
- primary and independent Arbitrum RPCs agree;
- primary and independent Liquid backends agree;
- refund watchtower heartbeat and gas balance healthy;
- Liquid claim fee reserve/subsidy wallet healthy;
- no invariant P0 or global circuit breaker active.

### 20.3 Exposure checks

- per-attempt amount cap;
- per-payer pending cap;
- per-merchant pending value cap;
- per-token and DEX route cap;
- hourly/daily volume cap;
- total funded unresolved cap;
- make-whole reserve coverage above stressed outstanding exposure;
- sufficient watchtower gas for every outstanding refund under stressed fees.

Fail closed before value moves. Once value moves, a degraded dependency may
stop new attempts but never stops recovery actions.

## 21. Security Policies

### 21.1 Key hierarchy

Use a stablecoin-specific root isolated from Bullnym's current swap master key.
Derive by domain and network so a key cannot cross roles:

```text
bullnym/stablecoin/mainnet/liquid-claim/<epoch>/<index>
bullnym/stablecoin/mainnet/preimage/<epoch>/<index>
bullnym/stablecoin/mainnet/manifest-signing/<epoch>
bullnym/stablecoin/mainnet/relayer/<epoch>
```

Indices are allocated append-only before provider calls. Never derive a
preimage from low-entropy attempt data alone. If deterministic preimages are
derived from a private child key, document and test the exact versioned
derivation so disaster recovery reproduces it forever.

The relayer key is not the claim key and holds only enough ETH for bounded gas.
The refund watchtower has a different gas key and credentials.

### 21.2 Policy executor controls

- no shell or general outbound network access;
- allow outbound only to pinned Boltz and Liquid endpoints needed to verify and
  broadcast;
- mutual attestation/mTLS with coordinator;
- signed, reproducible image and measured policy version;
- no raw-sign endpoint;
- no preimage-read endpoint;
- no arbitrary destination or transaction bytes supplied by caller;
- destination reconstructed from signed attempt manifest;
- two-person approval for policy/version changes, never per-payment approval;
- append-only access audit exported to an independent account;
- memory/core-dump protection and secret-redacting telemetry;
- merchant/quorum recovery capsule produced before readiness attestation.

### 21.3 Relayer controls

The EVM relayer accepts only a structured exact-lock command whose digest is
already in the operation journal. It rebuilds and verifies calldata locally.
It rejects arbitrary `to`, `data`, value, chain, token, nonce, or fee requests.
Use a dedicated EOA, strict nonce journal, balance cap, and destination firewall.

### 21.4 Dependency and build controls

- pin exact `boltz-swaps`, `boltz-core`, `viem`, Liquid, secp256k1-zkp, Permit2
  ABI, and router source revisions;
- commit lockfiles and verify package integrity hashes;
- record the package-level MIT licenses and obtain legal confirmation for any
  code extracted from the AGPL web-app repository;
- generate an SBOM and sign container images;
- run reproducible builds where practical;
- scan dependency and container updates;
- treat any ABI, contract address, code hash, pair schema, or signing-type
  change as a protocol migration, not a routine patch;
- keep old worker images runnable until no funded attempt depends on them.

### 21.5 Privacy and logging

Do not log or trace:

- full Permit2 signatures;
- payer capability tokens;
- raw preimages or claim keys;
- Liquid blinding private keys;
- encrypted recovery capsule contents;
- unredacted wallet/IP correlation.

Log digests, attempt IDs, normalized state, public txids, and structured error
codes. Restrict payer address access and set a retention policy. Public invoice
UUID knowledge must not reveal the payer wallet or source transaction.

### 21.6 Manual operations

Operators may:

- pause new attempts;
- simulate the next deterministic action;
- rebroadcast already persisted bytes;
- request a policy-safe rebuild with the same immutable destination;
- increase a fee within signed policy;
- rotate an unhealthy RPC/broadcaster;
- invoke the same permissionless refund tuple as the watchtower.

Operators may not:

- edit refund or merchant destinations;
- replace token, amount, preimage hash, claim key, or timelock;
- export a preimage/claim key;
- mark paid/refunded without chain proof;
- force a payer branch after preimage exposure;
- delete a funded attempt or its recovery material;
- stop recovery workers as part of feature rollback.

## 22. Reconciliation and Idempotency Procedures

### 22.1 Provider status

Use Boltz WebSocket/webhooks only as low-latency wakeups. The webhook contract
does not provide sufficient authentication and delivery guarantees to be money
authority. Poll the authoritative swap read endpoint and independently scan
both chains.

Persist every unknown status and alert. Do not acknowledge it as understood or
map it to failure. Continue chain-driven recovery deadlines.

### 22.2 Ambiguous create

On timeout or connection loss:

1. keep the same key index, claim public key, and preimage hash;
2. mark `create_ambiguous` and stop payer intent generation;
3. query the written, Boltz-approved recovery path by exact public key/xpub or
   provider-supported idempotency lookup;
4. if found, validate and persist the original response;
5. if not found, continue lookup through the agreed bounded window;
6. abandon as unfunded only after Boltz and independent evidence prove no
   fundable swap exists;
7. never create a replacement under the same invoice generation while
   ambiguity remains.

### 22.3 Ambiguous EVM broadcast

1. derive the tx hash locally from persisted signed bytes;
2. query by hash and relayer sender/nonce across independent RPCs;
3. scan exact-lock and ERC20Swap logs for the intent/preimage digest;
4. rebroadcast identical bytes if absent and nonce unused;
5. replace only with same nonce and identical call data under fee policy;
6. if a different transaction consumed the nonce, halt new funding and
   investigate relayer compromise.

### 22.4 Ambiguous Liquid claim

1. compute txid before broadcast and persist bytes;
2. query txid and expected target outpoint outspend through multiple backends;
3. if expected tx exists, continue confirmation tracking;
4. if another outspend exists, parse it and accept only a valid merchant output;
5. otherwise rebroadcast or policy-safe RBF/rebuild;
6. never request payer refund after preimage exposure.

### 22.5 Ambiguous refund

The refund call is idempotent at the contract-state level. Re-read the exact
swap hash mapping and events. Re-broadcast or same-nonce replace the identical
tuple. A confirmed `Claim` means refund is no longer possible; a confirmed
`Refund` plus token transfer to payer is terminal evidence.

## 23. Disaster Recovery

### 23.1 Recovery artifacts

Maintain all of these independently:

- point-in-time PostgreSQL backups and encrypted WAL;
- signed, encrypted, append-only attempt manifests in two storage accounts;
- policy-executor root/epoch backup under an independent quorum;
- merchant-encrypted per-attempt recovery capsules;
- public claim xpub or exact public-key recovery index where supported;
- payer recovery receipts/transparency-log entries;
- pinned source, ABI, package, and container artifacts for every active version.

Do not delete a key epoch, package image, manifest, or ABI until every attempt
under it is terminal on both chains, has deep finality, has passed the dispute
window, and meets legal retention requirements.

### 23.2 Empty-database rebuild

The quarterly destructive drill starts with no primary database:

1. activate the new-attempt circuit breaker;
2. restore signed manifests and verify their transparency chain;
3. restore invoice/destination facts from PostgreSQL backup or merchant-signed
   records;
4. restore claim epochs in an isolated recovery executor;
5. use Boltz's approved restore lookup by xpub/exact public key to recover
   provider swaps;
6. scan the pinned Arbitrum ERC20Swap logs by preimage hash/refund address and
   reconstruct lock tuples;
7. scan Liquid for every reconstructed target script/outpoint;
8. reconcile claims, refunds, and target outspends;
9. rebuild `next_action_at` for every nonterminal funded attempt;
10. have an independent reviewer compare reconstructed totals to chain state;
11. resume recovery workers before considering new-attempt service.

The drill passes only if all funded attempts are found and each has an
executable next action. Restoring row counts is not enough.

### 23.3 Bullnym-wide outage

The independent refund watchtower continues permissionless payer refunds. A
second claim/recovery domain consumes replicated signed manifests and policy
capsules. Merchant and payer recovery clients can independently search the
chains. DNS and the main Bullnym API are not dependencies for contract-level
refund.

### 23.4 Merchant recovery

Bull Bitcoin Mobile should be able to import the encrypted capsule, verify it
against the provider swap response and merchant destination, reconstruct the
claim with a pinned recovery tool, and broadcast through independent Liquid
infrastructure. This is a last-resort path; normal automatic claim workers
should finish first.

The capsule format is versioned, self-describing, encrypted to a purpose-
specific merchant recovery key, and contains integrity commitments to invoice,
attempt, claim pubkey, preimage hash, destination, amount, swap tree, and
provider ID. Never encrypt it only to a Bullnym-held key.

## 24. Merchant Make-Whole Policy

Protocol recovery and a merchant payment guarantee are separate promises.

At minimum, automatic compensation is mandatory when:

- the source was claimed using the attempt preimage but the required merchant
  L-BTC output is not confirmed by the SLO;
- the policy executor or Bullnym redirected/underpaid the claim;
- a Bullnym-controlled failure exposed the preimage early;
- verified merchant settlement reorged away after Bullnym reported final paid.

Product may additionally guarantee every accepted confirmed source lock. If so,
define the acceptance point, settlement SLO, exclusions for chain/issuer halt,
and automatic reserve transaction. Compensation pays the same immutable
merchant Liquid destination and is recorded with separate evidence source:

```text
source = stablecoin_make_whole
```

It does not suppress payer refund automation. If payer refund and merchant
compensation both occur, Bullnym absorbs the loss by design.

Admission stops before outstanding worst-case liability exceeds available
reserve after conservative haircut. Treasury and payment operations must not
share a single unfenced hot-wallet balance.

# Chain-Swap Reliability v3

- Status: Proposed
- Owner: Unassigned
- Affected repositories: `bullnym`, `bullbitcoin-mobile`
- Written against: `origin/main` at `6e73944` (PR #76, schema marker 044)
- Last updated: 2026-07-11

**Supersedes:** the implementation ordering and unresolved server model in
[archived Recovery v2](../../archive/plans/superseded/recovery-v2.md). The
single-address decision and the external mobile gap-limit plan remain valid.

## 1. Objective

Keep the current payer experience and Bullnym deployment model while making a
funded BTC-to-L-BTC chain swap a durable monetary obligation that cannot be
silently abandoned.

For every confirmed Bitcoin source outpoint sent to an address issued by
Bullnym, the server must continue working until it has independently verified
one of these outcomes:

1. a confirmed L-BTC output to the merchant's immutable Liquid destination; or
2. a confirmed Bitcoin output to the merchant's immutable emergency address.

An unconfirmed source transaction is watched until it confirms or is proven
evicted/conflicted; it does not create merchant credit by itself. Any other
outcome for a confirmed source is an explicit, non-terminal integrity incident.
It must stop new chain-swap admission, preserve all evidence, and remain visible
until an operator resolves it. A provider status, retry limit, invoice expiry,
process restart, transaction broadcast, or stale database flag is never
sufficient to declare a funded obligation complete.

This objective is narrower and more honest than "zero risk of loss": no
software can guarantee chain liveness, finality against arbitrary deep reorgs,
or safety after every copy of the keys and records is destroyed. Under the
threat model below, however, Bullnym should have no ordinary crash, retry,
backend, fee, restore, or state-machine path that abandons funds.

## 2. Locked constraints

- The merchant wallet may be offline for the entire payment and recovery flow.
- The payer may use any ordinary Bitcoin wallet. No Bullnym-aware protocol,
  refund address, refund key, or recovery file is required from the payer.
- Bullnym is the only policy operator. Public chain backends and Boltz may
  provide data or protocol services, but they do not approve merchant policy.
- Boltz compromise is explicitly outside this plan's threat model. Protocol
  validation still remains mandatory to catch drift, malformed responses,
  wrong-network data, and Bullnym integration errors.
- New swaps use one merchant-authenticated emergency Bitcoin address, not a
  descriptor and not a per-swap address.
- The emergency address comes from a Bullnym-specific recovery keychain in the
  merchant wallet, not the merchant's main wallet. Bullnym receives only the
  address.
- Rotation affects future swaps only. Each swap keeps the exact address copied
  into it at creation.
- Normal settlement remains L-BTC for privacy. Bitcoin recovery is the
  exceptional fallback.
- The public invoice, POS, and donation payer flow does not change.
- Stablecoins and Satora are outside this plan.

## 3. Threat model

### Included

- process crash or kill at every network and database boundary;
- database timeout, failed commit, stale snapshot restore, sequence rewind, or
  partial operational backup;
- dropped, duplicated, delayed, or reordered Boltz webhooks;
- temporary Boltz API unavailability;
- Bitcoin or Liquid backend outage, stale result, malformed raw transaction, or
  disagreement between configured backends;
- fee spikes, mempool eviction, replacement, rebroadcast, and ordinary reorgs;
- out-of-order provider statuses and retry exhaustion;
- underpayment, overpayment, multiple source outputs, and funding after invoice
  expiry;
- merchant archive/cancel racing with payment;
- an API or worker bug attempting to pay an address other than the immutable
  merchant destination;
- operator deployment with workers, keys, schema, backends, or recovery policy
  unavailable.

### Excluded or impossible under the constraints

- A malicious Bullnym process can still serve a false payer instruction and,
  because it holds the swap keys, can attempt to sign a theft transaction. An
  in-process policy validator reduces accidental misuse but is not a security
  boundary against the process itself.
- A compromised Boltz service is excluded by product decision.
- The payer has no unilateral refund path. If the merchant does not deliver the
  purchased good after Bullnym pays the merchant, protocol recovery cannot
  adjudicate that commercial dispute.
- Literal compensation after both on-chain paths are irreversibly lost requires
  a Bullnym-funded reserve. That is an economic guarantee, not a swap protocol
  property, and is a separate product decision described in section 11.

## 4. Baseline from the recent PRs

These changes are prerequisites and must not be reimplemented:

| PR | What it establishes | What remains |
|---|---|---|
| [#71](https://github.com/BullishNode/bullnym/pull/71) | Unique reverse `boltz_swap_id`; collisions fail closed. | No change needed for chain recovery. |
| [#72](https://github.com/BullishNode/bullnym/pull/72) | Repairs a claimed chain swap missing its invoice payment event. | Repair currently trusts `claimed` plus a txid. It must eventually require confirmed, validated merchant-output evidence. |
| [#73](https://github.com/BullishNode/bullnym/pull/73) | Prevents merchant purge while a chain swap is non-final. | The final-state definition must be updated when broadcast and confirmation states are split. |
| [#74](https://github.com/BullishNode/bullnym/pull/74) | Verifies Liquid raw bytes match the requested txid before caching or use. | Irreversible decisions still need confirmation/inclusion policy and backend-disagreement handling. |
| [#75](https://github.com/BullishNode/bullnym/pull/75) | Re-drives funded `claim_stuck` rows through the existing claim path with slow backoff. | `claim_stuck` remains incorrectly terminal in parts of the model. Retry is not a substitute for deciding between claim and recovery from chain evidence. |
| [#76](https://github.com/BullishNode/bullnym/pull/76) | Persists key indices and a root fingerprint; detects a simple sequence rewind. | Detection only logs. A complete stale database restore rewinds rows and sequence together and can pass the current check. Epochs, admission blocking, provider restore reconciliation, and external recovery manifests remain. |

The earlier PRs that added chain polling, script-path claims, round-robin
reconciliation, payment grace, backend failover, and real merchant recovery are
also retained. They are implementation primitives, not proof that the complete
obligation lifecycle is safe.

### Verified remaining gaps on `origin/main`

- `src/boltz.rs` still sends `pair_hash: None`, trusts the returned BIP21, and
  checks only the original server-lock amount beyond the fork's incomplete
  response validation.
- `src/claimer.rs` persists claim bytes but treats a successful broadcast as
  `claimed`; merchant recovery stores no raw refund bytes and marks `refunded`
  immediately after broadcast.
- the same file still constructs Liquid claims at `Fee::Relative(0.1)` and BTC
  recovery at `Fee::Relative(2.0)` regardless of current chain conditions.
- `src/db/chain_swaps.rs` still treats `claim_stuck` as terminal and uses the
  existence of any claim bytes/txid as a permanent recovery veto.
- merchant recovery still asks Boltz for the source transaction before using
  Esplora; it is not independently discoverable from the issued script alone.
- webhook deduplication is committed before processing in `src/claimer.rs`.
- `/ready` in `src/readiness.rs` checks only database and schema, not money-path
  readiness.

## 5. System invariants

All implementation work and tests should refer to these invariants by ID.

### I1 - Every confirmed source outpoint is an obligation

The unit of responsibility is a Bitcoin `(txid, vout)`, not a webhook and not
only the swap row. Every detected mempool outpoint is tracked, but it becomes a
hard merchant obligation only when confirmed. Partial, repeated, or late
funding creates one obligation per confirmed outpoint. No confirmed funded
outpoint is discarded because an invoice or provider swap expired.

### I2 - Merchant destinations are immutable per swap

Before a payer sees a Bitcoin address, the swap durably contains:

- the exact merchant Liquid output policy used by the claim builder; and
- the signed, single emergency Bitcoin address copied from merchant setup.

Rotation changes only subsequently created swaps. Builders accept a typed
`MerchantSettlementPolicy`; they do not accept arbitrary output strings.

### I3 - Persist before irreversible action

- Validated swap terms are committed before the payer BIP21 is returned.
- A provider-mutating operation is journaled before it is requested.
- Exact transaction bytes, inputs, outputs, fee, and locally calculated txid are
  committed before broadcast.
- A retry reuses the persisted operation or transaction. It never silently
  reconstructs a different attempt.

### I4 - Chains are authoritative; provider states are hints

Boltz webhooks and `get_swap` accelerate work but do not terminalize a funded
obligation. Bullnym independently observes the Bitcoin source script and the
Liquid server-lock script and classifies their outspends.

### I5 - Broadcast is not settlement

`constructed`, `broadcast`, `mempool`, `confirmed`, `finalized`, `replaced`, and
`reorged` are distinct transaction states. Invoice accounting becomes settled
only after the configured confirmation policy and exact merchant-output
validation pass.

### I6 - Account the value the merchant actually received

Payment events use the confirmed merchant output's actual asset, value, txid,
and vout. They never use a stale quote, the original requested amount, or a
provider status as a proxy. Underpayment stays partial; overpayment stays an
overpayment; recovery fees are visible and never hidden by pretending equality.

### I7 - Recovery never depends on admission

Closing new payment admission must not stop webhooks, chain scans, claiming,
rebroadcast, fee replacement, confirmation watching, or recovery of existing
obligations.

### I8 - New obligations require recovery readiness

Bullnym may expose a new swap address only when key derivation, schema,
required current-process workers, chain observation, fee policy, the exact
recovery destination, and startup reconciliation are healthy.

## 6. Target data model

Use the next available migration at implementation time. Do not copy obsolete
migration numbers from `recovery-v2.md`.

### 6.1 `chain_swap_fundings`

One row per Bitcoin source outpoint:

- `id`, `chain_swap_id`, `source_txid`, `source_vout`;
- `amount_sat`, `first_seen_at`, `last_seen_at`;
- mempool and confirmation evidence, including height and block hash;
- `spent_by_txid`, spend classification, and last verification time;
- resolution: `observed_unconfirmed`, `invalidated_unconfirmed`, `open`,
  `liquid_paid`, `btc_recovered`, or `integrity_hold`;
- resolving transaction and timestamps.

Unique `(source_txid, source_vout)`. Existing swaps are backfilled from chain
history; no amount is invented from the provider response.

### 6.2 `chain_swap_settlement_allocations`

Links source funding value to a confirmed merchant output:

- funding row, settlement tx attempt, output vout, and allocated amount;
- allocation kind `liquid_settlement` or `btc_recovery`;
- unique constraints that prevent one source value or merchant output value
  from being counted twice.

This is necessary because multiple Bitcoin fundings may map to one Liquid
server lock, while Bitcoin fallback normally maps one source outpoint to one
recovery input. A single Liquid output must not be copied into one payment event
per source outpoint. If Bullnym cannot prove the provider's value mapping, the
extra funding remains open or enters `integrity_hold`; it is not assumed paid.

### 6.3 `chain_swap_tx_attempts`

The target write-ahead ledger for both `liquid_claim` and `btc_recovery`:

- swap and optional funding identity;
- kind, attempt number, and replacement parent;
- exact source outpoints and immutable destination script;
- raw transaction hex and locally calculated txid;
- actual output amount, fee amount, fee rate, and units;
- construction, broadcast-attempt, mempool, confirmation, finalization, and
  invalidation timestamps;
- confirmation height and block hash;
- last broadcast result.

Existing `claim_tx_hex`, `claim_txid`, and `refund_txid` remain compatibility
columns during migration, but the attempt ledger becomes authoritative. The
schema must prevent two active, unrelated recovery attempts for one source
outpoint.

Migration 046 deliberately introduces only the `btc_recovery` writer and
executor needed to close issue #62's live broadcast ambiguity. Liquid claims
adopt the ledger with issue #83, after their confirmation/output evidence is
defined. Replacement lineage remains deferred with issue #86.

### 6.4 `chain_swap_operations`

Small journal for non-transaction side effects such as quote acceptance and a
cooperative-claim request that may disclose the preimage:

- operation kind and idempotency identity;
- request terms and response revision hash;
- `prepared`, `requested`, `acknowledged`, `reconciled`, `failed`;
- timestamps, retry count, and last error.

### 6.5 Process-local money admission

The accepted deployment contract uses one in-process, per-rail admission
snapshot. Persistent `worker_heartbeats` and cross-replica health coordination
are explicitly rejected: a new process starts closed and must observe its own
required workers complete successful startup cycles before it exposes a new
payment instruction. Historical database state can never open a new process.

Hard prerequisites close their dependent rail immediately. Runtime cycles use
three-failure/two-success hysteresis, and three missed cadences close the rail.
The snapshot gates only new addresses, invoices, keys, and provider
obligations; existing status, webhook, observation, claim, reconciliation,
settlement-repair, and recovery work never consults it. See
`architecture/abuse-and-readiness.md` for the rail matrix and public/private
error contract.

### 6.6 Recovery commitment and creation metadata

- append-only merchant recovery commitment containing address, original signed
  authorization, version, and registration timestamp. Rotation inserts a new
  version; it never updates the old row;
- immutable recovery commitment ID copied to each swap with a foreign key;
- pair hash, validated response hash, script hashes, timeouts, assets, networks,
  expected amounts, and derivation scheme/epoch;
- append-only recovery-manifest delivery state.

The runtime database role should not have `UPDATE` or `DELETE` permission on a
committed recovery-address version. A migration role may manage schema; normal
rotation is an insert.

## 7. Authoritative outcome reducer

Implement one pure decision function and make webhooks, polling, restart repair,
and manual recovery feed evidence into it. They must not each invent their own
state transitions.

The reducer returns one of: `Observe`, `ClaimLiquid`, `Renegotiate`,
`WaitForBitcoinTimeout`, `RecoverBitcoin`, `WatchTransaction`, `Finalize`, or
`IntegrityHold`.

Decision priority:

1. If a known merchant settlement transaction spends the relevant output,
   watch it to configured finality.
2. If an unknown transaction spends either swap output, enter
   `integrity_hold`; preserve evidence and block new chain-swap admission.
3. If the Bitcoin source is spent by Boltz using the preimage, require a
   matching merchant Liquid settlement. Never report success from the source
   spend alone.
4. If the Liquid server lock exists and is unspent, claim it. Provider expiry
   does not disable the script path.
5. If a safe renegotiation can still produce a valid server lock, re-drive the
   journaled negotiation.
6. If the Liquid path is demonstrably unavailable and the Bitcoin source is
   still unspent, attempt cooperative merchant recovery; if unavailable, wait
   for the script timeout and recover unilaterally.
7. If evidence is incomplete or backends disagree, keep observing. Do not
   convert uncertainty into `expired`, `refunded`, or `claimed`.

The current rule that any `claim_txid` or `claim_tx_hex` permanently blocks BTC
recovery is replaced by this evidence matrix. A constructed claim is intent,
not proof that the Liquid output remains payable or that a preimage reached the
source chain.

## 8. Implementation phases

Critical path:

`Phase 0 -> Phase 1 -> Phase 2 -> Phase 3 -> Phase 4 -> Phase 5C/5D -> Phase 6`

The server registration endpoint and mobile work in Phase 5A/5B may proceed in
parallel after Phase 0. They must be deployed before Phase 5C and before Phase
1 creation enforcement is considered fully compliant with invariant I2.

### Phase 0 - Make the baseline buildable and reproducible

**Purpose:** establish a trustworthy test and dependency baseline before
changing monetary state.

1. Repair the DB integration-test target noted in PRs #72, #73, and #75.
2. Add a minimal fault-injection harness with a controllable database, fake
   Boltz transport, fake Bitcoin backend, and fake Liquid backend.
3. Complete [#70](https://github.com/BullishNode/bullnym/issues/70): pin the
   exact `boltz-client` revision, embed it in release metadata, and fail builds
   when the expected checkout is absent or dirty.
4. Close issues already implemented and rewrite the remaining umbrella tickets
   using the mapping in section 10.

**Gate:** clean library, binary, migration, and DB integration tests from a
fresh checkout; reproducible release artifact identifies the exact Boltz fork.

### Phase 1 - Stop creating obligations Bullnym cannot recover

#### 1A. Minimal admission guard

Implement [#68](https://github.com/BullishNode/bullnym/issues/68) as one
process-local, per-rail guard:

- start every process closed and require its own successful worker startup
  scans; no persisted heartbeat may open a new process;
- require workers enabled, current schema/journal capability, initialized
  rail backends, safe key lineage, and the exact hard facts for that rail;
- check before key/address allocation, Boltz creation, invoice publication, or
  exposing a payer instruction;
- use fixed three-failure/two-success hysteresis and three-cadence staleness
  for runtime worker cycles;
- return a generic `503` and log only structured internal reason codes;
- leave unrelated direct rails and every existing-obligation path running.

#### 1B. Finish derivation recovery

Extend [#65](https://github.com/BullishNode/bullnym/issues/65):

- add derivation epoch and scheme version;
- make the PR #76 guard fail closed for new swap admission;
- compare the database high-water mark with Boltz's xpub restore index at
  startup. Validate the exact restore-index semantics against mainnet/test
  fixtures before relying on it;
- on disagreement, fetch the xpub restore list, reconcile missing swaps, and do
  not merely advance the sequence;
- enforce one global `(root, epoch, child_index)` allocation identity across
  reverse claim, chain claim, and chain refund purposes;
- write a signed, encrypted recovery manifest containing the non-secret policy
  and derivation metadata before exposing a payer instruction.

The manifest may use ordinary encrypted backup/object storage. It is passive
storage, not a policy operator. Without state outside the restored database,
detecting a complete stale database restore is impossible.

#### 1C. Validate chain-swap creation completely

- fetch and pin the current pair hash;
- validate both Taproot trees against the exact expected templates;
- independently assert both hashlocks equal the locally generated preimage hash
  and each other;
- verify client/server key roles, chains, networks, assets, amounts, limits,
  and timeout ordering;
- persist all approved terms and a canonical response hash;
- build BIP21 locally from the validated address and payer amount;
- commit the complete swap plus the immutable Liquid destination and any
  already-registered emergency address before BIP21 is returned.

Creation validation can deploy before the mobile registration rollout, but
such legacy/no-address swaps are not v3-compliant and retain manual recovery.
After Phase 5 registration is available, enforcing an emergency address before
new BTC offers is the gate that completes invariant I2.

This is protocol-correctness work even though malicious Boltz is excluded.

**Gate:** every creation crash point either exposes no address or leaves a
durable, restorable swap; malformed or inconsistent responses never reach the
payer.

### Phase 2 - Build chain evidence and the obligation reducer

#### 2A. Durable webhook inbox

Fix [#30](https://github.com/BullishNode/bullnym/issues/30): persist the webhook
payload into an inbox and acknowledge only after the inbox commit. A worker
marks it processed after successful handling. Monetary transitions remain
idempotent at their own unique keys. Do not permanently consume
`swap_id:status` before processing, because the same status can legitimately
reappear after retries or reorgs.

#### 2B. Independent source and destination scans

- discover Bitcoin funding from lockup-address/script history, not only Boltz
  `/transactions`;
- discover Liquid server locks and outspends from script history;
- verify raw txid, expected script, asset, value, and output index locally;
- use provider txids only as hints;
- record one `chain_swap_fundings` row per source outpoint;
- keep a low-frequency cold scan for expired/unfunded issued scripts so late
  payments are not abandoned;
- require either a self-hosted node/backend or agreement between independent
  configured backends for irreversible classification. Backend disagreement
  delays action and alerts; it does not select whichever answer is convenient.

#### 2C. Reducer in shadow mode

Run the pure reducer alongside existing logic without taking actions. Compare
its decision with current webhook/reconciler transitions and emit structured
drift metrics. Build the full table-driven evidence matrix before enabling it.

**Gate:** dropped webhooks, reordered statuses, expired invoices, multiple
funding outputs, and late funding all converge to stable obligations in tests;
shadow mode has no unexplained decision drift on staging.

### Phase 3 - Durable transactions, finality, and fees

#### 3A. Introduce #62's transaction journal

Implement [#62](https://github.com/BullishNode/bullnym/issues/62) for Bitcoin
recovery attempts first:

1. acquire the per-swap lock;
2. re-read evidence and reducer decision;
3. construct and locally validate exact inputs and merchant outputs;
4. persist exact bytes and txid;
5. commit;
6. broadcast only persisted bytes;
7. on ambiguity, inspect txid and source outpoint before rebroadcast;
8. freeze unknown outspends instead of reconstructing.

Liquid claims adopt the same ledger later under #83. Keep cooperative claims
first for their privacy advantage, but split the vendored Boltz API into
prepare and execute steps. Preparation must expose the
proposed Bitcoin source-claim transaction hash/nonce and the exact Liquid claim
template without sending Bullnym's partial signature or preimage. Persist that
authorization, template, destination, and a `cooperative_claim_requested`
operation before the execute call can disclose the preimage. If the fork cannot
provide this boundary, use the local script-path claim until it can; do not
reveal the preimage inside an unjournaled `construct_claim` call.

On an ambiguous execute response, the reducer verifies both chains, continues
pursuing the journaled Liquid output, and may use the local script path when it
remains valid. The source-chain spend is expected only if it matches the
journaled authorization or reveals the correct preimage. Cooperative failure is
never a terminal claim failure.

#### 3B. Make fee policy real

Complete [#64](https://github.com/BullishNode/bullnym/issues/64) phase 1:

- Bitcoin construction fetches `fastestFee` from the configured mempool-style
  primary with a 1-2 second timeout;
- invalid estimates use a validated fallback; valid estimates are clamped to a
  configured floor and maximum rather than replaced by a low fallback;
- Liquid uses a validated configured rate unless live estimation proves useful;
- every attempt records fee units, rate, and actual fee;
- already-journaled bytes are never rebuilt merely because estimates changed.

#### 3C. Confirmation and reorg lifecycle

- replace broadcast-terminal `claimed` and `refunded` semantics with
  constructed, broadcast, mempool, confirmed, and operationally finalized
  states;
- verify the confirmed transaction is the journaled transaction or an explicit
  linked replacement and pays only the approved merchant destination;
- create invoice payment events only from confirmed merchant outputs;
- on eviction, rebroadcast; on reorg, demote and resume watching;
- change PR #72's repair query to require confirmed journal evidence.

Recommended starting policy: two Liquid confirmations and three Bitcoin
recovery confirmations, configurable and tested at the boundaries.

#### 3D. Explicit Bitcoin fee replacement (deferred post-release, issue #86)

- signal RBF on recovery construction;
- after a configured time/block deadline, create a linked replacement spending
  the same source and paying the same merchant script;
- increase the fee monotonically within the merchant-value floor and global
  cap;
- preserve every parent attempt; never overwrite raw bytes;
- continue watching every attempt because an earlier version may confirm;
- do not depend on CPFP from an offline merchant wallet.

Liquid replacement should be added only if Elements behavior is proven by an
integration test. A conservative fixed Liquid rate plus rebroadcast is the
initial policy.

**Gate:** kill-at-every-boundary tests prove exact rebroadcast; no invoice is
settled on broadcast; fee spikes, eviction, replacement, and ordinary reorgs
converge without changing the merchant destination.

### Phase 4 - Make renegotiation crash-safe and amount-correct

Rewrite [#38](https://github.com/BullishNode/bullnym/issues/38) around the
operation journal and actual chain value:

- persist the quote, policy decision, and `accept_requested` before calling
  Boltz;
- after timeout or ambiguous response, reconcile the operation through
  `get_swap`, quote state, and chain evidence rather than falling directly to
  recovery;
- version validated swap terms after an accepted quote;
- make claim construction validate the actual unblinded Liquid lockup value,
  not the amount embedded in the original `boltz_response_json`;
- accept only economically positive quotes inside configured provider-fee and
  minimum-merchant-net bounds;
- credit only the confirmed merchant output value;
- retry transient `get_quote` and `accept_quote` failures from the reconciler;
- use protocol timeout margins, not a blind 24-hour grace period, to decide when
  the Liquid path has ended.

**Gate:** crashes before request, after request, after provider acceptance, and
before local commit all converge to the same terms; underpayment cannot be
credited at the original amount.

### Phase 5 - Precommitted automatic merchant recovery

#### 5A. Register one emergency address

- add a merchant-signed endpoint dedicated to recovery-address registration;
- insert an append-only commitment containing address, original signature,
  version, and timestamp;
- copy the commitment ID into every newly created chain swap;
- rotation changes only future swaps;
- after a migration window, do not expose a new BTC chain-swap offer unless an
  emergency address is registered;
- never expose the address through an anonymous endpoint.

The existing signed recovery endpoint remains for legacy swaps but cannot
change a precommitted destination.

#### 5B. Mobile recovery keychain and gap safety

- derive the single address from a Bullnym-specific Bitcoin recovery keychain,
  not the main merchant wallet;
- reserve and label it before registration;
- ship the applicable guardrails from
  `bullbitcoin-mobile/plans/gap-limit-guardrails.md` before or with
  registration;
- heal the label after seed restore;
- when the merchant wallet is online, auto-sweep each recovered UTXO separately
  to the main wallet according to merchant policy. Never aggregate unrelated
  recovery UTXOs in one sweep.

Using one address necessarily links all exceptional recoveries to each other.
Non-aggregating sweeps avoid adding a second consolidation link but cannot undo
that address-reuse tradeoff.

#### 5C. Automatic recovery worker

The reducer authorizes recovery only when:

- a source outpoint is confirmed and unspent;
- no confirmed or still-viable merchant Liquid path exists;
- renegotiation is resolved or outside its safe protocol window;
- the immutable emergency address exists;
- recovery is cooperative-safe now or script-path spendable at the current
  Bitcoin height.

The worker journals, broadcasts, fee-bumps, watches, and confirms without the
merchant wallet being online. Manual action is an override for legacy or
integrity-hold cases, not the normal executor.

Build one BTC recovery attempt per source outpoint. Bullnym must not aggregate
unrelated payer fundings merely because they share the single emergency
address.

#### 5D. Honest accounting and archive races

Merge the intent of [#29](https://github.com/BullishNode/bullnym/issues/29) and
[#77](https://github.com/BullishNode/bullnym/issues/77):

- archive replaces the mental model of rejecting late money;
- always record a confirmed monetary event even after archive/cancel;
- reject archive while a known live swap is funded when practical;
- record rail `btc_recovery`, actual output amount, fee, txid, vout, swap, and
  funding identity;
- let ordinary accounting determine partial, paid, or overpaid;
- do not suppress the evidence as "irreconcilable" merely to stop retries.

**Gate:** a real underpaid mainnet swap reaches confirmed merchant BTC with the
phone offline, records the actual amount exactly once, and survives crashes,
backend failover, and a fee replacement.

### Phase 6 - Complete recovery facts, restoration, and rollout

Issue [#68](https://github.com/BullishNode/bullnym/issues/68) supplies the
enforced admission boundary in Phase 1. Later packages supply hard facts to
that boundary rather than replacing it with another admission policy. In
particular, new chain-swap admission remains closed until it can verify:

- this process's required workers completed startup and remain live;
- the current schema/journal and safe derivation lineage;
- initialized Bitcoin, Liquid, and Boltz evidence paths;
- a persisted live fee decision from #64;
- the exact merchant recovery commitment from #84.

Do not add persistent heartbeats, cross-replica coordination, backlog scoring,
age/exposure prediction, or queue-capacity policy to #68. An integrity hold or
a later recovery capability may close a typed hard fact, but existing status,
observation, claim, reconciliation, and recovery execution must remain online.

Add runbooks and drills for:

- stale database restore and xpub reconciliation;
- loss of one chain backend;
- Boltz API unavailable through the cooperative window;
- transaction eviction and RBF;
- ordinary reorg after initial confirmation;
- key-root rotation while old swaps remain recoverable;
- restoring a missing swap from manifest plus Boltz restore data;
- pausing admission while proving existing recovery continues.

## 9. Rollout sequence

1. Land Phase 0 and the Phase 1 admission guard with enforcement active. A
   short staging shadow comparison is allowed, but no production bypass ships.
2. Deploy complete creation validation; fail closed by omitting only the BTC
   swap rail when validation or readiness fails.
3. Deploy Phase 2 evidence collection and reducer in shadow mode for at least
   one full swap-timeout window.
4. Enable journal v2 and confirmation watching for manual recovery first.
5. Run real low-value cases: exact pay, underpay, overpay, multiple outputs,
   late pay, dropped webhook, crash at every journal boundary, provider API
   outage, backend disagreement, eviction, RBF, and reorg simulation.
6. Release mobile emergency-address registration and verify restore/heal.
7. Require a registered address for new chain-swap offers.
8. Enable automatic recovery for a bounded merchant cohort and low exposure
   cap; expand only after confirmation and backlog SLOs hold.
9. Remove legacy state transitions only after all legacy swaps are terminal or
   explicitly migrated.

Rollback rules:

- disabling admission is always permitted;
- disabling observation or recovery for existing obligations is not a valid
  rollback;
- schema rollback must never delete transaction, operation, funding, or
  derivation evidence;
- feature flags may choose an executor, but all versions must understand and
  preserve newer non-terminal states.

## 10. Open-issue disposition

### Keep and rewrite against this plan

| Issue | New ownership |
|---|---|
| [#62](https://github.com/BullishNode/bullnym/issues/62) | Phase 3A, generalized claim/recovery transaction journal. |
| [#64](https://github.com/BullishNode/bullnym/issues/64) | Phase 3B only; create a separate child for Phase 3D replacement. |
| [#65](https://github.com/BullishNode/bullnym/issues/65) | Phase 1B remaining work after PR #76. |
| [#68](https://github.com/BullishNode/bullnym/issues/68) | One process-local per-rail admission gate; later phases supply typed hard facts. |
| [#70](https://github.com/BullishNode/bullnym/issues/70) | Phase 0 reproducibility. |
| [#30](https://github.com/BullishNode/bullnym/issues/30) | Phase 2A durable inbox. |
| [#38](https://github.com/BullishNode/bullnym/issues/38) | Phase 4 operation journal and actual-value settlement. |
| [#44](https://github.com/BullishNode/bullnym/issues/44) | Retitle to legacy/manual recovery; create children for registered address and automatic recovery. |
| [#29](https://github.com/BullishNode/bullnym/issues/29) | Phase 5D; absorb #77. |
| [#28](https://github.com/BullishNode/bullnym/issues/28) | Parallel direct-payment finality track using the same confirmation semantics. It does not gate chain-swap work. |

### Close after deployment verification

Issues #7, #8, #9, #12, #27, #36, and #47 appear implemented on `main`.
Issue #39 is superseded by merchant recovery. Close them with a link to the
implementing PR and a short acceptance note rather than leaving them in the
active roadmap.

### Rewrite or retire umbrellas

- #33 should become a small meta issue pointing to this plan and its active
  children, or be closed.
- #37 should retain only its unresolved display/rail-steering work.
- #14 should remove implemented findings and stop duplicating active issues.
- #77 should close into #29 after its reproducer becomes a test.

Issues #1 and #57 are unrelated product work. #31 remains a separate reverse
swap/LNURL availability track and should not be mixed into the chain-swap
critical path.

### New focused issues required

1. `[chain-swap][CRITICAL] Validate complete creation response and build BIP21 locally`
2. `[chain-swap][CRITICAL] Track each Bitcoin funding outpoint as a durable obligation`
3. `[chain-swap][CRITICAL] Implement the chain-evidence outcome reducer`
4. `[settlement][HIGH] Confirmation, reorg, and exact merchant-output lifecycle`
5. `[recovery][HIGH] Register and precommit one merchant emergency address`
6. `[recovery][HIGH] Automatically execute merchant Bitcoin fallback`
7. `[fees][HIGH] Persisted RBF replacement worker for Bitcoin recovery`
8. `[recovery][HIGH] Reconcile stale restores with Boltz xpub restore and signed manifests`
9. `[testing][HIGH] Restore DB integration tests and add swap fault injection`

## 11. Optional trust-minimization phase

The core plan first introduces a typed in-process settlement policy that rejects
arbitrary destinations. If reducing API-process theft authority later justifies
a second local service, move the swap master key and transaction signing into a
Bullnym-operated signer sidecar.

The sidecar would accept only:

- a validated swap response and source outpoint;
- the original merchant-signed Liquid and emergency-Bitcoin commitments;
- a transaction paying the committed destination within fee policy.

It would independently verify the merchant signature and return signed bytes,
never arbitrary private keys. This preserves the payer flow, merchant-offline
property, and single policy operator. It contains an API-process compromise but
does not make a malicious Bullnym deployment trustless, because Bullnym still
serves the payer instruction and operates both processes.

Do not make this sidecar a dependency of Phases 0-6. First make the single
process correct, recoverable, and observable; then use the same policy object as
the sidecar protocol if operational evidence justifies the boundary.

### Optional economic backstop

If the product wants a literal merchant-loss guarantee even after an
`integrity_hold` proves that neither on-chain path remains, Bullnym needs a
separately funded compensation reserve with per-swap, per-merchant, and global
exposure limits. The reserve pays the merchant, because the generic payer has
provided no refund destination. This does not recover the original swap funds
and cannot be described as trustless.

Automatic compensation for an unclassified spend is unsafe because it can be
abused to drain the reserve. Reserve policy therefore needs independent fraud
analysis and is not part of the automatic chain-swap reducer in Phases 0-6.

## 12. Definition of done

The plan is complete only when all of the following are demonstrated:

- every new swap is fully validated and durably recoverable before its BIP21 is
  exposed;
- a stale derivation state blocks new swaps and has a tested reconstruction
  procedure;
- every source outpoint, including late and repeated funding, is tracked, and
  unconfirmed funding is never credited;
- webhooks can be lost without losing progress;
- exact claim and recovery bytes survive every crash boundary;
- no broadcast alone creates a paid invoice or terminal swap;
- reorged or evicted transactions return to active watching;
- Bitcoin recovery automatically fee-bumps without changing its destination;
- renegotiation cannot credit a stale amount;
- a new swap always contains the merchant's single precommitted emergency
  address;
- an offline merchant receives either confirmed L-BTC or confirmed recovered
  BTC without tapping a recovery action;
- archived invoices retain late monetary evidence;
- new admission closes before a required recovery capability becomes
  unavailable, while existing recovery continues;
- the complete fault matrix and at least one real low-value automatic recovery
  pass before broad production enablement.

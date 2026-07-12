# Bullnym Trust-Minimization Audit and Strategy Portfolio

Status: architecture and protocol analysis, not an implementation plan

Audit date: 2026-07-09

Audited tree: `feat/invoice-notes`, HEAD `45a2a8ff5e984f990716b76f523fd48911c160e2`, with uncommitted work present

Scope: the existing BTC, Lightning, Liquid, invoice, Payment Page, POS, Donation Page, and Lightning Address flows

Explicitly out of scope: stablecoins

## Executive conclusion

Bullnym is noncustodial at the merchant wallet layer, but it is not currently a
trustless payment coordinator.

The distinction matters:

- Bullnym does not have the merchant wallet mnemonic or the ability to spend a
  correctly delivered direct payment.
- Bullnym does control what payment instruction the payer sees.
- For every Boltz reverse swap, Bullnym controls the preimage and claim key.
- For every Boltz BTC-to-LBTC chain swap, Bullnym controls the preimage, claim
  key, and payer-side refund key.
- Bullnym chooses the claim or refund transaction output at transaction-build
  time.
- Bullnym currently declares merchant settlement after transaction broadcast,
  not after confirmed receipt.

Consequently, a malicious or fully compromised Bullnym can redirect a swap
claim to itself, disclose the preimage so the payer's source leg settles, and
leave the merchant unpaid. In a failed chain swap it can also refund the payer's
BTC to an arbitrary address. It can substitute direct-payment instructions
before payment even though it cannot spend a payment that reached the correct
merchant address.

This is not fixed by adding retries, encrypting database columns, or calling the
server "noncustodial." Those are useful reliability controls, but the theft
authority comes from protocol key ownership and from the absence of a
merchant-authenticated payment contract that the payer verifies independently.

The strongest practical direction is not one universal architecture. Different
Bullnym surfaces have different availability constraints:

| Surface | Best trust-minimized direction |
|---|---|
| POS | Merchant device validates or creates the swap and signs the exact payment intent while present. |
| Merchant-created invoice | Derive a separate public PaymentIntent from the merchant request, excluding viewing secrets/private metadata, and sign or cross-certify it with an independently anchored merchant key. |
| Payment Page / Donation Page | Use pre-signed address or swap-ticket inventory plus independent policy signers/watchtowers; remove generic chain swaps unless the payer supplies a refund key. |
| Lightning Address | Treat full offline trustlessness as an unsolved constraint for generic LNURL wallets; use a federation, a merchant agent, or direct Lightning receipt, and disclose the remaining trust. |
| Bull-aware payer wallet | Move the swap to the payer wallet and make Bullnym a signed-intent relay and observer. This is the cleanest payer-recovery model. |

The near-term recommendation is a layered program:

1. Stop exposing new chain-swap funding instructions until the payer recovery
   and validation defects are addressed.
2. Fix response validation, confirmation-based settlement, recovery state, and
   durable restoration before adding new rails.
3. Preserve and expose merchant-signed payment intents so a separate wallet can
   reject server-substituted destinations.
4. Move secrets out of the API process into a policy-constrained executor, then
   add independent recovery watchers.
5. Pilot reverse-swap covenants for on-demand POS/invoice flows that the merchant
   client validates before the BOLT11 is shown.
6. Add a payer-aware chain-swap protocol in which the payer owns the refund key.
7. Offer sender-side swaps or independently verified, merchant-signed direct
   receipt followed by merchant-side conversion as the strongest modes, rather
   than pretending generic server-rendered QR flows provide the same guarantees.

## What "cannot steal" can and cannot mean

A realistic security target is:

> Given live chains and at least one honest recovery actor, a funded payment
> attempt has only two valid monetary outcomes: a confirmed output of the
> required asset and amount to a merchant-authenticated destination, or a
> unilateral refund to a payer-controlled destination. Bullnym alone cannot
> select a third destination, disclose the atomic secret outside the valid
> merchant claim, or stop every recovery actor.

This target does not guarantee:

- that the merchant delivers goods after payment;
- that the payer chooses to complete payment;
- that Bitcoin, Liquid, Lightning, Boltz, or all network paths remain live;
- finality against a catastrophic chain reorganization;
- recovery after every independent signer and every backup is destroyed;
- privacy when a Liquid claim covenant requires explicit asset and value data.

A malicious web server can also serve malicious JavaScript and a malicious QR.
A payer using only that server cannot use the server to prove the server is
honest. Strong payer protection therefore requires an independently distributed
wallet or verifier, a merchant-authenticated intent, and either payer-owned
refund authority or script-enforced outputs.

The merchant verification key also cannot be learned exclusively from the same
Bullnym response as the signature. A malicious server could substitute both.
The payer needs an independently anchored key from prior wallet pairing, a QR
shown by the merchant device, an external identity domain, or independently
witnessed Nostr history.

## Current architecture and authority map

### Runtime concentration

The Axum API process currently performs all of these roles:

- merchant configuration and invoice API;
- payer-facing page and QR generation;
- Boltz swap creation;
- master swap key derivation;
- storage and retrieval of raw preimages and private keys;
- webhook ingestion and provider reconciliation;
- Liquid claim construction and broadcast;
- Bitcoin chain-swap refund construction and broadcast;
- direct Bitcoin and Liquid settlement observation;
- invoice accounting and public payment status.

`SWAP_MNEMONIC` is loaded directly into the API process in
`src/main.rs:81-103`. `BoltzService` retains the resulting `SwapMasterKey` in
`src/boltz.rs:33-57`.

This means an API RCE, process memory disclosure, environment-secret leak, or
operator with equivalent access is not merely an availability incident. It is
an in-flight fund-redirection incident and a compromise of the deterministic
swap key hierarchy.

### Rail matrix

| Rail | Payer instruction | Spend/refund authority | Current settlement boundary | Bullnym theft capability |
|---|---|---|---|---|
| Direct Bitcoin invoice | Merchant supplied address, later served by Bullnym | Merchant wallet | Configured confirmations reported by a JSON address API | Bullnym cannot spend a correct output, but can substitute the served instruction or falsely report settlement. |
| Direct Liquid | Merchant supplied or server-derived descriptor address | Merchant wallet | Any matching Electrum history transaction, including mempool | Bullnym cannot spend a correct output, but can substitute the instruction or accept false/unconfirmed evidence. |
| Lightning via reverse swap | Bullnym-created BOLT11 | Bullnym owns preimage and claim key | Claim broadcast accepted or observed | Bullnym can claim L-BTC to itself and reveal the preimage, settling the payer's Lightning payment. |
| BTC-to-LBTC chain swap | Bullnym serves Boltz lockup address/BIP21 | Bullnym owns preimage, claim key, and refund key | Liquid claim broadcast accepted or observed | Bullnym can redirect the L-BTC claim or refund payer BTC to itself. |
| LUD-22 Liquid | Bullnym derives and serves descriptor address | Merchant wallet | Liquid watcher observation | Bullnym can substitute the returned address; a correct output remains merchant controlled. |

### Current reverse-swap flow

1. Bullnym allocates a database sequence index.
2. The API process derives a claim key and deterministic preimage.
3. Bullnym asks Boltz for a BTC-to-LBTC reverse swap without a claim address and
   with `claim_covenant: None`.
4. Bullnym returns Boltz's BOLT11 after checking only that the string exists.
5. After a Boltz lockup notification, Bullnym reads or derives the merchant
   Liquid destination from mutable database state.
6. Bullnym constructs a claim to that destination, normally through the
   cooperative MuSig2 path.
7. Bullnym persists the constructed claim transaction, broadcasts it, marks the
   swap `claimed`, and records invoice settlement.

Relevant code:

- key/preimage creation: `src/boltz.rs:61-74`;
- request with no destination and no covenant: `src/boltz.rs:76-103`;
- response accepted without validation: `src/boltz.rs:105-123`;
- plaintext persistence: `src/invoice.rs:1702-1726` and
  `src/lnurl.rs:400-422`;
- destination resolved at claim time: `src/claimer.rs:913-1054`;
- arbitrary builder output: `src/claimer.rs:1727-1791`;
- broadcast treated as settlement: `src/claimer.rs:1302-1420`.

### Current chain-swap flow

1. Anonymous checkout eagerly creates a chain swap before a payer chooses the
   Bitcoin rail.
2. Bullnym derives the preimage and both claim and refund keypairs.
3. Bullnym asks Boltz to gross up payer BTC while pinning the nominal Liquid
   server lock amount to the invoice amount.
4. Bullnym validates the two returned addresses with the local library, checks
   only `claim_details.amount`, and serves Boltz's address and BIP21.
5. Bullnym claims the Liquid server lock to the invoice address and reveals the
   preimage so Boltz can claim the payer BTC.
6. If the swap fails, Bullnym waits for a merchant-authenticated recovery request
   and refunds the payer lockup to the merchant-selected Bitcoin address.

Relevant code:

- key/preimage creation: `src/boltz.rs:126-143`;
- provider request: `src/boltz.rs:145-181`;
- incomplete validation: `src/boltz.rs:183-213`;
- plaintext persistence: `src/invoice.rs:1772-1823`;
- arbitrary claim output: `src/claimer.rs:1794-1866`;
- merchant-selected refund output: `src/invoice.rs:1147-1200` and
  `src/claimer.rs:2139-2272`;
- broadcast treated as terminal: `src/claimer.rs:1616-1709` and
  `src/claimer.rs:2083-2112`.

## Severity-ordered audit findings

### Critical 1: Bullnym can redirect every swap claim and chain refund

The raw authority is explicit:

- reverse preimages and claim keys are stored in `swap_records`;
- chain preimages, claim keys, and refund keys are stored in
  `chain_swap_records`;
- the runtime database role receives broad read/write/delete privileges;
- transaction builders accept a caller-supplied output address;
- no script condition binds the ordinary claim to the merchant's destination;
- the reverse request explicitly disables claim covenants.

Theft sequence for Lightning:

1. The payer pays the BOLT11.
2. Boltz locks L-BTC.
3. Bullnym constructs the valid claim to an attacker Liquid address.
4. The claim reveals the preimage, so Boltz settles the Lightning HTLC.
5. The payer has paid and the merchant has not received funds.

Theft sequence for chain swap:

1. The payer funds the returned Bitcoin lockup.
2. Boltz locks L-BTC.
3. Bullnym claims that L-BTC to an attacker address.
4. The revealed preimage lets Boltz claim the payer's BTC.
5. The merchant is unpaid and the payer has no refundable source output.

Theft sequence for a failed chain swap:

1. The payer funds the Bitcoin lockup.
2. The destination leg fails.
3. Bullnym uses its refund key to build a refund to an attacker address.
4. Neither the script nor the payer can reject that output.

Database encryption does not remove this authority because the live process
must decrypt and use the keys. The authority must be moved, split, or
cryptographically constrained.

### Critical 2: reverse-swap creation accepts unverified provider data

`src/boltz.rs:105-123` calls `post_reverse_req` and immediately returns the
response invoice. It never calls the vendored
`CreateReverseResponse::validate` at
`../boltz/boltz-rust/src/swaps/boltz.rs:1194-1226`.

It also does not independently verify:

- BOLT11 payment hash equals Bullnym's generated preimage hash;
- BOLT11 amount equals the approved payer debit;
- BOLT11 description or description hash equals the intended invoice URL;
- BOLT11 network, signature, expiry, and minimum remaining lifetime;
- returned swap script hashlock equals the local preimage;
- returned Taproot address and both exact script templates;
- returned on-chain amount agrees with locally calculated pair fees;
- timeout height and time margin meet policy;
- pair hash, limits, and maximum fees match the quote shown to the payer.

A malicious or compromised Boltz API can return an invoice whose preimage it
already knows, overcharge the payer, or return a payout that is too small. In the
first case it can settle the Lightning payment without creating a merchant-
claimable lockup.

Boltz's own guidance says clients must not trust critical API information,
especially chain addresses and Lightning invoices. It requires checking invoice
hash and amount, scripts, addresses, locally calculated amounts, and independent
chain data:
https://api.docs.boltz.exchange/dont-trust-verify.html

Calling the library's current `validate` is necessary but not sufficient because
its script parsing does not fully bind every returned field to Bullnym's local
policy. Bullnym needs explicit end-to-end policy validation around it.

### Critical 3: chain validation is tautological about the hashlock

Bullnym calls `CreateChainResponse::validate` in `src/boltz.rs:189-196`, but the
vendored implementation at
`../boltz/boltz-rust/src/swaps/boltz.rs:1282-1318` only asks each side to
reconstruct an address.

`LBtcSwapScript::chain_from_swap_resp` and the Bitcoin equivalent extract the
hashlock from the returned provider tree and then reconstruct an address using
that provider-supplied hashlock. They do not compare it with
`HASH160(local_preimage)`, and `CreateChainResponse::validate` does not require
the two sides to use the same hashlock.

This allows a malicious Boltz response to describe a payer-side Bitcoin lockup
whose claim secret is known to Boltz. The returned address can pass the current
validation because the check proves only that the returned address matches the
returned tree. After the payer funds it, Boltz can claim the BTC without a valid
merchant-side atomic outcome.

Required validation must independently parse both trees and assert:

- the exact expected claim/refund opcode templates;
- both hashlocks equal `HASH160(local_preimage)`;
- both sides use the expected client public keys;
- returned server public keys are valid and bound to the same swap response;
- lockup and claim addresses reconstruct from those independently approved
  values;
- the timeout ordering leaves a conservative source-refund margin;
- amounts, assets, networks, and pair hash equal the local quote policy;
- BIP21 is built locally from the validated address and amount rather than
  trusted as provider text.

### Critical 4: chain recovery belongs to the merchant/server, not the payer

The endpoint comment accurately states the current policy in
`src/invoice.rs:1147-1153`: the merchant recovers the payer's BTC to its own
address and makes the payer whole out of band.

This has three implications:

- a payer has no unilateral recovery credential;
- a dishonest merchant can recover payer BTC to itself;
- Bullnym holds the refund key and can ignore the endpoint policy entirely.

The recovery route is also default-off in `src/config.rs:88-104`. The only call
to the refund executor is the merchant HTTP request at `src/invoice.rs:1355`.
The reconciler does not automatically drain `refund_due` rows.

With the current Boltz Bitcoin script, the robust solution is for the payer to
provide and retain the refund key before funding. A generic BIP21 send does not
carry a payer refund public key, so a generic payer cannot receive this
guarantee without an interactive wallet protocol.

The product must choose one of these honest options:

- require a Bull-aware wallet handshake and payer-owned refund key;
- use direct merchant Bitcoin receipt and let the merchant convert later;
- keep merchant-controlled recovery as an explicitly trusted fallback;
- remove the generic BTC-to-LBTC rail.

There is no server-only policy change that makes a server-held refund key
cryptographically payer-owned.

### Critical 5: broadcast is treated as confirmed merchant settlement

Reverse claims are marked `claimed` and credited immediately after broadcast or
mempool discovery in `src/claimer.rs:1312-1420`. Chain claims do the same in
`src/claimer.rs:1616-1709`. Chain refunds become terminal `refunded` immediately
after broadcast in `src/claimer.rs:2083-2112`.

The refund transaction is also built and broadcast before its bytes or txid are
durably journaled. A crash after network acceptance but before
`mark_chain_swap_refunded` leaves only `refunding`; the reconciler later resets
stale rows to `refund_due` without first proving the original transaction's
chain or mempool outcome (`src/reconciler.rs:180-197`). A later request can then
build a conflicting refund, potentially with a different merchant-supplied
destination.

There is no persistent state for:

- claim transaction broadcast but unseen;
- mempool acceptance;
- confirmed merchant output;
- finality depth;
- mempool eviction;
- replacement transaction;
- reorganization;
- confirmed payer refund.

This is especially dangerous for atomic swaps because claim broadcast reveals
the preimage. Boltz can settle Lightning or claim source BTC after observing the
preimage even if the merchant claim is later evicted or loses a timeout race.

The code itself acknowledges that a claim transaction may be unconfirmed in
`src/db/chain_swaps.rs:568-573`, but accounting still treats the earlier
broadcast as terminal success.

Direct Liquid accounting has the same evidence problem. The watcher consumes
Electrum history that explicitly includes mempool transactions and immediately
records an accounting event in `src/chain_watcher.rs:261-353`.

Required states are at least:

`constructed -> broadcast -> mempool -> confirmed -> finalized`

and, separately:

`refund_eligible -> refund_constructed -> refund_broadcast -> refund_confirmed`.

Merchant fulfillment policy can choose a low confirmation target, but the
system must not call a broadcast proof a confirmation. A low-value 0-conf mode
should be an explicit, capped, insured risk tier.

### High 1: cooperative claims disclose the preimage before durable broadcast

The default path requests a cooperative MuSig2 signature. During construction,
the vendored library sends the raw preimage and unsigned claim transaction to
Boltz at `../boltz/boltz-rust/src/swaps/liquid.rs:716-742`.

Only after that request returns does Bullnym serialize and persist the signed
claim transaction at `src/claimer.rs:1256-1277` or
`src/claimer.rs:1570-1597`, commit, and broadcast.

The crash window is:

1. Boltz receives the preimage.
2. Boltz can settle the source leg.
3. Bullnym has not durably stored a signed merchant claim.
4. Bullnym crashes, the response is lost, or Boltz withholds a usable partial
   signature.

Strict safety mode should use the noncooperative script path so the preimage is
first disclosed inside a fully signed, destination-checked transaction being
broadcast. This costs more and reveals the swap script, but closes the API
pre-disclosure window.

A future cooperative protocol could use adaptor signatures or another exchange
in which the provider learns the secret only from the final transaction. That
requires Boltz protocol work; a write-ahead database row alone cannot make the
current network request atomic with transaction publication.

### High 2: settlement accounting credits nominal amounts, not proven outputs

Reverse settlement records `swap.amount_sat`, the requested Lightning amount,
at `src/claimer.rs:1409-1418`. It does not record Boltz's actual
`onchain_amount` minus the claim fee.

Chain settlement records the nominal or renegotiated server lock amount at
`src/claimer.rs:1692-1705`, while the actual merchant output is that lock amount
minus the Liquid claim fee.

This mixes at least four different monetary values:

- invoice target;
- payer debit;
- provider destination lock amount;
- confirmed merchant output amount.

The provider's swap fee and both chain fees need an explicit payer-pays or
merchant-pays product policy. If the promise is "merchant receives the invoice
amount in L-BTC," the payer instruction must be grossed up and the returned
lockup plus actual claim fee must be verified before display.

The alternative-outspend recovery path is weaker. It treats a spending
transaction as the merchant claim if any non-fee output script matches any
expected claim output script, without checking asset, value, outpoint,
confirmation, or whether an attacker also takes the balance:
`src/claimer.rs:2395-2449`.

Exact independent verification is not always possible with the data Bullnym
currently requires. An LN-only invoice may supply a confidential Liquid
destination without `liquid_blinding_key_hex`; the key is enforced only when
`accept_liquid` is true (`src/invoice.rs:2080-2100`). A watcher cannot later
unblind that merchant output to prove its asset and net value. Every swap
destination needs a scoped verification capability: for example, output
unblinding data retained by the policy executor, a view key encrypted to
independent accounting watchers, or merchant-wallet evidence cross-checked
against the transaction. The private blinding key must not be placed in the
public PaymentIntent.

The database constraints are also bypassable. In
`migrations/028_invoice_payment_event_evidence.sql:56-99`, every source, rail,
and evidence check permits `source IS NULL`; the runtime role can update and
delete event rows. A compromised API can therefore insert or mutate an
evidence-free accounting fact even after stronger route checks are added.

Every settlement event must contain canonical chain evidence:

- chain and network;
- transaction id and output index;
- block hash/height and confirmations;
- destination script;
- asset id;
- actual output value;
- source lock outpoint;
- swap id and immutable intent digest.

Make `source` and source-specific evidence non-null for all new events. Give an
append-only projector role sole insert authority, deny the API role event
update/delete privileges, and derive mutable invoice status from replayable
events rather than treating it as the monetary source of truth.

### High 3: chain renegotiation lacks economic authorization and durable state

Bullnym accepts any Boltz renegotiation quote that converts to a positive
`i64`; it does not bind the quote to an independently observed payer input, a
merchant-signed minimum net output, or a maximum provider fee
(`src/claimer.rs:394-421`). A malicious provider can quote a negligible
destination amount for a funded payer input. Accepting that quote can let the
provider consume the payer's BTC while the merchant receives almost nothing.

`accept_chain_swap_quote` is then called before the accepted amount is durably
committed (`src/claimer.rs:423-503`). A crash or ambiguous network response can
change provider state while Bullnym retains the old local state.

Renegotiation writes only `renegotiated_server_lock_amount_sat` in
`src/db/chain_swaps.rs:342-373`. Claim construction later parses the original
`boltz_response_json` in `src/claimer.rs:1820-1838`.

The vendored `SwapScript::construct_claim` validates the actual unblinded
destination UTXO against the `boltz_lockup` amount captured from that original
response at `../boltz/boltz-rust/src/swaps/wrappers.rs:565-668`.

A legitimate renegotiated server lock amount therefore differs from the stale
expected amount and can fail every claim attempt. Finite retries can then move
the funded swap into terminal `claim_stuck`.

Default to refund when observed funding differs from the immutable attempt.
Automatic renegotiation is acceptable only when Bullnym independently verifies
the payer outpoint and calculates a quote within merchant-signed minimum-net,
maximum-fee, and payer-debit policy. Persist an idempotent acceptance operation
before the external call, then fetch and validate a complete new response
revision. The quote, accepted amount, provider response, and both observed
lockups must be bound to that same revision, and accounting must use the proven
merchant output.

### High 4: retry exhaustion abandons live recovery

`claim_stuck` is terminal for both reverse and chain swaps. It is excluded from
the background claimer and from provider reconciliation. The default is 30
attempts, described as roughly 24 hours in `src/config.rs:176-203`.

Recovery must not stop because an operational retry budget was exhausted while
a spendable output still exists. A long node outage, fee spike, chain halt, or
dependency incident can outlive any fixed count.

Use two separate concepts:

- `attention_required`: page an operator and reduce retry frequency;
- `terminal`: chain evidence proves the source/destination outcome can no longer
  change under the defined finality policy.

The fee-bump runbook is also ineffective. It edits `current_fee_rate`, but both
claim builders hardcode `Fee::Relative(0.1)` in
`src/claimer.rs:1778-1786` and `src/claimer.rs:1849-1860`. Refunds hardcode
2 sat/vB and are marked terminal after their first accepted broadcast.

### High 5: claim construction can permanently block a safe payer refund

The chain refund gate refuses to start if either `claim_txid` or `claim_tx_hex`
exists, even if the claim was only constructed and never broadcast:
`src/claimer.rs:2044-2061` and `src/db/chain_swaps.rs:568-579`.

This is too coarse:

- a constructed but undisclosed claim does not make the preimage public;
- a broadcast claim may be absent from every mempool;
- a confirmed source claim proves the payer source is no longer refundable;
- a destination refund after timeout may prove the merchant claim is no longer
  possible.

The safe decision must come from both chains and preimage evidence, not from the
existence of a locally built transaction. Otherwise a failed pre-broadcast
attempt can block the only remaining payer recovery path forever.

### High 6: recovery remains dependent on the party being recovered from

Before a chain refund, Bullnym requires Boltz `get_swap` to say the swap is not
claimed and asks Boltz for the payer lockup transaction id before checking
Bitcoin: `src/claimer.rs:1953-2005` and `src/claimer.rs:1898-1943`.

If Boltz is down, censors the request, or lies, the unilateral refund is
deferred. A unilateral script path that depends on the provider for UTXO
discovery is not operationally unilateral.

Bullnym already knows the validated Bitcoin lockup script and address. Recovery
must discover and verify its funding/outspend from a self-hosted Bitcoin node or
independently verified chain index. Provider status remains advisory.

### High 7: missed or late Bitcoin funding can evade recovery indefinitely

On `swap.expired`, the chain handler decides whether payer BTC exists from the
local `user_lock_mempool` or `user_lock_confirmed` status:
`src/claimer.rs:616-642`. If the funding webhook was missed, or the payer funds
after Bullnym last recorded the attempt, the local row can remain `pending` even
though the lockup address has a spendable Bitcoin output.

The chain reconciler polls Boltz and replays the same handler, but it does not
independently scan the known source script. A remote `swap.expired` applied to a
locally `pending` row therefore does not prove that the source was unfunded and
does not route it to payer recovery.

Every issued source script must remain in a provider-independent Bitcoin scan
until its funding window and refund timeout have passed and chain evidence
proves there is no unspent output. Late funding must create or revive a recovery
obligation even when the invoice and Boltz attempt are already expired.

### High 8: total database loss is not a tested recovery path

Keys are deterministic, but the derivation indices live only in the PostgreSQL
sequence and are not recorded on swap rows:
`src/db/swaps.rs:85-90` and `migrations/003_swap_key_sequence.sql`.

There is no Bullnym implementation of Boltz xpub restore, no immutable attempt
manifest outside Postgres, and no documented destructive restore drill. A
database rebuild that resets the sequence while reusing the mnemonic can reuse a
claim key and deterministic preimage. Preimage reuse across live atomic swaps
can couple otherwise independent payments.

Boltz supports xpub restore and returns swap metadata, but it does not restore
Bullnym's merchant intent, invoice association, payer recovery destination, or
accounting policy:
https://api.docs.boltz.exchange/swap-restore.html

Required recovery records include key epoch and index, even if private keys move
to a signer. Add global uniqueness constraints for claim public key and preimage
hash across every swap table and environment.

### High 9: chain swaps can be offered while recovery is unavailable

Chain offers are eagerly created for checkout in `src/invoice.rs:668-678`.
Merchant recovery is a separate default-off feature. Background workers can be
disabled while all HTTP routes remain live (`src/main.rs:327-331`). Readiness
checks only database connectivity and schema (`src/readiness.rs:44-69`).

The service can therefore be "ready" and continue issuing fundable instructions
while no claim, watcher, reconciler, or refund executor is running.

Admission readiness must include:

- signer/claim executor quorum;
- recovery watchtower heartbeat;
- source and destination node health;
- chain height agreement;
- fee estimates and fee reserve;
- recovery manifest replication;
- maximum deadline slack;
- backlog age and oldest funded attempt;
- no derivation-index rollback;
- feature-specific recovery path enabled.

Recovery workers must continue when admission is paused. A global feature flag
must stop new attempts, not abandon funded attempts.

### High 10: public chain data is accepted without sufficient verification

The Liquid backend trusts the active Electrum server's scripthash history and
raw transaction response. `get_raw_tx` does not recompute and compare the
returned raw transaction id before caching it. Direct Liquid accounting neither
requires a block nor validates chain headers.

The Bitcoin watcher trusts the first responding mempool-shaped JSON endpoint for
transactions, tip height, and confirmation count. It does not validate raw
transactions, block headers, Merkle proofs, or source quorum.

A malicious or compromised endpoint can make Bullnym tell a POS merchant that a
payment settled when it did not. Failover improves availability but not
integrity; first-success from several services is not quorum.

Preferred order:

1. self-hosted `bitcoind` and `elementsd` as authoritative sources;
2. independently maintained indexes fed by those nodes;
3. external services used for comparison and broadcast diversity;
4. fail closed on disagreement for settlement, while retaining recovery
   rebroadcast paths.

### High 11: fiat-priced intents do not authenticate the satoshi obligation

For a fiat invoice, the merchant signs `fiat_amount_minor` and currency, but
Bullnym later fetches its own rate and computes `amount_sat` in
`src/invoice.rs:728-790`. The merchant has not signed the resolved satoshi
amount, rate source, timestamp, or acceptable slippage.

A compromised server can use an abusive rate and present an excessive Bitcoin
or Lightning amount while still displaying the merchant's intended fiat total.
The payer may notice in a wallet that shows sats clearly, but the protocol does
not let a verifier prove that the conversion was merchant-approved.

For fixed invoices, have the merchant sign the final satoshi obligation after
pricing, plus the fiat reference, rate timestamp, source policy, and expiry. For
dynamic POS/Payment Page amounts, use merchant-signed rate bounds or a
short-lived quote signed by an independent price quorum, and let capable payer
wallets check the rate independently. Outside those bounds, create a new intent
or refuse payment rather than silently repricing.

### Medium 1: webhook idempotency records success before processing success

`src/claimer.rs:207-230` inserts `{swap_id}:{status}` before loading and handling
the swap. A handler error leaves the event permanently deduplicated. Unknown
swap ids are also acknowledged and retained before a just-created swap record
may be committed.

The reconciler repairs some cases, but the correct model is a durable inbox with
`received`, `processing`, `processed`, and `failed` states. A webhook should be
acknowledged after durable enqueue, not after synchronous money movement, and a
failed handler must remain retryable.

### Medium 2: deadline-critical work is unbounded and sequential

The background claimer fetches every ready row without a limit and processes
reverse swaps sequentially before chain swaps. Claim construction performs
blocking Electrum operations and remote MuSig2 calls while a database transaction
and advisory lock are open. The configured production pool has only five
connections.

One degraded endpoint or large backlog can make later, near-timeout swaps miss
their claim window.

Use a durable deadline queue ordered by:

1. blocks remaining to timeout;
2. funded state and preimage exposure;
3. value at risk;
4. age.

Workers need bounded concurrency, independent provider/node semaphores, short DB
transactions, and no network I/O while holding a database transaction.

### Medium 3: merchant purge ignores live chain swaps

`src/db/users.rs:361-373` blocks purge based only on `swap_records`. It does not
check `chain_swap_records`. Recovery authorization later requires the active nym
owner.

A merchant can deactivate and scrub its registration while a chain swap remains
funded, then lose access to the only public recovery action. Purge must be
blocked by every non-final attempt and by any retained recovery obligation.

### Medium 4: signed actions are replayable and signatures are discarded

Merchant invoice and surface requests contain useful signatures over destination
fields, but Bullnym retains only the interpreted mutable values. The signature,
canonical bytes, digest, signer identity, and request id are not preserved as a
payer-verifiable contract.

The timestamp window limits replay to five minutes, but there is no signed nonce
or idempotency key. A captured save or create request can be replayed within that
window, potentially reverting configuration or creating duplicate invoices and
swaps.

Persist the original canonical signed intent and enforce a unique signed request
id. Never reconstruct signed bytes from mutable database columns.

### Medium 5: reverse swap ids are not unique

`swap_records.boltz_swap_id` has a normal index, not a unique constraint, while
chain swaps use a unique value. A provider bug, replay, or malicious response can
associate one webhook id with multiple reverse rows and ambiguous invoice
accounting.

Add uniqueness at the database boundary and reject any duplicate provider id
before exposing a payment instruction.

### Medium 6: the money-critical dependency is a dirty sibling worktree

`Cargo.toml` points `boltz-client` at `../boltz/boltz-rust`. The audited sibling
is on `feature/multi-output-claim` with local modifications. The claim covenant
request field exists, but the local Liquid swap implementation does not parse or
validate the optional covenant leaf.

This build is not reproducible from the Bullnym commit alone. Pin a reviewed
commit or vendored source with a recorded hash, CI provenance, SBOM, and
reproducible release artifact. Treat a swap-library update as a money-protocol
migration, not an ordinary dependency bump.

### Medium 7: cancellation can win before delayed payment evidence

Invoice cancellation changes any `unpaid` row to `cancelled`. Payment event
recording later ignores a cancelled invoice. A payer can pay an already-issued
BOLT11 or on-chain address while a cancellation races the first watcher/webhook.
The merchant may receive funds while Bullnym permanently reports cancellation.

Cancellation must revoke new instruction issuance but continue to account for
late payments to already fundable instructions. Attempt status and invoice
status cannot be collapsed into one row-level flag.

### Medium 8: documentation overstates the current boundary

`docs/architecture.md:9-24` says Bullnym does not custody and is trusted to
create swaps with the correct destination. This describes intended policy, not a
cryptographic boundary. The server holds unilateral spend/refund material during
the swap and can choose a different destination.

Documentation should distinguish:

- merchant wallet custody;
- transient swap authority;
- payer instruction authenticity;
- provider trust;
- chain-data trust;
- recovery authority.

### Medium 9: chain settlement accounting has no terminal-row repair

The settlement repair task in `src/reconciler.rs:99-171` repairs only reverse
swaps that reached `claimed` before invoice event recording failed. There is no
equivalent query and projector for a chain swap that commits `claimed` and then
crashes or errors before `record_invoice_payment` succeeds.

Terminal monetary state and accounting projection must be independently
replayable for every rail. A generic projector should consume immutable claim
facts for reverse swaps, chain swaps, and direct payments instead of relying on
each execution path to finish its own invoice mutation.

## Mandatory protocol invariants

These invariants should become schema constraints, signer policy, executable
checks, metrics, and property tests.

1. No payer funding instruction is exposed before the complete immutable attempt
   manifest is validated and durably replicated.
2. Every payment destination is authenticated by a merchant key that the payer
   anchors independently of Bullnym, not merely read from Bullnym's database.
3. A payer-aware chain swap commits the payer's refund public key before funding.
4. Bullnym's API process never receives a raw claim key, refund key, or preimage
   in the target architecture.
5. The preimage is disclosed only by a transaction that satisfies the immutable
   merchant destination, L-BTC asset, minimum net amount, and fee policy.
6. Both chain-swap hashlocks equal the locally generated preimage hash.
7. Provider status and webhooks are advisory; chain evidence is authoritative.
8. Merchant settlement is true only after the configured confirmation policy
   verifies the exact merchant output.
9. Payer refund is true only after the configured confirmation policy verifies
   the exact payer output.
10. A locally constructed transaction is not evidence that it was broadcast.
11. A broadcast transaction is not evidence that it confirmed.
12. Every funded attempt remains in a recovery queue until chain evidence proves
   a final claim or refund outcome.
13. `attention_required` never removes an attempt from recovery.
14. Only one fundable attempt for an invoice remainder may be active unless the
   UI explicitly presents and accounts for concurrent payments.
15. No replacement attempt is issued while an older instruction can still be
   funded without an independently recoverable outcome.
16. Every raw transaction response is decoded, its txid recomputed, and its
   relevant script, asset, value, and outpoint verified.
17. Actual payer debit, destination lock, merchant net, provider fee, and network
   fee are separate immutable values.
18. Critical destination, amount, key, hash, timeout, and recovery fields are
   append-only. Correcting one creates a new unfunded attempt version.
19. Disabling a rail blocks admission only. It never disables recovery for
   funded attempts.
20. The tuple `(derivation-root fingerprint, key epoch, derivation index)` is
   unique across swap types and disaster restoration. Production, staging, and
   other environments use distinct derivation roots; their numeric indices do
   not need to be globally coordinated.

## Strategy portfolio

No single strategy dominates every product surface. The following are genuinely
different security models, not small variants of one server-side design.

### Strategy A: harden the current coordinator

#### Design

Keep Bullnym responsible for creating and executing swaps, but repair the state
machine and operational foundation:

- complete local validation of every Boltz response;
- merchant-signed immutable PaymentIntent records;
- exact confirmed-outpoint accounting;
- source/destination full nodes;
- durable webhook inbox and operation outbox;
- transaction journal before broadcast;
- confirmation/reorg states and automatic fee bumping;
- deadline-prioritized bounded workers;
- key indices and xpub restore tooling;
- no terminal `claim_stuck` while an outcome remains possible;
- recovery-aware admission and exposure caps;
- encrypted recovery manifests and destructive restore drills.

#### What it prevents

- many provider-response attacks;
- false accounting from mempool/provider reports;
- crashes between database writes and broadcasts;
- indefinite manual recovery caused by transient failures;
- database-loss key reuse;
- worker-disabled issuance and deadline starvation.

#### What it does not prevent

Bullnym still owns every secret and chooses every output. A malicious operator or
full API compromise can still redirect money.

#### Tradeoff

This is the lowest migration cost and is mandatory under every other strategy,
but it is reliability hardening, not a trustless end state.

### Strategy B: policy-constrained claim executor and independent watchtower

#### Design

Split the money authority from the web/API process:

- API stores only public keys, preimage hashes, signed intents, and state;
- a separate claim executor generates or imports claim material;
- the executor independently reads chain data and parses the complete proposed
  Liquid transaction;
- it signs or broadcasts only when output 0 pays the merchant-authenticated
  script, uses L-BTC, meets minimum net value, and respects fee bounds;
- an independently credentialed watchtower observes every lock and rebroadcasts
  canonical transactions;
- the API cannot ask the executor to export a raw preimage or private key;
- operator break-glass can pause admission and rebroadcast an approved
  transaction, but cannot change destinations.

The strongest implementation is a 2-of-3 threshold signer or policy quorum in
independent administrative domains. A single sidecar run by the same root user
is only process isolation.

#### What it prevents

- an API or database compromise alone cannot redirect a claim;
- ordinary operator mistakes cannot edit money-critical outputs;
- a web outage does not stop independent recovery;
- plaintext swap secrets disappear from the general application database.

#### Residual trust

- a single non-threshold policy service can be malicious;
- signer software must correctly parse Liquid confidential transactions;
- colluding threshold operators can redirect;
- if the executor receives a full preimage, it must not leak it to Boltz outside
  a valid claim.

#### Tradeoff

This preserves generic payer compatibility and offline merchant UX better than
client-owned swaps, but it introduces a security-critical signer service. A
normal HSM is not sufficient unless it can validate the whole transaction
policy; generic secp256k1 signing APIs will happily sign a redirected output.

### Strategy C: reverse claim covenants plus permissionless claim watchers

#### Design

For Liquid reverse swaps, request `claimCovenant: true` and bind the covenant
leaf to:

- the merchant-authenticated output script;
- the L-BTC asset;
- the exact expected output amount;
- the swap preimage hash.

Register the validated covenant with multiple independently run `covclaim`
watchers. They can broadcast the script-path claim after observing the lockup.
The claim key no longer needs to be online for that recovery path.

Boltz documents that the covenant leaf enforces output script, asset, and value:
https://api.docs.boltz.exchange/claim-covenants.html

#### Critical conditions

- The recipient client or an independent merchant agent must validate the
  covenant tree before the payer sees the BOLT11.
- The validated BOLT11, or a digest that binds it to the merchant intent, must
  reach the payer from the merchant device or an independently verified signed
  channel. Otherwise Bullnym can ignore the valid swap and display an unrelated
  invoice that pays Bullnym.
- Bullnym must not retain an unconstrained keypath/ordinary-script authority that
  defeats the intended policy.
- The preimage must not be exportable by ordinary Bullnym code.
- A watcher with the full preimage can collude with the Lightning node by leaking
  it without claiming. Use merchant-held preimages, a policy executor, or a
  threshold release process.
- The local `boltz-rust` branch currently has only the request field; it does not
  provide complete covenant-leaf validation or a covenant claim implementation.
  Use and audit the reference `covclaim` flow or add complete library support.

#### Surface fit

This is strongest for an on-demand merchant-created invoice or POS transaction
where the merchant device can validate the covenant before display.

Boltz explicitly warns that spontaneous offline LNURL/Lightning Address
covenants are not trust-minimized when the recipient cannot validate the setup.
Pre-signed merchant address commitments and independent witnesses can improve
that model, but a generic LNURL payer still cannot prove the server used them.

#### Tradeoff

- loses Liquid Confidential Transactions privacy because covenant outputs need
  explicit asset/value data;
- applies to reverse swaps, not the documented chain-swap target side;
- adds watcher operations and covenant-specific audit work;
- gives excellent destination enforcement when correctly validated.

### Strategy D: merchant-sovereign claim agent plus payer-owned refund key

#### Design

Use the existing atomic-swap shape but split client roles correctly:

- merchant wallet or merchant recovery agent generates the claim key and
  preimage;
- payer wallet generates and retains the Bitcoin refund key;
- Bullnym receives only claim public key, refund public key, and preimage hash;
- both sides independently validate the returned scripts and timeout ordering;
- payer funds only after retaining a complete recovery package;
- merchant agent claims the destination L-BTC, revealing the preimage;
- if no valid destination claim occurs, the payer or payer watchtower refunds
  after timeout.

For automated payer recovery, the payer wallet can construct and sign a timeout
refund after it has built the funding transaction, then replicate that signed
transaction to independent watchtowers before broadcasting the funding
transaction. That refund is bound to the exact funding outpoint. The payer must
either freeze the funding transaction id after replication or create and
replicate a corresponding recovery package for every funding RBF replacement;
replacing the funding transaction otherwise invalidates the old refund. The
refund itself can use a pre-signed RBF fee ladder or a CPFP-able payer output so
future fees do not strand it.

Raw preimage ownership is a remaining collusion edge. A merchant agent that can
export the preimage can hand it to Boltz before publishing the merchant claim,
allowing the payer's BTC to be consumed without the merchant output. A robust
agent independently verifies the destination lock, constructs and broadcasts
the policy-valid merchant claim itself, and never exports the secret. Protecting
the payer against a malicious merchant-agent operator additionally requires an
independent threshold release, a destination covenant, or an adaptor-signature
protocol that binds secret disclosure to the merchant transaction.

#### What it prevents

- Bullnym cannot claim merchant L-BTC because it lacks the claim key/preimage;
- Bullnym cannot redirect the payer refund because it lacks the refund key;
- merchant cannot take the payer refund if only the payer has that key;
- the merchant can claim and the payer can time out/refund without Bullnym after
  both receive and validate the manifest.

#### Availability model

The merchant agent must be available before the destination timeout. Options
include:

- the merchant mobile app while POS is active;
- a merchant-operated always-on agent;
- an independent encrypted recovery service;
- a 2-of-3 threshold agent shared by merchant, Bull Bitcoin, and an independent
  recovery operator;
- a pre-provisioned pool of merchant-signed one-time swap tickets.

#### Tradeoff

This is the strongest straightforward use of current chain-swap primitives, but
it requires an interactive payer wallet. A generic Bitcoin wallet scanning a
BIP21 QR cannot contribute a refund public key or pre-sign a recovery
transaction.

### Strategy E: payer-owned swap, Bullnym as signed-intent relay

#### Design

Move the Boltz client into a Bull-aware payer wallet:

1. Merchant publishes a signed Liquid payment intent.
2. Payer wallet verifies the merchant identity, amount, destination, and expiry.
3. Payer wallet creates and validates its own Boltz reverse or chain swap.
4. Payer wallet holds every claim/refund key and its rescue package.
5. It claims the swap directly to the merchant Liquid address.
6. Bullnym watches the merchant output and reports it, but has no swap secret.

This follows Boltz's published integration model. Boltz states that noncustodial
integrations should run client-side, with end users controlling keys and refund
data:
https://api.docs.boltz.exchange/common-mistakes.html

#### What it prevents

- Bullnym cannot steal swap funds because it never receives swap secrets;
- payer recovery is local and compatible with Boltz rescue tooling;
- Bullnym outage after intent retrieval does not stop claim/refund;
- merchant settlement reduces to a direct Liquid output.

#### Tradeoff

- requires Bull Wallet or another compatible payer wallet;
- generic Lightning and Bitcoin wallets cannot use this trustless path;
- browser-based swaps recreate recovery-file and malicious-JavaScript problems;
- a payer can intentionally redirect its own swap, but that simply means the
  merchant is not paid and must not deliver goods.

This should be a first-class "verified payment" mode rather than blocked on
universal wallet adoption.

### Strategy F: direct receipt first, merchant conversion second

#### Design

Remove Bullnym from the atomic path:

- direct Bitcoin goes to a merchant Bitcoin wallet named in a signed intent;
- direct Liquid goes to the merchant Liquid wallet named in that intent;
- Lightning goes to a merchant-controlled Lightning node or async receive
  service bound to that intent;
- the payer verifies the merchant signature and destination in independently
  distributed wallet code, or accepts Bullnym as an instruction-authenticity
  trust assumption;
- the merchant wallet batches or schedules its own BTC/LN-to-LBTC conversion
  after receipt.

Bullnym remains an invoice, discovery, and observation service. The conversion
is a merchant wallet operation with merchant-held recovery material.

#### What it prevents

- payer payment is never held by a Bullnym swap key;
- when the payer verifies the signed intent, Bullnym cannot substitute the
  direct destination;
- Bullnym cannot atomically redirect the source and destination swap legs;
- recovery uses the merchant's normal wallet backup and the payer's normal send
  semantics;
- conversion failures cannot retroactively steal the payer's completed payment.

#### Tradeoff

- merchant briefly receives the payer's source rail rather than immediate L-BTC;
- requires Bitcoin and/or Lightning wallet capability and liquidity management;
- batching changes fee and timing semantics;
- a generic wallet that does not verify the merchant-signed intent still trusts
  Bullnym not to replace the address or Lightning invoice;
- a Lightning LSP or async-receive system introduces its own availability and
  privacy assumptions.

This is the simplest strong architecture if "eventual automatic L-BTC" is
acceptable instead of "the payer's transaction itself atomically yields L-BTC."

### Strategy G: proof-carrying, mostly stateless Bullnym

#### Design

Treat Bullnym as an untrusted relay and cache:

- merchant signs a canonical PaymentIntent;
- intent contains or commits to amount policy, rail destinations, expiry,
  merchant key, and recovery policy;
- merchant pre-signs a Merkle root of one-time Liquid address commitments or
  one-time swap tickets;
- Bullnym returns a leaf plus inclusion proof without learning merchant spend
  keys;
- payer wallet verifies the merchant signature and inclusion proof;
- swap execution occurs in payer/merchant agents or a threshold federation;
- attempt hashes are published to an append-only transparency log and witnessed
  through independent Nostr relays;
- merchant and payer retain self-contained recovery capsules.

#### What it prevents

- Bullnym cannot substitute an address without invalidating the signature/proof;
- database mutation is detectable;
- independent witnesses can detect equivocation between payers;
- Bullnym can be rebuilt from signed manifests and chain facts.

#### Tradeoff

- highest protocol and client complexity;
- requires an independently anchored merchant public key;
- transparency detects but does not itself prevent theft unless the payer
  verifies before funding;
- pre-signed inventory and offline lifecycle management are nontrivial.

This is the clean long-term direction if Bullnym is intended to become a
protocol rather than a trusted hosted payment service.

## Comparative strategy matrix

| Strategy | Bullnym swap-spend authority | Bullnym instruction-substitution ability | Payer recovery autonomy | Generic wallet compatibility | Complexity | Best use |
|---|---|---|---|---|---|---|
| A. Harden coordinator | Yes | Yes; signatures are ineffective unless the payer verifies them independently | No material change | High | Medium | Mandatory baseline and short-term risk reduction |
| B. Policy executor/watchtower | No, if independently controlled and policy-complete | Yes, unless the instruction carries an independently verified policy attestation | Chain remains weak unless the payer key changes | High | High | Hosted generic-wallet compatibility with disclosed instruction trust |
| C. Reverse covenants | No through the validated covenant path; preimage leakage remains a concern | Yes, unless the merchant displays it directly or the payer verifies a signed binding | Lightning refund is automatic only if the secret is not leaked | High payer UX; recipient validation needed | High | POS and on-demand invoice reverse swaps |
| D. Merchant claim + payer refund key | No after both clients validate the contract | No; independent clients reject changed keys, scripts, or destinations | Strong | Low to medium | High | Bull-aware chain swaps and POS |
| E. Payer-owned swap | No | No; payer wallet verifies the merchant intent | Strongest | Low | Medium in server, high in wallet | Bull Wallet verified-payment mode |
| F. Direct receipt, convert later | No incoming-swap authority | Yes for an unmodified generic wallet; no when the wallet verifies the merchant signature | Normal wallet semantics after a verified destination | High for trusted-server mode; lower for verified mode | Medium | Lowest swap risk when eventual conversion is acceptable |
| G. Proof-carrying stateless relay | No when clients verify | No when clients verify | Strong, determined by endpoint agents | Low initially | Very high | Long-term protocol architecture |

## Product-surface recommendations

### POS

The merchant device is present, so use that fact.

Recommended order:

1. POS device signs the exact amount, destination, expiry, and rail policy.
2. For Lightning, the device or merchant agent creates and validates a covenant
   reverse swap before the QR appears.
3. For Bull-aware Bitcoin, payer supplies a refund public key and validates the
   chain swap.
4. For generic Bitcoin, use direct merchant BTC or clearly disclose trusted
   merchant recovery.
5. POS marks fulfillment-ready only from wallet/node-confirmed merchant output,
   not Bullnym status alone.

This surface can achieve the strongest model with the least UX penalty.

### Merchant-created invoices

The mobile client already signs amount and address fields, but the current wire
payload is not a safe public contract. It also includes
`liquid_blinding_key_hex`, recipient metadata, and invoice metadata, and it is
signed by the server-auth `npub`, which may differ from the merchant's public
`verification_npub` (`src/invoice.rs:1893-1924` and
`docs/components/auth-identity.md:8-13`). Returning it unchanged would leak
Liquid viewing capability and potentially private business data.

Recommended order:

1. Add a separate canonical `PaymentIntentV1` containing only payer-visible
   commercial terms, rail commitments, expiry, and a signed request id.
2. Sign it with the independently anchored public merchant key, or include a
   cross-certificate from that key to a dedicated payment-intent key.
3. Keep blinding/viewing secrets, private notes, and internal invoice metadata
   outside the public intent.
4. Return intent, merchant signature, signer identity proof, and intent digest
   from the public invoice endpoint.
5. Let Bull Wallet verify it against a key learned through prior pairing,
   merchant-device QR, or independent identity history, never only from that
   endpoint response.
6. Let the merchant wallet create/validate reverse swaps or pre-provision a
   merchant claim agent.
7. Keep direct BTC and Liquid as simple verified destinations.

### Payment Page and Donation Page

The payer chooses an amount while the merchant may be offline. This is harder.

Recommended order:

1. Merchant pre-signs a surface manifest and address-commitment root.
2. Bullnym allocates a one-time leaf and provides its inclusion proof.
3. A threshold policy executor handles reverse swaps and independent watchers.
4. Bull-aware payers verify the manifest and run their own swap.
5. Do not expose generic BTC-to-LBTC chain swaps without payer-owned recovery.
6. Consider direct BTC settlement plus later merchant conversion for generic
   Bitcoin wallets.

### Lightning Address

Lightning Address is an offline recipient protocol. A payer asks Bullnym for a
fresh invoice while the merchant client is normally absent.

There are four honest choices:

- retain Bullnym trust, harden it, and disclose that trust;
- use multiple independent policy/covenant servers and require a quorum;
- pre-provision merchant-signed swap tickets and add verification to capable
  payer wallets;
- receive Lightning into a merchant-controlled async Lightning service and
  convert later.

Claim covenants alone do not make an offline Lightning Address trustless. Boltz
explicitly warns against claiming that model because the offline recipient
cannot validate the covenant setup before payment.

### Direct Liquid and LUD-22

These are the easiest rails to trust-minimize:

- merchant signs the concrete address or a commitment leaf;
- payer wallet verifies the signature independently;
- Bullnym uses a self-hosted Elements node to observe exact asset/value;
- confirmation state is explicit and reorg-aware;
- merchant wallet independently observes receipt.

For privacy, avoid publishing the full descriptor to every payer. A Merkle root
of one-time address commitments lets the payer verify ownership authorization
without revealing the entire receive descriptor and wallet history.

## Recommended target architecture

```text
Merchant wallet / merchant recovery agent
  |  signs PaymentIntent + address/swap commitment
  |  owns claim material or threshold share
  v
Independent intent log / Nostr witnesses
  ^
  | intent hash + checkpoints
  |
Bullnym API and payer pages
  |  public data, no raw swap secrets
  |  durable attempt commands/events
  v
Postgres (public state) ---- WORM encrypted manifests
  |
  +----> Policy signer quorum / claim executor
  |        | verifies merchant intent + full transaction
  |        | never exports keys/preimages
  |        v
  |      Liquid nodes + diverse broadcasters
  |
  +----> Independent claim/refund watchtowers
  |        | no ability to change committed outputs
  |        v
  |      Bitcoin and Liquid full nodes
  |
  +----> Accounting projector
           | consumes confirmed canonical chain facts
           v
         Invoice/payment status

Payer wallet (verified mode)
  | verifies merchant intent
  | owns chain refund key or entire sender-side swap
  +----> Bitcoin / Lightning / Liquid
```

### Component boundaries

#### API/coordinator

May:

- validate public request shape;
- store signed intents and public swap fields;
- enqueue commands;
- serve payment instructions with proofs;
- report chain-derived state.

Must not:

- read or export raw preimages/private swap keys;
- choose an output not committed by a merchant/payer signature;
- mark settlement from provider status;
- disable recovery when admission is paused.

#### Policy signer/claim executor

Must independently verify:

- intent signature and immutable digest;
- network and asset;
- source/destination scripts and hashlocks;
- exact output script and minimum amount;
- fee and extra-output policy;
- timeout margin and current chain height;
- destination lock confirmation policy;
- absence of a conflicting confirmed spend.

It should broadcast directly and return only transaction id and attested policy
result, not raw signatures or secrets that the coordinator can repurpose.

#### Watchtowers

Run under different credentials, provider, region, and preferably operator.
They consume manifests and chain facts, not mutable API instructions. At least
one recovery path should remain executable when Bullnym's API and primary
database are unavailable.

#### Accounting projector

Treats immutable facts as inputs. It should be possible to rebuild all invoice
status from manifests plus verified chain data. Provider/webhook states are
operational hints, not money evidence.

## Automated recovery procedures

### Reverse Lightning swap

#### Before exposing BOLT11

1. Validate merchant intent and destination commitment.
2. Generate claim key/preimage outside the API process.
3. Persist key epoch/index or public recovery reference.
4. Fetch pair data, enforce limits/fee cap, and pin pair hash.
5. Create the reverse swap.
6. Decode and verify BOLT11 hash, amount, description, network, expiry, and
   signature.
7. Parse and verify the exact swap tree, hashlock, keys, address, timeout, asset,
   and on-chain amount.
8. For covenant mode, validate the covenant leaf's output script, L-BTC asset,
   and amount.
9. Replicate the immutable manifest to two independent stores/watchers.
10. Expose the BOLT11 only after every recovery actor reports ready.

#### After payer payment

1. Observe the Liquid lock through independent nodes.
2. Verify outpoint, L-BTC asset, value, script, confirmations, and timeout slack.
3. In strict mode, build a script/covenant claim so the preimage first appears in
   the signed transaction.
4. Persist transaction hex and txid before broadcast.
5. Broadcast through multiple channels.
6. Continue rebroadcast/fee management until confirmed.
7. Record actual merchant output amount and vout.
8. Mark fulfillment-ready only at the configured confirmation depth.
9. If no preimage was disclosed and no valid claim occurs, verify that the
   Lightning HTLC cancels back to the payer.
10. If the source settles without confirmed merchant output, declare a severity
    zero invariant breach and trigger compensation policy.

### BTC-to-LBTC chain swap with payer-aware wallet

#### Before funding

1. Merchant agent supplies claim public key and preimage hash.
2. Payer wallet supplies refund public key.
3. Create the chain swap with both public keys.
4. Both clients independently verify hashlocks, scripts, amounts, assets,
   addresses, and timeout ordering.
5. Payer constructs the Bitcoin funding transaction.
6. Payer constructs and signs a timeout refund to its own address.
7. Payer stores the refund key and replicates a signed recovery transaction or
   fee ladder to independent watchtowers.
8. Only then does the payer broadcast funding.

#### Success

1. Confirm payer Bitcoin funding per policy.
2. Confirm Boltz Liquid destination lock per policy.
3. Merchant agent claims to the signed merchant destination.
4. Confirm exact merchant L-BTC output.
5. Observe Boltz source claim and preimage consistency.
6. Finalize accounting from actual outputs.

#### Failure

1. If destination lock never appears, do not reveal the preimage.
2. Attempt cooperative refund without making it mandatory.
3. At timeout, payer or independent watchtower broadcasts the pre-signed refund.
4. Fee bump through the pre-agreed ladder/anchor policy.
5. Confirm exact payer output.
6. Retain recovery material until deep finality and retention expiry.

### Legacy generic Bitcoin chain swap

With no payer refund key, Bullnym cannot deliver a trustless payer refund. Until
that flow is removed or upgraded:

1. label it as merchant/Bullnym-trusted recovery;
2. commit the merchant-selected recovery policy before funding;
3. preserve a payer-visible receipt identifying the recovery obligation;
4. run automatic provider-independent lockup discovery;
5. never depend on the merchant manually noticing a row;
6. maintain a compensation reserve for server/merchant recovery failures;
7. cap per-payment and aggregate value at risk;
8. do not call it noncustodial payer recovery.

## Data and state redesign

### Immutable attempt manifest

Persist at least:

- attempt UUID and version;
- product surface and invoice id;
- public merchant-signed PaymentIntent bytes, signature, independently anchored
  signer proof, schema version, and digest;
- fiat reference, resolved satoshi obligation, quote/rate policy, source,
  timestamp, bounds, and expiry when pricing is involved;
- payer refund public key/address or explicit declaration that none exists;
- provider, pair hash, quoted limits, fees, and quote timestamp;
- approved payer debit and merchant net target;
- preimage hash, claim public key, refund public key;
- signer key epoch and derivation indices;
- both exact trees, scripts, reconstructed addresses, and timeout heights;
- provider response hash and validated response snapshot;
- covenant policy, if any;
- source and destination chain/network;
- encrypted/scoped Liquid output-verification capability or retained output
  unblinding secrets, stored separately from the public intent;
- recovery actors and readiness attestations;
- manifest replication receipts.

### Immutable chain facts

Persist as append-only observations:

- funding outpoint and raw transaction hash;
- source lock confirmation/reorg events;
- destination lock outpoint, asset, and unblinded amount;
- claim/refund transaction versions and broadcast receipts;
- mempool, confirmation, replacement, eviction, and reorg events;
- outspend script, asset, amount, vout, block hash, and confirmations;
- preimage disclosure evidence;
- provider status as a separately labeled advisory fact.

### Derived attempt states

Avoid a single mutable status enum as the source of truth. Project states such
as:

- `prepared`;
- `fundable`;
- `source_seen`;
- `source_confirmed`;
- `destination_seen`;
- `destination_confirmed`;
- `claim_constructed`;
- `claim_broadcast`;
- `merchant_confirmed`;
- `refund_eligible`;
- `refund_broadcast`;
- `payer_refund_confirmed`;
- `attention_required`;
- `finalized`.

An attempt may have `attention_required` alongside any non-final monetary state.

### Accounting separation

Replace one ambiguous amount with explicit fields:

- `invoice_target_sat`;
- `payer_instruction_sat`;
- `payer_paid_sat`;
- `provider_fee_sat`;
- `source_network_fee_sat`;
- `destination_lock_sat`;
- `destination_claim_fee_sat`;
- `merchant_output_sat`;
- `payer_refund_sat`.

Invoice `payment_status` answers whether the payer satisfied the commercial
obligation. Attempt `settlement_status` answers what happened on each rail.
Merchant wallet receipt answers whether spendable funds arrived. These are not
the same boolean.

Payment events are append-only, require non-null source-specific evidence, and
are written by a narrow projector role. The API has no update/delete privilege
on the event ledger. Invoice and attempt status tables are disposable
projections that can be rebuilt from manifests and verified facts.

## Key and secret policy

### Immediate policy

- Remove raw preimages and private keys from routine logs, admin tools, support
  exports, and general database queries.
- Encrypt existing secret columns with a key unavailable to read-only DB
  operators.
- Give claim workers a narrower database role than the API.
- Record derivation-root fingerprint, key epoch, and index; enforce uniqueness
  of that tuple and of all derived public keys/preimage hashes.
- Separate production/staging derivation roots.
- Back up the rescue key offline under dual control.
- Do not rotate/delete a key epoch while any related attempt is non-final.

These controls reduce accidental exposure but do not make the server unable to
steal.

### Target policy

- API has no master swap seed.
- Claim/refund keys are generated by merchant/payer clients or threshold DKG.
- A policy executor never exports full private keys or preimages.
- Recovery shares live in independent administrative domains.
- Every use produces an auditable attestation tied to an immutable intent
  digest and transaction id.
- Signer quorum cannot authorize arbitrary messages; it understands the Bullnym
  transaction policy.

## Operational policies and procedures

### Admission gate

Do not issue a fundable instruction unless all are true:

- signed merchant intent verified;
- merchant signer anchored independently and the public intent contains no
  blinding/viewing secret or private metadata;
- final satoshi obligation or signed fiat rate bounds verified;
- provider response fully verified;
- exact fee/amount policy accepted;
- merchant output can be independently unblinded/verified without exposing its
  view key to the payer;
- timeout slack above minimum;
- signer and recovery quorum healthy;
- manifest replicated;
- authoritative nodes synced and agreeing;
- claim/refund fee reserve funded;
- no conflicting fundable attempt;
- value-at-risk caps available;
- recovery feature for that rail enabled;
- oldest funded backlog below SLO.

### Deployment

- Stop new admission before changing money-path code.
- Keep old recovery workers and signer versions running for old attempts.
- Support SIGTERM and drain HTTP commands into a durable queue.
- Never terminate a signer between preimage disclosure and transaction
  persistence/broadcast.
- Canary with low-value mainnet success and every refund path.
- Roll back admission code independently from recovery code.
- A rollback never deletes manifests, keys, old binaries, or watchtowers needed
  by live attempts.

### Incident classes

Severity zero:

- payer source settled while no valid merchant claim is confirmed;
- claim/refund output differs from immutable intent;
- unexpected preimage access or disclosure;
- reused preimage hash or claim/refund key;
- chain outspend by an unknown transaction;
- provider response passes API parsing but fails independent policy validation.

Response:

1. halt new admission only;
2. keep and scale recovery workers;
3. preserve all logs, manifests, memory-access audit, and chain facts;
4. reconcile every active attempt from both chains;
5. notify merchant and payer with verified facts;
6. trigger automatic compensation for a proven source-settled/merchant-unpaid
   invariant breach;
7. require two-person approval and root-cause review before unpausing.

### Economic backstop

Cryptography cannot reverse a chain halt, catastrophic software bug, or a secret
already disclosed to the wrong party. Maintain a capped compensation reserve or
insurance policy for the invariant:

`payer source irreversibly claimed AND merchant output not confirmed`.

This is not a substitute for trust minimization. It is the final reliability
layer for residual failure, and it should be sized to enforced exposure caps.

## Verification and test program

### Protocol tests

- malicious reverse response with wrong BOLT11 payment hash;
- wrong BOLT11 amount, description, network, expiry, or fee;
- wrong reverse script hashlock with a correct invoice hash;
- chain trees with different hashlocks;
- chain tree using a Boltz-known hashlock;
- wrong client/server keys, timeout, asset, amount, address, or BIP21;
- fiat intent with an unsigned/excessive resolved satoshi amount or stale rate;
- renegotiation quote below merchant minimum, above fee cap, or inconsistent
  with the independently observed payer outpoint;
- renegotiated amount claim using an updated response revision;
- crash/timeout after quote acceptance but before local commit;
- LN-only reverse destination without an available output-verification
  capability;
- insertion of a payment event with null source or missing source-specific
  evidence;
- policy signer rejection of every destination/amount/fee mutation;
- covenant leaf mutation and missing-covenant fallback;
- duplicate provider swap id and duplicate preimage/key.

### Crash tests

Kill the process:

- before provider creation;
- after provider creation but before manifest commit;
- after webhook enqueue but before handling;
- during cooperative signature exchange;
- after preimage disclosure;
- after transaction construction but before persistence;
- after persistence but before broadcast;
- after accepted broadcast but before state update;
- after mempool observation but before confirmation;
- during fee replacement;
- during refund broadcast;
- during database failover.

Every funded case must reconstruct to claim or refund from independent state.

### Chain tests

- mempool eviction;
- RBF/conflicting outspend;
- one- and multi-block reorgs;
- stale/malicious Electrum history;
- raw transaction whose bytes do not match requested txid;
- false Bitcoin address API confirmation;
- provider API down while unilateral recovery runs;
- source/destination nodes disagree;
- fee spike above every initial estimate;
- chain halt longer than the current retry budget;
- late funding after invoice/provider expiry;
- more than one output funds a lockup address.

### Disaster recovery tests

- restore from an empty Postgres database;
- restore with only rescue key, WORM manifests, and full nodes;
- reconcile against Boltz xpub restore without trusting it as sole truth;
- verify sequence/index cannot roll backward;
- restore with primary Bullnym API and provider API unavailable;
- merchant recovers claim capability without Bullnym;
- payer recovers chain refund capability without Bullnym;
- quarterly production-like drill with signed evidence and measured RTO/RPO.

### Property tests

For every generated state/event sequence:

- no state marks merchant confirmed without matching confirmed output evidence;
- no state marks payer refunded without matching confirmed refund evidence;
- every non-final funded state remains scheduled for recovery;
- destination/amount/key/hash fields never mutate in place;
- no source claim is authorized before a policy-valid destination claim exists;
- no second fundable attempt exists for the same remainder without explicit
  concurrency policy;
- reordering or duplicating webhooks cannot regress chain-derived state;
- cancellation cannot erase a late payment fact.

## Recommended staged program

### Phase 0: stop-ship controls

Before expanding usage:

1. Disable new BTC-to-LBTC checkout offers unless payer recovery is deliberately
   accepted as merchant-trusted and the recovery route is enabled/tested.
2. Call and extend reverse response validation before returning any BOLT11.
3. Add explicit chain hashlock validation against the local preimage.
4. Build BIP21 locally from validated fields.
5. Stop calling broadcast-only claims/refunds confirmed or settled.
6. Remove terminal retry exhaustion for funded attempts.
7. Make readiness fail for money admission when workers/recovery are absent.
8. Pin the Boltz dependency to a reviewed reproducible commit.
9. Default under/overfunded chain swaps to refund; disable automatic quote
   acceptance until minimum merchant output, maximum fee, independent funding
   observation, and durable acceptance are enforced.

### Phase 1: reliable current coordinator

1. Introduce immutable attempt manifests and operation inbox/outbox.
2. Add exact source/destination outpoint observations and confirmation states.
3. Add dynamic fee estimation, RBF/replacement tracking, and rebroadcast.
4. Add source/destination full nodes and disagreement handling.
5. Fix renegotiated response versioning and chain settlement repair.
6. Require non-null evidence and move payment events behind an append-only
   projector role.
7. Provision scoped Liquid output-verification data for every swap destination.
8. Store derivation root/epoch/index and implement xpub/chain restoration.
9. Move network work outside database transactions and prioritize deadlines.
10. Run crash, reorg, provider-failure, and empty-database drills.

Phase 1 materially improves reliability but still trusts Bullnym with money.

### Phase 2: authenticated payment contracts

1. Define a public canonical `PaymentIntentV1` distinct from the private API
   request and exclude viewing keys/private metadata.
2. Add merchant-key anchoring or cross-certification, signatures, and signed
   request ids.
3. Bind final satoshi amounts or explicit fiat-rate bounds into the intent.
4. Add payer-wallet verification in Bull Wallet.
5. Add one-time address commitment roots for offline surfaces.
6. Publish intent/attempt digests to independent Nostr witnesses.
7. Make POS fulfillment depend on merchant wallet/node evidence.

### Phase 3: remove API secret authority

1. Deploy a policy-constrained claim executor with separate credentials.
2. Remove `SWAP_MNEMONIC` and plaintext swap secrets from the API/database.
3. Deploy independent claim/refund watchtowers.
4. Prefer strict script-path claims until a safer cooperative protocol exists.
5. Pilot 2-of-3 threshold policy for high-value attempts.

### Phase 4: surface-specific trustless modes

1. POS/on-demand invoice reverse covenant pilot validated by merchant client.
2. Bull-aware payer chain swap with payer-owned refund key and pre-signed refund.
3. Sender-side Boltz swap in Bull Wallet.
4. Direct-receipt/merchant-conversion mode for generic wallets.
5. Decide whether generic Payment Page chain swaps remain as a disclosed trusted
   mode or are removed.

### Phase 5: protocol architecture

1. Proof-carrying, mostly stateless Bullnym relay.
2. Threshold/federated offline Lightning Address service.
3. Boltz protocol proposal for destination covenants on chain-swap Liquid claims.
4. Adaptor-signature cooperative claim protocol that does not disclose the
   preimage before the merchant transaction is publishable.

## Decisions that require product ownership

1. Must the merchant receive the exact invoice amount, or may provider and claim
   fees reduce merchant net?
2. Is 0-conf Liquid ever fulfillment-ready, and what value cap/insurance applies?
3. Is generic Bitcoin-to-LBTC worth retaining if the payer cannot own recovery?
4. Can "eventual automatic L-BTC" replace atomic conversion for generic wallets?
5. Is covenant privacy loss acceptable for stronger destination enforcement?
6. Which independent entity can operate the third threshold signer/watchtower?
7. Which payer wallets must support signed PaymentIntent verification?
8. Is Lightning Address allowed to remain a disclosed federated-trust product
   while invoices and POS become strongly trust-minimized?
9. What finality depth is required for POS, invoice settlement, payer refund, and
   accounting finalization?
10. What aggregate value at risk can the compensation reserve cover?
11. Which independently anchored merchant identity signs PaymentIntent, and how
   do existing merchants cross-certify it?
12. May an under/overfunded chain payment ever be auto-renegotiated, and what
   signed minimum merchant output and maximum fee apply?
13. Which independent accounting actors may receive scoped Liquid viewing data,
   and what privacy/retention policy governs it?

## Recommended decision

Adopt a dual-track architecture instead of searching for one compromise that is
both generic and trustless:

- **Compatible mode:** hardened coordinator, policy signer federation,
  independent nodes/watchtowers, explicit risk caps, and compensation. This
  supports generic wallets but retains disclosed federation trust.
- **Verified mode:** merchant-signed intent plus payer-owned or merchant-owned
  swap execution in Bull Wallet/merchant agent. Bullnym has no spend/refund
  secrets. This is the preferred security mode.

For chain swaps, do not claim payer protection until the payer supplies the
refund key or runs the swap. For reverse swaps, use script-path or validated
covenant claims so the preimage is not handed to Boltz before a destination-
constrained merchant transaction is ready. For every rail, derive settlement
from confirmed exact outputs, not from Bullnym's own status or a provider's
webhook.

That combination gives Bullnym a credible path from "merchant-wallet
noncustodial" to a payment system in which compromising the ordinary server is
not enough to steal either side's funds.

## Primary sources

- Boltz, Don't trust. Verify: https://api.docs.boltz.exchange/dont-trust-verify.html
- Boltz, Claims and Refunds: https://api.docs.boltz.exchange/claiming-swaps.html
- Boltz, Swap Restore: https://api.docs.boltz.exchange/swap-restore.html
- Boltz, Claim Covenants: https://api.docs.boltz.exchange/claim-covenants.html
- Boltz, Common Mistakes: https://api.docs.boltz.exchange/common-mistakes.html
- Boltz, Swap Lifecycle: https://api.docs.boltz.exchange/lifecycle.html
- Boltz, 0-conf risks: https://api.docs.boltz.exchange/0-conf.html
- Bullnym architecture: `docs/architecture.md`
- Bullnym payment semantics: `docs/payment-architecture.md`
- Bullnym owner/public identity split: `docs/components/auth-identity.md`
- Bullnym swap creation: `src/boltz.rs`
- Bullnym swap execution/recovery: `src/claimer.rs`
- Bullnym invoice/payment instructions: `src/invoice.rs`
- Bullnym direct Liquid watcher: `src/chain_watcher.rs`
- Bullnym direct Bitcoin watcher: `src/bitcoin_watcher.rs`
- Bullnym reverse state: `src/db/swaps.rs`
- Bullnym chain state: `src/db/chain_swaps.rs`
- Bullnym payment evidence constraints:
  `migrations/028_invoice_payment_event_evidence.sql`
- Vendored Boltz validation: `../boltz/boltz-rust/src/swaps/boltz.rs`
- Vendored transaction construction: `../boltz/boltz-rust/src/swaps/wrappers.rs`
- Vendored Liquid MuSig/claim construction: `../boltz/boltz-rust/src/swaps/liquid.rs`

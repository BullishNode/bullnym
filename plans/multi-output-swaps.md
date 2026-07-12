# Plan: multiple outputs on swap transactions (L-BTC and BTC)

Status: LIBRARY DONE (2026-07-11) — M0-M3 shipped as
https://github.com/SatoshiPortal/boltz-rust/pull/162 (branch
`feat/multi-output-claims` on the OFFICIAL repo, fresh implementation off
trunk, NOT the fork stash). Final API differs from the sketch below:
`additional_outputs: Vec<(Address, u64)>` + `with_additional_outputs`
builder on both SwapTx structs (primary address = implicit Remainder at
index 0), and `TransactionOptions::with_additional_outputs(Vec<(String,u64)>)`
in the wrappers (non-breaking). Claim AND refund, both chains. 45 lib tests
green incl. `verify_tx_amt_proofs` full-CT verification of a 4-output claim.
Local worktree: `~/bull-bitcoin-workspace/boltz/boltz-rust-multiout`.
Remaining: M4-M6 (bullnym integration, accounting, battle tests) — blocked on
PR #162 merge + the §0 product decision.

Companion research: `plans/two-output-claim-research.md`
(protocol verification: Boltz cooperatively signs the client-built tx WITHOUT
inspecting outputs; script path needs no cooperation; no destination is
pre-committed at swap creation — multi-output is purely client-side).

## 0. Scope and use cases

Add N-output support to the swap transactions **we** construct:

| Tx | Chain | Today | Multi-output use case |
|---|---|---|---|
| Reverse-swap claim (LN→L-BTC) | Liquid | 1 payment out + fee out | split settlement / service fee |
| Chain-swap claim (BTC→L-BTC) | Liquid | 1 payment out + fee out | split settlement / service fee |
| Chain-swap refund (merchant recovery) | Bitcoin | 1 out, implicit fee | split recovery destinations |
| (future) L-BTC→BTC claim | Bitcoin | 1 out, implicit fee | same |

Out of scope: Boltz-side lockup outputs (Boltz constructs those), submarine
swaps (we don't build their claim), changing the number of *inputs*.

**Open product decision (blocks M4, not M1-M3):** what the extra output is
*for* — fixed service fee, percentage split, or per-invoice split spec. The
library API below supports all three; bullnym's destination policy and
accounting depend on the answer.

## 1. Unified library API (design)

One destination model for both chains, replacing the single
`output_address: String`:

```rust
pub enum DestAmount { Fixed(u64), Remainder }   // exactly one Remainder required
pub struct SwapDestination { pub address: String, pub amount: DestAmount }
```

- **Remainder absorbs `input − fee − Σfixed`.** This fixes the fatal flaw in
  the stashed prototype: its strict `Σoutputs + fee == input` check breaks
  `create_tx_with_fee`'s trial-fee sizing pass (trial fee=1 never matches
  pre-computed amounts). With Remainder, both the trial and final builds
  balance by construction.
- Validation: ≥1 destination; exactly one `Remainder`; every fixed amount >
  dust (546 sat BTC / Liquid dust equivalent); remainder > dust after fee.
- Backward compat: `output_address: String` keeps working as
  `vec![SwapDestination { address, amount: Remainder }]`.

## 1.5 Prior art: how Boltz's own implementations do it (checked 2026-07-11)

**Go `boltz-client` — `ConstructTransaction` (`pkg/boltz/liquid.go`) already
builds multi-output blinded L-BTC claim txs.** Each claimed swap
(`OutputDetails`) carries its own destination `Address`; the builder
aggregates values per distinct address (`outValues` map) and emits **one
blinded payment TxOut per address**, each with its own `BlinderIndex`,
blinded generically by `go-elements/psetv2` + `zkpGenerator.BlindOutputs`.
This is the "hidden function": N blinded outputs in one claim tx.
Caveat: it's keyed per-INPUT (batch of swaps, each to its own address) — a
SINGLE swap still resolves to one address. Splitting one swap's value still
needs our `SwapDestination` API, but the CT machinery for N outputs is proven
in production there.

**TypeScript `boltz-core` (`lib/liquid/swap/Claim.ts`)** — batches N inputs
to ONE `destinationScript`, so no multi-output either; but it's built on
liquidjs-lib PSET (`Updater.addOutputs([...])` + `Blinder.blindLast`), where
N blinded outputs are native — extending it would be a few lines.

**Two lessons adopted from prior art:**
1. Both official clients delegate blinding to generic **PSET machinery**
   (psetv2 / liquidjs-lib Pset) instead of hand-rolling ABF/VBF/rangeproofs
   the way boltz-rust does. For M1 we have two routes:
   - (a) extend boltz-rust's hand-rolled blinding (the stash proves it works,
     smaller diff, no new deps) — **default**;
   - (b) rebuild the claim builder on `rust-elements` PSET blinding (mirrors
     Boltz's own clients, N outputs generic, and LWK in this workspace uses
     the same machinery) — bigger refactor, better long-term shape.
   Decide at M1 kickoff; the plan below works for either.
2. **Covenant constraint (future-proofing):** boltz-core's reverse-swap
   covenant tapleaf inspects OUTPUT INDEX 0 (`OP_INSPECTOUTPUTSCRIPTPUBKEY/
   OUTPUTVALUE/OUTPUTASSET`) — the committed destination and value MUST sit
   at output index 0. Our fork just added a `claim_covenant` request field;
   if covenant claims are ever enabled, the split output must go at index ≥1
   and the covenant-committed value at index 0 constrains split semantics
   (fixed-split-from-remainder, not percentage-of-total). Keep the
   Remainder/primary destination at index 0 unconditionally.

## 2. Phase M0 — rescue the stash (do first, 5 minutes)

`boltz-rust` local checkout, branch `feature/multi-output-claim`, `stash@{0}`
holds a ~223-line WIP (`sign_claim_to_outputs`/`create_claim_to_outputs`,
correct multi-output CT blinding, script-path only). It is one
`git stash drop` from oblivion:

```bash
cd ~/bull-bitcoin-workspace/boltz/boltz-rust
git stash branch feature/multi-output-claim-wip stash@{0}
git add -A && git commit -m "WIP: multi-output L-BTC claim prototype (script-path only)"
```

Keep as reference; the real implementation refactors `create_claim` itself
(§3) rather than shipping a parallel function.

## 3. Phase M1 — boltz-rust: Liquid multi-output (the core work)

Refactor `LBtcSwapTx` (`src/swaps/liquid.rs`) — **generalize the existing
path, don't duplicate it**, so the cooperative branch comes for free:

1. `LBtcSwapTx.output_address: Address` → `destinations: Vec<(Address, DestAmount)>`
   (`liquid.rs:543`); `new_claim`/`new_claim_with_utxo` (`:550/:575`) gain
   `new_claim_multi` constructors; old signatures delegate.
2. `create_claim` (`liquid.rs:806-955`): replace the single
   `payment_output` + `vec![payment_output, fee_output]` (`:886-899`) with the
   destination loop from the stash prototype, adapted:
   - resolve `Remainder` to `input − fee − Σfixed` per build (works under
     `create_tx_with_fee`'s trial pass);
   - per-output: own ABF, surjection proof, rangeproof; **place the
     Remainder/last output as the `ValueBlindingFactor::last` balancer** over
     {fee, all prior outputs} (stash got this right);
   - all destinations must be confidential (blinding pubkey required — keep
     the stash's per-output error).
3. Cooperative path: no extra work — `sign_claim`'s MuSig branch
   (`liquid.rs:674-801`) signs the key-spend sighash of whatever tx
   `create_claim` built, and sends the full tx hex to Boltz
   (`boltz.rs:557-633`). Verified server-side: Boltz signs without output
   inspection.
4. `create_refund` (`liquid.rs:1102`, output vec at `:1217`): same
   generalization (lower priority; Liquid refunds are rare for us).
5. Fee sizing: relative-fee path self-adjusts (`tx_size`→`discount_vsize`,
   `liquid.rs:1395-1400`). Update `LIQUID_TX_SIZES` (`src/swaps/fees.rs:27`)
   with per-extra-output increments (blinded output ≈ rangeproof-dominated;
   measure real discount-CT vsize in tests and record constants).
6. Unit tests: 2- and 3-output claims — unblind every output with its
   blinding key and assert exact values; CT balance (tx verifies); trial-fee
   pass with `Fee::Relative`; dust rejection; single-destination equivalence
   with old builder (byte-identical modulo randomness); discount-CT vsize
   assertions.

## 4. Phase M2 — boltz-rust: Bitcoin multi-output (small)

`BtcSwapTx` (`src/swaps/bitcoin.rs`) — no CT, so this is plain TxOut work:

1. `output_address: Address` → destinations (`bitcoin.rs:515`).
2. `create_claim` (`:799`): replace single `txout` /
   `output: vec![txout]` (`:835-844`) with the destination loop;
   `Remainder = input − fee − Σfixed` (fee implicit on BTC). Cooperative stub
   witness path (`is_cooperative` branch) is output-agnostic — unchanged.
3. `sign_refund` (`:899`, single spk at `:1070`): same loop — this is the one
   bullnym uses TODAY (merchant recovery refunds).
4. Fee sizing: vsize measured from the constructed tx; add per-output vbytes
   to any hardcoded estimates in `src/swaps/fees.rs`.
5. Unit tests: 2-output claim + 2-output refund, amount and dust assertions,
   coop and script paths.

## 5. Phase M3 — boltz-rust: wrapper plumbing

`src/swaps/wrappers.rs`:
- `SwapTransactionParams.output_address: String` (`:244`) →
  `destinations: Vec<SwapDestination>` (keep `output_address` as a
  deprecated shim mapping to one Remainder destination so bullnym compiles
  unchanged until M4).
- `construct_claim` dispatch (`:656-664` Liquid, `:616` Bitcoin) and
  `construct_refund` pass destinations through.
- Version-bump the crate; bullnym consumes via path dep — no release needed.

**Gate: M1+M2+M3 merge to the fork's trunk before any bullnym work.**

## 6. Phase M4 — bullnym: plumbing + destination policy

All single-address funnels (see research doc §3 for full map):

1. Feature flag `[features] multi_output_settlement = false`
   (`src/config.rs:69` FeaturesConfig, modeled on
   `chain_swap_merchant_recovery`), plus a policy block (e.g.
   `[settlement_split] address / percent_bp or fixed_sat`) — shape depends on
   the product decision (§0).
2. Reverse claims: `resolve_claim_address` (`src/claimer.rs:932`) returns
   `Vec<SwapDestination>`; cache the second address alongside the first
   (`swap_records`: new columns `address_2`, `address_2_index`,
   `amount_2_sat`).
3. Chain claims: destination read at `src/claimer.rs:1544` builds the vec;
   `chain_swap_records` gains the same second-destination columns
   (today it has NO output-address column — add both for auditability).
4. Claim constructors `construct_claim_tx` (`:1727`, param at `:1780`) and
   `construct_chain_claim_tx` (`:1794`, param at `:1851`) pass destinations.
5. Recovery refunds (BTC): optionally extend `invoice-recover` to accept a
   split — DEFER unless the product decision requires it; keep one-tap
   single-destination semantics.
6. Migrations: relax `invoice_payment_addresses` PK `(invoice_id, rail)`
   (`migrations/027`) only if the second output credits the invoice;
   if it's an operator fee, do NOT register it as an invoice payment address.

## 7. Phase M5 — bullnym: accounting (where money bugs live)

Settlement today credits ONE scalar per event
(`flip_invoice_on_lightning_settlement` `src/invoice.rs:214` /
`flip_invoice_on_bitcoin_boltz_settlement` `:277` →
`record_invoice_payment` `src/db/invoices.rs:647`):

1. Make **gross-claimed vs merchant-credited** explicit: event `amount_sat`
   becomes the merchant-credited portion; add `gross_amount_sat` +
   `split_amount_sat` + `split_address` columns on `invoice_payment_events`
   (new migration; CHECK constraints in `migrations/028` unchanged — same
   sources, richer rows).
2. Re-derive expected-amount tolerance: merchant net = `server_lock − claim_fee
   − split`; verify against `InvoiceAccountingConfig` tolerances
   (`src/config.rs:134`) and the underpay/overpay ladder — a split must NEVER
   flip a paid invoice to `underpaid`. Grossing-up at swap creation
   (`src/boltz.rs:161`) may need to include the split so the merchant still
   nets the invoice amount — product decision.
3. Public invoice status: decide whether the split is disclosed
   (`docs/api-reference.md` invoice amounts section must state the semantics
   either way).

## 8. Phase M6 — tests

1. boltz-rust unit tests (in M1/M2).
2. bullnym integration tests: 2-output reverse claim + 2-output chain claim
   against the docker `bullnym_test` DB; accounting assertions
   (merchant-credited vs gross; status ladder unaffected).
3. bullnym-tests battle tier `multi-output` (pattern: CRECV): create invoice
   → pay → claim → **unblind BOTH outputs from the explorer tx and assert
   exact values and destinations**; assert discount-CT fee within tolerance;
   flag-off case asserts single-output claims unchanged.
4. Mainnet dust pilot on pay2 (like CRECV-10): one LN payment and one BTC
   chain payment with a small fixed split; verify both outputs land and the
   invoice settles `paid`.

## 9. Rollout

- Default-off flag; deploy pay2 → dust pilot → enable per-operator.
- Cooperative-claim risk: Boltz signs blind today; if their policy ever
  rejects multi-output txs, the claimer's existing `cooperative_refused`
  fallback (script path) keeps claims unilateral. Monitor coop-refusal rate
  after enabling.
- Docs: api-reference invoice-amount semantics; ops note on the split config.

## 10. Order and rough effort

| Phase | Repo | Effort | Blocked by |
|---|---|---|---|
| M0 stash rescue | boltz-rust | trivial | — |
| M1 Liquid multi-output | boltz-rust | 2-3 days (CT tests dominate) | M0 |
| M2 Bitcoin multi-output | boltz-rust | 0.5-1 day | — |
| M3 wrappers | boltz-rust | 0.5 day | M1, M2 |
| M4 bullnym plumbing | bullnym | 1-2 days | M3 + product decision |
| M5 accounting | bullnym | 1-2 days (careful review) | M4 |
| M6 tests + pilot | both + bullnym-tests | 1-2 days | M5 |

Product decision (§0) can be made in parallel with M0-M3; it only gates M4+.

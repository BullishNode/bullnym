# Research: two L-BTC outputs on a swap claim

Status: RESEARCH (2026-07-11). Question: what would it take for bullnym to
produce TWO L-BTC payment outputs from a Boltz swap claim instead of one?
Boltz suggested "hidden functions" in their libraries support this.

## Verdict

**Technically sound and entirely client-side — but there are no hidden
functions in our stack.** The Boltz *protocol* places no constraint on claim
outputs; the single-output assumption is one hardcoded line in our
`boltz-rust` fork plus CT blinding written for exactly one blinded output.
The "hidden functions" claim matches Boltz's TypeScript `boltz-core` (its
claim builder takes arrays), not the Rust library bullnym uses. Effort splits
~70% library / ~30% bullnym, and the dominant risk is accounting semantics,
not transaction construction.

## 1. Protocol facts (verified in boltz-backend source)

- **Cooperative claim (key-path MuSig):** the client builds the COMPLETE
  claim tx locally and sends the whole serialized tx to Boltz
  (`POST swap/reverse/{id}/claim`, `POST swap/chain/{id}/claim`). Boltz's
  `createPartialSignature` (boltz-backend `lib/service/cooperative/Utils.ts:24`)
  validates ONLY the input index and (for claims) the preimage, then signs the
  taproot key-spend sighash of that exact tx. **It never inspects outputs.**
  Verified in `MusigSigner.signReverseSwapClaim` and
  `ChainSwapSigner.signClaim`.
- **Script path (non-cooperative):** fully unilateral — reveal preimage,
  spend via the swap tree. No Boltz involvement at all. Guaranteed fallback
  if Boltz server policy ever starts rejecting 2-output txs.
- **No destination pre-commitment:** bullnym sends no claim address at swap
  creation (reverse: `address: None`, MRH disabled, `src/boltz.rs:88-89`;
  chain: `CreateChainRequest` has no address field). The destination is chosen
  unilaterally at claim time. (Only the Magic-Routing-Hint opt-in would
  pre-commit an address; we don't use it.)

Conclusion: **two outputs is purely local transaction construction.**

## 2. Where the single-output assumption lives (boltz-rust)

Repo: `../boltz/boltz-rust` (branch `feature/multi-output-claim` is
aspirational-name-only; its single commit adds an unrelated `claim_covenant`
field). Both reverse (LN→LBTC) and chain (BTC→LBTC) L-BTC claims share ONE
code path:

| What | Where |
|---|---|
| Single-address data model | `LBtcSwapTx { output_address: Address, … }` `src/swaps/liquid.rs:540-547` |
| Claim constructors (single `output_address: String`) | `liquid.rs:550` `new_claim_with_utxo`, `:575` `new_claim` |
| **The hardcoded line** | `output: vec![payment_output, fee_output]` **`liquid.rs:899`** in `create_claim` (`:806-955`) |
| Wrapper param | `SwapTransactionParams.output_address: String` `src/swaps/wrappers.rs:244`, dispatch `:656-664` |
| Refund mirror (unaffected but same shape) | `create_refund` `liquid.rs:1102`, `vec![fee_output, payment_output]` `:1217` |

**No multi-output/recipient function exists anywhere in the crate** (grepped
`recipients`, `outputs`, `split`, `Vec<TxOut>`, `extra`, `additional`; only CT
crypto internals and test helpers).

### CT/blinding changes required (the real library work)

`create_claim` blinds exactly one output and balances with
`ValueBlindingFactor::last(...)` against the explicit fee output
(`liquid.rs:833-892`). For two blinded outputs:

1. Split `input_value − fee` across two payment TxOuts (amounts chosen by
   caller).
2. Output 1: random ABF + random VBF, own rangeproof + surjection proof.
3. Output 2: `ValueBlindingFactor::last(...)` computed over {output 1, fee}
   so the CT sum balances; own rangeproof + surjection proof.
4. `output: vec![out1, out2, fee_output]`.
5. Both destination addresses MUST be confidential (the builder requires
   `blinding_pubkey`, errors on unblinded addresses — `liquid.rs:868-872`).

Fees: the relative-fee path measures the actually-constructed tx
(`tx_size` → `discount_vsize`, ELIP-200; `liquid.rs:1395-1400`) so it
self-adjusts for the extra output. But the hardcoded estimate
`LIQUID_TX_SIZES.reverse_claim = 193` (`src/swaps/fees.rs:27`) undercounts a
2-output claim and needs a variant.

Cooperative path needs **zero** library changes beyond the builder — it
already serializes the whole tx to Boltz (`liquid.rs:674-801`,
`boltz.rs:557-633`).

### API sketch

Widen to a destination list, keep the old signature as a 1-element wrapper:

```rust
pub struct ClaimDestination { pub address: String, pub amount_sat: Option<u64> } // None = remainder
// LBtcSwapTx::new_claim_multi(script, Vec<ClaimDestination>, client, utxo)
// SwapTransactionParams { destinations: Vec<ClaimDestination>, … }
```

## 3. bullnym blast radius

Everything funnels a single `output_address` into the library:

- **Claim call sites:** reverse `src/claimer.rs:1165` (`claim_swap_inner`) →
  `construct_claim_tx` `:1727` → param at `:1780`; chain `:1497`
  (`claim_chain_swap_inner`) → `construct_chain_claim_tx` `:1794` → `:1851`.
- **Address resolution:** reverse `resolve_claim_address` `src/claimer.rs:932`
  (3 branches: cached / `invoices.liquid_address` / derive fresh from CT
  descriptor + bump `users.next_addr_idx`); chain reads
  `invoice.liquid_address` directly at `:1544`. A second destination needs a
  second derivation (+ blinding key) and caching.
- **DB:** `swap_records.address` is singular; `chain_swap_records` has NO
  output-address column (fetched live); `invoice_payment_addresses` PK
  `(invoice_id, rail)` allows only ONE liquid address per invoice —
  must be relaxed. New columns: second address (+index, +blinding key) and
  per-output amount split (`migrations/002/025/026/027`).
- **Accounting (the subtle part):** settlement credits ONE scalar per event —
  reverse credits `swap.amount_sat` (`src/claimer.rs:1412-1415`), chain
  credits `effective_server_lock_amount_sat()` (`:1692-1702`) via
  `flip_invoice_on_*_settlement` (`src/invoice.rs:214`/`277`) →
  `record_invoice_payment` (`src/db/invoices.rs:647`, sums all events at
  `:734`). With two outputs you must separate **gross claimed** from
  **merchant-credited** — either the event's `amount_sat` becomes the
  merchant portion only, or a second event/source is added (CHECK constraints
  in `migrations/028` enumerate sources). Fee-tolerance interplay:
  `src/boltz.rs:198-213`, `InvoiceAccountingConfig` `src/config.rs:134`.
- **No existing split/affiliate/fee-recipient concept anywhere** in bullnym.
- **Feature gate:** add default-off `[features]` flag in `FeaturesConfig`
  (`src/config.rs:69`), modeled on `chain_swap_merchant_recovery`.

## 4. What it would take (work plan sketch)

1. **boltz-rust: multi-output claim builder** — `ClaimDestination` list
   through `LBtcSwapTx`/`new_claim*`/`create_claim`/`SwapTransactionParams`;
   two-blinded-output CT math (§2); fee-size variant; unit tests incl.
   unblind-and-verify both outputs. This is the bulk of the work and it's
   self-contained.
2. **bullnym: destination policy** — where the 2nd address comes from
   (second descriptor? operator fee address? per-invoice split spec?) — this
   is a PRODUCT decision, undefined today.
3. **bullnym: plumbing** — second-address derivation/caching, claimer params,
   migrations, relaxed `invoice_payment_addresses` PK.
4. **bullnym: accounting** — gross-vs-credited split in settlement events;
   tolerance re-check; docs (`api-reference.md` invoice amounts semantics).
5. **Rollout** — default-off flag; script-path works unconditionally;
   cooperative path expected to work (Boltz signs blind) with automatic
   `cooperative_refused` fallback already in the claimer if their policy ever
   changes; battle-test tier in bullnym-tests (assert BOTH outputs unblind to
   expected values, and discount-CT fee within tolerance).

## 5. Risks / open questions

- **Boltz server policy drift:** today they sign blind; if they ever add
  output validation, cooperative claims could refuse — claimer already falls
  back to script path (bigger tx, higher fee, still unilateral). Low risk.
- **Both destinations must be blinded** (confidential addresses). Unblinded
  2nd destinations would need extra library work.
- **Accounting semantics** is where money bugs would live — the split must be
  explicit in `invoice_payment_events`, not inferred.
- **Fee estimation** (`estimate_claim_fee`) undercounts until updated.
- **What is the 2nd output FOR?** (service fee? split settlement? cold-storage
  skim?) — determines address custody, docs, and whether the public invoice
  status must disclose it. Not answerable from code.

# Recovery v2 — server settles, phone supervises

**Status:** PLAN (supersedes the recovery *model* of PR29; keeps its wire + code)
**Repos:** `bullnym` (server), `bullbitcoin-mobile` (client, branch stacks on `pr29-getpaid-stuck-swap-recovery`), `bullnym-tests` (verification)
**Companion docs:** `bullnym/plans/chain-swap-recovery-detection-server.md` (shipped),
`bullbitcoin-mobile/plans/pos-stuck-swap-recovery.md` (shipped; model superseded by this doc, wire/UI retained)

---

## 1. Why v2 — the critique this answers

PR29 + bullnym #44/#45 built a sound recovery *primitive* behind the wrong *product model*.
The accepted findings (verified against the tree):

| # | Finding | Where verified |
|---|---------|----------------|
| C1 | Recovery is treated as an exceptional refund, not invoice settlement. The recover handler commits the address, broadcasts, returns `{status, txid}` — **no** `mark_invoice_settlement_status` call anywhere on the refund path. The invoice stays `unpaid`/`expired`. | `src/invoice.rs` (`recover_chain_swap` tail → `claimer::execute_chain_swap_refund`) |
| C2 | The "settle with the customer at the till" out-of-band model only works for POS. A Payment-Page payer is anonymous/remote — the merchant has no contact and no refund address. One model was applied to two surfaces. | mobile plan §1 |
| C3 | Manual-only recovery is unreliable: it requires app-open + foreground scan + wallet available + merchant notices + merchant taps + server flag on. Funds can sit locked indefinitely even though the server holds the refund key. | mobile plan §6 (one-tap-only decision) |
| C4 | Recovery pays into the merchant's **main** ("Secure Bitcoin") wallet: links a main-wallet address to the Bullnym identity and deposits swap UTXOs there. | `recover_stuck_payment_usecase.dart` (`_freshDefaultWalletAddress`) |
| C5 | "Recovered" means **broadcast**, not confirmed. The handler returns success immediately after broadcast; a low-fee tx can be evicted after the merchant saw "Recovered". PR #45 itself lists confirmation finality + fee estimation as outstanding. | `recover_chain_swap` tail; PR #45 |
| C6 | Crash-consistency hole: `refunding` is committed, the tx is constructed + broadcast, then the txid is recorded — the exact raw tx is never journaled first. A crash in the window yields ambiguous state / a possibly different reconstructed tx. | bullnym issue #62 |
| C7 | The merchant signature does not constrain a malicious bullnym: the server holds the refund key and builds the tx. The signature is authorization + audit, not theft-resistance. | design fact; must be an ADR statement, not an implication |

**Also adopted (design review, this session):**

| # | Constraint |
|---|-----------|
| C8 | **Single registered recovery address**, NOT a per-swap BIP85 recovery descriptor. Recovery is an exception path; a descriptor adds a purpose-wallet, manifest/backup integration, and a server cursor to buy only per-recovery address uniqueness. Reuse across rare recoveries is an acceptable privacy cost; rotation is available. Crucially, a per-swap derivation would create one never-funded index per stuck swap — exactly the gap-limit growth pattern C9 forbids. |
| C9 | **Gap-limit safety is a hard constraint.** Every reserved-but-never-funded index is a permanent "unused" hole; ≥ stopGap consecutive holes below a funded index make funds invisible after seed restore (app default UX treats stopGap ≤ 20 as normal; external wallets default to 20). The mobile generate loop is currently **unbounded** (`wallet_address_repository.dart:126-141` — `while (isSystemLabel) index++` with no gap accounting) and BDK `getNewAddress` advances the index on every call. Recovery v2 must contribute a **constant +1** reserved index and must not ship on top of an unbounded loop. |

**Retained from v1 (unchanged):** Schnorr `bullpay-la-v2` auth; first-write-wins destinations;
idempotent retry; the always-on signed detection endpoint (`GET /api/v1/invoices/recoverable`)
+ `recovery_enabled`; the non-leak guarantee on the public `status()` endpoint; mainnet-only
addresses; the G12 double-payout guard (`claim_txid IS NULL` in `mark_chain_swap_refunding`);
one-tap manual recovery **as the fallback/override**, no longer the primary executor.

---

## 2. Target model (one paragraph)

At Get Paid setup the merchant signs **one** recovery address (derived once from the default
Bitcoin wallet, reserved with a `recovery` system label). Every chain swap is **born with its
refund destination precommitted**. When the reconciler proves the L-BTC path failed and a grace
window for Phase-3 renegotiation has passed, the server **automatically** journals the exact
refund tx, broadcasts it, and marks the swap `refund_broadcast`; the watcher promotes it to
`refunded` only after N confirmations, at which point the **invoice is settled** by a recovery
payment event (or recorded as an overpayment). The phone detects, monitors, and handles
exceptions; it derives nothing at recovery time and taps only for legacy/no-address swaps.

---

## 3. Phases

Order: **G ∥ R1 → R2 → R3 → R4.** G and R1 are independent of each other and of the model
debate; **R1 gates the mainnet dust pilot** under any model. R2 depends on G (it adds a
reservation). R3 depends on R1 + R2. R4 depends on R2 (client half) and R3 (copy/accounting).

---

### Phase G — gap-limit guardrails (mobile, independent, ships first or with R2)

> **Detailed implementation plan:** `bullbitcoin-mobile/plans/gap-limit-guardrails.md`
> (window-check algorithm, GapPolicy strict/bestEffortReuse — swap-watcher claim sites must
> never fail, they reuse instead — caller matrix, exact file changes, test matrix).

**Goal:** make address reservation gap-safe wallet-wide; pre-existing exposure, not
recovery-specific, but recovery must not add reservations on top of an unbounded loop.

**G1 — bound the generate loop (critical).**
`lib/core/wallet/data/repositories/wallet_address_repository.dart`:
- Track the highest FUNDED index per wallet/chain (BDK/LWK expose used-address info; fall back
  to the wallet's last-used index).
- In `generateNewReceiveAddress` / `generateNewLiquidReceiveAddressWithBlindingKey`: if the
  candidate index would exceed `highestFundedIndex + (stopGap − margin)` (margin default 5,
  stopGap from Electrum settings, floor 20), **throw a typed error**
  (`WalletError.gapLimitPressure`) instead of handing out the address. Callers (receive screen,
  invoices, recovery registration) surface "too many outstanding unpaid/reserved addresses —
  wait for payments or clear unpaid invoices."
- The skip loop itself gets the same bound (it currently walks unboundedly past labels).

**G2 — release-on-expiry.** When an invoice expires/cancels **unfunded**, delete its
reservation system label (invoices feature owns this; hook its status transitions). A released
never-funded index re-enters circulation — reuse is privacy-harmless and directly shrinks the gap.

**G3 — outstanding-reservation cap** (belt-and-braces): refuse new reservations when
`count(never-funded system-labelled indexes) ≥ cap` (default 10 « stopGap).

**Tests:** unit tests on a fake label store — loop refuses beyond the bound; release restores
issuance; cap enforced. Regression: reserving 1 recovery address + N invoice addresses ≤ cap
never trips G1.

**Acceptance:** no code path can widen the never-funded run beyond `stopGap − margin`; failure
is loud and typed. **Effort: S–M.**

---

### Phase R1 — refund durability + finality (server; gates the mainnet pilot)

**Goal:** make any recovery broadcast (manual v1 or auto v2) crash-safe and honest about
finality. Fixes C5 + C6 (#62).

**R1.1 — journal before broadcast (#62).**
New table `chain_swap_refund_txs` (migration `042_…`):
`swap_id UNIQUE REFERENCES chain_swap_records, raw_tx_hex, txid, fee_sat, created_at,
broadcast_at NULL`. `execute_chain_swap_refund` becomes:
construct → **INSERT journal row** → broadcast → set `broadcast_at`.
On restart/retry: if a journal row exists for a `refunding`/`refund_broadcast` swap,
**rebroadcast the SAME raw tx** (idempotent; never reconstruct a different one). The
reconciler backstop (`revert_stale_refunding_chain_swaps`) reverts to `refund_due` **only if
no journal row exists**; with a journal row it rebroadcasts instead.

**R1.2 — split the state: `refunding → refund_broadcast → refunded`.**
- `ChainSwapStatus` (`src/db/chain_swaps.rs`): add `RefundBroadcast` ("refund_broadcast"),
  non-terminal. `mark_chain_swap_refund_broadcast(id, txid)` (guarded from `refunding`);
  `mark_chain_swap_refunded` now guarded from `refund_broadcast`.
- **Confirmation watcher:** the bitcoin-watcher/reconciler tracks the journaled txid and
  promotes to `refunded` after `claim.refund_confirmations` (new config, default 3) confs.
  Detect eviction: txid absent from mempool + not confirmed after T → rebroadcast journal tx;
  alert (`operator P1`) if it re-fails.
- **Fee:** estimate at construction (esplora/electrum feerate, floor + cap config), RBF-signaled.
  Fee escalation/CPFP is out of scope (open question Q4).
- **API impact:** the recover endpoint's `RecoverResponse.status` becomes `"broadcast"`
  (docs + client tolerant-reader note); detection includes `refund_broadcast` in its status set
  (SQL `IN` list + spec §3.2). **老 clients:** the mobile mapper routes unknown statuses to
  `inFlightUnknown` (visible, action disabled) — deployed apps degrade safely.

**Tests:** integration — crash-window sim (journal row present, no broadcast_at → retry
rebroadcasts same raw tx bytes); `refund_broadcast` not terminal; watcher promotes on N confs
(regtest-style fake backend or unit on the watcher's decision fn); detection returns
`refund_broadcast` rows; non-leak test extended with the new substring.
**Acceptance:** kill -9 between journal and broadcast never produces a different tx; the app
never sees "Recovered" pre-confirmation. **Effort: M.**

---

### Phase R2 — registered recovery address (server + mobile)

**Goal:** every new chain swap is born with a precommitted, merchant-signed destination in a
dedicated-but-single address. Fixes C4; enables R3.

**Server:**
- Migration `043_users_recovery_address.sql`: `users.recovery_address TEXT NULL`,
  `users.recovery_address_updated_at`.
- **New signed endpoint** (do NOT widen the `register` payload — its signed field order
  `[ct_descriptor, verification_npub]` is a deployed wire contract; changing it breaks every
  installed client): `PUT /api/v1/:nym/recovery-address`, action
  `recovery-address-set`, fields `[btc_address]`, nym in the nym slot, `verify_la_v2` +
  `assert_nym_owner`, `validate_btc_refund_address` (mainnet) at registration. Registered in
  the `payment_pages || invoices` block (same rationale as detection). Rotation = same call;
  affects **future** swaps only.
- **Precommit at swap creation:** `create_bitcoin_chain_offer` passes
  `users.recovery_address` into `record_chain_swap` → `refund_address` set at INSERT.
  First-write-wins becomes vacuous for new swaps (no windows where a swap lacks a destination).
- **Expose:** `recovery_address_registered: bool` on the detection response (top level) and on
  the registration lookup (for the mobile heal re-label). Never expose the address itself on
  any public path.
- **Manual endpoint interplay:** unchanged code — a precommitted swap already rejects a
  different address via the existing mismatch branch; the client reads the committed address
  from the detection echo (PR29's echo-adoption machinery becomes the primary path).

**Mobile:**
- At Get Paid provisioning (and once, prompted, for existing merchants): derive ONE fresh
  default-wallet address → **reserve with `LabelSystem.recovery`** (label persistence failure
  = registration failure, same correctness rule as the invoices Liquid reservation) → sign
  `recovery-address-set` → register. Wire: new action const + `[btc_address]` builder + client
  method + facade + golden vector (`bullpay-la-v2\0recovery-address-set\0<npub>\0<nym>\0<addr>\0<ts>`).
- **Heal re-label:** after seed restore, the Get Paid heal (`lookupWalletOwnedRegistration`)
  re-asserts the `recovery` label on the registered address (labels are local state; C9).
- Recover usecase: for swaps with a precommitted address the derive branch is dead code —
  keep it only for legacy (no-address) swaps.
- **Gap math (C9):** exactly one never-funded index, allocated early, neighbors funded by
  normal use. Spec line: *"recovery reserves exactly ONE address (constant gap cost +1);
  recovery MUST NOT derive per-swap addresses."*

**Grandfathering:** swaps created before an address is registered keep the v1 manual flow
(PR29 UI) unchanged.

**Tests:** server — set/rotate/auth-negative/mainnet-reject; precommit visible in detection
echo at creation; CRECV tier: `recovery-address-set` cases + "new swap is born committed".
Mobile — golden vector; provisioning reserves + registers atomically; heal re-labels; contract
test that `generateNewReceiveAddress` never re-issues the labelled address.
**Acceptance:** a fresh POS/PP swap shows a non-null `refund_address` in detection from birth,
matching the registered address. **Effort: M (server S–M, mobile M).**

---

### Phase R3 — server auto-recovery + settlement accounting

**Goal:** the server completes recovery unattended; recovered value lands on the invoice.
Fixes C1 + C3; resolves C2 by making settlement, not personal reconciliation, the default story.

**R3.1 — auto-recovery worker (reconciler pass).**
Eligibility: `status = 'refund_due'` AND `refund_address IS NOT NULL` AND lockup confirmed AND
`claim_txid IS NULL` (G12) AND `age(refund_due) > auto_recover_grace` (config, default 24h —
gives Phase-3 renegotiation/self-claim first shot; CRECV-10 shows renegotiation is a valid
drain of `refund_due`). Then: `mark_chain_swap_refunding` (advisory lock) → R1 journal →
broadcast → `refund_broadcast` → watcher → `refunded`. Gated by **new flag
`features.chain_swap_auto_recovery` (default OFF)**, independent of the manual flag.

**R3.2 — settlement accounting on confirmed recovery.**
On `refunded` (confirmed only):
- Record a **payment event**, rail `btc_recovery`, amount = recovered sats (journal amount −
  fee), txid, swap id.
- Invoice not yet settled → `status = paid`, `paid_via = 'btc_recovery'`,
  `paid_amount_sat = recovered`, `settlement_status = 'settled'` (stays inside the existing
  write-guard enum — no public-enum widening, preserving the non-leak posture; the *mechanism*
  is visible only via `paid_via`, which is a deliberate, post-terminal disclosure: the payer
  seeing "paid" after a fallback settlement is correct for Payment Pages).
- Invoice already settled by a retry → record the payment event as **overpayment**
  (merchant-visible in detection/list; no invoice state change).
- **Amounts are honest:** recovered (grossed-up lockup − refund fee) ≠ invoice amount; both are
  recorded (`paid_amount_sat` vs `amount_sat`) — never pretend equality.
- **Surface attribution:** add `invoices.checkout_kind` (`pos` | `payment_page`, NULL legacy;
  migration `044`) populated by `create_anonymous_for_kind`, echoed in detection — this is
  what lets the client show POS-vs-PP-appropriate copy (C2).

**Tests:** worker eligibility matrix (grace, G12, no-address, legacy); renegotiation-vs-auto
race (renegotiated swap is never auto-recovered); settlement event on confirm (not broadcast);
overpayment branch; non-leak re-run (public payer sees `refund_due` never, `paid` after).
**Acceptance:** on staging with both flags on, an underpaid chain swap settles its invoice with
zero merchant interaction, only after N confs. **Effort: M–L.**

---

### Phase R4 — mobile becomes monitoring

**Goal:** repurpose PR29's UI from executor to supervisor. Fixes C2's UX half.

- `RecoveryState`: add `awaitingConfirmation` (maps `refund_broadcast`); `refunded` still →
  `recovered`. Old mapping's unknown→`inFlightUnknown` already covers the transition window.
- Detail/list states: "Recovering (confirming — n/a of N)" from detection echo; "Recovered"
  only on `refunded`; show payment-event settlement ("this invoice settled by recovery").
- **Surface-specific copy** via `checkout_kind`: POS → "settle with your customer if owed";
  Payment Page → "payment completed via fallback settlement" (no out-of-band demand); legacy
  NULL → generic.
- One-tap button appears ONLY for: legacy no-address swaps, and `failed`/stalled exceptions
  (retry). Address derivation is removed from the recover path (R2).
- Registration prompt for existing merchants (one-time card on the hub: "register a recovery
  address so stuck payments auto-recover").
- ADR/doc updates: trust boundary statement (C7 — the signature authorizes and audits; a
  malicious server holding the refund key can always redirect; merchant-held refund keys are
  the only fix and are out of scope), runbook rewrite, supersession banners on the v1 plans.

**Tests:** update the 44-suite mappings + lifecycle spec (detect → auto-settled arrives as
`recovered` without any recover POST; legacy swap still one-taps); wipe/heal re-label case.
**Acceptance:** with all flags on, the app's role in a normal stuck payment is: show badge →
show "confirming" → show "settled". Zero taps. **Effort: M.**

---

## 4. What survives from PR29 (explicit mapping)

| PR29 piece | v2 fate |
|---|---|
| Detection endpoint + CRECV-D1..D5 tier | unchanged (add `refund_broadcast`, `recovery_address_registered`, `checkout_kind`) |
| Wire layer (`invoice-recover`, `invoice-recovery-list`, DTOs, golden vectors) | unchanged + one new action (`recovery-address-set`) |
| Drift `payment_recoveries` + scan/reconcile + echo-adoption | unchanged — echo-adoption becomes the PRIMARY path |
| One-tap `RecoverStuckPaymentUsecase` | kept as legacy/exception fallback; derive branch retired for registered merchants |
| Hub badge / list / detail UI | kept; states + copy updated (R4) |
| `wipeAppState`, lifecycle spec, fake client | extended, not replaced |
| Out-of-band "settle at the till" notice | POS-only (R4) |

## 5. Rollout

1. **G + R1 land** → mainnet **dust pilot** of the existing manual flow (journal + confirmation
   now make it safe): one deliberately-underpaid swap on staging, manual recover, watch
   confirm-gated `refunded`.
2. **R2** deploys (endpoint always-on; app prompt behind the existing
   `GETPAID_RECOVERY_ENABLED` client flag).
3. **R3** staging with `chain_swap_auto_recovery=true` → repeat the pilot expecting **zero-touch**
   settlement → enable in prod.
4. **R4** app release.

## 6. Open questions

1. `refund_confirmations` depth (proposed default 3) and eviction-rebroadcast timeout.
2. `auto_recover_grace` (proposed 24h) — coordinate with Boltz renegotiation windows.
3. Existing-merchant registration: prompt-only, or block new POS provisioning until registered?
4. Fee escalation for stuck refund txs (RBF bump policy) — deferred; journal stores fee for audit.
5. Should overpayment-by-recovery be surfaced to the payer at all, or merchant-only?
6. Public `paid_via = 'btc_recovery'` — confirm we're comfortable disclosing mechanism
   post-settlement (alternative: reuse `'bitcoin'`).

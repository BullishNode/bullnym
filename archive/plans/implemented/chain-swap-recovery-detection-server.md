# Chain-Swap Recovery Detection — Server Spec (bullnym)

> **Archived: implemented.** Current code, API documentation, and RFC 001
> supersede implementation details in this plan.

Status: DRAFT for review
Scope: server-side changes that let a merchant **detect** a stuck (recoverable)
chain swap. The recovery **action** already exists
(`POST /api/v1/:nym/invoices/:id/recover`, `recover_chain_swap`,
`src/invoice.rs:1093`); this spec adds the read-side signal only.
No production code in this document.

---

## 1. Context (verified in tree, do not re-derive)

- Chain swaps are created at exactly one call site: `create_bitcoin_chain_offer`
  (`src/invoice.rs:1624`), reached only from `create_anonymous_for_kind`
  (`src/invoice.rs:467`) — the keyless checkout path (Payment Page
  `create_anonymous` + POS `create_anonymous_pos`). These invoices are
  nym-linked (`nym_owner = Some(nym)`, `npub_owner` = page owner,
  `origin = "checkout"`, `accept_btc = false`). `create_bitcoin_chain_offer`
  refuses to mint a swap without an owning nym (SF1 guard, `src/invoice.rs:1642`).
- Recovery lifecycle lives ONLY on `chain_swap_records`
  (`src/db/chain_swaps.rs`): `refund_due -> refunding -> refunded`
  (`ChainSwapStatus`, lines 10–36), plus `refund_address` (first-write-wins,
  immutable) and `refund_txid`. Columns added by migrations 036 and 038.
- `invoices.settlement_status` is guarded by `mark_invoice_settlement_status`
  (`src/db/invoices.rs:825`) to
  `none|pending|settled|claim_stuck|refunded|failed`. `refund_due`/`refunding`
  are deliberately NOT admitted and never reach the invoices row.
- Read paths today:
  - `GET /api/v1/invoices/:id/status` -> `status()` (`src/invoice.rs:939`,
    registered `src/main.rs:457`) — **anonymous**, polled by the payer's public
    checkout page. Serializes `inv.settlement_status` (`src/invoice.rs:1014`)
    and only surfaces a chain-swap lockup via
    `latest_payable_chain_swap_for_invoice` which requires
    `status = 'pending'` (`src/db/chain_swaps.rs:237`) — a `refund_due` swap is
    invisible here.
  - `GET /api/v1/invoices` -> `list_signed` (`src/invoice.rs:2296`, registered
    `src/main.rs:490`) — Schnorr-signed `invoice-list`
    (`ACTION_LIST`, `src/invoice.rs:65`), npub-keyed with empty nym, fields
    `[page, pageSize, status]` (`list_payload_fields`, `src/invoice.rs:1819`).
- Recover endpoint auth to mirror: `verify_la_v2(ACTION_RECOVER, npub, nym,
  [invoice_id, btc_address], ts, sig)` + `assert_nym_owner`
  (`src/invoice.rs:1753`) + invoice `npub_owner`/`nym_owner` re-check.
  Errors: `RecoveryNotAvailable`, `RecoveryInProgress`,
  `RecoveryAddressInvalid`, `InvoiceNotFound` (`src/error.rs:30-38`).
  Feature flag `features.chain_swap_merchant_recovery`, default OFF
  (`src/config.rs:94,104`), route gated at `src/main.rs:504`.

### Agreed detection contract (decisions already made)

1. Recovery state is exposed to the merchant ONLY via the signed,
   ownership-verified path, by joining `chain_swap_records`.
2. `invoices.settlement_status` and its write-guard enum are NOT widened —
   widening would leak onto the anonymous shared serializer (G13: a bystander
   with the invoice URL must not learn recoverable BTC exists).
3. The public `status()` endpoint stays coarse and byte-identical in shape.

---

## 2. Design decision: dedicated signed detection endpoint

### Options considered

**A. Embed a nested `recovery` object in `invoice-list` rows** (LEFT JOIN or
batched second query on the page of invoice ids).

- Pro: no new auth surface; mobile already calls `invoice-list`.
- Con (decisive): detection requires **page-walking**. `list_invoices_by_npub`
  (`src/db/invoices.rs:235`) is newest-first, page-size ≤ `LIST_LIMIT_MAX = 100`
  (`src/invoice.rs:77`), page ≤ 1000. A `refund_due` swap on an older invoice
  (merchant notices days later, or after app reinstall) is only detectable by
  walking the merchant's entire invoice history on every poll — O(history)
  requests for a signal that is almost always empty. It also forces either a
  new joined row struct beside `Invoice`/`INVOICE_COLUMNS`
  (`src/db/invoices.rs:22,63`) or a second query per page, inflating a hot
  endpoint for a cold feature.

**B. Dedicated signed endpoint: `GET /api/v1/invoices/recoverable`** (npub-keyed,
mirrors `invoice-list`), returning ALL swaps of this npub in
`refund_due | refunding | refunded`.

- Pro: one cheap request answers "do I have stuck funds?" completely —
  no page-walking, O(stuck swaps) rows (normally zero). Query is driven by
  `chain_swap_records_status_idx` (migration 025) over a tiny status set.
  It also directly serves post-reinstall reconciliation (Section 6): the full
  set of committed `refund_address`/`refund_txid` values comes back in one call.
- Pro: keeps `invoice-list` and its wire shape untouched.
- Con: one new signed action + one new mobile signer entry.

**Recommendation: B.** Ship the dedicated endpoint as the detection signal.
Embedding a compact hint in `invoice-list` rows is an optional later nicety for
the invoice-detail screen (Open question 5), not required for detection.

---

## 3. Endpoint specification

### 3.1 Route and auth

```
GET /api/v1/invoices/recoverable
    ?npub=<hex x-only pubkey>&timestamp=<unix>&signature=<schnorr hex>
```

- Handler: `invoice::list_recoverable_signed` (new), registered next to
  `list_signed` — see feature-flag posture (Section 7) for which block.
  No dynamic-segment conflict: there is no `GET /api/v1/invoices/:id` route
  (only DELETE at `src/main.rs:487` and GET `.../:id/status`), and axum gives
  static segments priority anyway.
- New action constant in `src/invoice.rs` beside `ACTION_LIST`:
  `pub const ACTION_RECOVERY_LIST: &str = "invoice-recovery-list";`
- New payload helper beside `list_payload_fields` (`src/invoice.rs:1819`):

  ```rust
  /// 0 fields. The action carries no request parameters that affect
  /// authorization or output shape; scope comes from `npub` which is
  /// already embedded in the LA-v2 message. If parameters are ever added
  /// (pagination, filters) they MUST be appended here and in the mobile
  /// signer in lockstep.
  fn recovery_list_payload_fields() -> [&'static str; 0] { [] }
  ```

- Verification mirrors `list_signed` exactly (`src/invoice.rs:2360-2370`):
  `auth::verify_la_v2(ACTION_RECOVERY_LIST, &params.npub, "", &fields,
  params.timestamp, &params.signature)?`. Nym is EMPTY — the action is
  identity-wide, like `invoice-list` (an npub can own invoices across nyms;
  each row carries its `nym` so the client can build the per-nym recover URL).
  No `assert_nym_owner` is needed (there is no path nym); npub scoping is
  structural: the signed message embeds `params.npub` and the query filters on
  the same value. Note this endpoint intentionally does NOT require an active
  registration row — like `invoice-list`, and unlike `recover_chain_swap` —
  so a merchant whose registration lapsed can still SEE stranded funds
  (recovering them still requires the nym-scoped recover endpoint).
- Rate limiting / whitelisting: copy the `list_signed` preamble verbatim
  (`ip_whitelist::caller_ip`, `certification::allows_scope` with
  `CertificationScope::MetadataLookup`, scope tag `"signed_invoice_recoverable"`,
  `check_metadata_per_ip`).
- Replay posture: read-only and idempotent; a replay inside the LA-v2 freshness
  window returns the same owner-scoped data to the same owner. No nonce needed.

### 3.2 Response schema (the mobile detection contract)

```jsonc
{
  // Server-side switch for the recover ACTION (Section 7). The client shows
  // "Recover now" when true, "Contact support" when false.
  "recovery_enabled": false,

  // Oldest-first within status; refund_due before refunding before refunded.
  "items": [
    {
      "invoice_id": "3f6f0f6e-...",           // Uuid
      "nym": "merchant-nym",                   // chain_swap_records.nym; build
                                               // POST /api/v1/<nym>/invoices/<invoice_id>/recover
      "recovery_status": "refund_due",         // "refund_due" | "refunding" | "refunded"

      // Amounts. user_lock is what the payer locked on BTC (the recoverable
      // UTXO, minus the refund network fee at broadcast time); server_lock is
      // the invoice-side L-BTC amount (renegotiated value when present —
      // ChainSwapRecord::effective_server_lock_amount_sat, src/db/chain_swaps.rs:154).
      "user_lock_amount_sat": 105000,
      "server_lock_amount_sat": 100000,

      "lockup_address": "bc1p...",             // the funded BTC lockup

      // Recovery bookkeeping — the reconciliation payload:
      "refund_address": null,                  // committed destination or null
      "refund_txid": null,                     // broadcast recovery txid or null

      "swap_created_at_unix": 1767000000,
      "swap_updated_at_unix": 1767003600,      // when the state last moved

      // Invoice context for the UI (no page-walk needed):
      "invoice": {
        "status": "expired",                   // invoices.status
        "amount_sat": 100000,
        "fiat_amount_minor": 5000,             // nullable
        "fiat_currency": "CAD",                // nullable
        "public_description": "Order 123",     // nullable
        "invoice_number": "INV-42",            // nullable
        "created_at_unix": 1766990000
      }
    }
  ],
  "count": 1,
  "has_more": false                            // true iff LIMIT was hit
}
```

Client semantics:

- **(a) recoverable now**: `recovery_status == "refund_due"`. If
  `refund_address == null`, no destination is committed yet — the app may call
  recover with a fresh address. If `refund_address != null` (a prior attempt
  committed one, e.g. the broadcast failed and the reconciler reverted
  `refunding -> refund_due`), the destination is immutable — the app MUST
  retry recover with exactly that address (`set_chain_swap_refund_address`
  is first-write-wins, `src/db/chain_swaps.rs:456`).
- **(b) in-flight / done**: `"refunding"` = broadcast in progress (retry later;
  the reconciler backstop `revert_stale_refunding_chain_swaps`,
  `src/db/chain_swaps.rs:551`, un-sticks stranded rows). `"refunded"` =
  terminal success; show `refund_txid`.
- **(c) post-reinstall reconciliation**: a wiped app calls this endpoint and
  learns every committed `refund_address` / `refund_txid` for its npub without
  guessing — see Section 6.

Explicitly NOT included: lockup confirmation counts. `chain_swap_records` does
not store per-swap confirmation depth (no such column; see `ChainSwapRecord`,
`src/db/chain_swaps.rs:110-141`), and by construction `refund_due` is only set
on a **funded** lockup (`mark_chain_swap_refund_due` doc,
`src/db/chain_swaps.rs:321`). The status string is the whole lifecycle signal.
Do not invent a confirmations column for detection.

Response structs (new, in `src/invoice.rs` beside `InvoiceListItem`):

```rust
#[derive(Serialize)]
pub struct RecoverableInvoiceContext {
    pub status: String,
    pub amount_sat: i64,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub public_description: Option<String>,
    pub invoice_number: Option<String>,
    pub created_at_unix: i64,
}

#[derive(Serialize)]
pub struct RecoverableItem {
    pub invoice_id: Uuid,
    pub nym: String,                      // required: SF1 guarantees swaps have a nym
    pub recovery_status: String,          // "refund_due" | "refunding" | "refunded"
    pub user_lock_amount_sat: i64,
    pub server_lock_amount_sat: i64,      // effective (renegotiated-aware)
    pub lockup_address: String,
    pub refund_address: Option<String>,
    pub refund_txid: Option<String>,
    pub swap_created_at_unix: i64,
    pub swap_updated_at_unix: i64,
    pub invoice: RecoverableInvoiceContext,
}

#[derive(Serialize)]
pub struct RecoverableListResponse {
    pub recovery_enabled: bool,           // state.config.features.chain_swap_merchant_recovery
    pub items: Vec<RecoverableItem>,
    pub count: usize,
    pub has_more: bool,
}
```

Field-population notes for the handler:

- `server_lock_amount_sat` = `effective_server_lock_amount_sat()` semantics
  (i.e. `COALESCE(renegotiated_server_lock_amount_sat, server_lock_amount_sat)`
  in SQL) — after a Phase 3 renegotiation the stale original would misstate
  what the invoice was worth.
- `nym`: `chain_swap_records.nym` is `Option<String>` but SF1
  (`src/invoice.rs:1634-1651`) guarantees it is set for every swap that can
  exist. Handler behavior for a NULL-nym row (legacy/manual data): skip the
  row and `tracing::error!` (operator P1) rather than emit an item the client
  cannot act on — mirrors the recover endpoint's nym-mismatch defense
  (`src/invoice.rs:1200`).
- Never serialize: `preimage_hex`, `claim_key_hex`, `refund_key_hex`,
  `boltz_response_json`, `boltz_swap_id`, `lockup_bip21`, claim bookkeeping.
  The projection in Section 5 physically cannot leak them (they are not
  selected).

---

## 4. Non-leak guarantee (public `status()` unchanged)

No change of any kind to `status()` (`src/invoice.rs:939`) or
`InvoiceStatusResponse` (`src/invoice.rs:913`). The guarantee is structural,
on three independent legs:

1. `InvoiceStatusResponse.settlement_status` serializes
   `inv.settlement_status`, whose only writers go through
   `mark_invoice_settlement_status` / `mark_invoice_settlement_status_for_swap`
   (`src/db/invoices.rs:825,852`), which **reject** any value outside
   `none|pending|settled|claim_stuck|refunded|failed` with
   `sqlx::Error::Protocol`. (`mark_invoice_in_progress`,
   `src/db/invoices.rs:814`, writes only `'pending'`.) `refund_due`/`refunding`
   cannot reach the column. This spec does NOT widen that enum — that is the
   design decision, not an accident.
2. The only chain-swap data `status()` emits (`bitcoin_chain_address`,
   `bitcoin_chain_bip21`) comes from `latest_payable_chain_swap_for_invoice`
   (`src/db/chain_swaps.rs:237`), whose WHERE clause requires
   `status = 'pending'`. A `refund_due`/`refunding`/`refunded` swap returns
   nothing; the payer sees `null` rails on a dead invoice.
3. `refund_address` / `refund_txid` appear in no public projection anywhere
   (grep gate in CI test below).

Payer-visible behavior for a `refund_due` invoice stays exactly what it is
today: coarse `inv.status` (`expired`/`in_progress`/...) +
`settlement_status ∈ {none,pending,failed,...}` — a generic terminal/failed
signal, never "recoverable BTC exists here".

**Non-leak test** (integration, Section 8): drive an invoice + chain swap to
`refund_due` with a committed `refund_address`, then `GET
/api/v1/invoices/:id/status` anonymously and assert:
- HTTP 200; `settlement_status` is one of the six public values;
- `bitcoin_chain_address` and `bitcoin_chain_bip21` are null;
- the raw response body contains **no substring** `refund_due`, `refunding`,
  `refund_address`, `refund_txid`, nor the committed address string itself.
Repeat the body-substring assertion with the swap in `refunding` and in
`refunded`.

---

## 5. DB changes (`src/db/chain_swaps.rs`)

### 5.1 New projection + helper (the only DB change)

Do NOT reuse `ChainSwapRecord` for the API path — it drags `preimage_hex` /
`claim_key_hex` / `refund_key_hex` through the handler for no reason. Add a
purpose-built read-only row:

```rust
/// Merchant-detection projection: one row per chain swap of this npub in a
/// recovery lifecycle state, joined with minimal invoice context. Excludes
/// all key material by construction. Backs GET /api/v1/invoices/recoverable.
#[derive(Debug, sqlx::FromRow)]
pub struct RecoverableChainSwapRow {
    pub invoice_id: Uuid,
    pub nym: Option<String>,
    pub status: String,                       // refund_due | refunding | refunded
    pub user_lock_amount_sat: i64,
    pub effective_server_lock_amount_sat: i64,
    pub lockup_address: String,
    pub refund_address: Option<String>,
    pub refund_txid: Option<String>,
    pub swap_created_at_unix: i64,
    pub swap_updated_at_unix: i64,
    pub invoice_status: String,
    pub invoice_amount_sat: i64,
    pub invoice_fiat_amount_minor: Option<i32>,
    pub invoice_fiat_currency: Option<String>,
    pub invoice_public_description: Option<String>,
    pub invoice_number: Option<String>,
    pub invoice_created_at_unix: i64,
}

pub async fn list_recoverable_chain_swaps_for_npub(
    pool: &PgPool,
    npub_owner: &str,
    limit: i64,
) -> Result<Vec<RecoverableChainSwapRow>, sqlx::Error>
```

SQL (single query, no pagination — see limit rationale below):

```sql
SELECT cs.invoice_id,
       cs.nym,
       cs.status,
       cs.user_lock_amount_sat,
       COALESCE(cs.renegotiated_server_lock_amount_sat,
                cs.server_lock_amount_sat)         AS effective_server_lock_amount_sat,
       cs.lockup_address,
       cs.refund_address,
       cs.refund_txid,
       EXTRACT(EPOCH FROM cs.created_at)::BIGINT   AS swap_created_at_unix,
       EXTRACT(EPOCH FROM cs.updated_at)::BIGINT   AS swap_updated_at_unix,
       i.status                                    AS invoice_status,
       i.amount_sat                                AS invoice_amount_sat,
       i.fiat_amount_minor                         AS invoice_fiat_amount_minor,
       i.fiat_currency                             AS invoice_fiat_currency,
       i.public_description                        AS invoice_public_description,
       i.invoice_number,
       EXTRACT(EPOCH FROM i.created_at)::BIGINT    AS invoice_created_at_unix
FROM chain_swap_records cs
JOIN invoices i ON i.id = cs.invoice_id
WHERE i.npub_owner = $1
  AND cs.status IN ('refund_due', 'refunding', 'refunded')
ORDER BY CASE cs.status
             WHEN 'refund_due' THEN 0
             WHEN 'refunding'  THEN 1
             ELSE 2
         END,
         cs.created_at ASC
LIMIT $2
```

- Handler passes `limit = 101` (fixed `RECOVERABLE_LIST_LIMIT: i64 = 100`
  + 1 for `has_more`), then truncates. No client-controlled pagination: the
  populated size of this set is stuck swaps per merchant, expected 0 and
  bounded by real incident volume; a merchant with >100 rows is an operator
  incident, and `has_more: true` tells the client to say "contact support".
  Keeping parameters out of the request also keeps the signed payload at zero
  fields (Section 3.1).
- Index posture: driven by `chain_swap_records_status_idx (status)`
  (migration 025) — the three recovery statuses are globally rare, so the
  status scan then PK-join to `invoices` is cheap regardless of merchant size.
  No new index needed at current volumes.
- **`refunded` rows are included unconditionally** (no time cap) in v1 —
  required for reinstall reconciliation, and volume is tiny. Retention cap is
  Open question 1.
- Defense-in-depth consistency: rows come back scoped by `i.npub_owner`;
  `cs.nym` should always equal `i.nym_owner` (SF1 + record path,
  `src/invoice.rs:1685`). The handler skip-and-alert on NULL `cs.nym` covers
  the only representable divergence worth handling.

### 5.2 Migrations

**None.** `refund_address`, `refund_txid` and the three statuses already exist
(migrations `036_chain_swap_refund_due.sql`, `038_chain_swap_refunding.sql`);
`chain_swap_records_invoice_idx` / `chain_swap_records_status_idx` already
exist (migration 025). Confirmed against the files in `migrations/`.

Re-exported automatically via `pub use chain_swaps::*;` in `src/db.rs:10`.

---

## 6. Post-reinstall reconciliation

Problem: after an app wipe, the merchant retries recovery with a fresh address
and hits the address-mismatch branch of `recover_chain_swap`
(`src/invoice.rs:1223`, `"a different recovery address was already committed"`)
— a dead end, because `AppError::RecoveryNotAvailable` carries only a message
string (`src/error.rs:34`, user copy at `:334`).

**Recommendation: reconcile via the detection endpoint, not via richer
errors.** The detection response already returns the committed
`refund_address` and `refund_txid` for every recovery-lifecycle swap of the
npub — that IS the reconciliation payload. Mandated client flow:

1. `GET /api/v1/invoices/recoverable` (always, before offering recover UI).
2. Row has `refund_address != null`? Display it; if `refund_due`, retry
   recover with **that exact string** (byte-equal — the LA-v2 payload signs
   the raw address, `recover_payload_fields`, `src/invoice.rs:1815`, and the
   idempotent path compares raw strings, `src/invoice.rs:1222`).
   If `refunded`, show `refund_txid` — done.
3. Row has `refund_address == null` and `refund_due`? Safe to commit a fresh
   address.

Under this flow the mismatch branch is only reachable by a client that skipped
step 1; keeping it a terminal coded error is correct. **No change to
`recover_chain_swap`, its error variants, or their response bodies.** This
avoids growing a structured-error contract for a path the detection endpoint
makes unreachable, and keeps error bodies data-free by default. (If the mobile
team still wants belt-and-braces error enrichment, that is Open question 6 —
it would be additive and non-breaking later.)

---

## 7. Feature-flag posture

**Recommendation: detection is ALWAYS-ON (no new flag, not gated by
`chain_swap_merchant_recovery`), registered inside the `features.invoices`
block next to `list_signed` (`src/main.rs:490`) — with one adjustment: like the
recover route's rationale comment (`src/main.rs:497-503`), chain swaps are born
under `payment_pages`, so register the detection route when
`features.invoices || features.payment_pages` (in practice both default ON;
the OR guards the same "swaps exist but route absent" hole the recover comment
describes).**

Justification:

- Detection is read-only behind Schnorr auth. The dangerous half —
  `chain_swap_merchant_recovery` — exists precisely because recover **signs and
  broadcasts real BTC** (`src/config.rs:88-94`); none of that risk attaches to
  a SELECT.
- The whole point of this spec is that merchants can SEE stranded funds
  **before** the broadcast path is battle-tested and enabled. Gating detection
  on the broadcast flag would blind merchants exactly during the window when
  operators most need reports ("my payment page shows a stuck payment") and
  would couple two independent rollouts.
- The client still needs to know whether the recover ACTION is live: that is
  the `recovery_enabled` response field
  (`state.config.features.chain_swap_merchant_recovery`), so the server —
  not app config — drives the "Recover now" vs "Contact support" UI, and
  flipping the flag needs no app release.

---

## 8. Test plan

### Unit (`src/invoice/tests.rs`)

1. `recovery_list_payload_field_order` — mirror `recover_payload_field_order`
   (`src/invoice/tests.rs:65`): assert `recovery_list_payload_fields() == []`
   with the "mobile MUST update in lockstep" message. Locks the wire contract
   even at zero fields (a future param added without test churn should fail
   here).
2. `settlement_status_guard_rejects_recovery_states` (in `src/db/tests.rs` or
   the integration suite if it needs a pool): `mark_invoice_settlement_status`
   and `mark_invoice_settlement_status_for_swap` return
   `sqlx::Error::Protocol` for `"refund_due"` and `"refunding"` — the enum
   lock that makes the non-leak structural. (Pure-string guard; if a pool is
   unavoidable, put it in the integration suite.)

### Integration (`tests/integration_test.rs`)

Reuse the existing scaffolding: `build_router` (add
`.route("/api/v1/invoices/recoverable", get(invoice::list_recoverable_signed))`
at line ~144 next to `list_signed`), `sign_la_action` (`:205`), the chain-swap
seeding pattern from `chain_swap_records_are_invoice_scoped_and_retrievable`
(`:3875` — `record_chain_swap` + `update_chain_swap_status` /
`mark_chain_swap_refund_due`), and add a
`sign_invoice_recovery_list_with_keypair` helper mirroring
`sign_invoice_list_with_keypair` (`:340`) with an empty fields slice.

1. `recoverable_list_shows_refund_due_swap` — register merchant, create
   checkout invoice, `record_chain_swap`, `mark_chain_swap_refund_due`
   (via a live state first, since `mark_chain_swap_refund_due` fires from
   non-terminal states); signed GET returns one item:
   `recovery_status == "refund_due"`, correct `nym`, `invoice_id`,
   `user_lock_amount_sat`, `refund_address == null`, invoice context populated.
2. `recoverable_list_is_npub_scoped` — second merchant's signed call returns
   `items: []` while merchant A's swap is `refund_due`; also merchant A signing
   with B's npub param fails `verify_la_v2` (401).
3. `recoverable_list_returns_committed_address_and_txid` — after
   `set_chain_swap_refund_address` + `mark_chain_swap_refunding` +
   `mark_chain_swap_refunded(txid)`: item shows `"refunded"`,
   the committed `refund_address`, and `refund_txid` (the reinstall payload);
   intermediate check at `"refunding"` shows address, null txid.
4. `recoverable_list_orders_and_effective_amount` — one `refund_due` (with
   `renegotiated_server_lock_amount_sat` set) + one `refunded` swap:
   `refund_due` first; `server_lock_amount_sat` equals the renegotiated value.
5. `public_status_never_leaks_recovery_state` — the Section 4 test: for each
   of `refund_due` (address committed), `refunding`, `refunded`, anonymous
   `GET /api/v1/invoices/:id/status` body contains none of the substrings
   `refund_due|refunding|refund_address|refund_txid|<committed address>`;
   `settlement_status ∈ {none,pending,settled,claim_stuck,refunded,failed}`;
   `bitcoin_chain_address`/`bitcoin_chain_bip21` null. (Follow the
   `invoice_status_*` test style at `:2471`/`:3185`.)
6. `recoverable_list_auth_negative` — bad signature, stale timestamp, and
   tampered (non-empty) payload fields each 401; unsigned request 4xx.
7. `recoverable_list_reports_recovery_enabled_flag` — with test config flag
   off (the default), `recovery_enabled == false` while items are still
   returned; a second router built with the flag on returns `true`.
8. `recoverable_list_skips_nymless_swap` — row seeded with `nym = NULL`
   (direct SQL) is omitted; endpoint still 200 with the remaining items.

### Manual/battle-test hook

Add a step to the existing battle-test runbook: after forcing a staging swap
into `refund_due`, confirm the payer-side checkout page (which polls
`status()`) shows no new information, then confirm the merchant app's
recoverable poll shows the row.

---

## 9. Milestones (detection ships independently of broadcast enablement)

**M1 — DB read path.**
`RecoverableChainSwapRow` + `list_recoverable_chain_swaps_for_npub` in
`src/db/chain_swaps.rs`; integration tests 1(query-level), 3, 4 against the
helper directly.
*Acceptance:* helper returns exactly the three-status set, npub-scoped,
renegotiation-aware amount, no key material in the struct; no migration in the
diff.

**M2 — Signed endpoint.**
`ACTION_RECOVERY_LIST`, `recovery_list_payload_fields`,
`list_recoverable_signed` handler + response structs in `src/invoice.rs`;
route registration in `src/main.rs` (always-on per Section 7) and in the test
router; unit test 1; integration tests 1–8 including the non-leak test 5.
*Acceptance:* all tests green; `git diff` shows zero changes to `status()`,
`InvoiceStatusResponse`, `list_signed`, `InvoiceListItem`,
`mark_invoice_settlement_status`, and `recover_chain_swap`; endpoint live with
`chain_swap_merchant_recovery` still OFF and `recovery_enabled: false`.

**M3 — Client contract handoff.**
Document the response schema + LA-v2 signing entry
(`invoice-recovery-list`, zero payload fields) for
`core/nostr/bullpay_la_v2_signing.dart`, and the mandated
detect-then-reconcile-then-recover client flow (Section 6). Add the
compatibility-ledger entry (`docs/compatibility-ledger.md`) for the new route.
*Acceptance:* mobile team sign-off on the JSON contract; runbook step added.

**M4 (independent, existing plan) — enable `chain_swap_merchant_recovery`**
after the staged real-broadcast test; flipping it changes only
`recovery_enabled` in the detection response. No detection code changes.

---

## 10. Open questions

1. **Refunded-row retention**: return `refunded` rows forever, or time-box
   (e.g. `cs.updated_at > NOW() - INTERVAL '90 days'`)? v1 spec says forever
   (tiny volume, simplest reconciliation); confirm ops is comfortable.
2. **`recovery_enabled` semantics**: confirmed as the raw
   `features.chain_swap_merchant_recovery` value, or should it also require
   `features.payment_pages` (mirroring the `main.rs:505` warning)?
3. **Zero signed payload fields**: is the mobile LA-v2 signer
   (`bullpay_la_v2_signing.dart`) comfortable with an empty field array, or
   would a constant sentinel field (e.g. `"1"` version tag) be easier to ship?
   Server cost of either is nil; must be decided before M2 freezes the wire.
4. **Naming**: `GET /api/v1/invoices/recoverable` + action
   `invoice-recovery-list` — any objection (vs `needs-recovery`)? GET chosen to
   mirror `invoice-list`'s query-string auth.
5. **Invoice-list embed (later)**: should `InvoiceListItem` eventually carry a
   compact `recovery_status` hint so the invoice-detail screen doesn't need a
   second call, or is client-side keying of the recoverable response by
   `invoice_id` sufficient? (Not needed for detection; deliberately out of v1.)
6. **Error enrichment**: keep `RecoveryNotAvailable` bodies data-free as
   specced, or additionally return the committed `refund_address` on the
   mismatch branch of `recover_chain_swap` as belt-and-braces for clients that
   skip the detection call?
7. **Certification scope**: reuse `CertificationScope::MetadataLookup` for the
   new endpoint (as `list_signed` and `recover_chain_swap` both do), or mint a
   dedicated scope for recovery-related reads?

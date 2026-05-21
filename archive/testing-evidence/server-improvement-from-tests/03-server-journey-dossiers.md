# 03 Server Journey Dossiers

These dossiers reconstruct what Bullnym server appeared to do in the meaningful evidence clusters. They are intentionally focused on server behavior, not on test-suite mechanics.

## Dossier A: Donation-Page Liquid Underpay

Evidence:

- `bullnym-run-1779151124-liquidv2.json`
- Scenario: `LQ-21`
- Description: donation-page Liquid underpay is classified from a real sender wallet.
- Observed result: failed because it did not reach terminal status within 180 seconds.
- Targeted rerun: `bullnym-run-1779153353-liquidv2.json` passed after operator force-terminal support.

Likely server journey:

1. User opens payment/donation page and creates a Liquid payment attempt.
2. Server creates invoice/payment row with a long outer expiry.
3. External LWK sender sends less than the requested amount.
4. Chain watcher observes funds and records partial payment.
5. Public status remains non-terminal while the outer expiry remains far in the future.
6. Operator/test force-terminal path can classify the invoice as `underpaid`.

Server conclusion:

- The server has partial-payment mechanics, but the user journey can remain stuck too long for payment-page underpay.
- This is not just a test problem; a real user who underpays a payment-page attempt needs a deterministic outcome and next action.

Server questions to answer in code:

- Should underpaid payment-page attempts terminalize immediately once the sender cannot satisfy the full amount through the same address/quote?
- Should partial payments remain payable until expiry for invoice flows but terminalize faster for donation/payment-page attempts?
- Should public status expose `partially_paid` plus remaining amount, or terminal `underpaid` plus retry/refund instructions?

Likely code areas:

- `src/db/invoices.rs`
- `src/gc.rs`
- `src/invoice.rs`
- `src/chain_watcher.rs`
- `src/donation_render.rs`

## Dossier B: BTC Broadcast But User-Visible Timeout

Evidence:

- `bullnym-run-1779140155-bitcoinv2.json`
- Scenario: `BTC-01`
- Observed result: terminal status timeout after a long wait.
- Prior operational note: a BTC tx was broadcast and later observed unconfirmed.

Likely server journey:

1. Server creates a Bitcoin-receivable invoice.
2. BDK sender broadcasts a BTC payment.
3. Mempool sees the transaction but it does not confirm within the test window.
4. Bullnym status does not give a precise enough user-visible state for "payment seen but unconfirmed".
5. The test/user sees a timeout rather than a clear pending confirmation state.

Server conclusion:

- BTC needs an explicit unconfirmed state and public tx evidence.
- With low fee policy, confirmation latency is expected; the server should not make this look like generic failure.

Likely code areas:

- `src/bitcoin_watcher.rs`
- `src/db/invoices.rs`
- `src/invoice.rs`
- `migrations/024_invoice_payment_events.sql`

## Dossier C: Registration, NIP-05, And Lookup Inconsistency

Evidence:

- ARS broad and certify runs.
- `R10`: NIP-05 `nostr.json` did not resolve after registration.
- `R16`: lookup active registration by npub returned empty/inactive data.
- `R11`, `R12`, `R13`: delete/reactivation flows were blocked by rate-limit errors.

Likely server journey:

1. Registration setup succeeds for early cases (`R01` through `R09` passed).
2. Later registration/lifecycle requests hit rate limits or return inconsistent lookup data.
3. `nostr.json` and LNURL metadata paths share lookup behavior but may diverge in rate-limit or active-status handling.

Server conclusion:

- Some lifecycle failures are contaminated by rate limiting.
- `R10` and `R16` still deserve direct server investigation because they point at lookup/index/status inconsistency.
- Certification cannot reliably distinguish lifecycle bugs from rate-limit protection until server supports a safe test/certification allowlist.

Likely code areas:

- `src/registration.rs`
- `src/nostr.rs`
- `src/lnurl.rs`
- `src/db/users.rs`
- `src/rate_limit.rs`

## Dossier D: Liquid Callback / Last-Unused Address Behavior

Evidence:

- ARS broad and certify runs.
- `C01`: liquid callback returns valid onchain address failed with `NymNotFound`.
- `C02`: repeated unauthenticated liquid callbacks must not burn distinct indices failed before address response.
- `C08`: repeated liquid callbacks return same last-unused address failed because zero successful callbacks were observed.

Likely server journey:

1. Test attempts LNURL/Liquid callback for a registered nym.
2. Server returns `NymNotFound`.
3. Last-unused semantics cannot be assessed because the nym was not resolved.

Server conclusion:

- The first question is not whether last-unused is correct; it is why the callback lookup did not resolve.
- Once lookup is fixed or isolated from setup contamination, last-unused behavior should be checked for index burn, address reuse safety, and concurrency.

Likely code areas:

- `src/lnurl.rs`
- `src/chain_watcher.rs`
- `src/db/watcher.rs`
- `src/db/users.rs`

## Dossier E: Wrong Binary Deployment

Evidence:

- `bullnym-run-1779153846-liquidv2.json`
- All 22 Liquid scenarios failed almost instantly.
- Failures included signed invoice auth errors and anonymous checkout internal errors.
- Rollback and correct `bullnym/main` deploy were followed by successful `LQ-01` smokes.

Likely server journey:

1. A stale/incompatible binary was deployed.
2. Server accepted traffic but did not match current client/test signing and route expectations.
3. `/health` was insufficient to detect wrong build provenance.
4. Product paths failed until rollback/correct deploy.

Server conclusion:

- `health = ok` is not enough.
- Bullnym needs build/version/schema provenance visible at runtime and deployment should gate on it.

Likely code areas:

- `src/main.rs`
- build/deploy scripts outside this repo if present
- CI/release artifact generation

## Dossier F: Successful High-Volume Lightning

Evidence:

- `bullnym-run-1779127807-lnstorm-count-20-concurrency-1-amount_msat-100000-prefix-jungle20seqb.json`
- `bullnym-run-1779128114-lnstorm-count-90-concurrency-1-amount_msat-100000-prefix-jungle90seq.json`

Likely server journey:

1. Server repeatedly creates or resolves LN payment requests.
2. Jungle pays sequentially.
3. Bullnym/Boltz settlement progresses to terminal success.
4. Repeated sequential payment path stays healthy through 90 payments.

Server conclusion:

- This path works well enough to move to smoke-only unless LN/Boltz settlement code changes.
- It still reveals optimization opportunities: batch observability, lower-polling status checks, and clearer per-payment correlation.

Likely code areas:

- `src/invoice.rs`
- `src/claimer.rs`
- `src/reconciler.rs`
- `src/boltz.rs`


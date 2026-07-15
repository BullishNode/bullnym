# Bullnym Operator Manual

This manual is an operational guide, not permission to deploy or change money
state. Use the current approved deployment runbook and change authority for
every production action. Never bypass readiness, admission, recovery, or
integrity gates.

## Evidence and release status

This revision deliberately separates source behavior from deployed behavior:

| Label | Meaning |
|---|---|
| **Deployed baseline** | Verified by a read-only probe of `https://pay2.bull-wallet.com` at 2026-07-15 04:23–04:26 UTC. |
| **Release candidate** | Implemented and tested at the exact source revision below, but not yet merged, installed, or production-certified. |
| **Deployed release** | Use this label only after the final merge commit, artifact and PWA digests, schema marker, running-process digest, and public certification all agree. |

Exact revisions used for this manual:

- deployed baseline: `512fb32b9fec31702b1260314427df4420f8e27c`, clean build, schema `060_lnurl_private_comment_intents`;
- merged candidate base: `746444166a41f2a42faa8bc0615c423150ac3c6f`, tree `78b04ae8f21e254d662ee13ba4147adab17fc556`;
- PR #177 candidate: `fa0003d95ce42620dbb217e4bbc70257959503e0`, tree `ea0f3cc80bb50ac2e87085cd31fa64c3259eaea8`, expected schema `062_invoice_quote_provider_attempts`.

The baseline public probe returned `200` for `/health`, `/ready`, `/version`,
`/api/v1/supported-currencies`, and `/api/v1/rate?currency=USD`.
`/ready` reported database and schema healthy. `/version` reported the baseline
commit above, `build_dirty: false`, production mode, and
`public_name_policy: permanent_names_v1`.

PR #177 is the complete server/PWA release candidate described by this manual.
It combines a 30-day outer invoice lifetime with immutable five-minute
payer-demand quotes, one stable direct-Liquid destination per invoice,
first-observation fiat valuation, atomic PWA refresh, PoS Bitcoin risk
acknowledgement, durable provider-attempt recovery, and schema 062 readiness.
It also carries forward the current-only automatic-recovery and permanent-name
contract from its merged base. It does not restore the tokenless LNURL callback,
legacy Payment Page media fields, or legacy payout/surface modes.

At the time of writing, the candidate is not a production capability. Its
local Rust, PWA, migration, recovery, and certification fault gates are source
evidence; final hosted CI, merge, fresh-database cutover, artifact installation,
and post-install certification remain release operations. Until all of those
complete, a production result that still exposes the seven-day/single-conversion
behavior is a candidate-not-deployed condition, not a regression in the
baseline release.

Before relying on this manual, repeat the provenance probes and compare the
result to the immutable release record. Do not infer deployment from a pull
request, branch name, schema table, or documentation commit.

## Architecture and trust boundaries

Bullnym is a Rust/Axum payment coordinator with PostgreSQL durability, Svelte
Payment Page and PoS applications, Boltz integration, Liquid Electrum
observation, and a Bitcoin mempool-compatible backend.

```text
merchant wallet/client ---- signed HTTPS ----+
                                              |
payer wallet ------------ public HTTPS ---- Bullnym ---- PostgreSQL
                                              |
                         +--------------------+------------------+
                         |                    |                  |
                       Boltz          Liquid Electrum     Bitcoin API
```

The merchant retains wallet spending keys. Bullnym stores descriptors,
addresses, invoices, payment evidence, swap-specific keys, exact transaction
evidence, and provider-recovery material. This is non-custodial coordination,
but it is not trustless: a compromised coordinator can issue dishonest payment
instructions, leak linkage, or mishandle a swap. The payer cannot independently
prove that a destination belongs to the merchant.

Trust boundaries operators must preserve:

- PostgreSQL is the durable coordination boundary, not provider status or an
  in-memory worker state.
- Boltz responses are inputs. Independent chain evidence is required for money
  conclusions.
- The off-host encrypted swap manifest is an independent stale-restore witness,
  not another active database.
- The server may hold swap-specific claim/refund keys. It must never receive the
  merchant wallet seed, descriptor spending keys, or recovery-address private
  key.
- A public invoice UUID is a bearer-readable capability. Logs and tickets must
  not include complete private URLs, signatures, comments, or payment secrets.
- An integrity hold preserves an obligation and stops unsafe automation. It is
  not a treasury payout or permission for an operator to guess.

## Application, database, and test VM roles

Keep the three operational roles separate:

| Role | Responsibility | Must not do |
|---|---|---|
| Application VM | nginx, `bullnym.service`, verified `pay-service` binary, matching PWA assets, workers, immutable release records, local generated OG files | Own production tables, apply privileged migrations as the runtime role, or host simulator wallet secrets |
| Database VM | PostgreSQL durability, backups, restricted runtime role, distinct privileged schema owner | Serve public traffic or give `bullnym_app` ownership/DDL authority |
| Test VM | `bullnym-tests`, `getpaid-e2e`, simulator wallets, reports, recycler, bounded acceptance traffic | Deploy Bullnym, use non-test funds, or reuse production secrets |

The documented production topology uses service `bullnym.service`, repository
`/opt/bullnym/bullnym`, binary `/usr/local/bin/pay-service`, active record
`/opt/bullnym/release.json`, immutable records under `/opt/bullnym/releases`,
and backups under `/opt/bullnym/backups`. Confirm these paths against the saved
runbook; do not invent substitute hosts or credentials.

Long-running simulation should use a separate directory such as
`/opt/bullnym-tests-soak` and a distinct service, logs, configuration, container
names, ports, volumes, and temporary files. It must not overwrite or disturb
`/opt/bullnym-tests`.

## Configuration and secrets

`config.toml` is non-secret policy. Production secrets belong in protected
environment files or a secret manager. At minimum, treat these as critical:

- `DATABASE_URL` for the restricted runtime role;
- `SWAP_MNEMONIC`, which derives swap-specific key material;
- manifest encryption/signing material and key identifiers;
- Boltz webhook path secret and provider credentials;
- certification tokens;
- wallet seeds, JWTs, signatures, comments, and complete invoice URLs.

Secret files must be root-owned, mode 0600, regular non-symlink files. The
runtime DB credential and privileged schema-owner credential must be distinct;
`bullnym_app` must not own protected tables or be able to assume the owner role.
Do not print an environment file, `DATABASE_URL`, mnemonic, private key,
webhook URL, or bearer token during diagnostics.

Review configuration for feature gates, worker enablement, rate limits, trusted
proxy handling, certification scope, public base URL, PWA/OG paths, Boltz and
chain endpoints, fee sources, retry cadence, and direct-rail finality. Explicit
invalid values are errors. A broken database/key/schema foundation prevents
normal startup. Invalid rail-specific configuration closes new admission for
that rail while safe existing-obligation work continues. Optional presentation
failure, such as OG rendering, should fall back without taking payment routes
down.

Never use the IP whitelist or certification token to bypass money admission.
They do not authorize a payment instruction when a rail is unsafe.

## Health, readiness, version, and provenance

Run public checks without leaking headers or secrets:

```bash
base=https://pay2.bull-wallet.com
curl --fail --silent --show-error "$base/health"
curl --fail --silent --show-error "$base/ready" | jq .
curl --fail --silent --show-error "$base/version" | jq .
```

Interpret them separately:

- `/health` proves only that HTTP is alive.
- `/ready` proves database access and exact schema/runtime journal boundaries.
  It deliberately does not expose private per-rail admission details.
- `/version` binds the public build commit, dirty state, runtime mode, schema
  marker, and public-name policy. It does not expose full dependency identity.
- `pay-service --build-info` and startup logs provide the operator-only Bullnym,
  Boltz, toolchain, target, profile, and PWA identity.
- The installed binary SHA-256 must match the immutable release record before
  promotion.

A healthy `/ready` does not mean every rail will admit new money. Check private
`money_admission_changed` and
`money_admission_creation_circuit_changed` transitions and use a non-money
certification preflight. An admission refusal is expected safety behavior when
a dependency, fee policy, recovery commitment, or worker is not ready.

## Build, deployment, cutover, and rollback

Deployment principles:

1. Start from a clean exact commit. Remove local Cargo path overrides.
2. Run `scripts/release-preflight.sh`; build only with
   `scripts/build-release.sh`.
3. When PWA source changes, rebuild and verify `pwa/dist`; binary and PWA are
   one release identity.
4. Preserve the staged binary and release record. Verify its digest.
5. Stop writers when the migration boundary requires it, take and validate a
   fresh database backup, and apply migrations with the distinct schema owner.
6. Deploy one version across all instances. Never run mixed writers across a
   signed-contract or migration boundary.
7. Verify loopback and public health/readiness/version, release digest, worker
   startup, non-money public surfaces, and logs before promotion.
8. Observe at least one reconciler cycle after promotion.

For the PR #177 candidate, the expected schema marker is exactly
`062_invoice_quote_provider_attempts`. Run the read-only certification both
against the staged release and after installation:

```bash
scripts/certify-deployment.py \
  --repo-root /path/to/exact-clean-bullnym \
  --release-record /path/to/pay-service.release.json \
  --binary /path/to/pay-service \
  --pwa-dir /path/to/pwa/dist \
  --base-url https://pay2.bull-wallet.com \
  --expected-commit "$EXPECTED_BULLNYM_COMMIT" \
  --expected-artifact-sha256 "$EXPECTED_ARTIFACT_SHA256" \
  --expected-pwa-sha256 "$EXPECTED_PWA_SHA256" \
  --expected-schema-marker 062_invoice_quote_provider_attempts
```

Supply the commit actually embedded in the candidate artifact. After merge,
do not substitute the reviewed PR head when the release was built from a
different merge commit. The preflight is deliberately read-only and cannot
prove worker health, private rail admission, or a safe money journey; retain
those as separate gates.

Migrations 050, 051, 053, 057, 059, and 060 have explicit stopped-writer or
roll-forward constraints documented in `docs/operations/deployment.md`.
Migrations 061 and 062 are privileged-owner migrations and must receive the
reviewed `runtime_role` value. Migration 061 alone is only the immutable quote
foundation. The matching schema-062 candidate activates the current-only
denomination rules, first-observation valuation, provider-attempt journals,
runtime ACLs, and readiness boundary. Never infer product capability from a
table's existence alone.

At candidate source `fa0003d95ce42620dbb217e4bbc70257959503e0`, migrations
058 and 059 are current-only empty-state guards: they require all user, surface,
invoice, swap, allocation, and returned-address history to be empty before
creating the permanent-name registry and removing pre-launch fields. Migration
062 likewise refuses to fabricate monetary authority for incompatible legacy
fiat or quote rows. The deployed schema-060 marker does not prove any of these
candidate boundaries. Do not apply rewritten migrations to an existing
database; use only the approved stopped-writer fresh-database cutover and exact
complete migration sequence through `062_invoice_quote_provider_attempts`.

Do not start the candidate against schema 061, and do not reopen traffic merely
because schema 062 applied. Require the matching binary/PWA identity,
`/health`, `/ready`, `/version`, worker starts, private admission evidence, and
the read-only certification preflight. Once schema-062 quote or provider-attempt
history exists, an older writer cannot safely interpret it; fix forward, or
restore the complete pre-cutover database and its matching release while all
writers remain stopped.

The locked program permits a fresh-database cutover because the product has no
users, but that is an exceptional release decision, not routine maintenance.
Before a reset, stop all writers, capture exact release/schema/row counts,
preserve immutable monetary and recovery evidence for any existing test
obligation, take a verified backup, prove the target really is the approved
empty deployment, and retain the rollback/fix-forward record. Never erase rows
to satisfy a migration precondition or conceal an unresolved obligation.

Rollback principles:

- A binary rollback cannot undo provider or chain mutations.
- Do not roll the database backward blindly.
- Check schema and durable journals before starting the older binary.
- If a roll-back gate refuses, leave the service in the runbook-defined safe
  state and fix forward. Never delete transition, lineage, comment, manifest,
  or cooperative-signing evidence to force compatibility.
- Reconcile every in-flight swap before and after a version change.

## Backup and restore verification

A usable recovery set includes PostgreSQL, `SWAP_MNEMONIC`, manifest
signing/encryption material, immutable release records, PWA identity, generated
OG storage or its rebuild plan, and the independent off-host manifest store.
Keep database and key backups separately protected.

For every backup:

1. Record Bullnym SHA, schema marker, database snapshot time, manifest
   high-water, and active root/epoch without recording secrets.
2. Verify the archive can be listed and restored into an isolated database.
3. Run all migrations or the exact rollback-safe target against the restored
   copy.
4. Run the protected runtime-boundary probes with disposable roles.
5. Verify `swap_key_allocations`, legacy high-water, both swap tables,
   `swap_key_seq`, recovery commitments, transaction attempts, merchant
   settlement evidence, manifest delivery, and comments remain coherent.
6. Compare PostgreSQL, the signed off-host manifest set, validated Boltz xpub
   restore data, and independent chain evidence.
7. Keep new affected swap admission closed until the active root/epoch and next
   index are proven safe and every missing obligation is reconstructed or held.

A sequence rewind is repaired only after independent evidence. Never lower the
sequence, invent lineage for a legacy row, or merely advance the counter while
forgetting a missing swap.

## Rates, payer amounts, and fee authority

The public fiat endpoints expose supported currencies and fresh rate evidence:

```bash
curl --fail --silent --show-error \
  https://pay2.bull-wallet.com/api/v1/supported-currencies | jq .
curl --fail --silent --show-error \
  'https://pay2.bull-wallet.com/api/v1/rate?currency=USD' | jq .
```

Validate pair, currency, precision, positive finite rate, source,
`observed_at_unix`, `fetched_at_unix`, and the exclusive expiry. An unexpired
last-known-good observation may be used only within policy. When no trustworthy
fresh rate exists, pause new fiat quote creation; do not guess.

The schema-062 candidate keeps a fiat invoice's currency and minor-unit face
value as its only denomination authority; `amount_sat` remains zero. A payer
explicitly selects one rail with `POST /api/v1/invoices/:id/quote`. Status and
other GET requests are projections and must not allocate provider or monetary
state. A successful request creates or reuses one immutable rate snapshot with
an exact five-minute lifetime and returns one instruction bound to that
snapshot. The PWA retires every displayed instruction at the exclusive expiry,
disables QR/copy while replacement is pending, rejects late responses from a
retired version, and publishes the replacement amount, cost, QR, and copy value
as one unit.

Instruction authority differs by product and rail:

- direct Liquid reuses the invoice's one settlement address for its full outer
  life, up to 30 days; each refreshed quote changes amount/rate metadata, never
  the destination, and creates no guessed provider-offer identity;
- wallet-origin direct Bitcoin uses the merchant's invoice-scoped Bitcoin
  address and does not call Boltz merely to price a fiat instruction;
- Payment Page and PoS Bitcoin remains a Boltz BTC-to-LBTC chain swap;
- Lightning remains a Boltz reverse swap; provider-backed Bitcoin and
  Lightning persist exact quote, offer, and swap attribution.

For direct outputs, durable first observation is valuation authority. Sats
first observed before a quote's expiry retain that quote only for those sats.
Sats first observed at or after expiry require a distinct freshness-proven
snapshot that covered that observation boundary. If no such snapshot can be
made, retain the payment and observation as visible but unvalued/in-progress;
do not borrow a later rate. Reorg or replay changes active accounting state,
not the immutable event valuation evidence.

Transaction fees are construction-time authority, not the public Bullnym
`/api/v1/rate` endpoint:

- Bitcoin uses the configured mempool-compatible base joined to exactly
  `/v1/fees/precise`, yielding the public contract
  `https://mempool.space/api/v1/fees/precise`. Validate `fastestFee` and
  `minimumFee` in sat/vByte. Do not fall back to `/fees/recommended`.
- Liquid uses a compatible Esplora `/api/fee-estimates` response and target
  `"1"`, also in sat/vByte.
- Try compatible live sources, then only a recent persisted same-rail
  last-known-good observation. If none is valid, wait.
- Bounds reject unsafe quotes; they never become substitute fee rates.
- Persist source, observation time, rate, policy, and actual constructed fee.
  Never mutate already-journaled transaction bytes because the market moved.

For fixed checkout, the payer covers the merchant face value plus applicable
provider and payment-network costs. Rail payer amounts can differ. A source
wallet may add its own Lightning routing or funding transaction fee. Lightning
Address is a sender-chosen LNURL product and is outside fixed-checkout gross-up.

## Boltz admission and provider failure

The creation circuit covers new provider-dependent offers only. The deployed
policy uses five consecutive transport-class failures, a 30-second open
interval, and one half-open probe. It must not block status, claims,
reconciliation, recovery, or healthy direct Liquid.

Classify provider outcomes:

- transport timeout, DNS/connect failure, HTTP 429, or 5xx: transient provider
  failure; admission may shed new work after hysteresis;
- expected business 4xx: request outcome, not provider-outage proof;
- malformed or money-unsafe response: immediate safety refusal;
- timeout after a provider mutation: ambiguous; reconcile before retrying;
- expired offer: retain and supervise it because a payer may use copied
  instructions later.

For schema-062 quote-scoped provider creation, PostgreSQL records the canonical
request authority and key allocations before any network mutation. It then
records the one-way dispatch boundary before the POST, and commits provider
completion together with the quote offer and swap. A process that finds a
dispatched but incomplete attempt does not own another POST: it restores and
validates the provider result, or writes a durable integrity hold.

The candidate can reconstruct chain-create results only from validated Boltz
xpub restore evidence matching the persisted request. The pinned reverse-swap
restore response does not carry the original BOLT11, so an ambiguous reverse
create cannot be completed by guessing; it remains held. Treat
`provider_outcome_unknown`, absent/unavailable restore, incomplete restored
response, and invalid restored response as evidence-preserving safety states.
Do not delete a dispatch or hold row to make another create request possible.

Never turn retry exhaustion, a provider status, or missing evidence into proof
that Bitcoin fallback is safe. Ordinary Liquid claim wins. Wrong/late funding
tries safe renegotiation. Incomplete or conflicting evidence remains pending or
enters integrity hold.

## Watchers, scheduling, and backlog

Bitcoin and Liquid direct watchers use deterministic recent and historical
lanes. Recent, partial, and settling invoices receive most capacity; a reserved
share covers expired, cancelled, archived, and old targets. Cursors survive
restart, but a new process must prove its own full startup traversal before its
dependent admission opens.

Monitor:

- last successful cycle and duration for every worker;
- recent/historical backlog count, oldest due time, and lane lag;
- frozen lane start, persisted cursor progress, wraps, and no-progress pages;
- reconcilers, settlement repair, slow recovery, fee refresh, manifest
  delivery/audit, OG repair, and GC;
- database pool pressure and worker task exits.

Mempool evidence can drive immediate presentation. Direct accounting activates
at one confirmation and reaches configurable finality at three Bitcoin or two
Liquid confirmations by default. A regression/reorg demotes evidence without
deleting history. Lightning Address Liquid cursor advancement requires
confirmed history; mempool-only dust must not permanently advance it.

## Settlement, recovery, and integrity holds

Payment presentation and settlement are different facts. “Payment received”
can be shown while confirmation, swap claim, or fallback remains pending.

For a stuck obligation, preserve and reconcile:

1. complete invoice, swap, observation, event, attempt, and settlement rows;
2. provider response/status;
3. exact raw Bitcoin/Liquid transactions, outputs, blocks, outspends, and
   confirmation history;
4. manifest and derivation evidence;
5. worker logs and release provenance.

Never clear exact transaction hex/txid, swap keys, destination commitments,
or attempt history. A known committed transaction may be rebroadcast as
identical bytes. An unknown spend, crossed destination, ambiguous provider
mutation, or disagreeing chain backend is an integrity hold—not permission to
rebuild or switch outcomes.

Chain-swap fallback is automatic and uses the exact merchant Bitcoin address
commitment copied onto the swap before payer exposure. It is not a late address
choice. Normal Liquid settlement and safe renegotiation have priority. Existing
recovery continues when admission of new payments is closed. RBF execution is
not part of the initial locked release; a stuck priority-priced transaction is
watched and identically rebroadcast, not silently fee-bumped.

Cancellation stops issuing new instructions. Archive is presentation-only.
Neither ends observation. Late, partial, overpaid, expired, cancelled, failed,
or reorged money stays attached to the original invoice and remains visible.
Do not auto-refund merely because a payment is late.

## Logs, alerts, and incident diagnosis

There is no documented public metrics endpoint. Treat structured logs and
database/backlog queries as the current observable contract; use private
metrics only when the deployed release record documents them.

```bash
sudo systemctl status bullnym.service --no-pager
sudo journalctl -u bullnym.service --since '30 minutes ago' --no-pager
sudo /usr/local/bin/pay-service --build-info | jq .
```

Do not paste unredacted output into a public issue. Sanitize URLs, comments,
descriptors, signatures, raw transactions, provider payloads, and identifiers
that link payers to merchants.

Page immediately on:

- claim/refund conflict or unknown spend;
- a funded obligation whose retry schedule is not advancing;
- provider/database/chain disagreement about a terminal state;
- repeated settlement-repair or manifest-delivery failure;
- worker exit, pool exhaustion, or sustained watcher backlog growth;
- unexplained wallet/recycler discrepancy;
- public cache or log leakage of private comments or invoice details.

Practical read-only database triage begins inside a repeatable-read, read-only
transaction. Query only the affected invoice and swap rows and preserve the
result as restricted incident evidence. Use the maintained
`docs/operations/runbooks/stuck-swaps.md`; do not improvise state-changing SQL.

After opening the approved protected read-only database connection, set the
invoice UUID as a local `psql` variable and capture a bounded snapshot:

```sql
\set invoice_id '00000000-0000-0000-0000-000000000000'

BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;

SELECT id, status, presentation_status, settlement_status,
       paid_via, paid_amount_sat, expires_at
  FROM invoices
 WHERE id = :'invoice_id';

SELECT rail, event_key, amount_sat, accounting_state, created_at
  FROM invoice_payment_events
 WHERE invoice_id = :'invoice_id'
 ORDER BY created_at, event_key;

SELECT rail, source, txid, vout, amount_sat, confirmations,
       last_seen_state, first_seen_at, last_seen_at
  FROM invoice_payment_observations
 WHERE invoice_id = :'invoice_id'
 ORDER BY first_seen_at, event_key;

SELECT id, boltz_swap_id, status, claim_txid,
       next_claim_attempt_at, next_slow_attempt_at, updated_at
  FROM swap_records
 WHERE invoice_id = :'invoice_id'
 ORDER BY created_at, id;

SELECT id, boltz_swap_id, status, claim_txid, refund_txid,
       next_claim_attempt_at, next_slow_attempt_at, updated_at
  FROM chain_swap_records
 WHERE invoice_id = :'invoice_id'
 ORDER BY created_at, id;

SELECT attempt.chain_swap_id, attempt.purpose, attempt.txid,
       attempt.status, attempt.broadcast_attempts,
       attempt.first_broadcast_attempt_at, attempt.confirmed_at,
       attempt.finalized_at, attempt.integrity_hold_at,
       attempt.updated_at
  FROM chain_swap_tx_attempts AS attempt
  JOIN chain_swap_records AS swap ON swap.id = attempt.chain_swap_id
 WHERE swap.invoice_id = :'invoice_id'
 ORDER BY attempt.constructed_at, attempt.id;

SELECT attempt.id, attempt.quote_version_id, attempt.rail,
       attempt.operation, attempt.created_at,
       dispatch.dispatched_at, completion.completed_at,
       hold.reason AS integrity_hold_reason, hold.held_at
  FROM invoice_quote_provider_attempts AS attempt
  LEFT JOIN invoice_quote_provider_dispatches AS dispatch
    ON dispatch.provider_attempt_id = attempt.id
  LEFT JOIN invoice_quote_provider_completions AS completion
    ON completion.provider_attempt_id = attempt.id
  LEFT JOIN invoice_quote_provider_integrity_holds AS hold
    ON hold.provider_attempt_id = attempt.id
 WHERE attempt.invoice_id = :'invoice_id'
 ORDER BY attempt.created_at, attempt.id;

ROLLBACK;
```

This snapshot intentionally omits raw transaction bytes, addresses, comments,
signatures, descriptors, and provider payloads. Retrieve those only into a
restricted incident artifact when they are necessary. Never use an application
runtime connection as a reason to grant new diagnostic privileges.

The persisted watcher rotation can be inspected without treating it as worker
health:

```sql
SELECT worker, lane, cursor_created_at, cursor_invoice_id, updated_at
  FROM watcher_lane_progress
 ORDER BY worker, lane;
```

Compare that rotation evidence to current-process startup/cycle logs. A recent
cursor timestamp does not prove that the current process completed a healthy
full lane traversal.

## Test suites, soak, and real-money acceptance

Use layers rather than one “all tests” result:

| Layer | Purpose |
|---|---|
| Bullnym library and integration tests | Domain, migration, concurrency, fault, privacy, and runtime-role behavior |
| PWA tests | Browser state, payload consistency, accessibility, cache behavior |
| `bullnym-tests` | Deployed server/API, adversarial, wallet, recycler, and real-rail behavior |
| `getpaid-e2e` | Mobile/application process behavior and deterministic failure matrices |

Server gates from a clean source tree include:

```bash
cargo test --lib
cargo test --tests --no-run
scripts/test-db.sh
scripts/check-docs.sh
scripts/test-release-provenance.sh
scripts/test-release-record.sh
scripts/release-preflight.sh
(cd pwa && npm ci && npm test && npm run build && npm run check:dist)
```

Every report must record deployed SHA, source/test SHA, dirty state, schema,
seed, actors, actions, and capability detection. An unavailable or undeployed
feature is blocked/skipped with evidence, never called a server failure or pass.

The test VM supports focused no-funds and real-money journeys. Before live
testing, inventory every simulator-controlled wallet balance without printing
secrets, set an aggregate sat budget, verify the destination is simulator
controlled, and prove the recycler can recover each funded actor wallet. Stop
if those conditions are not true.

Current harness commands include:

```bash
cargo run --release -- recycle-wallets --dry-run
cargo run --release -- recycle-wallets
cargo run --release -- --server https://pay2.bull-wallet.com ars run-minimal
```

The existing README contains older target examples; override the server to the
exact authorized host and use the branch-specific help before running. Never
run the legacy mixed `all` command as certification.

A soak should be seeded, checkpointed, resumable, bounded, and supervised. It
must retain actor-to-wallet mapping, current scenario, action history, in-flight
provider obligations, expected fees/losses, and idempotency keys. On restart it
must not duplicate sends. Keep implementing and diagnosing while a soak runs;
do not let a long process become unobserved.

## Recycler and test-wallet accounting

Maintain a per-actor ledger with opening balance, transfers, payments,
provider/network fees, closing balance, expected loss, and unexplained delta.
Secrets stay in mode-0600 files outside Git.

The recycler must:

- identify every simulator wallet and owning actor;
- rebalance before a journey and reclaim after it;
- retain funds committed to in-flight swaps;
- use durable operation IDs so a crash cannot repeat a send;
- distinguish expected provider/network fees from unexplained loss;
- resume an ambiguous operation by transaction/provider evidence rather than
  creating another transfer.

The existing harness includes recipient-wallet sweeps and a Liquid-to-Lightning
Boltz recycler. Do not assume that makes a newly created actor wallet safely
reclaimable. Add or verify the required recycler path in the test repository
before funding it. If a recycler swap becomes ambiguous, preserve the swap ID,
refund key material, lockup transaction, destination, and checkpoint; do not
start another transfer merely because the command timed out.

## Common failure checklist

| Symptom | First checks | Safe response |
|---|---|---|
| `/health` fails | process, listener, nginx, recent journal | keep traffic out; inspect artifact and startup failure |
| `/health` passes, `/ready` fails | DB reachability, schema marker, protected journal/runtime ACL | repair the dependency or fix forward; do not bypass |
| One rail returns 503 | private admission reasons, required worker, fee evidence, provider circuit, recovery commitment | treat as expected fail-closed behavior until the exact prerequisite recovers |
| Rate endpoint 503 | pricer freshness, pair/source validation, throttle | pause new fiat quotes; preserve existing obligations |
| Provider timeout during quote-offer creation | provider attempt, dispatch, completion, integrity hold, request digest, validated restore evidence | never repeat a dispatched POST blindly; restore, complete atomically, or hold |
| Provider timeout after accept/settlement mutation | persisted intent, provider lookup, manifest/delivery state | reconcile; do not create a second obligation blindly |
| Watcher backlog grows | lane cursors, no-progress pages, backend errors, pool pressure | restore worker/backend progress; do not drop historical targets |
| `claim_stuck` | exact attempt, provider and chain evidence, slow-recovery schedule | restore dependency and let idempotent recovery continue |
| `refund_due` | fallback eligibility, committed address, source/server-lock evidence, fee decision | allow automatic executor only after positive under-lock recheck |
| `refunding` after timeout | journaled bytes/txid and source outspend | reconcile or identically rebroadcast; never rebuild from guesswork |
| Payment after cancel/expiry | original invoice and late event | keep request closed, preserve and surface payment; do not auto-refund |
| Reorg/demotion | block/hash regression and exact output | retain history, demote accounting, continue observation |
| Missing OG file | immutable key, local volume, worker retry | serve bundled fallback; payment routes remain available |
| Restore disagreement | DB, manifest, Boltz xpub, chain, root/epoch/high-water | close affected new admission and reconstruct or hold |

## Evidence sources

The operational claims above were checked against `README.md`, `SECURITY.md`,
`config.toml`, `src/config.rs`, `src/main.rs`, `src/readiness.rs`, migration
files 045–062, server and DB integration tests, the architecture/API/product
documents under `docs/`, the `bullnym-tests` README and recycler source, and the
locked completion-plan, rationale, and server/PWA gap-audit records maintained
outside this repository. Candidate-specific claims were checked at exact
source `fa0003d95ce42620dbb217e4bbc70257959503e0`.

Historical RFCs and older manuals are evidence only when current source and the
locked records still agree with them.

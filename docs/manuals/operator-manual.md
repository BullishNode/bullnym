# Bullnym Operator Manual

This manual is an operational guide, not permission to deploy or change money
state. Use the current approved deployment runbook and change authority for
every production action. Never bypass readiness, admission, recovery, or
integrity gates.

## Evidence and release status

This revision deliberately separates source, installation, and journey
certification evidence:

| Label | Meaning |
|---|---|
| **Historical deployed baseline** | Verified by a read-only probe of `https://pay2.bull-wallet.com` at 2026-07-15 04:23–04:26 UTC, before the schema-062 cutover. |
| **Deployment-certified schema-062 release** | The exact merged artifact, PWA, release record, running process, fresh schema, read-only deployment certification, startup recovery evidence, and observed private rail admission agree. |
| **Verified installed schema-063 release** | Through PR #185, migration 063, the exact verified release, running process, source, PWA, public version, startup recovery, and repeated fee refreshes agree. This proves deployment identity and readiness at the observed times, not the unfinished payment journeys. |
| **Current deployed source** | PR #185 exact main contains the final runtime fixes described below. Its exact artifact and active release record are verified, but deployment identity is not journey certification. |
| **Journey-certified production release** | Use this label only after the schema-063 no-funds smoke and bounded live-Liquid/recycler journey pass, and certification authority is removed with a clean final audit. Those results remain explicit placeholders below. |

Exact revisions used for this manual:

- historical deployed baseline: `512fb32b9fec31702b1260314427df4420f8e27c`, clean build, schema `060_lnurl_private_comment_intents`;
- reviewed PR #177 base: `746444166a41f2a42faa8bc0615c423150ac3c6f`, tree `78b04ae8f21e254d662ee13ba4147adab17fc556`;
- reviewed PR #177 head: `01fb3f08aeb69e44d1ce71dfd2111ecd63e23253`, tree `93f9f06f10d58520547a8d4d9ac85064c822fa07`;
- schema-062 release source: `e17c465939ccf766ebf77b7d9bd7dbfb776c395d`, tree `93f9f06f10d58520547a8d4d9ac85064c822fa07`, expected schema `062_invoice_quote_provider_attempts`;
- schema-062 binary SHA-256: `21628acc96d20475662898bbed851a48b4762c5d2b70b92ecc08910c46cd4873`;
- schema-062 active release-record SHA-256: `326dd87cbcd9fb1092acf9e2c193c1649920cb032a6c1cb780dc7e7f2d2c4163`;
- passed deployment-certification report SHA-256: `3586ad4a4d7c98975ec8a5a3460ca51c97cfa1030356473a7ded30f5165bc799`;
- first schema-063 release: PR #179 merge `fe36a8d1701416222a30670000978075b0b58196`, followed by PR #180 merge `f91cc7d1438079e8eca8c018ed3d64487f4264cf`, tree `8b5edaf6bcc93655ac37ae1f4e8fe56d6fd9accc`;
- first schema-063 exact-main CI: run `29407076211`, terminal success at 2026-07-15 10:33:38 UTC;
- first schema-063 deployed binary SHA-256: `2ab891a3c372cf5f619c0a702beb099bd5b80f447f571d2fb66c1c2a3a3c9a5b`;
- first schema-063 deployed release-record SHA-256: `652819a2c8a4e8812b1c8722b742aba200a8cee33ade69697b72fcb35b92de56`;
- prior schema-063 production source: PR #182 merge `0f459fff770d4eef24e7858b7c546e652846ed08`, tree `b0996999265fddaba1e3c5335aecf1ae7a6a4ed2`;
- prior verified installed production source: PR #183 merge `71203f082b8f09c7f257bc1cd53ba981f71924f2`, tree `3b5ce89b2e205f724f1969866534feba3e7e43c4`, expected schema `063_checkout_private_memo`;
- prior verified installed and running binary SHA-256: `d486bc2c311299c533c99f3005fe88a96ec36b77cda96f1652bbdf56914b97dc`;
- prior verified active release-record SHA-256: `f43abde09473e24f7ef55a96bd1c0fdb64510c5e3fd2b3b12cfa914a58ba88f5`;
- most recently verified PWA content SHA-256: `c193bf22ed5b7fbc0e0463cd8ea90b4154fdad660a77ea74ec0b6ec1e526d09c`;
- current deployed source: PR #185 merge `c026691cdede46cff56c9a34fade0fd4339bd5b7`, tree `203abc2352b7d06819e383b56c91b99f113633eb`, expected schema `063_checkout_private_memo`;
- final deployed PR #185 artifact SHA-256: `eb49032953177b4ff49c99f5e76743dd0d0b53bc4697b7b5d625516e91ffb325`;
- final active PR #185 release-record SHA-256: `4eaa7bb7221bad2c75e190f0cc4285519e19c4b1b6ea13c28bbb0bfcfc0ae131`;
- certification harness source: `65f46fa70fa41cd99f291a54af0970d5304a72cb`, clean, simulator SHA-256 `663613f01315390d1a59cdb179ccfcfd0def238635a2cc2d1c5b7a9984d3ecdd`;
- protected production configuration SHA-256 after the test-certification
  allowlist change: `1a9dbaf5c85ea1bbec0db81f8ccbedce1166c74ac78fd44a597e4fadf2f98385`; the forward deploy verified that configuration and the runtime environment were byte-preserved.

The historical baseline public probe returned `200` for `/health`, `/ready`, `/version`,
`/api/v1/supported-currencies`, and `/api/v1/rate?currency=USD`.
`/ready` reported database and schema healthy. `/version` reported the baseline
commit above, `build_dirty: false`, production mode, and
`public_name_policy: permanent_names_v1`.

At 2026-07-15 08:03 UTC, the stopped-writer fresh reset had applied all 62
migrations and the application VM installed the exact release above. Read-only
loopback and public probes returned `ok`, `/ready` reported `ready: true` with
healthy database and schema components, and `/version` reported the exact
installed commit, clean production build, schema
`062_invoice_quote_provider_attempts`, and permanent-name policy. The installed
file and running-process digests both matched the binary digest above, and the
checked-out PWA matched its recorded content digest.

Merged PR #177 is the complete server/PWA release source described by this
manual.
It combines a 30-day outer invoice lifetime with immutable five-minute
payer-demand quotes, one stable direct-Liquid destination per invoice,
first-observation fiat valuation, atomic PWA refresh, PoS Bitcoin risk
acknowledgement, durable provider-attempt recovery, and schema 062 readiness.
It also carries forward the current-only automatic-recovery and permanent-name
contract from its merged base. It does not restore the tokenless LNURL callback,
legacy Payment Page media fields, or legacy payout/surface modes.

At 2026-07-15 08:34 UTC, the new recovery generation reconciled with exact
all-zero startup counts. After the normal transient `startup_pending` state,
the exact deployed process opened `direct_bitcoin`, `lightning_reverse`,
`direct_liquid`, and `bitcoin_chain`, each with an empty reason-code set. A
separate read-only deployment certification also passed. These facts resolve
the recovery-generation, deployment-identity, and private-admission gates for
that restart; they do not make rail availability permanent.

The subsequent schema-062 no-funds smoke kept its funds gate closed, set its
maximum spend and broadcast count to zero, and passed its setup, metadata, and
registration stages. It then failed its first fiat Payment Page invoice at
stage S62-03 with `InternalError`. Production evidence identified the cause as
the `invoices_checkout_no_metadata_chk` database constraint rejecting the
valid private checkout note. No provider mutation, callback, broadcast, or
funds movement occurred. This is a failed journey, not a pending or passing
one, and the bounded live-money journey was not started.

The same post-deployment observation also found brief private-rail admission
closures during normal fee refresh. A new in-memory live snapshot generation
could become visible before its PostgreSQL persistence completed, so readiness
compared that pending generation with the prior persisted generation and
closed until persistence caught up. This was fail-closed, but it was an
availability defect rather than evidence that the fee sources were stale.

PR #179 merged both remediations. Migration
`063_checkout_private_memo` replaces the obsolete constraint so Page and PoS
checkout can persist a private `memo`, while `recipient_label`,
`public_description`, and `invoice_number` remain wallet-only. Its fee-runtime
change keeps only the prior fresh, source-authorized, explicitly restored
durable last-known-good decision eligible while a newer live generation awaits
durable acceptance. The pending live value is neither construction authority
nor a reason to close admission when that exact durable predecessor remains
valid. Missing, stale, unauthorized, or inconsistent durable evidence still
closes admission. PR #180 then made the anonymous checkout JSON contract
strict and aligned the 280-character note boundary with PostgreSQL Unicode
character semantics.

At 2026-07-15 17:55 UTC, the stopped writer captured the final schema-062
backup: 33 public tables, 66 public rows, dump SHA-256
`c2c84ff8fada68395839b9d558a391d0e3f413f83e781ab0c834a3c8767d5b4b`,
and backup-manifest SHA-256
`8c588d9efd2de4a0b928fb6dc43accff4f0a14e8145c6415e46051b3b5152c12`.
Migration 063 was then applied from exact migration SHA-256
`576855ef56613084769170082acca3322741a4187435117c04655818bafedd85`;
the permission catalog remained exact at
`8c33727be388cca894c4a5e9eeeb9757beb132b3ea421fe2b783e833a9a074c5`.
At 18:03 UTC the qualified installer activated exact `f91cc7d...`. The strict
18:03–18:04 UTC read-only APP/TEST/DB/public audit matched source, binary,
running process, release record, PWA, schema, health, readiness, and public
version. Three Bitcoin and three Liquid fee-refresh observations then passed
with zero bad samples and zero admission closures.

The first schema-063 no-funds attempt stopped and kept its funds boundary
closed when an unquoted fiat invoice projected its outer deadline as a rate
lock instead of the required zero sentinel. The accompanying startup work also
found that legitimate allocator-only reverse/orphan lineage was classified too
strictly. PR #182 fixes only those two production-observed boundaries. An
unquoted fiat invoice now reports `rate_minor_per_btc: null` and
`rate_locks_until_unix: 0`; sat-fixed invoices retain their outer deadline as
the sentinel. Recovery accepts allocator-only lineage only when chain-record
coverage is exact and the active-root provider/local high-water relation is not
provider-ahead. Missing local lineage, local-behind evidence, provider-ahead
state, unsafe chain inventory, and witness disagreement still fail closed.

At 2026-07-15 19:01 UTC, the qualified forward installer reran migration 063
as `already_applied`, fast-forwarded production from `f91cc7d...` to exact
`0f459fff...`, and activated that verified artifact. Startup
reported one consistent recovery pass, zero inconsistent passes, and zero
unavailable passes. Public `/version` reported exact `0f459fff...`, clean
production mode, schema `063_checkout_private_memo`, and permanent-name policy.
Three further Bitcoin and three Liquid fee-refresh observations passed with
zero bad samples and zero admission closures.

The next zero-spend run found a timestamp-contract defect before any funds
gate. PostgreSQL's direct floating-point epoch-to-`BIGINT` cast rounded some
fractional timestamps, so the API could advertise an exclusive deadline one
second later than the stored instant used by database comparisons. PR #183
replaced those projections with an explicit floor. Its exact merge
`71203f082b8f09c7f257bc1cd53ba981f71924f2` is the most recently verified
installed production source recorded above. This evidence establishes that
installation identity; it is not a final journey certificate.

The subsequent zero-spend run passed its earlier stages and then exposed the
first of two boundaries fixed by PR #185. The direct-payment watcher compared
the raw invoice expiry to `NOW()` while the rest of the accounting policy
allows a configured payment-grace interval. An empty post-expiry scan of an
evidence-free fiat invoice could therefore synthesize `underpaid` with null
paid fields and fail the database constraint, repeatedly preventing the batch
from advancing. Current merged source binds the exact grace interval in both
locked direct-payment projections and the legacy recorder. With no payment
evidence the invoice remains `unpaid` during grace and becomes `expired` after
grace; `underpaid` remains reserved for positive partial credit.

Production provider evidence also showed that the live fixed-checkout Boltz
create endpoint can accept the exact request `onchainAmount` and `pairHash` but
omit `onchainAmount` from its successful response. The pinned generic SDK type
required the echo and rejected that otherwise complete response. PR #185 adds
a fixed-checkout-only typed compatibility envelope: an omitted amount is
normalized from the immutable request authority. If the provider does return
the field, it must exactly match; explicit null, duplicate known fields,
malformed values, and request/response mismatches still fail closed. The
ordinary reverse-swap decoder remains strict, and no response can replace the
persisted request amount or pair hash.

PR #185 is merged at exact main
`c026691cdede46cff56c9a34fade0fd4339bd5b7`, tree
`203abc2352b7d06819e383b56c91b99f113633eb`. Its exact artifact is installed
and running with the active release record below; this manual does not yet
claim that it is journey-certified.

Its verified deployment digests are:

- final deployed PR #185 binary/artifact SHA-256:
  `eb49032953177b4ff49c99f5e76743dd0d0b53bc4697b7b5d625516e91ffb325`;
- final active PR #185 release-record SHA-256:
  `4eaa7bb7221bad2c75e190f0cc4285519e19c4b1b6ea13c28bbb0bfcfc0ae131`.

The final journey evidence and deliberately unresolved cleanup field in this
revision are:

- final no-funds schema-063 result: run
  `nofunds-c026691-20260715T213857Z` passed 12/12 with zero sats spent and
  zero broadcasts; log SHA-256
  `390d99c5541314f97913f262995a98dda5d0bb0dcf06eadfd7f6ae25748f5ec0`
  and report SHA-256
  `ab827e5124ea627c4176012cdafd17df8db0a2b3cf746864674788c0e0c78366`;
- final bounded live-Liquid/recycler result: successful run
  `live-liquid-c026691-fee400-20260715T220456Z` paid 500 sats by direct
  Liquid, incurred a 326-sat forward fee and a 191-sat recycler fee within
  the 1,800-sat cap, returned the principal, and left an aggregate wallet
  delta of exactly 517 sats; report SHA-256
  `f77577f1b2d91cdfd6708c8e6586af972d51bc913bec8a3e39a3dfec1aabaf67`
  and log SHA-256
  `b866387eb6de4f9ca1f78af47f5dd52c853431aa0bb3a24904c918a8a46315aa`.
  The preceding 250-sat cap refusal occurred before payment preparation and
  before any broadcast, so it was a preflight refusal rather than a failed
  payment;
- certification-authority removal and final APP/TEST/DB audit:
  `PENDING_FINAL_CERTIFICATION_CLEANUP_AUDIT`.

Deployment provenance is bound to the private cutover records by SHA-256:

- schema-062 backup result: `03bd3e456fe14511e60fb78a3656d7a92c332549e688524346c16e69764764c5`;
- schema-063 migration result: `8d2e74b52a6a1d6d44136e9f9fe8ea95e689b9d0d9b820617b35867accabe9d8`;
- first schema-063 install result: `4801ffd3eed9ec234ef4339612cc8d81e82f9f2b9fb58c2032a3d35dbcb796df`;
- first schema-063 read-only VM audit: `647495c4aeae5440231fd027e142df4b10cad3e9a55263f3520a89a83f1e62da`;
- upgraded TEST source/artifact result: `2070413969a10d8f77688d2e4395473889fc07e7bac80f079e00e36eadea4473`;
- TEST offline certification precheck: `c748b1f7a9ba5af889adcfd28d4d2640b116a8068ac58d7727fce8ce630ecb1a`;
- pre-hotfix APP/TEST/DB/public audit: `4a26ceadd14391a4d231f002692a800ef33f0c9761ca2523b45778c2069a877b`;
- exact hotfix forward-deploy result: `dbf3ff77f22efd5c1b25081f00f488c618db3a192a79924eaa63abe4fc92a457`;
- post-deploy public version response: `c006511c9e347ef0a70b5dc609411e39f0931dda42e8f292d388ac7311fa88bf`;
- each repeated post-install fee-cycle result: `254fbf35f7640a25ec1f81690b72e5de2a2f8130855bba0bfbd58e709ff69b8a`.

Do not infer current rail availability from `/ready` or from this manual;
inspect the current per-rail admission state.

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

For the installed PR #177 release, the expected schema marker is exactly
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

Supply the commit actually embedded in the release artifact. Do not substitute
the reviewed PR head for the merged release commit. The preflight is
deliberately read-only and cannot prove worker health, private rail admission,
or a safe money journey; retain those as separate gates.

For the installed cutover, this certification completed in `read_only` mode
with status `passed`. Its restricted report has SHA-256
`3586ad4a4d7c98975ec8a5a3460ca51c97cfa1030356473a7ded30f5165bc799`.
It moved no funds, called no provider, and made only public `GET` requests to
`/version`, `/health`, and `/ready`. Treat it as deployment-identity and public-
readiness evidence, not as schema-062 smoke or live-money certification.

The production marker is exactly `063_checkout_private_memo`. The most recently
verified installed identity is PR #185 merge
`c026691cdede46cff56c9a34fade0fd4339bd5b7`, artifact digest
`eb49032953177b4ff49c99f5e76743dd0d0b53bc4697b7b5d625516e91ffb325`,
active release-record digest
`4eaa7bb7221bad2c75e190f0cc4285519e19c4b1b6ea13c28bbb0bfcfc0ae131`,
PWA digest `c193bf22ed5b7fbc0e0463cd8ea90b4154fdad660a77ea74ec0b6ec1e526d09c`,
and this schema marker. Never reuse the schema-062 certification report as
proof of the current release, and never substitute merge or deployment
identity for a pending journey result.

The production configuration supports a narrowly scoped certification bypass
for exactly one allowlisted source, the TEST VM, and exactly these five scopes:

- `registration_setup`;
- `metadata_lookup`;
- `invoice_create`;
- `invoice_status`;
- `live_money_offer`.

The signed TEST-VM preflight proved the source, credential, configured scopes,
and requested scopes agreed with no missing scope. This bypass is separate
from the general production IP-rate-limit policy and does not bypass readiness,
private money admission, recovery, integrity holds, or value limits. Never
record the credential, its derivative values, or secret-bearing configuration
content in a manual, log, report, command line, or ticket.

Migrations 050, 051, 053, 057, 059, and 060 have explicit stopped-writer or
roll-forward constraints documented in `docs/operations/deployment.md`.
Migrations 061 and 062 are privileged-owner migrations and must receive the
reviewed `runtime_role` value. Migration 061 alone is only the immutable quote
foundation. The matching schema-062 release activates the current-only
denomination rules, first-observation valuation, provider-attempt journals,
runtime ACLs, and readiness boundary. Never infer product capability from a
table's existence alone.

Migration 063 is a fix-forward replacement of
`invoices_checkout_no_metadata_chk`. Apply it with the schema owner while the
application writer is stopped. The exact resulting constraint permits checkout
`memo` but still requires checkout `recipient_label`, `public_description`, and
`invoice_number` to be null. Schema-063 readiness verifies the constraint body;
merely retaining the old constraint name does not satisfy readiness.

At installed source `e17c465939ccf766ebf77b7d9bd7dbfb776c395d`, migrations
058 and 059 are current-only empty-state guards: they require all user, surface,
invoice, swap, allocation, and returned-address history to be empty before
creating the permanent-name registry and removing pre-launch fields. Migration
062 likewise refuses to fabricate monetary authority for incompatible legacy
fiat or quote rows. The historical schema-060 marker did not prove any of these
schema-062 boundaries. Do not apply rewritten migrations to an existing
database; use only the approved stopped-writer fresh-database cutover and exact
complete migration sequence through `062_invoice_quote_provider_attempts`.

Do not start the installed release against schema 061, and do not reopen traffic
merely because schema 062 applied. Require the matching binary/PWA identity,
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

The schema-062 cutover retained these restricted recovery records:

- the final pre-reset PostgreSQL set at
  `/opt/bullnym/backups/schema062-final-pre-reset-20260715T075659Z`, captured
  from schema `060_lnurl_private_comment_intents` with 27 public tables and
  3,755 rows; its `SHA256SUMS` digest is
  `4ddbe3e3a39dfdaa1510c8ef0bc983b4933c45320c07dcedf76b066db6dd3935`
  and its database dump digest is
  `39e15dacc9004a5ec770d1807f468b705da4631ab65f65a3e5f01963afe43af9`;
- the separately protected runtime supplement manifest has SHA-256
  `9dca49561cd7904ded145e1c82f5d1da9bc8870dc548454df0540dbe6b3b7f1f`;
- the stopped-MinIO physical snapshot at
  `/var/backups/bullnym-witness-minio/schema062-precutover-20260715T075737Z`
  has inventory SHA-256
  `0ef741ffeecbff656fcbfa415a3ac29fb5e87ee4ec9f238d97d9655e8af68691`,
  physical-tar SHA-256
  `94b4f6497f3b7bb85318b74aff7fb41d3b06358c21068cc313586796b5b3dcab`,
  and `SHA256SUMS` digest
  `72f13a17fa3895c8800037be0ccdbba100ea13b668f5818ac5f073172ac1aa99`.

These hashes identify restricted evidence; they are not restoration approval.
Never publish the archived environment files, object keys, database contents,
or secrets merely because their container hashes are documented here.

### Current-only recovery generation separation

A fresh current-only PostgreSQL generation must not be paired with a nonempty
active witness namespace from the retired database generation. A post-cutover
read-only inventory found 16 retained objects, 62,984 bytes, under the then
configured witness prefix, with inventory SHA-256
`0ba7f77a0b2e88fb2f7c712c68eb69ccacba057a807a8c9037be13f2bf807c8a`.
Those authenticated manifests reference merchant, invoice, Liquid-address, and
recovery-commitment rows that intentionally do not exist in the fresh database;
startup therefore fails closed instead of fabricating them.

The retired namespace remains preserved as immutable evidence. The current
runtime now uses the nonsecret generation prefix
`bullnym/schema062-e17c465-g1`; its scoped inventory contained zero objects.
The physical bucket does not need to be empty because the loader reads only the
configured `<prefix>/v1` namespace. Do not delete retained evidence or bypass
retention to force an empty result.

An empty witness namespace is necessary but not sufficient. Startup also
validates the Boltz restore set for the xpub derived from `SWAP_MNEMONIC`. For a
fresh database, require all three active sources to describe the same empty
current generation: zero witness manifests, zero local swap/recovery inventory,
and a validated provider response with no records and restore index `-1`. If
the retired provider records remain visible under the existing xpub, rotate the
mnemonic before accepting current-generation money; keep the old mnemonic in
the restricted retired recovery set. New witness encryption/signing material
and credentials can make a generation boundary clearer. For this empty-prefix
cutover, the existing signing and encryption keys were retained after the
scoped inventory and provider restore both proved empty; key reuse is not a
substitute for that proof.

The one-shot auxiliary validator used during the cutover has SHA-256
`d104a24e2b8cc1aa7b78592d1b0b72cb6643ef13cef0a7db11578bd88cf56f5a`.
It parsed the protected runtime with the installed source, listed only the
active prefix, and used the exact release's Boltz restore adapter. It emitted
only nonsecret identity and count evidence. This locally built validator is
supporting evidence, not the deployed release artifact or the sole admission
authority.

The authoritative deployed `startup_provider_recovery_consistent` event at
2026-07-15 08:34 UTC reported exact zero values for every recovery field:

- `repaired_obligation_count`, `reconstructed_chain_swap_count`, and
  `reconstructed_delivery_count`;
- `manifest_count`, `provider_record_count`, `provider_chain_record_count`,
  `local_record_count`, and `local_chain_inventory_count`;
- `current_v1_chain_record_count`, `complete_legacy_chain_record_count`, and
  `chain_observation_count`;
- `chain_missing_manifest_count`, `chain_unconfirmed_manifest_count`,
  `chain_confirmed_manifest_count`, `chain_spent_manifest_count`,
  `chain_conflicting_manifest_count`, and
  `chain_amount_mismatch_manifest_count`.

The active-prefix inventory independently reported zero witness objects and
zero provider records with no provider maximum child index. After this event,
the same exact restart observed `direct_bitcoin`, `lightning_reverse`,
`direct_liquid`, and `bitcoin_chain` transition open with empty reason-code
sets. The event was reproduced on a later restart. These observations prove
empty-generation startup and private admission at those instants; a healthy
`/ready` alone does not, and any rail can close again when its foundations
degrade.

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

Current merged schema-063 source keeps a fiat invoice's currency and minor-unit
face value as its only denomination authority; `amount_sat` remains zero. Until
the first quote, `rate_minor_per_btc` remains null and
`rate_locks_until_unix` is the zero no-lock sentinel. A payer
explicitly selects one rail with `POST /api/v1/invoices/:id/quote`. Status and
other GET requests are projections and must not allocate provider or monetary
state. A successful request creates or reuses one immutable rate snapshot with
an exact five-minute lifetime and returns one instruction bound to that
snapshot. The PWA retires every displayed instruction at the exclusive expiry,
disables QR/copy while replacement is pending, rejects late responses from a
retired version, and publishes the replacement amount, cost, QR, and copy value
as one unit.

All projected Unix invoice timestamps use
`FLOOR(EXTRACT(EPOCH FROM value))::BIGINT`. A direct cast can round a fractional
PostgreSQL timestamp up by one second and contradict the exclusive database
deadline. Do not replace the explicit floor or certify a deadline from a
rounded projection.

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

Direct-payment lifecycle projection uses the configured payment-grace interval,
not the raw outer invoice expiry. Every locked reducer read and the legacy
payment recorder must use the same grace boundary. Evidence-free fiat state is
`unpaid` during grace and `expired` after it; only positive partial credit can
be `underpaid`. A direct observation batch that cannot persist this coherent
projection must fail and retry without advancing its applied generation.

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
- A newly fetched live observation that is still awaiting durable acceptance
  is not construction authority. During that persistence handoff, PR #179's
  candidate runtime may continue only on the explicitly restored predecessor
  when its durable authorization, source, rail, bounds, and freshness still
  agree. It never substitutes the pending live value or
  refreshes the predecessor's lifetime. If that durable predecessor is absent,
  stale, unauthorized, or inconsistent, admission closes.
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

For the fixed-checkout reverse-create path only, live Boltz may omit
`onchainAmount` from a successful response after accepting the exact amount and
`pairHash` in the request. Current merged source normalizes only an absent
response field from the immutable request amount. A present amount must match
exactly; explicit null, duplicate known fields, malformed values, and mismatches
are protocol failures. Do not broaden this compatibility rule to ordinary
reverse creation, infer an amount from other response fields, or weaken the
persisted request/pair contract.

The merged release can reconstruct chain-create results only from validated
Boltz xpub restore evidence matching the persisted request. The pinned reverse-swap
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

The obsolete TEST-VM `bw-bullnym-health-test.timer` is disabled and inactive.
Its referenced script was missing, so it made no Bullnym request and only
produced misleading local failure telemetry. Do not re-enable it until a
reviewed replacement exists. The schema-062 no-funds smoke failed at its first
fiat Payment Page invoice because the obsolete checkout-metadata constraint
rejected a valid private note. Its preceding no-funds stages passed, its funds
gate remained closed, and it moved no funds. PRs #179 and #180 supplied the
first schema-063 deployment. The first schema-063 no-funds attempt then found
the pre-quote projection and allocator-only startup-lineage defects described
above, still before the live-money gate. PR #182 was deployed and the upgraded
harness staged. Later zero-spend runs exposed the rounded timestamp projection
fixed by installed PR #183, then the direct-payment grace/projection defect and
fixed-checkout Boltz response compatibility fixed by merged PR #185. Every
failed run kept its spend and broadcast boundary at zero; it is defect evidence,
not a passing certificate. Final PR #185 run
`nofunds-c026691-20260715T213857Z` subsequently passed 12/12 with zero sats
spent and zero broadcasts; its log SHA-256 is
`390d99c5541314f97913f262995a98dda5d0bb0dcf06eadfd7f6ae25748f5ec0`
and its report SHA-256 is
`ab827e5124ea627c4176012cdafd17df8db0a2b3cf746864674788c0e0c78366`.
Successful run `live-liquid-c026691-fee400-20260715T220456Z` then paid 500
sats by direct Liquid, incurred a 326-sat forward fee and a 191-sat recycler
fee within its 1,800-sat cap, returned the principal, and left an aggregate
wallet delta of exactly 517 sats; its report SHA-256 is
`f77577f1b2d91cdfd6708c8e6586af972d51bc913bec8a3e39a3dfec1aabaf67`
and its log SHA-256 is
`b866387eb6de4f9ca1f78af47f5dd52c853431aa0bb3a24904c918a8a46315aa`.
The earlier 250-sat cap refusal occurred before payment preparation and before
any broadcast, so it was not a failed payment. Certification cleanup remains
`PENDING_FINAL_CERTIFICATION_CLEANUP_AUDIT`. Neither the disabled timer, merge
status, deployment identity, offline precheck, nor the earlier schema-062
certification substitutes for these recorded results.

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
outside this repository. Merged-release-specific claims were checked at exact
source `e17c465939ccf766ebf77b7d9bd7dbfb776c395d`, whose reviewed PR #177 head
was `01fb3f08aeb69e44d1ce71dfd2111ecd63e23253` with the same tree.

Schema-063 source claims were checked against migration 063, the fee-runtime
changes, strict anonymous checkout handling, pre-quote projection, and recovery
shadow audit, explicit epoch flooring, direct-payment grace projection, and the
fixed-checkout-only Boltz compatibility boundary at current exact main
`c026691cdede46cff56c9a34fade0fd4339bd5b7`, tree
`203abc2352b7d06819e383b56c91b99f113633eb`. The hosted release record,
stopped-writer migration, exact artifact installs, public version, startup
recovery, configuration preservation, and repeated fee cycles are observed
deployment evidence. PR #185's final artifact, release record, no-funds
journey, and live-Liquid/recycler journey are recorded explicitly above;
certification cleanup/audit remains the sole explicit placeholder.

Historical RFCs and older manuals are evidence only when current source and the
locked records still agree with them.

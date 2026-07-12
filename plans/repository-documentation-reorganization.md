# Bullnym Repository and Documentation Reorganization

**Status:** PROPOSED
**Prepared:** 2026-07-11
**Scope:** Bullnym repository structure, maintained documentation, API
reference, architecture records, runbooks, plans, research, archives, generated
artifacts, and documentation governance.
**Temporary location:** this plan remains under `plans/` only until the cleanup
creates the RFC/archive structure described below. It must then move with the
other active plans.

## 1. Objective

Make the repository understandable to four audiences without forcing any of
them through internal planning history:

1. an integrator using the Bullnym API;
2. an operator deploying and recovering the service;
3. an engineer changing the server or PWA;
4. a maintainer reviewing product and architecture decisions.

Every maintained fact should have one authoritative home. The root README must
be a landing page, not a whitepaper, API manual, configuration reference, and
runbook combined. Plans and historical investigations must never be presented
as current behavior.

## 2. Audit summary

The repository currently has useful material, but the information architecture
does not communicate which material is authoritative.

### 2.1 Scale and duplication

- `README.md` is 561 lines and duplicates product, architecture, API,
  configuration, database, worker, testing, and release documentation.
- `docs/api-reference.md` is 983 lines while `docs/components/http-api.md` is
  another 375-line API description. They describe the same contract at
  different levels and will drift.
- `docs/payment-architecture.md`, `docs/architecture.md`,
  `docs/components/payment-rails.md`, `docs/components/data-model.md`, and the
  product feature pages repeat payment and settlement semantics.
- Eight untracked plan files contain more than 8,000 lines. They mix active
  design, shipped work, superseded work, vendor-blocked research, and work the
  product explicitly paused.
- `archive/testing-evidence` is already correctly identified as historical,
  but the repository has no top-level archive policy or index covering plans
  and research.

The local relative-link scan found no broken Markdown file links. The main
problem is authority, currency, and navigation rather than link syntax.

### 2.2 Materially stale or unsafe content

These are correctness problems, not editorial preferences:

- `docs/runbook-stuck-swap.md` says `claim_stuck` rows are ignored forever,
  tells operators to treat Boltz status as truth, and recommends clearing
  journaled claim bytes and transaction IDs. Recent PRs added slow recovery and
  raw-transaction safety; reconstructing by manual SQL can destroy evidence or
  create an ambiguous spend.
- The same runbook claims an operator can change `current_fee_rate`, while the
  current builders still use hardcoded fees. Issue #64 exists precisely because
  that control is disconnected.
- `README.md` makes an unqualified legal conclusion that Bullnym eliminates
  money-transmission risk and says it does not facilitate a payment. This is
  neither a technical contract nor an appropriate legal conclusion for a
  software README.
- The README and architecture docs use "non-custodial" without consistently
  explaining that Bullnym controls swap preimages and claim/refund keys and can
  redirect swap outputs.
- `docs/README.md`, the rate-limit feature page, the data-model page, and the
  nginx snippet still advertise or operationalize image uploads. Bullnym no
  longer exposes an upload API. The complete API reference correctly calls the
  stored image fields legacy read-only data.
- `docs/nginx-bullpay.conf.snippet` is dominated by the removed upload/image
  pipeline and old donation naming. Its deployment instructions should not be
  treated as a current production proxy configuration.
- `docs/components/background-workers.md` omits recently merged settlement
  repair and slow recovery behavior.
- `docs/components/data-model.md` does not describe the schema-042 through
  schema-044 reliability additions and presents legacy image columns as a
  current feature.
- `docs/architecture.md` says the service is stateless except for Postgres,
  despite key/configuration, in-memory limiting, built PWA assets, and external
  chain/provider state being relevant runtime dependencies.
- Current product docs expose `donation_page` implementation names as product
  terminology. Those names remain part of database, API, and code compatibility
  but the product is Payment Pages.

### 2.3 Repository hygiene

The local worktree contains:

- 23 GB in `target/` and 2.9 GB in unignored `target2/`;
- 124 MB in `pwa/node_modules/`;
- ignored assistant instruction files copied into a nested
  `bull-bitcoin-workspace/` and a mobile-shaped root `lib/` directory;
- an untracked manual recovery probe under `examples/`;
- untracked plans and the untracked complete API reference.

The standard `target/` and `pwa/node_modules/` are expected local artifacts.
`target2/`, the nested workspace, and the mobile-shaped `lib/` are local
contamination and should not be normal repository contents. They must not be
deleted until the current uncommitted work has been checkpointed and their
contents have been confirmed disposable.

`pwa/dist` is tracked intentionally and has `pwa/scripts/check-dist.sh`. Keep it
until the release process is changed to build PWA assets reproducibly in CI;
document that policy instead of treating all generated files as equivalent.

### 2.4 Dirty-worktree constraint

The current `feat/invoice-notes` worktree has modified server code and 13
modified documentation files, plus untracked `docs/api-reference.md`, plans,
and examples. `origin/main` now includes the API reference through PR #78, but
this older feature worktree still sees its working copy as untracked. A
reorganization performed directly in this worktree would mix feature work,
documentation corrections, and mass renames.

The cleanup must begin from a dedicated branch based on the latest `main`,
after the current documentation changes are either committed to their owning
feature branches or exported as reviewed patches.

## 3. Documentation authority model

| Information | Authority | Other documents may do |
|---|---|---|
| Actual runtime behavior | Code, migrations, config types, and tests | Explain and link; never contradict. |
| External HTTP contract | `docs/api/` | Summarize routes but link for fields, signatures, errors, and retries. |
| System design | `docs/architecture/` | Product docs link to it instead of restating rail state machines. |
| Product behavior | `docs/products/` | Explain user-visible flows; avoid schema and complete payload tables. |
| Operator procedure | `docs/operations/` | Reference exact build/schema applicability and preserve monetary evidence. |
| Accepted rationale | `docs/adr/` | Current docs state the result and link to the ADR for why. |
| Proposed change | `docs/rfcs/` and GitHub issues | Never be cited as implemented behavior. |
| Historical evidence | `archive/` | Read-only context; never an active contract. |
| Work status | GitHub issues/milestones | Docs do not maintain duplicate open-item checklists. |

Rules:

1. A maintained page must state its audience and authoritative scope.
2. Current docs do not cite branches, PR numbers, issue numbers, session notes,
   or `plans/` as proof of behavior. ADRs, RFCs, changelog notes, and archives
   may contain those references.
3. Plans must use explicit `proposed`, `accepted`, `implemented`, `superseded`,
   or `abandoned` status. A plan is not a product document.
4. Runbooks must state preconditions, evidence to capture, safe automated
   action, verification, escalation, and rollback. Direct money-state SQL is
   break-glass material and requires a second-person review warning.
5. Legal and regulatory conclusions do not belong in technical documentation.
   The trust and key-authority facts should be documented precisely.

## 4. Target repository layout

```text
README.md
CONTRIBUTING.md
SECURITY.md

docs/
  README.md
  architecture/
    overview.md
    payment-lifecycle.md
    trust-model.md
    data-and-workers.md
    pwa.md
  api/
    README.md
    conventions-and-errors.md
    authentication.md
    nyms-and-discovery.md
    payment-pages-and-pos.md
    invoices-and-payment-state.md
    chain-swap-recovery.md
    operations.md
  products/
    lightning-address.md
    payment-pages.md
    pos.md
    invoices.md
  protocols/
    lud-22.md
  operations/
    configuration.md
    deployment.md
    monitoring.md
    runbooks/
      stuck-swaps.md
  reference/
    compatibility.md
    glossary.md
  adr/
    README.md
    template.md
    NNN-*.md
  rfcs/
    README.md
    template.md
    NNN-*.md

archive/
  README.md
  plans/
    implemented/
    superseded/
    abandoned/
  research/
  testing-evidence/
```

This is a ceiling, not a requirement to create empty directories. Create a
directory only when at least one maintained document belongs there.

## 5. Current-file disposition

### Root and primary navigation

| Current file | Action | Target/result |
|---|---|---|
| `README.md` | Rewrite | 100-150 line landing page: purpose, products, honest trust summary, quick start, supported status, and links. Remove full API/config/database/runbook material. |
| `docs/README.md` | Rewrite | Audience-based navigation, authority rules, and clear links to maintained docs. Archive appears once as historical material. |
| No `CONTRIBUTING.md` | Add | Local setup, test commands, PWA build/dist policy, migration workflow, documentation rules, and PR checklist. |
| No `SECURITY.md` | Add | Vulnerability reporting, supported versions, and concise server/key trust boundary. |

### Architecture and product docs

| Current file(s) | Action | Target/result |
|---|---|---|
| `docs/architecture.md` | Reduce and move | `docs/architecture/overview.md`; system boundary, deployment shape, dependencies, module map. |
| `docs/payment-architecture.md` + `components/payment-rails.md` | Consolidate | `docs/architecture/payment-lifecycle.md`; one canonical payment/settlement state model. |
| `components/data-model.md` + worker persistence sections | Consolidate and verify | `docs/architecture/data-and-workers.md`; current schema concepts through latest migration, worker ownership, durability boundaries. |
| `components/background-workers.md` | Merge | Worker behavior in `data-and-workers.md`; monitoring and operational controls move to operations docs. |
| `components/pwa-runtime.md` | Move | `docs/architecture/pwa.md`. |
| `features/lightning-address.md` | Move and trim | `docs/products/lightning-address.md`. |
| `features/donation-pages.md` | Rename and trim | `docs/products/payment-pages.md`; `donation_pages` mentioned only as a legacy implementation identifier. |
| `features/pos.md` | Move and trim | `docs/products/pos.md`. |
| `features/invoices.md` | Move and trim | `docs/products/invoices.md`. |
| `features/rate-limits-certification.md` | Split | Abuse model to architecture/trust; certification procedure to operations/testing. Remove image-upload row. |
| `features/testing.md` | Merge | `CONTRIBUTING.md` for developer tests and operations/deployment for staging certification. |

### API and protocol docs

| Current file(s) | Action | Target/result |
|---|---|---|
| `docs/api-reference.md` | Preserve as source, then split | Canonical `docs/api/` reference. Retain signing byte order, null/omitted semantics, error contracts, retry implications, and recovery privacy implications. |
| `components/http-api.md` | Delete after merge | Its unique route/response facts move to `docs/api/`; architecture keeps only an API surface overview. |
| `components/auth-identity.md` | Split | Signing contract to `docs/api/authentication.md`; identity/trust concepts to architecture/reference. |
| `alias-slugs-client-integration.md` | Merge then delete | API details into Payment Page/POS API page; user behavior into product pages; compatibility notes into compatibility reference. |
| `lud-22-currency-negotiation.md` | Move and retain | `docs/protocols/lud-22.md`, treated as the current protocol contract. |
| `lud-22-vs-mrh-research.md` | Distill and archive | Accepted result becomes an ADR; detailed adversarial analysis moves to `archive/research/`. |
| `compatibility-ledger.md` | Move and normalize | `docs/reference/compatibility.md`, with owner, removal condition, telemetry needed, and review trigger for every entry. |

Do not adopt OpenAPI merely to make the tree look modern. Bullnym's signed byte
layouts, omission semantics, privacy boundaries, and retry behavior need prose
and vectors. Reconsider OpenAPI later only if it can be generated from or
verified against Rust types without creating a third contract to maintain.

### Operations

| Current file | Action | Target/result |
|---|---|---|
| `runbook-stuck-swap.md` | Immediately quarantine, then rewrite from current `main` | `docs/operations/runbooks/stuck-swaps.md`; no clearing journaled transactions, no provider-status-as-truth, include slow recovery and evidence-preserving escalation. |
| `nginx-bullpay.conf.snippet` | Replace | Current PWA/proxy/TLS-forwarding configuration under operations. Put optional legacy `/img` serving in a separate compatibility snippet only if production still has legacy media. |
| README config section + `config.toml` | Consolidate | Annotated `config.toml` remains default authority; operations page explains required secrets, feature gates, production constraints, and validation. Do not duplicate every default. |
| README build/test/release sections | Move | `CONTRIBUTING.md` and operations deployment guide. |

### ADRs

Keep accepted decisions only after verifying them against current Bullnym and,
where they assert mobile behavior, current Bull Bitcoin Mobile:

- add date, scope, status, owners, supersedes/superseded-by, and verification
  references;
- rename `docs/decisions` to standard `docs/adr` only in the structural PR;
- update ADR 005 for alias and recovery actions;
- update ADR 006 to use Payment Page terminology and the current chain-swap
  recovery boundary;
- keep ADR 007 if route/cursor tests still prove it;
- move mobile-only decisions 002, 003, and 008 to the mobile repository, or
  mark them explicitly cross-repository with a maintained source link;
- add an ADR for the accurate Bullnym trust/key-authority model;
- add an ADR recording removal of image uploads and the legacy-media policy.

### Plans and research

| Plan | Disposition |
|---|---|
| `chain-swap-reliability-v3.md` | Convert to active RFC. Its accepted work must be represented by GitHub issues; the RFC owns design, not task status. |
| `public-name-reservation-policy.md` | Convert to active RFC after the unresolved lifetime/rename decision is made explicit. |
| `chain-swap-recovery-detection-server.md` | Archive as implemented after extracting the stable API contract and ADR decision. |
| `recovery-v2.md` | Archive as superseded by chain-swap reliability v3. |
| `bullnym-trust-minimization-audit-and-strategies.md` | Extract trust facts into `trust-model.md`; retain the long analysis under `archive/research/`. |
| `boltz-stablecoin-payment-page.md` | Archive as superseded. |
| `boltz-core-stablecoin-to-lbtc-reliability.md` | Archive as paused/abandoned product research; stablecoins are not active Bullnym scope. |
| `satora-bitcoin-to-liquid.md` | Archive as vendor-blocked research, not an implementation roadmap. |
| This reorganization plan | Convert to tracked issues during execution, then archive as implemented or delete once the resulting structure and ADRs carry its durable decisions. |

Active implementation checklists belong in GitHub issues and milestones. RFCs
contain problem, constraints, alternatives, decision, rollout, and risks, but
must not become an ever-growing session transcript.

### Archive and local tools

- Keep `archive/testing-evidence` read-only. Add `archive/README.md` explaining
  that archives are not product contracts and giving capture dates.
- Do not rewrite historical evidence to sound current. Add a banner when its
  assumptions are known obsolete.
- Move `examples/recover_probe.rs` to `tools/test-support/` or a DB integration
  fixture if it remains useful. It is a manual diagnostic with deterministic
  keys, not an example integration clients should copy.

## 6. Unsupported image-upload cleanup

The documentation cleanup must be paired with a scoped code decision:

1. Query production data for non-null `avatar_sha256`/`og_sha256` and verify
   whether legacy media still needs to render.
2. Keep the legacy database columns and read-only rendering while compatibility
   requires them. Mark them legacy in API and schema docs.
3. Remove upload-only code and dependencies that are no longer reachable:
   multipart support, image decode/resize/encode logic, upload size/dimension
   configuration, and upload-specific tests.
4. If alias backfill still needs file path and atomic-copy helpers, extract a
   minimal `legacy_media` module instead of retaining an upload pipeline.
5. Split legacy `/img` serving from the main nginx configuration and give it an
   explicit removal condition.
6. Once no supported deployment has legacy media, remove the columns, render
   paths, compatibility snippet, and image dependency in a later migration.

This prevents documentation from claiming uploads exist while also avoiding a
careless deletion of already published merchant media.

## 7. Execution plan

Each phase should be a separate reviewable PR. Do not mix mass file moves with
substantive factual rewrites.

### Phase 0 - Preserve work and establish the baseline

1. Checkpoint the current dirty docs and untracked API/plans without reverting
   feature work.
2. Use the PR #78 API reference on `origin/main` as the base, compare the
   uncommitted working copy against it, and retain only reviewed newer deltas.
3. Start the cleanup branch from current `origin/main`, not
   `feat/invoice-notes`.
4. Produce a file inventory with disposition, current owner, and verification
   source. The tables in this plan are the starting inventory.
5. Confirm which plans are active with the product owner before archiving.

**Gate:** no unique documentation or plan content is lost; cleanup diff contains
no server behavior changes.

### Phase 1 - Correct dangerous and false claims in place

Before moving files:

1. Replace the stuck-swap runbook with a safe current-main version or a clear
   quarantine notice.
2. Remove image-upload claims and separate legacy image serving.
3. Replace legal conclusions and shorthand non-custodial claims with the
   precise key/authority trust model.
4. Update workers, data model, readiness, and recovery docs through the latest
   merged migrations and PRs.
5. Normalize product vocabulary: Bullnym, Payment Page, POS, Invoice,
   Lightning Address, L-BTC. Preserve legacy route/table/action names only in
   code formatting.

**Gate:** no maintained page instructs an unsafe monetary-state mutation or
advertises a removed endpoint.

### Phase 2 - Establish navigation and move files

1. Rewrite the root README and docs index.
2. Add the glossary and authority statement.
3. Use `git mv` to create the architecture, API, product, protocol, operations,
   reference, ADR, RFC, and archive locations.
4. Add redirect stubs for one release only where external links are likely;
   internal links update in the same PR.
5. Add `archive/README.md`, RFC template, and ADR template.

**Gate:** every maintained page is reachable from `docs/README.md`; every
non-reachable Markdown file is intentionally listed in the archive or RFC
index.

### Phase 3 - Remove duplicate authorities

1. Split the complete API reference by surface and merge unique facts from
   `components/http-api.md`, auth docs, and the alias guide.
2. Delete the duplicate HTTP API page and one-off alias guide after coverage is
   proven.
3. Consolidate payment architecture, rail, data, and worker documents.
4. Trim product pages so they describe product behavior and link to canonical
   API/architecture details.
5. Convert research conclusions into ADRs and archive the long analysis.

**Gate:** endpoint fields and signing order exist in one maintained location;
payment and settlement state definitions exist in one maintained location.

### Phase 4 - Professional operator and contributor surfaces

1. Add `CONTRIBUTING.md` and `SECURITY.md`.
2. Add configuration, deployment, monitoring, backup/restore, and current
   stuck-swap runbooks.
3. Document the tracked `pwa/dist` policy and its reproducibility check.
4. Move or remove the manual recovery probe.
5. Execute the image-upload code cleanup after the production legacy-data
   check.

**Gate:** a new engineer can build/test from one guide; an operator can deploy
and diagnose without reading source comments or archived plans.

### Phase 5 - Repository hygiene

After checkpointing and explicit approval for deletion:

1. Remove local `target2/`, nested assistant scratch trees, and copied mobile
   `lib/` material.
2. Add a narrow `/target2/` ignore rule or standardize alternate Cargo targets
   outside the repository. Do not add a broad ignore that could conceal real
   source directories.
3. Keep `pwa/node_modules/` ignored and generated by `npm ci`.
4. Keep `pwa/dist` tracked until CI owns the build; then change policy in a
   dedicated build/release PR.
5. Ensure a clean clone has only intentional top-level directories.

**Gate:** `git status --untracked-files=all` is readable; build artifacts and
assistant scratch do not appear as repository content.

### Phase 6 - Prevent regression

Add a lightweight docs check to CI:

- Markdown formatting/lint;
- local link validation;
- orphan-page detection;
- no links from maintained docs to `plans/`;
- required status metadata for ADRs, RFCs, and archive documents;
- prohibited current-doc phrases such as `DRAFT`, branch names, or
  issue-tracking checklists outside allowed directories;
- `config.toml` parse test and existing `pwa/scripts/check-dist.sh`;
- documentation checklist in the PR template for API, config, migration,
  feature-flag, and compatibility changes.

Use an existing link/lint action or a small repository script. Do not introduce
a documentation site generator unless publishing requirements justify its
maintenance cost.

Add docs ownership through `CODEOWNERS` or the repository's existing review
rules:

- API changes require server/API review;
- runbooks require an operator and money-path reviewer;
- ADR/RFC status changes require the relevant product owner;
- mobile-contract assertions require a mobile reviewer.

**Gate:** CI fails on broken navigation, unclassified plan material, and the
most common sources of contract drift.

## 8. Review method for factual rewrites

Every maintained page must be checked against evidence, in this order:

1. current `origin/main` route wiring and public types;
2. migrations and database constraints;
3. config types/defaults and the sample config;
4. contract and state-machine tests;
5. current Bull Bitcoin Mobile only for mobile-owned behavior;
6. production runbook evidence where behavior depends on deployment topology.

Do not use an old README, plan, PR description, issue comment, or archived test
report as the sole source for a current claim.

For API pages, maintain a review matrix containing method/path, feature gate,
auth action, request type, response type, error codes, rate limit, idempotency,
and contract test. This matrix may live in the API index; it should not become
a second independently maintained route specification.

## 9. Definition of done

- Root README is a concise professional entry point, not a duplicated manual.
- The trust model states exactly which keys and redirection powers Bullnym has
  and makes no legal conclusion.
- The API contract has one maintained authority and includes byte-exact signing
  semantics.
- Product pages contain no implementation-plan references or task tracking.
- Payment/settlement statuses are defined once and linked elsewhere.
- Unsupported image uploads are not advertised; legacy media behavior is
  explicitly classified and removable.
- The stuck-swap runbook preserves journaled evidence and matches current
  recovery workers.
- Every ADR/RFC/archive file has an unambiguous lifecycle status.
- Stablecoin and Satora research cannot be mistaken for active Bullnym scope.
- Every maintained document is indexed; local links pass.
- A clean clone has an understandable top-level tree and no alternate Cargo
  targets or assistant scratch.
- PWA generated-artifact policy is explicit and reproducibly checked.
- CI and review ownership prevent the repository from returning to multiple
  conflicting sources of truth.

# Permanent Public Names: Server Implementation Plan

Status: locked product semantics; implementation pending

Date locked: 2026-07-11

Server baseline: BullishNode/bullnym PR #92, branch feat/public-name-reservations, commit 41b164d35d178822b4da250edb1cedd6fbc628cc.

Client baseline: BullishNode/bullbitcoin-mobile branch pr30-getpaid-sweep-labels, commit 9b1b255feede3ce6297525441e59ec1ebd24e7c3.

This plan supersedes every active/inactive-name, alias-clear, alias-reactivation, and nym-reactivation design in plans/public-name-reservation-policy.md and in the current implementation of PR #92. Product availability may be online or offline. Public-name ownership may not.

The coordinated mobile plan is:

- ../../bullbitcoin-mobile/plans/permanent-public-names-client.md

## Objective

Implement one permanent nym and one optional permanent alias per npub while keeping Lightning Address, Payment Page, and Point of Sale availability fully independent.

An already distributed identifier must never begin paying an unrelated owner. Taking a product offline must never mutate, deactivate, clear, release, or replace either public name.

## Locked product model

### Permanent names

Each npub may have:

- exactly one lifetime nym after its first nym claim;
- zero or one lifetime alias;
- no rename, replacement, release, clear, or user-controlled active flag for either name.

Normal name state is only:

    unclaimed -> claimed forever

The nym is the Lightning Address local part and the default public name for web surfaces. The alias is an optional web-only public name shared by Payment Page and Point of Sale.

Nyms and aliases share one allocation namespace for all new claims. A string claimed as either type can never later be claimed as the other type or by another npub.

### Independent products

Each product owns its own availability state:

    offline <-> online

For one npub:

    npub
    |-- nym: permanent
    |-- alias: permanent and optional
    |-- Lightning Address: online/offline
    |-- Payment Page: online/offline
    |-- Point of Sale: online/offline

The required independence rules are:

- Taking Lightning Address offline disables only LNURL/Lightning Address payments.
- Taking Lightning Address offline does not archive, disable, or otherwise change Payment Page or Point of Sale.
- Taking Payment Page offline does not affect Lightning Address or Point of Sale.
- Taking Point of Sale offline does not affect Lightning Address or Payment Page.
- An offline product can be turned online again using its already-owned nym, alias, configuration, and descriptor. This is product enablement, not name reactivation.

### Effective web name and routes

The effective web name is:

    effective_public_name = claimed_alias ?? nym

No alias claim is synthesized from the nym.

Before an alias claim:

- Payment Page share URL is https://domain/<nym>.
- Point of Sale share URL is https://domain/<nym>/pos.
- Surface saves omit the alias JSON key and signed field.

After an alias claim:

- Payment Page share URL is https://domain/a/<alias>.
- Point of Sale share URL is https://domain/a/<alias>/pos.
- Both nym routes remain valid.
- The alias remains the effective web name even when either surface is offline.

Surface availability, not alias state, determines whether a route is payable:

| Route | Availability source |
|---|---|
| /<nym> | Payment Page state |
| /a/<alias> | Payment Page state |
| /<nym>/pos | Point of Sale state |
| /a/<alias>/pos | Point of Sale state |
| <nym>@domain | Lightning Address state |

An offline surface may render the existing non-payable notice or return the documented unavailable response, but invoice creation must fail. The other surface remains unaffected.

## Terminology

Use these terms in code, API documentation, logs, tests, and UI contracts:

- permanent nym claim;
- permanent alias claim;
- Lightning Address online/offline;
- Payment Page online/offline;
- Point of Sale online/offline;
- turn a product on/off;
- canonical name and historical tombstone only for migration exceptions.

Do not use:

- active or inactive nym;
- active or inactive alias;
- clear alias;
- deactivate or reactivate a name;
- release or rename a name.

The existing users.is_active column may remain physically named that way for a scoped migration, but domain and API language must define it strictly as Lightning Address availability.

## Historical migration exception

Existing deployments may contain multiple historical nyms or aliases for one npub. The normal product must still expose one canonical nym and at most one canonical alias.

Every noncanonical historical name remains permanently reserved as a grandfathered tombstone. A tombstone is not an inactive user name and cannot be turned on by the user. It exists only to guarantee that a previously distributed identifier never pays a different owner.

Required behavior:

- One canonical nym is selected for every owner with nym history.
- When an owner has one or more historical aliases, exactly one canonical alias is selected. The operator may not select no alias merely to simulate an inactive alias.
- Other historical names remain owner-bound tombstones.
- Tombstone public routes are permanently non-payable.
- Tombstone names remain usable for historical invoice owner verification when required.
- Existing cross-type collisions are grandfathered with typed routing, but block every new claim of that string.
- No migration silently chooses among multiple candidates.

## Required schema and migration changes

PR #92 migrations 045 and 046 have not shipped and must be corrected in place before merge.

### Migration 045: preflight

Replace active-name choices with canonical-name choices:

- Rename active_alias to canonical_alias in the preflight model.
- Add an explicit canonical-nym choice for owners with multiple historical nyms.
- Auto-resolve a single candidate.
- Require an operator choice for multiple candidates.
- If alias candidates exist, canonical_alias must resolve to exactly one candidate; NULL is not a valid final choice.
- Report surfaces and Lightning Address rows attached to every noncanonical candidate.
- Continue reporting cross-type name collisions and drift.
- Quiesce registration and surface writes between 045 and 046.

### Migration 046: authoritative registry

The public_names table must model immutable ownership, not product state:

- Remove active.
- Remove deactivated_at.
- Add an immutable canonical marker or equivalent canonical owner pointer.
- Retain name, owner_npub, kind, claimed_at, and grandfathered identity data.
- Enforce at most one canonical nym and one canonical alias per owner.
- For every new claim, reject the insert if the owner has any lifetime claim of that kind, including a historical tombstone.
- For every new claim, reject the insert if the name exists with either kind.
- Prevent product code from updating or deleting name identity or canonical selection.
- Preserve typed grandfathered collisions without permitting new ones.
- Backfill users.is_active only as Lightning Address availability; do not copy it into public-name state.
- Backfill donation-page archived/enabled state only as surface availability; do not copy it into alias state.
- Detect every legacy Payment Page whose descriptor currently falls back to the Lightning Address descriptor. Before product lifecycles are decoupled, snapshot that descriptor into the Payment Page row without resetting its surface address cursor. No online web surface may continue depending on the Lightning Address product descriptor after this migration.
- Remove donation_pages.alias after canonical and tombstone reservations are safely backfilled.
- Keep the migration transactional and fail closed on unresolved choices or preflight drift.

Suggested conceptual registry:

    public_name_owners(
      npub primary key,
      created_at
    )

    public_names(
      id primary key,
      name,
      owner_npub,
      kind nym|alias,
      canonical,
      claimed_at,
      grandfathered
    )

The exact pointer/index representation may differ, but canonical selection and product availability must never share a column.

## Required database-layer changes

### Public-name repository

Refactor src/db/public_names.rs:

- Replace apply_alias_update with claim_alias_if_unclaimed.
- Omitted alias means no public-name operation.
- A non-empty alias performs first claim, same-value idempotency, or conflict.
- A different owned alias returns AliasAlreadyAssigned.
- A globally reserved name returns NameTaken.
- Empty alias never maps to a state change.
- Delete every update that changes public_names active/deactivated_at.
- Add canonical nym/alias lookup by npub.
- Add owner lookup that does not depend on Lightning Address availability.
- Keep historical alias-to-owner verification for old invoices.

### User and Lightning Address repository

Refactor src/db/users.rs:

- Treat users.is_active solely as Lightning Address online/offline.
- Resolve the permanent canonical nym independently from users.is_active.
- POST with the same permanent nym may turn Lightning Address online.
- A different nym for the owner returns NymAlreadyAssigned.
- Turning Lightning Address offline updates only the Lightning Address row.
- Remove automatic donation-page/POS archival from deactivate_user.
- Remove every public_names state update from deactivate_user and purge_user.
- Audit purge_user so Lightning Address cleanup cannot delete or invalidate Payment Page/POS descriptors, invoices, address cursors, or availability.
- Refuse purge or complete the descriptor backfill first if any legacy Payment Page still depends on the Lightning Address descriptor.
- Ensure grandfathered noncanonical nym rows cannot become a second canonical product identity.

### Surface repository

Refactor src/db/donation_pages.rs:

- Authorize by permanent npub/nym ownership, not users.is_active.
- Join the canonical alias regardless of Lightning Address or surface status.
- Return the canonical alias for both surface kinds.
- Remove alias_active from database/domain rows.
- Resolve alias routes by canonical alias plus requested surface kind.
- Resolve a canonical nym route even while Lightning Address is offline.
- Resolve tombstone names only to a non-payable historical response.
- Keep Payment Page and Point of Sale availability independent.

## Required HTTP/API changes

### Registration API

POST /register:

- First valid nym claims the permanent nym and turns Lightning Address online.
- The same nym while offline turns Lightning Address online.
- The same nym while already online is idempotent or returns a stable already-online result that does not imply another name may be chosen.
- A different nym returns HTTP 409 NymAlreadyAssigned with the owned nym in details.
- A name reserved as either type returns HTTP 409 NameTaken.

DELETE /register:

- Means turn Lightning Address offline.
- Never changes a public-name row.
- Never changes Payment Page or Point of Sale.
- Should be idempotent for an already-offline Lightning Address.
- Purge, if retained, remains a Lightning Address operational cleanup only and must pass the cross-product money-state audit.

GET /register/lookup:

- Always returns the permanent canonical nym for an owner.
- Reports Lightning Address availability separately.
- Returns the canonical alias as a nullable string.
- Returns public_name_policy: permanent_names_v1 as the mobile capability signal.
- Retains the existing top-level active field temporarily for compatibility, but documents it strictly as Lightning Address online status.
- Retains quota compatibility fields according to the compatibility ledger.
- Does not expose a user-controlled name-active state.

Target response shape:

    {
      "nym": "alice",
      "active": false,
      "lightning_address_online": false,
      "alias": "coffee",
      "public_name_policy": "permanent_names_v1",
      "quota": { "used": 1, "cap": 1, "remaining": 0 }
    }

### Surface save API

PUT /donation-page alias semantics:

- Omitted or null: preserve the existing alias claim and omit its signed field.
- First non-empty value: claim the one permanent alias.
- Same non-empty value: idempotent.
- Different non-empty value: HTTP 409 AliasAlreadyAssigned.
- Empty string: reject as DonationPageInvalid; it never clears or disables an alias.

The signature remains append-only compatible:

- alias is still the newest optional terminal field after kind;
- omission preserves the old signed byte layout;
- a valid first claim signs the non-empty alias terminally;
- empty remains byte-verifiable if received, but the request is rejected and performs no state change.

DonationPageView:

- alias is the canonical claimed alias or null if never claimed;
- alias does not depend on Lightning Address or surface availability;
- public_url uses the alias whenever it exists;
- enabled/is_archived describe only the selected surface.

### Surface archive API

DELETE /donation-page:

- Takes only the selected kind offline.
- Does not mutate nym or alias ownership.
- Does not affect the other surface.
- A later save turns only that selected surface online.

### Error details

Stable conflict details must include:

- NymAlreadyAssigned: owned nym and domain;
- AliasAlreadyAssigned: owned alias;
- NameTaken: no ownership leakage beyond the stable code;
- KeyAlreadyRegistered, if retained: owned nym and explicit lightning_address_online meaning.

Clients continue branching on code, never reason.

## Required route and invoice behavior

- LNURL metadata/callback checks Lightning Address online status.
- Payment Page nym and alias routes check only Payment Page availability.
- Point of Sale nym and alias routes check only Point of Sale availability.
- Taking Lightning Address offline does not block management or rendering of an online Payment Page/POS.
- Alias invoice creation selects the requested surface kind and rejects only when that surface is offline/missing.
- Nym invoice creation follows the same surface-specific rule.
- Historical tombstone routes never create invoices.
- Historical invoice ownership checks continue using permanent owner binding.
- Alias-rendered pages and payment descriptions continue scrubbing the nym.

## Implementation sequence

Each chunk must be independently reviewed and tested before the next begins.

### Server chunk 1: contract tests first

- Rewrite public-name tests to encode permanent names and independent products.
- Add a full product-state matrix before changing implementation.
- Add failing tests for empty alias rejection and for Lightning Address off while both surfaces remain online.

Gate:

- Focused tests compile and fail only on the intended old behavior.

### Server chunk 2: migrations and registry

- Rewrite migrations 045/046.
- Replace active-name state with canonical/tombstone ownership.
- Update migration fixtures and the operator resolution workflow.

Gate:

- Fresh migration succeeds.
- Upgrade drill from schema 001-044 succeeds after explicit choices.
- Unresolved, NULL-choice, and drift cases fail transactionally.
- Every historical name remains reserved to its original owner.

### Server chunk 3: nym ownership versus Lightning Address status

- Refactor public-name and user DB helpers.
- Make registration same-name/idempotent and different-name rejecting.
- Remove cross-product effects from delete/purge.

Gate:

- Nym concurrency and lifetime tests pass.
- Turning Lightning Address off leaves both surfaces and aliases unchanged.

### Server chunk 4: alias claim-only semantics

- Replace alias update/deactivate/reactivate logic with first-claim/idempotent logic.
- Reject empty alias.
- Return canonical alias in lookup and error details.

Gate:

- Signing compatibility, collision, idempotency, and concurrency tests pass.

### Server chunk 5: surface authorization and routing

- Remove Lightning Address online checks from surface management and rendering.
- Resolve canonical nym/alias independently for each kind.
- Enforce tombstone non-payability.

Gate:

- Full route/manifest/invoice state matrix passes.
- Payment Page and POS can be toggled independently while Lightning Address is either online or offline.

### Server chunk 6: API, documentation, and rollout metadata

- Add public_name_policy and explicit product status fields.
- Update all API, architecture, product, ADR, compatibility, and operations documentation.
- Remove active/inactive-name language.

Gate:

- cargo test --lib
- cargo test --tests
- dedicated migration drill
- scripts/check-docs.sh
- readiness/version checks

## Mandatory server test matrix

### Name ownership

- First nym claim succeeds.
- Same nym is idempotent and can turn Lightning Address online.
- Different nym for the same npub fails.
- First alias claim succeeds.
- Same alias is idempotent.
- Empty alias fails without mutation.
- Different alias for the same npub fails.
- Cross-npub and cross-type claims fail.
- Delete/purge/archive never releases a name.
- Concurrent claims produce exactly one winner.

### Product independence

Test all eight combinations of Lightning Address, Payment Page, and Point of Sale online/offline state.

For every combination assert:

- name ownership is unchanged;
- each public route follows only its product state;
- taking one product offline does not mutate another;
- invoice creation is allowed only for the selected online surface;
- lookup reports permanent names plus separate product status.

### Default and claimed alias

- No alias creates no alias row and signs no alias field.
- No alias uses nym URLs for both surfaces.
- A claimed alias changes both generated URLs.
- Taking either surface offline does not change generated name selection.
- Taking Lightning Address offline does not change either generated surface URL.
- Nym routes remain valid after alias claim.

### Migration

- Single-name owners become canonical automatically.
- Multi-name owners require explicit canonical choices.
- Every noncanonical name becomes a permanent tombstone.
- Cross-type historical collisions remain owner-bound and block new claims.
- Legacy Payment Pages that used the Lightning Address descriptor fallback receive an equivalent surface-owned descriptor without cursor reset.
- Tombstone routes are non-payable.
- Migration rollback is transactional.

## Documentation updates

At minimum update:

- README.md
- docs/api/authentication.md
- docs/api/conventions-and-errors.md
- docs/api/integration-guide.md
- docs/api/nyms-and-discovery.md
- docs/api/payment-pages-and-pos.md
- docs/architecture/data-and-workers.md
- docs/products/lightning-address.md
- docs/products/payment-pages-and-pos.md
- docs/reference/compatibility.md
- ADR 011
- deployment and migration runbooks

Every document must distinguish permanent name ownership from product availability.

## Rollout

1. Amend PR #92 before merge; do not deploy its current active-name migrations.
2. Freeze registration and surface writes.
3. Apply revised migration 045.
4. Resolve every canonical nym/alias choice.
5. Back up the database and run the preflight drift check.
6. Apply revised migration 046.
7. Deploy the server and verify version/readiness plus public_name_policy=permanent_names_v1.
8. Verify all three products independently in production-like smoke tests.
9. Release the protocol-capable mobile client.
10. Enable mobile permanent-name UI only after the capability is present.

An old server binary is not a valid rollback target after revised migration 046. Use a forward fix or restore the pre-migration database backup.

## Server definition of done

- Names have no user-controlled active/inactive state.
- One canonical lifetime nym and at most one canonical lifetime alias are enforced for new product behavior.
- Historical extra names are permanent non-payable tombstones.
- Lightning Address, Payment Page, and Point of Sale availability are mutually independent.
- Empty alias cannot clear or disable a claim.
- Lookup exposes permanent names and separate product status.
- Returned surface URLs use alias when claimed and nym otherwise.
- All migration, concurrency, signing, route, invoice, and product-state tests pass.
- Server documentation contains no obsolete name-reactivation semantics.

## Explicit non-goals

- Name transfer between npubs.
- Nym or alias rename.
- Releasing names after account deletion or purge.
- Multiple normal nyms or aliases per npub.
- A user-facing tombstone restoration flow.
- Client-side ownership persistence.
- Combining the three product availability controls.

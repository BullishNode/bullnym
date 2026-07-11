# Public Name Reservation Policy: Nyms and Aliases

> **Archived: implemented.** Retained as design rationale; maintained API,
> architecture documentation, migrations, and code are authoritative.

- Status: Implemented
- Owner: Unassigned
- Affected repositories: `bullnym`, `bullbitcoin-mobile`
- Last updated: 2026-07-11

The design record was captured before implementation; default nym-fallback
behavior was confirmed on 2026-07-11.

This document preserves the product discussion, external research, current-code
audit, preferred direction, implementation outline, and remaining decisions for
Bullnym public names.

## Safety invariant

An already-distributed payment identifier must never begin paying an unrelated
new owner.

For every public nym, Lightning Address, or alias URL, the permanent behavior
must be one of:

1. It continues reaching its original owner.
2. It becomes inactive and returns a non-payable response.
3. It is restored by its original owner.

It must never be reassigned to a different owner. Old saved URLs, Lightning
Addresses, QR codes, address-book entries, and social-media links must not route
payments to a new holder.

## Preferred product model at the end of the discussion

The cleanest proposed model is:

- One lifetime nym claim per npub.
- One optional lifetime alias claim per npub.
- Until an alias is explicitly claimed and active, both Payment Page and PoS
  use the nym as their effective public name.
- Nyms and aliases occupy one global namespace.
- A name can never be reassigned to a different npub.
- The nym is the Lightning Address local part.
- The alias is web-only and exists for the Payment Page and PoS.
- A merchant may share public surface links using either its nym or its alias.
- The alias belongs to the npub, not to an individual Payment Page or PoS row.
- Payment Page versus PoS is selected by the route, not by giving each surface
  a different alias.

Conceptually:

```text
npub P
|-- nym:   alice (default public name)
`-- alias: coffee (optional public-name override)
    |-- Payment Page
    `-- PoS
```

The shared namespace prevents cross-type impersonation:

```text
alice   nym    npub-P
coffee  alias  npub-P
```

No other npub may claim `alice` or `coffee`, as either a nym or an alias. The
same npub should not claim an alias identical to its own nym because the global
name is already occupied and the alias would be redundant.

Only the nym resolves as a Lightning Address. An alias such as `coffee` may
resolve at `/a/coffee`, but `coffee@domain` must not become a Lightning Address.
Sharing one allocation namespace does not make the two name types protocol-
equivalent.

### Important consequence: lifetime versus active limit

If "one nym and one alias per npub" is a lifetime constraint, both names are
immutable after first claim:

```text
unclaimed -> active -> inactive -> active again
```

There is no rename to a second nym or alias. Clearing only deactivates; it never
releases. The original npub may reactivate the same name.

If product requirements still require alias renaming, the rule must instead be
"one active alias per npub." In that model an npub may accumulate multiple
historical aliases, every historical alias remains permanently owned by the
same npub, and a separate lifetime cap is needed. That is a different and more
complex policy.

At the battery-cutoff point, the strict lifetime one-nym/one-alias model was the
preferred direction, but this immutability consequence should be explicitly
confirmed before implementation.

### Default public-name fallback

The product may describe the default as the alias being inherited from the
nym. The implementation must treat it as fallback behavior, not as a second
stored claim:

```text
effective_public_name = active_alias ?? nym
```

Before the merchant explicitly chooses an alias:

- `public_names` contains only the nym claim for that name.
- No alias row is synthesized with the nym's value.
- The donation-page/PoS alias field remains absent or `NULL`.
- The alias terminal field is omitted from signed saves unless the merchant
  explicitly changes alias state.
- Payment Page and PoS link builders generate their nym-based routes.

After the merchant claims an alias, generated and shared links default to the
alias-based routes, while the nym-based routes remain valid and may still be
shared deliberately. If the alias is deactivated, link generation falls back
to the nym; the inactive alias remains permanently reserved to the same npub.

This avoids creating a redundant alias equal to the nym, which would conflict
with the shared namespace, while giving the merchant the intended zero-setup
Payment Page and PoS experience.

## Public route model

Both the nym and alias can identify the same merchant surfaces. A possible
backward-compatible shape is:

```text
Donation Page by nym:    /<nym>
Donation Page by alias:  /a/<alias>
PoS by nym:              /pos/<nym>
PoS by alias:            /a/<alias>/pos
```

The exact PoS route remains to be locked. The architectural rule is that the
route selects the surface and the public name selects the owner. There is no
longer a separate alias claim for each `(nym, kind)` row.

With no active alias, the default Payment Page and PoS share actions use the
nym routes. With an active alias, those actions default to the alias routes.
The presence of an alias does not disable the nym routes.

Alias rendering must continue to scrub the nym from the served page and payment
payloads. Nym rendering may expose the nym as it does today.

## Current implementation audit

The audit fetched the latest remote state on 2026-07-10 and inspected
`origin/main` at commit `6e73944701242a19397debf3eea18d90f714c3ba`.
The alias feature branch was already merged through PR #58. No fetched remote
branch contains an alias reservation ledger, alias lifetime quota, or equivalent
tombstone implementation.

The local checkout was `feat/invoice-notes` with substantial pre-existing user
changes. The audit used the fetched `origin/main` ref so those working-tree
changes did not affect the conclusion.

### Nyms today

Nyms already satisfy non-reassignment under supported application operations:

- `users.nym` has an unconditional global `UNIQUE` constraint.
- Deactivation sets `is_active = FALSE`; it does not delete the user row.
- Purge deletes eligible operational history, archives donation pages, scrubs
  the descriptor, and leaves the user row and `(nym, npub)` binding intact.
- LNURL metadata and callbacks query only active users.
- Another npub cannot insert the inactive nym because the inactive row retains
  the unique name.
- Tests cover takeover rejection after delete and purge.
- The configured lifetime nym count currently includes active and inactive
  rows and defaults to a per-npub cap of three.

Relevant code:

- `migrations/001_initial.sql`
- `migrations/005_nym_lifecycle.sql`
- `migrations/013_users_nym_no_cascade.sql`
- `src/db/users.rs`
- `src/registration.rs`
- `src/lnurl.rs`
- `tests/integration_test.rs`

Current edge case: `register_user_atomic` checks only the most recently created
inactive row when deciding whether to reactivate. If an npub has several
historical nyms, an older one remains safely reserved but may not be
reactivatable through the current flow. This does not permit takeover, but it
does not provide arbitrary same-owner restoration either.

Operator caveat: a database superuser can physically delete or truncate user
rows. The normal delete and purge APIs do not. The operator-gated historical
wipe migration and integration-test cleanup are exceptional hard-delete paths.

### Aliases today

Aliases do not satisfy permanent reservation.

Migration 040 adds only a nullable column and a partial unique index:

```sql
CREATE UNIQUE INDEX donation_pages_alias_uidx
    ON donation_pages (alias) WHERE alias IS NOT NULL;
```

There is no alias claim ledger or tombstone table. Current behavior is:

| Operation | Old alias retained? | Claimable by another holder? |
|---|---:|---:|
| Omit alias | Yes | No |
| Clear with `"alias": ""` | No | Yes, immediately |
| Change to another alias | No | Yes, immediately |
| Archive surface | Yes | No |
| Deactivate nym | Yes; page is archived | No |
| Purge nym | Yes; page is archived | No |
| Hard-delete user row | No; page cascades | Yes |

The save handler maps an empty alias to `Some(None)`. The database upsert writes
that as `NULL`; a replacement writes the new string over the old one. The old
string then exists nowhere in the merchant tables and the partial unique index
no longer blocks it.

The public lookup is effectively:

```sql
SELECT ... FROM donation_pages WHERE alias = $1
```

Therefore the following unsafe sequence is possible today:

```text
Alice claims /a/coffee
Alice clears it or changes to /a/alices-cafe
Bob claims /a/coffee
An old saved /a/coffee link now opens Bob's surface
POST /a/coffee/invoice now creates a Bob-owned invoice
```

Historical alias invoice rendering performs an owner check, so an old invoice
URL containing Alice's invoice ID fails rather than displaying Bob's invoice.
The reusable base alias and new-invoice route are nevertheless unsafe.

Relevant code:

- `migrations/016_donation_pages.sql`
- `migrations/034_donation_pages_kind.sql`
- `migrations/040_donation_pages_alias.sql`
- `migrations/041_invoices_public_slug.sql`
- `src/donation_page.rs`
- `src/db/donation_pages.rs`
- `src/donation_render.rs`
- `src/invoice.rs`

There are signature-layout, validation, reserved-word, and nym-scrubbing alias
tests, but no database integration tests covering claim, clear/change, and a
second holder attempting to claim the former alias.

## External product research

Research was checked on 2026-07-10. Public documentation often does not state
the critical old-name reuse rule, so confirmed behavior and inference must stay
separate.

### Strike

Confirmed:

- Strike usernames are mutable.
- The current username determines both `username@strike.me` and the public
  tipping-page URL.
- Strike internally has a stable account UUID separate from the mutable handle.
- Its resolver can return a distinct non-payable `User can't receive` state.

Not publicly documented:

- Whether a former username remains reserved after rename.
- Whether a former username can be restored only by the same account.
- Whether closed-account names are ever recycled.
- Whether historical Lightning Addresses are permanently tombstoned.

Strike is not reliable precedent for either safe recycling or permanent
reservation without a direct written answer from Strike.

Sources:

- https://strike.me/en/faq/what-is-my-strike-username/
- https://strike.me/faq/what-is-my-strike-lightning-address/
- https://strike.me/faq/how-do-i-close-my-account/
- https://docs.strike.me/api/fetch-public-account-profile-info-by-handle/

### Wallet of Satoshi

Confirmed:

- Custom Lightning Addresses require a wallet backup, at least ten Lightning
  transactions, and at least 100,000 sats of on-chain activity.
- WoS describes this as proof of work against mass squatting.
- Its guide describes custom addresses as unique and belonging to the chooser.
- Support can migrate an existing custom address between the same user's
  custodial and self-custodial wallets.
- An older first-party statement says the initial random address continues
  working after customization, while replacing one custom address with another
  causes the former custom address to stop working.

Not publicly documented:

- Whether a stopped custom address can ever be issued to an unrelated user.
- The exact reservation behavior after account deletion.

Sources:

- https://support.walletofsatoshi.com/support/solutions/articles/36000583190-lightning-addresses-how-they-work-and-how-to-create-a-custom-one
- https://support.walletofsatoshi.com/support/solutions/articles/36000550831-how-do-i-create-a-custom-lightning-address-

### Blink

Blink is the strongest inspectable precedent for permanent tombstoning:

- Username setting rejects an account that already has a username.
- Account deletion marks the account closed but retains the row and username.
- Username availability lookup includes closed records.
- Invoice creation rejects inactive accounts.
- Current migration messaging says the Lightning Address moves with the same
  user from custodial to non-custodial service.

The observable result is claim once, retain the identifier after closure, and
reject future payments rather than assign the address to another owner.

Sources:

- https://github.com/GaloyMoney/blink/blob/6c536737a327013f2ebe0a37091a3277ec802373/core/api/src/app/accounts/set-username.ts#L33-L43
- https://github.com/GaloyMoney/blink/blob/6c536737a327013f2ebe0a37091a3277ec802373/core/api/src/app/accounts/mark-account-for-deletion.ts#L80-L90
- https://github.com/GaloyMoney/blink/blob/6c536737a327013f2ebe0a37091a3277ec802373/core/api/src/services/mongoose/accounts.ts#L43-L57
- https://github.com/GaloyMoney/blink/blob/6c536737a327013f2ebe0a37091a3277ec802373/core/api/src/domain/accounts/account-validator.ts#L5-L11
- https://www.blink.sv/blog/important-changes-to-custodial-accounts-in-your-region

## Rejected or superseded directions

### Reassigning names with generation prefixes

A proposed model used paths such as `/2/<nym>` for a later holder while leaving
the generation-one URL inactive. This can technically protect old HTTP URLs,
but a Lightning Address has no path component. It would require a different
local part or domain, such as `2-alice@domain` or `alice@2.domain`, meaning it is
not the same Lightning Address anyway. Dynamic DNS is avoidable with wildcard
DNS and TLS, but the product and compatibility complexity remains unjustified.

The preferred policy is not to reassign public payment names.

### Per-surface alias ownership

The current integration spec permits one alias for `payment_page` and another
for `pos`. The preferred one-alias-per-npub model supersedes that. A shared alias
identifies the merchant; the route identifies the surface.

### Permanent alias binding to a single nym

This protects an exact destination but strands the alias when the owner changes
nyms. If the final policy instead makes both nym and alias immutable lifetime
claims, this distinction disappears because the npub cannot change to a second
nym. If nym changes remain supported, alias ownership should be anchored to the
npub and any rebind must require explicit authentication by that same npub.

## Proposed authoritative schema direction

A single registry is the clean way to enforce cross-type uniqueness. Separate
unique indexes on `users.nym` and `donation_pages.alias` cannot prevent a string
from appearing once in each table.

Conceptual schema:

```sql
CREATE TYPE public_name_kind AS ENUM ('nym', 'alias');

CREATE TABLE public_names (
    name TEXT PRIMARY KEY,
    owner_npub TEXT NOT NULL,
    kind public_name_kind NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deactivated_at TIMESTAMPTZ,
    UNIQUE (owner_npub, kind)
);
```

Properties:

- `PRIMARY KEY(name)` creates the shared nym/alias namespace.
- `UNIQUE(owner_npub, kind)` permits at most one nym and one alias per npub.
- Rows are never deleted during product lifecycle operations.
- Deactivation changes state, not ownership.
- System route names remain separately rejected or may be represented as
  system-owned reserved claims.

The final implementation may introduce a stable owner/identity table and use
foreign keys from `users` and public surfaces into `public_names`. Avoid relying
only on application checks for the cross-table namespace invariant.

## Migration requirements

The existing database can violate the proposed rules, so migration must audit
before adding constraints.

Required preflight queries must detect:

1. Multiple lifetime nym rows with the same npub.
2. Multiple active aliases belonging to the same npub through different nyms
   or surfaces.
3. Any alias string equal to any existing nym string.
4. Alias ownership ambiguity across Payment Page and PoS.
5. Aliases on inactive or archived rows.
6. Any exceptional hard-deleted historical names recoverable from backups or
   deployment records.

Do not silently choose a winner for real conflicting merchant data. Produce an
operator-readable conflict report and resolve or grandfather each case
deliberately.

Existing historical nym rows may need to remain as permanent inactive claims
even if the new rule permits only one new lifetime nym per npub. The migration
can grandfather historical reservations while prohibiting future additions.

## API and signed-payload compatibility

The current save signature contract must remain byte-compatible:

```text
bullpay-la-v2\0donation-page-save\0<npub>\0<nym>\0...\0alias\0<timestamp>
```

Alias remains the optional terminal signed field:

- Key omitted: do not sign it and do not change alias state.
- `"alias": ""`: sign the empty terminal field and deactivate the existing
  alias without releasing its claim; generated links fall back to the nym.
- Non-empty alias: on first claim, reserve it; on a subsequent identical save,
  treat it idempotently/reactivate it; if strict lifetime immutability is
  adopted, reject a different alias for the same npub.

Omitting the alias when none has been claimed must not create an alias claim or
write the nym into an alias column. The server and clients derive the effective
public name from the active alias, falling back to the nym.

Suggested errors:

- `NameTaken`: the string is already any kind of public name.
- `AliasAlreadyAssigned`: the npub already owns a different lifetime alias.
- `NymAlreadyAssigned`: the npub already owns a different lifetime nym.
- Existing validation errors remain for invalid/reserved syntax.

The server must remain authoritative. Client-side validation is only immediate
feedback.

## Implementation outline

1. Lock the remaining product decisions listed below.
2. Add migration preflight/reporting for current nyms and aliases.
3. Add the shared `public_names` registry and backfill all retained claims.
4. Add database constraints/FKs so neither cross-type collisions nor second
   per-npub claims can bypass the registry.
5. Refactor nym registration to claim/reactivate through the registry.
6. Refactor alias save so first claim is permanent and clear only deactivates.
7. Move alias ownership from `(nym, kind)` to the npub-level identity.
8. Implement one effective-public-name selector for both surfaces: use the
   active alias when present and otherwise use the nym, without persisting a
   synthetic alias.
9. Make Payment Page and PoS resolve the shared alias by route/surface while
   keeping their nym routes valid.
10. Add explicit inactive responses for nym LNURL and alias web routes.
11. Preserve historical invoice ownership checks.
12. Update the client integration document and mobile UX.
13. Roll out backend and migration before an alias-capable mobile release.

Required tests include:

- Nym claim followed by cross-npub nym attempt.
- Alias claim followed by cross-npub alias attempt.
- Alias attempting to equal any nym and vice versa.
- Second nym attempt for the same npub.
- Second alias attempt for the same npub.
- A merchant with no alias gets working nym-based Payment Page and PoS links.
- The no-alias fallback does not create an alias registry row, write the nym to
  an alias column, or add the alias field to an otherwise alias-free signature.
- Claiming an alias makes both surfaces default to alias-based share links while
  their nym-based links continue to work.
- Clear/deactivate preserves both reservations.
- Clearing/deactivating an alias returns both surfaces' generated links to the
  nym fallback without releasing the alias.
- Archive and purge preserve both reservations.
- Original npub can reactivate the same name.
- Inactive Lightning Address returns an LNURL error and never falls through.
- Inactive alias shows a non-payable page and cannot create invoices.
- Old saved alias never resolves to another owner.
- Payment Page and PoS both resolve through the same alias owner without
  leaking the nym on alias pages.
- Concurrent cross-type claims for the same string produce exactly one winner.
- Migration backfills active and inactive historical claims without loss.

## Remaining decisions to confirm

1. Does one nym/alias per npub mean one lifetime immutable claim, or one active
   claim with permanently retained historical names? The strict lifetime model
   is currently preferred.
2. What exact PoS and Payment Page paths should be used under a shared alias?
3. How should existing npubs with multiple historical nyms be grandfathered?
4. How should any existing npub with two per-surface aliases choose the retained
   alias?
5. Should a future cryptographically authorized npub key-rotation mechanism be
   supported? It must preserve owner continuity and must never release a name
   into the public pool.

## Worktree note

No implementation files were changed as part of this design discussion or
audit. This document is the only new file created for the save request. The
repository already contained unrelated modified and untracked files before this
document was added; preserve them.

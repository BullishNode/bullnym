# Permanent Public Names and Independent Surfaces

- Status: Accepted
- Supersedes: RFC-002 implementation guidance
- Affected repository: `bullnym`
- Accepted: 2026-07-14

## Decision

Each authentication npub may own exactly one permanent nym and, optionally,
exactly one permanent alias. Both kinds occupy the same lowercase namespace.
Ownership is an insert-only fact: no product operation clears, renames,
releases, reassigns, deactivates, or reactivates a name.

The nym is the Lightning Address local part. The alias is a web routing name
shared by Payment Page and POS:

| Surface | Nym route | Alias route |
|---|---|---|
| Payment Page | `/:nym` | `/a/:alias` |
| POS | `/:nym/pos` | `/a/:alias/pos` |

The route selects the surface; the name selects the permanent owner. An alias
is not a Lightning Address and does not make `alias@domain` payable.

## Availability

Name ownership and product availability are separate:

- `users.is_active` controls only Lightning Address availability.
- `donation_pages.enabled` and `archived_at` control each Page/POS row.
- Taking one product offline does not mutate names or the other products.
- Page/POS ownership, routing, management, and checkout do not require the
  Lightning Address to be online.
- Archiving Page or POS never changes the alias claim.

## Save contract

`alias` remains the newest optional trailing field in the signed
`donation-page-save` payload for byte compatibility.

- omitted/null: preserve the current claim;
- empty string: reject with `DonationPageInvalid`;
- first valid value: insert the permanent alias claim;
- exact same owner/value: idempotent success;
- different value after that owner has an alias: `AliasAlreadyAssigned`;
- any nym/alias namespace collision: `NameTaken`.

The alias belongs to the npub, not a donation_pages row. A save that loses a
concurrent claim race must not mutate its Page/POS row.

## Database authority and empty-state cutover

Bullnym has no production users at this boundary, so migration 058 is a strict
empty-state guard rather than a historical compatibility mechanism. With all
writers stopped, it locks and requires `users`, surfaces, invoices, swaps,
allocations, and returned-address history to be empty. It creates no choice,
backfill, mapping, or communication-report state.

Migration 059 repeats that locked empty-state proof, creates `public_names`
from scratch, makes every Page/POS descriptor mandatory, and removes the
pre-launch mutable surface `alias` and `pos_mode` fields. It never infers a
name, owner, payout wallet, or invoice relationship from old rows. Any nonempty
source requires the documented fresh database reset before the migration can
proceed.

Database constraints and triggers enforce:

- one shared nym/alias namespace;
- exactly one nym and at most one alias per owner;
- an alias requires the same owner to have a nym;
- database-owned claim timestamps;
- rejection of every name UPDATE and DELETE;
- an exact owner-matched permanent nym for every `users` row.

## Rollout

Stop every writer, retain a final pre-reset backup for audit, reset the
production database, and apply the full migration sequence as the privileged
schema owner with the runtime role supplied to role-aware migrations. Verify
the read-only boundary through the runtime role, then deploy the matching
binary. Crossing 059 disables automatic binary rollback. Mobile changes are
delivered only through the separately owned stacked mobile branches/PRs.

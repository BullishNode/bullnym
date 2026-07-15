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

## Database authority and historical cutover

Migration 058 snapshots every owner's historical nym and alias candidates in
`public_name_migration_choices` while writers are stopped. Alias history is
the union of current/archived surfaces and exactly owner-verified invoice
slugs, so old alias invoice routes keep their ownership proof. Single
candidates resolve automatically. An existing active nym is the required
canonical nym; fully-offline multi-nym and multi-alias owners require explicit
operator choices. Candidate arrays are immutable, completion is
schema-constrained, and the companion view reports merchant URLs that change
to a canonical alias.

Migration 059 locks the sources, compares both candidate sets and the active
nym with the snapshot, and aborts on drift or incomplete resolution. It
backfills every historical name into `public_names`: selected names are
canonical and every other historical name is an owner-bound non-payable
tombstone. Typed historical nym/alias collisions are preserved while every new
claim still uses one shared namespace. Before removing the older mutable
`donation_pages.alias` column, it rejects any descriptor-less Page/POS row;
the name cutover never infers or copies a payout wallet from another product.

Database constraints and triggers enforce:

- shared nym/alias uniqueness for every new claim;
- typed preservation of historical cross-kind collisions;
- at most one canonical claim of each kind per owner;
- permanent owner binding for every historical tombstone;
- an alias requires the same owner to have a nym;
- database-owned claim timestamps;
- rejection of ownership/canonical UPDATEs and ordinary DELETEs;
- rejection of any attempt to make a noncanonical nym an active Lightning
  Address.

## Rollout

Apply 058 as the privileged schema owner while every writer is stopped, resolve
and record all choices, capture the merchant communication report, validate a
fresh backup, and apply 059 in the same stopped-writer window. Verify the
read-only boundary through the runtime role, then deploy the matching binary.
Crossing 059 disables automatic binary rollback. Mobile changes are delivered
only through the separately owned stacked mobile branches/PRs.

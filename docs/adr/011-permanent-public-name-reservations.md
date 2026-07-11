# 011 Permanent public-name reservations

- Status: Accepted
- Date: 2026-07-11
- Owners: Bull Bitcoin

## Context

Nyms were retained in `users` after deactivation, but aliases previously lived
only in `donation_pages.alias`. Clearing or replacing an alias removed the only
reservation, allowing an unrelated owner to claim an already distributed
payment URL. Old links could then begin creating invoices for the wrong
merchant.

## Decision

- Each npub may claim one lifetime nym and one optional lifetime alias.
- Nyms and aliases share one allocation namespace for new claims.
- A claim may transition between active and inactive but is never released,
  renamed, deleted through product operations, or assigned to another npub.
- The alias belongs to the npub and is shared by Payment Page and POS; the
  route selects the surface (`/a/:alias` or `/a/:alias/pos`).
- Without an active alias, both surfaces use their nym routes. This is derived
  fallback behavior and does not create a synthetic alias claim.
- Only a nym is a Lightning Address local part. Aliases remain web-only.
- Historical multi-nym, multi-alias, and cross-type collision states are
  preserved as grandfathered reservations while all new claims obey the strict
  policy.

## Consequences

An owner cannot choose a different nym or alias after the first claim; it can
only reactivate the same value. Deactivated identifiers remain non-payable and
cannot become payment destinations for a different merchant. Deployment
requires the two-stage public-name preflight/backfill migration documented in
[Deployment](../operations/deployment.md#public-name-migration-045046).

The authoritative registry is `public_name_owners` plus `public_names`.
`donation_pages` no longer stores per-surface aliases. The signed
`donation-page-save` layout remains compatible because `alias` stays the newest
optional terminal field.

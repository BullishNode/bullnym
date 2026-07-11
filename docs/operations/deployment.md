# Deployment

1. Build the Rust binary and, when PWA source changed, rebuild and verify
   `pwa/dist`.
2. Back up PostgreSQL and confirm the swap mnemonic recovery procedure.
3. Apply migrations before starting a binary that depends on the new schema.
4. Deploy one version consistently across all instances. Mixed binaries can
   disagree about signed payloads or state transitions.
5. Start the service and require `/health`, `/ready`, and `/version` to pass.
6. Verify worker-start events for claimers, reconcilers, chain watchers,
   settlement repair, slow recovery, and GC.
7. Exercise public metadata, a Payment Page, POS, invoice status, static assets,
   and webhook reachability without moving funds.
8. Monitor error and recovery events through at least one reconciler cycle.

## Public-name migration 045/046

For an existing database, quiesce registration and surface writes before the
public-name migration. Apply `045_public_names_preflight.sql`, inspect
`public_name_migration_alias_choices`, and resolve every owner with multiple
historical aliases by selecting the alias that should remain active or `NULL`
to leave all of that owner's aliases inactive. Then apply
`046_public_names.sql`.

Both migrations are transactional. Migration 046 fails closed while any choice
is unresolved or if the alias set changed after preflight. The database cannot
discover names that were already hard-deleted, so compare backups or deployment
records and restore any such permanent reservations before applying 046.

Rollback the binary only when its migrations and signed API behavior remain
compatible. Never roll back the database blindly. A rollback does not undo an
on-chain transaction; reconcile in-flight swaps before and after the change.

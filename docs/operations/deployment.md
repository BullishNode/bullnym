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

Rollback the binary only when its migrations and signed API behavior remain
compatible. Never roll back the database blindly. A rollback does not undo an
on-chain transaction; reconcile in-flight swaps before and after the change.

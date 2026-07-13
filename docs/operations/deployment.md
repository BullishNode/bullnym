# Deployment

1. Remove any `.cargo/config.toml` local dependency override, then run
   `scripts/release-preflight.sh`. It requires a clean Bullnym checkout and
   proves Cargo resolves `boltz-client` from the exact repository/SHA pinned in
   `release-manifest.toml`. It also verifies the actual writable Cargo Git
   checkout is at that SHA with no tracked or untracked source changes.
2. Build only with `scripts/build-release.sh`. It brackets compilation with
   release preflight and rejects a bare `cargo build --release`. When PWA
   source changes, rebuild and verify the checked-in `pwa/dist` first. PWA-only
   promotion is unsupported because it would invalidate the binary's embedded
   content digest. The wrapper captures Cargo's actual native executable even
   when its target directory is customized, then stages only the verified
   artifact and record under `target/verified-release/`.
3. Preserve the staged record with the installed artifact. It contains the
   binary SHA-256 plus the embedded Bullnym, verified Boltz source, schema,
   build profile, pinned Rust/Cargo toolchain, target, and PWA content
   identities.
4. Back up PostgreSQL and confirm the swap mnemonic recovery procedure.
5. Apply migrations before starting a binary that depends on the new schema.
6. Deploy one version consistently across all instances. Mixed binaries can
   disagree about signed payloads or state transitions.
7. Start the service and require `/health`, `/ready`, and `/version` to pass.
   Compare the running process digest and public version fields to the
   candidate record before promoting it to `release.json`. The full
   operator-only build object is available without configuration or database
   access through `pay-service --build-info` and is emitted at startup.
8. Verify worker-start events for claimers, reconcilers, chain watchers,
   settlement repair, slow recovery, and GC.
9. Exercise public metadata, a Payment Page, POS, invoice status, static assets,
   and webhook reachability without moving funds.
10. Monitor error and recovery events through at least one reconciler cycle.

Rollback the binary only when its migrations and signed API behavior remain
compatible. Never roll back the database blindly. A rollback does not undo an
on-chain transaction; reconcile in-flight swaps before and after the change.

Migration 047 has an explicit binary boundary. A same-schema rollback remains
allowed. An initial rollback from a 047 binary to a 046 binary is also allowed
while `invoice_direct_payment_transitions` is absent or empty. Once any direct
lifecycle transition exists, the 046 writer is incompatible with that durable
history, so `scripts/deploy.sh` refuses the entire automatic binary/PWA restore
and leaves the candidate files installed for operator recovery. Do not delete
transition history to force a rollback; repair or roll forward with a
047-compatible binary.

## Reproducing a prior artifact

1. Check out the Bullnym `build_commit` from its preserved release record.
2. Install the version in `rust-toolchain.toml` and confirm it matches the
   record's `rustc_version`, `cargo_version`, and `build_target`.
3. Confirm the corresponding Boltz SHA is still the value in
   `release-manifest.toml`, then run `cargo fetch --locked` and
   `scripts/release-preflight.sh`.
4. Build with `scripts/build-release.sh` on the recorded native target. Cross
   compilation is not part of the current release mechanism.
5. Generate a new release record and compare its source/content fields. Compare
   the artifact SHA-256 when the compiler/toolchain/linker environment is also
   reproduced exactly.

To upgrade `boltz-client`, first push the desired commit to the pinned
BullishNode repository. In one reviewed Bullnym PR, update the full SHA in
`release-manifest.toml` and `Cargo.toml`, regenerate `Cargo.lock`, and run the
provenance fault tests plus a clean release build. Never point a release at a
branch name or sibling worktree.

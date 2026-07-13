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
   Migration 050 is a stop-the-writers boundary; follow the dedicated sequence
   below instead of applying it while an older service is live. Migration 051
   is also a stopped-service cutover because its new insert trigger requires
   the complete creation packet written by a 051-aware chain-swap caller.
   Migration 053 is a stopped-writer, privileged-owner, roll-forward boundary;
   the runtime `payservice` role must never apply it.
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

Migration 050 is an unconditional roll-forward-only writer boundary. Before
applying it, close new reverse- and chain-swap admission, drain requests, and
stop every pre-050 Bullnym instance. Verify no old process or job can create a
swap, take the required backup, apply `050_swap_key_lineage.sql`, and then start
only a 050-aware binary. Do not use a rolling or mixed-version rollout across
this boundary: an old writer can expose a key to Boltz without first committing
the allocation journal. The backup must preserve `swap_key_allocations`,
`swap_key_legacy_high_water`, both swap tables, and `swap_key_seq` together.
After migration 050 exists, automatic rollback to any pre-050 binary is refused
even when no swap has yet been created; recover by repairing or rolling forward
with a lineage-aware binary.

Migration 051 is the chain-swap creation-evidence writer boundary. Stop the
service and drain its database sessions, take and validate a fresh backup, then
apply `051_chain_swap_creation_terms.sql` and start only the matching binary.
The migration deliberately leaves historical rows nullable but rejects every
new chain-swap insert that lacks all required creation terms. Therefore a 050
binary accidentally started on schema 051 fails closed before exposing a payer
instruction, but it can still create provider-side orphans and must not be used
as a rollback strategy. Repair or roll forward with a 051-aware binary. Verify
that new rows contain one immutable creation packet and that legacy rows remain
readable before reopening chain-swap admission.

## Migration 053 privileged-owner boundary

Migration 053 creates the private append-only recovery-address ledger and makes
its exact commitment ID/address pair mandatory for every new chain swap. The
ledger's runtime ACL is safe only when its owner is distinct from the runtime
`payservice` role: a PostgreSQL table owner retains implicit mutation and
truncate authority that `REVOKE` cannot remove.

Close new swap admission, drain requests, stop every Bullnym writer, and take a
validated database backup. Set the schema-owner name to a role that can perform
DDL and that is not `payservice`; use normal libpq credential handling rather
than the runtime password file.

```bash
sudo systemctl stop payservice
if sudo systemctl is-active --quiet payservice; then
  echo "payservice is still active; refusing migration 053" >&2
  exit 1
fi

export BULLNYM_SCHEMA_OWNER='<privileged-schema-owner>'
test "$BULLNYM_SCHEMA_OWNER" != payservice
```

Run this first-application preflight as that owner. It fails if a runtime
session survived the stop, if the core 053 ledger or column is already present,
or if a pre-053 row contains unexplained address-only evidence.

```bash
psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --host 127.0.0.1 --username "$BULLNYM_SCHEMA_OWNER" --dbname payservice <<'SQL'
DO $migration_053_preflight$
BEGIN
    IF current_user = 'payservice' THEN
        RAISE EXCEPTION 'migration 053 must not run as payservice';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_stat_activity
         WHERE datname = current_database()
           AND usename = 'payservice'
           AND pid <> pg_backend_pid()
    ) THEN
        RAISE EXCEPTION 'payservice database sessions remain';
    END IF;
    IF to_regclass('public.recovery_address_commitments') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 053 ledger already exists';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'chain_swap_records'
           AND column_name = 'recovery_address_commitment_id'
    ) THEN
        RAISE EXCEPTION 'migration 053 chain-swap column already exists';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM chain_swap_records
         WHERE merchant_emergency_btc_address IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'pre-053 chain swap has address-only recovery evidence';
    END IF;
END
$migration_053_preflight$;
SQL
```

Apply the migration in one `ON_ERROR_STOP` session as the same privileged
owner. The file contains its own transaction and independently refuses the
runtime role and runtime ownership.

```bash
psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --host 127.0.0.1 --username "$BULLNYM_SCHEMA_OWNER" --dbname payservice \
  --file migrations/053_recovery_address_commitments.sql
```

Capture a concise postflight record before starting Bullnym. The ACL row must
show a non-`payservice` owner, runtime `SELECT/INSERT` only, and no PUBLIC
grant. The two constraint definitions must show the ordered
`(recovery_address_commitment_id, merchant_emergency_btc_address)` reference
with `ON UPDATE/DELETE RESTRICT` plus the NULL-pair check. The trigger query
must return the five migration-053 triggers, enabled, with their expected
functions.

```bash
psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --host 127.0.0.1 --username "$BULLNYM_SCHEMA_OWNER" --dbname payservice <<'SQL'
SELECT pg_get_userbyid(relation.relowner) AS ledger_owner,
       relation.relacl AS ledger_acl
  FROM pg_class relation
 WHERE relation.oid = 'public.recovery_address_commitments'::REGCLASS;

SELECT constraint_info.conname,
       constraint_info.convalidated,
       pg_get_constraintdef(constraint_info.oid) AS definition
  FROM pg_constraint constraint_info
  JOIN pg_class relation ON relation.oid = constraint_info.conrelid
 WHERE relation.oid = 'public.chain_swap_records'::REGCLASS
   AND constraint_info.conname IN (
       'chain_swap_records_recovery_commitment_pair_check',
       'chain_swap_records_recovery_commitment_fkey'
   )
 ORDER BY constraint_info.conname;

SELECT relation.relname,
       trigger_info.tgname,
       trigger_info.tgenabled,
       function_info.proname
  FROM pg_trigger trigger_info
  JOIN pg_class relation ON relation.oid = trigger_info.tgrelid
  JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid
 WHERE trigger_info.tgname IN (
     'recovery_address_commitment_validate_insert',
     'recovery_address_commitment_reject_update',
     'recovery_address_commitment_reject_delete',
     'chain_swap_records_require_recovery_commitment',
     'chain_swap_records_reject_recovery_commitment_update'
 )
 ORDER BY relation.relname, trigger_info.tgname;
SQL
```

Then run `scripts/deploy.sh`. Before it builds or changes the installed
service, its read-only `payservice` probe mechanically requires a distinct
ledger owner, exact runtime/PUBLIC ACL, the validated ordered composite foreign
key, the validated pair constraint, and all five enabled trigger/function
bindings. It prints no runtime-role migration command and refuses on missing or
drifted evidence.

Start only a 053-aware binary and require its startup recovery-commitment
verification plus the normal `/health`, `/ready`, and `/version` checks before
reopening traffic. After 053 commits, never start or automatically restore a
pre-053 writer: it cannot supply the required commitment pair and can create a
provider-side orphan before its database insert fails. Repair or roll forward.
`scripts/deploy.sh` verifies the 053 boundary before building and refuses an
automatic cross-boundary rollback.

```bash
sudo journalctl -u payservice --since '10 minutes ago' \
  | grep -F 'private append-only recovery commitment binding verified'
curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null
curl --fail --silent --show-error http://127.0.0.1:8080/ready
curl --fail --silent --show-error http://127.0.0.1:8080/version
```

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

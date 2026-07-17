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
   the runtime `bullnym_app` role must never apply it.
   Migrations 058 and 059 are one stopped-writer, empty-state permanent-name
   cutover: 058 refuses any existing production state; 059 repeats that proof,
   creates the current registry, requires surface descriptors, and removes the
   pre-launch mutable alias/mode columns.
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

Before promotion and again against the installed release, run the
[read-only deployment certification preflight](deployment-certification.md)
with the operator-recorded exact commit, artifact digest, PWA digest, and
schema marker. It reuses the release-record verifier and probes public
health/readiness/version without replacing this runbook's running-process
digest, worker-log, migration, or admission checks.

Rollback the binary only when its migrations and signed API behavior remain
compatible. Never roll back the database blindly. A rollback does not undo an
on-chain transaction; reconcile in-flight swaps before and after the change.

Migration 064 advances the exact runtime schema marker even though its new
wallet-backup table is additive. A schema-063 binary therefore cannot become
ready against a schema-064 database. Automatic binary/PWA rollback across this
boundary is refused. To return to the pre-064 release, stop every writer and
restore the validated schema-063 database backup together with its matching
binary, PWA, and release record. Otherwise repair or roll forward with a
schema-064-aware binary.

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

## Migrations 058-059 permanent-name cutover

Apply 058 and 059 only as part of the documented fresh production database
reset. Bullnym has no production users at this boundary; these migrations do
not preserve, select, or backfill pre-launch identity or payment state.

1. Close admission and stop every Bullnym writer and worker.
2. Take and validate a final pre-reset backup for audit and rollback to the
   pre-cutover release only.
3. Reset the production database while preserving the reviewed database owner,
   runtime role, and connection-secret topology.
4. Apply the complete migration sequence as the privileged schema owner. Supply
   `--set runtime_role=bullnym_app` to each role-aware migration.
5. Start only a binary whose schema expectation includes migration 059 or
   later.

Migration 058 takes exclusive locks and requires all identity, surface, invoice,
swap, allocation, and returned-address source tables to be empty. It creates no
persistent object. Migration 059 repeats the same proof, refuses any obsolete
migration artifact, creates the five-column current-only `public_names`
registry, requires a non-null descriptor for each Page/POS row, and removes the
pre-launch `donation_pages.alias` and `pos_mode` fields.

A nonempty source table is not an operator-choice workflow. It means the reset
was incomplete: stop, diagnose the reset, and begin again from the validated
empty database. Do not delete individual rows to force the guard.

Before starting Bullnym, verify the result through the protected runtime
connection:

```bash
sudo /opt/bullnym/bullnym/scripts/check-migration-059-boundary.sh \
  /etc/bullnym/bullnym.env bullnym_app bullnym
```

The probe must print successful boundaries for 053, 055, 056, 057, 058, and
059. It proves the current shared namespace, one nym plus optional alias per
owner, alias-to-nym requirement, immutable claims, runtime ACL/function
boundary, exact user ownership, surface descriptor independence, and removal
of obsolete surface fields. Before applying later migrations, a 059 binary's
`/ready` reports `059_remove_surface_alias`.

After 059, automatic binary rollback is forbidden. Repair or roll forward with
a compatible binary, or restore the full validated pre-reset database and its
matching pre-059 binary while every writer remains stopped.

## Migration 064 opaque wallet backups

Apply `064_wallet_backup_blobs.sql` as the privileged schema owner with
`--set runtime_role=bullnym_app`. The migration creates only the opaque
current-object table, its tombstone cleanup index, constraints, comments, and
runtime CRUD grants. It does not transform existing payment or identity rows.

Treat the schema marker as a stopped-writer deployment boundary:

1. Stop every Bullnym writer and confirm the runtime role has no surviving
   database session.
2. Take a schema-063 PostgreSQL backup and prove it is readable with
   `pg_restore --list` or an isolated restore. Preserve the matching binary,
   PWA, release record, and configuration with it.
3. Apply migration 064 as the distinct privileged owner. Never apply it as
   `bullnym_app`.
4. Start only the reviewed schema-064 binary and require `/ready`, `/version`,
   the installed artifact digest, and the release record to agree before
   enabling mobile backup traffic.
5. Verify the runtime role has only `SELECT`, `INSERT`, `UPDATE`, and `DELETE`
   on `wallet_backup_blobs`; it must not own the table or hold `TRUNCATE`,
   `REFERENCES`, `TRIGGER`, or PUBLIC-derived privileges.
6. Apply the exact wallet-backup locations from `nginx.conf.example`, inspect
   the effective configuration with `nginx -T`, run `nginx -t`, and reload.
   Verify that the store route has a 3 MiB proxy ceiling, the fetch route has
   an 8 KiB ceiling, both retain the Nginx API flood gate, and access logging
   is disabled for both. Exercise an authenticated 2 MiB store through the
   public proxy before launch; a direct loopback test does not prove the proxy
   contract.

Rollback is a paired restore, not a table drop: stop the schema-064 writer,
restore the validated schema-063 database, then restore its matching old
binary/PWA/release record. Do not start the old binary against schema 064 and
do not delete the backup table merely to force the old readiness marker.

## Migration 060 private LNURL comments

Apply `060_lnurl_private_comment_intents.sql` as the privileged schema owner
with `--set runtime_role=bullnym_app`. It adds an append-only private intent
ledger and column-scoped runtime grants. The matching binary advertises a
120-character callback contract, persists Lightning comments, and atomically
binds their swap and merchant-side claim evidence. Direct-Liquid comments fail
closed. The signed `/api/v1/lnurl/comments` projection exposes only
payment-evidenced rows to the authenticated merchant, with bounded pagination
and private no-store response headers. The binary expects schema marker
`060_lnurl_private_comment_intents` and refuses readiness when the ledger,
guards, or private ACL boundary is missing. Once the 060 callback is serving,
automatic rollback to a 059-aware binary is forbidden because that binary
would advertise a different limit and discard newly submitted comments. Roll
forward or restore the validated pre-060 backup while writers are stopped.
Before enabling the callback, apply the dedicated `/lnurlp/callback/` nginx
location from `nginx.conf.example` and verify both `access_log off` and its
location-local error-log sink; LUD-12 places the private comment in the GET
query string and nginx error records can include the request line. The
application trace span records neither the URI query nor the callback's opaque
intent token.

## Migration 061 versioned fiat quote foundation

Apply `061_invoice_quote_versions.sql` as the privileged schema owner with
`--set runtime_role=bullnym_app`. It adds immutable five-minute fiat quote
versions and version-bound payer-offer identities, plus nullable attribution on
reverse swaps, chain swaps, and invoice payment events. Existing rows remain
unattributed; the migration never reconstructs missing rate/source evidence or
deletes an old instruction.

This migration is intentionally not the runtime quote-refresh cutover. It does
not make a read-only page/status request create a provider swap, does not change
the invoice lifetime, and refuses a new quote after payment evidence until the
focused expired-quote fiat valuation policy is selected and wired. A payment
event may still reference an expired quote/offer with its first-observed time
while all fiat-credit fields remain NULL, preserving the evidence without
guessing the accounting result.

## Migration 053 privileged-owner boundary

Migration 053 creates the private append-only recovery-address ledger and makes
its exact commitment ID/address pair mandatory for every new chain swap. This
production topology uses database `bullnym`, runtime role `bullnym_app`, and the
protected runtime connection in `/etc/bullnym/bullnym.env`. The systemd service
is `bullnym.service`; the repository is `/opt/bullnym/bullnym`, the executable
is `/usr/local/bin/pay-service`, the active release record is
`/opt/bullnym/release.json`, immutable records are under
`/opt/bullnym/releases`, and backups are under `/opt/bullnym/backups`. None of
those names is the database runtime identity. PostgreSQL table ownership must
stay with a separate privileged schema owner because an owner retains mutation
and truncate authority that `REVOKE` cannot remove.

Close new swap admission, drain requests, stop every Bullnym writer, and take a
validated database backup. Obtain a root-only owner environment file containing
only `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`, and any required
`PGSSLMODE`/`PGSSLROOTCERT` for a role that can alter database `bullnym`. It must
not reuse `/etc/bullnym/bullnym.env`, role `bullnym_app`, or credentials
inherited by `bullnym_app`. The examples use
`/etc/bullnym/bullnym-db-owner.env`; it must be a root-owned, mode-0600 regular
non-symlink file. Provisioning that distinct secret is an operator prerequisite.

```bash
sudo systemctl stop bullnym.service
if sudo systemctl is-active --quiet bullnym.service; then
  echo "bullnym.service is still active; refusing migration 053" >&2
  exit 1
fi

sudo test -f /etc/bullnym/bullnym-db-owner.env
sudo test ! -L /etc/bullnym/bullnym-db-owner.env
sudo test "$(sudo stat --format='%u:%a' /etc/bullnym/bullnym-db-owner.env)" = 0:600
sudo test "$(sudo stat --format='%u:%a' /etc/bullnym/bullnym.env)" = 0:600
```

Run this first-application preflight as that owner. It fails if a runtime
session survived the stop, if the core 053 ledger or column is already present,
if the owner connection targets the wrong database, or if a pre-053 row contains
unexplained address-only evidence. Every psql child below receives only the
explicit libpq connection fields and fixed process basics, not the sourced
owner environment.

```bash
sudo bash <<'ROOT'
set -euo pipefail
owner_env=/etc/bullnym/bullnym-db-owner.env
[[ -f "$owner_env" && ! -L "$owner_env" && -O "$owner_env" && -r "$owner_env" ]]
owner_mode="$(stat --format='%a' "$owner_env")"
(( (8#$owner_mode & 077) == 0 ))
safe_path="$PATH"
psql_bin="$(command -v psql)"
source "$owner_env"
for required in PGHOST PGDATABASE PGUSER PGPASSWORD; do
  [[ -n "${!required:-}" ]]
done
[[ "$PGDATABASE" == bullnym ]]
owner_libpq=(
  "PGHOST=$PGHOST" "PGPORT=${PGPORT:-5432}" "PGDATABASE=$PGDATABASE"
  "PGUSER=$PGUSER" "PGPASSWORD=$PGPASSWORD"
)
[[ -z "${PGSSLMODE:-}" ]] || owner_libpq+=("PGSSLMODE=$PGSSLMODE")
[[ -z "${PGSSLROOTCERT:-}" ]] || owner_libpq+=("PGSSLROOTCERT=$PGSSLROOTCERT")
owner_psql() {
  env -i HOME=/root PATH="$safe_path" PGCONNECT_TIMEOUT=5 \
    "${owner_libpq[@]}" "$psql_bin" "$@"
}
owner_psql --no-psqlrc --no-password --set ON_ERROR_STOP=1 <<'SQL'
DO $migration_053_preflight$
BEGIN
    IF current_database() <> 'bullnym' THEN
        RAISE EXCEPTION 'migration 053 owner connection must target bullnym';
    END IF;
    IF current_user = 'bullnym_app' THEN
        RAISE EXCEPTION 'migration 053 must not run as bullnym_app';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'bullnym_app'
    ) THEN
        RAISE EXCEPTION 'runtime role bullnym_app does not exist';
    END IF;
    IF pg_has_role('bullnym_app', current_user, 'MEMBER') THEN
        RAISE EXCEPTION 'bullnym_app can assume the migration owner role';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_stat_activity
         WHERE datname = current_database()
           AND usename = 'bullnym_app'
           AND pid <> pg_backend_pid()
    ) THEN
        RAISE EXCEPTION 'bullnym_app database sessions remain';
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
ROOT
```

Apply the migration in one `ON_ERROR_STOP` session as the same privileged
owner. The file contains its own transaction and independently refuses the
runtime role and runtime ownership.

```bash
sudo bash <<'ROOT'
set -euo pipefail
owner_env=/etc/bullnym/bullnym-db-owner.env
[[ -f "$owner_env" && ! -L "$owner_env" && -O "$owner_env" && -r "$owner_env" ]]
owner_mode="$(stat --format='%a' "$owner_env")"
(( (8#$owner_mode & 077) == 0 ))
safe_path="$PATH"
psql_bin="$(command -v psql)"
source "$owner_env"
for required in PGHOST PGDATABASE PGUSER PGPASSWORD; do
  [[ -n "${!required:-}" ]]
done
[[ "$PGDATABASE" == bullnym ]]
owner_libpq=(
  "PGHOST=$PGHOST" "PGPORT=${PGPORT:-5432}" "PGDATABASE=$PGDATABASE"
  "PGUSER=$PGUSER" "PGPASSWORD=$PGPASSWORD"
)
[[ -z "${PGSSLMODE:-}" ]] || owner_libpq+=("PGSSLMODE=$PGSSLMODE")
[[ -z "${PGSSLROOTCERT:-}" ]] || owner_libpq+=("PGSSLROOTCERT=$PGSSLROOTCERT")
owner_psql() {
  env -i HOME=/root PATH="$safe_path" PGCONNECT_TIMEOUT=5 \
    "${owner_libpq[@]}" "$psql_bin" "$@"
}
cd /opt/bullnym/bullnym
owner_psql --no-psqlrc --no-password --set ON_ERROR_STOP=1 \
  --set runtime_role=bullnym_app \
  --file migrations/053_recovery_address_commitments.sql
ROOT
```

Capture a concise postflight record before starting Bullnym. The ACL row must
show a non-`bullnym_app` owner, runtime `SELECT/INSERT` only, and no PUBLIC
grant. The two constraint definitions must show the ordered
`(recovery_address_commitment_id, merchant_emergency_btc_address)` reference
with `ON UPDATE/DELETE RESTRICT` plus the NULL-pair check. The trigger query
must return the five migration-053 triggers, enabled, with their expected
functions.

```bash
sudo bash <<'ROOT'
set -euo pipefail
owner_env=/etc/bullnym/bullnym-db-owner.env
[[ -f "$owner_env" && ! -L "$owner_env" && -O "$owner_env" && -r "$owner_env" ]]
owner_mode="$(stat --format='%a' "$owner_env")"
(( (8#$owner_mode & 077) == 0 ))
safe_path="$PATH"
psql_bin="$(command -v psql)"
source "$owner_env"
for required in PGHOST PGDATABASE PGUSER PGPASSWORD; do
  [[ -n "${!required:-}" ]]
done
[[ "$PGDATABASE" == bullnym ]]
owner_libpq=(
  "PGHOST=$PGHOST" "PGPORT=${PGPORT:-5432}" "PGDATABASE=$PGDATABASE"
  "PGUSER=$PGUSER" "PGPASSWORD=$PGPASSWORD"
)
[[ -z "${PGSSLMODE:-}" ]] || owner_libpq+=("PGSSLMODE=$PGSSLMODE")
[[ -z "${PGSSLROOTCERT:-}" ]] || owner_libpq+=("PGSSLROOTCERT=$PGSSLROOTCERT")
owner_psql() {
  env -i HOME=/root PATH="$safe_path" PGCONNECT_TIMEOUT=5 \
    "${owner_libpq[@]}" "$psql_bin" "$@"
}
owner_psql --no-psqlrc --no-password --set ON_ERROR_STOP=1 <<'SQL'
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
ROOT

sudo /opt/bullnym/bullnym/scripts/check-migration-053-boundary.sh \
  /etc/bullnym/bullnym.env bullnym_app bullnym
```

Do not run the repository's generic `scripts/deploy.sh` in current production;
its self-build filesystem and unit layout is intentionally different. Follow
the primary schema-053 hosted-artifact runbook, and require it to invoke the
committed boundary helper above before starting `bullnym.service`. The helper
sources the protected runtime `DATABASE_URL` without printing it, proves the
connection is role `bullnym_app` on database `bullnym`, and mechanically
requires a distinct ledger owner, exact runtime/PUBLIC ACL, the validated
ordered composite foreign key, validated pair constraint, and all five enabled
trigger/function bindings. Explicit environment/role/database arguments are
the portability seam for disposable tests; no-argument defaults are this
production database topology.

Start only a 053-aware binary and require its startup recovery-commitment
verification plus the normal `/health`, `/ready`, and `/version` checks before
reopening traffic. After 053 commits, never start or automatically restore a
pre-053 writer: it cannot supply the required commitment pair and can create a
provider-side orphan before its database insert fails. Repair or roll forward.
`scripts/deploy.sh` verifies the 053 boundary before building and refuses an
automatic cross-boundary rollback.

```bash
sudo journalctl -u bullnym.service --since '10 minutes ago' \
  | grep -F 'private append-only recovery commitment binding verified'
curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null
curl --fail --silent --show-error http://127.0.0.1:8080/ready
curl --fail --silent --show-error http://127.0.0.1:8080/version
```

## Migration 057 cooperative-signing boundary

Migration 057 is a stopped-writer, roll-forward-only boundary. Stop
`bullnym.service` and every database writer, then apply
`migrations/057_chain_swap_cooperative_signing_operations.sql` as the same
distinct protected schema owner used for migrations 053–056. Pass
`--set runtime_role=bullnym_app`; never apply it as `bullnym_app`, never
backfill historical provider calls, and never start a pre-057 writer after it
commits.

Before restarting, verify the runtime view through the protected runtime
environment. This proves the exact 60-column journal, state/fee/digest
constraints, RESTRICT parent identity, active index, trigger bindings,
non-assumable owner, runtime `SELECT/INSERT/UPDATE` ACL, absent PUBLIC/function
authority, and absence of generated sequence authority.

```bash
sudo /opt/bullnym/bullnym/scripts/check-migration-057-boundary.sh \
  /etc/bullnym/bullnym.env bullnym_app bullnym
```

The signing executor may issue its single provider request only after the
outer transaction containing exact preparation and `prepared -> requested`
commits under `chain-claim:<id>`. Completion must insert the exact immutable
`btc_recovery` attempt and advance `response_received -> completed` in one
transaction. An ambiguous request is never posted again; it can only receive
the exact late response or become `superseded` at unilateral timeout. The
generic deploy preflight verifies this boundary and refuses automatic rollback
across schema 057.

Every generic deployment of a schema-057-or-later artifact also stops the
current writer before inspecting the cooperative-signing journal. It refuses
the switch when that protected runtime-role query is unreadable or any row is
still nonterminal. If candidate verification later fails, automatic rollback
first stops the candidate writer and repeats the same zero-row check; a
nonzero or unreadable result leaves the candidate files installed and the
writer stopped for fix-forward recovery. This ordering closes the race in
which a candidate could otherwise create a nonce-bound operation after a
successful count and before its replacement. Deployments ending before schema
057 retain their existing rollback rules. The specialized hosted-artifact
schema-057 helper owns the initial production boundary; this generic drain gate
applies to subsequent schema-057-or-later replacements.

Do not rotate `BULLNYM_RECOVERY_MANIFEST_ENCRYPTION_KEY_ID` or
`BULLNYM_RECOVERY_MANIFEST_ENCRYPTION_KEY_HEX`, change the build target
platform/architecture, or change the pinned `secp256k1` MuSig package while
any cooperative-signing row is nonterminal (`prepared`, `requested`,
`ambiguous`, or `response_received`). Serialized secret nonces are valid only
with the same protected key, libsecp version, and platform. Drain each row to
`completed`, `integrity_hold`, or timeout `superseded` using the original
artifact first; never re-POST an ambiguous request or reuse its nonce with a
different provider nonce/session.

The zero-nonterminal gate deliberately freezes the entire runtime tuple rather
than attempting to compare or print individual capabilities: artifact,
key ID and key material, MuSig/libsecp implementation, and target platform.
Neither the protected key nor any derived key/artifact fingerprint is emitted
by the check. Drain with the original artifact before changing any member of
that tuple.

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

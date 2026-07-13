# Chain-swap manifest delivery ledger

Migration 052 is the local durable handoff for issue #87. It stores the exact
opaque encrypted envelope that a later worker must create off-host. This
package does not configure S3, hold delivery open across a network call, wire
swap creation or payer exposure, or declare the recovery path ready.

## Append-only topology

`chain_swap_manifest_deliveries` permits one row per chain-swap UUID. Manifest
UUIDs and positive global sequences are unique. Sequence 1 alone has no
predecessor; every later row must extend the exact current tail, and a manifest
UUID can be used as a predecessor only once. A dedicated transaction-level
advisory lock serializes this check for Rust and direct SQL writers.

PostgreSQL represents the sequence as `BIGINT`, so the durable domain is
`1..=i64::MAX`. Rust checks every conversion and projects valid rows to `u64`
for manifest-v1. The unreachable upper half of `u64` is intentionally outside
the database contract.

Every insert starts `pending`. While any pending row exists, tail reservation
refuses every later manifest. A crash after local commit therefore leaves one
exact envelope for a worker to resume; it cannot let another payer-facing
record skip an undelivered predecessor. Delivery advances only
`pending -> delivered`, with a corresponding timestamp. Exact repeated
acknowledgement is idempotent; a mismatched manifest, swap, sequence,
predecessor, or digest changes nothing.

The Rust insert boundary accepts only `EncryptedSwapManifestV1`, so an
arbitrary or noncanonical string cannot become the global pending barrier.
PostgreSQL still independently requires a nonempty envelope of at most one MiB
and checks its exact lowercase SHA-256, protecting against direct SQL writers.
Identity, topology, envelope, digest, and creation timestamp are immutable,
and ordinary deletion is rejected. Audit reads return full envelopes and are
therefore capped at 64 rows per page (at most 64 MiB of envelope bytes before
row metadata overhead).

## Transaction boundary

A future writer must use one database transaction to:

1. call `lock_manifest_delivery_tail`;
2. allocate the manifest UUID and construct the returned sequence/predecessor
   identity;
3. sign and encrypt the manifest with that identity;
4. parse those exact envelope bytes as `EncryptedSwapManifestV1` and call
   `insert_manifest_delivery` with that validated value;
5. commit the pending row.

Off-host I/O happens after that commit. Restart code reads
`list_pending_manifest_deliveries`, retries create-only delivery of the exact
bytes, and calls `mark_manifest_delivered` with the exact identity and digest.
Database rows are parsed back into `EncryptedSwapManifestV1` before any read or
resume API returns them; malformed restored or direct-SQL bytes fail closed as
a sanitized database-corruption error. Only after successful delivery can
another tail be reserved.

The database cannot decrypt the envelope and cannot prove its ciphertext binds
the clear ledger metadata. Typed manifest construction and restore-time
authentication remain separate required boundaries.

## Unwired delivery coordinator

`resume_pending_manifest_delivery` is the smallest bridge from the durable
ledger to `RecoveryManifestStore`. It reads a two-row invariant probe (the
schema permits at most one pending row), rejects a digest mismatch before any
object-store call, derives the object identity from the exact swap and manifest
UUIDs, and accepts only a verified create or verified identical retry. It then
requires the exact identity-and-digest acknowledgement row before reporting
success.

A storage conflict or failure leaves the row pending. If the process stops, or
the database acknowledgement fails, after a durable create, the next call is
safe: create-only storage returns the verified `AlreadyPresent` outcome and the
same acknowledgement is retried. This coordinator is not invoked by startup,
swap creation, invoice handling, admission, or a background worker; scheduling
and retry policy remain intentionally out of scope.

The opt-in `scripts/test-swap-manifest-delivery-minio.sh` contract harness runs
this coordinator against disposable PostgreSQL with the complete migration
chain and a real, versioned MinIO bucket. It proves create-and-ack, retained
readback, post-put/pre-ack retry, conflict-without-ack, and exactly one retained
object version per attempted identity. Both containers and their unique
resources are removed on success or failure; the wrapper first exercises each
cleanup trap through an intentional post-start failure and verifies the exact
anonymous data volume is absent before running the successful contract.

## Independent retention

The ledger has no persistent foreign key to `chain_swap_records`. Its insert
trigger takes a key-share lock and requires the source row to exist in the same
transaction, but later operational cleanup can remove that source without
erasing or blocking the append-only witness. There is deliberately no cascade.

No readiness check is added yet: the delivery ledger is not wired into payer
exposure, and treating an inactive foundation as a required runtime dependency
would falsely fail current deployments.

# Swap-key lineage and recovery

Bullnym derives every reverse-claim, chain-claim, and chain-refund key from
`SWAP_MNEMONIC` at an index issued by `swap_key_seq`. Migration 050 adds
`swap_key_allocations`, the non-secret, immutable allocation journal shared by
all three purposes, plus `swap_key_legacy_high_water`, the immutable per-root
exclusion copied from migration-044 rows. A reservation is committed before
Boltz sees the key.

The journal contains the root fingerprint, key epoch, derivation scheme
version, child index, purpose, compressed public key, and (for claim keys) the
preimage hash. It never contains a mnemonic, private key, or preimage.

## Legacy NULL rows

Rows created before migration 050 keep the new lineage columns `NULL`. This is
intentional. Do not invent or backfill an epoch, scheme, public key, preimage
hash, or allocation ID unless a separately verified recovery procedure proves
every value. A legacy `NULL` does not mean that an index is unused: migration
044's `(root_fingerprint, index)` indexes and the startup derivation guard remain
the conservative protection for those rows.

That compatibility is update-only for rows that already exist. After migration
050, every new reverse or chain swap insert must carry complete allocation
lineage; the database rejects even an all-`NULL` insert from a pre-044 writer.

Never edit a lineaged swap row to look legacy, and never attach an orphan
allocation to a different provider obligation.

Before any migration-044 swap row can be purged, migration 050 copies each
root's conservative maximum child index into `swap_key_legacy_high_water`.
Migration 050 refuses to run if a migration-044 identity is partially populated:
reverse metadata must be either all `NULL` or a complete root/index pair, and
chain metadata must be either all `NULL` or a complete root/claim/refund triple.
This prevents corrupt partial metadata from being silently omitted.

Signed user purge deletes all terminal reverse and chain swap rows, including
their private keys and preimages. It does not delete `swap_key_allocations` or
`swap_key_legacy_high_water`. The former preserves every migration-050
derivation identity; the latter preserves the migration-044 per-root maximum
after the detailed legacy rows are gone. Both are non-secret and immutable.
The allocation trigger rejects every index at or below the legacy maximum
before provider I/O, so gaps below the maximum remain permanently burned.

## Intentional gaps and orphan allocations

The sequence is consumed and the allocation is committed before the remote
provider call. Provider rejection, timeout, process death, or a later swap-row
write failure can therefore leave an allocation with no referencing swap row.
That orphan is expected audit evidence and its child index is an intentional
permanent gap.

Do not delete, renumber, recycle, or manually attach orphan allocations. Gaps
are harmless; reusing externally exposed key material is not. Allocation and
lineage mutation is rejected by database triggers.

## Root and epoch rotation

A rotation is a coordinated secret-and-generation change:

1. Close new reverse- and chain-swap admission while leaving recovery workers
   available for existing obligations.
2. Take and verify a PostgreSQL backup that includes `swap_key_allocations`,
   `swap_key_legacy_high_water`, both swap tables, and `swap_key_seq`.
3. Generate and escrow a new `SWAP_MNEMONIC` through the approved secret
   procedure. Never print it in a terminal transcript, ticket, or log.
4. Increment `boltz.key_epoch` and install the new mnemonic in the same release.
5. Start one instance and verify its logged non-secret root fingerprint differs
   from the previous root and reports the intended epoch and scheme version.
6. Confirm readiness and the derivation guard are healthy before reopening new
   swap admission.

Never perform an epoch-only rotation with the same mnemonic/root. The same root
and child index derives the same private key regardless of the epoch label;
public-key uniqueness will reject it, and operators must treat that rejection
as a safety incident rather than bypass it. Likewise, changing the mnemonic
without incrementing the epoch loses the intended generation boundary.

## Backup and restore requirements

Every database backup, logical export, replica promotion, and disaster-recovery
snapshot must include:

- `swap_key_allocations` and its constraints/triggers;
- `swap_key_legacy_high_water` and its constraints/triggers;
- `swap_records` and `chain_swap_records`;
- the current state of `swap_key_seq`; and
- the migration history through `050_swap_key_lineage`.

The mnemonic is backed up separately in the secret-management system. A
database without its matching mnemonic cannot recover existing swaps. A
mnemonic without the complete database allocation journal and legacy
high-water ledger must not be used to create new swaps.

After a restore, keep new swap admission closed until the active root and epoch
match the restored data and the next sequence value is strictly greater than
the active allocation maximum, the immutable legacy high-water value, and any
still-live migration-044 index for that root.

## Sequence rollback recovery

The startup check and 30-second monitor close new swap admission when
`swap_key_seq` would issue an already reserved or legacy-recorded index. Existing
claim and recovery work remains available.

When this alert fires:

1. Do not delete allocation or high-water rows and do not change the epoch to
   silence the guard. Preserve any live swap rows needed for recovery.
2. Confirm the configured mnemonic's logged root fingerprint and
   `boltz.key_epoch` match the intended restored generation.
3. Prefer restoring the correct, newest consistent database backup, including
   the allocation registry and sequence.
4. If the data is correct and only the sequence is behind, calculate the
   maximum for the active root/epoch/scheme plus the legacy ledger/live-row
   maximum. Have a second operator verify the root, epoch, scheme, maximum, and
   backup before advancing the sequence.
5. Advance only forward, restart or wait for the monitor, and confirm admission
   reopens. Never lower the sequence.

Example diagnostic query (substitute the non-secret active values):

```sql
WITH indices AS (
    SELECT child_index AS idx
      FROM swap_key_allocations
     WHERE root_fingerprint = '<active-root-fingerprint>'
       AND key_epoch = <active-key-epoch>
       AND derivation_scheme_version = 1
    UNION ALL
    SELECT max_child_index
      FROM swap_key_legacy_high_water
     WHERE root_fingerprint = '<active-root-fingerprint>'
    UNION ALL
    SELECT key_index
      FROM swap_records
     WHERE root_fingerprint = '<active-root-fingerprint>'
    UNION ALL
    SELECT claim_key_index
      FROM chain_swap_records
     WHERE root_fingerprint = '<active-root-fingerprint>'
    UNION ALL
    SELECT refund_key_index
      FROM chain_swap_records
     WHERE root_fingerprint = '<active-root-fingerprint>'
)
SELECT MAX(idx) AS required_last_issued FROM indices;
```

After independent verification, advance the sequence to at least that maximum
with PostgreSQL's `setval(..., true)` so the next `nextval` is greater. Preserve
any already-higher sequence value; never use this procedure to move backward.

Do not roll the schema back by dropping migration 050 or its registry. A
pre-050 binary must not admit new swaps against a post-050 database; roll
forward to a lineage-aware binary instead.

Migration 050 itself must be applied with every pre-050 writer stopped. Close
new swap admission, drain and stop all old instances, take the backup, apply
the migration, and start only the lineage-aware release. A rolling deployment
across this boundary is unsafe because an old process can contact the provider
without committing the allocation journal. The deployment rollback helper
therefore refuses every automatic transition from schema 050 or newer to a
pre-050 binary.

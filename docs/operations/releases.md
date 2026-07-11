# Releases

Bullnym does not currently declare a stable semantic-versioning contract or
publish repository release tags. `Cargo.toml` remains at `0.1.0`; production
identity comes from the exact Git commit and schema marker returned by
`GET /version`.

Every deployment record must capture:

- Bullnym commit SHA and dirty-state flag;
- boltz-client commit SHA;
- highest applied database migration;
- PWA build revision;
- configuration revision or change record;
- deployment and rollback timestamps.

API and signed-payload compatibility is governed by the compatibility ledger,
not the crate version. A future tagged release/versioning policy requires an
ADR defining compatibility guarantees, migration support, artifact provenance,
and rollback expectations.

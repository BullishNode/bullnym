# Recovery manifest witness loader

`swap_manifest_witness` is the bounded restore-side reader for the passive
manifest store. It is intentionally unwired.

`load_quiescent` consumes the dedicated v1 prefix to EOF, exact-reads every
listed object, opens each canonical envelope with an explicit encryption-key
identifier, 32-byte key, and pinned BIP340 signer, then requires the signed
manifest identity to equal the S3 object identity. Only after the complete set
has authenticated does the loader run the append-only set audit. Returned
manifests are in signed sequence order; an empty witness is a valid complete
result.

Completeness has an explicit quiescence precondition. The generic object-store
contract does not guarantee listing order, so the loader performs no cursor
pagination: it consumes one stream, bounds it, rejects duplicate typed object
identities, and sorts only after EOF. The caller must stop or serialize all
manifest delivery creation for the entire scan because a changing stream is not
a coherent snapshot. The loader does not itself wire the startup/delivery lock
that will satisfy this precondition.

The production limit is 10,000 records per complete load. Encountering object
10,001 fails before that entry is retained. Every retained key and size is
validated before the complete set is sorted and exact-read.

List, get, envelope, object-identity, and set-audit failures collapse into
fixed loader error classes. They retain no provider error, endpoint, key
identifier or key, envelope, object key, UUID, hash, provider identifier, or
other runtime configuration. The opening material and loader also redact their
entire store/key/signer configuration from `Debug`.

This package does not read SQL, compare the database or Boltz, reconstruct
records, run at startup, change admission, deliver pending manifests, or wire
runtime configuration. Those remain later #87 integration boundaries.

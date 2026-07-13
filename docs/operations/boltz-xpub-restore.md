# Boltz xpub restore semantics

Bullnym is pinned to `boltz-client` commit
`c20511854bbd996a74f914fa0327d4601b5d4f62`. Issue #87 recovery code must
not infer restore semantics from a different client revision.

The pinned `SwapMasterKey` derives its account key at `m/44/0/0/0` and exports
that account xpub with `get_master_xpub()`. Its `derive_swapkey(index)` method
then parses the direct relative path `m/{index}`. Because an xpub cannot derive
hardened children, valid provider indexes are exactly `0..=2^31-1`.

The pinned restore response maps indexes as follows:

- a Bullnym reverse swap (`BTC` to `L-BTC`) has one client claim index in
  `claimDetails.keyIndex`;
- a Bullnym chain swap (`BTC` to `L-BTC`) has its Liquid claim index in
  `claimDetails.keyIndex` and its Bitcoin refund index in
  `refundDetails.keyIndex`;
- the restore-index response is `-1` for no records or the highest child index
  represented by the complete restore record set.

`boltz_restore::validate_restore_records` derives each reported child locally,
checks the deterministic claim preimage, and uses the pinned Boltz contract
validators to bind the derived role key to the reported lockup contract. It
also rejects unsupported swap shapes, malformed records, duplicate provider
IDs, reused child indexes, covenant variants, and indexes with bit 31 set.
`validate_reported_high_water` requires the summary response to equal the
maximum of the validated records; the summary can never be used by itself to
advance the database allocator.

The realistic serialized fixtures are
`tests/fixtures/boltz-xpub-restore-v1.json` and
`tests/fixtures/boltz-xpub-restore-index-v1.json`. They are generated from the
pinned response types and contract primitives with the same deterministic test
mnemonic used by Bullnym's Boltz tests.

This package is intentionally offline. It does not call Boltz, alter startup or
admission, reconcile database rows, or advance `swap_key_seq`. Later wiring
must put network calls behind a bounded transport and pass the typed responses
through this validator before using manifests or database state.

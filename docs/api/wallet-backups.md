# Opaque Wallet Backups

Bullnym stores one current client-encrypted object for each stream-specific
wallet key. It cannot decrypt the object and does not accept plaintext wallet
metadata. This is a best-effort convenience service, not fund-recovery
authority.

## Routes

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/wallet-backups/fetch` | Fetch the current object or tombstone head. |
| `PUT` | `/api/v1/wallet-backups` | Conditionally create or replace an object. |
| `DELETE` | `/api/v1/wallet-backups` | Conditionally delete an object and retain a short tombstone. |

The closed stream values are `keychain_manifest` and `wallet_metadata`. Each
stream must use its own seed-derived signing key. Identifiers are JSON fields,
not URL components, so ordinary access logs do not contain public keys.

## Authentication

All requests carry `version: 1`, a canonical lowercase 64-character x-only
public key in `npub`, a Unix-seconds `timestamp`, and a canonical lowercase
128-character BIP340 `signature`. Timestamps must be within 300 seconds of the
server clock.

The signature verifies over SHA-256 of these exact NUL-separated bytes:

```text
bullbitcoin-wallet-backup-v1\0<action>\0<stream>\0<npub>\0<generation>\0<expected_etag_or_empty>\0<ciphertext_sha256_or_empty>\0<ciphertext_bytes>\0<timestamp>
```

Actions are exactly `backup-fetch`, `backup-store`, and `backup-delete`.
Unsigned JSON serialization is irrelevant. Numeric fields use unsigned base-10
without leading zeros in the signed bytes.

Fetch signs generation `0`, empty ETag/hash, and byte count `0`. Delete signs
the proposed next generation and current ETag with an empty hash and byte count
`0`.

The deterministic ETag is:

```text
SHA256("bullbitcoin-wallet-backup-etag-v1\0" || stream || "\0" ||
       npub || "\0" || generation_decimal || "\0" ||
       ciphertext_sha256_or_empty)
```

The cross-language vectors are maintained in
`tests/fixtures/wallet-backup-v1.json`.

## Fetch

Request:

```json
{
  "version": 1,
  "stream": "wallet_metadata",
  "npub": "<64 lowercase hex>",
  "timestamp": 1700000000,
  "signature": "<128 lowercase hex>"
}
```

A live response includes canonical base64 ciphertext and its independently
checked hash and decoded byte count:

```json
{
  "version": 1,
  "found": true,
  "generation": 7,
  "etag": "<64 lowercase hex>",
  "ciphertext": "<canonical base64>",
  "ciphertext_sha256": "<64 lowercase hex>",
  "ciphertext_bytes": 183421,
  "updated_at": 1700000000
}
```

An unused key returns `found: false`, generation `0`, and `etag: null`. A
recent delete returns `found: false` with the tombstone's nonzero generation,
ETag, and update time.

## Store

```json
{
  "version": 1,
  "stream": "wallet_metadata",
  "npub": "<64 lowercase hex>",
  "generation": 8,
  "expected_etag": "<current ETag or null for generation 1>",
  "ciphertext": "<canonical base64>",
  "ciphertext_sha256": "<64 lowercase hex>",
  "ciphertext_bytes": 184002,
  "timestamp": 1700000000,
  "signature": "<128 lowercase hex>"
}
```

The initial store requires generation `1` and `expected_etag: null`. A
replacement requires the current ETag and exactly the current generation plus
one. An exact retry of the current generation and ciphertext succeeds, which
makes a lost HTTP response safe to retry. A stale writer receives HTTP `409`
without the current object's contents.

Decoded ciphertext is limited to exactly 2 MiB (`2097152` bytes). The store
JSON body is limited to 3 MiB for base64 overhead. Bullnym verifies canonical
base64, decoded size, declared size, hash, timestamp, and signature before
writing.

Successful store and delete responses contain `version`, `generation`, and the
resulting `etag`.

## Delete

```json
{
  "version": 1,
  "stream": "wallet_metadata",
  "npub": "<64 lowercase hex>",
  "generation": 9,
  "expected_etag": "<current ETag>",
  "timestamp": 1700000000,
  "signature": "<128 lowercase hex>"
}
```

Delete cannot remove a newer write. It erases ciphertext and writes a
ten-minute tombstone head. Repeating the exact delete succeeds. The tombstone
outlives the authentication window so a captured initial-store request cannot
recreate a deleted object after its head disappears.

## Errors and Privacy

Backup errors always use the Bullnym JSON envelope and meaningful HTTP status:

| HTTP | Code | Meaning |
|---:|---|---|
| `400` | `BackupInvalidRequest` | Shape, version, canonical key/signature encoding, ciphertext encoding, hash, or declared size is invalid. |
| `401` | `BackupAuthError` | A well-formed key/signature did not authenticate, or the timestamp is outside the allowed window. |
| `409` | `BackupHeadConflict` | Generation or expected ETag is stale. |
| `413` | `BackupBlobTooLarge` | Body or decoded ciphertext exceeds its limit. |
| `429` | `RateLimited` | A source, key, or distinct-key gate rejected the attempt. |
| `503` | `BackupCapacityExceeded` | The configured global live-byte ceiling rejected a store. |

Fetch and conditional delete remain available when storage is full. Bullnym
observes source IP, stream, pseudonymous signing key, timing, and ciphertext
size. It does not log request bodies, ciphertext, signatures, public keys, or
ETags. Aggregate structured events include only action, stream, status,
latency, size bucket, and outcome.

All success and error responses set `Cache-Control: private, no-store,
max-age=0` and `Pragma: no-cache` so authenticated backup payloads and heads
are not retained by ordinary browser or intermediary caches.

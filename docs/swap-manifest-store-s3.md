# Chain-swap manifest S3 store

This package adds the passive S3-compatible storage boundary for issue #87. It
does **not** connect storage to swap creation, change admission, reconstruct a
database row, or claim that production has an off-host destination.

`RecoveryManifestStore` uses Apache `object_store` `0.13.2` with its maintained
S3 implementation. That library owns SigV4, TLS, custom endpoints, path-style
requests, and conditional `If-None-Match` writes. Bullnym does not implement an
S3 signing protocol.

## Object contract

The deterministic version-1 key is:

```text
<prefix>/v1/<chain-swap-uuid>/<manifest-uuid>.json
```

Both variable segments are typed canonical UUIDs. The configured prefix is
restricted to safe lowercase path segments. A write uses atomic create-only
mode and is followed synchronously by a full bounded read. Bullnym verifies the
returned bytes, byte length, format metadata, and SHA-256 metadata before it
reports success.

The write API accepts only `EncryptedSwapManifestV1`. Constructing that type
requires a canonical closed-schema v1 envelope with the fixed algorithms, a
safe key identifier, a parseable x-only signer, a 192-bit lowercase-hex nonce,
and bounded lowercase-hex ciphertext. This is structural admission, not
decryption: only restore-time authentication with the expected key and signer
can validate the encrypted payload, and the ciphertext cannot be assumed to
bind the UUIDs in the object key.

Retrying the same identity with the same bytes is idempotent. The same identity
with different bytes is an integrity conflict. The Bullnym API exposes no
overwrite or delete operation. Reads are capped at one MiB and lexicographic
S3 list pages are capped at 1,000 objects per call with an exclusive typed
cursor for the next request.

## Configuration boundary

The unwired typed configuration requires:

- endpoint and region;
- bucket and safe dedicated prefix;
- path-style or virtual-hosted-style selection;
- an explicit opt-in for plain HTTP, intended only for isolated development;
- access-key ID, secret access key, and optional session token.

Credential fields and the endpoint are redacted from `Debug`; provider error
details are not copied into public errors. Future runtime wiring must load the
credentials from a protected environment file rather than checked-in TOML.

## Disposable MinIO contract gate

Run the opt-in real-adapter check with:

```bash
scripts/test-swap-manifest-store-minio.sh
```

The harness starts a uniquely named MinIO container on a random loopback port,
creates a disposable bucket, and runs the otherwise ignored integration test.
It proves create-only write, identical retry, differing-byte conflict without
overwrite, verified read-after-write, bounded cursor pagination, rejected
credentials, and public error/debug redaction. The pinned MinIO server and
client images can be deliberately overridden with `MINIO_IMAGE` and
`MINIO_MC_IMAGE`. The harness removes and verifies removal of its container and
network on success or failure.

## Off-host provisioning still required

The production VM currently has no configured independent object store. Before
creation wiring can be enabled, operators must provision one S3-compatible
bucket that supports conditional create, configure least-privilege credentials,
and fixture-test its exact behavior. The runtime principal should have only the
minimum create/get/list permissions and no delete permission. Bucket versioning
or provider retention/object-lock controls are recommended defense in depth;
they do not replace Bullnym's create-only conditional request.

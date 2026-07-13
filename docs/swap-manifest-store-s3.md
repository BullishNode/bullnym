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

## Off-host provisioning still required

The production VM currently has no configured independent object store. Before
creation wiring can be enabled, operators must provision one S3-compatible
bucket that supports conditional create, configure least-privilege credentials,
and fixture-test its exact behavior. The runtime principal should have only the
minimum create/get/list permissions and no delete permission. Bucket versioning
or provider retention/object-lock controls are recommended defense in depth;
they do not replace Bullnym's create-only conditional request.

# ADR 010: Legacy media is read-only

- Status: Accepted
- Date: 2026-07-11
- Scope: `bullnym`, `bullbitcoin-mobile`

## Context

Older Payment Page records and API responses contain avatar and Open Graph
image hashes. Bullnym no longer supports image upload.

## Decision

The server exposes legacy media fields only for compatibility. The upload
route, multipart handler, image processor, upload-specific errors, rate limits,
configuration, tests, and image dependency are removed. New clients must not
offer upload controls or depend on media fields being populated. Proxy and
operations documentation must not configure a writable media pipeline.

Removal of the legacy columns, existing files, read-only rendering, and alias
copy helper requires a production data/traffic audit and a separately reviewed
migration.

## Consequences

The compatibility surface remains visible until audited deletion is safe, but
it is not a supported feature. This avoids destroying references used by older
records while preventing new uploads or new operational dependence.

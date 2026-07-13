# Utility and Operations APIs

| Method and path | Response/use | Implication |
|---|---|---|
| `GET /qr.svg?data=...` | Deterministic 256px-minimum SVG, input 1-4096 UTF-8 bytes | Public/rate-limited. Encode only payment payloads; arbitrary untrusted data may produce unusable dense QRs. |
| `GET /health` | Liveness response | Proves the process serves HTTP, not that DB/schema/dependencies work. |
| `GET /ready` | Component JSON and HTTP 200/503 | Checks DB, the complete expected schema marker, and required access to the chain-swap recovery journal plus the live direct-payment reducer's scan/transition journals. Compatibility writers share its projection and Boltz-supersession boundaries. Use for load-balancer readiness. |
| `GET /version` | Public compatibility fields: service/crate/Bullnym revision, dirty state, runtime mode, expected schema marker | Use for rollout preflight and support reports. Full verified Boltz, toolchain, target, profile, and PWA provenance remains operator-only through `pay-service --build-info` and startup logs. |
| `GET /robots.txt` | Indexing policy | Privacy aid, not access control. |
| `GET /certification/preflight?scopes=...` | Certification readiness | Test-harness endpoint; not end-user authentication. |
| `POST /webhook/boltz/:secret` | Boltz status delivery | Operator integration. Path secret is sensitive and may appear in proxy logs. |
| `POST /webhook/boltz` | Legacy/development webhook | Rejected when a webhook URL secret is configured. Do not deploy as the production target. |

Certification scopes are comma-separated values from `registration_setup`,
`metadata_lookup`, `invoice_create`, `invoice_status`, and `live_money_offer`.
Authorized harnesses send `x-bullnym-certification-token`. The response reports
`enabled`, source/token validity, requested/configured/missing scopes, and
`ready`. It only bypasses selected rate limits from configured source networks;
it does not bypass signatures, ownership, validation, or money invariants.

`/ready` deliberately does not report per-rail money admission. An HTTP-serving
instance with the current writable schema must stay available to process
existing webhooks, claims, reconciliation, status reads, and recovery even when
it refuses new payment instructions. New-money requests for a closed rail
receive HTTP 503 with the fixed public message `This payment method is
temporarily unavailable. Try again later.` Operators diagnose the private
rail/dependency reason codes from `money_admission_changed` transition logs.

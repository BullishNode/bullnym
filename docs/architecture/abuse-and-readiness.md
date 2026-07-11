# Rate Limits and Certification

Bullnym rate limits protect descriptors, public lookup endpoints, expensive
external calls, webhooks, and signed write paths.

## Rate-Limit Surfaces

| Surface | Purpose |
|---|---|
| Registration | Prevent nym squatting and expensive descriptor/signature floods. |
| Metadata and NIP-05 lookup | Limit public probing of nyms and owner keys. |
| LNURL callback | Protect Boltz and Liquid Electrum calls. |
| LUD-22 proof checks | Bound Liquid UTXO verification and descriptor-index allocation. |
| Payment Page/POS render | Protect public HTML fallback. |
| Checkout creation | Protect surface descriptor cursor allocation and eager offer creation. |
| Invoice create/list/status | Protect signed dashboard and public polling surfaces. |
| Webhook | Bound webhook-bombing from a single source. |

## LUD-22 Descriptor Protection

LUD-22 protects descriptor cursors with:

- UTXO ownership proof
- minimum UTXO value
- `(nym, outpoint)` idempotency
- per-outpoint fan-out caps
- optional per-pubkey cap (disabled by default)
- pending reservation TTL cleanup

These controls make address allocation costly to abuse and prevent repeated
requests for the same outpoint from advancing the cursor.

Public-surface descriptor allocation is different from LUD-22. Opening the page
does not allocate an address, but `POST /:nym/invoice` currently allocates the
checkout settlement address immediately. Protecting that cursor depends on the
anonymous invoice-create rate limit and certification preflight, not on a
Liquid-specific proof-of-funds request.

## IP Whitelist

`rate_limit.ip_whitelist` bypasses all rate limits and the LUD-22 proof gate.
It is intentionally broad and should be reserved for known infrastructure that
needs full bypass behavior.

## Certification Allowlist

`[certification]` is narrower than the IP whitelist. It requires:

- enabled certification mode
- allowed source IP/CIDR
- `X-Bullnym-Certification-Token`
- explicit scopes

Certification scopes are for deterministic server/payment-rail tests. They do
not turn bullnym-test into a mobile test environment.

## Preflight

Broad certification should call `/certification/preflight` before setup or
money movement. If source, token, scope, balances, or server provenance are not
ready, the run should fail preflight instead of producing skipped scenarios.

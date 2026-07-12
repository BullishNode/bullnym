# 005 Bullnym Mobile Protocol Contract

Status: Accepted

## Decision

Bull Bitcoin Mobile talks to Bullnym through a shared `features/bullnym`
protocol client. Product features must not hand-roll Bullnym HTTP calls,
signature payloads, DTO parsing, or error mapping.

Current signed mobile surfaces include:

- Lightning Address registration/update/recovery and NIP-05 verification;
- Payment Page get/save/archive;
- linked and unlinked invoice create/list/cancel;
- BTCPay/SamRock descriptor exchange through the owning BTCPay flow.

Signed payload field order is a server contract. Mobile DTOs mirror server
response shapes but stay behind feature ports so presentation code does not
depend directly on Bullnym transport types.

## Rationale

Bullnym APIs mix public routes, signed mutations, rate-limited endpoints,
payment state, descriptors, and Nostr identity material. Duplicating this wire
logic in each product feature would make mobile/server compatibility fragile.

## Consequences

- Signing changes must update Bullnym docs, mobile Bullnym DTO/client tests,
  and feature tests together.
- `verification_npub`, page descriptors, invoice wallet-origin addresses, and
  chain-swap fields are compatibility-sensitive.
- Presentation code must never derive or carry Nostr secrets directly.
- Private mobile-only metadata, such as invoice private memo, must not be sent
  to Bullnym unless the server contract explicitly adds it.

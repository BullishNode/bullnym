# Integration Decisions

## Descriptor or explicit address

Use descriptors for long-lived Lightning Address/Payment Page/POS products that
need a fresh address per payment. Use explicit unique addresses for one-off
wallet invoices. Descriptors improve address-reuse privacy but give the server
visibility across the dedicated wallet; explicit addresses reduce server
derivation power but make the client responsible for uniqueness and recovery.

## Linked or unlinked invoice

Link when the payer benefits from the recipient's stable name/branding and the
recipient owns an active nym. Use unlinked invoices for a minimally branded
share URL or identities without a nym. Neither mode hides the invoice from the
server, and the UUID remains a public bearer capability for status.

## Lightning, Liquid, or Bitcoin

Lightning maximizes payer compatibility but adds Boltz dependency, fees, and
asynchronous settlement. Direct Liquid is fast and inexpensive but requires a
Liquid-capable payer and exposes unblinding data to Bullnym. Direct Bitcoin is
widely verifiable but confirmation-latent and reorg-sensitive. Enabling all
rails improves conversion but requires clients to handle mixed/partial payment
accounting and retain keys for every destination.

## Alias or nym URL

Alias URLs decouple public branding from the Lightning Address nym and can
scrub it from page/payment presentation. One optional lifetime alias belongs to
the npub and is shared by Payment Page and POS; nyms and aliases occupy one
permanent namespace. Without an active alias, generated links fall back to the
nym without creating a second claim. Aliases are public and enumerable, so
they are not an anonymity boundary. HTTP management clients receive
`public_url` in `DonationPageView` and should use it for sharing. The
server-injected PWA configuration also has `invoice_base` for browser clients;
it is not returned by the management API.

## Production client checklist

1. Pin HTTPS and configure the deployment origin; never accept a base URL from
   an invoice response without an explicit trust policy.
2. Use a dedicated BIP-85-derived auth key and dedicated Liquid purpose
   wallets/descriptors; back them up through the wallet's documented recovery.
3. Build signing bytes independently of JSON serialization and test byte-exact
   vectors, especially empty fields and optional trailing surface fields.
4. Parse coded error envelopes on every status, including HTTP 200.
5. Fetch supported currencies, preserve integer minor units, and avoid
   floating-point money calculations.
6. Generate a fresh Bitcoin/Liquid address for every wallet invoice and retain
   its spend/blinding material before calling create.
7. Treat invoice URLs/UUIDs as bearer-readable, stop polling terminal states,
   and distinguish payment accounting from swap settlement.
8. Reconcile ambiguous create/cancel outcomes through signed list/status APIs
   before repeating state-changing operations.
9. Validate `/version` and `/ready` during rollout; feature-probe optional
   routes such as NIP-05 and recovery.
10. Localize by stable error `code`, log build metadata and request context,
    and never log private keys, descriptors, blinding keys, signatures, BOLT11s,
    webhook secrets, or complete payment URLs at broad log levels.

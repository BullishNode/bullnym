# Bullnym documentation

These documents describe the maintained Bullnym server. Proposed work belongs
in [RFCs](rfcs/README.md); completed, superseded, and abandoned material belongs
in the [archive](../archive/README.md).

## Start here

- [Architecture overview](architecture/overview.md)
- [Trust model](architecture/trust-model.md)
- [Payment lifecycle](architecture/payment-lifecycle.md)
- [API reference](api/README.md)
- [Operations](operations/README.md)
- [Compatibility ledger](reference/compatibility.md)
- [Glossary](reference/glossary.md)

## Architecture

- [Overview](architecture/overview.md)
- [Trust model](architecture/trust-model.md)
- [Payment lifecycle](architecture/payment-lifecycle.md)
- [Data and workers](architecture/data-and-workers.md)
- [Identity and authentication](architecture/identity-and-auth.md)
- [Abuse controls and readiness](architecture/abuse-and-readiness.md)
- [PWA runtime](architecture/pwa.md)

## Products and protocols

- [Lightning Address](products/lightning-address.md)
- [Payment Pages](products/payment-pages.md)
- [POS](products/pos.md)
- [Invoices](products/invoices.md)
- [LUD-22 Liquid negotiation](protocols/lud-22.md)

## Engineering records

- [Architecture decisions](adr/README.md)
- [RFCs](rfcs/README.md)
- [Operations](operations/README.md)
- [Reference](reference/README.md)

## Documentation policy

Maintained documentation states current behavior and links to source where a
claim is subtle. ADRs record accepted decisions. RFCs describe work that has
not necessarily shipped. Archived files are historical evidence only and must
carry a lifecycle label.

Run `scripts/check-docs.sh` before submitting documentation changes.

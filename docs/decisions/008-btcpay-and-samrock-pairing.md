# 008 BTCPay and SamRock Pairing

Status: Accepted

## Decision

BTCPay uses reserved BIP85 index `77` for both Bitcoin and Liquid wallets.
Local wallet preparation is separate from server pairing.

The mobile BTCPay/SamRock flow:

- parses HTTPS SamRock protocol URLs ending in `/samrock/protocol`;
- requires a non-empty `otp`;
- supports `btc-chain`/`btc`, `liquid-chain`/`lbtc`, `btc-ln`/`btcln`, omitted
  setup, and `setup=all`;
- creates or reuses requested path-77 BTC/LBTC wallets after a pairing request
  is supplied;
- uses the Liquid path-77 wallet for Lightning setup because SamRock `BTCLN` is
  Boltz-backed and carries Liquid descriptor data;
- submits descriptor data to the SamRock protocol URL;
- marks the dashboard connected/ready only after server confirmation succeeds;
- publishes the wallet manifest best-effort only after all requested local
  wallets exist and the server accepts the pairing.

## Rationale

BTCPay pairing is both local wallet preparation and remote server state. Mixing
those states would make the UI claim readiness before the SamRock server has
accepted descriptors.

## Consequences

- Manifest publication for BTCPay must not happen after only one of the
  requested BTC/LBTC wallets exists.
- Server-connected state is BTCPay/SamRock-owned and is not inferred from local
  wallet existence.
- Get Paid manual recovery can recreate BTCPay path-77 wallets but does not
  recreate server pairing state.

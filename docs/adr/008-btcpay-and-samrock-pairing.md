# 008 BTCPay and SamRock Pairing

- Status: Accepted
- Amended: 2026-07-28 — corrected to the shipping pairing flow (#273, #274)
- Scope: `bullbitcoin-mobile`; verify SamRock behavior externally

## Decision

BTCPay uses the reserved BIP85 child seed at `39'/0'/12'/100'` for both its
Bitcoin and Liquid wallets. Local wallet preparation is separate from server
pairing.

The mobile BTCPay/SamRock flow:

- parses HTTPS SamRock protocol URLs whose path ends in
  `/plugins/{store}/samrock/protocol`; the store ID is taken from that path;
- requires a non-empty `otp`;
- requires an explicit `setup` value: a comma-separated, case-insensitive list
  of `btc-chain`/`btc`, `liquid-chain`/`lbtc`, and `btc-ln`/`btcln`, or
  `setup=all`. An absent, empty, or unrecognized `setup` is rejected;
- always prepares (creates or reuses) both the Bitcoin and the Liquid
  path-`100'` wallets, even when the server requests one payment rail; the
  consent copy discloses both wallets;
- records the keychain-manifest entry for both wallet materializations after
  the wallets exist and before payload construction or descriptor submission;
  if that record step fails, descriptors are not shared and the prepared
  wallets are kept for retry;
- uses the Liquid path-`100'` wallet's descriptor for Lightning setup because
  SamRock `BTCLN` is Boltz-backed and carries Liquid descriptor data;
- submits the requested descriptors to the SamRock protocol URL in one HTTP
  call;
- saves the connection as confirmed only on explicit server success; explicit
  rejection is not saved as a connection, and transport or ambiguous outcomes
  persist as `uncertain`;
- applies BTCPay wallet-behavior defaults best-effort after server acceptance.

## Rationale

BTCPay pairing is both local wallet preparation and remote server state. Mixing
those states would make the UI claim readiness before the SamRock server has
accepted descriptors.

Recovery metadata is recorded before any descriptor leaves the device: once a
descriptor may have reached a server, the wallets behind it must already be
recoverable, and a crash, rejection, or lost response must never orphan them.
Retained wallets and manifest entries make retries idempotent.

## Consequences

- Wallet materialization and keychain-manifest recording precede descriptor
  disclosure; they are never rolled back because pairing failed afterwards.
- Server-connected state is BTCPay/SamRock-owned and is not inferred from local
  wallet existence.
- Manifest/seed restore may recreate the BTCPay path-`100'` wallets, but local
  wallet existence does not recreate server pairing state.
- Remote backup publication is coordinated by `wallet_backup` from the
  manifest record signal; it is best-effort and does not gate pairing.

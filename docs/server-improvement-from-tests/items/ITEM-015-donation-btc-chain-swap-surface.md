# ITEM-015: Donation BTC Chain-Swap Surface

Backlog reference: `ISSUE-013`
Type: BTC/Boltz/payment-page reliability
Priority: P2
Status: closed

## Confirmed Conclusion

Donation-page BTC chain swaps are distinct from direct BTC invoice observations. The server already separates direct BTC addresses from Boltz BTC-to-LBTC chain-swap offers in invoice status and render code. Remaining proof requires live Boltz chain-swap scenarios.

## Non-Goals

- Do not treat direct BTC invoice tests as chain-swap proof.
- Do not force BTC chain-swap availability for small amounts Boltz refuses.

## Verification Result

- Local compile coverage for chain-swap status helpers exists in integration test build.
- Remaining proof: `DCHAIN-*` targeted runs after `/version` and certification preflight.

## Closure Decision

Closed for local server assessment. Live DCHAIN certification remains required.

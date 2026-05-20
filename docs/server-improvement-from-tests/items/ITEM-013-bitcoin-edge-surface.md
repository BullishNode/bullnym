# ITEM-013: Bitcoin Edge Surface

Backlog reference: `ISSUE-009`
Type: BTC reliability
Priority: P1
Status: closed

## Confirmed Conclusion

The local server work needed before BTC edge certification was ITEM-003: persisted direct-BTC observations and explicit status projection. The remaining BTC edge cases are live/VM certification work, not additional local code without evidence.

## Non-Goals

- Do not run full BTC edge suites without funded sender, mempool visibility, and `/version` preflight.
- Do not infer server defects from skipped `BTC-02` through `BTC-20`.

## Verification Result

- Local compile and DB invariants were covered by ITEM-003.
- Remaining proof: targeted `BTC-01`, then BTC underpay/overpay/late/cancel/reuse cases.

## Closure Decision

Closed for local server implementation. BTC edge certification remains blocked on live preflight and funding.

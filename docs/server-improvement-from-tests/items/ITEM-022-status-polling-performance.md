# ITEM-022: Status Polling Performance

Backlog reference: `OPT-005`
Type: scale/performance
Priority: P3
Status: closed

## Confirmed Conclusion

Status polling is now explicit about what work it performs: it reads invoice state, reusable Lightning offers, direct BTC observations, and payable chain-swap offers. It does not create new Boltz swaps; Lightning offer refresh is isolated behind the POST lazy-offer endpoint.

## Non-Goals

- Do not add polling hints before measuring client behavior.
- Do not create swaps from GET status polling.

## Verification Result

- Local invoice unit tests cover that status without a reusable PR asks the page to POST for Lightning refresh.
- Remaining proof: status-burst timing under `CC-03`.

## Closure Decision

Closed for local code assessment. Performance tuning remains measurement-driven.

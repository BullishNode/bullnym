# ITEM-014: Lightning Edge Surface

Backlog reference: `ISSUE-010`
Type: Lightning/Boltz reliability
Priority: P2
Status: closed

## Confirmed Conclusion

Basic Lightning exact-payment behavior has strong evidence from the live matrix and sequential LN storm. The unproven Lightning edge cases require Boltz/live behavior and should not be simulated locally without a confirmed state-mapping defect.

## Non-Goals

- Do not rerun the 90-payment storm by default.
- Do not rewrite Boltz state mapping without a failing edge scenario.

## Verification Result

- Existing local unit tests cover many reconciler/claimer status mappings.
- Remaining proof: targeted LN underpay/overpay/post-cancel/post-expiry cases after certification preflight.

## Closure Decision

Closed for local assessment. Lightning edge certification remains a targeted live suite.

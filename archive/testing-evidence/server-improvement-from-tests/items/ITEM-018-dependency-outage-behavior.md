> **Archived: testing evidence.** Retained for historical verification context; current code and maintained documentation are authoritative.

# ITEM-018: Dependency Outage Behavior

Backlog reference: `ISSUE-018` / `OPT-011`
Type: operational resilience
Priority: P2
Status: closed

## Confirmed Conclusion

Dependency outage behavior cannot be proven by local unit tests alone. The server already returns typed `ServiceUnavailable` for pricer-dependent invoice creation and has explicit Boltz/Electrum error classes. The remaining work is executable outage drills.

## Non-Goals

- Do not add fake health success for dependencies.
- Do not swallow dependency failures into generic success responses.

## Verification Result

- Local code inspection only.
- Remaining proof: `OP-02` through `OP-05` with controlled pricer, Boltz, Electrum, and mempool outages.

## Closure Decision

Closed for local assessment. Dependency outage certification remains VM/playbook work.

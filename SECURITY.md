# Security policy

Do not open a public issue for a vulnerability that could expose payment
metadata, descriptors, swap keys, recovery material, authentication secrets, or
create a path to fund loss. Use [Bullnym private vulnerability reporting](https://github.com/BullishNode/bullnym/security/advisories/new).

Include affected revision, deployment assumptions, reproduction steps, impact,
and whether funds or secrets may currently be at risk. Do not move real funds,
access data that is not yours, or test against production without explicit
authorization.

Operational payment incidents should preserve database rows, provider
responses, transaction artifacts, and independent chain evidence. Follow the
[swap recovery runbook](docs/operations/runbooks/stuck-swaps.md); do not publish
sensitive incident artifacts in GitHub issues.

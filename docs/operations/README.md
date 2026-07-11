# Operations

- [Configuration](configuration.md)
- [Deployment](deployment.md)
- [Monitoring](monitoring.md)
- [Swap recovery runbook](runbooks/stuck-swaps.md)
- [nginx example](nginx.conf.example)

Operational decisions involving money state require three-way reconciliation:
database records, independent chain evidence, and provider evidence. Preserve
all recovery artifacts before intervening.

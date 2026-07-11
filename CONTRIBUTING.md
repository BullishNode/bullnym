# Contributing

## Workflow

1. Read the architecture overview, trust model, and relevant ADRs.
2. Keep changes within the owning module and preserve signed API compatibility.
3. Use an RFC for cross-product behavior, migrations with recovery impact, or
   changes to payment trust boundaries.
4. Add tests proportional to the money, compatibility, and migration risk.
5. Update maintained docs in the same change; archive completed planning notes.

Run the focused test first, then the applicable suite:

```bash
cargo fmt --check
cargo test --lib
cargo test --tests --no-run
scripts/check-docs.sh
```

PWA changes additionally require `npm test`, `npm run build`, and
`npm run check:dist` from `pwa/`. Database integration tests require an isolated
`TEST_DATABASE_URL`. Never aim broad tests at production payment resources.

## Documentation lifecycle

- `docs/architecture`, `products`, `protocols`, `api`, `operations`, and
  `reference` describe current behavior.
- `docs/adr` records accepted decisions.
- `docs/rfcs` contains active proposals and must not be cited as shipped fact.
- `archive` contains historical material only.

Do not duplicate the API contract in feature docs. Link to the canonical API
page and explain only product or architectural implications.

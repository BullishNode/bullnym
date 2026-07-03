# PWA Architecture

## Tech stack

Identical to nostr-pos's `pos-pwa` — same decisions, for the same reasons:

| Layer | Choice | Why |
|---|---|---|
| Framework | Svelte 5 (runes) | Reactive, minimal, compiles away |
| Build | Vite + vite-plugin-pwa | Fast, PWA manifest + service worker |
| Routing | svelte-spa-router | Hash routing, no SSR, pure static output |
| Styling | Tailwind CSS | Same as nostr-pos; utility-first, easy to port design tokens |
| Language | TypeScript (strict) | Type-safe API client |
| HTTP client | native `fetch` | No dependencies needed |
| QR | qrcode (npm) | Small, terminal-friendly render |
| Print | browser `window.print()` | No deps, works everywhere |
| NFC | Web NFC API | Native browser, Android Chrome only |
| Confetti | canvas-confetti | 3 KB, nostr-pos already uses it |

No Nostr libraries. No IndexedDB crypto. No relay connections. No gift-wrap. No key
derivation. The logic layer is a typed REST client and a handful of Svelte stores.

## Two entry points, one PWA workspace

Both modes share components and the API client. Two separate Vite entry points produce
two separate HTML shells:

```
pwa/apps/donation/index.html   → served for donation-mode nyms
pwa/apps/pos/index.html        → served for POS-mode nyms
```

The server renders the right shell based on `pos_mode` on the nym's `donation_pages` row.
Both shells import from `pwa/lib/`.

## How the server serves the PWA

Today the server renders `store_amount.html` via Askama. Replace that with:

1. At startup, Rust reads the built PWA output (`pwa/dist/donation/` and `pwa/dist/pos/`)
   into memory, or serves them as static files via `tower-http::ServeDir`.
2. `GET /<nym>` route (the fallback in `donation_render.rs`) checks `pos_mode`:
   - `false` → serve `dist/donation/index.html` with nym injected as a `<script>` data
     block or query param
   - `true` → serve `dist/pos/index.html` same way
3. Static assets (`/pwa-assets/...`) served from `dist/` via `ServeDir`.

Nym is injected server-side as a small JSON block in the HTML shell:

```html
<script id="bullnym-config" type="application/json">
{"nym":"smoke-d1418d1dc13f","mode":"pos","currency":"USD"}
</script>
```

PWA reads this at boot — no API round-trip needed to know which nym it's running for.

## Service worker scope

`vite-plugin-pwa` generates a service worker that pre-caches the app shell and static
assets. API calls (`POST /<nym>/invoice`, `GET /api/v1/invoices/:id/status`) are
network-first, never cached. This lets the PWA install and open offline but correctly
fails payment creation when the server is unreachable.

## Development workflow

```bash
cd pwa
npm install
npm run dev          # both entry points via Vite dev server
npm run build        # outputs to pwa/dist/
npm run check        # tsc + svelte-check
npm run test         # vitest unit tests
```

In development, proxy API calls to the running Rust server:

```ts
// vite.config.ts
server: {
  proxy: {
    '/api': 'http://127.0.0.1:8080',
    '/.well-known': 'http://127.0.0.1:8080',
  }
}
```

## Build integration with Cargo

`build.rs` in the Rust crate can run `npm run build` before compilation if
`pwa/dist/` is stale, or this can be a Makefile target. Either way, `cargo build
--release` should produce a self-contained binary that embeds or serves the PWA.

Options:
- `include_dir!` macro to embed PWA into binary (best for single-binary deploys)
- `tower-http::ServeDir` pointing at a path (more flexible, easier to update PWA
  without recompiling Rust)

Recommended: `ServeDir` for now. Binary embedding deferred to later.

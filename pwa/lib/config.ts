// Server-injected boot config. The Rust server replaces the
// <!-- BULLNYM_CONFIG --> placeholder in the HTML shell with a
// <script id="bullnym-config" type="application/json"> block, so the
// PWA knows its nym without an API round-trip.

export interface BullnymConfig {
  /// Merchant nym. Present on nym-path pages; empty on alias pages (the
  /// server omits it so the alias page never carries the nym). Prefer
  /// `page_key` for storage keys and `invoice_base` for URL construction.
  nym: string
  /// Public base path the client appends `/invoice` and `/i/<id>` to:
  /// `/<nym>`, `/<nym>/pos`, `/a/<slug>`, or `/a/<slug>/pos`. The client no
  /// longer composes this from the nym, so alias pages stay nym-free.
  invoice_base: string
  /// Stable namespace key for client-side storage (settings, history, PIN).
  /// Equals the nym on nym pages (no key migration for installed PWAs) and
  /// the slug on alias pages.
  page_key: string
  mode: 'donation' | 'pos'
  currency: string
  header: string
  description: string
  website: string | null
  twitter: string | null
  instagram: string | null
  /// Minor units per BTC at render time. 0 = rate unavailable.
  minor_per_btc: number
  last_known_rate: boolean
  domain: string
  /// Liquid Bitcoin (L-BTC) asset id, used to build liquidnetwork: URIs
  /// (see lib/payloads.ts's liquidUri). Server-injected in production; the
  /// fallback below is the real mainnet L-BTC asset id so dev/tests work
  /// without a live server.
  liquid_btc_asset_id: string
}

const FALLBACK: BullnymConfig = {
  nym: '',
  invoice_base: '',
  page_key: '',
  mode: 'donation',
  currency: 'USD',
  header: '',
  description: '',
  website: null,
  twitter: null,
  instagram: null,
  minor_per_btc: 0,
  last_known_rate: false,
  // `location` doesn't exist in vitest's default Node test environment —
  // lib/invoice-load.ts (and anything importing it) pulls in this module
  // just for `config.currency`'s fallback, so this can't unconditionally
  // touch `location` at module-load time the way it used to when only
  // browser code imported config.ts.
  domain: typeof location !== 'undefined' ? location.host : '',
  liquid_btc_asset_id: '6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d',
}

// Back-compat: a stale cached shell served by an older backend sends `nym`
// and `mode` but no `invoice_base`/`page_key`. Derive them from the nym so
// those installs (and dev/tests) keep working; a fresh server always supplies
// both explicitly, which wins.
function withDerivedRouting(c: BullnymConfig): BullnymConfig {
  const invoice_base =
    c.invoice_base || (c.nym ? (c.mode === 'pos' ? `/${c.nym}/pos` : `/${c.nym}`) : '')
  const page_key = c.page_key || c.nym
  return { ...c, invoice_base, page_key }
}

export function parseConfig(): BullnymConfig {
  if (typeof document === 'undefined') return FALLBACK
  const el = document.getElementById('bullnym-config')
  if (!el?.textContent) {
    // Dev server: allow ?nym= override so `npm run dev` works against a
    // live backend without the injected block.
    if (import.meta.env.DEV) {
      const params = new URLSearchParams(location.search)
      const nym = params.get('nym')
      if (nym) return withDerivedRouting({ ...FALLBACK, nym, header: nym })
    }
    return FALLBACK
  }
  try {
    return withDerivedRouting({ ...FALLBACK, ...JSON.parse(el.textContent) })
  } catch {
    return FALLBACK
  }
}

export const config: BullnymConfig = parseConfig()

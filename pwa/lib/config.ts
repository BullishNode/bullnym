// Server-injected boot config. The Rust server replaces the
// <!-- BULLNYM_CONFIG --> placeholder in the HTML shell with a
// <script id="bullnym-config" type="application/json"> block, so the
// PWA knows its nym without an API round-trip.

export interface BullnymConfig {
  nym: string
  mode: 'donation' | 'pos'
  currency: string
  header: string
  description: string
  avatar_url: string | null
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
  mode: 'donation',
  currency: 'USD',
  header: '',
  description: '',
  avatar_url: null,
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

export function parseConfig(): BullnymConfig {
  if (typeof document === 'undefined') return FALLBACK
  const el = document.getElementById('bullnym-config')
  if (!el?.textContent) {
    // Dev server: allow ?nym= override so `npm run dev` works against a
    // live backend without the injected block.
    const params = new URLSearchParams(location.search)
    const nym = params.get('nym')
    if (nym) return { ...FALLBACK, nym, header: nym }
    return FALLBACK
  }
  try {
    return { ...FALLBACK, ...JSON.parse(el.textContent) }
  } catch {
    return FALLBACK
  }
}

export const config: BullnymConfig = parseConfig()

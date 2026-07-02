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
  domain: location.host,
}

export function parseConfig(): BullnymConfig {
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

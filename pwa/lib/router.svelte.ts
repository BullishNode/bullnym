// Minimal hash router. Five static route shapes total across both
// modes — a dependency-free $state wrapper beats pulling in a router
// library that predates Svelte 5 runes.

function parseHash(): string {
  const h = location.hash
  return h.startsWith('#/') ? h.slice(1) : '/'
}

const state = $state({ path: parseHash() })

window.addEventListener('hashchange', () => {
  state.path = parseHash()
})

export const router = {
  get path(): string {
    return state.path
  },
  go(path: string): void {
    location.hash = '#' + path
  },
  /** Match "/pay/:id" style patterns; returns params or null. */
  match(pattern: string): Record<string, string> | null {
    const p = pattern.split('/')
    const a = state.path.split('/')
    if (p.length !== a.length) return null
    const params: Record<string, string> = {}
    for (let i = 0; i < p.length; i++) {
      const seg = p[i]!
      if (seg.startsWith(':')) params[seg.slice(1)] = decodeURIComponent(a[i]!)
      else if (seg !== a[i]) return null
    }
    return params
  },
}

// Minimal hash router. Five static route shapes total across both
// modes — a dependency-free $state wrapper beats pulling in a router
// library that predates Svelte 5 runes.

function parseHash(): string {
  const h = location.hash
  return h.startsWith('#/') ? h.slice(1) : '/'
}

const state = $state({ path: parseHash() })

const NAVIGATION_STATE_KEY = 'bullnymRoute'

interface NavigationState {
  from: string | null
  to: string
}

function currentHistoryState(): Record<string, unknown> {
  return history.state && typeof history.state === 'object'
    ? (history.state as Record<string, unknown>)
    : {}
}

function navigationState(): NavigationState | null {
  const value = currentHistoryState()[NAVIGATION_STATE_KEY]
  if (!value || typeof value !== 'object') return null
  const from = (value as { from?: unknown }).from
  const to = (value as { to?: unknown }).to
  if ((from !== null && typeof from !== 'string') || typeof to !== 'string') return null
  return { from: from ?? null, to }
}

function writeRoute(path: string, replace: boolean): void {
  const nextState = {
    ...currentHistoryState(),
    [NAVIGATION_STATE_KEY]: {
      from: replace ? navigationState()?.from ?? null : state.path,
      to: path,
    },
  }
  if (replace) history.replaceState(nextState, '', `#${path}`)
  else history.pushState(nextState, '', `#${path}`)
  // pushState/replaceState do not emit hashchange or popstate.
  state.path = path
}

function syncPath(): void {
  state.path = parseHash()
}

window.addEventListener('hashchange', syncPath)
window.addEventListener('popstate', syncPath)

export const router = {
  get path(): string {
    return state.path
  },
  go(path: string): void {
    writeRoute(path, false)
  },
  /**
   * A payment deep link may be the browser tab's first Bullnym entry. Insert
   * an in-app fallback behind it so the browser/app Back action opens the
   * donation form instead of closing the externally opened tab. Internal
   * navigation already has that entry and is left untouched.
   */
  ensureBackTarget(fallbackPath: string): void {
    const currentPath = state.path
    const currentNavigation = navigationState()
    if (currentNavigation?.from === fallbackPath && currentNavigation.to === currentPath) return

    history.replaceState(
      {
        ...currentHistoryState(),
        [NAVIGATION_STATE_KEY]: { from: null, to: fallbackPath },
      },
      '',
      `#${fallbackPath}`,
    )
    history.pushState(
      {
        ...currentHistoryState(),
        [NAVIGATION_STATE_KEY]: { from: fallbackPath, to: currentPath },
      },
      '',
      `#${currentPath}`,
    )
  },
  /** Return to an existing in-app fallback when one is known; otherwise keep
   * the payer in the current tab by replacing the current route. */
  backOrReplace(fallbackPath: string): void {
    const currentNavigation = navigationState()
    if (currentNavigation?.from === fallbackPath && currentNavigation.to === state.path) {
      history.back()
      return
    }
    writeRoute(fallbackPath, true)
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

import { afterEach, describe, expect, it, vi } from 'vitest'

type Listener = () => void

function installBrowser(initialHash: string) {
  const listeners = new Map<string, Listener[]>()
  const locationMock = { hash: initialHash }
  const entries: Array<{ hash: string; state: unknown }> = [{ hash: initialHash, state: null }]
  let index = 0
  let backCalls = 0

  const dispatch = (type: string) => {
    for (const listener of listeners.get(type) ?? []) listener()
  }
  const historyMock = {
    get state() {
      return entries[index]!.state
    },
    pushState(state: unknown, _unused: string, url?: string | URL | null) {
      entries.splice(index + 1)
      const hash = String(url ?? locationMock.hash)
      entries.push({ hash, state })
      index = entries.length - 1
      locationMock.hash = hash
    },
    replaceState(state: unknown, _unused: string, url?: string | URL | null) {
      const hash = String(url ?? locationMock.hash)
      entries[index] = { hash, state }
      locationMock.hash = hash
    },
    back() {
      backCalls += 1
      if (index === 0) return
      index -= 1
      locationMock.hash = entries[index]!.hash
      dispatch('popstate')
    },
  }
  const windowMock = {
    addEventListener(type: string, listener: Listener) {
      listeners.set(type, [...(listeners.get(type) ?? []), listener])
    },
  }

  vi.stubGlobal('location', locationMock)
  vi.stubGlobal('history', historyMock)
  vi.stubGlobal('window', windowMock)

  return {
    entries,
    history: historyMock,
    location: locationMock,
    get backCalls() {
      return backCalls
    },
  }
}

afterEach(() => {
  vi.resetModules()
  vi.unstubAllGlobals()
})

describe('hash router back targets', () => {
  it('uses the existing donation entry after internal navigation', async () => {
    const browser = installBrowser('#/')
    const { router } = await import('./router.svelte')

    router.go('/pay/invoice-1')
    expect(router.path).toBe('/pay/invoice-1')
    expect(browser.entries).toHaveLength(2)

    router.ensureBackTarget('/')
    expect(browser.entries).toHaveLength(2)

    router.backOrReplace('/')
    expect(browser.backCalls).toBe(1)
    expect(router.path).toBe('/')
    expect(browser.location.hash).toBe('#/')
  })

  it('inserts an in-app entry behind a directly opened payment link', async () => {
    const browser = installBrowser('#/pay/deep-link')
    const { router } = await import('./router.svelte')

    router.ensureBackTarget('/')
    expect(browser.entries.map((entry) => entry.hash)).toEqual(['#/', '#/pay/deep-link'])

    browser.history.back()
    expect(router.path).toBe('/')
    expect(browser.location.hash).toBe('#/')
  })

  it('replaces an unmarked direct route instead of leaving the app', async () => {
    const browser = installBrowser('#/pay/unmarked')
    const { router } = await import('./router.svelte')

    router.backOrReplace('/')
    expect(browser.backCalls).toBe(0)
    expect(browser.entries).toHaveLength(1)
    expect(browser.location.hash).toBe('#/')
    expect(router.path).toBe('/')
  })
})

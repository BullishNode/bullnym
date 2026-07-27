import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

let render: typeof import('svelte/server').render
let App: typeof import('./App.svelte').default

beforeAll(async () => {
  vi.useFakeTimers()
  vi.stubGlobal('location', { hash: '#/pay/invoice-1', host: 'example.test', search: '' })
  vi.stubGlobal('history', {
    state: null,
    pushState: vi.fn(),
    replaceState: vi.fn(),
    back: vi.fn(),
  })
  vi.stubGlobal('window', {
    addEventListener: vi.fn(),
    sessionStorage: undefined,
  })
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({ currencies: [] }),
  }))

  const [server, app] = await Promise.all([
    import('svelte/server'),
    import('./App.svelte'),
  ])
  render = server.render
  App = app.default
}, 60_000)

afterAll(() => {
  vi.useRealTimers()
  vi.resetModules()
  vi.unstubAllGlobals()
})

describe('donation payment navigation', () => {
  it('keeps the visible Back control enabled before status or cancellation authority is known', () => {
    const { body } = render(App)
    const backButton = body.match(/<button[^>]*aria-label="Back to donation form"[^>]*>/)?.[0]

    expect(backButton).toBeDefined()
    expect(backButton).not.toContain('disabled')
  })
})

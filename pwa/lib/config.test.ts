import { afterEach, describe, expect, it, vi } from 'vitest'
import { parseConfig } from './config'

describe('parseConfig', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.unstubAllEnvs()
  })

  it('parses the server-injected config block', () => {
    vi.stubGlobal('document', {
      getElementById: () => ({
        textContent: JSON.stringify({
          nym: 'alice',
          mode: 'pos',
          currency: 'CRC',
          header: 'Alice Coffee',
          description: 'Fresh coffee',
        }),
      }),
    })

    const config = parseConfig()

    expect(config.nym).toBe('alice')
    expect(config.mode).toBe('pos')
    expect(config.currency).toBe('CRC')
    expect(config.header).toBe('Alice Coffee')
    expect(config.description).toBe('Fresh coffee')
    // Back-compat: a payload without invoice_base/page_key derives them from
    // the nym + mode (stale cached shell served by an older backend).
    expect(config.invoice_base).toBe('/alice/pos')
    expect(config.page_key).toBe('alice')
  })

  it('honours an explicit alias config with no nym', () => {
    vi.stubGlobal('document', {
      getElementById: () => ({
        textContent: JSON.stringify({
          invoice_base: '/a/alices-shop',
          page_key: 'alices-shop',
          mode: 'donation',
          currency: 'USD',
          header: "Alice's Shop",
        }),
      }),
    })

    const config = parseConfig()

    // Alias pages carry no nym; routing/storage come from the explicit fields.
    expect(config.nym).toBe('')
    expect(config.invoice_base).toBe('/a/alices-shop')
    expect(config.page_key).toBe('alices-shop')
  })

  it('keeps an explicit alias POS base nym-free and surface-specific', () => {
    vi.stubGlobal('document', {
      getElementById: () => ({
        textContent: JSON.stringify({
          invoice_base: '/a/alices-shop/pos',
          page_key: 'alices-shop',
          mode: 'pos',
          currency: 'CRC',
          header: "Alice's Register",
        }),
      }),
    })

    const config = parseConfig()

    expect(config.nym).toBe('')
    expect(config.invoice_base).toBe('/a/alices-shop/pos')
    expect(config.page_key).toBe('alices-shop')
    expect(config.mode).toBe('pos')
  })

  it('prefers explicit invoice_base/page_key over the derived values', () => {
    vi.stubGlobal('document', {
      getElementById: () => ({
        textContent: JSON.stringify({
          nym: 'alice',
          mode: 'pos',
          invoice_base: '/a/override',
          page_key: 'override',
        }),
      }),
    })

    const config = parseConfig()

    expect(config.invoice_base).toBe('/a/override')
    expect(config.page_key).toBe('override')
  })

  it('ignores ?nym= outside dev builds', () => {
    vi.stubEnv('DEV', false)
    vi.stubGlobal('document', {
      getElementById: () => null,
    })
    vi.stubGlobal('location', {
      search: '?nym=alice',
      host: 'bullpay.ca',
    })

    const config = parseConfig()

    expect(config.nym).toBe('')
    expect(config.header).toBe('')
  })
})

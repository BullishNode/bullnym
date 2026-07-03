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

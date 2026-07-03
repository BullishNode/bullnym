import { describe, it, expect } from 'vitest'
import { decodeBech32ToString } from './bech32'

describe('decodeBech32ToString', () => {
  it('decodes the canonical LNURL example from the LUD-01 spec', () => {
    const encoded =
      'LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS'
    const decoded = decodeBech32ToString(encoded)
    expect(decoded).toBe('https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df')
  })

  it('rejects a bad checksum', () => {
    expect(() => decodeBech32ToString('lnurl1dp68gurn8ghj7um9wfmxjcm99e3k7mf0v9cxj0m385ekvcenxc6r2c35xvukxefcv5mkv0000000')).toThrow()
  })
})

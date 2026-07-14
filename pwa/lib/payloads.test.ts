// CONTRACT 2's builders. liquidUri's shape is pinned against the server's
// own test fixture (src/invoice/tests.rs:~311-318): the assetid query param
// must be the raw hex asset id with no additional encoding, and the amount
// must be the fixed 8-decimal BTC string (not sats).
import { describe, expect, it } from 'vitest'
import { btcAmount, btcUri, bitcoinPayload, liquidUri } from './payloads'

const LIQUID_BTC_ASSET_ID = '6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d'

describe('btcAmount', () => {
  it('formats sats as a fixed 8-decimal-place BTC string', () => {
    expect(btcAmount(10_800)).toBe('0.00010800')
    expect(btcAmount(100_000_000)).toBe('1.00000000')
    expect(btcAmount(1)).toBe('0.00000001')
    expect(btcAmount(0)).toBe('0.00000000')
  })
})

describe('btcUri', () => {
  it('builds a bare bitcoin: URI with the 8dp amount', () => {
    expect(btcUri('bc1qxyz', 10_800)).toBe('bitcoin:bc1qxyz?amount=0.00010800')
  })
})

describe('bitcoinPayload', () => {
  it('prefers the server-issued bip21 URI when present', () => {
    const bip21 = 'bitcoin:bc1qxyz?amount=0.00010800&label=Sale'
    expect(bitcoinPayload('bc1qxyz', bip21, 10_800)).toBe(bip21)
  })

  it('falls back to a bare btcUri when bip21 is null', () => {
    expect(bitcoinPayload('bc1qxyz', null, 10_800)).toBe('bitcoin:bc1qxyz?amount=0.00010800')
  })

  it('falls back to btcUri when bip21 is an empty string', () => {
    expect(bitcoinPayload('bc1qxyz', '', 10_800)).toBe('bitcoin:bc1qxyz?amount=0.00010800')
  })

  it('uses the typed grossed-up payer amount instead of the lower invoice amount', () => {
    const merchantInvoiceSat = 10_000
    const bitcoinChainAmountSat = 10_431
    expect(bitcoinChainAmountSat).toBeGreaterThan(merchantInvoiceSat)
    expect(bitcoinPayload('bc1qgrossup', null, bitcoinChainAmountSat)).toBe(
      'bitcoin:bc1qgrossup?amount=0.00010431',
    )
  })
})

describe('liquidUri', () => {
  it('matches the server-issued canonical shape (src/invoice/tests.rs)', () => {
    expect(liquidUri('lq1qxyz', 10_800, LIQUID_BTC_ASSET_ID)).toBe(
      `liquidnetwork:lq1qxyz?amount=0.00010800&assetid=${LIQUID_BTC_ASSET_ID}`,
    )
  })

  it('uses the remaining amount, not any other amount, in 8dp form', () => {
    // A partial payment leaves e.g. 543 sat remaining out of an original
    // 10,800 sat invoice — the URI must reflect the remaining amount.
    expect(liquidUri('lq1qxyz', 543, LIQUID_BTC_ASSET_ID)).toBe(`liquidnetwork:lq1qxyz?amount=0.00000543&assetid=${LIQUID_BTC_ASSET_ID}`)
  })
})

// Rail-tab gating (review item 1: "never show a selectable tab with a
// blank QR" — the pre-rewrite bug derived tabs from the frozen create
// response only, so a rail that got disabled or lost its payload mid-poll
// stayed selectable with an empty QR).
import { describe, expect, it } from 'vitest'
import { availableRails } from './rails'

describe('availableRails', () => {
  it('all three available when accepted and payloads present', () => {
    expect(
      availableRails({
        acceptLn: true,
        lightningPr: 'lnbc1...',
        acceptLiquid: true,
        liquidAddress: 'lq1...',
        acceptBtc: true,
        bitcoinAddress: 'bc1...',
        bitcoinChainAddress: null,
      }),
    ).toEqual({ lightning: true, liquid: true, bitcoin: true })
  })

  it('accept_liquid=false hides the liquid tab even with an address present', () => {
    const result = availableRails({
      acceptLn: true,
      lightningPr: 'lnbc1...',
      acceptLiquid: false,
      liquidAddress: 'lq1...',
      acceptBtc: true,
      bitcoinAddress: 'bc1...',
      bitcoinChainAddress: null,
    })
    expect(result.liquid).toBe(false)
  })

  it('a missing liquid_address hides the liquid tab even when accepted', () => {
    const result = availableRails({
      acceptLn: true,
      lightningPr: 'lnbc1...',
      acceptLiquid: true,
      liquidAddress: null,
      acceptBtc: true,
      bitcoinAddress: 'bc1...',
      bitcoinChainAddress: null,
    })
    expect(result.liquid).toBe(false)
  })

  it('no bitcoin offer (null address) hides the bitcoin tab', () => {
    const result = availableRails({
      acceptLn: true,
      lightningPr: 'lnbc1...',
      acceptLiquid: true,
      liquidAddress: 'lq1...',
      acceptBtc: true,
      bitcoinAddress: null,
      bitcoinChainAddress: null,
    })
    expect(result.bitcoin).toBe(false)
  })

  it('an empty-string payload counts as absent (falsy), same as null', () => {
    const result = availableRails({
      acceptLn: true,
      lightningPr: '',
      acceptLiquid: true,
      liquidAddress: 'lq1...',
      acceptBtc: true,
      bitcoinAddress: 'bc1...',
      bitcoinChainAddress: null,
    })
    expect(result.lightning).toBe(false)
  })

  it('undefined accept flags (pre-first-poll) default to accepted', () => {
    const result = availableRails({
      acceptLn: undefined,
      lightningPr: 'lnbc1...',
      acceptLiquid: undefined,
      liquidAddress: 'lq1...',
      acceptBtc: undefined,
      bitcoinAddress: null,
      bitcoinChainAddress: null,
    })
    // lightning/liquid have both "accepted" (defaulted) and a payload ->
    // available; bitcoin has no payload -> not available even though its
    // accept flag also defaults to true.
    expect(result).toEqual({ lightning: true, liquid: true, bitcoin: false })
  })

  it('chain-swap address keeps the bitcoin tab even when accept_btc=false', () => {
    // The regression: a checkout invoice with direct BTC disabled
    // (accept_btc=false) but a Liquid address gets a BTC->L-BTC chain-swap
    // offer. The chain lockup address is payable and must not be gated on
    // accept_btc, or the tab vanishes on the first poll.
    const result = availableRails({
      acceptLn: true,
      lightningPr: 'lnbc1...',
      acceptLiquid: true,
      liquidAddress: 'lq1...',
      acceptBtc: false,
      bitcoinAddress: 'bc1qlockup...', // merged current address == chain address
      bitcoinChainAddress: 'bc1qlockup...',
    })
    expect(result.bitcoin).toBe(true)
  })

  it('accept_btc=false with only a direct address (no chain swap) hides bitcoin', () => {
    const result = availableRails({
      acceptLn: true,
      lightningPr: 'lnbc1...',
      acceptLiquid: true,
      liquidAddress: 'lq1...',
      acceptBtc: false,
      bitcoinAddress: 'bc1direct...',
      bitcoinChainAddress: null,
    })
    expect(result.bitcoin).toBe(false)
  })
})

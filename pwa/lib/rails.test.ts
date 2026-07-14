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
        lightningAmountSat: 1_050,
        acceptLiquid: true,
        liquidAddress: 'lq1...',
        liquidAmountSat: 1_000,
        acceptBtc: true,
        bitcoinAddress: 'bc1...',
        bitcoinChainAddress: null,
        bitcoinChainAmountSat: null,
      }),
    ).toEqual({ lightning: true, liquid: true, bitcoin: true })
  })

  it('accept_liquid=false hides the liquid tab even with an address present', () => {
    const result = availableRails({
      acceptLn: true,
      lightningPr: 'lnbc1...',
      lightningAmountSat: 1_050,
      acceptLiquid: false,
      liquidAddress: 'lq1...',
      liquidAmountSat: 1_000,
      acceptBtc: true,
      bitcoinAddress: 'bc1...',
      bitcoinChainAddress: null,
      bitcoinChainAmountSat: null,
    })
    expect(result.liquid).toBe(false)
  })

  it('a missing liquid_address hides the liquid tab even when accepted', () => {
    const result = availableRails({
      acceptLn: true,
      lightningPr: 'lnbc1...',
      lightningAmountSat: 1_050,
      acceptLiquid: true,
      liquidAddress: null,
      liquidAmountSat: 1_000,
      acceptBtc: true,
      bitcoinAddress: 'bc1...',
      bitcoinChainAddress: null,
      bitcoinChainAmountSat: null,
    })
    expect(result.liquid).toBe(false)
  })

  it('no bitcoin offer (null address) hides the bitcoin tab', () => {
    const result = availableRails({
      acceptLn: true,
      lightningPr: 'lnbc1...',
      lightningAmountSat: 1_050,
      acceptLiquid: true,
      liquidAddress: 'lq1...',
      liquidAmountSat: 1_000,
      acceptBtc: true,
      bitcoinAddress: null,
      bitcoinChainAddress: null,
      bitcoinChainAmountSat: null,
    })
    expect(result.bitcoin).toBe(false)
  })

  it('an empty-string payload counts as absent (falsy), same as null', () => {
    const result = availableRails({
      acceptLn: true,
      lightningPr: '',
      lightningAmountSat: 1_050,
      acceptLiquid: true,
      liquidAddress: 'lq1...',
      liquidAmountSat: 1_000,
      acceptBtc: true,
      bitcoinAddress: 'bc1...',
      bitcoinChainAddress: null,
      bitcoinChainAmountSat: null,
    })
    expect(result.lightning).toBe(false)
  })

  it('undefined accept flags (pre-first-poll) default to accepted', () => {
    const result = availableRails({
      acceptLn: undefined,
      lightningPr: 'lnbc1...',
      lightningAmountSat: 1_050,
      acceptLiquid: undefined,
      liquidAddress: 'lq1...',
      liquidAmountSat: 1_000,
      acceptBtc: undefined,
      bitcoinAddress: null,
      bitcoinChainAddress: null,
      bitcoinChainAmountSat: null,
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
      lightningAmountSat: 10_850,
      acceptLiquid: true,
      liquidAddress: 'lq1...',
      liquidAmountSat: 10_800,
      acceptBtc: false,
      bitcoinAddress: 'bc1qlockup...', // merged current address == chain address
      bitcoinChainAddress: 'bc1qlockup...',
      bitcoinChainAmountSat: 10_800,
    })
    expect(result.bitcoin).toBe(true)
  })

  it('accept_btc=false with only a direct address (no chain swap) hides bitcoin', () => {
    const result = availableRails({
      acceptLn: true,
      lightningPr: 'lnbc1...',
      lightningAmountSat: 1_050,
      acceptLiquid: true,
      liquidAddress: 'lq1...',
      liquidAmountSat: 1_000,
      acceptBtc: false,
      bitcoinAddress: 'bc1direct...',
      bitcoinChainAddress: null,
      bitcoinChainAmountSat: null,
    })
    expect(result.bitcoin).toBe(false)
  })

  it('fails closed on a chain address without an exact safe positive amount', () => {
    for (const bitcoinChainAmountSat of [null, 0, -1, Number.MAX_SAFE_INTEGER + 1]) {
      const result = availableRails({
        acceptLn: false,
        lightningPr: null,
        lightningAmountSat: null,
        acceptLiquid: false,
        liquidAddress: null,
        liquidAmountSat: null,
        acceptBtc: false,
        bitcoinAddress: null,
        bitcoinChainAddress: 'bc1qamountlesschain',
        bitcoinChainAmountSat,
      })
      expect(result.bitcoin).toBe(false)
    }
  })

  it('fails closed when Lightning or Liquid payload lacks its exact amount', () => {
    for (const amount of [null, 0, -1, Number.MAX_SAFE_INTEGER + 1]) {
      const lightning = availableRails({
        acceptLn: true,
        lightningPr: 'lnbc1...',
        lightningAmountSat: amount,
        acceptLiquid: false,
        liquidAddress: null,
        liquidAmountSat: null,
        acceptBtc: false,
        bitcoinAddress: null,
        bitcoinChainAddress: null,
        bitcoinChainAmountSat: null,
      })
      expect(lightning.lightning).toBe(false)

      const liquid = availableRails({
        acceptLn: false,
        lightningPr: null,
        lightningAmountSat: null,
        acceptLiquid: true,
        liquidAddress: 'lq1...',
        liquidAmountSat: amount,
        acceptBtc: false,
        bitcoinAddress: null,
        bitcoinChainAddress: null,
        bitcoinChainAmountSat: null,
      })
      expect(liquid.liquid).toBe(false)
    }
  })
})

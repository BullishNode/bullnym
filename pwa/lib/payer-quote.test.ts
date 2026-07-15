import { describe, expect, it, vi } from 'vitest'
import type {
  PayerDemandQuoteResponse,
  PayerQuoteRail,
  VersionedPayerInstruction,
} from './api/client'
import {
  PayerQuoteCoordinator,
  activeQuoteSnapshot,
  assertLightningQuoteAuthorityCurrent,
  captureLightningQuoteAuthority,
  formatQuoteCountdown,
  quoteAccessibilityState,
  quoteRailPresentation,
} from './payer-quote'

const INVOICE_ID = '11111111-1111-4111-8111-111111111111'
const ASSET_ID = '6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d'
const CREATED_AT = 1_700_000_000

function instructionFor(
  rail: PayerQuoteRail,
  suffix: string,
  payerAmountSat: number,
): VersionedPayerInstruction {
  if (rail === 'lightning') {
    return {
      kind: 'lightning_boltz_reverse',
      quote_offer_id: `offer-ln-${suffix}`,
      pr: `lnbc-${suffix}`,
      payer_amount_sat: payerAmountSat,
    }
  }
  if (rail === 'liquid') {
    return {
      kind: 'liquid_direct',
      address: `lq1-${suffix}`,
      payer_amount_sat: payerAmountSat,
    }
  }
  return {
    kind: 'bitcoin_boltz_chain',
    quote_offer_id: `offer-btc-${suffix}`,
    address: `bc1-${suffix}`,
    bip21: `bitcoin:bc1-${suffix}?amount=0.00010100&label=exact-${suffix}`,
    payer_amount_sat: payerAmountSat,
  }
}

function responseFor(
  rail: PayerQuoteRail,
  version = 1,
  suffix = `v${version}`,
  createdAt = CREATED_AT,
  merchantAmountSat = 10_000,
  payerAmountSat = rail === 'liquid' ? merchantAmountSat : merchantAmountSat + 100,
): PayerDemandQuoteResponse {
  return {
    pricing_mode: 'fiat_fixed',
    invoice_id: INVOICE_ID,
    selected_rail: rail,
    quote: {
      quote_version_id: `quote-${version}`,
      version_number: version,
      fiat_face_amount_minor: 1_000,
      fiat_target_amount_minor: version === 1 ? 1_000 : 600,
      fiat_currency: 'USD',
      rate_minor_per_btc: 10_000_000,
      rate_source: 'test-rate',
      rate_observed_at_unix: createdAt - 1,
      rate_fetched_at_unix: createdAt - 1,
      rate_fresh_until_unix: createdAt + 90,
      merchant_amount_sat: merchantAmountSat,
      created_at_unix: createdAt,
      expires_at_unix: createdAt + 300,
    },
    instruction: instructionFor(rail, suffix, payerAmountSat),
  }
}

function directBitcoinResponseFor(
  version: number,
  merchantAmountSat: number,
  createdAt = CREATED_AT,
): PayerDemandQuoteResponse {
  const response = responseFor(
    'bitcoin',
    version,
    `direct-v${version}`,
    createdAt,
    merchantAmountSat,
    merchantAmountSat,
  )
  return {
    ...response,
    instruction: {
      kind: 'bitcoin_direct',
      address: 'bc1-stable-wallet-destination',
      bip21: `bitcoin:bc1-stable-wallet-destination?amount=${
        merchantAmountSat === 10_000 ? '0.00010000' : '0.00005000'
      }`,
      payer_amount_sat: merchantAmountSat,
    },
  }
}

function deferred<T>(): {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason?: unknown) => void
} {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

describe('PayerQuoteCoordinator', () => {
  it('enforces the exact expiry boundary and locks stale QR/copy while refresh is pending', async () => {
    let now = CREATED_AT * 1_000
    const pendingRefresh = deferred<PayerDemandQuoteResponse>()
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(responseFor('liquid'))
      .mockReturnValueOnce(pendingRefresh.promise)
    const coordinator = new PayerQuoteCoordinator(INVOICE_ID, fetcher, () => now)

    await coordinator.refresh('liquid', 'initial')
    expect(formatQuoteCountdown(coordinator.state, now)).toBe('5:00')

    now = (CREATED_AT + 300) * 1_000 - 1
    expect(formatQuoteCountdown(coordinator.state, now)).toBe('0:01')
    expect(quoteRailPresentation(coordinator.state, 'liquid', now, ASSET_ID)?.copyDisabled).toBe(false)

    now += 1
    expect(coordinator.expire(now)).toBe(true)
    expect(quoteRailPresentation(coordinator.state, 'liquid', now, ASSET_ID)).toBeNull()
    expect(formatQuoteCountdown(coordinator.state, now)).toBe('0:00')

    const refresh = coordinator.refresh('liquid', 'timer')
    expect(quoteAccessibilityState(coordinator.state, 'liquid', now)).toEqual({
      busy: true,
      copyDisabled: true,
      message: 'Refreshing liquid quote',
    })
    expect(activeQuoteSnapshot(coordinator.state, 'liquid', now)).toBeNull()

    pendingRefresh.resolve(responseFor('liquid', 2, 'fresh', CREATED_AT + 300))
    await refresh
    expect(quoteRailPresentation(coordinator.state, 'liquid', now, ASSET_ID)?.qrValue).toContain(
      'lq1-fresh',
    )
  })

  it('coalesces concurrent timer, reload, tab, and manual triggers for one rail', async () => {
    const pending = deferred<PayerDemandQuoteResponse>()
    const fetcher = vi.fn().mockReturnValue(pending.promise)
    const coordinator = new PayerQuoteCoordinator(INVOICE_ID, fetcher, () => CREATED_AT * 1_000)

    const timer = coordinator.refresh('lightning', 'timer')
    const reload = coordinator.refresh('lightning', 'reload')
    const tab = coordinator.refresh('lightning', 'tab')
    const manual = coordinator.refresh('lightning', 'manual')
    expect(reload).toBe(timer)
    expect(tab).toBe(timer)
    expect(manual).toBe(timer)
    expect(fetcher).toHaveBeenCalledTimes(1)

    pending.resolve(responseFor('lightning'))
    await timer
    expect(coordinator.state.pending.lightning).toBe(false)
    expect(coordinator.state.rails.lightning?.instruction.kind).toBe('lightning_boltz_reverse')
  })

  it('lazily reuses a selected rail already bound to the active version', async () => {
    const fetcher = vi.fn().mockResolvedValue(responseFor('liquid'))
    const coordinator = new PayerQuoteCoordinator(INVOICE_ID, fetcher, () => CREATED_AT * 1_000)

    await coordinator.ensure('liquid', 'tab')
    const reused = await coordinator.ensure('liquid', 'tab')
    expect(reused.ok).toBe(true)
    expect(reused.snapshot).toBe(coordinator.state.rails.liquid)
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('reload adopts one complete immutable snapshot without mixing old and new fields', async () => {
    const fetcher = vi.fn().mockResolvedValue(responseFor('bitcoin', 3, 'reload', CREATED_AT, 6_000, 6_250))
    const coordinator = new PayerQuoteCoordinator(INVOICE_ID, fetcher, () => CREATED_AT * 1_000)

    const result = await coordinator.refresh('bitcoin', 'reload')
    const presentation = quoteRailPresentation(coordinator.state, 'bitcoin', CREATED_AT * 1_000, ASSET_ID)
    expect(result.ok).toBe(true)
    expect(fetcher).toHaveBeenCalledWith('bitcoin', 'reload')
    expect(Object.isFrozen(coordinator.state)).toBe(true)
    expect(Object.isFrozen(coordinator.state.rails.bitcoin)).toBe(true)
    expect(presentation).toMatchObject({
      quoteVersionId: 'quote-3',
      versionNumber: 3,
      merchantAmountSat: 6_000,
      payerAmountSat: 6_250,
      swapCostSat: 250,
      qrValue: 'bitcoin:bc1-reload?amount=0.00010100&label=exact-reload',
      copyValue: 'bitcoin:bc1-reload?amount=0.00010100&label=exact-reload',
    })
  })

  it('refreshes direct Bitcoin amount and BIP21 atomically over one stable address', async () => {
    let now = CREATED_AT * 1_000
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(directBitcoinResponseFor(1, 10_000))
      .mockResolvedValueOnce(directBitcoinResponseFor(2, 5_000, CREATED_AT + 300))
    const coordinator = new PayerQuoteCoordinator(INVOICE_ID, fetcher, () => now)

    await coordinator.refresh('bitcoin', 'initial')
    expect(quoteRailPresentation(coordinator.state, 'bitcoin', now, ASSET_ID)).toMatchObject({
      quoteVersionId: 'quote-1',
      merchantAmountSat: 10_000,
      payerAmountSat: 10_000,
      swapCostSat: 0,
      qrValue: 'bitcoin:bc1-stable-wallet-destination?amount=0.00010000',
    })

    now = (CREATED_AT + 300) * 1_000
    coordinator.expire(now)
    expect(quoteRailPresentation(coordinator.state, 'bitcoin', now, ASSET_ID)).toBeNull()
    await coordinator.refresh('bitcoin', 'timer')
    const refreshed = quoteRailPresentation(coordinator.state, 'bitcoin', now, ASSET_ID)
    expect(refreshed).toMatchObject({
      quoteVersionId: 'quote-2',
      merchantAmountSat: 5_000,
      payerAmountSat: 5_000,
      swapCostSat: 0,
      qrValue: 'bitcoin:bc1-stable-wallet-destination?amount=0.00005000',
      copyValue: 'bitcoin:bc1-stable-wallet-destination?amount=0.00005000',
    })
    expect(coordinator.state.rails.bitcoin?.instruction).toMatchObject({
      kind: 'bitcoin_direct',
      address: 'bc1-stable-wallet-destination',
    })
  })

  it('keeps Liquid usable when Lightning provider creation fails', async () => {
    const fetcher = vi.fn((rail: PayerQuoteRail) => {
      if (rail === 'lightning') return Promise.reject(new Error('provider down'))
      return Promise.resolve(responseFor(rail))
    })
    const coordinator = new PayerQuoteCoordinator(INVOICE_ID, fetcher, () => CREATED_AT * 1_000)

    const [lightning, liquid] = await Promise.all([
      coordinator.refresh('lightning', 'initial'),
      coordinator.refresh('liquid', 'tab'),
    ])
    expect(lightning.ok).toBe(false)
    expect(liquid.ok).toBe(true)
    expect(coordinator.state.errors.lightning).toContain('Lightning'.toLowerCase())
    expect(quoteRailPresentation(coordinator.state, 'lightning', CREATED_AT * 1_000, ASSET_ID)).toBeNull()
    expect(quoteRailPresentation(coordinator.state, 'liquid', CREATED_AT * 1_000, ASSET_ID)).toMatchObject({
      payerAmountSat: 10_000,
      swapCostSat: 0,
      copyDisabled: false,
    })
  })

  it('does not resurrect an expired offer after refresh failure', async () => {
    let now = CREATED_AT * 1_000
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(responseFor('lightning', 1, 'old'))
      .mockRejectedValueOnce(new Error('unavailable'))
    const coordinator = new PayerQuoteCoordinator(INVOICE_ID, fetcher, () => now)

    await coordinator.refresh('lightning', 'initial')
    expect(quoteRailPresentation(coordinator.state, 'lightning', now, ASSET_ID)?.qrValue).toBe('lnbc-old')

    now = (CREATED_AT + 300) * 1_000
    const result = await coordinator.refresh('lightning', 'timer')
    expect(result.ok).toBe(false)
    expect(coordinator.state.quote).toBeNull()
    expect(quoteRailPresentation(coordinator.state, 'lightning', now, ASSET_ID)).toBeNull()
    expect(quoteAccessibilityState(coordinator.state, 'lightning', now)).toEqual({
      busy: false,
      copyDisabled: true,
      message: 'lightning quote unavailable',
    })
  })

  it('retires every old-quote rail atomically before adopting a new version', async () => {
    let now = CREATED_AT * 1_000
    const responses = [
      responseFor('lightning', 1, 'old-ln'),
      responseFor('liquid', 1, 'old-liquid'),
      responseFor('liquid', 2, 'new-liquid', CREATED_AT + 300, 6_000, 6_000),
    ]
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(responses.shift()!))
    const coordinator = new PayerQuoteCoordinator(INVOICE_ID, fetcher, () => now)

    await coordinator.refresh('lightning', 'initial')
    await coordinator.refresh('liquid', 'tab')
    expect(coordinator.state.rails.lightning).not.toBeNull()
    expect(coordinator.state.rails.liquid).not.toBeNull()

    now = (CREATED_AT + 300) * 1_000
    coordinator.expire(now)
    expect(coordinator.state.rails.lightning).toBeNull()
    expect(coordinator.state.rails.liquid).toBeNull()

    await coordinator.refresh('liquid', 'timer')
    expect(coordinator.state.quote?.quote_version_id).toBe('quote-2')
    expect(coordinator.state.rails.lightning).toBeNull()
    expect(quoteRailPresentation(coordinator.state, 'liquid', now, ASSET_ID)).toMatchObject({
      quoteVersionId: 'quote-2',
      qrValue: expect.stringContaining('lq1-new-liquid'),
      payerAmountSat: 6_000,
    })
  })

  it('rejects a mismatched selected rail without partially adopting it', async () => {
    const mismatched = responseFor('liquid')
    const coordinator = new PayerQuoteCoordinator(
      INVOICE_ID,
      () => Promise.resolve(mismatched),
      () => CREATED_AT * 1_000,
    )
    const result = await coordinator.refresh('lightning', 'tab')
    expect(result.ok).toBe(false)
    expect(coordinator.state.quote).toBeNull()
    expect(coordinator.state.rails.lightning).toBeNull()
  })

  it('invalidates Bolt Card authority on pending, expiry, unavailability, and version replacement', async () => {
    let now = CREATED_AT * 1_000
    const replacement = deferred<PayerDemandQuoteResponse>()
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(responseFor('lightning', 1, 'card-v1'))
      .mockReturnValueOnce(replacement.promise)
    const coordinator = new PayerQuoteCoordinator(INVOICE_ID, fetcher, () => now)
    await coordinator.refresh('lightning', 'initial')
    const authority = captureLightningQuoteAuthority(coordinator.state, now)
    expect(authority).not.toBeNull()
    if (!authority) return
    expect(() => assertLightningQuoteAuthorityCurrent(coordinator.state, authority, now)).not.toThrow()

    const refreshing = coordinator.refresh('lightning', 'manual')
    expect(captureLightningQuoteAuthority(coordinator.state, now)).toBeNull()
    expect(() => assertLightningQuoteAuthorityCurrent(coordinator.state, authority, now)).toThrow(
      /expired or changed/,
    )

    replacement.resolve(responseFor('lightning', 2, 'card-v2', CREATED_AT, 6_000, 6_100))
    await refreshing
    expect(() => assertLightningQuoteAuthorityCurrent(coordinator.state, authority, now)).toThrow(
      /expired or changed/,
    )

    const replacementAuthority = captureLightningQuoteAuthority(coordinator.state, now)
    expect(replacementAuthority?.quoteVersionId).toBe('quote-2')
    now = (CREATED_AT + 300) * 1_000
    expect(captureLightningQuoteAuthority(coordinator.state, now)).toBeNull()
    if (replacementAuthority) {
      expect(() =>
        assertLightningQuoteAuthorityCurrent(coordinator.state, replacementAuthority, now),
      ).toThrow(/expired or changed/)
    }

    coordinator.expire(now)
    expect(captureLightningQuoteAuthority(coordinator.state, now)).toBeNull()
  })
})

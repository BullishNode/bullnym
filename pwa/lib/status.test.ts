import { describe, expect, it } from 'vitest'
import type { InvoiceStatus } from './api/client'
import {
  bitcoinPaymentPayloadFromStatus,
  derivePayView,
  isCancelableStatus,
  isTerminalView,
  LN_REFRESH_COOLDOWN_MS,
  nextLightningPr,
  payViewBeforeFirstStatus,
  payViewLabel,
  payViewSupport,
  shouldPollDetail,
  shouldRefreshLightning,
  showsRails,
} from './status'

function makeStatus(overrides: Partial<InvoiceStatus> = {}): InvoiceStatus {
  return {
    status: 'unpaid',
    presentation_status: 'unpaid',
    pricing_mode: 'fiat_fixed',
    settlement_status: 'none',
    amount_sat: 10_800,
    fiat_amount_minor: 500,
    fiat_currency: 'USD',
    remaining_amount_sat: 10_800,
    payment_tolerance_sat: 0,
    rate_minor_per_btc: null,
    rate_locks_until_unix: 0,
    expires_at_unix: 0,
    paid_via: null,
    paid_at_unix: null,
    paid_amount_sat: null,
    lightning_pr: null,
    lightning_amount_sat: null,
    liquid_address: null,
    liquid_amount_sat: null,
    bitcoin_address: null,
    bitcoin_chain_address: null,
    bitcoin_chain_bip21: null,
    bitcoin_chain_amount_sat: null,
    accept_btc: true,
    accept_ln: true,
    accept_liquid: true,
    quote_rail_availability: { lightning: true, liquid: true, bitcoin: true },
    ...overrides,
  }
}

describe('derivePayView combined server projection', () => {
  it('hides every rail before the first trustworthy status response', () => {
    const view = payViewBeforeFirstStatus()
    expect(view).toEqual({ kind: 'unknown' })
    expect(showsRails(view)).toBe(false)
    expect(
      shouldRefreshLightning({
        accept: true,
        pr: null,
        view,
        refreshing: false,
        lastFailedAt: null,
        now: 1_000_000,
      }),
    ).toBe(false)
  })

  it('uses presentation+settlement ahead of accounting terminality', () => {
    expect(
      derivePayView(
        makeStatus({ status: 'paid', presentation_status: 'payment_received', settlement_status: 'pending' }),
      ),
    ).toEqual({ kind: 'settling' })
  })

  it('keeps partial payment instructions visible while settlement is pending', () => {
    const view = derivePayView(
      makeStatus({ status: 'partially_paid', presentation_status: 'partial', settlement_status: 'pending' }),
    )
    expect(view).toEqual({ kind: 'partially_paid_pending' })
    expect(showsRails(view)).toBe(true)
    expect(payViewLabel(view, 1234)).toBe('Partially paid — 1,234 sat due')
    expect(payViewSupport(view)).toBe('Settlement pending')
  })

  it('preserves overpaid copy while provisional and finalizes only when accounting agrees', () => {
    const pending = derivePayView(
      makeStatus({ status: 'paid', presentation_status: 'overpaid', settlement_status: 'pending' }),
    )
    expect(pending).toEqual({ kind: 'overpaid_pending' })
    expect(payViewLabel(pending, 0)).toBe('Overpaid')
    expect(showsRails(pending)).toBe(false)
    expect(isTerminalView(pending)).toBe(false)

    expect(
      derivePayView(makeStatus({ status: 'overpaid', presentation_status: 'overpaid', settlement_status: 'settled' })),
    ).toEqual({ kind: 'overpaid' })
  })

  it('finalizes sufficient payment only with a compatible aggregate lifecycle', () => {
    expect(
      derivePayView(makeStatus({ status: 'paid', presentation_status: 'payment_received', settlement_status: 'settled' })),
    ).toEqual({ kind: 'paid' })
    expect(
      derivePayView(makeStatus({ status: 'paid', presentation_status: 'payment_received', settlement_status: 'none' })),
    ).toEqual({ kind: 'paid' })
  })

  it('surfaces money after cancellation without reopening payment instructions', () => {
    const settling = derivePayView(
      makeStatus({ status: 'cancelled', presentation_status: 'partial', settlement_status: 'pending' }),
    )
    expect(settling).toEqual({ kind: 'settling' })
    expect(showsRails(settling)).toBe(false)

    const partial = derivePayView(
      makeStatus({ status: 'cancelled', presentation_status: 'partial', settlement_status: 'settled' }),
    )
    expect(partial).toEqual({ kind: 'underpaid' })
    expect(isTerminalView(partial)).toBe(true)

    const paid = derivePayView(
      makeStatus({ status: 'cancelled', presentation_status: 'payment_received', settlement_status: 'settled' }),
    )
    expect(paid).toEqual({ kind: 'paid' })
    expect(isTerminalView(paid)).toBe(true)

    const overpaid = derivePayView(
      makeStatus({ status: 'cancelled', presentation_status: 'overpaid', settlement_status: 'settled' }),
    )
    expect(overpaid).toEqual({ kind: 'overpaid' })
    expect(isTerminalView(overpaid)).toBe(true)
  })

  it('shows resolution pending as a visible, nonterminal payment issue', () => {
    const view = derivePayView(
      makeStatus({ status: 'in_progress', presentation_status: 'partial', settlement_status: 'resolution_pending' }),
    )
    expect(view).toEqual({ kind: 'resolution_pending' })
    expect(payViewLabel(view, null)).toBe('Payment issue')
    expect(payViewSupport(view)).toBe('Settlement problem — being checked')
    expect(isTerminalView(view)).toBe(false)
    expect(showsRails(view)).toBe(false)
  })

  it('preserves all existing swap incident tokens', () => {
    const stuck = derivePayView(
      makeStatus({ status: 'paid', presentation_status: 'payment_received', settlement_status: 'claim_stuck' }),
    )
    expect(stuck).toEqual({ kind: 'needs_review' })
    expect(isTerminalView(stuck)).toBe(false)

    const refunded = derivePayView(
      makeStatus({ status: 'paid', presentation_status: 'payment_received', settlement_status: 'refunded' }),
    )
    expect(refunded).toEqual({ kind: 'refunded' })
    expect(isTerminalView(refunded)).toBe(true)

    const failed = derivePayView(
      makeStatus({ status: 'paid', presentation_status: 'payment_received', settlement_status: 'failed' }),
    )
    expect(failed).toEqual({ kind: 'failed' })
    expect(isTerminalView(failed)).toBe(true)

    expect(derivePayView(makeStatus({ presentation_status: null, settlement_status: 'refunded' }))).toEqual({
      kind: 'refunded',
    })
  })

  it('treats null/future presentation, settlement, and accounting values conservatively', () => {
    for (const status of [
      makeStatus({ presentation_status: null }),
      makeStatus({ presentation_status: 'future_presentation' }),
      makeStatus({ settlement_status: 'future_settlement' }),
      makeStatus({ status: 'future_accounting' }),
    ]) {
      const view = derivePayView(status)
      expect(view).toEqual({ kind: 'unknown' })
      expect(isTerminalView(view)).toBe(false)
      expect(showsRails(view)).toBe(false)
      expect(payViewLabel(view, null)).not.toBe('Waiting for payment')
    }
  })

  it('keeps finalized partial payable without reporting a terminal sale', () => {
    const view = derivePayView(
      makeStatus({ status: 'partially_paid', presentation_status: 'partial', settlement_status: 'settled' }),
    )
    expect(view).toEqual({ kind: 'partially_paid' })
    expect(showsRails(view)).toBe(true)
    expect(isTerminalView(view)).toBe(false)
  })
})

describe('polling and cancellation', () => {
  it('polls pending, resolution, waiting, and unknown states', () => {
    for (const status of [
      makeStatus(),
      makeStatus({ presentation_status: 'payment_received', settlement_status: 'pending' }),
      makeStatus({ presentation_status: 'partial', settlement_status: 'resolution_pending' }),
      makeStatus({ presentation_status: null }),
    ]) {
      expect(shouldPollDetail(status)).toBe(true)
    }
  })

  it('keeps polling a settled partial so a later top-up is observed', () => {
    expect(
      shouldPollDetail(
        makeStatus({ status: 'partially_paid', presentation_status: 'partial', settlement_status: 'settled' }),
      ),
    ).toBe(true)
    expect(
      shouldPollDetail(
        makeStatus({ status: 'underpaid', presentation_status: 'partial', settlement_status: 'settled' }),
      ),
    ).toBe(false)
  })

  it('stops automatic polling on settled sufficient states and existing stop-polling incidents', () => {
    expect(
      shouldPollDetail(
        makeStatus({ status: 'paid', presentation_status: 'payment_received', settlement_status: 'settled' }),
      ),
    ).toBe(false)
    expect(
      shouldPollDetail(makeStatus({ presentation_status: 'payment_received', settlement_status: 'refunded' })),
    ).toBe(false)
    expect(shouldPollDetail(makeStatus({ presentation_status: 'payment_received', settlement_status: 'failed' }))).toBe(
      false,
    )
    expect(
      shouldPollDetail(makeStatus({ presentation_status: 'payment_received', settlement_status: 'claim_stuck' })),
    ).toBe(false)
  })

  it('allows cancel only for the exact known no-evidence state', () => {
    expect(isCancelableStatus(makeStatus())).toBe(true)
    expect(isCancelableStatus(makeStatus({ status: 'in_progress', presentation_status: 'unpaid' }))).toBe(false)
    expect(isCancelableStatus(makeStatus({ presentation_status: 'partial' }))).toBe(false)
    expect(isCancelableStatus(makeStatus({ settlement_status: 'pending' }))).toBe(false)
    expect(isCancelableStatus(makeStatus({ presentation_status: null }))).toBe(false)
    expect(isCancelableStatus(makeStatus({ settlement_status: 'future' }))).toBe(false)
  })
})

describe('Lightning offer decisions', () => {
  const base = {
    accept: true,
    pr: null,
    view: { kind: 'waiting' } as const,
    refreshing: false,
    lastFailedAt: null,
    now: 1_000_000,
  }

  it('refreshes waiting and partial states, including partial+pending', () => {
    expect(shouldRefreshLightning(base)).toBe(true)
    expect(shouldRefreshLightning({ ...base, view: { kind: 'partially_paid' } })).toBe(true)
    expect(shouldRefreshLightning({ ...base, view: { kind: 'partially_paid_pending' } })).toBe(true)
  })

  it('never refreshes sufficient, incident, or unknown states', () => {
    for (const view of [
      { kind: 'settling' },
      { kind: 'overpaid_pending' },
      { kind: 'resolution_pending' },
      { kind: 'needs_review' },
      { kind: 'unknown' },
    ] as const) {
      expect(shouldRefreshLightning({ ...base, view })).toBe(false)
    }
  })

  it('honors acceptance, in-flight state, current offers, and cooldown', () => {
    expect(shouldRefreshLightning({ ...base, accept: false })).toBe(false)
    expect(shouldRefreshLightning({ ...base, refreshing: true })).toBe(false)
    expect(shouldRefreshLightning({ ...base, pr: 'lnbc1...' })).toBe(false)
    expect(shouldRefreshLightning({ ...base, lastFailedAt: 999_000 })).toBe(false)
    expect(
      shouldRefreshLightning({ ...base, lastFailedAt: 1_000_000 - LN_REFRESH_COOLDOWN_MS }),
    ).toBe(true)
  })

  it('adopts fresh offers, clears stale partial offers, and retains hidden ones', () => {
    expect(nextLightningPr('old', makeStatus({ lightning_pr: 'new' }))).toBe('new')
    expect(
      nextLightningPr(
        'stale',
        makeStatus({ status: 'partially_paid', presentation_status: 'partial', settlement_status: 'pending' }),
      ),
    ).toBeNull()
    expect(
      nextLightningPr(
        'keep',
        makeStatus({ status: 'paid', presentation_status: 'payment_received', settlement_status: 'pending' }),
      ),
    ).toBe('keep')
  })
})

describe('Bitcoin payment payload transitions', () => {
  it('clears an amount-mismatched chain offer after a partial payment', () => {
    const offered = bitcoinPaymentPayloadFromStatus(
      makeStatus({
        bitcoin_chain_address: 'bc1qfullamountlockup',
        bitcoin_chain_bip21: 'bitcoin:bc1qfullamountlockup?amount=0.00010800',
        bitcoin_chain_amount_sat: 10_800,
      }),
    )
    expect(offered.chainAddress).toBe('bc1qfullamountlockup')

    const partial = bitcoinPaymentPayloadFromStatus(
      makeStatus({
        status: 'partially_paid',
        presentation_status: 'partial',
        settlement_status: 'pending',
        remaining_amount_sat: 4_000,
        bitcoin_chain_address: null,
        bitcoin_chain_bip21: null,
        bitcoin_chain_amount_sat: null,
      }),
    )
    expect(partial).toEqual({ directAddress: null, chainAddress: null, chainBip21: null, chainAmountSat: null })
  })

  it('clears a chain offer that is no longer pending while preserving direct BTC separately', () => {
    const next = bitcoinPaymentPayloadFromStatus(
      makeStatus({
        bitcoin_address: 'bc1qmerchantdirect',
        bitcoin_chain_address: null,
        bitcoin_chain_bip21: 'bitcoin:bc1qstalechain?amount=0.00010800',
        bitcoin_chain_amount_sat: 10_800,
      }),
    )
    expect(next).toEqual({
      directAddress: 'bc1qmerchantdirect',
      chainAddress: null,
      chainBip21: null,
      chainAmountSat: null,
    })
  })

  it('fails closed when an address has no exact positive payer amount', () => {
    for (const bitcoin_chain_amount_sat of [null, 0, -1, Number.MAX_SAFE_INTEGER + 1]) {
      const next = bitcoinPaymentPayloadFromStatus(
        makeStatus({
          bitcoin_chain_address: 'bc1qamountlesschain',
          bitcoin_chain_bip21: null,
          bitcoin_chain_amount_sat,
        }),
      )
      expect(next).toEqual({
        directAddress: null,
        chainAddress: null,
        chainBip21: null,
        chainAmountSat: null,
      })
    }
  })

  it('keeps an exact amount when BIP21 is absent so fallback construction is safe', () => {
    expect(
      bitcoinPaymentPayloadFromStatus(
        makeStatus({
          bitcoin_chain_address: 'bc1qfallbackchain',
          bitcoin_chain_bip21: null,
          bitcoin_chain_amount_sat: 11_234,
        }),
      ),
    ).toEqual({
      directAddress: null,
      chainAddress: 'bc1qfallbackchain',
      chainBip21: null,
      chainAmountSat: 11_234,
    })
  })
})

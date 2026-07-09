// CONTRACT 1 (derivePayView) and the lightning-refresh throttle
// (shouldRefreshLightning) — both pure, both exhaustively pinned here since
// they're the two places review item 4/6's bugs lived (in_progress
// mislabeled as "Waiting for payment"; a failing offer-creation call
// hammered every 3s poll).
import { describe, expect, it } from 'vitest'
import type { InvoiceStatus } from './api/client'
import { derivePayView, isTerminalView, showsRails, payViewLabel, shouldRefreshLightning, nextLightningPr, LN_REFRESH_COOLDOWN_MS } from './status'

function makeStatus(overrides: Partial<InvoiceStatus> = {}): InvoiceStatus {
  return {
    status: 'unpaid',
    pricing_mode: 'fiat',
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
    liquid_address: null,
    bitcoin_address: null,
    bitcoin_chain_address: null,
    bitcoin_chain_bip21: null,
    accept_btc: true,
    accept_ln: true,
    accept_liquid: true,
    ...overrides,
  }
}

describe('derivePayView priority order', () => {
  it('unpaid/pending -> waiting', () => {
    expect(derivePayView(makeStatus({ status: 'unpaid' }))).toEqual({ kind: 'waiting' })
    expect(derivePayView(makeStatus({ status: 'pending' }))).toEqual({ kind: 'waiting' })
  })

  it('in_progress -> in_progress (distinct from waiting — review item 4)', () => {
    expect(derivePayView(makeStatus({ status: 'in_progress' }))).toEqual({ kind: 'in_progress' })
  })

  it('partially_paid -> partially_paid', () => {
    expect(derivePayView(makeStatus({ status: 'partially_paid' }))).toEqual({ kind: 'partially_paid' })
  })

  it('paid -> paid, overpaid -> overpaid (distinct terminals)', () => {
    expect(derivePayView(makeStatus({ status: 'paid' }))).toEqual({ kind: 'paid' })
    expect(derivePayView(makeStatus({ status: 'overpaid' }))).toEqual({ kind: 'overpaid' })
  })

  it('underpaid is terminal, distinct from paid/overpaid', () => {
    const v = derivePayView(makeStatus({ status: 'underpaid' }))
    expect(v).toEqual({ kind: 'underpaid' })
    expect(isTerminalView(v)).toBe(true)
  })

  it('cancelled is distinct from expired', () => {
    expect(derivePayView(makeStatus({ status: 'expired' }))).toEqual({ kind: 'expired' })
    expect(derivePayView(makeStatus({ status: 'cancelled' }))).toEqual({ kind: 'cancelled' })
  })

  it('settlement_status pending -> settling', () => {
    expect(derivePayView(makeStatus({ status: 'in_progress', settlement_status: 'pending' }))).toEqual({ kind: 'settling' })
  })

  it('settlement_status claim_stuck -> needs_review', () => {
    expect(derivePayView(makeStatus({ status: 'in_progress', settlement_status: 'claim_stuck' }))).toEqual({
      kind: 'needs_review',
    })
  })

  it('settlement_status refunded -> refunded (terminal)', () => {
    const v = derivePayView(makeStatus({ status: 'in_progress', settlement_status: 'refunded' }))
    expect(v).toEqual({ kind: 'refunded' })
    expect(isTerminalView(v)).toBe(true)
  })

  it('terminal status beats a stale/racing settlement_status', () => {
    // status='partially_paid' + settlement_status='pending' -> settling
    // (settlement beats live)...
    expect(derivePayView(makeStatus({ status: 'partially_paid', settlement_status: 'pending' }))).toEqual({ kind: 'settling' })
    // ...but status='paid' + settlement_status='pending' -> paid (terminal
    // beats settlement) — the pinned example from the brief.
    expect(derivePayView(makeStatus({ status: 'paid', settlement_status: 'pending' }))).toEqual({ kind: 'paid' })
  })
})

describe('isTerminalView / showsRails', () => {
  it('terminal kinds: paid overpaid underpaid expired cancelled refunded', () => {
    for (const kind of ['paid', 'overpaid', 'underpaid', 'expired', 'cancelled', 'refunded'] as const) {
      expect(isTerminalView({ kind })).toBe(true)
    }
  })

  it('non-terminal kinds: waiting in_progress partially_paid settling needs_review', () => {
    for (const kind of ['waiting', 'in_progress', 'partially_paid', 'settling', 'needs_review'] as const) {
      expect(isTerminalView({ kind })).toBe(false)
    }
  })

  it('showsRails is true only for waiting/partially_paid (detected hides the QR)', () => {
    expect(showsRails({ kind: 'waiting' })).toBe(true)
    expect(showsRails({ kind: 'partially_paid' })).toBe(true)
    // Once a payment is detected we show "Payment received", not the QR.
    expect(showsRails({ kind: 'in_progress' })).toBe(false)
    expect(showsRails({ kind: 'settling' })).toBe(false)
    expect(showsRails({ kind: 'needs_review' })).toBe(false)
    expect(showsRails({ kind: 'paid' })).toBe(false)
  })
})

describe('payViewLabel', () => {
  it('in_progress reads "Payment received" (success on detection), NOT "Waiting for payment"', () => {
    expect(payViewLabel({ kind: 'in_progress' }, null)).toBe('Payment received')
    expect(payViewLabel({ kind: 'waiting' }, null)).toBe('Waiting for payment')
  })

  it('partially_paid includes the grouped remaining sat amount', () => {
    expect(payViewLabel({ kind: 'partially_paid' }, 1234)).toBe('Partially paid — 1,234 sat due')
  })

  it('settling shows success; needs_review / refunded stay distinct incidents', () => {
    // Detection (settling) renders as success — the "Settlement is in progress"
    // disclaimer is shown by the panel, not the label.
    expect(payViewLabel({ kind: 'settling' }, null)).toBe('Payment received')
    expect(payViewLabel({ kind: 'needs_review' }, null)).toBe('Payment needs review')
    expect(payViewLabel({ kind: 'refunded' }, null)).toBe('Settlement failed')
  })
})

describe('shouldRefreshLightning throttle', () => {
  const base = { accept: true, pr: null, view: { kind: 'waiting' } as const, refreshing: false, lastFailedAt: null, now: 1_000_000 }

  it('refreshes when accepted, no current offer, view is waiting, and not already refreshing', () => {
    expect(shouldRefreshLightning(base)).toBe(true)
  })

  it('does not refresh when a Lightning offer already exists', () => {
    expect(shouldRefreshLightning({ ...base, pr: 'lnbc1...' })).toBe(false)
  })

  it('does not refresh when Lightning is not accepted', () => {
    expect(shouldRefreshLightning({ ...base, accept: false })).toBe(false)
  })

  it('does not refresh when a request is already in flight', () => {
    expect(shouldRefreshLightning({ ...base, refreshing: true })).toBe(false)
  })

  it('refreshes on partially_paid too, not just waiting', () => {
    expect(shouldRefreshLightning({ ...base, view: { kind: 'partially_paid' } })).toBe(true)
  })

  it('does not refresh on in_progress/settling/needs_review views', () => {
    expect(shouldRefreshLightning({ ...base, view: { kind: 'in_progress' } })).toBe(false)
    expect(shouldRefreshLightning({ ...base, view: { kind: 'settling' } })).toBe(false)
    expect(shouldRefreshLightning({ ...base, view: { kind: 'needs_review' } })).toBe(false)
  })

  it('a recent failure blocks retry within the cooldown window', () => {
    expect(shouldRefreshLightning({ ...base, lastFailedAt: 999_000, now: 1_000_000 })).toBe(false)
  })

  it('retry is allowed once the cooldown has elapsed', () => {
    const lastFailedAt = 1_000_000 - LN_REFRESH_COOLDOWN_MS
    expect(shouldRefreshLightning({ ...base, lastFailedAt, now: 1_000_000 })).toBe(true)
  })

  it('retry is still blocked 1ms before the cooldown elapses', () => {
    const lastFailedAt = 1_000_000 - LN_REFRESH_COOLDOWN_MS + 1
    expect(shouldRefreshLightning({ ...base, lastFailedAt, now: 1_000_000 })).toBe(false)
  })
})

describe('nextLightningPr — adopt fresh / clear stale (finding #2, review item 6)', () => {
  it('adopts a fresh server-issued offer', () => {
    expect(nextLightningPr('old', makeStatus({ status: 'partially_paid', lightning_pr: 'new' }))).toBe('new')
    expect(nextLightningPr(null, makeStatus({ lightning_pr: 'fresh' }))).toBe('fresh')
  })

  it('clears a stale offer to null on a still-payable invoice so it gets re-requested', () => {
    // Partial payment invalidates the full-amount BOLT11; server returns null
    // until POST /lightning. The old offer must NOT linger.
    expect(nextLightningPr('stale', makeStatus({ status: 'partially_paid', lightning_pr: null }))).toBeNull()
    expect(nextLightningPr('stale', makeStatus({ status: 'unpaid', lightning_pr: null }))).toBeNull()
  })

  it('keeps the current offer when the server reports none but the invoice is no longer rail-payable', () => {
    // e.g. settlement pending/in_progress: not re-requesting, so don't churn.
    expect(nextLightningPr('keep', makeStatus({ status: 'in_progress', lightning_pr: null }))).toBe('keep')
    expect(nextLightningPr('keep', makeStatus({ status: 'unpaid', settlement_status: 'pending', lightning_pr: null }))).toBe('keep')
  })

  it('does not clear when Lightning is not accepted', () => {
    expect(nextLightningPr('keep', makeStatus({ status: 'unpaid', accept_ln: false, lightning_pr: null }))).toBe('keep')
  })
})

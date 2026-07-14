// Cache-hit path (§3's "cache hit uses cached" case) + the shared
// amount-label derivation used by both the cache-hit and reconstruction
// paths (see lib/invoice-load.ts for the reconstruction-side tests).
import { describe, expect, it } from 'vitest'
import { cacheInvoice, getCachedInvoice, amountLabelFor } from './invoiceCache'
import type { CreateInvoiceResponse } from '$lib/api/client'
import { formatFiat } from '$lib/money'

function makeInvoice(id: string): CreateInvoiceResponse {
  return {
    invoice_id: id,
    lightning_pr: 'lnbc1...',
    lightning_amount_sat: 1_050,
    liquid_address: 'lq1...',
    liquid_amount_sat: 1_000,
    bitcoin_chain_address: null,
    bitcoin_chain_bip21: null,
    bitcoin_chain_amount_sat: null,
    expires_at_unix: 1_700_000_000,
  }
}

describe('cacheInvoice / getCachedInvoice', () => {
  it('a cached entry round-trips exactly', () => {
    const invoice = makeInvoice('cache-hit-1')
    cacheInvoice({ invoice, note: 'table 5', precision: 2, unit: 'fiat', fiatAmountMinor: 1500, currency: 'USD' })
    const hit = getCachedInvoice('cache-hit-1')
    expect(hit?.note).toBe('table 5')
    expect(hit?.fiatAmountMinor).toBe(1500)
    expect(hit?.invoice.lightning_pr).toBe('lnbc1...')
  })

  it('an unknown id misses', () => {
    expect(getCachedInvoice('never-cached')).toBeUndefined()
  })
})

describe('amountLabelFor', () => {
  // Note: intentionally compares against formatFiat(...)'s own output
  // rather than a hardcoded string literal — Intl's currency formatting
  // inserts a non-breaking space (not a plain ' ') between the code and
  // amount for some locales/ICU versions, which makes a literal expectation
  // fragile across environments.
  it('fiat uses formatFiat(minor, currency, precision)', () => {
    expect(amountLabelFor({ unit: 'fiat', fiatAmountMinor: 850000, currency: 'CRC', precision: 0 })).toBe(
      formatFiat(850000, 'CRC', 0),
    )
  })

  it('sat formats as a grouped integer + " sat"', () => {
    expect(amountLabelFor({ unit: 'sat', amountSat: 21_000, precision: 0 })).toBe('21,000 sat')
  })

  it('btc formats as an up-to-8dp amount + " BTC"', () => {
    expect(amountLabelFor({ unit: 'btc', amountSat: 150_000, precision: 8 })).toBe('0.0015 BTC')
  })
})

// Reconstruction path (§3, deep link / page reload — the in-memory
// invoiceCache is gone). Mocks global fetch the same way
// lib/api/client.test.ts does, since reconstructInvoice calls straight
// through to getInvoiceStatus/getSupportedCurrencies.
import { describe, expect, it, vi, afterEach } from 'vitest'
import { reconstructInvoice } from './invoice-load'
import { formatFiat } from './money'

function mockSequence(responses: Array<{ status: number; body: unknown }>): void {
  const fn = vi.fn()
  for (const { status, body } of responses) {
    fn.mockResolvedValueOnce({
      ok: status >= 200 && status < 300,
      status,
      statusText: 'irrelevant',
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(JSON.stringify(body)),
    })
  }
  vi.stubGlobal('fetch', fn)
}

afterEach(() => {
  vi.unstubAllGlobals()
})

const fiatStatus = {
  status: 'unpaid',
  presentation_status: 'unpaid',
  pricing_mode: 'fiat',
  settlement_status: 'none',
  amount_sat: 10_800,
  fiat_amount_minor: 850000,
  fiat_currency: 'CRC',
  remaining_amount_sat: 10_800,
  payment_tolerance_sat: 0,
  rate_minor_per_btc: 78_000_000_00,
  rate_locks_until_unix: 0,
  expires_at_unix: 1_700_000_900,
  paid_via: null,
  paid_at_unix: null,
  paid_amount_sat: null,
  lightning_pr: 'lnbc1...',
  lightning_amount_sat: 10_850,
  liquid_address: 'lq1...',
  liquid_amount_sat: 10_800,
  bitcoin_address: null,
  bitcoin_chain_address: null,
  bitcoin_chain_bip21: null,
  bitcoin_chain_amount_sat: null,
  accept_btc: true,
  accept_ln: true,
  accept_liquid: true,
}

const currenciesBody = { currencies: [{ code: 'CRC', precision: 0 }, { code: 'USD', precision: 2 }] }

describe('reconstructInvoice — fiat status', () => {
  it('builds a fiat amount label using the resolved currency precision', async () => {
    mockSequence([
      { status: 200, body: fiatStatus },
      { status: 200, body: currenciesBody },
    ])
    const res = await reconstructInvoice('abc')
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.data.unit).toBe('fiat')
    expect(res.data.precision).toBe(0)
    expect(res.data.currency).toBe('CRC')
    expect(res.data.amountLabel).toBe(formatFiat(850000, 'CRC', 0))
    expect(res.data.invoice.invoice_id).toBe('abc')
    expect(res.data.invoice.lightning_pr).toBe('lnbc1...')
  })

  it('falls back to precision 2 when the currencies call fails', async () => {
    mockSequence([
      { status: 200, body: fiatStatus },
      { status: 500, body: 'boom' },
    ])
    const res = await reconstructInvoice('abc')
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.data.precision).toBe(2)
  })
})

describe('reconstructInvoice — sat status (no fiat amount)', () => {
  it('builds a sat amount label when fiat_amount_minor is null', async () => {
    const satStatus = { ...fiatStatus, fiat_amount_minor: null, fiat_currency: null, amount_sat: 21_000, remaining_amount_sat: 21_000 }
    mockSequence([
      { status: 200, body: satStatus },
      { status: 200, body: currenciesBody },
    ])
    const res = await reconstructInvoice('sat-invoice')
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.data.unit).toBe('sat')
    expect(res.data.amountLabel).toBe('21,000 sat')
    expect(res.data.amountSat).toBe(21_000)
  })
})

describe('reconstructInvoice — not found', () => {
  it('an LNURL error envelope (InvoiceNotFound) resolves not-ok with "Invoice not found"', async () => {
    mockSequence([
      { status: 200, body: { status: 'ERROR', code: 'InvoiceNotFound', reason: 'invoice not found: xyz' } },
      { status: 200, body: currenciesBody },
    ])
    const res = await reconstructInvoice('xyz')
    expect(res.ok).toBe(false)
    if (res.ok) return
    expect(res.error).toBe('invoice not found: xyz')
  })

  it('a 200 OK with an unrecognized status value reconstructs for conservative live handling', async () => {
    mockSequence([
      { status: 200, body: { ...fiatStatus, status: 'some_future_status' } },
      { status: 200, body: currenciesBody },
    ])
    const res = await reconstructInvoice('weird')
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.data.invoice.invoice_id).toBe('weird')
  })
})

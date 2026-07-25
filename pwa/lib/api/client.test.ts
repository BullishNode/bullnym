// Covers truthful non-2xx JSON errors plus rolling-deploy/LNURL compatibility
// with the legacy HTTP-200 error envelope.
import { describe, expect, it, vi, afterEach } from 'vitest'
import { ApiError, createInvoice, fetchPayerQuote, getInvoiceStatus } from './client'

function response(status: number, body: unknown, headers: Record<string, string> = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: 'irrelevant',
    headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
    text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
  }
}

function mockFetchOnce(status: number, body: unknown, headers: Record<string, string> = {}): void {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(response(status, body, headers)),
  )
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('request() error-envelope detection', () => {
  it('throws ApiError(404, reason, code) for a 200 InvoiceNotFound envelope', async () => {
    mockFetchOnce(200, { status: 'ERROR', code: 'InvoiceNotFound', reason: 'invoice not found: abc' })
    await expect(getInvoiceStatus('abc')).rejects.toMatchObject({
      status: 404,
      code: 'InvoiceNotFound',
      message: 'invoice not found: abc',
    })
  })

  it('throws ApiError(404, ...) for DonationPageNotFound and NymNotFound too', async () => {
    mockFetchOnce(200, { status: 'ERROR', code: 'DonationPageNotFound', reason: 'no donation page for x' })
    await expect(getInvoiceStatus('x')).rejects.toMatchObject({ status: 404, code: 'DonationPageNotFound' })

    mockFetchOnce(200, { status: 'ERROR', code: 'NymNotFound', reason: 'nym not found: x' })
    await expect(getInvoiceStatus('x')).rejects.toMatchObject({ status: 404, code: 'NymNotFound' })
  })

  it('throws ApiError(429, ...) for RateLimited* codes, surfaced via isRateLimited', async () => {
    mockFetchOnce(200, { status: 'ERROR', code: 'RateLimitedSender', reason: 'rate limited (sender)' })
    try {
      await createInvoice('/alice', { amount_sat: 1000 })
      expect.unreachable('expected createInvoice to reject')
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError)
      const apiErr = err as ApiError
      expect(apiErr.status).toBe(429)
      expect(apiErr.isRateLimited).toBe(true)
      expect(apiErr.code).toBe('RateLimitedSender')
    }
  })

  it('maps unrecognized error codes to 400, using reason as the message', async () => {
    mockFetchOnce(200, {
      status: 'ERROR',
      code: 'ProofOfFundsRequired',
      reason: 'computed amount 17 sat below minimum 100 sat',
    })
    await expect(createInvoice('/alice', { amount_sat: 17 })).rejects.toMatchObject({
      status: 400,
      code: 'ProofOfFundsRequired',
      message: 'computed amount 17 sat below minimum 100 sat',
    })
  })

  it('still resolves normally for a real (non-envelope) 200 response', async () => {
    mockFetchOnce(200, {
      pricing_mode: 'sat_fixed',
      invoice_id: 'real-id',
      lightning_pr: 'lnbc1...',
      lightning_amount_sat: 1_050,
      liquid_address: 'lq1...',
      liquid_amount_sat: 1_000,
      bitcoin_chain_address: null,
      bitcoin_chain_bip21: null,
      bitcoin_chain_amount_sat: null,
      expires_at_unix: 1234567890,
    })
    const res = await createInvoice('/alice', { amount_sat: 1000 })
    expect(res.invoice_id).toBe('real-id')
  })

  it('preserves the code and sanitized reason from a non-2xx JSON envelope', async () => {
    mockFetchOnce(500, { status: 'ERROR', code: 'InternalError', reason: 'Internal server error.' })
    await expect(getInvoiceStatus('x')).rejects.toMatchObject({
      status: 500,
      code: 'InternalError',
      message: 'Internal server error.',
    })
  })

  it('POSTs to <invoice_base>/invoice, so an alias base stays nym-free', async () => {
    mockFetchOnce(200, {
      pricing_mode: 'sat_fixed',
      invoice_id: 'id',
      lightning_pr: '',
      lightning_amount_sat: null,
      liquid_address: '',
      liquid_amount_sat: null,
      bitcoin_chain_address: null,
      bitcoin_chain_bip21: null,
      bitcoin_chain_amount_sat: null,
      expires_at_unix: 0,
    })
    await createInvoice('/a/alices-shop', { amount_sat: 1000 })
    expect(fetch).toHaveBeenCalledWith(
      '/a/alices-shop/invoice',
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('uses one explicit POST for payer quotes and preserves the Lightning default body', async () => {
    const quote = {
      pricing_mode: 'fiat_fixed',
      invoice_id: 'invoice-id',
      selected_rail: 'lightning',
      quote: {
        quote_version_id: 'quote-id',
        version_number: 1,
        fiat_face_amount_minor: 1_000,
        fiat_target_amount_minor: 1_000,
        fiat_currency: 'USD',
        rate_minor_per_btc: 10_000_000,
        rate_source: 'test',
        rate_observed_at_unix: 1,
        rate_fetched_at_unix: 2,
        rate_fresh_until_unix: 90,
        merchant_amount_sat: 10_000,
        created_at_unix: 10,
        expires_at_unix: 310,
      },
      instruction: {
        kind: 'lightning_boltz_reverse',
        quote_offer_id: 'offer-id',
        pr: 'lnbc1...',
        payer_amount_sat: 10_100,
      },
    }
    mockFetchOnce(200, quote)
    await expect(fetchPayerQuote('invoice-id')).resolves.toEqual(quote)
    expect(fetch).toHaveBeenCalledWith('/api/v1/invoices/invoice-id/quote', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })

    mockFetchOnce(200, { ...quote, selected_rail: 'liquid' })
    await fetchPayerQuote('invoice-id', 'liquid')
    expect(fetch).toHaveBeenCalledWith('/api/v1/invoices/invoice-id/quote', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"rail":"liquid"}',
    })
  })

  it('retries QUOTE_BUSY exactly once using Retry-After and preserves the code if it stays busy', async () => {
    vi.useFakeTimers()
    vi.spyOn(Math, 'random').mockReturnValue(0)
    const busy = { status: 'ERROR', code: 'QUOTE_BUSY', reason: 'The invoice quote is being updated.' }
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(response(503, busy, { 'retry-after': '1' }))
      .mockResolvedValueOnce(response(503, busy, { 'retry-after': '1' }))
    vi.stubGlobal('fetch', fetchMock)

    const pending = fetchPayerQuote('invoice-id', 'bitcoin').catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(1_000)
    await expect(pending).resolves.toMatchObject({
      status: 503,
      code: 'QUOTE_BUSY',
      retryAfterSeconds: 1,
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
    vi.useRealTimers()
  })

  it('keeps status reads as a projection-only GET', async () => {
    mockFetchOnce(200, { status: 'unpaid', pricing_mode: 'fiat_fixed' })
    await getInvoiceStatus('projection-only')
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/invoices/projection-only/status',
      undefined,
    )
  })
})

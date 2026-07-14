// Covers the LNURL-style (LUD-06) error-envelope detection in request()
// (see src/error.rs) — the server returns HTTP 200 with
// {"status":"ERROR","code":"...","reason":"..."} for most failures across
// nearly every endpoint, rather than a real non-2xx status. Before this
// fix, request() only checked res.ok, so every such envelope silently
// parsed as a success (e.g. createInvoice returning invoice_id: undefined).
import { describe, expect, it, vi, afterEach } from 'vitest'
import { ApiError, createInvoice, getInvoiceStatus } from './client'

function mockFetchOnce(status: number, body: unknown): void {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      statusText: 'irrelevant',
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(JSON.stringify(body)),
    }),
  )
}

afterEach(() => {
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

  it('still throws for a real non-2xx status (unchanged behavior)', async () => {
    mockFetchOnce(401, 'unauthorized')
    await expect(getInvoiceStatus('x')).rejects.toMatchObject({ status: 401 })
  })

  it('POSTs to <invoice_base>/invoice, so an alias base stays nym-free', async () => {
    mockFetchOnce(200, {
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
})

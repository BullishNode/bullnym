// Typed client for the bullnym anonymous checkout endpoints. Shapes
// mirror src/invoice.rs exactly — do not "improve" field names here.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
  ) {
    super(message)
  }
  get isRateLimited(): boolean {
    return this.status === 429
  }
}

export interface CreateInvoiceRequest {
  amount_sat?: number
  fiat_amount_minor?: number
  fiat_currency?: string
  /** Optional free-text note stored as the invoice's private memo (PoS
   * description / donor message). Returned only on the signed invoice list. */
  note?: string
}

/** Response of POST /<nym>/invoice (invoice.rs CreateInvoiceResponse). */
export interface CreateInvoiceResponse {
  invoice_id: string
  lightning_pr: string
  liquid_address: string
  bitcoin_chain_address: string | null
  bitcoin_chain_bip21: string | null
  expires_at_unix: number
}

/** Response of GET /api/v1/invoices/:id/status (InvoiceStatusResponse). */
export interface InvoiceStatus {
  status:
    | 'pending'
    | 'partially_paid'
    | 'paid'
    | 'overpaid'
    | 'underpaid'
    | 'expired'
    | 'cancelled'
    | string
  pricing_mode: string
  settlement_status: string
  amount_sat: number
  fiat_amount_minor: number | null
  fiat_currency: string | null
  remaining_amount_sat: number
  payment_tolerance_sat: number
  rate_minor_per_btc: number | null
  rate_locks_until_unix: number
  expires_at_unix: number
  paid_via: string | null
  paid_at_unix: number | null
  paid_amount_sat: number | null
  lightning_pr: string | null
  liquid_address: string | null
  bitcoin_address: string | null
  bitcoin_chain_address: string | null
  bitcoin_chain_bip21: string | null
  accept_btc: boolean
  accept_ln: boolean
  accept_liquid: boolean
}

export interface CurrencyView {
  code: string
  precision: number
}

export interface SupportedCurrenciesResponse {
  currencies: CurrencyView[]
}

// Per src/error.rs: the server deliberately returns HTTP 200 with an
// LNURL-style (LUD-06) error envelope — {"status":"ERROR","code":"...",
// "reason":"..."} — for nearly all error conditions, across nearly every
// endpoint (POST /:nym/invoice and the status endpoint included). Only
// AuthError (401), the two address-already-used variants (409), and
// ServiceUnavailable (503) get a real non-2xx status; everything else is a
// 200 whose body needs to be inspected to detect failure. Before this fix,
// request() only checked res.ok, so every such envelope parsed as success
// — this was the true origin of the "createInvoice succeeds with
// invoice_id undefined, app navigates to /#/pay/undefined and polls
// forever" bug: the envelope has no invoice_id, so CreateInvoiceResponse
// came back with invoice_id === undefined.
const NOT_FOUND_CODES = new Set(['InvoiceNotFound', 'DonationPageNotFound', 'NymNotFound'])
const RATE_LIMITED_CODES = new Set(['RateLimitedSender', 'RateLimitedRecipient', 'RateLimitedNetwork'])

interface ErrorEnvelope {
  status: 'ERROR'
  code?: string
  reason?: string
}

function isErrorEnvelope(body: unknown): body is ErrorEnvelope {
  return typeof body === 'object' && body !== null && (body as { status?: unknown }).status === 'ERROR'
}

function envelopeHttpStatus(code: string | undefined): number {
  if (code && NOT_FOUND_CODES.has(code)) return 404
  if (code && RATE_LIMITED_CODES.has(code)) return 429
  return 400
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(url, init)
  } catch {
    throw new ApiError(0, 'Server unreachable')
  }
  if (!res.ok) {
    let msg = res.statusText
    try {
      msg = await res.text()
    } catch {
      /* keep statusText */
    }
    throw new ApiError(res.status, msg)
  }
  const body = (await res.json()) as unknown
  if (isErrorEnvelope(body)) {
    throw new ApiError(envelopeHttpStatus(body.code), body.reason ?? body.code ?? 'Request failed', body.code)
  }
  return body as T
}

export function createInvoice(
  invoiceBase: string,
  req: CreateInvoiceRequest,
): Promise<CreateInvoiceResponse> {
  // `invoiceBase` already encodes the surface: `/<nym>` (Payment Page),
  // `/<nym>/pos` (POS), or `/a/<slug>` (alias). The server resolves the
  // settlement descriptor from it, so POS receipts settle to the POS
  // descriptor (idx 103) and never fall back to the Lightning Address wallet
  // (KR-1 / issue #7). Alias pages stay nym-free because the base carries the
  // slug, not the nym.
  return request(`${invoiceBase}/invoice`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  })
}

export function getInvoiceStatus(id: string): Promise<InvoiceStatus> {
  return request(`/api/v1/invoices/${id}/status`)
}

export function getSupportedCurrencies(): Promise<SupportedCurrenciesResponse> {
  return request('/api/v1/supported-currencies')
}

/**
 * Requests (or re-requests) a fresh Lightning offer for an invoice. Used
 * both for the initial offer (when the create response seeded lightning_pr
 * as '', e.g. on deep-link reconstruction) and to replace an offer that
 * expired mid-payment. On a non-payable/error invoice the server returns
 * the LNURL error envelope, which request() already converts into a thrown
 * ApiError — callers catch it (see PaymentScreen.svelte's throttled
 * maybeRefreshLightning()).
 */
export function fetchLightningOffer(id: string): Promise<{ pr: string }> {
  return request(`/api/v1/invoices/${id}/lightning`, { method: 'POST' })
}

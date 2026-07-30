// Typed client for the bullnym anonymous checkout endpoints. Shapes
// mirror src/invoice.rs exactly — do not "improve" field names here.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
    public retryAfterSeconds?: number,
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
export interface FiatFixedCreateInvoiceResponse {
  pricing_mode: 'fiat_fixed'
  invoice_id: string
  expires_at_unix: number
}

export interface SatFixedCreateInvoiceResponse {
  pricing_mode: 'sat_fixed'
  invoice_id: string
  /** Policy-bearing sat invoices deliberately return no destination at
   * creation; the payer must explicitly select a rail. */
  payer_demand_required?: boolean
  amount_sat?: number
  lightning_pr?: string
  /** Exact BOLT11 principal paired with lightning_pr. */
  lightning_amount_sat?: number | null
  liquid_address?: string
  /** Exact direct-Liquid amount paired with liquid_address. */
  liquid_amount_sat?: number | null
  bitcoin_chain_address?: string | null
  bitcoin_chain_bip21?: string | null
  /** Exact payer-side Bitcoin lock amount for the chain-swap offer. */
  bitcoin_chain_amount_sat?: number | null
  expires_at_unix: number
}

export type CreateInvoiceResponse = FiatFixedCreateInvoiceResponse | SatFixedCreateInvoiceResponse

/** Response of GET /api/v1/invoices/:id/status (InvoiceStatusResponse). */
export type PresentationStatus = 'unpaid' | 'partial' | 'payment_received' | 'overpaid' | string
export type SettlementStatus =
  | 'none'
  | 'pending'
  | 'settled'
  | 'resolution_pending'
  | 'claim_stuck'
  | 'refunded'
  | 'failed'
  | string

export interface InvoiceStatus {
  status:
    | 'unpaid'
    | 'in_progress'
    | 'pending'
    | 'partially_paid'
    | 'paid'
    | 'overpaid'
    | 'underpaid'
    | 'expired'
    | 'cancelled'
    | string
  /** Server-computed amount/tolerance projection. Null is a conservative
   * rollout/unknown state, never an alias for `unpaid`. */
  presentation_status: PresentationStatus | null
  pricing_mode: string
  settlement_status: SettlementStatus
  amount_sat: number
  fiat_amount_minor: number | null
  fiat_currency: string | null
  remaining_amount_sat: number
  /** Server-owned payment-admission projection. False after any credible
   * payment evidence; absent only during a rolling server upgrade. */
  accepting_payments?: boolean
  /** Bullnym never creates a remaining-balance instruction on this invoice. */
  top_up_allowed?: boolean
  payment_tolerance_sat: number
  rate_minor_per_btc: number | null
  rate_locks_until_unix: number
  expires_at_unix: number
  paid_via: string | null
  paid_at_unix: number | null
  paid_amount_sat: number | null
  lightning_pr: string | null
  /** Exact BOLT11 principal paired with lightning_pr. */
  lightning_amount_sat: number | null
  liquid_address: string | null
  /** Exact direct-Liquid amount paired with liquid_address. */
  liquid_amount_sat: number | null
  bitcoin_address: string | null
  bitcoin_chain_address: string | null
  bitcoin_chain_bip21: string | null
  /** Exact payer-side Bitcoin lock amount; null with no usable chain offer. */
  bitcoin_chain_amount_sat: number | null
  accept_btc: boolean
  accept_ln: boolean
  accept_liquid: boolean
  /** Pure GET projection. Present for every selected-rail payer-demand
   * invoice (fiat-fixed or policy-bearing sat-fixed) and null for the legacy
   * sat flow; it never creates a quote or provider obligation. */
  quote_rail_availability: PayerQuoteRailAvailability | null
}

export type PayerQuoteRail = 'lightning' | 'liquid' | 'bitcoin'

export interface PayerQuoteRailAvailability {
  lightning: boolean
  liquid: boolean
  bitcoin: boolean
}

export interface FiatQuoteView {
  quote_version_id: string
  version_number: number
  fiat_face_amount_minor: number
  fiat_target_amount_minor: number
  fiat_currency: string
  rate_minor_per_btc: number
  rate_source: string
  rate_observed_at_unix: number
  rate_fetched_at_unix: number
  rate_fresh_until_unix: number
  merchant_amount_sat: number
  created_at_unix: number
  expires_at_unix: number
}

export type VersionedPayerInstruction =
  | {
      kind: 'lightning_boltz_reverse'
      quote_offer_id: string
      pr: string
      payer_amount_sat: number
    }
  | {
      kind: 'lightning_direct'
      pr: string
      payer_amount_sat: number
    }
  | {
      kind: 'lightning_current'
      pr: string
      payer_amount_sat: number
    }
  | {
      kind: 'liquid_direct'
      address: string
      payer_amount_sat: number
    }
  | {
      kind: 'bitcoin_direct'
      address: string
      bip21: string
      payer_amount_sat: number
    }
  | {
      kind: 'bitcoin_boltz_chain'
      quote_offer_id: string
      address: string
      bip21: string
      payer_amount_sat: number
    }
  | {
      kind: 'bitcoin_boltz_chain_current'
      address: string
      bip21: string
      payer_amount_sat: number
    }

export interface FiatFixedPayerDemandQuoteResponse {
  pricing_mode: 'fiat_fixed'
  invoice_id: string
  selected_rail: PayerQuoteRail
  quote: FiatQuoteView
  instruction: VersionedPayerInstruction
  instruction_expires_at_unix: number | null
}

export interface SatFixedPayerDemandQuoteResponse {
  pricing_mode: 'sat_fixed'
  invoice_id: string
  selected_rail: PayerQuoteRail
  amount_sat: number
  expires_at_unix: number
  instruction: VersionedPayerInstruction
  instruction_expires_at_unix: number | null
}

export type PayerDemandQuoteResponse =
  | FiatFixedPayerDemandQuoteResponse
  | SatFixedPayerDemandQuoteResponse

export interface CurrencyView {
  code: string
  precision: number
}

export interface SupportedCurrenciesResponse {
  currencies: CurrencyView[]
}

// Bullnym 0.3 returns truthful HTTP statuses on JSON APIs. Keep recognizing a
// 200 error envelope for rolling-deploy compatibility and for protocol routes
// that deliberately use the LNURL/LUD-06 transport contract.
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

interface RequestPolicy {
  retryQuoteBusy?: boolean
}

function retryAfterSeconds(res: Response): number | undefined {
  const raw = res.headers?.get('Retry-After')
  if (raw == null) return undefined
  const parsed = Number(raw)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined
}

async function responseBody(res: Response): Promise<unknown> {
  const text = await res.text()
  if (!text) return null
  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

async function requestOnce<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(url, init)
  } catch {
    throw new ApiError(0, 'Server unreachable')
  }
  const body = await responseBody(res)
  if (!res.ok) {
    if (isErrorEnvelope(body)) {
      throw new ApiError(
        res.status,
        body.reason ?? body.code ?? 'Request failed',
        body.code,
        retryAfterSeconds(res),
      )
    }
    throw new ApiError(res.status, typeof body === 'string' ? body : res.statusText)
  }
  if (isErrorEnvelope(body)) {
    throw new ApiError(envelopeHttpStatus(body.code), body.reason ?? body.code ?? 'Request failed', body.code)
  }
  return body as T
}

async function request<T>(url: string, init?: RequestInit, policy: RequestPolicy = {}): Promise<T> {
  try {
    return await requestOnce<T>(url, init)
  } catch (error) {
    if (!(policy.retryQuoteBusy && error instanceof ApiError && error.code === 'QUOTE_BUSY')) {
      throw error
    }
    const baseDelayMs = Math.min(1_250, Math.max(250, (error.retryAfterSeconds ?? 1) * 1_000))
    const jitterMs = Math.floor(Math.random() * 200)
    await new Promise((resolve) => setTimeout(resolve, baseDelayMs + jitterMs))
    return requestOnce<T>(url, init)
  }
}

export function createInvoice(
  invoiceBase: string,
  req: CreateInvoiceRequest,
): Promise<CreateInvoiceResponse> {
  // `invoiceBase` already encodes the surface: `/<nym>` (Payment Page),
  // `/<nym>/pos` (POS), `/a/<slug>` (alias Page), or `/a/<slug>/pos` (alias
  // POS). The server resolves the
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
 * The sole fiat payer-instruction mutation. Omitting `rail` deliberately uses
 * the server's Lightning default; all GET endpoints remain projection-only.
 */
export function fetchPayerQuote(
  id: string,
  rail?: PayerQuoteRail,
): Promise<PayerDemandQuoteResponse> {
  return request(`/api/v1/invoices/${id}/quote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(rail ? { rail } : {}),
  }, { retryQuoteBusy: true })
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
export function fetchLightningOffer(id: string): Promise<{ pr: string; lightning_amount_sat: number }> {
  return request(`/api/v1/invoices/${id}/lightning`, { method: 'POST' })
}

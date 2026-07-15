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
export interface FiatFixedCreateInvoiceResponse {
  pricing_mode: 'fiat_fixed'
  invoice_id: string
  expires_at_unix: number
}

export interface SatFixedCreateInvoiceResponse {
  pricing_mode: 'sat_fixed'
  invoice_id: string
  lightning_pr: string
  /** Exact BOLT11 principal paired with lightning_pr. */
  lightning_amount_sat: number | null
  liquid_address: string
  /** Exact direct-Liquid amount paired with liquid_address. */
  liquid_amount_sat: number | null
  bitcoin_chain_address: string | null
  bitcoin_chain_bip21: string | null
  /** Exact payer-side Bitcoin lock amount for the chain-swap offer. */
  bitcoin_chain_amount_sat: number | null
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
  /** Pure GET projection. Required for fiat-fixed invoices and null for
   * sat-fixed invoices; it never creates a quote or provider obligation. */
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
      kind: 'liquid_direct'
      address: string
      payer_amount_sat: number
    }
  | {
      kind: 'bitcoin_boltz_chain'
      quote_offer_id: string
      address: string
      bip21: string
      payer_amount_sat: number
    }

export interface PayerDemandQuoteResponse {
  pricing_mode: 'fiat_fixed'
  invoice_id: string
  selected_rail: PayerQuoteRail
  quote: FiatQuoteView
  instruction: VersionedPayerInstruction
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
  })
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

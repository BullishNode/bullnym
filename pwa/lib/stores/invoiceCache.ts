// In-memory (module-scope, not persisted) cache mapping invoice_id -> the
// full CreateInvoiceResponse plus the request-time context PayFlow/
// PaymentScreen and the receipt need but the response itself doesn't carry
// (amount/currency aren't echoed back by POST /:nym/invoice — see
// lib/api/client.ts).
//
// Deliberately not localStorage: this is scoped to the current tab session.
// A reload or deep link to /#/pay/:id falls back to reconstructing from
// GET /api/v1/invoices/:id/status (see lib/invoice-load.ts).
//
// Renamed from posInvoice.ts (review item 3 + §4): the shape now also
// covers donation's sat/BTC entry (unit/amountSat), not just POS's
// fiat-only Charge flow, so a POS-specific name was no longer accurate.

import type { CreateInvoiceResponse } from '$lib/api/client'
import { formatFiat, formatCryptoAmount } from '$lib/money'

export interface CachedInvoice {
  invoice: CreateInvoiceResponse
  note: string
  precision: number
  unit: 'fiat' | 'sat' | 'btc'
  /** set when unit === 'fiat' */
  fiatAmountMinor?: number
  /** set when unit === 'fiat' */
  currency?: string
  /** set when unit === 'sat' | 'btc' */
  amountSat?: number
}

const cache = new Map<string, CachedInvoice>()

export function cacheInvoice(entry: CachedInvoice): void {
  cache.set(entry.invoice.invoice_id, entry)
}

export function getCachedInvoice(id: string): CachedInvoice | undefined {
  return cache.get(id)
}

/**
 * Shared amount-label derivation (§3) for a cache-hit invoice: fiat uses
 * formatFiat(fiatAmountMinor, currency, precision); sat/btc use the
 * dedicated crypto formatter on the whole-unit amount (amountSat converted
 * to whole sat or whole BTC first, since formatCryptoAmount takes the
 * entry-style decimal string, not raw sats).
 */
export function amountLabelFor(entry: Pick<CachedInvoice, 'unit' | 'fiatAmountMinor' | 'currency' | 'precision' | 'amountSat'>): string {
  if (entry.unit === 'sat') return formatCryptoAmount(String(entry.amountSat ?? 0), 'sat')
  if (entry.unit === 'btc') return formatCryptoAmount(String((entry.amountSat ?? 0) / 1e8), 'btc')
  return formatFiat(entry.fiatAmountMinor ?? 0, entry.currency ?? 'USD', entry.precision)
}

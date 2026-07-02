// In-memory (module-scope, not persisted) cache mapping invoice_id -> the
// full CreateInvoiceResponse plus the request-time context PaymentScreen and
// the receipt need but the response itself doesn't carry (amount/currency
// aren't echoed back by POST /:nym/invoice — see lib/api/client.ts).
//
// Deliberately not localStorage: this is scoped to the current tab session.
// A reload or deep link to /#/pay/:id falls back to GET
// /api/v1/invoices/:id/status (see apps/pos/screens/PayScreen.svelte).

import type { CreateInvoiceResponse } from '$lib/api/client'

export interface CachedInvoice {
  invoice: CreateInvoiceResponse
  note: string
  precision: number
  fiatAmountMinor: number
  currency: string
}

const cache = new Map<string, CachedInvoice>()

export function cacheInvoice(entry: CachedInvoice): void {
  cache.set(entry.invoice.invoice_id, entry)
}

export function getCachedInvoice(id: string): CachedInvoice | undefined {
  return cache.get(id)
}

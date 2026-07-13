// Shared invoice-loading logic for PayFlow.svelte's reconstruction path
// (deep link / page reload — the in-memory invoiceCache is gone). Pulled
// out of the component so it's unit-testable with a stubbed global fetch
// (same pattern as lib/api/client.test.ts) instead of requiring a
// component-testing harness this project doesn't have.
//
// Ported from apps/pos/screens/PayScreen.svelte's old reconstruction
// $effect, extended to also produce a sat-denominated amount label when the
// invoice was a sat/BTC donation (fiat_amount_minor === null) — the old
// PayScreen version only ever handled fiat, since POS never created
// anything else.
import { ApiError, getInvoiceStatus, getSupportedCurrencies, type CreateInvoiceResponse } from '$lib/api/client'
import { formatFiat, formatCryptoAmount } from '$lib/money'
import { config } from '$lib/config'

export interface ReconstructedInvoice {
  invoice: CreateInvoiceResponse
  amountLabel: string
  unit: 'fiat' | 'sat'
  precision: number
  fiatAmountMinor?: number
  currency?: string
  amountSat?: number
}

export type ReconstructResult = { ok: true; data: ReconstructedInvoice } | { ok: false; error: string }

export async function reconstructInvoice(id: string): Promise<ReconstructResult> {
  try {
    const [status, currencies] = await Promise.all([getInvoiceStatus(id), getSupportedCurrencies().catch(() => null)])
    // True root cause of the "/#/pay/undefined polls forever with a bare
    // ERROR state" bug: the server deliberately returns HTTP 200 with an
    // LNURL-style (LUD-06) error envelope for most failures (src/error.rs).
    // request() already converts that into a thrown ApiError (caught below).
    // Future status/presentation tokens remain reconstructable; the live
    // state machine treats them conservatively instead of inventing a 404.

    const invoice: CreateInvoiceResponse = {
      invoice_id: id,
      lightning_pr: status.lightning_pr ?? '',
      liquid_address: status.liquid_address ?? '',
      bitcoin_chain_address: status.bitcoin_chain_address,
      bitcoin_chain_bip21: status.bitcoin_chain_bip21,
      expires_at_unix: status.expires_at_unix,
    }

    if (status.fiat_amount_minor != null) {
      const currency = status.fiat_currency ?? config.currency
      const match = currencies?.currencies.find((c) => c.code === currency)
      const precision = match?.precision ?? 2
      return {
        ok: true,
        data: {
          invoice,
          amountLabel: formatFiat(status.fiat_amount_minor, currency, precision),
          unit: 'fiat',
          precision,
          fiatAmountMinor: status.fiat_amount_minor,
          currency,
        },
      }
    }

    // No fiat amount recorded — this was a sat/BTC donation (§4). The
    // server always reports the target in `amount_sat`, so that's the only
    // amount we can reconstruct (whether the sender originally typed sat or
    // BTC isn't recoverable, and doesn't matter for display).
    return {
      ok: true,
      data: {
        invoice,
        amountLabel: formatCryptoAmount(String(status.amount_sat), 'sat'),
        unit: 'sat',
        precision: 0,
        amountSat: status.amount_sat,
      },
    }
  } catch (err) {
    return { ok: false, error: err instanceof ApiError ? err.message : 'Invoice not found' }
  }
}

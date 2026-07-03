// Shared label mapping for InvoiceStatus.paid_via. Values confirmed against
// src/db/invoices.rs: 'lightning' | 'liquid' | 'bitcoin' | 'mixed' (settled
// across more than one rail, e.g. partial LN + remainder Liquid). No
// 'onchain' value exists server-side.

export function railLabel(rail: string | null): string {
  switch (rail) {
    case 'lightning':
      return 'Lightning'
    case 'liquid':
      return 'Liquid'
    case 'bitcoin':
      return 'Bitcoin'
    case 'mixed':
      return 'Multiple rails'
    default:
      return '—'
  }
}

/**
 * Rail-tab gating (review item 1's "never show a selectable tab with a
 * blank QR" fix) — a rail is offered only if it's accepted AND its payload
 * has actually arrived. Before the first poll, InvoiceStatus's accept_*
 * flags are unknown, so `undefined` is treated as accepted (matching the
 * create-response's implicit "this rail was offered" seed) — the payload
 * presence check still gates it, so a seed with no payload for a rail never
 * shows a tab for it either way.
 *
 * Extracted as a pure function (rather than inline $derived in
 * PaymentScreen.svelte) so the gating matrix is directly unit-testable —
 * see rails.test.ts.
 */
export interface RailAvailabilityInput {
  acceptLn: boolean | undefined
  lightningPr: string | null
  acceptLiquid: boolean | undefined
  liquidAddress: string | null
  acceptBtc: boolean | undefined
  bitcoinAddress: string | null
}

export interface RailAvailability {
  lightning: boolean
  liquid: boolean
  bitcoin: boolean
}

export function availableRails(input: RailAvailabilityInput): RailAvailability {
  return {
    lightning: (input.acceptLn ?? true) && !!input.lightningPr,
    liquid: (input.acceptLiquid ?? true) && !!input.liquidAddress,
    bitcoin: (input.acceptBtc ?? true) && !!input.bitcoinAddress,
  }
}

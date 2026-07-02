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

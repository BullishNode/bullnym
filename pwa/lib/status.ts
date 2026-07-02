// Status label/tone mapping for our InvoiceStatus vocabulary
// ('pending'|'partially_paid'|'paid'|'overpaid'|'underpaid'|'expired'|
// 'cancelled'), styled to match nostr-pos's StatusPill/TransactionSheet
// tone classes (~/apps/nostr-pos/apps/pos-pwa/src/lib/ui/StatusPill.svelte,
// TransactionSheet.svelte). Upstream keys off a much larger SaleStatus enum
// (Nostr/Boltz swap lifecycle states) that doesn't exist in our simpler
// server model — this is the adaptation layer, same visual tones.

// The full set of status values our server can return for a real invoice.
// InvoiceStatus.status is typed with a `| string` fallback (lib/api/client.ts)
// precisely because the server can return values outside this set — notably
// for an id that doesn't resolve to a real invoice, where the endpoint can
// come back 200 OK with a status we don't recognize rather than 404. Used
// to detect that case (see lib/components/PaymentScreen.svelte's poll() and
// apps/pos/screens/PayScreen.svelte's reconstruction effect) instead of
// treating an unrecognized status as "still waiting for payment" forever.
// Verified against src/db/invoices.rs: 'unpaid' and 'in_progress' are the
// live pre-payment states — omitting them made PayScreen's deep-link
// reconstruction reject every fresh invoice as "Invoice not found".
// ('pending' kept defensively.)
export const KNOWN_STATUSES = new Set([
  'unpaid',
  'in_progress',
  'pending',
  'partially_paid',
  'paid',
  'overpaid',
  'underpaid',
  'expired',
  'cancelled',
])

export function isTerminalPaid(status: string): boolean {
  return status === 'paid' || status === 'overpaid'
}

export function isTerminalFailed(status: string): boolean {
  return status === 'expired' || status === 'cancelled'
}

export function statusLabel(status: string): string {
  switch (status) {
    case 'unpaid':
    case 'in_progress':
    case 'pending':
      return 'Waiting for payment'
    case 'partially_paid':
      return 'Partial payment'
    case 'paid':
    case 'overpaid':
      return 'Paid'
    case 'expired':
      return 'Expired'
    case 'cancelled':
      return 'Cancelled'
    default:
      return status
  }
}

export function statusPillTone(status: string): string {
  if (isTerminalPaid(status)) return 'bg-[#d9f3df] text-[#14522d]'
  if (isTerminalFailed(status)) return 'bg-[#eee5d8] text-[#6d5f4e]'
  return 'bg-[#e2edf5] text-[#1e4e73]'
}

export function statusTextTone(status: string): string {
  if (isTerminalPaid(status)) return 'text-[#14522d] dark:text-[#8bc8a4]'
  if (isTerminalFailed(status)) return 'text-[#6d5f4e] dark:text-[#b9aa91]'
  return 'text-[#1e4e73] dark:text-[#9fc6e3]'
}

export function statusBorderTone(status: string): string {
  if (isTerminalPaid(status)) return 'border-l-[#1f513a]'
  if (status === 'cancelled') return 'border-l-[#a9362f]'
  if (status === 'expired') return 'border-l-[#b1a287]'
  return 'border-l-[#7aa0bd]'
}

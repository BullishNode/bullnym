// Status label/tone mapping for our InvoiceStatus vocabulary
// ('pending'|'partially_paid'|'paid'|'overpaid'|'underpaid'|'expired'|
// 'cancelled'), styled to match nostr-pos's StatusPill/TransactionSheet
// tone classes (~/apps/nostr-pos/apps/pos-pwa/src/lib/ui/StatusPill.svelte,
// TransactionSheet.svelte). Upstream keys off a much larger SaleStatus enum
// (Nostr/Boltz swap lifecycle states) that doesn't exist in our simpler
// server model — this is the adaptation layer, same visual tones.
//
import type { InvoiceStatus } from '$lib/api/client'

// statusLabel/statusPillTone/statusBorderTone/statusTextTone below are the
// ORIGINAL helpers, still used as-is by history/receipt views
// (StatusPill.svelte, TransactionSheet.svelte, ReceiptScreen.svelte) which
// only ever see a terminal-ish record status, not a live polling status.
// PayView (below) is the newer, richer view model for the LIVE payment
// screen: it exists because a bare `status` string collapses distinctions
// the payment screen must show separately — e.g. 'in_progress' was
// rendering the same "Waiting for payment" label as 'unpaid' (review item
// 4's headline bug), and settlement incidents (pending/claim_stuck/refunded
// on settlement_status) weren't represented at all.

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

// ---------------------------------------------------------------------------
// PayView — the live payment-screen view model (CONTRACT 1).
//
// Reference: templates/invoice_payment.html:526-605's pollStatus(), which
// this is a direct port of the *branching logic* for (the old page's
// initial-server-render markup is NOT the source of truth here — see the
// brief's ground rules). derivePayView is pure and exhaustively unit-tested
// in status.test.ts; PaymentScreen.svelte only ever reads the result, never
// re-derives the branching itself.
// ---------------------------------------------------------------------------

export type PayView =
  | { kind: 'waiting' }
  | { kind: 'in_progress' }
  | { kind: 'partially_paid' }
  | { kind: 'settling' }
  | { kind: 'needs_review' }
  | { kind: 'refunded' }
  | { kind: 'paid' }
  | { kind: 'overpaid' }
  | { kind: 'underpaid' }
  | { kind: 'expired' }
  | { kind: 'cancelled' }

const TERMINAL_LIVE_STATUSES = new Set(['paid', 'overpaid', 'underpaid', 'expired', 'cancelled'])

/**
 * Priority order, EXACTLY (see status.test.ts for the pinned cases):
 *   1. terminal `status` (paid/overpaid/underpaid/expired/cancelled) — wins
 *      over everything, including a stale/racing settlement_status.
 *   2. `settlement_status` (pending/claim_stuck/refunded) — a settlement
 *      incident on an otherwise-live invoice overrides the live status.
 *   3. live `status` (in_progress/partially_paid, else waiting).
 */
export function derivePayView(status: InvoiceStatus): PayView {
  if (TERMINAL_LIVE_STATUSES.has(status.status)) {
    return { kind: status.status as 'paid' | 'overpaid' | 'underpaid' | 'expired' | 'cancelled' }
  }
  if (status.settlement_status === 'pending') return { kind: 'settling' }
  if (status.settlement_status === 'claim_stuck') return { kind: 'needs_review' }
  if (status.settlement_status === 'refunded') return { kind: 'refunded' }
  if (status.status === 'in_progress') return { kind: 'in_progress' }
  if (status.status === 'partially_paid') return { kind: 'partially_paid' }
  return { kind: 'waiting' }
}

export function isTerminalView(v: PayView): boolean {
  return (
    v.kind === 'paid' ||
    v.kind === 'overpaid' ||
    v.kind === 'underpaid' ||
    v.kind === 'expired' ||
    v.kind === 'cancelled' ||
    v.kind === 'refunded'
  )
}

/** True for the three "live, rails-visible" views — QR/tab bar renders. */
export function showsRails(v: PayView): boolean {
  return v.kind === 'waiting' || v.kind === 'in_progress' || v.kind === 'partially_paid'
}

export function payViewLabel(v: PayView, remainingAmountSat: number | null): string {
  switch (v.kind) {
    case 'waiting':
      return 'Waiting for payment'
    case 'in_progress':
      return 'Payment detected…'
    case 'partially_paid':
      return remainingAmountSat != null
        ? `Partially paid — ${new Intl.NumberFormat().format(remainingAmountSat)} sat due`
        : 'Partially paid'
    case 'settling':
      return 'Payment detected — confirming settlement'
    case 'needs_review':
      return 'Payment needs review'
    case 'refunded':
      return 'Settlement failed'
    case 'paid':
    case 'overpaid':
      return 'Paid'
    case 'underpaid':
      return 'Underpaid'
    case 'expired':
      return 'Expired'
    case 'cancelled':
      return 'Cancelled'
  }
}

export function payViewTone(v: PayView): string {
  switch (v.kind) {
    case 'paid':
    case 'overpaid':
      return 'text-[#14522d] dark:text-[#8bc8a4]'
    case 'underpaid':
    case 'needs_review':
      return 'text-[#a9362f] dark:text-[#e8a49e]'
    case 'refunded':
    case 'cancelled':
    case 'expired':
      return 'text-[#6d5f4e] dark:text-[#b9aa91]'
    default:
      return 'text-[#1e4e73] dark:text-[#9fc6e3]'
  }
}

// ---------------------------------------------------------------------------
// TerminalState (CONTRACT 5) — what PaymentScreen reports UP to PayFlow
// exactly once per invoice, replacing the old onPaid/onExpired/onNotFound
// trio. That trio couldn't distinguish paid from overpaid, or expired from
// cancelled, from the callback shape alone — callers had to re-inspect
// `status.status` themselves (and PayScreen/App.svelte's onExpired handlers
// didn't distinguish expired/cancelled at all). One discriminated callback
// fixes both.
// ---------------------------------------------------------------------------

export type TerminalState =
  | { kind: 'paid'; status: InvoiceStatus }
  | { kind: 'overpaid'; status: InvoiceStatus }
  | { kind: 'underpaid'; status: InvoiceStatus }
  | { kind: 'expired' }
  | { kind: 'cancelled' }
  | { kind: 'refunded' }
  | { kind: 'not_found' }

/** Maps a terminal PayView (isTerminalView(v) === true) to the TerminalState PaymentScreen reports. Returns null for a non-terminal view. */
export function payViewToTerminal(view: PayView, status: InvoiceStatus): TerminalState | null {
  switch (view.kind) {
    case 'paid':
      return { kind: 'paid', status }
    case 'overpaid':
      return { kind: 'overpaid', status }
    case 'underpaid':
      return { kind: 'underpaid', status }
    case 'expired':
      return { kind: 'expired' }
    case 'cancelled':
      return { kind: 'cancelled' }
    case 'refunded':
      return { kind: 'refunded' }
    default:
      return null
  }
}

// ---------------------------------------------------------------------------
// Lightning-offer refresh throttle (review item 6). Extracted as a pure
// decision function so the cooldown logic is unit-testable without faking
// timers around a live component (see status.test.ts).
// ---------------------------------------------------------------------------

/** Minimum gap between a failed offer-creation attempt and the next retry. */
export const LN_REFRESH_COOLDOWN_MS = 15_000

/**
 * The Lightning offer to hold after a `/status` poll, mirroring
 * invoice_payment.html:562-576. Adopt a fresh server-issued offer; CLEAR a
 * stale one to null when the server reports no offer on a still-payable
 * invoice (waiting/partially_paid) so shouldRefreshLightning re-requests it.
 * Without the clear, a partial payment that invalidates the full-amount
 * BOLT11 (server returns lightning_pr=null until POST /lightning) would leave
 * the old, wrong-amount offer on screen and in Bolt Card taps.
 */
export function nextLightningPr(current: string | null, status: InvoiceStatus): string | null {
  if (status.lightning_pr) return status.lightning_pr
  const v = derivePayView(status)
  if ((v.kind === 'waiting' || v.kind === 'partially_paid') && (status.accept_ln ?? true)) return null
  return current
}

export function shouldRefreshLightning(params: {
  /** invoice's accept_ln flag; `true` when unknown (pre-first-poll — see PaymentScreen's rail gating). */
  accept: boolean
  /** current adopted Lightning offer, if any. */
  pr: string | null
  view: PayView
  /** an offer request is already in flight. */
  refreshing: boolean
  /** ms-since-epoch of the last failed attempt, or null if none yet. */
  lastFailedAt: number | null
  now: number
}): boolean {
  const { accept, pr, view, refreshing, lastFailedAt, now } = params
  if (!accept || pr || refreshing) return false
  if (view.kind !== 'waiting' && view.kind !== 'partially_paid') return false
  if (lastFailedAt != null && now - lastFailedAt < LN_REFRESH_COOLDOWN_MS) return false
  return true
}

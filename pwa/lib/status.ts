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
// Reference: the former standalone invoice poller, now shared here, which
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
  | { kind: 'partially_paid_pending' }
  | { kind: 'settling' }
  | { kind: 'overpaid_pending' }
  | { kind: 'resolution_pending' }
  | { kind: 'unknown' }
  | { kind: 'needs_review' }
  | { kind: 'refunded' }
  | { kind: 'failed' }
  | { kind: 'paid' }
  | { kind: 'overpaid' }
  | { kind: 'underpaid' }
  | { kind: 'expired' }
  | { kind: 'cancelled' }

/** Before the first successful detail response, cached create-response
 * payloads are not proof that the invoice is still payable. Keep the live
 * screen conservative and rail-free until current server state arrives. */
export function payViewBeforeFirstStatus(): PayView {
  return { kind: 'unknown' }
}

const KNOWN_PRESENTATION_STATUSES = new Set(['unpaid', 'partial', 'payment_received', 'overpaid'])
const KNOWN_ACCOUNTING_STATUSES = new Set([
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
const KNOWN_SETTLEMENT_STATUSES = new Set([
  'none',
  'pending',
  'settled',
  'resolution_pending',
  'claim_stuck',
  'refunded',
  'failed',
])

/**
 * The server-owned presentation and settlement projections win over cached
 * accounting terminality. Amounts, tolerances, mixed rails, and fiat rules are
 * deliberately absent from this function.
 */
export function derivePayView(status: InvoiceStatus): PayView {
  const presentation = status.presentation_status
  const instructionsClosed = status.status === 'cancelled' || status.status === 'expired'
  if (!KNOWN_SETTLEMENT_STATUSES.has(status.settlement_status)) return { kind: 'unknown' }

  if (status.settlement_status === 'claim_stuck') return { kind: 'needs_review' }
  if (status.settlement_status === 'refunded') return { kind: 'refunded' }
  if (status.settlement_status === 'failed') return { kind: 'failed' }
  if (status.settlement_status === 'resolution_pending') return { kind: 'resolution_pending' }
  if (presentation == null || !KNOWN_PRESENTATION_STATUSES.has(presentation)) return { kind: 'unknown' }
  if (!KNOWN_ACCOUNTING_STATUSES.has(status.status)) return { kind: 'unknown' }

  if (status.settlement_status === 'pending') {
    if (presentation === 'partial') {
      if (instructionsClosed) return { kind: 'settling' }
      if (status.status === 'unpaid' || status.status === 'in_progress' || status.status === 'partially_paid') {
        return { kind: 'partially_paid_pending' }
      }
      return { kind: 'unknown' }
    }
    if (presentation === 'overpaid') return { kind: 'overpaid_pending' }
    return { kind: 'settling' }
  }

  if (presentation === 'partial') {
    if (instructionsClosed) return { kind: 'underpaid' }
    if (status.status === 'underpaid') return { kind: 'underpaid' }
    if (status.status === 'unpaid' || status.status === 'in_progress' || status.status === 'partially_paid') {
      return { kind: 'partially_paid' }
    }
    return { kind: 'unknown' }
  }
  if (presentation === 'payment_received') {
    if (
      (status.status === 'paid' || instructionsClosed) &&
      (status.settlement_status === 'none' || status.settlement_status === 'settled')
    ) {
      return { kind: 'paid' }
    }
    return { kind: 'in_progress' }
  }
  if (presentation === 'overpaid') {
    if (
      (status.status === 'overpaid' || instructionsClosed) &&
      (status.settlement_status === 'none' || status.settlement_status === 'settled')
    ) {
      return { kind: 'overpaid' }
    }
    return { kind: 'overpaid_pending' }
  }

  if (status.settlement_status !== 'none') return { kind: 'unknown' }
  if (status.status === 'expired') return { kind: 'expired' }
  if (status.status === 'cancelled') return { kind: 'cancelled' }
  if (status.status === 'unpaid' || status.status === 'pending') return { kind: 'waiting' }
  return { kind: 'unknown' }
}

export function isTerminalView(v: PayView): boolean {
  return (
    v.kind === 'paid' ||
    v.kind === 'overpaid' ||
    v.kind === 'underpaid' ||
    v.kind === 'expired' ||
    v.kind === 'cancelled' ||
    v.kind === 'refunded' ||
    v.kind === 'failed'
  )
}

/** True for the "live, rails-visible" views — QR/tab bar renders. Once a
 * payment is detected (in_progress / settling) we stop showing the QR and
 * render the "Payment received" panel instead. */
export function showsRails(v: PayView): boolean {
  return v.kind === 'waiting' || v.kind === 'partially_paid' || v.kind === 'partially_paid_pending'
}

/** Unknown values and every accepted-evidence state are intentionally
 * non-cancellable. Only the exact fresh, no-lifecycle projection is safe. */
export function isCancelableStatus(status: InvoiceStatus): boolean {
  return status.status === 'unpaid' && status.presentation_status === 'unpaid' && status.settlement_status === 'none'
}

/** Automatic detail polling continues through payable partials, pending,
 * resolution, and unknown projections. A settled partial is still payable, so
 * it must keep observing a later top-up. Settled sufficient/overpaid states and
 * existing stop-polling incidents remain manually refreshable. */
export function shouldPollDetail(status: InvoiceStatus, view = derivePayView(status)): boolean {
  if (view.kind === 'refunded' || view.kind === 'failed') return false
  if (view.kind === 'needs_review') return false
  if (view.kind === 'unknown') return true
  if (
    status.settlement_status === 'pending' ||
    status.settlement_status === 'resolution_pending'
  ) {
    return true
  }
  if (status.settlement_status === 'settled') return view.kind === 'partially_paid'
  return !isTerminalView(view)
}

export function payViewLabel(v: PayView, remainingAmountSat: number | null): string {
  switch (v.kind) {
    case 'waiting':
      return 'Waiting for payment'
    case 'in_progress':
      return 'Payment received'
    case 'partially_paid':
    case 'partially_paid_pending':
      return remainingAmountSat != null
        ? `Partially paid — ${new Intl.NumberFormat().format(remainingAmountSat)} sat due`
        : 'Partially paid'
    case 'settling':
      return 'Payment received'
    case 'overpaid_pending':
      return 'Overpaid'
    case 'resolution_pending':
      return 'Payment issue'
    case 'unknown':
      return 'Checking payment status'
    case 'needs_review':
      return 'Payment needs review'
    case 'refunded':
    case 'failed':
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

export function payViewSupport(v: PayView): string | null {
  switch (v.kind) {
    case 'settling':
    case 'partially_paid_pending':
    case 'overpaid_pending':
      return 'Settlement pending'
    case 'resolution_pending':
      return 'Settlement problem — being checked'
    case 'unknown':
      return 'Payment status is being checked'
    case 'in_progress':
      return 'Settlement status is being checked'
    case 'needs_review':
      return 'Settlement is delayed. The operator has been alerted.'
    case 'refunded':
    case 'failed':
      return 'The payment could not be settled.'
    default:
      return null
  }
}

export function payViewTone(v: PayView): string {
  switch (v.kind) {
    case 'paid':
    case 'overpaid':
    // Payment detected renders as success (green) with a settlement note.
    case 'in_progress':
    case 'settling':
    case 'overpaid_pending':
      return 'text-[#14522d] dark:text-[#8bc8a4]'
    case 'underpaid':
    case 'needs_review':
    case 'resolution_pending':
    case 'unknown':
      return 'text-[#a9362f] dark:text-[#e8a49e]'
    case 'refunded':
    case 'failed':
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
  | { kind: 'failed' }
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
    case 'failed':
      return { kind: 'failed' }
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
 * the former standalone invoice flow. Adopt a fresh server-issued offer; CLEAR a
 * stale one to null when the server reports no offer on a still-payable
 * invoice (waiting/partially_paid) so shouldRefreshLightning re-requests it.
 * Without the clear, a partial payment that invalidates the full-amount
 * BOLT11 (server returns lightning_pr=null until POST /lightning) would leave
 * the old, wrong-amount offer on screen and in Bolt Card taps.
 */
export function nextLightningPr(current: string | null, status: InvoiceStatus): string | null {
  if (status.lightning_pr) return status.lightning_pr
  const v = derivePayView(status)
  if (
    (v.kind === 'waiting' || v.kind === 'partially_paid' || v.kind === 'partially_paid_pending') &&
    (status.accept_ln ?? true)
  ) return null
  return current
}

export interface BitcoinPaymentPayloadState {
  directAddress: string | null
  chainAddress: string | null
  chainBip21: string | null
  chainAmountSat: number | null
}

/** Replace Bitcoin payment payloads from one authoritative status snapshot.
 * A null chain offer is meaningful: the prior Boltz lockup may have expired,
 * left `pending`, or no longer match the exact remaining amount. Never merge
 * that null with a cached chain address. */
export function bitcoinPaymentPayloadFromStatus(
  status: Pick<
    InvoiceStatus,
    'bitcoin_address' | 'bitcoin_chain_address' | 'bitcoin_chain_bip21' | 'bitcoin_chain_amount_sat'
  >,
): BitcoinPaymentPayloadState {
  const chainAddress = status.bitcoin_chain_address ?? null
  const chainAmountSat = status.bitcoin_chain_amount_sat
  const completeChainOffer =
    !!chainAddress && Number.isSafeInteger(chainAmountSat) && (chainAmountSat ?? 0) > 0
  return {
    directAddress: status.bitcoin_address ?? null,
    chainAddress: completeChainOffer ? chainAddress : null,
    chainBip21: completeChainOffer ? (status.bitcoin_chain_bip21 ?? null) : null,
    chainAmountSat: completeChainOffer ? chainAmountSat : null,
  }
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
  if (view.kind !== 'waiting' && view.kind !== 'partially_paid' && view.kind !== 'partially_paid_pending') return false
  if (lastFailedAt != null && now - lastFailedAt < LN_REFRESH_COOLDOWN_MS) return false
  return true
}

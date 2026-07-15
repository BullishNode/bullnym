export const POS_BITCOIN_RISK_COPY =
  'For in-person payments, Lightning network is recommended. Bitcoin on-chain payments can be cancelled by the sender for up to a few hours, and should not be considered safe until confirmed.'

export const POS_BITCOIN_ACKNOWLEDGEMENT = 'I understand'

export const POS_BITCOIN_ACKNOWLEDGEMENT_SESSION_KEY =
  'bullnym:pos-bitcoin-risk-acknowledgement:v1'

export type PaymentSurfaceMode = 'pos' | 'donation' | 'page' | 'invoice' | 'lnurl'
export type QuoteRail = 'lightning' | 'liquid' | 'bitcoin'

export interface QuoteRailAvailability {
  readonly lightning: boolean
  readonly liquid: boolean
  readonly bitcoin: boolean
}

export interface SessionStorageLike {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export type BitcoinSelectionAction = 'acknowledge' | 'allow'

export function requiresPosBitcoinAcknowledgement(
  mode: PaymentSurfaceMode,
  acknowledgedForInvoiceSession: boolean,
): boolean {
  return mode === 'pos' && !acknowledgedForInvoiceSession
}

export function bitcoinSelectionAction(
  mode: PaymentSurfaceMode,
  acknowledgedForInvoiceSession: boolean,
): BitcoinSelectionAction {
  return requiresPosBitcoinAcknowledgement(mode, acknowledgedForInvoiceSession)
    ? 'acknowledge'
    : 'allow'
}

/**
 * Payload exposure and the first Bitcoin quote/offer request deliberately use
 * the same authority. A future caller cannot reveal an instruction while its
 * network mutation is still denied, or vice versa.
 */
export function mayUseBitcoinPaymentInstruction(
  mode: PaymentSurfaceMode,
  acknowledgedForInvoiceSession: boolean,
): boolean {
  return bitcoinSelectionAction(mode, acknowledgedForInvoiceSession) === 'allow'
}

export function mayRequestBitcoinQuote(
  mode: PaymentSurfaceMode,
  acknowledgedForInvoiceSession: boolean,
): boolean {
  return mayUseBitcoinPaymentInstruction(mode, acknowledgedForInvoiceSession)
}

/**
 * Starts the invoice-local acknowledgement scope. The same invoice survives a
 * reload in this browser tab, while observing a new invoice retires any prior
 * acknowledgement so navigating back cannot revive stale consent.
 */
export function beginBitcoinRiskAcknowledgementScope(
  mode: PaymentSurfaceMode,
  invoiceId: string,
  storage: SessionStorageLike | undefined,
): boolean {
  if (mode !== 'pos' || !storage) return false
  try {
    const acknowledged = storage.getItem(POS_BITCOIN_ACKNOWLEDGEMENT_SESSION_KEY) === invoiceId
    if (!acknowledged) storage.removeItem(POS_BITCOIN_ACKNOWLEDGEMENT_SESSION_KEY)
    return acknowledged
  } catch {
    return false
  }
}

export function rememberBitcoinRiskAcknowledgement(
  mode: PaymentSurfaceMode,
  invoiceId: string,
  storage: SessionStorageLike | undefined,
): void {
  if (mode !== 'pos' || !storage) return
  try {
    storage.setItem(POS_BITCOIN_ACKNOWLEDGEMENT_SESSION_KEY, invoiceId)
  } catch {
    // Storage can be disabled in hardened/private browser contexts. The live
    // component still remembers the acknowledgement until it is unmounted.
  }
}

export function preferredInitialFiatQuoteRail(
  mode: PaymentSurfaceMode,
  acknowledgedForInvoiceSession: boolean,
  availability: QuoteRailAvailability,
): QuoteRail | null {
  if (availability.lightning) return 'lightning'
  if (availability.liquid) return 'liquid'
  if (
    availability.bitcoin &&
    mayRequestBitcoinQuote(mode, acknowledgedForInvoiceSession)
  ) return 'bitcoin'
  return null
}

export function preferredRailAfterBitcoinDecline<Rail extends string>(
  rails: readonly Rail[],
): Rail | undefined {
  return rails.find((rail) => rail === 'lightning') ?? rails.find((rail) => rail !== 'bitcoin')
}

export function nextDialogFocusIndex(
  currentIndex: number,
  controlCount: number,
  backwards: boolean,
): number {
  if (controlCount <= 0) return -1
  if (backwards) return currentIndex <= 0 ? controlCount - 1 : currentIndex - 1
  return currentIndex < 0 || currentIndex === controlCount - 1 ? 0 : currentIndex + 1
}

import type {
  FiatQuoteView,
  PayerDemandQuoteResponse,
  PayerQuoteRail,
  VersionedPayerInstruction,
} from '$lib/api/client'
import { liquidUri } from '$lib/payloads'

export type QuoteRefreshTrigger = 'initial' | 'reload' | 'tab' | 'timer' | 'manual'

export interface PayerQuoteRailSnapshot {
  readonly rail: PayerQuoteRail
  readonly quote: Readonly<FiatQuoteView>
  readonly instruction: Readonly<VersionedPayerInstruction>
}

type RailValues<T> = Readonly<Record<PayerQuoteRail, T>>

export interface PayerQuoteState {
  readonly quote: Readonly<FiatQuoteView> | null
  readonly rails: RailValues<PayerQuoteRailSnapshot | null>
  readonly pending: RailValues<boolean>
  readonly errors: RailValues<string | null>
  /** Monotonic lineage survives local expiry so a late response cannot
   * resurrect an already retired quote version. */
  readonly lastVersionNumber: number
  readonly lastQuoteVersionId: string | null
}

export interface QuoteRefreshResult {
  readonly ok: boolean
  readonly snapshot: PayerQuoteRailSnapshot | null
  readonly error: string | null
}

export interface QuoteRailPresentation {
  readonly quoteVersionId: string
  readonly versionNumber: number
  readonly rail: PayerQuoteRail
  readonly merchantAmountSat: number
  readonly payerAmountSat: number
  readonly swapCostSat: number
  readonly qrValue: string
  readonly copyValue: string
  readonly copyDisabled: false
  readonly expiresAtUnix: number
}

export interface QuoteAccessibilityState {
  readonly busy: boolean
  readonly copyDisabled: boolean
  readonly message: string
}

export interface LightningQuoteAuthority {
  readonly key: string
  readonly quoteVersionId: string
  readonly versionNumber: number
  readonly expiresAtUnix: number
  readonly bolt11: string
  readonly payerAmountSat: number
}

export type PayerQuoteFetcher = (
  rail: PayerQuoteRail,
  trigger: QuoteRefreshTrigger,
) => Promise<PayerDemandQuoteResponse>

const RAILS: readonly PayerQuoteRail[] = ['lightning', 'liquid', 'bitcoin']
export const PAYER_QUOTE_LIFETIME_SECONDS = 5 * 60

function railValues<T>(value: T): Record<PayerQuoteRail, T> {
  return { lightning: value, liquid: value, bitcoin: value }
}

function freezeState(state: {
  quote: Readonly<FiatQuoteView> | null
  rails: Record<PayerQuoteRail, PayerQuoteRailSnapshot | null>
  pending: Record<PayerQuoteRail, boolean>
  errors: Record<PayerQuoteRail, string | null>
  lastVersionNumber: number
  lastQuoteVersionId: string | null
}): PayerQuoteState {
  return Object.freeze({
    ...state,
    rails: Object.freeze(state.rails),
    pending: Object.freeze(state.pending),
    errors: Object.freeze(state.errors),
  })
}

export function emptyPayerQuoteState(): PayerQuoteState {
  return freezeState({
    quote: null,
    rails: railValues<PayerQuoteRailSnapshot | null>(null),
    pending: railValues(false),
    errors: railValues<string | null>(null),
    lastVersionNumber: 0,
    lastQuoteVersionId: null,
  })
}

function isSafePositiveInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0
}

function assertInstruction(
  rail: PayerQuoteRail,
  instruction: VersionedPayerInstruction,
): void {
  if (!isSafePositiveInteger(instruction.payer_amount_sat)) {
    throw new Error('quote instruction has an invalid payer amount')
  }
  if (rail === 'lightning') {
    if (
      instruction.kind !== 'lightning_boltz_reverse' ||
      !instruction.quote_offer_id ||
      !instruction.pr
    ) {
      throw new Error('quote instruction does not match the selected rail')
    }
    return
  }
  if (rail === 'liquid') {
    if (instruction.kind !== 'liquid_direct' || !instruction.address) {
      throw new Error('quote instruction does not match the selected rail')
    }
    return
  }
  if (
    instruction.kind !== 'bitcoin_boltz_chain' ||
    !instruction.quote_offer_id ||
    !instruction.address ||
    !instruction.bip21
  ) {
    throw new Error('quote instruction does not match the selected rail')
  }
}

function assertQuote(quote: FiatQuoteView, nowMs: number): void {
  if (
    !quote.quote_version_id ||
    !Number.isSafeInteger(quote.version_number) ||
    quote.version_number <= 0 ||
    !isSafePositiveInteger(quote.fiat_face_amount_minor) ||
    !isSafePositiveInteger(quote.fiat_target_amount_minor) ||
    quote.fiat_target_amount_minor > quote.fiat_face_amount_minor ||
    !quote.fiat_currency ||
    !isSafePositiveInteger(quote.rate_minor_per_btc) ||
    !quote.rate_source ||
    !Number.isSafeInteger(quote.rate_observed_at_unix) ||
    !Number.isSafeInteger(quote.rate_fetched_at_unix) ||
    !Number.isSafeInteger(quote.rate_fresh_until_unix) ||
    quote.rate_observed_at_unix >= quote.rate_fresh_until_unix ||
    quote.rate_fetched_at_unix >= quote.rate_fresh_until_unix ||
    !isSafePositiveInteger(quote.merchant_amount_sat) ||
    !Number.isSafeInteger(quote.created_at_unix) ||
    !Number.isSafeInteger(quote.expires_at_unix) ||
    quote.expires_at_unix <= quote.created_at_unix ||
    quote.expires_at_unix - quote.created_at_unix !== PAYER_QUOTE_LIFETIME_SECONDS ||
    nowMs >= quote.expires_at_unix * 1_000
  ) {
    throw new Error('quote response is incomplete or expired')
  }
}

function quoteFingerprint(quote: Readonly<FiatQuoteView>): string {
  return JSON.stringify([
    quote.quote_version_id,
    quote.version_number,
    quote.fiat_face_amount_minor,
    quote.fiat_target_amount_minor,
    quote.fiat_currency,
    quote.rate_minor_per_btc,
    quote.rate_source,
    quote.rate_observed_at_unix,
    quote.rate_fetched_at_unix,
    quote.rate_fresh_until_unix,
    quote.merchant_amount_sat,
    quote.created_at_unix,
    quote.expires_at_unix,
  ])
}

function snapshotFromResponse(
  invoiceId: string,
  rail: PayerQuoteRail,
  response: PayerDemandQuoteResponse,
  nowMs: number,
): PayerQuoteRailSnapshot {
  if (
    response.pricing_mode !== 'fiat_fixed' ||
    response.invoice_id !== invoiceId ||
    response.selected_rail !== rail
  ) {
    throw new Error('quote response identity does not match the request')
  }
  assertQuote(response.quote, nowMs)
  assertInstruction(rail, response.instruction)
  if (
    (rail === 'liquid' &&
      response.instruction.payer_amount_sat !== response.quote.merchant_amount_sat) ||
    (rail !== 'liquid' &&
      response.instruction.payer_amount_sat <= response.quote.merchant_amount_sat)
  ) {
    throw new Error('payer amount does not match the selected rail policy')
  }
  const quote = Object.freeze({ ...response.quote })
  const instruction = Object.freeze({ ...response.instruction }) as Readonly<VersionedPayerInstruction>
  return Object.freeze({ rail, quote, instruction })
}

export function quoteRemainingMs(state: PayerQuoteState, nowMs: number): number {
  return state.quote ? Math.max(0, state.quote.expires_at_unix * 1_000 - nowMs) : 0
}

export function formatQuoteCountdown(state: PayerQuoteState, nowMs: number): string {
  const seconds = Math.ceil(quoteRemainingMs(state, nowMs) / 1_000)
  const minutes = Math.floor(seconds / 60)
  return `${minutes}:${(seconds % 60).toString().padStart(2, '0')}`
}

export function activeQuoteSnapshot(
  state: PayerQuoteState,
  rail: PayerQuoteRail,
  nowMs: number,
): PayerQuoteRailSnapshot | null {
  if (!state.quote || nowMs >= state.quote.expires_at_unix * 1_000) return null
  const snapshot = state.rails[rail]
  if (!snapshot || snapshot.quote.quote_version_id !== state.quote.quote_version_id) return null
  return snapshot
}

export function quoteRailPresentation(
  state: PayerQuoteState,
  rail: PayerQuoteRail,
  nowMs: number,
  liquidAssetId: string,
): QuoteRailPresentation | null {
  const snapshot = activeQuoteSnapshot(state, rail, nowMs)
  if (!snapshot) return null
  const payerAmountSat = snapshot.instruction.payer_amount_sat
  const merchantAmountSat = snapshot.quote.merchant_amount_sat
  const swapCostSat = payerAmountSat - merchantAmountSat
  let qrValue: string
  if (snapshot.instruction.kind === 'lightning_boltz_reverse') {
    qrValue = snapshot.instruction.pr
  } else if (snapshot.instruction.kind === 'liquid_direct') {
    qrValue = liquidUri(snapshot.instruction.address, payerAmountSat, liquidAssetId)
  } else {
    // A chain offer's BIP21 is provider-bound evidence. Never synthesize it
    // from an address and amount on the client.
    qrValue = snapshot.instruction.bip21
  }
  return Object.freeze({
    quoteVersionId: snapshot.quote.quote_version_id,
    versionNumber: snapshot.quote.version_number,
    rail,
    merchantAmountSat,
    payerAmountSat,
    swapCostSat,
    qrValue,
    copyValue: qrValue,
    copyDisabled: false,
    expiresAtUnix: snapshot.quote.expires_at_unix,
  })
}

export function quoteAccessibilityState(
  state: PayerQuoteState,
  rail: PayerQuoteRail,
  nowMs: number,
): QuoteAccessibilityState {
  const usable = activeQuoteSnapshot(state, rail, nowMs) !== null
  const busy = state.pending[rail]
  if (usable) {
    return {
      busy,
      copyDisabled: false,
      message: busy ? `Refreshing ${rail} quote` : `${rail} quote ready`,
    }
  }
  if (busy) {
    return { busy: true, copyDisabled: true, message: `Refreshing ${rail} quote` }
  }
  if (state.errors[rail]) {
    return { busy: false, copyDisabled: true, message: `${rail} quote unavailable` }
  }
  return { busy: false, copyDisabled: true, message: `${rail} quote required` }
}

export function captureLightningQuoteAuthority(
  state: PayerQuoteState,
  nowMs: number,
): LightningQuoteAuthority | null {
  if (state.pending.lightning) return null
  const snapshot = activeQuoteSnapshot(state, 'lightning', nowMs)
  if (!snapshot || snapshot.instruction.kind !== 'lightning_boltz_reverse') return null
  const authority = {
    quoteVersionId: snapshot.quote.quote_version_id,
    versionNumber: snapshot.quote.version_number,
    expiresAtUnix: snapshot.quote.expires_at_unix,
    bolt11: snapshot.instruction.pr,
    payerAmountSat: snapshot.instruction.payer_amount_sat,
  }
  return Object.freeze({
    ...authority,
    key: [
      authority.quoteVersionId,
      authority.versionNumber,
      authority.expiresAtUnix,
      authority.bolt11,
      authority.payerAmountSat,
    ].join('\0'),
  })
}

export function assertLightningQuoteAuthorityCurrent(
  state: PayerQuoteState,
  authority: LightningQuoteAuthority,
  nowMs: number,
): void {
  const current = captureLightningQuoteAuthority(state, nowMs)
  if (!current || current.key !== authority.key) {
    throw new DOMException('Fiat Lightning quote expired or changed', 'AbortError')
  }
}

/**
 * Owns a single immutable quote lineage and its rail-bound instructions.
 * Same-rail triggers share one Promise; different rails remain independent.
 */
export class PayerQuoteCoordinator {
  private stateValue = emptyPayerQuoteState()
  private readonly inFlight = new Map<PayerQuoteRail, Promise<QuoteRefreshResult>>()

  constructor(
    private readonly invoiceId: string,
    private readonly fetcher: PayerQuoteFetcher,
    private readonly now: () => number = () => Date.now(),
    private readonly onChange: (state: PayerQuoteState) => void = () => undefined,
  ) {}

  get state(): PayerQuoteState {
    return this.stateValue
  }

  private publish(state: PayerQuoteState): void {
    this.stateValue = state
    this.onChange(state)
  }

  expire(nowMs = this.now()): boolean {
    const quote = this.stateValue.quote
    if (!quote || nowMs < quote.expires_at_unix * 1_000) return false
    this.publish(
      freezeState({
        ...this.stateValue,
        quote: null,
        rails: railValues<PayerQuoteRailSnapshot | null>(null),
        pending: { ...this.stateValue.pending },
        errors: { ...this.stateValue.errors },
      }),
    )
    return true
  }

  ensure(rail: PayerQuoteRail, trigger: QuoteRefreshTrigger): Promise<QuoteRefreshResult> {
    const snapshot = activeQuoteSnapshot(this.stateValue, rail, this.now())
    if (snapshot) {
      return Promise.resolve(Object.freeze({ ok: true, snapshot, error: null }))
    }
    return this.refresh(rail, trigger)
  }

  refresh(rail: PayerQuoteRail, trigger: QuoteRefreshTrigger): Promise<QuoteRefreshResult> {
    const current = this.inFlight.get(rail)
    if (current) return current

    this.expire(this.now())
    this.publish(
      freezeState({
        ...this.stateValue,
        rails: { ...this.stateValue.rails },
        pending: { ...this.stateValue.pending, [rail]: true },
        errors: { ...this.stateValue.errors, [rail]: null },
      }),
    )

    const request = this.fetcher(rail, trigger)
      .then((response): QuoteRefreshResult => {
        const snapshot = snapshotFromResponse(this.invoiceId, rail, response, this.now())
        const incoming = snapshot.quote
        const currentQuote = this.stateValue.quote

        if (!currentQuote) {
          if (
            incoming.version_number < this.stateValue.lastVersionNumber ||
            (incoming.version_number === this.stateValue.lastVersionNumber &&
              this.stateValue.lastQuoteVersionId !== null)
          ) {
            throw new Error('late quote response belongs to a retired version')
          }
        } else if (incoming.version_number < currentQuote.version_number) {
          throw new Error('late quote response is older than the active version')
        } else if (incoming.version_number === currentQuote.version_number) {
          if (
            incoming.quote_version_id !== currentQuote.quote_version_id ||
            quoteFingerprint(incoming) !== quoteFingerprint(currentQuote)
          ) {
            throw new Error('quote version identity changed in place')
          }
        }

        const replacesVersion =
          !currentQuote || incoming.version_number > currentQuote.version_number
        const rails = replacesVersion
          ? railValues<PayerQuoteRailSnapshot | null>(null)
          : { ...this.stateValue.rails }
        rails[rail] = snapshot
        this.publish(
          freezeState({
            quote: snapshot.quote,
            rails,
            pending: { ...this.stateValue.pending },
            errors: replacesVersion
              ? { ...railValues<string | null>(null), [rail]: null }
              : { ...this.stateValue.errors, [rail]: null },
            lastVersionNumber: incoming.version_number,
            lastQuoteVersionId: incoming.quote_version_id,
          }),
        )
        return Object.freeze({ ok: true, snapshot, error: null })
      })
      .catch((): QuoteRefreshResult => {
        const message = `Could not refresh the ${rail} quote.`
        this.publish(
          freezeState({
            ...this.stateValue,
            rails: { ...this.stateValue.rails },
            pending: { ...this.stateValue.pending },
            errors: { ...this.stateValue.errors, [rail]: message },
          }),
        )
        return Object.freeze({ ok: false, snapshot: null, error: message })
      })
      .finally(() => {
        this.inFlight.delete(rail)
        this.publish(
          freezeState({
            ...this.stateValue,
            rails: { ...this.stateValue.rails },
            pending: { ...this.stateValue.pending, [rail]: false },
            errors: { ...this.stateValue.errors },
          }),
        )
      })

    this.inFlight.set(rail, request)
    return request
  }
}

export function payerQuoteRails(): readonly PayerQuoteRail[] {
  return RAILS
}

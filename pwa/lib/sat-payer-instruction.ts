import type {
  PayerDemandQuoteResponse,
  PayerQuoteRail,
  SatFixedPayerDemandQuoteResponse,
  VersionedPayerInstruction,
} from '$lib/api/client'
import { liquidUri } from '$lib/payloads'
import type { QuoteRefreshTrigger } from '$lib/payer-quote'

type RailValues<T> = Readonly<Record<PayerQuoteRail, T>>

export interface SatPayerInstructionSnapshot {
  readonly rail: PayerQuoteRail
  readonly amountSat: number
  readonly invoiceExpiresAtUnix: number
  readonly instructionExpiresAtUnix: number | null
  readonly instruction: Readonly<VersionedPayerInstruction>
}

export interface SatPayerInstructionState {
  readonly amountSat: number | null
  readonly rails: RailValues<SatPayerInstructionSnapshot | null>
  readonly pending: RailValues<boolean>
  readonly errors: RailValues<string | null>
}

export interface SatPayerInstructionPresentation {
  readonly key: string
  readonly rail: PayerQuoteRail
  readonly merchantAmountSat: number
  readonly payerAmountSat: number
  readonly swapCostSat: number
  readonly qrValue: string
  readonly expiresAtUnix: number
}

export interface SatLightningAuthority {
  readonly key: string
  readonly bolt11: string
  readonly payerAmountSat: number
  readonly expiresAtUnix: number
}

export type SatPayerInstructionFetcher = (
  rail: PayerQuoteRail,
  trigger: QuoteRefreshTrigger,
) => Promise<PayerDemandQuoteResponse>

function railValues<T>(value: T): Record<PayerQuoteRail, T> {
  return { lightning: value, liquid: value, bitcoin: value }
}

function freezeState(state: {
  amountSat: number | null
  rails: Record<PayerQuoteRail, SatPayerInstructionSnapshot | null>
  pending: Record<PayerQuoteRail, boolean>
  errors: Record<PayerQuoteRail, string | null>
}): SatPayerInstructionState {
  return Object.freeze({
    ...state,
    rails: Object.freeze(state.rails),
    pending: Object.freeze(state.pending),
    errors: Object.freeze(state.errors),
  })
}

export function emptySatPayerInstructionState(): SatPayerInstructionState {
  return freezeState({
    amountSat: null,
    rails: railValues<SatPayerInstructionSnapshot | null>(null),
    pending: railValues(false),
    errors: railValues<string | null>(null),
  })
}

function isPositiveSafeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0
}

function instructionMatchesRail(
  rail: PayerQuoteRail,
  instruction: VersionedPayerInstruction,
): boolean {
  if (!isPositiveSafeInteger(instruction.payer_amount_sat)) return false
  if (rail === 'lightning') {
    return (
      (instruction.kind === 'lightning_boltz_reverse' ||
        instruction.kind === 'lightning_direct' ||
        instruction.kind === 'lightning_current') &&
      !!instruction.pr &&
      (instruction.kind !== 'lightning_boltz_reverse' || !!instruction.quote_offer_id)
    )
  }
  if (rail === 'liquid') {
    return instruction.kind === 'liquid_direct' && !!instruction.address
  }
  return (
    (instruction.kind === 'bitcoin_direct' ||
      instruction.kind === 'bitcoin_boltz_chain' ||
      instruction.kind === 'bitcoin_boltz_chain_current') &&
    !!instruction.address &&
    !!instruction.bip21 &&
    (instruction.kind !== 'bitcoin_boltz_chain' || !!instruction.quote_offer_id)
  )
}

function instructionFingerprint(instruction: Readonly<VersionedPayerInstruction>): string {
  return JSON.stringify(instruction)
}

function snapshotFromResponse(
  invoiceId: string,
  rail: PayerQuoteRail,
  expectedAmountSat: number,
  response: PayerDemandQuoteResponse,
  nowUnix: number,
): SatPayerInstructionSnapshot {
  if (
    response.pricing_mode !== 'sat_fixed' ||
    response.invoice_id !== invoiceId ||
    response.selected_rail !== rail ||
    response.amount_sat !== expectedAmountSat ||
    !isPositiveSafeInteger(response.amount_sat) ||
    !Number.isSafeInteger(response.expires_at_unix) ||
    response.expires_at_unix <= nowUnix ||
    !instructionMatchesRail(rail, response.instruction)
  ) {
    throw new Error('payer instruction identity does not match the request')
  }
  const instructionExpiry = response.instruction_expires_at_unix
  if (
    instructionExpiry !== null &&
    (!Number.isSafeInteger(instructionExpiry) || instructionExpiry <= nowUnix)
  ) {
    throw new Error('payer instruction is expired')
  }
  const direct =
    response.instruction.kind === 'lightning_direct' ||
    response.instruction.kind === 'liquid_direct' ||
    response.instruction.kind === 'bitcoin_direct'
  if (
    (direct && response.instruction.payer_amount_sat !== response.amount_sat) ||
    (!direct && response.instruction.payer_amount_sat < response.amount_sat)
  ) {
    throw new Error('payer amount does not match the settlement route')
  }
  return Object.freeze({
    rail,
    amountSat: response.amount_sat,
    invoiceExpiresAtUnix: response.expires_at_unix,
    instructionExpiresAtUnix: instructionExpiry,
    instruction: Object.freeze({ ...response.instruction }),
  })
}

function effectiveExpiry(snapshot: SatPayerInstructionSnapshot): number {
  return snapshot.instructionExpiresAtUnix === null
    ? snapshot.invoiceExpiresAtUnix
    : Math.min(snapshot.invoiceExpiresAtUnix, snapshot.instructionExpiresAtUnix)
}

export function activeSatPayerInstruction(
  state: SatPayerInstructionState,
  rail: PayerQuoteRail,
  nowMs: number,
): SatPayerInstructionSnapshot | null {
  const snapshot = state.rails[rail]
  if (
    !snapshot ||
    snapshot.amountSat !== state.amountSat ||
    nowMs >= effectiveExpiry(snapshot) * 1_000
  ) return null
  return snapshot
}

export function satPayerInstructionPresentation(
  state: SatPayerInstructionState,
  rail: PayerQuoteRail,
  nowMs: number,
  liquidAssetId: string,
): SatPayerInstructionPresentation | null {
  const snapshot = activeSatPayerInstruction(state, rail, nowMs)
  if (!snapshot) return null
  const instruction = snapshot.instruction
  const payerAmountSat = instruction.payer_amount_sat
  let qrValue: string
  if (
    instruction.kind === 'lightning_boltz_reverse' ||
    instruction.kind === 'lightning_direct' ||
    instruction.kind === 'lightning_current'
  ) {
    qrValue = instruction.pr
  } else if (instruction.kind === 'liquid_direct') {
    qrValue = liquidUri(instruction.address, payerAmountSat, liquidAssetId)
  } else if (
    instruction.kind === 'bitcoin_direct' ||
    instruction.kind === 'bitcoin_boltz_chain' ||
    instruction.kind === 'bitcoin_boltz_chain_current'
  ) {
    qrValue = instruction.bip21
  } else {
    return null
  }
  return Object.freeze({
    key: [rail, snapshot.amountSat, instructionFingerprint(instruction)].join('\0'),
    rail,
    merchantAmountSat: snapshot.amountSat,
    payerAmountSat,
    swapCostSat: payerAmountSat - snapshot.amountSat,
    qrValue,
    expiresAtUnix: effectiveExpiry(snapshot),
  })
}

export function satInstructionAccessibility(
  state: SatPayerInstructionState,
  rail: PayerQuoteRail,
  nowMs: number,
): { busy: boolean; error: boolean } {
  return {
    busy: state.pending[rail],
    error: activeSatPayerInstruction(state, rail, nowMs) === null && state.errors[rail] !== null,
  }
}

export function captureSatLightningAuthority(
  state: SatPayerInstructionState,
  nowMs: number,
): SatLightningAuthority | null {
  if (state.pending.lightning) return null
  const snapshot = activeSatPayerInstruction(state, 'lightning', nowMs)
  if (!snapshot) return null
  const instruction = snapshot.instruction
  if (
    instruction.kind !== 'lightning_boltz_reverse' &&
    instruction.kind !== 'lightning_direct' &&
    instruction.kind !== 'lightning_current'
  ) return null
  return Object.freeze({
    key: ['sat', snapshot.amountSat, instructionFingerprint(instruction)].join('\0'),
    bolt11: instruction.pr,
    payerAmountSat: instruction.payer_amount_sat,
    expiresAtUnix: effectiveExpiry(snapshot),
  })
}

export function assertSatLightningAuthorityCurrent(
  state: SatPayerInstructionState,
  authority: SatLightningAuthority,
  nowMs: number,
): void {
  const current = captureSatLightningAuthority(state, nowMs)
  if (!current || current.key !== authority.key) {
    throw new DOMException('Lightning instruction expired or changed', 'AbortError')
  }
}

export class SatPayerInstructionCoordinator {
  private stateValue = emptySatPayerInstructionState()
  private readonly inFlight = new Map<string, Promise<boolean>>()

  constructor(
    private readonly invoiceId: string,
    private readonly fetcher: SatPayerInstructionFetcher,
    private readonly now: () => number = () => Date.now(),
    private readonly onChange: (state: SatPayerInstructionState) => void = () => undefined,
  ) {}

  get state(): SatPayerInstructionState {
    return this.stateValue
  }

  private publish(state: SatPayerInstructionState): void {
    this.stateValue = state
    this.onChange(state)
  }

  setAmount(amountSat: number): void {
    if (!isPositiveSafeInteger(amountSat)) return
    if (this.stateValue.amountSat === amountSat) return
    this.publish(
      freezeState({
        amountSat,
        rails: railValues<SatPayerInstructionSnapshot | null>(null),
        pending: railValues(false),
        errors: railValues<string | null>(null),
      }),
    )
  }

  ensure(
    rail: PayerQuoteRail,
    amountSat: number,
    trigger: QuoteRefreshTrigger,
  ): Promise<boolean> {
    this.setAmount(amountSat)
    if (activeSatPayerInstruction(this.stateValue, rail, this.now())) {
      return Promise.resolve(true)
    }
    return this.refresh(rail, amountSat, trigger)
  }

  refresh(
    rail: PayerQuoteRail,
    amountSat: number,
    trigger: QuoteRefreshTrigger,
  ): Promise<boolean> {
    this.setAmount(amountSat)
    const requestIdentity = `${rail}:${amountSat}`
    const current = this.inFlight.get(requestIdentity)
    if (current) return current
    this.publish(
      freezeState({
        amountSat: this.stateValue.amountSat,
        rails: { ...this.stateValue.rails },
        pending: { ...this.stateValue.pending, [rail]: true },
        errors: { ...this.stateValue.errors, [rail]: null },
      }),
    )
    const request = this.fetcher(rail, trigger)
      .then((response) => {
        const snapshot = snapshotFromResponse(
          this.invoiceId,
          rail,
          amountSat,
          response,
          Math.floor(this.now() / 1_000),
        )
        if (this.stateValue.amountSat !== amountSat) return false
        const prior = this.stateValue.rails[rail]
        if (
          prior &&
          this.now() < effectiveExpiry(prior) * 1_000 &&
          instructionFingerprint(prior.instruction) !== instructionFingerprint(snapshot.instruction)
        ) {
          throw new Error('payer instruction changed before expiry')
        }
        this.publish(
          freezeState({
            amountSat,
            rails: { ...this.stateValue.rails, [rail]: snapshot },
            pending: { ...this.stateValue.pending },
            errors: { ...this.stateValue.errors, [rail]: null },
          }),
        )
        return true
      })
      .catch(() => {
        if (this.stateValue.amountSat === amountSat) {
          this.publish(
            freezeState({
              amountSat,
              rails: { ...this.stateValue.rails },
              pending: { ...this.stateValue.pending },
              errors: {
                ...this.stateValue.errors,
                [rail]: `Could not load the ${rail} instruction.`,
              },
            }),
          )
        }
        return false
      })
      .finally(() => {
        this.inFlight.delete(requestIdentity)
        if (this.stateValue.amountSat === amountSat) {
          this.publish(
            freezeState({
              amountSat,
              rails: { ...this.stateValue.rails },
              pending: { ...this.stateValue.pending, [rail]: false },
              errors: { ...this.stateValue.errors },
            }),
          )
        }
      })
    this.inFlight.set(requestIdentity, request)
    return request
  }
}

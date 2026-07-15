import { describe, expect, it } from 'vitest'
import {
  POS_BITCOIN_ACKNOWLEDGEMENT,
  POS_BITCOIN_ACKNOWLEDGEMENT_SESSION_KEY,
  POS_BITCOIN_RISK_COPY,
  beginBitcoinRiskAcknowledgementScope,
  bitcoinSelectionAction,
  mayRequestBitcoinQuote,
  mayUseBitcoinPaymentInstruction,
  nextDialogFocusIndex,
  preferredInitialFiatQuoteRail,
  preferredRailAfterBitcoinDecline,
  rememberBitcoinRiskAcknowledgement,
  requiresPosBitcoinAcknowledgement,
  type PaymentSurfaceMode,
  type SessionStorageLike,
} from './pos-bitcoin-risk'

class MemorySessionStorage implements SessionStorageLike {
  readonly values = new Map<string, string>()

  getItem(key: string): string | null {
    return this.values.get(key) ?? null
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value)
  }

  removeItem(key: string): void {
    this.values.delete(key)
  }
}

describe('PoS Bitcoin risk acknowledgement', () => {
  it('preserves the approved copy and action exactly', () => {
    expect(POS_BITCOIN_RISK_COPY).toBe(
      'For in-person payments, Lightning network is recommended. Bitcoin on-chain payments can be cancelled by the sender for up to a few hours, and should not be considered safe until confirmed.',
    )
    expect(POS_BITCOIN_ACKNOWLEDGEMENT).toBe('I understand')
  })

  it('allows neither a Bitcoin quote request nor payload before PoS acknowledgement', () => {
    expect(requiresPosBitcoinAcknowledgement('pos', false)).toBe(true)
    expect(bitcoinSelectionAction('pos', false)).toBe('acknowledge')
    expect(mayRequestBitcoinQuote('pos', false)).toBe(false)
    expect(mayUseBitcoinPaymentInstruction('pos', false)).toBe(false)
    expect(
      preferredInitialFiatQuoteRail('pos', false, {
        lightning: false,
        liquid: false,
        bitcoin: true,
      }),
    ).toBeNull()
  })

  it('allows the selected Bitcoin quote and payload immediately after acknowledgement', () => {
    const storage = new MemorySessionStorage()
    expect(beginBitcoinRiskAcknowledgementScope('pos', 'invoice-a', storage)).toBe(false)

    rememberBitcoinRiskAcknowledgement('pos', 'invoice-a', storage)

    expect(beginBitcoinRiskAcknowledgementScope('pos', 'invoice-a', storage)).toBe(true)
    expect(requiresPosBitcoinAcknowledgement('pos', true)).toBe(false)
    expect(bitcoinSelectionAction('pos', true)).toBe('allow')
    expect(mayRequestBitcoinQuote('pos', true)).toBe(true)
    expect(mayUseBitcoinPaymentInstruction('pos', true)).toBe(true)
    expect(
      preferredInitialFiatQuoteRail('pos', true, {
        lightning: false,
        liquid: false,
        bitcoin: true,
      }),
    ).toBe('bitcoin')
  })

  it('keeps non-Bitcoin fiat rails lazy-selected without opening the Bitcoin gate', () => {
    const availability = { lightning: true, liquid: true, bitcoin: true }
    expect(preferredInitialFiatQuoteRail('pos', false, availability)).toBe('lightning')
    expect(
      preferredInitialFiatQuoteRail('pos', false, {
        ...availability,
        lightning: false,
      }),
    ).toBe('liquid')
  })

  it('survives a same-invoice reload but resets irreversibly for a new invoice', () => {
    const storage = new MemorySessionStorage()
    rememberBitcoinRiskAcknowledgement('pos', 'invoice-a', storage)

    expect(beginBitcoinRiskAcknowledgementScope('pos', 'invoice-a', storage)).toBe(true)
    expect(beginBitcoinRiskAcknowledgementScope('pos', 'invoice-b', storage)).toBe(false)
    expect(storage.values.has(POS_BITCOIN_ACKNOWLEDGEMENT_SESSION_KEY)).toBe(false)
    expect(beginBitcoinRiskAcknowledgementScope('pos', 'invoice-a', storage)).toBe(false)
  })

  it('rejects a stale or malformed acknowledgement value', () => {
    const storage = new MemorySessionStorage()
    storage.setItem(POS_BITCOIN_ACKNOWLEDGEMENT_SESSION_KEY, 'stale-invoice')

    expect(beginBitcoinRiskAcknowledgementScope('pos', 'current-invoice', storage)).toBe(false)
    expect(storage.values.size).toBe(0)
  })

  it('is inaccessible to donation, Payment Page, ordinary invoice, and LNURL surfaces', () => {
    const storage = new MemorySessionStorage()
    const otherModes: PaymentSurfaceMode[] = ['donation', 'page', 'invoice', 'lnurl']

    for (const mode of otherModes) {
      expect(requiresPosBitcoinAcknowledgement(mode, false)).toBe(false)
      expect(bitcoinSelectionAction(mode, false)).toBe('allow')
      expect(mayRequestBitcoinQuote(mode, false)).toBe(true)
      expect(mayUseBitcoinPaymentInstruction(mode, false)).toBe(true)
      expect(beginBitcoinRiskAcknowledgementScope(mode, 'invoice-a', storage)).toBe(false)
      rememberBitcoinRiskAcknowledgement(mode, 'invoice-a', storage)
    }
    expect(storage.values.size).toBe(0)
  })

  it('declines to Lightning first, then another safe rail, without selecting Bitcoin', () => {
    expect(preferredRailAfterBitcoinDecline(['liquid', 'lightning', 'bitcoin'])).toBe('lightning')
    expect(preferredRailAfterBitcoinDecline(['liquid', 'bitcoin'])).toBe('liquid')
    expect(preferredRailAfterBitcoinDecline(['bitcoin'])).toBeUndefined()
  })

  it('contains keyboard focus inside both dialog controls in both directions', () => {
    expect(nextDialogFocusIndex(-1, 2, false)).toBe(0)
    expect(nextDialogFocusIndex(0, 2, false)).toBe(1)
    expect(nextDialogFocusIndex(1, 2, false)).toBe(0)
    expect(nextDialogFocusIndex(0, 2, true)).toBe(1)
    expect(nextDialogFocusIndex(1, 2, true)).toBe(0)
    expect(nextDialogFocusIndex(0, 0, false)).toBe(-1)
  })
})

// Ported verbatim from nostr-pos
// (~/apps/nostr-pos/apps/pos-pwa/src/lib/pos/amount-input.test.ts), plus
// added coverage for the '00' key (our addition — see amount-input.ts) and
// the maxDecimalDigits param (review item 7's BTC entry — see
// amount-input.ts).
//
// NOTE: every `.reduce(...)` below wraps applyAmountInput in an explicit
// 2-arg arrow (`(acc, k) => applyAmountInput(acc, k)`) rather than passing
// applyAmountInput directly as the reduce callback. Array.prototype.reduce
// invokes its callback as (accumulator, currentValue, currentIndex, array)
// — now that applyAmountInput takes an optional 3rd `maxDecimalDigits`
// param, passing it directly would silently feed the array INDEX in as
// maxDecimalDigits on every step (e.g. index 3 briefly allowing a 3rd cents
// digit). This bit us once already while wiring up BTC's 8dp entry; keep
// the wrapper so it can't come back.
import { describe, expect, it } from 'vitest'
import { applyAmountInput } from './amount-input'

function type(keys: string[], maxDecimalDigits?: number): string {
  return keys.reduce((acc, k) => applyAmountInput(acc, k, maxDecimalDigits), '')
}

describe('amount keypad input', () => {
  it('enters whole amounts without cents until decimal is pressed', () => {
    expect(type(['1', '2', '3'])).toBe('123')
  })

  it('starts cents entry with 0 when decimal is pressed first', () => {
    expect(applyAmountInput('', '.')).toBe('0.')
  })

  it('allows up to two cents digits after decimal', () => {
    expect(type(['1', '2', '.', '3', '4', '5'])).toBe('12.34')
  })

  it('keeps only one decimal point', () => {
    expect(type(['1', '.', '.', '2'])).toBe('1.2')
  })

  it('deletes across cents and decimal point', () => {
    expect(type(['1', '2', '.', '3', 'back', 'back', '4'])).toBe('124')
  })

  it('00 key appends two zeros for zero-decimal currency entry', () => {
    expect(type(['3', '00'])).toBe('300')
  })

  it('00 key on empty input strips leading zeros the same way whole-digit entry does', () => {
    expect(applyAmountInput('', '00')).toBe('0')
    expect(type(['00', '5'])).toBe('5')
  })

  it('00 key is a no-op once a decimal point is present (defensive — should never be reachable via the UI)', () => {
    expect(type(['1', '.', '00'])).toBe('1.')
  })

  it('maxDecimalDigits defaults to 2 (fiat cents) when omitted', () => {
    expect(type(['0', '.', '1', '2', '3', '4'])).toBe('0.12')
  })

  it('maxDecimalDigits=8 allows a full satoshi-precision BTC amount', () => {
    expect(type(['0', '.', '0', '0', '0', '0', '0', '5', '4', '6'], 8)).toBe('0.00000546')
  })

  it('maxDecimalDigits=8 still stops accepting digits past the 8th', () => {
    expect(type(['0', '.', '1', '2', '3', '4', '5', '6', '7', '8', '9'], 8)).toBe('0.12345678')
  })
})

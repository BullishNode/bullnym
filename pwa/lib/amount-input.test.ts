// Ported verbatim from nostr-pos
// (~/apps/nostr-pos/apps/pos-pwa/src/lib/pos/amount-input.test.ts), plus
// added coverage for the '00' key (our addition — see amount-input.ts).
import { describe, expect, it } from 'vitest'
import { applyAmountInput } from './amount-input'

describe('amount keypad input', () => {
  it('enters whole amounts without cents until decimal is pressed', () => {
    expect(['1', '2', '3'].reduce(applyAmountInput, '')).toBe('123')
  })

  it('starts cents entry with 0 when decimal is pressed first', () => {
    expect(applyAmountInput('', '.')).toBe('0.')
  })

  it('allows up to two cents digits after decimal', () => {
    const entered = ['1', '2', '.', '3', '4', '5'].reduce(applyAmountInput, '')
    expect(entered).toBe('12.34')
  })

  it('keeps only one decimal point', () => {
    expect(['1', '.', '.', '2'].reduce(applyAmountInput, '')).toBe('1.2')
  })

  it('deletes across cents and decimal point', () => {
    expect(['1', '2', '.', '3', 'back', 'back', '4'].reduce(applyAmountInput, '')).toBe('124')
  })

  it('00 key appends two zeros for zero-decimal currency entry', () => {
    expect(['3', '00'].reduce(applyAmountInput, '')).toBe('300')
  })

  it('00 key on empty input strips leading zeros the same way whole-digit entry does', () => {
    expect(applyAmountInput('', '00')).toBe('0')
    expect(['00', '5'].reduce(applyAmountInput, '')).toBe('5')
  })

  it('00 key is a no-op once a decimal point is present (defensive — should never be reachable via the UI)', () => {
    expect(['1', '.', '00'].reduce(applyAmountInput, '')).toBe('1.')
  })
})

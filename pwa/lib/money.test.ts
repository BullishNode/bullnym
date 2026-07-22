// Donation sat/BTC entry (review item 7): formatCryptoAmount is the
// dedicated path so 'sat'/'btc' never hit Intl.NumberFormat({style:
// 'currency'}), which throws on non-ISO codes; cryptoAmountSat owns the
// create-invoice unit -> amount_sat mapping.
import { describe, expect, it } from 'vitest'
import { formatCryptoAmount, cryptoAmountSat } from './money'

describe('formatCryptoAmount', () => {
  it('sat: grouped integer + " sat"', () => {
    expect(formatCryptoAmount('21000', 'sat')).toBe('21,000 sat')
    expect(formatCryptoAmount('0', 'sat')).toBe('0 sat')
    expect(formatCryptoAmount('', 'sat')).toBe('0 sat')
  })

  it('sat: truncates any stray fractional part rather than throwing', () => {
    expect(formatCryptoAmount('123.9', 'sat')).toBe('123 sat')
  })

  it('btc: echoes the typed amount (already capped at 8dp by amount-input.ts) + " BTC"', () => {
    expect(formatCryptoAmount('0.001', 'btc')).toBe('0.001 BTC')
    expect(formatCryptoAmount('0.00000546', 'btc')).toBe('0.00000546 BTC')
  })

  it('btc: does not pad short entries to a fixed 8dp', () => {
    expect(formatCryptoAmount('1', 'btc')).toBe('1 BTC')
  })

  it('btc: empty entry displays as 0 BTC', () => {
    expect(formatCryptoAmount('', 'btc')).toBe('0 BTC')
  })
})

describe('cryptoAmountSat', () => {
  it('sat rounds to the nearest whole sat', () => {
    expect(cryptoAmountSat(21000, 'sat')).toBe(21000)
    expect(cryptoAmountSat(21000.6, 'sat')).toBe(21001)
  })

  it('btc multiplies by 1e8 and rounds to the nearest sat', () => {
    expect(cryptoAmountSat(0.001, 'btc')).toBe(100_000)
    expect(cryptoAmountSat(0.00000546, 'btc')).toBe(546)
    expect(cryptoAmountSat(1, 'btc')).toBe(100_000_000)
  })
})

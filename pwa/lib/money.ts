// Currency formatting helpers. Amounts move through the API in minor
// units (i32 on the server), matching the pricer's per-currency precision.

/** Format minor units as a localized currency string, e.g. 850000/CRC → "₡8,500". */
export function formatFiat(minor: number, currency: string, precision: number): string {
  const major = minor / 10 ** precision
  try {
    return new Intl.NumberFormat(undefined, {
      style: 'currency',
      currency,
      minimumFractionDigits: precision,
      maximumFractionDigits: precision,
    }).format(major)
  } catch {
    // Unknown ISO code for Intl — fall back to plain grouping.
    return `${new Intl.NumberFormat(undefined, {
      minimumFractionDigits: precision,
      maximumFractionDigits: precision,
    }).format(major)} ${currency}`
  }
}

/** Format sats as a BTC string with 8 decimals, e.g. 10800 → "0.00010800 BTC". */
export function formatBtc(sats: number): string {
  return `${(sats / 1e8).toFixed(8)} BTC`
}

export function formatSats(sats: number): string {
  return `${new Intl.NumberFormat().format(sats)} sats`
}

/** Ported from nostr-pos's shortId (~/apps/nostr-pos/apps/pos-pwa/src/lib/util/formatting.ts). */
export function shortId(value?: string): string {
  if (!value) return 'Pending'
  if (value.length <= 12) return value
  return `${value.slice(0, 6)}...${value.slice(-6)}`
}

/** Format a rate (minor units per BTC) as e.g. "₡78,703,124/BTC". */
export function formatRate(minorPerBtc: number, currency: string, precision: number): string {
  return `${formatFiat(minorPerBtc, currency, precision)}/BTC`
}

/**
 * Ported from nostr-pos's formatFiat
 * (~/apps/nostr-pos/apps/pos-pwa/src/lib/util/formatting.ts) — operates on
 * a major-unit decimal string/number (the ported Keypad + applyAmountInput
 * produce these directly) rather than minor units, with cents shown only
 * once a decimal point has been typed. Named differently from formatFiat
 * above to avoid colliding with the minor-unit version still used by
 * receipts/history/rate display.
 *
 * Deviation from upstream: takes `precision` instead of hardcoding
 * `currency === 'CRC' ? 0 : 2`. Upstream's currency-name special case only
 * covers its one hardcoded zero-decimal currency; ours resolves precision
 * from the real supported-currencies list, so any zero-decimal currency
 * displays correctly, and a stray '.' can never force 2 decimals onto a
 * precision-0 currency (which is exactly what produced "CRC 11.00").
 */
export function formatFiatAmount(amount: string | number, currency: string, precision: number, showCents = false): string {
  const value = typeof amount === 'string' ? Number(amount) : amount
  const digits = precision === 0 ? 0 : showCents ? 2 : 0
  try {
    return new Intl.NumberFormat(undefined, {
      style: 'currency',
      currency,
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    }).format(value)
  } catch {
    // Unknown ISO code for Intl — fall back to plain grouping.
    return `${new Intl.NumberFormat(undefined, { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(value)} ${currency}`
  }
}

/**
 * Donation sat/BTC entry (review item 7): 'sat' and 'btc' are NOT ISO
 * currency codes, so `Intl.NumberFormat({style:'currency', currency})`
 * throws for them — formatFiatAmount above can never be used for a crypto
 * unit. This is the dedicated crypto-format path for the entry amount
 * string as the Keypad produces it (see lib/amount-input.ts): sat is a
 * grouped integer, btc is echoed as typed (amount-input.ts already caps
 * entry at 8 decimal places for a precision-8 unit) — no reformatting to a
 * fixed 8dp, so "0.001" stays "0.001 BTC" rather than padding to
 * "0.00100000 BTC".
 */
export function formatCryptoAmount(amount: string, unit: 'sat' | 'btc'): string {
  if (unit === 'sat') {
    return `${new Intl.NumberFormat().format(Math.trunc(Number(amount || '0')))} sat`
  }
  return `${amount || '0'} BTC`
}

/**
 * Maps a donation entry amount (in the unit's own major denomination) to
 * sats for the create-invoice request body: sat rounds to the nearest whole
 * sat (no fractional sat), while btc multiplies by 1e8 then rounds.
 */
export function cryptoAmountSat(value: number, unit: 'sat' | 'btc'): number {
  return unit === 'sat' ? Math.round(value) : Math.round(value * 1e8)
}

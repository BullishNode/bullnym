// Ported from nostr-pos
// (~/apps/nostr-pos/apps/pos-pwa/src/lib/pos/amount-input.ts). Governs the
// decimal-string amount state driven by the ported Keypad component.
// Conversion to fiat minor units (per currency precision) happens at the
// call site, not here — this module only knows about typed characters.
//
// Deviation from upstream: added a '00' key handler. Upstream's Keypad
// always shows a '.' key regardless of currency (their terminal is
// CRC-only in practice but never gates entry), which — combined with
// formatFiatAmount always showing 2 decimals once a '.' is typed — lets a
// cashier type "11." on CRC (precision 0) and see "CRC 11.00" ($0.01
// increments on a currency with no cents). We instead gate the Keypad's
// bottom-left key by the resolved currency precision (see
// lib/components/Keypad.svelte): '.' for precision > 0, '00' for
// precision === 0. This '00' branch is the input-side half of that fix.

const maxWholeDigits = 9
const defaultMaxDecimalDigits = 2

/**
 * `maxDecimalDigits` defaults to 2 (fiat cents) for every existing caller.
 * Added so the donation sat/BTC entry (review item 7,
 * apps/donation/App.svelte) can pass 8 for a BTC unit — BTC amounts need up
 * to 8 decimal places (1 sat = 0.00000001 BTC), which the old hardcoded cap
 * of 2 made impossible to type. Sat entry never reaches the decimal branch
 * at all (its Keypad shows '00', not '.' — see Keypad.svelte's
 * precision-gated bottomLeft key), so this only actually changes behavior
 * for the BTC unit.
 */
export function applyAmountInput(current: string, key: string, maxDecimalDigits = defaultMaxDecimalDigits): string {
  if (key === 'back') return current.slice(0, -1)
  if (key === '.') {
    if (current.includes('.')) return current
    return current ? `${current}.` : '0.'
  }
  if (key === '00') {
    // Only ever shown for precision-0 currencies, so `current` should
    // never contain a decimal point — but guard defensively anyway.
    if (current.includes('.')) return current
    const next = `${current || '0'}00`.replace(/^0+(?=\d)/, '')
    return next.length > maxWholeDigits ? current : next
  }
  if (!/^\d$/.test(key)) return current

  const [whole, cents] = current.split('.')
  if (cents !== undefined) {
    if (cents.length >= maxDecimalDigits) return current
    return `${whole}.${cents}${key}`
  }

  const next = `${current}${key}`.replace(/^0+(?=\d)/, '')
  return next.length > maxWholeDigits ? current : next
}

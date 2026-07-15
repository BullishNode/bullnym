// Bolt Card (Web NFC, Android Chrome only). No new dependency: bech32 decoding
// is self-contained in ./bech32.ts.

import { decodeBech32ToString } from './bech32'

export interface WithdrawParams {
  tag: string
  callback: string
  k1: string
  /** Millisatoshis, per LNURL-withdraw spec — NOT sats. */
  minWithdrawable: number
  /** Millisatoshis, per LNURL-withdraw spec — NOT sats. */
  maxWithdrawable: number
  defaultDescription?: string
}

/** Decodes bech32 `lnurl1...`, `lightning:lnurl1...`, `lnurlw://...`, or a plain https(s):// URL into an HTTPS URL. */
export function decodeLnurl(raw: string): string {
  const trimmed = raw.trim()
  const lower = trimmed.toLowerCase()

  if (lower.startsWith('lightning:')) {
    return decodeLnurl(trimmed.slice('lightning:'.length))
  }
  if (lower.startsWith('lnurl1')) {
    const decoded = decodeBech32ToString(trimmed)
    if (!/^https?:\/\//i.test(decoded)) throw new Error('Decoded LNURL is not a URL')
    return decoded
  }
  if (lower.startsWith('lnurlw://')) {
    return 'https://' + trimmed.slice('lnurlw://'.length)
  }
  if (lower.startsWith('https://') || lower.startsWith('http://')) {
    return trimmed
  }
  throw new Error('Unrecognized LNURL format on tag')
}

/**
 * Scans for an NFC tag and resolves with the raw URL/LNURL string found in
 * its first `url` NDEF record. Rejects with an AbortError if `signal` fires
 * before a tag is read — callers MUST abort this when switching away from
 * the Tap Card tab, unmounting, or on invoice expiry, per the plan doc's
 * "never leave a scan running in background" rule.
 */
export function scanForLnurl(signal: AbortSignal): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!('NDEFReader' in window)) {
      reject(new Error('Web NFC is not supported on this device'))
      return
    }
    if (signal.aborted) {
      reject(new DOMException('Aborted', 'AbortError'))
      return
    }

    const ndef = new NDEFReader()

    const onAbort = () => {
      reject(new DOMException('Aborted', 'AbortError'))
    }
    signal.addEventListener('abort', onAbort, { once: true })

    ndef
      .scan({ signal })
      .then(() => {
        ndef.onreading = (event) => {
          for (const record of event.message.records) {
            if (record.recordType === 'url' && record.data) {
              const url = new TextDecoder().decode(record.data)
              signal.removeEventListener('abort', onAbort)
              resolve(url)
              return
            }
          }
          signal.removeEventListener('abort', onAbort)
          reject(new Error('No URL record found on tag'))
        }
        ndef.onreadingerror = () => {
          signal.removeEventListener('abort', onAbort)
          reject(new Error('Failed to read NFC tag'))
        }
      })
      .catch((err) => {
        signal.removeEventListener('abort', onAbort)
        reject(err instanceof Error ? err : new Error('Failed to start NFC scan'))
      })
  })
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')
}

export async function fetchWithdrawParams(
  lnurlOrUrl: string,
  signal?: AbortSignal,
): Promise<WithdrawParams> {
  throwIfAborted(signal)
  const url = decodeLnurl(lnurlOrUrl)
  const res = await fetch(url, { signal })
  throwIfAborted(signal)
  if (!res.ok) throw new Error('Failed to reach card service')
  const params = (await res.json()) as Partial<WithdrawParams> & { reason?: string }
  throwIfAborted(signal)
  if (params.tag !== 'withdrawRequest') {
    throw new Error(params.reason ?? 'Tag is not a withdraw request')
  }
  return params as WithdrawParams
}

/** Sale amount is in sats; withdraw limits are in millisats — convert before comparing. */
export function assertAmountWithinRange(amountSat: number, params: WithdrawParams): void {
  const amountMillisat = amountSat * 1000
  if (amountMillisat < params.minWithdrawable || amountMillisat > params.maxWithdrawable) {
    throw new Error('This amount is outside the card’s withdraw limits')
  }
}

export async function submitWithdraw(
  params: WithdrawParams,
  bolt11: string,
  signal?: AbortSignal,
): Promise<void> {
  throwIfAborted(signal)
  const callbackUrl = new URL(params.callback)
  callbackUrl.searchParams.set('k1', params.k1)
  callbackUrl.searchParams.set('pr', bolt11)

  const res = await fetch(callbackUrl.toString(), { signal })
  throwIfAborted(signal)
  if (!res.ok) throw new Error('Card service request failed')
  const result = (await res.json()) as { status: string; reason?: string }
  if (result.status !== 'OK') throw new Error(result.reason ?? 'Card declined')
}

/**
 * Full withdraw flow for an already-scanned tag: fetch withdraw params,
 * validate the amount fits the card's limits, submit the invoice. Success
 * is NOT detected here — the caller's existing invoice-status poller picks
 * up the resulting Lightning payment.
 */
export async function payViaBoltCard(
  lnurlOrUrl: string,
  bolt11: string,
  amountSat: number,
  authority: {
    signal?: AbortSignal
    /** Revalidates the exact caller-owned payment instruction. It is called
     * after every remote await and immediately before callback submission. */
    assertCurrent?: () => void
  } = {},
): Promise<void> {
  authority.assertCurrent?.()
  const params = await fetchWithdrawParams(lnurlOrUrl, authority.signal)
  authority.assertCurrent?.()
  assertAmountWithinRange(amountSat, params)
  authority.assertCurrent?.()
  await submitWithdraw(params, bolt11, authority.signal)
}

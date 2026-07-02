# Bolt Card / NFC Tap-to-Pay

POS mode only. Shown as a third tab ("Tap Card") on the payment screen when:
- `navigator.nfc` is available (Android Chrome only)
- Bolt Card is not disabled in settings

## Flow

```
1. Cashier selects "Tap Card" tab
2. Screen shows: "Hold card near back of device"
3. Web NFC reader activated (navigator.nfc.NDEFReader.scan())
4. Customer taps Bolt Card
5. PWA reads NDEF message, extracts LNURL-withdraw URL
6. PWA decodes LNURL (bech32 or plain URL starting with lnurl:)
7. GET {lnurl_url} → { tag: "withdrawRequest", callback, k1,
                        minWithdrawable, maxWithdrawable, defaultDescription }
8. Verify sale amount is within [minWithdrawable, maxWithdrawable]
9. GET {callback}?k1={k1}&pr={invoice.ln_offer}
10. Card service pays the Lightning invoice
11. Boltz detects payment → creates lockup tx → claimer claims L-BTC
12. Status polling detects paid → success screen
```

## Implementation

```ts
// lib/bolt-card/reader.ts

export async function readBoltCard(): Promise<string> {
  const ndef = new NDEFReader()
  return new Promise((resolve, reject) => {
    ndef.scan().then(() => {
      ndef.onreading = (event) => {
        for (const record of event.message.records) {
          if (record.recordType === 'url') {
            const url = new TextDecoder().decode(record.data)
            resolve(url)
            return
          }
        }
        reject(new Error('No URL record in NFC tag'))
      }
      ndef.onerror = reject
    }).catch(reject)
  })
}

export async function payViaBoltCard(lnurlUrl: string, bolt11: string): Promise<void> {
  // Decode bech32 LNURL if needed
  const url = decodeLnurl(lnurlUrl)

  // Fetch withdraw parameters
  const params = await fetch(url).then(r => r.json())
  if (params.tag !== 'withdrawRequest') throw new Error('Not a withdraw request')

  // Submit invoice to card service
  const callbackUrl = new URL(params.callback)
  callbackUrl.searchParams.set('k1', params.k1)
  callbackUrl.searchParams.set('pr', bolt11)

  const result = await fetch(callbackUrl.toString()).then(r => r.json())
  if (result.status !== 'OK') throw new Error(result.reason ?? 'Card declined')
}
```

## UI states

```
[Tap Card tab selected]
  → "Hold card near the back of this device."
  → [small NFC ring animation]

[Card detected]
  → "Card detected — requesting payment..."
  → [spinner]

[Payment sent to card service]
  → "Payment sent. Waiting for confirmation..."
  → [same status polling as Lightning tab]

[Card declined]
  → "Card declined. Try Lightning or Liquid."
  → [tabs still available]

[NFC not supported]
  → Tab hidden entirely
```

## Invoice requirement for Bolt Card

Bolt Card uses the same Lightning invoice (`ln_offer` Bolt11) that's already in the
invoice response. No additional server endpoint needed. The PWA just needs the Bolt11
to be present — which it will be if Lightning is enabled for the nym.

## Abort / timeout

If the NFC reader is active and the cashier switches to another tab (Lightning/Liquid),
call `ndef.abort()` to stop scanning. Don't leave an active NFC reader running in the
background.

Invoice expiry still applies. If the invoice expires while waiting for a card tap,
show the expired state and disable NFC.

## Platform notes

- Android Chrome: full support
- iOS: Web NFC unavailable. Tab hidden. Customers fall through to QR.
- Desktop: Web NFC unavailable. Tab hidden.
- Chromium flags: `chrome://flags/#enable-web-nfc` — should be on by default in
  recent Chrome for Android.

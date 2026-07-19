import { describe, expect, it } from 'vitest'
import { paymentQrDataUrl } from './invoiceQr'

describe('paymentQrDataUrl', () => {
  it('renders payment data to a local image data URL', async () => {
    const result = await paymentQrDataUrl('lnbc1-private-payment-payload')

    expect(result).toMatch(/^data:image\/png;base64,/)
  })

  it('rejects an empty payload', async () => {
    await expect(paymentQrDataUrl('')).rejects.toThrow('payment QR payload is empty')
  })
})

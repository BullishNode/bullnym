import QRCode from 'qrcode'

/** Render a payment payload entirely in the payer's browser. */
export function paymentQrDataUrl(payload: string): Promise<string> {
  if (!payload) return Promise.reject(new Error('payment QR payload is empty'))

  return QRCode.toDataURL(payload, {
    width: 256,
    margin: 4,
    errorCorrectionLevel: 'M',
    color: {
      dark: '#0E0E0EFF',
      light: '#F5F5F5FF',
    },
  })
}

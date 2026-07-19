import { afterEach, describe, expect, it, vi } from 'vitest'
import interoperabilityFixture from '../../tests/fixtures/private_invoice_v1.json'
import {
  decryptPrivateInvoicePresentation,
  parsePrivateInvoiceFragment,
  startPrivateInvoicePresentation,
  validatePrivateInvoicePresentation,
} from './privateInvoice'

const encoder = new TextEncoder()
const aad = encoder.encode('bullnym-private-invoice-presentation-v1')

function base64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

async function encryptedFixture(): Promise<{
  envelope: string
  key: string
}> {
  const key = Uint8Array.from({ length: 32 }, (_, index) => index)
  const nonce = Uint8Array.from({ length: 12 }, (_, index) => 0xa0 + index)
  const presentation = {
    schema: 'bullnym-private-invoice',
    version: 1,
    payer: {
      name: 'Jane Smith',
      corporate_name: 'Example Corporation',
      address: '123 Main Street\nMontréal, QC',
      email: 'jane@example.com',
      phone: '+1 514 555 0100',
    },
    invoice: {
      description: 'Website design services',
      number: 'INV-2026-0042',
      purchase_order_reference: 'PO-9182',
      invoice_date: '2026-07-18',
      payment_deadline: '2026-08-18',
    },
    payee: {
      name: 'John Merchant',
      corporate_name: 'Merchant Studio Inc.',
    },
  }
  const json = encoder.encode(JSON.stringify(presentation))
  const padded = new Uint8Array(4_096)
  padded[0] = json.length >> 8
  padded[1] = json.length & 0xff
  padded.set(json, 2)
  const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt'])
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
      cryptoKey,
      padded,
    ),
  )
  const envelope = new Uint8Array(1 + nonce.length + ciphertext.length)
  envelope[0] = 1
  envelope.set(nonce, 1)
  envelope.set(ciphertext, 1 + nonce.length)
  return { envelope: base64Url(envelope), key: base64Url(key) }
}

describe('private-invoice-v1', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('parses only canonical 32-byte view-key fragments', () => {
    const key = base64Url(Uint8Array.from({ length: 32 }, (_, index) => index))
    expect(parsePrivateInvoiceFragment(`#v1.${key}`)).toBe(key)
    expect(() => parsePrivateInvoiceFragment(`#v2.${key}`)).toThrow()
    expect(() => parsePrivateInvoiceFragment('#v1.AQAA')).toThrow()
    expect(() => parsePrivateInvoiceFragment(`#v1.${key}=`)).toThrow()
  })

  it('decrypts and validates every optional presentation section', async () => {
    const fixture = await encryptedFixture()
    expect(fixture.key).toBe(interoperabilityFixture.view_key_base64url)
    expect(fixture.envelope).toBe(
      interoperabilityFixture.presentation_envelope_base64url,
    )
    const presentation = await decryptPrivateInvoicePresentation(
      interoperabilityFixture.presentation_envelope_base64url,
      interoperabilityFixture.view_key_base64url,
    )

    expect(presentation.payer?.name).toBe('Jane Smith')
    expect(presentation.payer?.address).toContain('Montréal')
    expect(presentation.invoice?.number).toBe('INV-2026-0042')
    expect(presentation.invoice?.payment_deadline).toBe('2026-08-18')
    expect(presentation.payee?.corporate_name).toBe('Merchant Studio Inc.')
  })

  it('rejects tampered authenticated ciphertext', async () => {
    const fixture = await encryptedFixture()
    const raw = Uint8Array.from(
      atob(fixture.envelope.replaceAll('-', '+').replaceAll('_', '/')),
      (character) => character.charCodeAt(0),
    )
    raw[raw.length - 1] = raw[raw.length - 1]! ^ 1

    await expect(
      decryptPrivateInvoicePresentation(base64Url(raw), fixture.key),
    ).rejects.toThrow()
  })

  it('does not replace a known-good session key with an unauthenticated fragment key', async () => {
    const fixture = await encryptedFixture()
    const wrongKey = base64Url(Uint8Array.from({ length: 32 }, (_, index) => index + 1))
    const stored = new Map([['bullnym-private-invoice:v1:invoice-id', fixture.key]])
    const warning = { hidden: true }
    const container = {}

    vi.stubGlobal('location', {
      hash: `#v1.${wrongKey}`,
      origin: 'https://pay.example',
      pathname: '/invoice/invoice-id',
      search: '',
    })
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('sessionStorage', {
      getItem: (key: string) => stored.get(key) ?? null,
      setItem: (key: string, value: string) => stored.set(key, value),
    })
    vi.stubGlobal('document', {
      getElementById: (id: string) => {
        if (id === 'private-invoice-presentation') return container
        if (id === 'private-invoice-warning') return warning
        return null
      },
    })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ presentation_envelope: fixture.envelope }),
    }))

    await startPrivateInvoicePresentation('invoice-id')

    expect(stored.get('bullnym-private-invoice:v1:invoice-id')).toBe(fixture.key)
    expect(warning.hidden).toBe(false)
  })

  it('accepts an empty optional presentation and rejects unknown fields', () => {
    expect(
      validatePrivateInvoicePresentation({
        schema: 'bullnym-private-invoice',
        version: 1,
      }),
    ).toEqual({
      schema: 'bullnym-private-invoice',
      version: 1,
      payer: undefined,
      invoice: undefined,
      payee: undefined,
    })

    expect(() =>
      validatePrivateInvoicePresentation({
        schema: 'bullnym-private-invoice',
        version: 1,
        payer: { name: 'Jane', tax_identifier: 'secret' },
      }),
    ).toThrow('invalid private invoice field')
    expect(() =>
      validatePrivateInvoicePresentation({
        schema: 'bullnym-private-invoice',
        version: 1,
        invoice: { payment_deadline: '2026-02-30' },
      }),
    ).toThrow('invalid private invoice date')
    expect(() =>
      validatePrivateInvoicePresentation({
        schema: 'bullnym-private-invoice',
        version: 1,
        payee: { name: '   ' },
      }),
    ).toThrow('invalid private invoice field')
  })
})

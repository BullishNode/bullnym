const PRESENTATION_SCHEMA = 'bullnym-private-invoice'
const PRESENTATION_VERSION = 1
const ENVELOPE_BYTES = 4_125
const PADDED_PLAINTEXT_BYTES = 4_096
const VIEW_KEY_BYTES = 32
const NONCE_BYTES = 12
const AAD = new TextEncoder().encode('bullnym-private-invoice-presentation-v1')

type FieldRule = { maxBytes: number; date?: true }

const PAYER_FIELDS = {
  name: { maxBytes: 120 },
  corporate_name: { maxBytes: 160 },
  address: { maxBytes: 500 },
  email: { maxBytes: 254 },
  phone: { maxBytes: 64 },
} as const satisfies Record<string, FieldRule>

const INVOICE_FIELDS = {
  description: { maxBytes: 1_000 },
  number: { maxBytes: 128 },
  purchase_order_reference: { maxBytes: 128 },
  invoice_date: { maxBytes: 10, date: true },
  payment_deadline: { maxBytes: 10, date: true },
} as const satisfies Record<string, FieldRule>

const PAYEE_FIELDS = PAYER_FIELDS

type ContactSection = Partial<Record<keyof typeof PAYER_FIELDS, string>>
type InvoiceSection = Partial<Record<keyof typeof INVOICE_FIELDS, string>>

export interface PrivateInvoicePresentation {
  schema: typeof PRESENTATION_SCHEMA
  version: typeof PRESENTATION_VERSION
  payer?: ContactSection
  invoice?: InvoiceSection
  payee?: ContactSection
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function decodeBase64Url(value: string, expectedBytes: number): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid base64url')
  const padding = '='.repeat((4 - (value.length % 4)) % 4)
  let binary: string
  try {
    binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding)
  } catch {
    throw new Error('invalid base64url')
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  if (bytes.length !== expectedBytes || encodeBase64Url(bytes) !== value) {
    throw new Error('non-canonical base64url')
  }
  return bytes
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

export function parsePrivateInvoiceFragment(fragment: string): string {
  const match = /^#v1\.([A-Za-z0-9_-]{43})$/.exec(fragment)
  if (!match) throw new Error('invalid private invoice fragment')
  const encodedKey = match[1]!
  decodeBase64Url(encodedKey, VIEW_KEY_BYTES)
  return encodedKey
}

function validateDateOnly(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value)
  if (!match) return false
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const date = new Date(Date.UTC(year, month - 1, day))
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  )
}

function validateSection(
  value: unknown,
  rules: Record<string, FieldRule>,
): Record<string, string> | undefined {
  if (value === undefined) return undefined
  if (!isRecord(value)) throw new Error('invalid private invoice section')
  const result: Record<string, string> = {}
  for (const [key, field] of Object.entries(value)) {
    const rule = rules[key]
    if (!rule || typeof field !== 'string' || field.trim().length === 0) {
      throw new Error('invalid private invoice field')
    }
    if (new TextEncoder().encode(field).length > rule.maxBytes) {
      throw new Error('private invoice field is too long')
    }
    if (rule.date && !validateDateOnly(field)) {
      throw new Error('invalid private invoice date')
    }
    result[key] = field
  }
  return Object.keys(result).length > 0 ? result : undefined
}

export function validatePrivateInvoicePresentation(
  value: unknown,
): PrivateInvoicePresentation {
  if (!isRecord(value)) throw new Error('invalid private invoice presentation')
  const allowed = new Set(['schema', 'version', 'payer', 'invoice', 'payee'])
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error('unknown private invoice field')
  }
  if (value.schema !== PRESENTATION_SCHEMA || value.version !== PRESENTATION_VERSION) {
    throw new Error('unsupported private invoice presentation')
  }
  return {
    schema: PRESENTATION_SCHEMA,
    version: PRESENTATION_VERSION,
    payer: validateSection(value.payer, PAYER_FIELDS) as ContactSection | undefined,
    invoice: validateSection(value.invoice, INVOICE_FIELDS) as InvoiceSection | undefined,
    payee: validateSection(value.payee, PAYEE_FIELDS) as ContactSection | undefined,
  }
}

export async function decryptPrivateInvoicePresentation(
  envelopeBase64Url: string,
  viewKeyBase64Url: string,
): Promise<PrivateInvoicePresentation> {
  const envelope = decodeBase64Url(envelopeBase64Url, ENVELOPE_BYTES)
  if (envelope[0] !== PRESENTATION_VERSION) throw new Error('unsupported envelope version')
  const viewKey = decodeBase64Url(viewKeyBase64Url, VIEW_KEY_BYTES)
  const nonce = envelope.slice(1, 1 + NONCE_BYTES)
  const ciphertext = envelope.slice(1 + NONCE_BYTES)
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    viewKey.buffer as ArrayBuffer,
    'AES-GCM',
    false,
    ['decrypt'],
  )
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce.buffer as ArrayBuffer,
        additionalData: AAD.buffer as ArrayBuffer,
        tagLength: 128,
      },
      cryptoKey,
      ciphertext.buffer as ArrayBuffer,
    ),
  )
  if (plaintext.length !== PADDED_PLAINTEXT_BYTES) throw new Error('invalid plaintext size')
  const jsonLength = (plaintext[0]! << 8) | plaintext[1]!
  if (jsonLength === 0 || jsonLength > PADDED_PLAINTEXT_BYTES - 2) {
    throw new Error('invalid private invoice JSON length')
  }
  const jsonBytes = plaintext.slice(2, 2 + jsonLength)
  const json = new TextDecoder('utf-8', { fatal: true }).decode(jsonBytes)
  return validatePrivateInvoicePresentation(JSON.parse(json) as unknown)
}

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text !== undefined) node.textContent = text
  return node
}

function localizedDate(value: string): string {
  const parts = value.split('-')
  const year = Number(parts[0]!)
  const month = Number(parts[1]!)
  const day = Number(parts[2]!)
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeZone: 'UTC',
  }).format(new Date(Date.UTC(year, month - 1, day)))
}

function addDetail(parent: HTMLElement, label: string, value: string): void {
  const row = element('div', 'invoice-detail')
  row.append(element('dt', 'invoice-detail-label', label))
  row.append(element('dd', 'invoice-detail-value', value))
  parent.append(row)
}

function contactCard(title: string, section: ContactSection): HTMLElement {
  const card = element('section', 'invoice-party')
  card.append(element('h3', 'invoice-section-title', title))
  const details = element('dl', 'invoice-detail-list')
  if (section.name) addDetail(details, 'Name', section.name)
  if (section.corporate_name) addDetail(details, 'Corporate name', section.corporate_name)
  if (section.address) addDetail(details, 'Address', section.address)
  if (section.email) addDetail(details, 'Email', section.email)
  if (section.phone) addDetail(details, 'Phone', section.phone)
  card.append(details)
  return card
}

function renderPresentation(container: HTMLElement, presentation: PrivateInvoicePresentation): void {
  container.replaceChildren()
  const header = element('header', 'invoice-document-header')
  const heading = element('div')
  heading.append(element('p', 'invoice-eyebrow', 'Private payment request'))
  heading.append(element('h2', 'invoice-document-title', 'Invoice'))
  header.append(heading)

  const invoice = presentation.invoice
  if (invoice?.number) header.append(element('div', 'invoice-number', `#${invoice.number}`))
  container.append(header)

  if (invoice && (invoice.invoice_date || invoice.payment_deadline)) {
    const dates = element('dl', 'invoice-date-grid')
    if (invoice.invoice_date) addDetail(dates, 'Invoice date', localizedDate(invoice.invoice_date))
    if (invoice.payment_deadline) {
      const deadline = localizedDate(invoice.payment_deadline)
      addDetail(dates, 'Payment deadline', deadline)
      const deadlineDate = new Date(`${invoice.payment_deadline}T23:59:59.999Z`)
      if (Date.now() > deadlineDate.getTime()) dates.classList.add('invoice-date-overdue')
    }
    container.append(dates)
  }

  if (presentation.payer) container.append(contactCard('Bill to', presentation.payer))

  if (invoice && (invoice.description || invoice.purchase_order_reference)) {
    const detailsCard = element('section', 'invoice-description-card')
    detailsCard.append(element('h3', 'invoice-section-title', 'Payment details'))
    const details = element('dl', 'invoice-detail-list')
    if (invoice.description) addDetail(details, 'Description', invoice.description)
    if (invoice.purchase_order_reference) {
      addDetail(details, 'Purchase-order reference', invoice.purchase_order_reference)
    }
    detailsCard.append(details)
    container.append(detailsCard)
  }

  if (presentation.payee) container.append(contactCard('From', presentation.payee))
  container.hidden = false
}

function showWarning(): void {
  const warning = document.getElementById('private-invoice-warning')
  if (warning) warning.hidden = false
}

function storageKey(invoiceId: string): string {
  return `bullnym-private-invoice:v1:${invoiceId}`
}

function scrubFragment(): void {
  try {
    history.replaceState(history.state, '', `${location.pathname}${location.search}`)
  } catch {
    // Some embedded browsers can deny history mutation. Decryption still
    // works; the page's no-referrer policy prevents fragment disclosure.
  }
}

function installLinkActions(encodedKey: string): void {
  const actions = document.getElementById('private-invoice-link-actions')
  const copy = document.getElementById('copy-private-invoice-link')
  const share = document.getElementById('share-private-invoice-link')
  if (!actions || !(copy instanceof HTMLButtonElement) || !(share instanceof HTMLButtonElement)) {
    return
  }
  const privateLink = () => `${location.origin}${location.pathname}#v1.${encodedKey}`
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(privateLink())
      copy.textContent = 'Copied'
      setTimeout(() => { copy.textContent = 'Copy private link' }, 1_500)
    } catch {
      // Payment remains usable when clipboard permission is unavailable.
    }
  })
  if (typeof navigator.share === 'function') {
    share.addEventListener('click', async () => {
      try {
        await navigator.share({ title: 'Private invoice', url: privateLink() })
      } catch {
        // User cancellation and platform share failures need no page error.
      }
    })
  } else {
    share.hidden = true
  }
  actions.hidden = false
}

export async function startPrivateInvoicePresentation(invoiceId: string): Promise<void> {
  const container = document.getElementById('private-invoice-presentation')
  if (!container) return

  let encodedKey: string | null = null
  let keyCameFromFragment = false
  if (location.hash) {
    try {
      encodedKey = parsePrivateInvoiceFragment(location.hash)
      keyCameFromFragment = true
    } catch {
      // The generic warning below deliberately does not distinguish bad keys,
      // incomplete links, unsupported versions, or corrupted presentations.
    } finally {
      scrubFragment()
    }
  } else {
    try {
      encodedKey = sessionStorage.getItem(storageKey(invoiceId))
    } catch {
      encodedKey = null
    }
  }

  if (!encodedKey) {
    showWarning()
    return
  }

  try {
    const response = await fetch(`/api/v1/invoices/${invoiceId}/presentation`, {
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    })
    if (!response.ok) throw new Error('presentation unavailable')
    const value = await response.json() as unknown
    if (
      !isRecord(value) ||
      Object.keys(value).length !== 1 ||
      typeof value.presentation_envelope !== 'string'
    ) {
      throw new Error('invalid presentation response')
    }
    const presentation = await decryptPrivateInvoicePresentation(
      value.presentation_envelope,
      encodedKey,
    )
    // Authenticate the fragment key before replacing a key that may already
    // be known-good for this tab. A malformed or tampered shared link must not
    // destroy the user's working session copy.
    if (keyCameFromFragment) {
      try {
        sessionStorage.setItem(storageKey(invoiceId), encodedKey)
      } catch {
        // Keep the authenticated key in memory when storage is blocked.
      }
    }
    renderPresentation(container, presentation)
    installLinkActions(encodedKey)
  } catch {
    showWarning()
  }
}

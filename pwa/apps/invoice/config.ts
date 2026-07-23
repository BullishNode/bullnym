export interface InvoicePageConfig {
  invoice_id: string
  private_presentation: boolean
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export function parseInvoicePageConfig(): InvoicePageConfig | null {
  const element = document.getElementById('bullnym-invoice-config')
  if (!element?.textContent) return null
  try {
    const value = JSON.parse(element.textContent) as Record<string, unknown>
    if (
      Object.keys(value).some(
        (key) => key !== 'invoice_id' && key !== 'private_presentation',
      ) ||
      typeof value.invoice_id !== 'string' ||
      !UUID.test(value.invoice_id) ||
      typeof value.private_presentation !== 'boolean'
    ) {
      return null
    }
    return {
      invoice_id: value.invoice_id,
      private_presentation: value.private_presentation,
    }
  } catch {
    return null
  }
}

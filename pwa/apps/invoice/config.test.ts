import { afterEach, describe, expect, it, vi } from 'vitest'
import { parseInvoicePageConfig } from './config'

describe('parseInvoicePageConfig', () => {
  afterEach(() => vi.unstubAllGlobals())

  function inject(value: unknown) {
    vi.stubGlobal('document', {
      getElementById: () => ({ textContent: JSON.stringify(value) }),
    })
  }

  it('accepts only the minimal server-injected invoice config', () => {
    inject({
      invoice_id: '1d2ee5d8-1d3e-47ec-805e-35398e717fe7',
      private_presentation: true,
    })

    expect(parseInvoicePageConfig()).toEqual({
      invoice_id: '1d2ee5d8-1d3e-47ec-805e-35398e717fe7',
      private_presentation: true,
    })
  })

  it('fails closed for malformed, missing, or expanded config', () => {
    for (const value of [
      { invoice_id: 'not-a-uuid', private_presentation: true },
      { invoice_id: '1d2ee5d8-1d3e-47ec-805e-35398e717fe7' },
      {
        invoice_id: '1d2ee5d8-1d3e-47ec-805e-35398e717fe7',
        private_presentation: false,
        nym: 'must-not-be-exposed',
      },
    ]) {
      inject(value)
      expect(parseInvoicePageConfig()).toBeNull()
    }
  })
})

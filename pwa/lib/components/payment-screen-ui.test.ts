import { render } from 'svelte/server'
import { describe, expect, it } from 'vitest'
import PaymentScreen from './PaymentScreen.svelte'

describe('PaymentScreen initial status', () => {
  it('renders the pre-first-status state as loading rather than a warning', () => {
    const { body } = render(PaymentScreen, {
      props: {
        invoice: {
          pricing_mode: 'sat_fixed',
          invoice_id: 'invoice-1',
          amount_sat: 2_000,
          lightning_pr: 'lnbc1example',
          lightning_amount_sat: 2_000,
          liquid_address: 'lq1example',
          liquid_amount_sat: 2_000,
          expires_at_unix: 2_000_000_000,
        },
        nym: 'donation',
        amountLabel: '2,000 sat',
        onTerminal: () => {},
      },
    })

    expect(body).toContain('Checking payment status')
    expect(body).toContain('aria-label="Loading"')
    expect(body).not.toContain('Payment status is being checked')
  })
})

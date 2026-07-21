import { describe, expect, it, vi } from 'vitest'
import type { PayerDemandQuoteResponse, PayerQuoteRail } from './api/client'
import {
  SatPayerInstructionCoordinator,
  activeSatPayerInstruction,
  captureSatLightningAuthority,
  satPayerInstructionPresentation,
} from './sat-payer-instruction'

const ID = '11111111-1111-4111-8111-111111111111'
const NOW = 1_700_000_000
const ASSET = '6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d'

function response(rail: PayerQuoteRail, amount = 10_000): PayerDemandQuoteResponse {
  const instruction = rail === 'lightning'
    ? { kind: 'lightning_direct' as const, pr: 'lnbc-test', payer_amount_sat: amount }
    : rail === 'liquid'
      ? { kind: 'liquid_direct' as const, address: 'lq1-test', payer_amount_sat: amount }
      : {
          kind: 'bitcoin_direct' as const,
          address: 'bc1-test',
          bip21: 'bitcoin:bc1-test?amount=0.00010000',
          payer_amount_sat: amount,
        }
  return {
    pricing_mode: 'sat_fixed',
    invoice_id: ID,
    selected_rail: rail,
    amount_sat: amount,
    expires_at_unix: NOW + 3_600,
    instruction,
    instruction_expires_at_unix: rail === 'lightning' ? NOW + 600 : null,
  }
}

describe('SatPayerInstructionCoordinator', () => {
  it('coalesces exact retries and exposes only a selected instruction', async () => {
    const fetcher = vi.fn().mockResolvedValue(response('lightning'))
    const coordinator = new SatPayerInstructionCoordinator(ID, fetcher, () => NOW * 1_000)
    const first = coordinator.ensure('lightning', 10_000, 'initial')
    const retry = coordinator.ensure('lightning', 10_000, 'tab')
    await Promise.all([first, retry])
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(activeSatPayerInstruction(coordinator.state, 'liquid', NOW * 1_000)).toBeNull()
    expect(satPayerInstructionPresentation(coordinator.state, 'lightning', NOW * 1_000, ASSET)).toMatchObject({
      payerAmountSat: 10_000,
      swapCostSat: 0,
      qrValue: 'lnbc-test',
      expiresAtUnix: NOW + 600,
    })
    expect(captureSatLightningAuthority(coordinator.state, NOW * 1_000)?.bolt11).toBe('lnbc-test')
  })

  it('invalidates all prior instructions when the remaining amount changes', async () => {
    const fetcher = vi.fn().mockImplementation((rail: PayerQuoteRail) => Promise.resolve(response(rail)))
    const coordinator = new SatPayerInstructionCoordinator(ID, fetcher, () => NOW * 1_000)
    await coordinator.ensure('liquid', 10_000, 'initial')
    coordinator.setAmount(5_000)
    expect(activeSatPayerInstruction(coordinator.state, 'liquid', NOW * 1_000)).toBeNull()
  })

  it('rejects expired or wrong-amount instructions', async () => {
    const wrong = { ...response('bitcoin'), amount_sat: 9_999 }
    const coordinator = new SatPayerInstructionCoordinator(
      ID,
      () => Promise.resolve(wrong),
      () => NOW * 1_000,
    )
    expect(await coordinator.ensure('bitcoin', 10_000, 'initial')).toBe(false)
    expect(coordinator.state.errors.bitcoin).toContain('Could not load')
  })
})

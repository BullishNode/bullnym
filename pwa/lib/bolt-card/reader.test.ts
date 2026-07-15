import { afterEach, describe, expect, it, vi } from 'vitest'
import { payViaBoltCard, type WithdrawParams } from './reader'

const PARAMS: WithdrawParams = {
  tag: 'withdrawRequest',
  callback: 'https://card.example/callback',
  k1: 'card-k1',
  minWithdrawable: 1_000,
  maxWithdrawable: 100_000_000,
}

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    json: () => Promise.resolve(body),
  } as Response
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((next) => {
    resolve = next
  })
  return { promise, resolve }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('payViaBoltCard authority boundary', () => {
  it('threads one AbortSignal through params and callback and rechecks before submission', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(PARAMS))
      .mockResolvedValueOnce(jsonResponse({ status: 'OK' }))
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()
    const assertCurrent = vi.fn()

    await payViaBoltCard('https://card.example/withdraw', 'lnbc-current', 10_000, {
      signal: controller.signal,
      assertCurrent,
    })

    expect(assertCurrent).toHaveBeenCalledTimes(3)
    expect(fetchMock).toHaveBeenNthCalledWith(1, 'https://card.example/withdraw', {
      signal: controller.signal,
    })
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://card.example/callback?k1=card-k1&pr=lnbc-current',
      { signal: controller.signal },
    )
  })

  it('prevents callback submission when authority changes during params fetch', async () => {
    const paramsFetch = deferred<Response>()
    const fetchMock = vi.fn().mockReturnValueOnce(paramsFetch.promise)
    vi.stubGlobal('fetch', fetchMock)
    let current = true

    const payment = payViaBoltCard('https://card.example/withdraw', 'lnbc-old', 10_000, {
      assertCurrent: () => {
        if (!current) throw new DOMException('Quote changed', 'AbortError')
      },
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)

    current = false
    paramsFetch.resolve(jsonResponse(PARAMS))
    await expect(payment).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('prevents callback submission when the attempt is aborted during params fetch', async () => {
    const paramsFetch = deferred<Response>()
    const fetchMock = vi.fn().mockReturnValueOnce(paramsFetch.promise)
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()

    const payment = payViaBoltCard('https://card.example/withdraw', 'lnbc-old', 10_000, {
      signal: controller.signal,
    })
    controller.abort()
    paramsFetch.resolve(jsonResponse(PARAMS))

    await expect(payment).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('preserves the sat-fixed call shape when no quote authority is supplied', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(PARAMS))
      .mockResolvedValueOnce(jsonResponse({ status: 'OK' }))
    vi.stubGlobal('fetch', fetchMock)

    await payViaBoltCard('https://card.example/withdraw', 'lnbc-sat-fixed', 10_000)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

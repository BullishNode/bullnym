import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { watchLiquidAddress } from './liquid-ws'

// Minimal WebSocket stand-in: captures sends + listeners and lets the test
// drive open/message/close events synchronously.
class FakeWS {
  static instances: FakeWS[] = []
  url: string
  sent: string[] = []
  private listeners: Record<string, ((ev: unknown) => void)[]> = {}
  closed = false
  constructor(url: string) {
    this.url = url
    FakeWS.instances.push(this)
  }
  addEventListener(type: string, cb: (ev: unknown) => void) {
    ;(this.listeners[type] ??= []).push(cb)
  }
  send(data: string) {
    this.sent.push(data)
  }
  close() {
    this.closed = true
  }
  emit(type: string, ev?: unknown) {
    ;(this.listeners[type] ?? []).forEach((cb) => cb(ev))
  }
}

beforeEach(() => {
  FakeWS.instances = []
  ;(globalThis as unknown as { WebSocket: unknown }).WebSocket = FakeWS
})
afterEach(() => {
  delete (globalThis as unknown as { WebSocket?: unknown }).WebSocket
  vi.useRealTimers()
})

describe('watchLiquidAddress', () => {
  it('subscribes to the address via track-address on open', () => {
    const w = watchLiquidAddress('lq1addr', () => {})
    const ws = FakeWS.instances[0]!
    ws.emit('open')
    expect(ws.sent).toEqual([JSON.stringify({ 'track-address': 'lq1addr' })])
    w.close()
  })

  it('fires onActivity for address-transactions, not for the block firehose', () => {
    const onActivity = vi.fn()
    const w = watchLiquidAddress('lq1addr', onActivity)
    const ws = FakeWS.instances[0]!
    ws.emit('message', { data: JSON.stringify({ block: { height: 1 } }) })
    ws.emit('message', { data: JSON.stringify({ blocks: [] }) })
    ws.emit('message', { data: JSON.stringify({ mempoolInfo: {} }) })
    expect(onActivity).not.toHaveBeenCalled()
    ws.emit('message', { data: JSON.stringify({ 'address-transactions': [{ txid: 'x' }] }) })
    ws.emit('message', { data: JSON.stringify({ 'block-transactions': [{ txid: 'y' }] }) })
    expect(onActivity).toHaveBeenCalledTimes(2)
    w.close()
  })

  it('ignores malformed / non-string messages', () => {
    const onActivity = vi.fn()
    const w = watchLiquidAddress('a', onActivity)
    const ws = FakeWS.instances[0]!
    ws.emit('message', { data: 'not json' })
    ws.emit('message', { data: 123 })
    expect(onActivity).not.toHaveBeenCalled()
    w.close()
  })

  it('reconnects with backoff after an unexpected close', () => {
    vi.useFakeTimers()
    watchLiquidAddress('a', () => {})
    expect(FakeWS.instances.length).toBe(1)
    FakeWS.instances[0]!.emit('close')
    vi.advanceTimersByTime(1000)
    expect(FakeWS.instances.length).toBe(2)
  })

  it('close() cancels any pending reconnect', () => {
    vi.useFakeTimers()
    const w = watchLiquidAddress('a', () => {})
    w.close()
    FakeWS.instances[0]!.emit('close')
    vi.advanceTimersByTime(60_000)
    expect(FakeWS.instances.length).toBe(1)
  })
})

// Zero-conf Liquid payment detection (§8). Bull Bitcoin runs a
// mempool.space-style Esplora WebSocket for Liquid at
// wss://liquid.bullbitcoin.com/liquid/api/v1/ws (confirmed: replies to the
// mempool `want`/`track-address` protocol; returns 101 on upgrade). We
// subscribe to the invoice's Liquid settlement address; any address-tx push
// triggers an immediate status poll.
//
// The server stays AUTHORITATIVE — this watcher NEVER flips UI state itself.
// It only collapses the up-to-3s polling latency to ~instant. On any failure
// (handshake blocked, drop, parse error) it silently reconnects with backoff
// and, failing that, the component's 3s poller keeps working unchanged —
// kiosk networks block WS often, so degradation must be invisible.

const LIQUID_WS_URL = 'wss://liquid.bullbitcoin.com/liquid/api/v1/ws'
const INITIAL_RECONNECT_MS = 1000
const MAX_RECONNECT_MS = 30_000

export interface LiquidWatcher {
  close(): void
}

// mempool.space pushes address activity as {"address-transactions":[...]}
// (and {"multi-address-transactions":{...}} / {"block-transactions":[...]}
// on confirmation). Those are the only keys that indicate our tracked
// address moved; block/mempool firehose messages (which we never subscribe
// to via `want`) are ignored so we don't poll on every new Liquid block.
function isAddressActivity(data: unknown): boolean {
  if (!data || typeof data !== 'object') return false
  return (
    'address-transactions' in data ||
    'multi-address-transactions' in data ||
    'block-transactions' in data
  )
}

/**
 * Watch `address` for on-chain activity, calling `onActivity` (debounced only
 * by the caller's own idempotent poll) whenever the WS reports a transaction
 * touching it. Returns a handle whose close() tears down the socket and
 * cancels any pending reconnect. Safe to call in non-browser/SSR contexts —
 * it no-ops if WebSocket is unavailable.
 */
export function watchLiquidAddress(address: string, onActivity: () => void): LiquidWatcher {
  if (typeof WebSocket === 'undefined') {
    return { close() {} }
  }

  let ws: WebSocket | null = null
  let closed = false
  let reconnectDelay = INITIAL_RECONNECT_MS
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined

  function scheduleReconnect(): void {
    if (closed) return
    ws = null
    reconnectTimer = setTimeout(connect, reconnectDelay)
    reconnectDelay = Math.min(reconnectDelay * 2, MAX_RECONNECT_MS)
  }

  function connect(): void {
    if (closed) return
    let socket: WebSocket
    try {
      socket = new WebSocket(LIQUID_WS_URL)
    } catch {
      scheduleReconnect()
      return
    }
    ws = socket

    socket.addEventListener('open', () => {
      reconnectDelay = INITIAL_RECONNECT_MS
      try {
        socket.send(JSON.stringify({ 'track-address': address }))
      } catch {
        /* the close handler will reconnect */
      }
    })

    socket.addEventListener('message', (ev: MessageEvent) => {
      if (typeof ev.data !== 'string') return
      let data: unknown
      try {
        data = JSON.parse(ev.data)
      } catch {
        return
      }
      // We don't parse tx details — the authoritative server decides
      // paid/partial/settling. Any activity for our address just means
      // "poll now instead of waiting up to 3s".
      if (isAddressActivity(data)) onActivity()
    })

    socket.addEventListener('close', () => {
      if (!closed) scheduleReconnect()
    })

    socket.addEventListener('error', () => {
      // Force the close path (some browsers fire error without close).
      try {
        socket.close()
      } catch {
        scheduleReconnect()
      }
    })
  }

  connect()

  return {
    close() {
      closed = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      if (ws) {
        try {
          ws.close()
        } catch {
          /* already closing */
        }
        ws = null
      }
    },
  }
}

// Exchange-rate store. Seeded from the server-injected render-time rate,
// refreshed every 60s from GET /api/v1/rate?currency=X (public, cached
// server-side by the pricer). The server stays authoritative — fiat
// invoices send (fiat_amount_minor, fiat_currency) and the server locks
// its own rate — this store only drives display and the Charge gate.

import { config } from '$lib/config'

const REFRESH_MS = 60_000
const STALE_AMBER_MS = 2 * 60_000
const STALE_HARD_MS = 5 * 60_000

const state = $state({
  currency: config.currency,
  minorPerBtc: config.minor_per_btc,
  fetchedAt: Date.now(),
  lastKnown: config.last_known_rate,
  // True only during the fetch triggered by a currency switch (which zeroes
  // minorPerBtc). Lets consumers show a same-height "updating" state instead
  // of the taller "unavailable" block, so switching currency doesn't reflow
  // the centered entry stack. The 60s interval refresh keeps the current
  // rate visible and never sets this.
  loading: false,
  // ticks so `ageMs` getters re-evaluate in templates
  now: Date.now(),
})

async function refresh(): Promise<void> {
  try {
    const res = await fetch(`/api/v1/rate?currency=${encodeURIComponent(state.currency)}`)
    if (!res.ok) return
    const body = (await res.json()) as { minor_per_btc: number; last_known_rate: boolean }
    if (body.minor_per_btc > 0) {
      state.minorPerBtc = body.minor_per_btc
      state.fetchedAt = Date.now()
      state.lastKnown = body.last_known_rate
    }
  } catch {
    /* offline: existing rate ages out naturally */
  } finally {
    state.loading = false
  }
}

setInterval(refresh, REFRESH_MS)
setInterval(() => {
  state.now = Date.now()
}, 10_000)

export const rate = {
  get currency(): string {
    return state.currency
  },
  set currency(c: string) {
    if (c === state.currency) return
    state.currency = c
    state.minorPerBtc = 0
    state.loading = true
    void refresh()
  },
  get loading(): boolean {
    return state.loading
  },
  get minorPerBtc(): number {
    return state.minorPerBtc
  },
  get ageMs(): number {
    // Root cause of the transient "-1s ago": `state.now` only ticks every
    // 10s (see setInterval below), but `state.fetchedAt` updates
    // immediately on a successful refresh(). If a refresh lands between
    // ticks, fetchedAt can be momentarily newer than the last `now`
    // snapshot, making the subtraction go negative until the next tick.
    // Clamping here fixes every consumer (RateBar.svelte's "Xs ago" label
    // included) at the source.
    return Math.max(0, state.now - state.fetchedAt)
  },
  get available(): boolean {
    return state.minorPerBtc > 0 && this.ageMs < STALE_HARD_MS
  },
  get amber(): boolean {
    return state.lastKnown || this.ageMs >= STALE_AMBER_MS
  },
  refresh,
}

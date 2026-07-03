// POS transaction history — plain localStorage, keyed per nym. No IndexedDB,
// no encryption, matches plans/pos/04-pos-mode.md's local-only history store.

import { localStore } from '$lib/stores/local.svelte'
import { config } from '$lib/config'

export interface HistoryRecord {
  id: string
  amount_fiat_minor: number | null
  currency: string | null
  precision: number
  amount_sat: number
  rail: string | null
  status: string
  paid_at_unix: number | null
  note: string
  rate_minor_per_btc: number | null
}

const MAX_RECORDS = 200

const store = localStore<HistoryRecord[]>(`bullnym:history:${config.nym}`, [])

export const history = {
  get records(): HistoryRecord[] {
    return store.value
  },
  /** Newest-first insert; prunes oldest past MAX_RECORDS. */
  add(record: HistoryRecord): void {
    store.value = [record, ...store.value.filter((r) => r.id !== record.id)].slice(0, MAX_RECORDS)
  },
  find(id: string): HistoryRecord | undefined {
    return store.value.find((r) => r.id === id)
  },
  clear(): void {
    store.value = []
  },
}

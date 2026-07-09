// POS-only local settings. Everything here is per-nym, local-only UX
// preference — no server round-trip, no secrets except the PIN hash
// (see lib/pin.ts), which itself is a local gate, not server auth.

import { localStore } from '$lib/stores/local.svelte'
import { config } from '$lib/config'

export type PaperSize = '58mm' | '80mm' | 'a4'

const currencyStore = localStore<string | null>(`bullnym:settings:${config.page_key}:currency`, null)
const boltCardStore = localStore<boolean>(`bullnym:settings:${config.page_key}:boltcard`, true)
// Deliberately NOT nym-scoped: ReceiptScreen.svelte already reads this exact
// key directly from localStorage (predates this store).
const paperSizeStore = localStore<PaperSize>('bullnym:paper-size', '80mm')

export const settings = {
  /** Display currency override; falls back to the server-injected config default. */
  get currency(): string {
    return currencyStore.value ?? config.currency
  },
  set currency(c: string) {
    currencyStore.value = c
  },
  get boltCardEnabled(): boolean {
    return boltCardStore.value
  },
  set boltCardEnabled(v: boolean) {
    boltCardStore.value = v
  },
  get paperSize(): PaperSize {
    return paperSizeStore.value
  },
  set paperSize(v: PaperSize) {
    paperSizeStore.value = v
  },
}

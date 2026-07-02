<script lang="ts">
  // Payment screen — reskinned to nostr-pos's Pos.svelte layout
  // (~/apps/nostr-pos/apps/pos-pwa/src/routes/Pos.svelte): big font-display
  // amount, status dot + label, pill tab bar, QrCard. Upstream only has
  // two rails (lightning_swap/liquid) selected inline inside one screen;
  // we extend the exact same tab-bar markup/classes to our 3-4 rails
  // (Lightning/Liquid/Bitcoin/Tap Card) since the coordinator asked to
  // keep Bolt Card as a dedicated tab (not upstream's QrCard-embedded
  // "Bolt Card" button) — all underlying data/poll/Bolt-Card logic is
  // unchanged from the prior milestones, this is a screen-level reskin.
  import { untrack } from 'svelte'
  import QrCard from '$lib/components/QrCard.svelte'
  import BullSpinner from '$lib/components/BullSpinner.svelte'
  import Button from '$lib/components/Button.svelte'
  import { ApiError, getInvoiceStatus, type CreateInvoiceResponse, type InvoiceStatus } from '$lib/api/client'
  import { localStore } from '$lib/stores/local.svelte'
  import { config } from '$lib/config'
  import { settings } from '$lib/stores/settings.svelte'
  import { scanForLnurl, payViaBoltCard } from '$lib/bolt-card/reader'
  import { statusLabel, statusTextTone, KNOWN_STATUSES } from '$lib/status'

  // True root cause of the "polls /status forever on a bad id" bug: the
  // server deliberately returns HTTP 200 with an LNURL-style (LUD-06) error
  // envelope ({"status":"ERROR","code":"InvoiceNotFound",...}) rather than
  // a real 404 for most error conditions (src/error.rs) — lib/api/client.ts's
  // request() now detects that envelope and throws a real ApiError(404,
  // ..., code) for it, so this mostly becomes a normal caught error below.
  // KNOWN_STATUSES stays as belt-and-suspenders in case a genuinely-200
  // response ever carries a status value we don't model.
  const MAX_NOT_FOUND_STREAK = 5

  let {
    invoice,
    nym,
    amountLabel,
    onPaid,
    onExpired,
    onNotFound,
  }: {
    invoice: CreateInvoiceResponse
    nym: string
    amountLabel: string
    onPaid: (status: InvoiceStatus) => void
    onExpired: () => void
    /**
     * Called after MAX_NOT_FOUND_STREAK consecutive polls come back either
     * as a 404 or as a 200 with a status value outside our known set (see
     * poll() below). Falls back to onExpired if the caller doesn't
     * distinguish "not found" from "expired" in its UI. The back/cancel
     * link now lives entirely in the caller's own header (donation
     * App.svelte / apps/pos/screens/PayScreen.svelte) — this component no
     * longer renders one itself, since both callers already have their own
     * header row and rendering a second one here duplicated it (POS's
     * PayScreen showed two stacked "← Cancel sale" rows).
     */
    onNotFound?: () => void
  } = $props()

  type Rail = 'lightning' | 'liquid' | 'bitcoin' | 'boltcard'

  const hasBitcoin = $derived(!!invoice.bitcoin_chain_bip21)
  // Bolt Card is POS-only (plans/pos/06-bolt-card.md) and Android
  // Chrome-only. Gated defensively on config.mode too, in addition to the
  // NDEFReader + settings toggle checks, so it can never leak into the
  // donation shell even if this shared component is reused elsewhere.
  const hasBoltCard = $derived(
    config.mode === 'pos' && typeof window !== 'undefined' && 'NDEFReader' in window && settings.boltCardEnabled,
  )

  const railLabels: Record<Rail, string> = {
    lightning: 'Lightning',
    liquid: 'Liquid',
    bitcoin: 'Bitcoin',
    boltcard: 'Tap Card',
  }

  function fallbackTab(stored: Rail): Rail {
    if (stored === 'bitcoin' && !invoice.bitcoin_chain_bip21) return 'lightning'
    // Must match hasBoltCard's full gate exactly: settings.boltCardEnabled
    // can change between mounts (cashier disables it after previously
    // using Tap Card), and a stale 'boltcard' rail must not resurrect the
    // scan panel — that would both violate the toggle and leave a scan
    // running with no visible tab selected.
    if (stored === 'boltcard' && !untrack(() => hasBoltCard)) return 'lightning'
    return stored
  }

  const activeTabStore = untrack(() => localStore<Rail>(`bullnym:${nym}:rail`, 'lightning'))
  const initialTab: Rail = untrack(() => fallbackTab(activeTabStore.value))
  let activeTab = $state<Rail>(initialTab)

  // Bolt Card scan state machine — never leave a scan running in the
  // background (plan doc's explicit rule): aborted on tab switch, unmount,
  // and invoice expiry.
  type CardState = 'idle' | 'scanning' | 'requesting' | 'sent' | 'declined'
  let cardState = $state<CardState>('idle')
  let cardError = $state<string | null>(null)
  let cardAbort: AbortController | undefined
  let latestAmountSat = $state<number | null>(null)

  function stopCardScan() {
    cardAbort?.abort()
    cardAbort = undefined
  }

  function startCardScan() {
    stopCardScan()
    cardError = null
    cardState = 'scanning'
    const controller = new AbortController()
    cardAbort = controller
    scanForLnurl(controller.signal)
      .then(async (lnurl) => {
        if (controller.signal.aborted) return
        cardState = 'requesting'
        if (latestAmountSat === null) throw new Error('Amount not yet known — try again in a moment')
        await payViaBoltCard(lnurl, invoice.lightning_pr, latestAmountSat)
        if (controller.signal.aborted) return
        cardState = 'sent'
        // Success detection is the existing status poller below — no
        // second poller here.
      })
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === 'AbortError') return
        cardState = 'declined'
        cardError = err instanceof Error ? err.message : 'Card declined'
      })
  }

  function selectTab(tab: Rail) {
    if (activeTab === 'boltcard' && tab !== 'boltcard') {
      stopCardScan()
      cardState = 'idle'
      cardError = null
    }
    activeTab = tab
    activeTabStore.value = tab
    if (tab === 'boltcard') startCardScan()
  }

  $effect(() => {
    if (untrack(() => activeTab) === 'boltcard') startCardScan()
    return () => stopCardScan()
  })

  const qrValue = $derived(
    activeTab === 'lightning'
      ? invoice.lightning_pr
      : activeTab === 'liquid'
        ? invoice.liquid_address
        : (invoice.bitcoin_chain_bip21 ?? invoice.bitcoin_chain_address ?? ''),
  )

  let currentStatus = $state('pending')
  const initialExpiresAt = untrack(() => invoice.expires_at_unix)
  let remainingMs = $state(Math.max(0, initialExpiresAt * 1000 - Date.now()))

  const countdown = $derived.by(() => {
    const totalSec = Math.max(0, Math.floor(remainingMs / 1000))
    const m = Math.floor(totalSec / 60)
    const s = totalSec % 60
    return `${m}:${s.toString().padStart(2, '0')}`
  })

  let pollHandle: ReturnType<typeof setInterval> | undefined
  let tickHandle: ReturnType<typeof setInterval> | undefined
  let stopped = false
  let notFoundStreak = 0

  function giveUpAsNotFound() {
    stopPolling()
    stopCardScan()
    if (onNotFound) onNotFound()
    else onExpired()
  }

  async function poll() {
    if (stopped) return
    try {
      const status = await getInvoiceStatus(invoice.invoice_id)
      if (!KNOWN_STATUSES.has(status.status)) {
        // 200 OK but not a status we recognize — the id didn't resolve to
        // a real invoice server-side even though the request itself
        // succeeded. Don't treat this as "waiting for payment" forever.
        notFoundStreak += 1
        if (notFoundStreak >= MAX_NOT_FOUND_STREAK) giveUpAsNotFound()
        return
      }
      notFoundStreak = 0
      latestAmountSat = status.amount_sat
      currentStatus = status.status
      if (status.status === 'paid' || status.status === 'overpaid') {
        stopPolling()
        stopCardScan()
        onPaid(status)
      } else if (status.status === 'expired' || status.status === 'cancelled') {
        stopPolling()
        stopCardScan()
        onExpired()
      }
    } catch (err) {
      if (err instanceof ApiError && (err.status === 404 || err.code === 'InvoiceNotFound')) {
        notFoundStreak += 1
        if (notFoundStreak >= MAX_NOT_FOUND_STREAK) giveUpAsNotFound()
        return
      }
      /* other transient network errors: keep polling, don't count toward the streak */
    }
  }

  function stopPolling() {
    stopped = true
    if (pollHandle) clearInterval(pollHandle)
    if (tickHandle) clearInterval(tickHandle)
  }

  $effect(() => {
    pollHandle = setInterval(poll, 3000)
    tickHandle = setInterval(() => {
      remainingMs = invoice.expires_at_unix * 1000 - Date.now()
      if (remainingMs <= -30_000) {
        stopPolling()
        stopCardScan()
        onExpired()
      }
    }, 1000)
    void poll()
    return () => stopPolling()
  })

  const tabs = $derived<Rail[]>(['lightning', 'liquid', ...(hasBitcoin ? (['bitcoin'] as const) : []), ...(hasBoltCard ? (['boltcard'] as const) : [])])
</script>

<div class="mx-auto flex w-full max-w-md flex-col items-center gap-5">
  <div class="flex w-full flex-col items-center gap-1">
    <p class="font-display text-7xl tabular-nums tracking-display leading-none">{amountLabel}</p>
    <p class={`inline-flex items-center gap-1.5 text-xs font-semibold ${statusTextTone(currentStatus)}`}>
      <span class="inline-block h-1.5 w-1.5 rounded-full bg-current"></span>
      {statusLabel(currentStatus)}
    </p>
  </div>

  <div class="inline-flex rounded-md bg-[#eadfce] p-0.5 text-xs dark:bg-[#2c2922]">
    {#each tabs as tab (tab)}
      <button
        type="button"
        class={`min-h-9 rounded-md px-4 font-semibold transition ${
          activeTab === tab
            ? 'bg-[#fffaf0] text-[#1f513a] shadow-sm dark:bg-[#161512] dark:text-[#8bc8a4]'
            : 'text-[#5f5547] dark:text-[#c9bca7]'
        }`}
        onclick={() => selectTab(tab)}
      >
        {railLabels[tab]}
      </button>
    {/each}
  </div>

  {#if activeTab === 'boltcard'}
    <div class="flex w-full flex-col items-center gap-3 py-6">
      {#if cardState === 'idle' || cardState === 'scanning'}
        <BullSpinner size={72} label="Hold card near the back of this device" />
      {:else if cardState === 'requesting'}
        <BullSpinner size={72} label="Card detected — requesting payment" />
      {:else if cardState === 'sent'}
        <p class="text-sm text-[#776b5a] dark:text-[#b9aa91]">Payment sent. Waiting for confirmation...</p>
      {:else if cardState === 'declined'}
        <p class="text-sm font-semibold text-[#8c2d28] dark:text-[#e8a49e]">Card declined. Try Lightning or Liquid.</p>
        {#if cardError}
          <p class="text-xs text-[#776b5a] dark:text-[#b9aa91]">{cardError}</p>
        {/if}
        <Button variant="secondary" onclick={startCardScan}>Try again</Button>
      {/if}
    </div>
  {:else}
    <QrCard value={qrValue} label={`${railLabels[activeTab]} payment code`} />
  {/if}

  <p class="text-center text-xs text-[#776b5a] tabular-nums dark:text-[#b9aa91]">Expires in {countdown}</p>
</div>

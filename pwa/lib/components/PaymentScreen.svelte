<script lang="ts">
  // Payment screen — owns everything LIVE: polling, rail payloads,
  // Lightning-offer refresh, Bolt Card, manual refresh, and the countdown.
  // Renders all NON-terminal PayViews (waiting/in_progress/partially_paid
  // with QR+tabs; settling/needs_review as hide-QR panels while it keeps
  // polling). Renders NOTHING terminal — on a terminal PayView it stops
  // polling and reports exactly once via onTerminal; PayFlow.svelte owns
  // the terminal panels (paid/overpaid/underpaid/expired/cancelled/
  // refunded/not_found), since it also owns the per-mode success actions
  // and the onPaid side effect (history.add for POS).
  //
  // Full rewrite for PR #5 review remediation (items 1,4,5,6,10). The
  // reference for ALL payment semantics is the inline JS state machine in
  // templates/invoice_payment.html:290-618 — the branching below is a
  // close 1:1 port of it (via lib/status.ts's pure derivePayView /
  // shouldRefreshLightning helpers), not a from-scratch redesign. Visual
  // chrome (tab bar, QrCard, Bolt Card panel) is unchanged from the prior
  // nostr-pos-reskinned version.
  import { untrack } from 'svelte'
  import { RefreshCw } from 'lucide-svelte'
  import QrCard from '$lib/components/QrCard.svelte'
  import BullSpinner from '$lib/components/BullSpinner.svelte'
  import Button from '$lib/components/Button.svelte'
  import { ApiError, getInvoiceStatus, fetchLightningOffer, type CreateInvoiceResponse, type InvoiceStatus } from '$lib/api/client'
  import { localStore } from '$lib/stores/local.svelte'
  import { config } from '$lib/config'
  import { settings } from '$lib/stores/settings.svelte'
  import { scanForLnurl, payViaBoltCard } from '$lib/bolt-card/reader'
  import {
    KNOWN_STATUSES,
    derivePayView,
    isTerminalView,
    showsRails,
    payViewLabel,
    payViewTone,
    payViewToTerminal,
    shouldRefreshLightning,
    nextLightningPr,
    type PayView,
    type TerminalState,
  } from '$lib/status'
  import { availableRails } from '$lib/rails'
  import { liquidUri, bitcoinPayload } from '$lib/payloads'
  import { watchLiquidAddress } from '$lib/liquid-ws'

  // See poll()/giveUpAsNotFound() below: a 200 OK with a status value
  // outside KNOWN_STATUSES, or MAX_NOT_FOUND_STREAK consecutive 404s, means
  // the id never resolved to a real invoice server-side even though the
  // request itself succeeded.
  const MAX_NOT_FOUND_STREAK = 5

  let {
    invoice,
    nym,
    amountLabel,
    onTerminal,
  }: {
    invoice: CreateInvoiceResponse
    nym: string
    amountLabel: string
    /** Fires exactly once, the first time the invoice reaches a terminal PayView (see lib/status.ts's TerminalState / CONTRACT 5). */
    onTerminal: (t: TerminalState) => void
  } = $props()

  type Rail = 'lightning' | 'liquid' | 'bitcoin' | 'boltcard'

  const railLabels: Record<Rail, string> = {
    lightning: 'Lightning',
    liquid: 'Liquid',
    bitcoin: 'Bitcoin',
    boltcard: 'Tap Card',
  }

  // ---------------------------------------------------------------------
  // Live status. `invoice` only SEEDS the initial rail payloads (its
  // lightning_pr can be '' on the reconstruction path — see
  // maybeRefreshLightning's mount call below); every poll updates `latest`,
  // and payloads/countdown/accept-flags come from `latest` once it exists.
  // This mirrors invoice_payment.html:562-596 exactly.
  // ---------------------------------------------------------------------
  let latest = $state<InvoiceStatus | null>(null)
  let currentLightningPr = $state<string | null>(untrack(() => invoice.lightning_pr || null))
  let currentLiquidAddress = $state<string | null>(untrack(() => invoice.liquid_address || null))
  let currentBitcoinAddress = $state<string | null>(untrack(() => invoice.bitcoin_chain_address))
  let currentBitcoinBip21 = $state<string | null>(untrack(() => invoice.bitcoin_chain_bip21))
  // Tracked apart from currentBitcoinAddress (which merges chain + direct BTC
  // for the QR): the chain-swap rail is payable regardless of accept_btc, so
  // availableRails needs to know when the current bitcoin payload is a chain
  // swap vs a direct address it must gate on accept_btc.
  let currentBitcoinChainAddress = $state<string | null>(untrack(() => invoice.bitcoin_chain_address))

  const view = $derived<PayView>(latest ? derivePayView(latest) : { kind: 'waiting' })
  // Amount for payloads/Bolt Card. Deliberately NOT `?? invoice.amount_sat`
  // — remaining_amount_sat is always present on InvoiceStatus once polled;
  // null here means "haven't polled yet", not "unknown remaining amount".
  const remainingAmountSat = $derived<number | null>(latest?.remaining_amount_sat ?? null)
  // Offers can be re-issued with a later expiry; prefer the polled value.
  const expiresAtUnix = $derived(latest?.expires_at_unix ?? invoice.expires_at_unix)

  // Rail-tab gating (review item 1) — accept flags are unknown before the
  // first poll, so `undefined` reads as accepted (availableRails' default);
  // the payload-presence check still gates the seed itself.
  const rails = $derived(
    availableRails({
      acceptLn: latest?.accept_ln,
      lightningPr: currentLightningPr,
      acceptLiquid: latest?.accept_liquid,
      liquidAddress: currentLiquidAddress,
      acceptBtc: latest?.accept_btc,
      bitcoinAddress: currentBitcoinAddress,
      bitcoinChainAddress: currentBitcoinChainAddress,
    }),
  )

  // Bolt Card is POS-only and Android Chrome-only. Gated defensively on
  // config.mode too, in addition to the
  // NDEFReader + settings toggle checks, so it can never leak into the
  // donation shell even if this shared component is reused elsewhere.
  const hasBoltCard = $derived(
    config.mode === 'pos' && typeof window !== 'undefined' && 'NDEFReader' in window && settings.boltCardEnabled,
  )

  const tabs = $derived<Rail[]>([
    ...(rails.lightning ? (['lightning'] as const) : []),
    ...(rails.liquid ? (['liquid'] as const) : []),
    ...(rails.bitcoin ? (['bitcoin'] as const) : []),
    ...(hasBoltCard ? (['boltcard'] as const) : []),
  ])

  const activeTabStore = untrack(() => localStore<Rail>(`bullnym:${nym}:rail`, 'lightning'))
  let activeTab = $state<Rail>(untrack(() => activeTabStore.value))

  // Never show a selectable tab with a blank QR (today's bug — tabs used to
  // derive once from the create response, which is frozen at invoice
  // creation and can't reflect later accept-flag/payload changes). Runs at
  // mount (the seed may already exclude a rail the persisted tab pointed
  // at) and again any time `tabs` changes as poll data arrives.
  $effect(() => {
    if (tabs.length === 0) return
    if (tabs.includes(activeTab)) return
    const next = tabs[0]!
    if (activeTab === 'boltcard' && next !== 'boltcard') stopCardScan()
    activeTab = next
    activeTabStore.value = next
    if (next === 'boltcard') startCardScan()
  })

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

  // ---------------------------------------------------------------------
  // Lightning offer refresh (review item 6), mirroring
  // invoice_payment.html:562-576 + the old setRail lightning branch: adopt
  // a fresh offer as soon as polling reports one, else request one
  // (throttled — see lib/status.ts's shouldRefreshLightning) whenever
  // there's no current offer and the invoice is still payable.
  // ---------------------------------------------------------------------
  let lnRefreshing = $state(false)
  let lnFailedAt = $state<number | null>(null)

  async function maybeRefreshLightning(): Promise<void> {
    const decision = shouldRefreshLightning({
      accept: latest?.accept_ln ?? true,
      pr: currentLightningPr,
      view,
      refreshing: lnRefreshing,
      lastFailedAt: lnFailedAt,
      now: Date.now(),
    })
    if (!decision) return
    lnRefreshing = true
    try {
      const res = await fetchLightningOffer(invoice.invoice_id)
      currentLightningPr = res.pr
      lnFailedAt = null
    } catch {
      lnFailedAt = Date.now()
    } finally {
      lnRefreshing = false
    }
  }

  // ---------------------------------------------------------------------
  // Bolt Card scan state machine — never leave a scan running in the
  // background: aborted on tab switch, unmount, and invoice expiry.
  // ---------------------------------------------------------------------
  type CardState = 'idle' | 'preparing' | 'scanning' | 'requesting' | 'sent' | 'declined'
  let cardState = $state<CardState>('idle')
  let cardError = $state<string | null>(null)
  let cardAbort: AbortController | undefined

  // While there's no current offer (empty or mid-refresh) or the remaining
  // amount isn't known yet, Tap Card must not start a scan (don't throw on
  // a null amount like the pre-rewrite version did) — show a waiting state
  // instead.
  const boltCardReady = $derived(!!currentLightningPr && !lnRefreshing && remainingAmountSat !== null)

  function stopCardScan() {
    cardAbort?.abort()
    cardAbort = undefined
  }

  function startCardScan() {
    stopCardScan()
    cardError = null
    if (!untrack(() => boltCardReady)) {
      cardState = 'preparing'
      return
    }
    cardState = 'scanning'
    const controller = new AbortController()
    cardAbort = controller
    scanForLnurl(controller.signal)
      .then(async (lnurl) => {
        if (controller.signal.aborted) return
        cardState = 'requesting'
        const pr = currentLightningPr
        const amt = remainingAmountSat
        if (!pr || amt === null) throw new Error('Lightning offer not ready — try again in a moment')
        await payViaBoltCard(lnurl, pr, amt)
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

  // Mount-time only: if the persisted/initial tab is already 'boltcard',
  // start scanning (the normal case — switching TO boltcard — is handled
  // by selectTab/the tabs-fallback effect above).
  $effect(() => {
    if (untrack(() => activeTab) === 'boltcard') startCardScan()
    return () => stopCardScan()
  })

  // Re-attempt once the offer/amount become ready while parked on
  // 'preparing'. Reads cardState via untrack so this effect only reruns
  // when readiness or the active tab changes — not on every cardState
  // mutation (which would abort an in-flight scan the instant it starts).
  $effect(() => {
    if (activeTab === 'boltcard' && boltCardReady) {
      untrack(() => {
        if (cardState === 'preparing') startCardScan()
      })
    }
  })

  // ---------------------------------------------------------------------
  // Polling. Terminal states (including expiry) come ONLY from the server via
  // derivePayView(status); the countdown is display-only (see the setup
  // effect). onTerminal must fire exactly once.
  // ---------------------------------------------------------------------
  let pollHandle: ReturnType<typeof setInterval> | undefined
  let tickHandle: ReturnType<typeof setInterval> | undefined
  let stopped = false
  let notFoundStreak = 0
  let remainingMs = $state(Math.max(0, untrack(() => invoice.expires_at_unix) * 1000 - Date.now()))

  const countdown = $derived.by(() => {
    const totalSec = Math.max(0, Math.floor(remainingMs / 1000))
    const m = Math.floor(totalSec / 60)
    const s = totalSec % 60
    return `${m}:${s.toString().padStart(2, '0')}`
  })

  function stopPolling() {
    stopped = true
    if (pollHandle) clearInterval(pollHandle)
    if (tickHandle) clearInterval(tickHandle)
  }

  function giveUpAsNotFound() {
    stopPolling()
    stopCardScan()
    onTerminal({ kind: 'not_found' })
  }

  async function poll(): Promise<void> {
    if (stopped) return
    try {
      const status = await getInvoiceStatus(invoice.invoice_id)
      // Re-check after the await: a concurrent poll (manual refresh /
      // WS-triggered / interval) may have already reached a terminal state and
      // stopped polling while this request was in flight — onTerminal must
      // fire exactly once (CONTRACT 5), so don't let a late response race it.
      if (stopped) return
      if (!KNOWN_STATUSES.has(status.status)) {
        notFoundStreak += 1
        if (notFoundStreak >= MAX_NOT_FOUND_STREAK) giveUpAsNotFound()
        return
      }
      notFoundStreak = 0
      latest = status

      // Adopt a fresh Lightning offer, or clear a stale one so it gets
      // re-requested (review item 6 / finding #2 — a partial payment
      // invalidates the full-amount BOLT11 and the server returns
      // lightning_pr=null until POST /lightning issues a new one).
      currentLightningPr = nextLightningPr(currentLightningPr, status)
      if (status.liquid_address && status.liquid_address !== currentLiquidAddress) {
        currentLiquidAddress = status.liquid_address
      }
      const nextBitcoinAddress = status.bitcoin_chain_address ?? status.bitcoin_address
      if (nextBitcoinAddress && nextBitcoinAddress !== currentBitcoinAddress) {
        currentBitcoinAddress = nextBitcoinAddress
      }
      if (status.bitcoin_chain_address && status.bitcoin_chain_address !== currentBitcoinChainAddress) {
        currentBitcoinChainAddress = status.bitcoin_chain_address
      }
      const nextBip21 = status.bitcoin_chain_bip21 ?? null
      if (nextBip21 !== currentBitcoinBip21) {
        currentBitcoinBip21 = nextBip21
      }

      void maybeRefreshLightning()

      const v = derivePayView(status)
      if (isTerminalView(v)) {
        stopPolling()
        stopCardScan()
        const t = payViewToTerminal(v, status)
        if (t) onTerminal(t)
      }
    } catch (err) {
      if (stopped) return
      if (err instanceof ApiError && (err.status === 404 || err.code === 'InvoiceNotFound')) {
        notFoundStreak += 1
        if (notFoundStreak >= MAX_NOT_FOUND_STREAK) giveUpAsNotFound()
        return
      }
      /* other transient network errors: keep polling, don't count toward the streak */
    }
  }

  // ---------------------------------------------------------------------
  // Manual refresh (review item 10). Exposed as an instance export so a
  // later pull-to-refresh feature can trigger it — not implemented here.
  // ---------------------------------------------------------------------
  let refreshing = $state(false)

  export async function refreshNow(): Promise<void> {
    if (refreshing) return
    refreshing = true
    try {
      // poll() re-fetches status AND triggers a throttled Lightning refresh
      // when the offer is missing (via maybeRefreshLightning). Routing the
      // manual button + pull-to-refresh through the SAME throttle means an
      // explicit action can't hammer POST /lightning past the 15s failure
      // cooldown (finding #4).
      await poll()
    } finally {
      refreshing = false
    }
  }

  // Mount-only setup. The body MUST run exactly once: poll()/
  // maybeRefreshLightning() read reactive state ($state/$derived), so without
  // untrack this effect would subscribe to them and re-run on the first poll —
  // its cleanup (stopPolling) sets `stopped = true`, which the re-run never
  // resets, silently killing all polling after the first tick (finding #1).
  $effect(() => {
    untrack(() => {
      pollHandle = setInterval(poll, 3000)
      // Countdown is DISPLAY ONLY. Expiry is server-authoritative — the poller
      // terminalizes on status==='expired'; we never stop locally on the clock
      // (a fast device clock or an in-progress/settling payment near expiry
      // must not be shown as Expired while the server still resolves it —
      // finding #3, matching invoice_payment.html's countdown-text-only behavior).
      tickHandle = setInterval(() => {
        remainingMs = expiresAtUnix * 1000 - Date.now()
      }, 1000)
      void poll()
      // Reconstructed invoices seed lightning_pr as '' — fetch immediately
      // rather than waiting for the first poll's adoption check (fixes
      // "Lightning blank after reload").
      void maybeRefreshLightning()
    })
    return () => stopPolling()
  })

  // ---------------------------------------------------------------------
  // Zero-conf Liquid detection (§8). While Liquid is a live payable rail,
  // open the address-subscription WebSocket; any on-chain activity for the
  // address triggers an immediate poll (the server stays authoritative — the
  // WS never flips UI state, it only collapses the ≤3s poll latency). The
  // effect closes the socket on terminal/settlement views (liquidWatchable
  // goes false), on a Liquid-address change, and on unmount. Failures degrade
  // silently to the 3s poller (see lib/liquid-ws.ts).
  // ---------------------------------------------------------------------
  const liquidWatchable = $derived(showsRails(view) && (latest?.accept_liquid ?? true) && !!currentLiquidAddress)
  $effect(() => {
    if (!liquidWatchable || !currentLiquidAddress) return
    const watcher = watchLiquidAddress(currentLiquidAddress, () => void poll())
    return () => watcher.close()
  })

  // ---------------------------------------------------------------------
  // Rail QR payload (CONTRACT 2 builders). Prefers the polled
  // bitcoin_chain_bip21 over the fallback btcUri — the server re-issues
  // bip21 with the remaining amount after a partial payment
  // (src/invoice.rs:925-929).
  // ---------------------------------------------------------------------
  const qrValue = $derived.by(() => {
    if (activeTab === 'lightning') return currentLightningPr ?? ''
    if (remainingAmountSat === null) return ''
    if (activeTab === 'liquid') {
      return currentLiquidAddress ? liquidUri(currentLiquidAddress, remainingAmountSat, config.liquid_btc_asset_id) : ''
    }
    if (activeTab === 'bitcoin') {
      return currentBitcoinAddress ? bitcoinPayload(currentBitcoinAddress, currentBitcoinBip21, remainingAmountSat) : ''
    }
    return ''
  })

  const qrPlaceholder = $derived(activeTab === 'lightning' ? 'Loading Lightning offer…' : 'Preparing payment code…')

  // After a partial payment the original amount is misleading, so the primary
  // display switches to the remaining amount due (finding #5 / review item 5,
  // mirroring invoice_payment.html:597-600's "{remaining} sat remaining").
  const mainAmount = $derived(
    view.kind === 'partially_paid' && remainingAmountSat !== null
      ? `${new Intl.NumberFormat().format(remainingAmountSat)} sat`
      : amountLabel,
  )
</script>

<div class="mx-auto flex w-full max-w-md flex-col items-center gap-5">
  <div class="flex w-full flex-col items-center gap-1">
    <p class="font-display text-7xl tabular-nums tracking-display leading-none">{mainAmount}</p>
    <div class="flex items-center gap-1.5">
      <p class={`inline-flex items-center gap-1.5 text-xs font-semibold ${payViewTone(view)}`}>
        <span class="inline-block h-1.5 w-1.5 rounded-full bg-current"></span>
        {payViewLabel(view, remainingAmountSat)}
      </p>
      <button
        type="button"
        class="grid h-5 w-5 place-items-center rounded-full text-[#776b5a] transition hover:bg-[#eadfce] disabled:opacity-40 dark:text-[#b9aa91] dark:hover:bg-[#2c2922]"
        onclick={refreshNow}
        disabled={refreshing}
        aria-label="Refresh status"
      >
        <RefreshCw size={12} class={refreshing ? 'animate-spin' : ''} />
      </button>
    </div>
  </div>

  {#if showsRails(view)}
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
        {:else if cardState === 'preparing'}
          <BullSpinner size={72} label="Preparing Lightning offer…" />
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
    {:else if qrValue}
      <QrCard value={qrValue} label={`${railLabels[activeTab]} payment code`} />
    {:else}
      <div
        class="mx-auto grid w-full max-w-sm place-items-center rounded-lg border border-[#d7c8b4] bg-[#fffaf0] p-8 text-center text-sm text-[#776b5a] shadow-sm dark:border-[#3a342a] dark:bg-[#211f1a] dark:text-[#b9aa91]"
      >
        {qrPlaceholder}
      </div>
    {/if}

    <p class="text-center text-xs text-[#776b5a] tabular-nums dark:text-[#b9aa91]">Expires in {countdown}</p>
  {:else}
    <div class="flex flex-col items-center gap-3 py-10 text-center">
      <div
        class={`grid h-16 w-16 place-items-center rounded-full text-3xl ${
          view.kind === 'needs_review'
            ? 'bg-[#fff0c7] text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]'
            : 'bg-[#d9f3df] text-[#14522d] dark:bg-[#1f3d2a] dark:text-[#8bc8a4]'
        }`}
      >
        {view.kind === 'needs_review' ? '!' : '✓'}
      </div>
      <p class={`text-lg font-semibold ${payViewTone(view)}`}>{payViewLabel(view, remainingAmountSat)}</p>
      <p class="text-sm text-[#776b5a] dark:text-[#b9aa91]">
        {view.kind === 'needs_review' ? 'Settlement is delayed. The operator has been alerted.' : 'Settlement is in progress'}
      </p>
    </div>
  {/if}
</div>

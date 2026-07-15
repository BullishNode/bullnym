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
  import BitcoinRiskAcknowledgement from '$lib/components/BitcoinRiskAcknowledgement.svelte'
  import {
    ApiError,
    fetchLightningOffer,
    fetchPayerQuote,
    getInvoiceStatus,
    type CreateInvoiceResponse,
    type InvoiceStatus,
    type PayerQuoteRail,
  } from '$lib/api/client'
  import { localStore } from '$lib/stores/local.svelte'
  import { config } from '$lib/config'
  import { settings } from '$lib/stores/settings.svelte'
  import { scanForLnurl, payViaBoltCard } from '$lib/bolt-card/reader'
  import {
    bitcoinPaymentPayloadFromStatus,
    derivePayView,
    isTerminalView,
    isCancelableStatus,
    shouldPollDetail,
    showsRails,
    payViewLabel,
    payViewSupport,
    payViewTone,
    payViewToTerminal,
    shouldRefreshLightning,
    nextLightningPr,
    payViewBeforeFirstStatus,
    type PayView,
    type TerminalState,
  } from '$lib/status'
  import { availableRails } from '$lib/rails'
  import { liquidUri, bitcoinPayload } from '$lib/payloads'
  import { watchLiquidAddress } from '$lib/liquid-ws'
  import {
    beginBitcoinRiskAcknowledgementScope,
    mayRequestBitcoinQuote,
    mayUseBitcoinPaymentInstruction,
    preferredInitialFiatQuoteRail,
    preferredRailAfterBitcoinDecline,
    rememberBitcoinRiskAcknowledgement,
    requiresPosBitcoinAcknowledgement,
    type SessionStorageLike,
  } from '$lib/pos-bitcoin-risk'
  import {
    PayerQuoteCoordinator,
    assertLightningQuoteAuthorityCurrent,
    captureLightningQuoteAuthority,
    emptyPayerQuoteState,
    formatQuoteCountdown,
    quoteAccessibilityState,
    quoteRailPresentation,
    type LightningQuoteAuthority,
    type QuoteRefreshTrigger,
  } from '$lib/payer-quote'

  // Only repeated explicit not-found responses terminalize this view. Future
  // wire values are valid-but-unknown states and stay visible/polling.
  const MAX_NOT_FOUND_STREAK = 5

  let {
    invoice,
    nym,
    amountLabel,
    onTerminal,
    onCancelableChange,
  }: {
    invoice: CreateInvoiceResponse
    nym: string
    amountLabel: string
    /** Fires exactly once, the first time the invoice reaches a terminal PayView (see lib/status.ts's TerminalState / CONTRACT 5). */
    onTerminal: (t: TerminalState) => void
    /** Enables the outer Cancel/Back affordance only for a positively known
     * no-evidence state. */
    onCancelableChange?: (cancelable: boolean) => void
  } = $props()

  type Rail = 'lightning' | 'liquid' | 'bitcoin' | 'boltcard'

  const railLabels: Record<Rail, string> = {
    lightning: 'Lightning',
    liquid: 'Liquid',
    bitcoin: 'Bitcoin',
    boltcard: 'Tap Card',
  }

  // ---------------------------------------------------------------------
  // Live status. The create response remains a cache seed only; until the
  // first successful detail poll, the conservative `unknown` view hides every
  // instruction. Each successful poll replaces nullable payload state rather
  // than merging it, because null withdraws a stale/amount-mismatched offer.
  // ---------------------------------------------------------------------
  let latest = $state<InvoiceStatus | null>(null)
  let currentLightningAmountSat = $state<number | null>(
    untrack(() =>
      invoice.pricing_mode === 'sat_fixed' &&
      Number.isSafeInteger(invoice.lightning_amount_sat) &&
      (invoice.lightning_amount_sat ?? 0) > 0
        ? invoice.lightning_amount_sat
        : null,
    ),
  )
  let currentLightningPr = $state<string | null>(
    untrack(() =>
      invoice.pricing_mode === 'sat_fixed' && currentLightningAmountSat !== null
        ? (invoice.lightning_pr || null)
        : null,
    ),
  )
  let currentLiquidAmountSat = $state<number | null>(
    untrack(() =>
      invoice.pricing_mode === 'sat_fixed' &&
      Number.isSafeInteger(invoice.liquid_amount_sat) &&
      (invoice.liquid_amount_sat ?? 0) > 0
        ? invoice.liquid_amount_sat
        : null,
    ),
  )
  let currentLiquidAddress = $state<string | null>(
    untrack(() =>
      invoice.pricing_mode === 'sat_fixed' && currentLiquidAmountSat !== null
        ? (invoice.liquid_address || null)
        : null,
    ),
  )
  let currentBitcoinDirectAddress = $state<string | null>(null)
  let currentBitcoinChainAmountSat = $state<number | null>(
    untrack(() =>
      invoice.pricing_mode === 'sat_fixed' &&
      Number.isSafeInteger(invoice.bitcoin_chain_amount_sat) &&
      (invoice.bitcoin_chain_amount_sat ?? 0) > 0
        ? invoice.bitcoin_chain_amount_sat
        : null,
    ),
  )
  let currentBitcoinChainAddress = $state<string | null>(
    untrack(() =>
      invoice.pricing_mode === 'sat_fixed' && currentBitcoinChainAmountSat !== null
        ? invoice.bitcoin_chain_address
        : null,
    ),
  )
  let currentBitcoinChainBip21 = $state<string | null>(
    untrack(() =>
      invoice.pricing_mode === 'sat_fixed' && currentBitcoinChainAddress
        ? invoice.bitcoin_chain_bip21
        : null,
    ),
  )
  const currentBitcoinAddress = $derived(currentBitcoinChainAddress ?? currentBitcoinDirectAddress)

  let quoteState = $state(emptyPayerQuoteState())
  let quoteNowMs = $state(untrack(() => Date.now()))
  const quoteCoordinator = untrack(
    () =>
      new PayerQuoteCoordinator(
        invoice.invoice_id,
        (rail, trigger) =>
          fetchPayerQuote(
            invoice.invoice_id,
            rail === 'lightning' && trigger === 'initial' ? undefined : rail,
          ),
        () => Date.now(),
        (next) => (quoteState = next),
      ),
  )

  const view = $derived<PayView>(latest ? derivePayView(latest) : payViewBeforeFirstStatus())
  const support = $derived(payViewSupport(view))
  const isFiatFixed = $derived(
    latest?.pricing_mode === 'fiat_fixed' ||
      (!latest && invoice.pricing_mode === 'fiat_fixed'),
  )
  // Amount for payloads/Bolt Card. Deliberately NOT `?? invoice.amount_sat`
  // — remaining_amount_sat is always present on InvoiceStatus once polled;
  // null here means "haven't polled yet", not "unknown remaining amount".
  const remainingAmountSat = $derived<number | null>(latest?.remaining_amount_sat ?? null)
  // Offers can be re-issued with a later expiry; prefer the polled value.
  const expiresAtUnix = $derived(latest?.expires_at_unix ?? invoice.expires_at_unix)

  // Rail-tab gating (review item 1). `showsRails(view)` is the outer authority;
  // these flags decide which payloads are selectable after status is known.
  const satRails = $derived(
    availableRails({
      acceptLn: latest?.accept_ln,
      lightningPr: currentLightningPr,
      lightningAmountSat: currentLightningAmountSat,
      acceptLiquid: latest?.accept_liquid,
      liquidAddress: currentLiquidAddress,
      liquidAmountSat: currentLiquidAmountSat,
      acceptBtc: latest?.accept_btc,
      bitcoinAddress: currentBitcoinDirectAddress,
      bitcoinChainAddress: currentBitcoinChainAddress,
      bitcoinChainAmountSat: currentBitcoinChainAmountSat,
    }),
  )

  // Bolt Card is POS-only and Android Chrome-only. Gated defensively on
  // config.mode too, in addition to the
  // NDEFReader + settings toggle checks, so it can never leak into the
  // donation shell even if this shared component is reused elsewhere.
  const hasBoltCard = $derived(
    config.mode === 'pos' && typeof window !== 'undefined' && 'NDEFReader' in window && settings.boltCardEnabled,
  )

  const tabs = $derived.by<Rail[]>(() => {
    if (isFiatFixed) {
      const availability = latest?.quote_rail_availability
      if (!availability) return []
      return [
        ...(availability.lightning ? (['lightning'] as const) : []),
        ...(availability.liquid ? (['liquid'] as const) : []),
        ...(availability.bitcoin ? (['bitcoin'] as const) : []),
        ...(hasBoltCard && availability.lightning ? (['boltcard'] as const) : []),
      ]
    }
    return [
      ...(satRails.lightning ? (['lightning'] as const) : []),
      ...(satRails.liquid ? (['liquid'] as const) : []),
      ...(satRails.bitcoin ? (['bitcoin'] as const) : []),
      ...(hasBoltCard ? (['boltcard'] as const) : []),
    ]
  })

  const activeTabStore = untrack(() => localStore<Rail>(`bullnym:${nym}:rail`, 'lightning'))
  const bitcoinRiskStorage = untrack<SessionStorageLike | undefined>(() => {
    if (typeof window === 'undefined') return undefined
    try {
      return window.sessionStorage
    } catch {
      return undefined
    }
  })
  const acknowledgedAtMount = untrack(() =>
    beginBitcoinRiskAcknowledgementScope(
      config.mode,
      invoice.invoice_id,
      bitcoinRiskStorage,
    ),
  )
  const storedBitcoinRequested = untrack(
    () =>
      invoice.pricing_mode === 'sat_fixed' &&
      config.mode === 'pos' &&
      !acknowledgedAtMount &&
      activeTabStore.value === 'bitcoin',
  )
  let activeTab = $state<Rail>(
    untrack(() =>
      invoice.pricing_mode === 'fiat_fixed' || storedBitcoinRequested
        ? 'lightning'
        : activeTabStore.value,
    ),
  )
  let bitcoinAcknowledged = $state(acknowledgedAtMount)
  let bitcoinRiskOpen = $state(false)
  let pendingStoredBitcoin = $state(storedBitcoinRequested)
  let fiatInitialRequested = false
  const bitcoinInstructionAllowed = $derived(
    mayUseBitcoinPaymentInstruction(config.mode, bitcoinAcknowledged),
  )
  const activeQuoteRail = $derived<PayerQuoteRail>(activeTab === 'boltcard' ? 'lightning' : activeTab)
  const activeFiatPresentation = $derived(
    quoteRailPresentation(
      quoteState,
      activeQuoteRail,
      quoteNowMs,
      config.liquid_btc_asset_id,
    ),
  )
  const activeQuoteAccessibility = $derived(
    quoteAccessibilityState(quoteState, activeQuoteRail, quoteNowMs),
  )
  const fiatLightningPresentation = $derived(
    quoteRailPresentation(
      quoteState,
      'lightning',
      quoteNowMs,
      config.liquid_btc_asset_id,
    ),
  )
  const fiatQuoteCountdown = $derived(formatQuoteCountdown(quoteState, quoteNowMs))
  const displayedRemainingAmountSat = $derived(
    isFiatFixed ? (activeFiatPresentation?.merchantAmountSat ?? null) : remainingAmountSat,
  )

  function quoteRailAvailable(rail: PayerQuoteRail): boolean {
    return latest?.quote_rail_availability?.[rail] === true
  }

  function requestFiatQuote(
    rail: PayerQuoteRail,
    trigger: QuoteRefreshTrigger,
  ): Promise<unknown> | undefined {
    if (
      stopped ||
      !isFiatFixed ||
      !showsRails(view) ||
      !quoteRailAvailable(rail) ||
      (rail === 'bitcoin' && !mayRequestBitcoinQuote(config.mode, bitcoinAcknowledged))
    ) return
    return trigger === 'tab'
      ? quoteCoordinator.ensure(rail, trigger)
      : quoteCoordinator.refresh(rail, trigger)
  }

  function activateTab(tab: Rail) {
    // Keep this guard below every public selection path as a second line of
    // defence. Internal callers cannot reveal Bitcoin by assigning the rail.
    if (tab === 'bitcoin' && !bitcoinInstructionAllowed) {
      bitcoinRiskOpen = true
      return
    }
    if (activeTab === 'boltcard' && tab !== 'boltcard') {
      stopCardScan()
      cardState = 'idle'
      cardError = null
    }
    activeTab = tab
    activeTabStore.value = tab
    if (tab === 'boltcard') startCardScan()
  }

  function requestBitcoinTab() {
    if (requiresPosBitcoinAcknowledgement(config.mode, bitcoinAcknowledged)) {
      bitcoinRiskOpen = true
      return
    }
    activateTab('bitcoin')
    if (isFiatFixed) void requestFiatQuote('bitcoin', 'tab')
  }

  function acknowledgeBitcoinRisk() {
    rememberBitcoinRiskAcknowledgement(
      config.mode,
      invoice.invoice_id,
      bitcoinRiskStorage,
    )
    bitcoinAcknowledged = true
    bitcoinRiskOpen = false
    activateTab('bitcoin')
    if (isFiatFixed) {
      fiatInitialRequested = true
      void requestFiatQuote('bitcoin', 'tab')
    }
  }

  function leaveBitcoinRisk() {
    bitcoinRiskOpen = false
    const safeTab = preferredRailAfterBitcoinDecline(tabs)
    if (safeTab) activateTab(safeTab)
  }

  // Never show a selectable tab with a blank QR (today's bug — tabs used to
  // derive once from the create response, which is frozen at invoice
  // creation and can't reflect later accept-flag/payload changes). Runs at
  // mount (the seed may already exclude a rail the persisted tab pointed
  // at) and again any time `tabs` changes as poll data arrives.
  $effect(() => {
    if (tabs.length === 0) return
    if (tabs.includes(activeTab)) return
    const next = tabs.find((tab) => tab !== 'bitcoin' || bitcoinInstructionAllowed)
    if (!next) return
    activateTab(next)
  })

  // A Bitcoin preference belongs to the prior invoice, not the new PoS
  // session. Re-open the warning only after authoritative status says that
  // Bitcoin is available; no payload or quote request occurs underneath it.
  $effect(() => {
    if (!pendingStoredBitcoin || !showsRails(view) || !tabs.includes('bitcoin')) return
    pendingStoredBitcoin = false
    requestBitcoinTab()
  })

  $effect(() => {
    if (!showsRails(view) || !tabs.includes('bitcoin')) bitcoinRiskOpen = false
  })

  function selectTab(tab: Rail) {
    if (tab === 'bitcoin') {
      requestBitcoinTab()
      return
    }
    activateTab(tab)
    if (isFiatFixed) void requestFiatQuote(tab === 'boltcard' ? 'lightning' : tab, 'tab')
  }

  // The first trustworthy fiat status starts exactly one default Lightning
  // POST. Other rails remain lazy and are requested only when selected.
  $effect(() => {
    const status = latest
    if (!status || !isFiatFixed || !showsRails(view) || fiatInitialRequested) return
    const availability = status.quote_rail_availability
    if (!availability) return
    const initialRail = preferredInitialFiatQuoteRail(
      config.mode,
      bitcoinAcknowledged,
      availability,
    )
    if (!initialRail) return
    fiatInitialRequested = true
    activateTab(initialRail)
    void requestFiatQuote(initialRail, 'initial')
  })

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
    if (isFiatFixed) return
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
      const amountSat = Number.isSafeInteger(res.lightning_amount_sat) && res.lightning_amount_sat > 0
        ? res.lightning_amount_sat
        : null
      currentLightningPr = res.pr && amountSat !== null ? res.pr : null
      currentLightningAmountSat = currentLightningPr ? amountSat : null
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
  let cardFiatAuthority: LightningQuoteAuthority | null = null

  // While there's no current offer (empty or mid-refresh) or the remaining
  // amount isn't known yet, Tap Card must not start a scan (don't throw on
  // a null amount like the pre-rewrite version did) — show a waiting state
  // instead.
  const boltCardLightningPr = $derived(
    isFiatFixed && fiatLightningPresentation
      ? fiatLightningPresentation.qrValue
      : currentLightningPr,
  )
  const boltCardAmountSat = $derived(
    isFiatFixed && fiatLightningPresentation
      ? fiatLightningPresentation.payerAmountSat
      : currentLightningAmountSat,
  )
  const boltCardRefreshing = $derived(
    isFiatFixed ? quoteState.pending.lightning : lnRefreshing,
  )
  const boltCardReady = $derived(
    showsRails(view) &&
      !!boltCardLightningPr &&
      !boltCardRefreshing &&
      boltCardAmountSat !== null,
  )

  function stopCardScan() {
    cardAbort?.abort()
    cardAbort = undefined
    cardFiatAuthority = null
  }

  function startCardScan() {
    stopCardScan()
    cardError = null
    if (!untrack(() => boltCardReady)) {
      cardState = 'preparing'
      return
    }
    const fiatAuthority = untrack(() =>
      isFiatFixed
        ? captureLightningQuoteAuthority(quoteState, Date.now())
        : null,
    )
    if (untrack(() => isFiatFixed) && !fiatAuthority) {
      cardState = 'preparing'
      return
    }
    cardState = 'scanning'
    const controller = new AbortController()
    cardAbort = controller
    cardFiatAuthority = fiatAuthority
    scanForLnurl(controller.signal)
      .then(async (lnurl) => {
        if (controller.signal.aborted) return
        cardState = 'requesting'
        const pr = fiatAuthority?.bolt11 ?? boltCardLightningPr
        const amt = fiatAuthority?.payerAmountSat ?? boltCardAmountSat
        if (!pr || amt === null) throw new Error('Lightning offer not ready — try again in a moment')
        await payViaBoltCard(lnurl, pr, amt, {
          signal: controller.signal,
          assertCurrent: fiatAuthority
            ? () => assertLightningQuoteAuthorityCurrent(quoteState, fiatAuthority, Date.now())
            : undefined,
        })
        if (controller.signal.aborted) return
        cardState = 'sent'
        // Success detection is the existing status poller below — no
        // second poller here.
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return
        if (err instanceof DOMException && err.name === 'AbortError') {
          cardFiatAuthority = null
          cardState = 'preparing'
          return
        }
        cardState = 'declined'
        cardError = err instanceof Error ? err.message : 'Card declined'
      })
  }

  // A card operation is authority-bound, not merely UI-bound. Pending,
  // unavailable, replaced, or expired fiat Lightning state invalidates the
  // exact token captured when scanning began and aborts every remote await.
  $effect(() => {
    const currentAuthority = isFiatFixed
      ? captureLightningQuoteAuthority(quoteState, quoteNowMs)
      : null
    if (!isFiatFixed) return
    untrack(() => {
      if (
        (cardState === 'scanning' || cardState === 'requesting') &&
        cardFiatAuthority?.key !== currentAuthority?.key
      ) {
        stopCardScan()
        cardError = null
        cardState = 'preparing'
      }
    })
  })

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
    clearPollInterval()
    if (tickHandle) clearInterval(tickHandle)
    onCancelableChange?.(false)
  }

  function clearPollInterval() {
    if (pollHandle) clearInterval(pollHandle)
    pollHandle = undefined
  }

  function ensurePollInterval() {
    if (stopped || pollHandle) return
    pollHandle = setInterval(poll, 3000)
  }

  function reconcilePollInterval(status: InvoiceStatus, currentView: PayView) {
    if (shouldPollDetail(status, currentView)) ensurePollInterval()
    else clearPollInterval()
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
      notFoundStreak = 0

      if (status.pricing_mode === 'sat_fixed') {
        // Sat-fixed retains the legacy independent instruction flow.
        const nextPr = nextLightningPr(currentLightningPr, status)
        const nextLightningAmountSat = Number.isSafeInteger(status.lightning_amount_sat) && (status.lightning_amount_sat ?? 0) > 0
          ? status.lightning_amount_sat
          : null
        currentLightningPr = nextPr && nextLightningAmountSat !== null ? nextPr : null
        currentLightningAmountSat = currentLightningPr ? nextLightningAmountSat : null
        const nextLiquidAmountSat = Number.isSafeInteger(status.liquid_amount_sat) && (status.liquid_amount_sat ?? 0) > 0
          ? status.liquid_amount_sat
          : null
        currentLiquidAddress = status.liquid_address && nextLiquidAmountSat !== null
          ? status.liquid_address
          : null
        currentLiquidAmountSat = currentLiquidAddress ? nextLiquidAmountSat : null
        const bitcoin = bitcoinPaymentPayloadFromStatus(status)
        currentBitcoinDirectAddress = bitcoin.directAddress
        currentBitcoinChainAddress = bitcoin.chainAddress
        currentBitcoinChainBip21 = bitcoin.chainBip21
        currentBitcoinChainAmountSat = bitcoin.chainAmountSat
      } else {
        // Fiat GETs are projection-only. Never reconstruct an instruction
        // from their nullable legacy fields; only the quote POST may fill it.
        currentLightningPr = null
        currentLightningAmountSat = null
        currentLiquidAddress = null
        currentLiquidAmountSat = null
        currentBitcoinDirectAddress = null
        currentBitcoinChainAddress = null
        currentBitcoinChainBip21 = null
        currentBitcoinChainAmountSat = null
      }
      // Publish the new view only after every payload has been replaced, so a
      // payable render cannot observe the prior snapshot for one frame.
      latest = status
      onCancelableChange?.(isCancelableStatus(status))

      void maybeRefreshLightning()

      const v = derivePayView(status)
      if (!showsRails(v)) stopCardScan()
      if (isTerminalView(v)) {
        stopPolling()
        stopCardScan()
        const t = payViewToTerminal(v, status)
        if (t) onTerminal(t)
      } else {
        reconcilePollInterval(status, v)
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
      if (isFiatFixed) {
        await requestFiatQuote(activeQuoteRail, 'manual')
      }
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
      ensurePollInterval()
      // The outer invoice countdown remains display-only and server-authoritative.
      // The five-minute quote clock is different: it locally suppresses stale
      // copy/QR state, while the server remains authoritative for payment state.
      tickHandle = setInterval(() => {
        const now = Date.now()
        remainingMs = expiresAtUnix * 1000 - now
        quoteNowMs = now
      }, 1000)
      void poll()
      // This is intentionally a no-op for the conservative pre-status view.
      // Once poll() establishes payability, it calls the same helper again and
      // requests a missing/expired offer without exposing cached instructions.
      void maybeRefreshLightning()
    })
    return () => stopPolling()
  })

  // Wake at the exact immutable quote boundary instead of waiting for the
  // display tick. Retire every rail first, then request only the selected one;
  // the coordinator coalesces this with manual/tab/reload races.
  $effect(() => {
    const quote = quoteState.quote
    if (!isFiatFixed || !quote || stopped) return
    const delay = Math.max(0, quote.expires_at_unix * 1000 - Date.now()) + 1
    const handle = setTimeout(() => {
      quoteNowMs = Date.now()
      if (quoteCoordinator.expire(quoteNowMs)) {
        void requestFiatQuote(activeQuoteRail, 'timer')
      }
    }, delay)
    return () => clearTimeout(handle)
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
  const fiatLiquidAddress = $derived.by(() => {
    const snapshot = quoteState.rails.liquid
    return snapshot?.instruction.kind === 'liquid_direct' &&
      quoteNowMs < snapshot.quote.expires_at_unix * 1_000
      ? snapshot.instruction.address
      : null
  })
  const liquidWatchAddress = $derived(isFiatFixed ? fiatLiquidAddress : currentLiquidAddress)
  const liquidWatchable = $derived(
    showsRails(view) &&
      (latest?.quote_rail_availability?.liquid ?? latest?.accept_liquid ?? true) &&
      !!liquidWatchAddress,
  )
  $effect(() => {
    if (!liquidWatchable || !liquidWatchAddress) return
    const watcher = watchLiquidAddress(liquidWatchAddress, () => void poll())
    return () => watcher.close()
  })

  // ---------------------------------------------------------------------
  // Rail QR payload (CONTRACT 2 builders). A server-supplied chain BIP21 is
  // bound to its chain lockup. If the chain offer is withdrawn, direct BTC may
  // remain, but the old chain address/BIP21 must never be reused or synthesized
  // with the new remaining amount.
  // ---------------------------------------------------------------------
  const qrValue = $derived.by(() => {
    if (isFiatFixed) {
      if (activeTab === 'bitcoin' && !bitcoinInstructionAllowed) return ''
      return activeFiatPresentation?.qrValue ?? ''
    }
    if (activeTab === 'lightning') return currentLightningPr ?? ''
    if (activeTab === 'liquid') {
      return currentLiquidAddress && currentLiquidAmountSat !== null
        ? liquidUri(currentLiquidAddress, currentLiquidAmountSat, config.liquid_btc_asset_id)
        : ''
    }
    if (activeTab === 'bitcoin') {
      if (!bitcoinInstructionAllowed) return ''
      if (remainingAmountSat === null) return ''
      const bip21 = currentBitcoinChainAddress ? currentBitcoinChainBip21 : null
      const amountSat = currentBitcoinChainAddress ? currentBitcoinChainAmountSat : remainingAmountSat
      return currentBitcoinAddress && amountSat !== null
        ? bitcoinPayload(currentBitcoinAddress, bip21, amountSat)
        : ''
    }
    return ''
  })

  const bitcoinChainSwapCostSat = $derived.by(() => {
    if (
      !currentBitcoinChainAddress ||
      currentBitcoinChainAmountSat === null ||
      remainingAmountSat === null
    ) return null
    const cost = currentBitcoinChainAmountSat - remainingAmountSat
    return Number.isSafeInteger(cost) && cost >= 0 ? cost : null
  })

  const lightningSwapCostSat = $derived.by(() => {
    if (currentLightningAmountSat === null || remainingAmountSat === null) return null
    const cost = currentLightningAmountSat - remainingAmountSat
    return Number.isSafeInteger(cost) && cost >= 0 ? cost : null
  })

  const qrPlaceholder = $derived.by(() => {
    if (isFiatFixed) {
      if (activeQuoteAccessibility.busy) return `Refreshing ${railLabels[activeTab]} quote…`
      if (quoteState.errors[activeQuoteRail]) {
        return `${railLabels[activeTab]} is temporarily unavailable. Choose another rail or retry.`
      }
      return `Preparing ${railLabels[activeTab]} quote…`
    }
    return activeTab === 'lightning' ? 'Loading Lightning offer…' : 'Preparing payment code…'
  })

  // After a partial payment the original amount is misleading, so the primary
  // display switches to the remaining amount due (finding #5 / review item 5,
  // mirroring invoice_payment.html:597-600's "{remaining} sat remaining").
  const mainAmount = $derived(
    !isFiatFixed &&
      (view.kind === 'partially_paid' || view.kind === 'partially_paid_pending') &&
      remainingAmountSat !== null
      ? `${new Intl.NumberFormat().format(remainingAmountSat)} sat`
      : amountLabel,
  )
  const problemView = $derived(
    view.kind === 'needs_review' || view.kind === 'resolution_pending' || view.kind === 'unknown',
  )
</script>

<div
  class="mx-auto flex w-full max-w-md flex-col items-center gap-5"
  inert={bitcoinRiskOpen}
  aria-hidden={bitcoinRiskOpen ? 'true' : undefined}
>
  <div class="flex w-full flex-col items-center gap-1">
    <p class="font-display text-7xl tabular-nums tracking-display leading-none">{mainAmount}</p>
    <div class="flex items-center gap-1.5">
      <p class={`inline-flex items-center gap-1.5 text-xs font-semibold ${payViewTone(view)}`}>
        <span class="inline-block h-1.5 w-1.5 rounded-full bg-current"></span>
        {payViewLabel(view, displayedRemainingAmountSat)}
      </p>
      <button
        type="button"
        class="grid h-5 w-5 place-items-center rounded-full text-[#776b5a] transition hover:bg-[#eadfce] disabled:opacity-40 dark:text-[#b9aa91] dark:hover:bg-[#2c2922]"
        onclick={refreshNow}
        disabled={refreshing}
        aria-label={isFiatFixed ? 'Refresh status and selected payment quote' : 'Refresh status'}
        aria-busy={refreshing}
      >
        <RefreshCw size={12} class={refreshing ? 'animate-spin' : ''} />
      </button>
    </div>
    {#if showsRails(view) && support}
      <p class="text-center text-xs text-[#776b5a] dark:text-[#b9aa91]">{support}</p>
    {/if}
  </div>

  {#if showsRails(view)}
    <div
      class="inline-flex rounded-md bg-[#eadfce] p-0.5 text-xs dark:bg-[#2c2922]"
      role="tablist"
      aria-label="Payment rail"
    >
      {#each tabs as tab (tab)}
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === tab}
          aria-controls="payment-rail-panel"
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

    {#if isFiatFixed && activeFiatPresentation && (activeTab !== 'bitcoin' || bitcoinInstructionAllowed)}
      <div class="flex flex-col items-center gap-1 text-center">
        <p class="font-display text-4xl tabular-nums tracking-display leading-none">
          Send {new Intl.NumberFormat().format(activeFiatPresentation.payerAmountSat)} sats
        </p>
        <p class="max-w-sm text-xs text-[#776b5a] dark:text-[#b9aa91]">
          {#if activeFiatPresentation.swapCostSat > 0}
            Includes {new Intl.NumberFormat().format(activeFiatPresentation.swapCostSat)} sats in swap costs;
          {/if}
          your wallet may add its own {railLabels[activeTab]} network or routing fee.
        </p>
      </div>
    {:else if !isFiatFixed && activeTab === 'lightning' && currentLightningAmountSat !== null && lightningSwapCostSat !== null}
      <div class="flex flex-col items-center gap-1 text-center">
        <p class="font-display text-4xl tabular-nums tracking-display leading-none">
          Send {new Intl.NumberFormat().format(currentLightningAmountSat)} sats
        </p>
        <p class="max-w-sm text-xs text-[#776b5a] dark:text-[#b9aa91]">
          Includes {new Intl.NumberFormat().format(lightningSwapCostSat)} sats in swap costs; your wallet may add its own Lightning routing fee.
        </p>
      </div>
    {:else if !isFiatFixed && activeTab === 'liquid' && currentLiquidAmountSat !== null}
      <div class="flex flex-col items-center gap-1 text-center">
        <p class="font-display text-4xl tabular-nums tracking-display leading-none">
          Send {new Intl.NumberFormat().format(currentLiquidAmountSat)} sats
        </p>
        <p class="max-w-sm text-xs text-[#776b5a] dark:text-[#b9aa91]">
          Your wallet may add its own Liquid network fee.
        </p>
      </div>
    {:else if bitcoinInstructionAllowed && !isFiatFixed && activeTab === 'bitcoin' && currentBitcoinChainAddress && currentBitcoinChainAmountSat !== null && bitcoinChainSwapCostSat !== null}
      <div class="flex flex-col items-center gap-1 text-center">
        <p class="font-display text-4xl tabular-nums tracking-display leading-none">
          Send {new Intl.NumberFormat().format(currentBitcoinChainAmountSat)} sats
        </p>
        <p class="max-w-sm text-xs text-[#776b5a] dark:text-[#b9aa91]">
          Includes {new Intl.NumberFormat().format(bitcoinChainSwapCostSat)} sats in swap costs; your wallet may add its own Bitcoin network fee.
        </p>
      </div>
    {:else if bitcoinInstructionAllowed && !isFiatFixed && activeTab === 'bitcoin' && currentBitcoinDirectAddress && remainingAmountSat !== null}
      <div class="flex flex-col items-center gap-1 text-center">
        <p class="font-display text-4xl tabular-nums tracking-display leading-none">
          Send {new Intl.NumberFormat().format(remainingAmountSat)} sats
        </p>
        <p class="max-w-sm text-xs text-[#776b5a] dark:text-[#b9aa91]">
          Your wallet may add its own Bitcoin network fee.
        </p>
      </div>
    {/if}

    <div
      id="payment-rail-panel"
      role="tabpanel"
      class="contents"
      aria-live="polite"
      aria-busy={isFiatFixed && activeQuoteAccessibility.busy}
    >
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
      {#key isFiatFixed ? `${activeFiatPresentation?.quoteVersionId}:${activeTab}` : `${activeTab}:${qrValue}`}
        <QrCard value={qrValue} label={`${railLabels[activeTab]} payment code`} />
      {/key}
    {:else}
      <div
        class="mx-auto grid w-full max-w-sm place-items-center gap-3 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] p-8 text-center text-sm text-[#776b5a] shadow-sm dark:border-[#3a342a] dark:bg-[#211f1a] dark:text-[#b9aa91]"
        role="status"
      >
        <span>{qrPlaceholder}</span>
        {#if isFiatFixed && quoteState.errors[activeQuoteRail] && !activeQuoteAccessibility.busy}
          <Button variant="secondary" onclick={() => requestFiatQuote(activeQuoteRail, 'manual')}>
            Retry {railLabels[activeTab]}
          </Button>
        {/if}
      </div>
    {/if}
    </div>

    <p class="text-center text-xs text-[#776b5a] tabular-nums dark:text-[#b9aa91]">
      {isFiatFixed ? 'Quote' : 'Invoice'} expires in {isFiatFixed ? fiatQuoteCountdown : countdown}
    </p>
  {:else}
    <div class="flex flex-col items-center gap-3 py-10 text-center">
      <div
        class={`grid h-16 w-16 place-items-center rounded-full text-3xl ${
          problemView
            ? 'bg-[#fff0c7] text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]'
            : 'bg-[#d9f3df] text-[#14522d] dark:bg-[#1f3d2a] dark:text-[#8bc8a4]'
        }`}
      >
        {problemView ? '!' : '✓'}
      </div>
      {#if !problemView}
        <p class="font-display text-5xl tabular-nums tracking-display leading-none text-[#211f1a] dark:text-[#fff6e8]">
          {amountLabel}
        </p>
      {/if}
      <p class={`text-lg font-semibold ${payViewTone(view)}`}>{payViewLabel(view, displayedRemainingAmountSat)}</p>
      <p class="text-sm text-[#776b5a] dark:text-[#b9aa91]">
        {support ?? 'Settlement status is being checked'}
      </p>
    </div>
  {/if}
</div>

<BitcoinRiskAcknowledgement
  open={bitcoinRiskOpen}
  onAcknowledge={acknowledgeBitcoinRisk}
  onBack={leaveBitcoinRisk}
/>

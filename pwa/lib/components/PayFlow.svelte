<script lang="ts">
  // Extracted from apps/pos/screens/PayScreen.svelte + apps/donation/
  // App.svelte's payment/success screens (review item 3 + Lee's ask): both
  // apps were duplicating invoice-loading, cache-lookup/reconstruction, and
  // terminal-panel rendering with only cosmetic differences (header row,
  // success button labels, whether a paid sale gets recorded to local
  // history). PayFlow.svelte is the single owner of that shared machinery;
  // PayScreen.svelte and donation's pay route are now thin wrappers that
  // only supply the per-mode bits via props/snippets below.
  //
  // OWNS: (a) invoice loading — cache hit (from invoiceCache.ts) vs.
  // reconstruction (lib/invoice-load.ts, deep link / reload); (b) the
  // terminal panels for every TerminalState PaymentScreen.svelte reports
  // (paid/overpaid → SuccessScreen; underpaid/expired/cancelled/refunded/
  // not_found → a plain status panel). PaymentScreen.svelte itself renders
  // only the LIVE (non-terminal) views.
  import type { Snippet } from 'svelte'
  import { RefreshCw } from 'lucide-svelte'
  import { config } from '$lib/config'
  import type { InvoiceStatus } from '$lib/api/client'
  import { getCachedInvoice, amountLabelFor, type CachedInvoice } from '$lib/stores/invoiceCache'
  import { reconstructInvoice } from '$lib/invoice-load'
  import { railLabel } from '$lib/rails'
  import type { TerminalState } from '$lib/status'
  import PaymentScreen from '$lib/components/PaymentScreen.svelte'
  import SuccessScreen from '$lib/components/SuccessScreen.svelte'
  import BullSpinner from '$lib/components/BullSpinner.svelte'
  import Button from '$lib/components/Button.svelte'

  let {
    id,
    header,
    successActionLabel,
    onSuccessAction,
    successSecondaryLabel,
    onSuccessSecondary,
    onPaid,
    onExit,
  }: {
    id: string
    /** Single header row for every screen state (loading/error/live/terminal) — each caller supplies its own so it's never duplicated (the old bug: POS's PayScreen wrapped PaymentScreen, which used to render its own header too). */
    header: Snippet<[boolean]>
    successActionLabel: string
    onSuccessAction: () => void
    successSecondaryLabel?: string
    onSuccessSecondary?: () => void
    /**
     * POS: history.add(...) — fires for BOTH paid and overpaid (money WAS
     * received). Donation: omitted. Receives the full loaded context (note/
     * precision/currency/fiatAmountMinor) alongside the terminal status
     * since HistoryRecord needs fields InvoiceStatus alone can't always
     * supply (precision, the merchant note) — see PayScreen.svelte's onPaid.
     */
    onPaid?: (status: InvoiceStatus, ctx: CachedInvoice) => void
    /** Navigate back to the entry screen ('/'). Called automatically ~1.8s after an 'expired' terminal state (matching the pre-rewrite POS grace period), and by every other terminal panel's action button. */
    onExit: () => void
  } = $props()

  let loadState = $state<'loading' | 'ready' | 'error'>('loading')
  let loaded = $state<CachedInvoice | null>(null)
  let amountLabel = $state('')
  let loadError = $state<string | null>(null)
  let terminal = $state<TerminalState | null>(null)
  let canCancel = $state(false)

  $effect(() => {
    // Both callers wrap PayFlow in {#key id}, so an id change remounts us —
    // but a shared component shouldn't rely on that: guard the async
    // reconstruction so a stale id's response can't overwrite a newer load.
    let cancelled = false
    loadState = 'loading'
    terminal = null
    canCancel = false
    const cached = getCachedInvoice(id)
    if (cached) {
      loaded = cached
      amountLabel = amountLabelFor(cached)
      loadState = 'ready'
      return
    }
    // Deep link / page reload: the in-memory cache is gone. Reconstruct a
    // minimal invoice shape from the status endpoint.
    reconstructInvoice(id).then((res) => {
      if (cancelled) return
      if (!res.ok) {
        loadError = res.error
        loadState = 'error'
        return
      }
      loaded = {
        invoice: res.data.invoice,
        note: '',
        precision: res.data.precision,
        unit: res.data.unit,
        fiatAmountMinor: res.data.fiatAmountMinor,
        currency: res.data.currency,
        amountSat: res.data.amountSat,
      }
      amountLabel = res.data.amountLabel
      loadState = 'ready'
    })
    return () => {
      cancelled = true
    }
  })

  function handleTerminal(t: TerminalState) {
    canCancel = false
    terminal = t
    if ((t.kind === 'paid' || t.kind === 'overpaid') && loaded) {
      onPaid?.(t.status, loaded)
    }
  }

  // ---------------------------------------------------------------------
  // Pull-to-refresh (§7). Dependency-free (matches router.svelte.ts's
  // no-library approach): a downward drag from the top of the page while the
  // live PaymentScreen is mounted triggers the SAME refreshNow() as the
  // visible refresh button (which stays — kiosks may lack a touch-drag
  // affordance, and the reviewer explicitly asked for a visible action).
  // ---------------------------------------------------------------------
  const PULL_THRESHOLD = 70
  const PULL_MAX = 110
  let containerEl = $state<HTMLElement>()
  let paymentScreen = $state<{ refreshNow: () => Promise<void> }>()
  let pullY = $state(0)
  let ptrRefreshing = $state(false)

  $effect(() => {
    const el = containerEl
    if (!el) return
    let startY = 0
    let active = false

    const atTop = () => (document.scrollingElement?.scrollTop ?? window.scrollY) <= 0
    const canPull = () => loadState === 'ready' && !terminal && !ptrRefreshing && !!paymentScreen

    function onStart(e: TouchEvent) {
      if (!canPull() || e.touches.length !== 1 || !atTop()) {
        active = false
        return
      }
      startY = e.touches[0]!.clientY
      active = true
    }
    function onMove(e: TouchEvent) {
      if (!active) return
      const dy = e.touches[0]!.clientY - startY
      if (dy <= 0 || !atTop()) {
        pullY = 0
        return
      }
      // Rubber-band resistance; suppress native overscroll only while we're
      // actually driving the indicator.
      pullY = Math.min(dy * 0.5, PULL_MAX)
      if (pullY > 4) e.preventDefault()
    }
    async function onEnd() {
      if (!active) return
      active = false
      const trigger = pullY >= PULL_THRESHOLD
      if (trigger && paymentScreen) {
        ptrRefreshing = true
        pullY = PULL_THRESHOLD
        try {
          await paymentScreen.refreshNow()
        } finally {
          ptrRefreshing = false
          pullY = 0
        }
      } else {
        pullY = 0
      }
    }

    el.addEventListener('touchstart', onStart, { passive: true })
    el.addEventListener('touchmove', onMove, { passive: false })
    el.addEventListener('touchend', onEnd)
    el.addEventListener('touchcancel', onEnd)
    return () => {
      el.removeEventListener('touchstart', onStart)
      el.removeEventListener('touchmove', onMove)
      el.removeEventListener('touchend', onEnd)
      el.removeEventListener('touchcancel', onEnd)
    }
  })

  // Auto-return to entry ~1.8s after expiry, matching the pre-rewrite POS
  // UX (apps/pos/screens/PayScreen.svelte's old onExpired). Every other
  // terminal panel instead waits for the user to tap its action button.
  $effect(() => {
    if (terminal?.kind !== 'expired') return
    const t = setTimeout(() => onExit(), 1800)
    return () => clearTimeout(t)
  })
</script>

{#snippet terminalPanel(icon: string, tone: 'warn' | 'err', title: string, detail: string, actionLabel?: string)}
  <div class="mx-auto flex max-w-lg flex-col items-center gap-3 py-10 text-center">
    <div
      class={`grid h-20 w-20 place-items-center rounded-full text-4xl ${
        tone === 'err'
          ? 'bg-[#ffe0d9] text-[#8c2d28] dark:bg-[#3a211e] dark:text-[#e8a49e]'
          : 'bg-[#fff0c7] text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]'
      }`}
    >
      {icon}
    </div>
    <p class="font-display text-4xl uppercase tracking-display leading-none">{title}</p>
    <p class="text-sm text-[#776b5a] dark:text-[#b9aa91]">{detail}</p>
    {#if actionLabel}
      <Button variant="secondary" onclick={onExit}>{actionLabel}</Button>
    {/if}
  </div>
{/snippet}

<main bind:this={containerEl} class="min-h-screen bg-[#f5f0e8] text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
  <div class="mx-auto grid min-h-screen max-w-4xl grid-rows-1">
    <section class="px-5 py-5 sm:px-8">
      {@render header(canCancel)}

      {#if pullY > 0 || ptrRefreshing}
        <div
          class="flex items-center justify-center overflow-hidden text-[#776b5a] dark:text-[#b9aa91]"
          style={`height:${ptrRefreshing ? 36 : pullY}px`}
          aria-hidden="true"
        >
          <span style={`display:inline-flex;transform:rotate(${Math.min(pullY, PULL_THRESHOLD) * 2.5}deg)`}>
            <RefreshCw size={20} class={ptrRefreshing ? 'animate-spin' : ''} />
          </span>
        </div>
      {/if}

      {#if loadState === 'error'}
        <div class="mx-auto max-w-lg rounded-lg bg-[#ffe0d9] p-5 text-[#8c2d28]">
          <h1 class="text-xl font-bold">Could not prepare payment.</h1>
          <p class="mt-2">{loadError}</p>
          <div class="mt-4"><Button onclick={onExit}>Try Again</Button></div>
        </div>
      {:else if loadState === 'loading' || !loaded}
        <div class="grid min-h-[60vh] place-items-center">
          <BullSpinner size={72} label="Preparing" />
        </div>
      {:else if terminal}
        {#if terminal.kind === 'paid'}
          <SuccessScreen
            {amountLabel}
            rail={railLabel(terminal.status.paid_via)}
            actionLabel={successActionLabel}
            onaction={onSuccessAction}
            secondaryLabel={successSecondaryLabel}
            onsecondary={onSuccessSecondary}
          />
        {:else if terminal.kind === 'overpaid'}
          <div class="flex flex-col items-center gap-3">
            <SuccessScreen
              {amountLabel}
              rail={railLabel(terminal.status.paid_via)}
              actionLabel={successActionLabel}
              onaction={onSuccessAction}
              secondaryLabel={successSecondaryLabel}
              onsecondary={onSuccessSecondary}
            />
            <p class="max-w-sm rounded-md bg-[#fff0c7] px-4 py-3 text-center text-sm font-semibold text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]">
              Paid — overpaid: got {terminal.status.paid_amount_sat ?? terminal.status.amount_sat} sat, expected {terminal.status
                .amount_sat} sat
            </p>
          </div>
        {:else if terminal.kind === 'underpaid'}
          {@render terminalPanel(
            '!',
            'warn',
            'Underpaid',
            `Expected ${terminal.status.amount_sat} sat, got ${terminal.status.paid_amount_sat ?? 0} sat`,
            'Back',
          )}
        {:else if terminal.kind === 'expired'}
          {@render terminalPanel('×', 'err', 'Expired', 'This invoice expired without payment. Returning...')}
        {:else if terminal.kind === 'cancelled'}
          {@render terminalPanel('×', 'err', 'Cancelled', 'The recipient cancelled this invoice.', 'Back')}
        {:else if terminal.kind === 'refunded'}
          {@render terminalPanel('!', 'err', 'Settlement failed', 'The payment could not be settled.', 'Back')}
        {:else if terminal.kind === 'failed'}
          {@render terminalPanel('!', 'err', 'Settlement failed', 'The payment could not be settled.', 'Back')}
        {:else if terminal.kind === 'not_found'}
          {@render terminalPanel('×', 'err', 'Not found', 'This invoice could not be found.', 'Try Again')}
        {/if}
      {:else}
        <PaymentScreen
          bind:this={paymentScreen}
          invoice={loaded.invoice}
          nym={config.page_key}
          {amountLabel}
          onTerminal={handleTerminal}
          onCancelableChange={(value) => (canCancel = value)}
        />
      {/if}
    </section>
  </div>
</main>

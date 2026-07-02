<script lang="ts">
  // Reskinned to nostr-pos's Pos.svelte header
  // (~/apps/nostr-pos/apps/pos-pwa/src/routes/Pos.svelte): "Cancel sale"
  // link + History/Settings icon buttons. All invoice-loading, history-write,
  // and paid/expired handling logic is unchanged from prior milestones.
  import { History, Settings } from 'lucide-svelte'
  import { config } from '$lib/config'
  import {
    ApiError,
    getInvoiceStatus,
    getSupportedCurrencies,
    type CreateInvoiceResponse,
    type InvoiceStatus,
  } from '$lib/api/client'
  import { getCachedInvoice } from '$lib/stores/posInvoice'
  import { history } from '$lib/stores/history.svelte'
  import { formatFiat } from '$lib/money'
  import { router } from '$lib/router.svelte'
  import { railLabel } from '$lib/rails'
  import { KNOWN_STATUSES } from '$lib/status'
  import Button from '$lib/components/Button.svelte'
  import BullSpinner from '$lib/components/BullSpinner.svelte'
  import PaymentScreen from '$lib/components/PaymentScreen.svelte'
  import SuccessScreen from '$lib/components/SuccessScreen.svelte'

  let { id }: { id: string } = $props()

  let invoice = $state<CreateInvoiceResponse | null>(null)
  let note = $state('')
  let precision = $state(2)
  let fiatAmountMinor = $state(0)
  let currency = $state(config.currency)
  let loadError = $state<string | null>(null)
  let paidStatus = $state<InvoiceStatus | null>(null)
  let expired = $state(false)

  $effect(() => {
    const cached = getCachedInvoice(id)
    if (cached) {
      invoice = cached.invoice
      note = cached.note
      precision = cached.precision
      fiatAmountMinor = cached.fiatAmountMinor
      currency = cached.currency
      return
    }
    // Deep link / page reload: the in-memory cache is gone. Reconstruct a
    // minimal invoice shape from the status endpoint (CreateInvoiceResponse
    // itself is never persisted, only its request-time context was).
    //
    // True root cause of the "/#/pay/undefined polls forever with a bare
    // ERROR state" bug: the server deliberately returns HTTP 200 with an
    // LNURL-style (LUD-06) error envelope for most failures, including this
    // endpoint (src/error.rs) — e.g. {"status":"ERROR","code":
    // "InvoiceNotFound",...} for an id that never resolved to a real
    // invoice. lib/api/client.ts's request() now detects that envelope and
    // throws a real ApiError for it, so this hits .catch() below like any
    // other failed request. The KNOWN_STATUSES check stays as
    // belt-and-suspenders in case a genuinely-200 response ever carries an
    // InvoiceStatus.status value we don't model.
    Promise.all([getInvoiceStatus(id), getSupportedCurrencies().catch(() => null)])
      .then(([status, currencies]) => {
        if (!KNOWN_STATUSES.has(status.status)) {
          loadError = 'Invoice not found'
          return
        }
        invoice = {
          invoice_id: id,
          lightning_pr: status.lightning_pr ?? '',
          liquid_address: status.liquid_address ?? '',
          bitcoin_chain_address: status.bitcoin_chain_address,
          bitcoin_chain_bip21: status.bitcoin_chain_bip21,
          expires_at_unix: status.expires_at_unix,
        }
        currency = status.fiat_currency ?? config.currency
        fiatAmountMinor = status.fiat_amount_minor ?? 0
        const match = currencies?.currencies.find((c) => c.code === currency)
        precision = match?.precision ?? 2
      })
      .catch((err: unknown) => {
        loadError = err instanceof ApiError ? err.message : 'Invoice not found'
      })
  })

  const amountLabel = $derived(formatFiat(fiatAmountMinor, currency, precision))

  function onPaid(status: InvoiceStatus) {
    paidStatus = status
    history.add({
      id,
      amount_fiat_minor: status.fiat_amount_minor ?? fiatAmountMinor,
      currency: status.fiat_currency ?? currency,
      precision,
      amount_sat: status.paid_amount_sat ?? status.amount_sat,
      rail: status.paid_via,
      status: status.status,
      paid_at_unix: status.paid_at_unix,
      note,
      rate_minor_per_btc: status.rate_minor_per_btc,
    })
  }

  function onExpired() {
    expired = true
    setTimeout(() => router.go('/'), 1800)
  }

  function onNotFound() {
    invoice = null
    loadError = 'Invoice not found'
  }

  function goToReceipt() {
    router.go(`/receipt/${id}`)
  }

  function newSale() {
    router.go('/')
  }
</script>

<main class="min-h-screen bg-[#f5f0e8] text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
  <div class="mx-auto grid min-h-screen max-w-4xl grid-rows-1">
    <section class="px-5 py-5 sm:px-8">
      <header class="mb-6 flex items-center justify-between">
        <button
          type="button"
          class="inline-flex min-h-12 items-center gap-2 rounded-md px-2 text-sm font-semibold"
          onclick={newSale}
        >
          ← Cancel sale
        </button>
        <div class="flex items-center gap-2">
          <a
            class="grid min-h-12 min-w-12 place-items-center rounded-md bg-[#eadfce] text-[#211f1a] dark:bg-[#2c2922] dark:text-[#fff6e8]"
            href="#/history"
            aria-label="Recent transactions"
          >
            <History size={22} />
          </a>
          <a
            class="grid min-h-12 min-w-12 place-items-center rounded-md bg-[#eadfce] text-[#211f1a] dark:bg-[#2c2922] dark:text-[#fff6e8]"
            href="#/settings"
            aria-label="Settings"
          >
            <Settings size={22} />
          </a>
        </div>
      </header>

      {#if loadError}
        <div class="mx-auto max-w-lg rounded-lg bg-[#ffe0d9] p-5 text-[#8c2d28]">
          <h1 class="text-xl font-bold">Could not prepare payment.</h1>
          <p class="mt-2">{loadError}</p>
          <div class="mt-4"><Button href="#/">Try Again</Button></div>
        </div>
      {:else if expired}
        <div class="mx-auto max-w-lg rounded-lg bg-[#ffe0d9] p-5 text-center text-[#8c2d28]">
          <p class="font-display text-4xl uppercase tracking-display leading-none">Invoice expired</p>
          <p class="mt-2 text-sm">Returning to keypad...</p>
        </div>
      {:else if paidStatus}
        <SuccessScreen
          {amountLabel}
          rail={railLabel(paidStatus.paid_via)}
          actionLabel="New Sale"
          onaction={newSale}
          secondaryLabel="Print Receipt"
          onsecondary={goToReceipt}
        />
      {:else if invoice}
        <PaymentScreen {invoice} nym={config.nym} {amountLabel} {onPaid} {onExpired} {onNotFound} />
      {:else}
        <div class="grid min-h-[60vh] place-items-center">
          <BullSpinner size={72} label="Preparing" />
        </div>
      {/if}
    </section>
  </div>
</main>

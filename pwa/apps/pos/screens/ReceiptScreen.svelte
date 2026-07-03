<script lang="ts">
  // Reskinned to nostr-pos's Receipt.svelte
  // (~/apps/nostr-pos/apps/pos-pwa/src/routes/Receipt.svelte): back link +
  // Print/Share (or New sale) actions, ReceiptView card, paid/status
  // banner below. Paper-size handling (58mm/80mm/A4) and the fallback to
  // GET /api/v1/invoices/:id/status are our additions — upstream is
  // 80mm-only and always has local IndexedDB data, no server fallback.
  import { untrack } from 'svelte'
  import { Printer, RotateCw, Share2 } from 'lucide-svelte'
  import { config } from '$lib/config'
  import { history } from '$lib/stores/history.svelte'
  import { getInvoiceStatus, getSupportedCurrencies } from '$lib/api/client'
  import { formatFiat, formatSats, shortId } from '$lib/money'
  import { router } from '$lib/router.svelte'
  import { railLabel } from '$lib/rails'
  import { isTerminalPaid, statusLabel as statusLabelFor } from '$lib/status'
  import Button from '$lib/components/Button.svelte'
  import ReceiptView from '$lib/components/ReceiptView.svelte'

  let { id }: { id: string } = $props()

  type PaperSize = '58mm' | '80mm' | 'a4'

  function loadPaperSize(): PaperSize {
    try {
      const v = localStorage.getItem('bullnym:paper-size')
      if (v === '58mm' || v === '80mm' || v === 'a4') return v
    } catch {
      /* localStorage unavailable */
    }
    return '80mm'
  }

  const paperSize = loadPaperSize()

  const record = untrack(() => history.find(id))

  let fallback = $state<{
    fiat_amount_minor: number | null
    fiat_currency: string | null
    amount_sat: number
    paid_via: string | null
    paid_at_unix: number | null
    precision: number
    status: string
  } | null>(null)
  let notFound = $state(false)

  $effect(() => {
    if (record) return
    // Not in local history (cleared, different device, direct navigation).
    // Resolve precision from the currency's real precision rather than
    // hardcoding — CRC (precision 0) is the primary market, and defaulting
    // to 2 here would silently misprint amounts by 100x on paper.
    Promise.all([getInvoiceStatus(id), getSupportedCurrencies().catch(() => null)])
      .then(([s, currencies]) => {
        const currency = s.fiat_currency ?? config.currency
        const match = currencies?.currencies.find((c) => c.code === currency)
        fallback = {
          fiat_amount_minor: s.fiat_amount_minor,
          fiat_currency: currency,
          amount_sat: s.paid_amount_sat ?? s.amount_sat,
          paid_via: s.paid_via,
          paid_at_unix: s.paid_at_unix,
          precision: match?.precision ?? 2,
          status: s.status,
        }
      })
      .catch(() => {
        notFound = true
      })
  })

  const receiptNo = $derived.by(() => {
    const clean = id.replace(/-/g, '').toUpperCase()
    const last6 = clean.slice(-6).padStart(6, '0')
    return `${last6.slice(0, 2)}-${last6.slice(2)}`
  })

  const precision = $derived(record?.precision ?? fallback?.precision ?? 2)
  const amountMinor = $derived(record?.amount_fiat_minor ?? fallback?.fiat_amount_minor ?? 0)
  const currency = $derived(record?.currency ?? fallback?.fiat_currency ?? config.currency)
  const amountSat = $derived(record?.amount_sat ?? fallback?.amount_sat ?? 0)
  const rail = $derived(record?.rail ?? fallback?.paid_via ?? null)
  const paidAtUnix = $derived(record?.paid_at_unix ?? fallback?.paid_at_unix ?? null)
  const note = $derived(record?.note ?? '')
  const status = $derived(record?.status ?? fallback?.status ?? 'pending')
  const isPaid = $derived(isTerminalPaid(status))

  const dateLabel = $derived(paidAtUnix ? new Date(paidAtUnix * 1000).toLocaleString() : '—')

  async function share() {
    await navigator.share?.({ title: 'Receipt', url: location.href })
  }

  function printReceipt() {
    window.print()
  }

  function newSale() {
    router.go('/')
  }

  // Body class drives in-flow print typography (scoped selectors in
  // app.css). @page size/margin can't be conditioned on a class, so that
  // part is injected as a standalone style element for the component's life.
  $effect(() => {
    document.body.classList.add(`paper-${paperSize}`)
    return () => document.body.classList.remove(`paper-${paperSize}`)
  })

  $effect(() => {
    const pageSizes: Record<PaperSize, string> = { '58mm': '58mm auto', '80mm': '80mm auto', a4: 'A4' }
    const margins: Record<PaperSize, string> = { '58mm': '4mm', '80mm': '5mm', a4: '20mm' }
    const style = document.createElement('style')
    style.textContent = `@media print { @page { size: ${pageSizes[paperSize]}; margin: ${margins[paperSize]}; } }`
    document.head.appendChild(style)
    return () => style.remove()
  })
</script>

<main class="min-h-screen bg-[#f5f0e8] px-5 py-5 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
  <div class="no-print mx-auto mb-5 flex max-w-xl items-center justify-between">
    <button class="inline-flex min-h-12 items-center gap-2 rounded-md font-bold" onclick={newSale}>← Back</button>
    <div class="flex gap-2">
      {#if isPaid}
        <Button variant="secondary" onclick={printReceipt}><Printer size={18} />Print</Button>
        <Button variant="ghost" onclick={share}><Share2 size={18} />Share</Button>
      {:else}
        <Button href="#/" variant="secondary"><RotateCw size={18} />New sale</Button>
      {/if}
    </div>
  </div>

  {#if notFound}
    <p class="py-20 text-center">Receipt not found.</p>
  {:else}
    <ReceiptView
      merchantName={config.header || config.nym}
      posName={config.description || config.domain}
      receiptNumber={receiptNo}
      {dateLabel}
      methodLabel={railLabel(rail)}
      statusLabel={statusLabelFor(status)}
      amountSatsLabel={formatSats(amountSat)}
      amountFiatLabel={formatFiat(amountMinor, currency, precision)}
      {note}
      saleIdShort={shortId(id)}
    />
    <div class="no-print mx-auto mt-5 max-w-sm text-center">
      <div
        class={`rounded-md px-5 py-4 ${
          isPaid ? 'bg-[#d9f3df] text-[#14522d]' : 'bg-[#fff0c7] text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]'
        }`}
      >
        <p class="font-display text-5xl uppercase tracking-display leading-none">{isPaid ? 'Paid' : statusLabelFor(status)}</p>
        <p class="mt-1 text-sm">
          {#if isPaid}
            Receipt ready.
          {:else}
            Start a new sale.
          {/if}
        </p>
      </div>
    </div>
  {/if}
</main>

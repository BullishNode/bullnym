<script lang="ts">
  // Thin wrapper over PayFlow.svelte (review item 3): supplies POS's header
  // row (Cancel sale + History/Settings icons), success actions (New Sale +
  // Print Receipt), the onRecord history.add side effect (B2: records the sale
  // as soon as payment evidence appears and updates it on each status
  // transition — partial/settling/pending included — so the completed-sales
  // list carries every sale with money received, not only terminal paid), and
  // exit navigation (back to the keypad). All invoice-loading, polling, and
  // terminal-panel rendering now lives in PayFlow.svelte + PaymentScreen.svelte
  // — PaymentScreen is no longer imported directly here.
  import { History, Settings } from 'lucide-svelte'
  import type { InvoiceStatus } from '$lib/api/client'
  import type { CachedInvoice } from '$lib/stores/invoiceCache'
  import { history } from '$lib/stores/history.svelte'
  import { derivePayView, payViewRecordStatus } from '$lib/status'
  import { router } from '$lib/router.svelte'
  import PayFlow from '$lib/components/PayFlow.svelte'

  let { id }: { id: string } = $props()

  function onRecord(status: InvoiceStatus, ctx: CachedInvoice) {
    history.add({
      id,
      amount_fiat_minor: status.fiat_amount_minor ?? ctx.fiatAmountMinor ?? null,
      currency: status.fiat_currency ?? ctx.currency ?? null,
      precision: ctx.precision,
      amount_sat: status.paid_amount_sat ?? status.amount_sat,
      rail: status.paid_via,
      // Derived from the live view, not raw status.status: a partial can report
      // status.status==='unpaid', which would mislabel the row as waiting.
      status: payViewRecordStatus(derivePayView(status)),
      paid_at_unix: status.paid_at_unix,
      note: ctx.note,
      rate_minor_per_btc: status.rate_minor_per_btc,
    })
  }

  function newSale() {
    router.go('/')
  }

  function goToReceipt() {
    router.go(`/receipt/${id}`)
  }
</script>

{#snippet header(canCancel: boolean)}
  <header class="mb-6 flex items-center justify-between">
    <button
      type="button"
      class="inline-flex min-h-12 items-center gap-2 rounded-md px-2 text-sm font-semibold"
      onclick={newSale}
      disabled={!canCancel}
      aria-label={canCancel ? 'Cancel sale' : 'Cancel unavailable after payment evidence'}
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
{/snippet}

<PayFlow
  {id}
  {header}
  {onRecord}
  successActionLabel="New Sale"
  onSuccessAction={newSale}
  successSecondaryLabel="Print Receipt"
  onSuccessSecondary={goToReceipt}
  onExit={newSale}
/>

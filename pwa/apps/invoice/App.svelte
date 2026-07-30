<script lang="ts">
  import PayFlow from '$lib/components/PayFlow.svelte'
  import PrivateInvoiceCard from './PrivateInvoiceCard.svelte'
  import { parseInvoicePageConfig } from './config'

  const page = parseInvoicePageConfig()

  function reload() {
    location.reload()
  }
</script>

{#if page}
  {#snippet header(_canCancel: boolean)}
    <header class="mx-auto mb-6 max-w-xl text-center">
      <span class="inline-flex rounded-full border border-[#d7c8b4] bg-[#fffaf0] px-3 py-1 text-[0.68rem] font-bold uppercase tracking-[0.16em] text-[#776b5a] dark:border-[#3a342a] dark:bg-[#211f1a] dark:text-[#b9aa91]">
        Merchant invoice
      </span>
      <h1 class="mt-3 font-display text-5xl uppercase tracking-display leading-none sm:text-6xl">Invoice</h1>
      <p class="mx-auto mt-2 max-w-sm text-sm text-[#776b5a] dark:text-[#b9aa91]">
        Review the invoice details, then choose how you want to pay.
      </p>
    </header>
    {#if page.private_presentation}
      <PrivateInvoiceCard invoiceId={page.invoice_id} />
    {/if}
  {/snippet}

  <PayFlow
    id={page.invoice_id}
    {header}
    onExit={reload}
    autoExitExpired={false}
    paymentContextKey={`invoice:${page.invoice_id}`}
  />
{:else}
  <main class="grid min-h-screen place-items-center bg-[#f5f0e8] px-5 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
    <div class="max-w-sm text-center">
      <p class="font-display text-4xl uppercase tracking-display">Invoice unavailable</p>
      <p class="mt-2 text-sm text-[#776b5a] dark:text-[#b9aa91]">This invoice could not be prepared. Ask the merchant for a new link.</p>
    </div>
  </main>
{/if}

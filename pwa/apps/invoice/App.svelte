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
    <header class="mb-6 text-center">
      <p class="text-xs font-semibold uppercase tracking-[0.14em] text-[#776b5a] dark:text-[#b9aa91]">
        Bull Bitcoin payment request
      </p>
      <h1 class="mt-1 font-display text-4xl uppercase tracking-display leading-none">Pay invoice</h1>
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
      <p class="mt-2 text-sm text-[#776b5a] dark:text-[#b9aa91]">The payment page could not be prepared.</p>
    </div>
  </main>
{/if}

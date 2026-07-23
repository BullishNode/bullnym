<script lang="ts">
  import { onMount } from 'svelte'
  import Button from '$lib/components/Button.svelte'
  import { startPrivateInvoicePresentation } from '$lib/privateInvoice'

  let { invoiceId }: { invoiceId: string } = $props()

  onMount(() => {
    void startPrivateInvoicePresentation(invoiceId)
  })
</script>

<section
  id="private-invoice-presentation"
  class="invoice-document mb-6 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] p-5 shadow-sm dark:border-[#3a342a] dark:bg-[#211f1a] sm:p-6"
  hidden
></section>

<div
  id="private-invoice-warning"
  class="mb-4 rounded-md bg-[#fff0c7] px-4 py-3 text-sm font-semibold text-[#725315] dark:bg-[#3a321f] dark:text-[#f0d38a]"
  role="status"
  hidden
>
  Invoice details could not be displayed. The payment instructions remain valid.
</div>

<div id="private-invoice-link-actions" class="mb-6 flex gap-2" hidden>
  <div class="flex-1 [&>button]:w-full">
    <Button id="copy-private-invoice-link" variant="secondary">Copy private link</Button>
  </div>
  <div class="flex-1 [&>button]:w-full">
    <Button id="share-private-invoice-link" variant="secondary">Share</Button>
  </div>
</div>

<style>
  :global(.invoice-document-header) {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid #d7c8b4;
  }
  :global(.invoice-eyebrow),
  :global(.invoice-section-title) {
    margin: 0 0 0.35rem;
    color: #776b5a;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }
  :global(.invoice-document-title) {
    margin: 0;
    font-family: 'Bebas Neue', ui-sans-serif, system-ui, sans-serif;
    font-size: 2.5rem;
    font-weight: 500;
    letter-spacing: 0.03em;
    line-height: 1;
    text-transform: uppercase;
  }
  :global(.invoice-number) {
    max-width: 45%;
    color: #776b5a;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.75rem;
    overflow-wrap: anywhere;
    text-align: right;
  }
  :global(.invoice-date-grid) {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 1rem;
    margin: 1rem 0 0;
  }
  :global(.invoice-party),
  :global(.invoice-description-card) {
    margin-top: 1.25rem;
    padding-top: 1rem;
    border-top: 1px solid #e3d7c5;
  }
  :global(.invoice-detail-list) {
    display: grid;
    gap: 0.6rem;
    margin: 0;
  }
  :global(.invoice-detail) {
    display: grid;
    grid-template-columns: minmax(7rem, 0.38fr) minmax(0, 1fr);
    gap: 0.75rem;
  }
  :global(.invoice-detail-label) {
    color: #776b5a;
    font-size: 0.75rem;
  }
  :global(.invoice-detail-value) {
    margin: 0;
    font-size: 0.9rem;
    font-weight: 600;
    overflow-wrap: anywhere;
    white-space: pre-line;
  }
  :global(.invoice-date-overdue .invoice-detail:last-child .invoice-detail-value) {
    color: #a9362f;
  }
  @media (max-width: 420px) {
    :global(.invoice-date-grid),
    :global(.invoice-detail) {
      grid-template-columns: 1fr;
    }
    :global(.invoice-detail) {
      gap: 0.15rem;
    }
  }
  @media (prefers-color-scheme: dark) {
    :global(.invoice-document-header),
    :global(.invoice-party),
    :global(.invoice-description-card) {
      border-color: #3a342a;
    }
    :global(.invoice-eyebrow),
    :global(.invoice-section-title),
    :global(.invoice-number),
    :global(.invoice-detail-label) {
      color: #b9aa91;
    }
  }
</style>

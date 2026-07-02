<script lang="ts">
  // Reskinned to nostr-pos's Transactions.svelte
  // (~/apps/nostr-pos/apps/pos-pwa/src/routes/Transactions.svelte),
  // rendered with the ported TransactionSheet component.
  import { Settings } from 'lucide-svelte'
  import { config } from '$lib/config'
  import { history } from '$lib/stores/history.svelte'
  import TransactionSheet from '$lib/components/TransactionSheet.svelte'
  import BullFooter from '$lib/components/BullFooter.svelte'
</script>

<main class="min-h-screen bg-[#f5f0e8] px-5 py-5 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
  <div class="mx-auto max-w-3xl">
    <header class="mb-8 flex items-center justify-between gap-4">
      <a class="inline-flex min-h-12 items-center gap-2 rounded-md px-2 text-sm font-semibold" href="#/">← Back</a>
      <a
        class="grid min-h-12 min-w-12 place-items-center rounded-md bg-[#eadfce] text-[#211f1a] dark:bg-[#2c2922] dark:text-[#fff6e8]"
        href="#/settings"
        aria-label="Settings"
      >
        <Settings size={22} />
      </a>
    </header>

    <div class="mb-5">
      <h1 class="font-display text-4xl uppercase tracking-display leading-none">Recent transactions</h1>
      <p class="mt-1 text-xs font-medium uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">
        {config.header || config.nym}
      </p>
    </div>

    <TransactionSheet rows={history.records} />
    <BullFooter />
  </div>
</main>

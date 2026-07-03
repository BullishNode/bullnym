<script lang="ts">
  // POS mode shell — hash-routed over lib/router.svelte.ts. Deferred:
  // PWA manifest/service worker.
  import { router } from '$lib/router.svelte'
  import KeypadScreen from './screens/KeypadScreen.svelte'
  import PayScreen from './screens/PayScreen.svelte'
  import ReceiptScreen from './screens/ReceiptScreen.svelte'
  import HistoryScreen from './screens/HistoryScreen.svelte'
  import SettingsScreen from './screens/SettingsScreen.svelte'

  const payId = $derived(router.match('/pay/:id')?.id)
  const receiptId = $derived(router.match('/receipt/:id')?.id)
  const isHistory = $derived(router.path === '/history')
  const isSettings = $derived(router.path === '/settings')
</script>

{#if payId}
  {#key payId}
    <PayScreen id={payId} />
  {/key}
{:else if receiptId}
  {#key receiptId}
    <ReceiptScreen id={receiptId} />
  {/key}
{:else if isHistory}
  <HistoryScreen />
{:else if isSettings}
  <SettingsScreen />
{:else}
  <KeypadScreen />
{/if}

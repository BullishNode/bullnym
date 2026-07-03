<script lang="ts">
  // Reskinned to nostr-pos's muted-text convention (text-[#776b5a] /
  // dark:text-[#b9aa91], as used throughout Pos.svelte/Keypad.svelte for
  // secondary text). No direct upstream equivalent — nostr-pos doesn't
  // display a live fiat/BTC rate bar.
  import { rate } from '$lib/stores/rate.svelte'
  import { formatRate } from '$lib/money'

  let { precision = 2 }: { precision?: number } = $props()

  const ageLabel = $derived.by(() => {
    // rate.ageMs is already clamped at the source (lib/stores/rate.svelte.ts),
    // but clamp again here too — belt and suspenders against ever
    // rendering "-1s ago".
    const s = Math.max(0, Math.floor(rate.ageMs / 1000))
    if (s < 60) return `${s}s ago`
    return `${Math.floor(s / 60)}m ago`
  })
</script>

<div
  class={`text-center text-xs ${rate.available && rate.amber ? 'text-[#a9362f] dark:text-[#e8a49e]' : 'text-[#776b5a] dark:text-[#b9aa91]'}`}
>
  {#if rate.loading}
    Updating rate…
  {:else if !rate.available}
    rate unavailable
  {:else}
    Rate: {formatRate(rate.minorPerBtc, rate.currency, precision)} (updated {ageLabel})
  {/if}
</div>

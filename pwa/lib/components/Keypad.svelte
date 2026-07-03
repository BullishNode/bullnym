<script lang="ts">
  // Ported from nostr-pos
  // (~/apps/nostr-pos/apps/pos-pwa/src/lib/ui/Keypad.svelte). Single
  // onInput(key) callback (keys: '0'-'9', '.'/'00', 'back') replaces our
  // old ondigit/onbackspace pair — paired with the ported applyAmountInput
  // (lib/amount-input.ts) at call sites instead of a minor-unit
  // accumulator.
  //
  // Deviations from upstream, both product-driven (not fidelity misses):
  //  1. `precision` gates the bottom-left key: '.' for precision > 0, '00'
  //     for precision === 0 (upstream always shows '.' regardless of
  //     currency, which combined with formatFiatAmount's cents-on-'.'
  //     behavior let CRC — a zero-decimal currency — display "CRC 11.00").
  //  2. `precision={null}` renders the bottom-left slot as an inert empty
  //     placeholder instead of a key — used by the PIN pad (settings PIN
  //     set/challenge screens), which is digits-only and has no notion of
  //     a decimal or "00" shortcut.
  import { Delete } from 'lucide-svelte'

  let { precision = 2, onInput }: { precision?: number | null; onInput: (value: string) => void } = $props()

  const bottomLeft = $derived(precision === null ? null : precision > 0 ? '.' : '00')
  const keys = $derived<(string | null)[]>(['1', '2', '3', '4', '5', '6', '7', '8', '9', bottomLeft, '0', 'back'])

  function ariaLabel(key: string): string {
    if (key === 'back') return 'Delete digit'
    if (key === '.') return 'Add cents'
    if (key === '00') return 'Add zeros'
    return `Add ${key}`
  }
</script>

<div class="grid touch-manipulation select-none grid-cols-3 gap-3">
  {#each keys as key, i (i)}
    {#if key === null}
      <div class="h-[clamp(3.5rem,8.5dvh,5.5rem)]" aria-hidden="true"></div>
    {:else}
      <button
        type="button"
        class="grid h-[clamp(3.5rem,8.5dvh,5.5rem)] touch-manipulation select-none place-items-center rounded-md border border-[#d7c8b4] bg-[#fffaf0] text-3xl font-semibold tabular-nums text-[#211f1a] shadow-sm transition-transform duration-75 ease-out active:scale-[0.97] active:bg-[#ecdcc1] active:shadow-inner dark:border-[#3a342a] dark:bg-[#211f1a] dark:text-[#fff6e8] dark:active:bg-[#2f2a22]"
        aria-label={ariaLabel(key)}
        onclick={() => onInput(key)}
      >
        {#if key === 'back'}
          <Delete size={30} />
        {:else}
          {key}
        {/if}
      </button>
    {/if}
  {/each}
</div>

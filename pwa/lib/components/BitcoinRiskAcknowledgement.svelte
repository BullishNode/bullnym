<script lang="ts">
  import { tick } from 'svelte'
  import {
    nextDialogFocusIndex,
    POS_BITCOIN_ACKNOWLEDGEMENT,
    POS_BITCOIN_RISK_COPY,
  } from '$lib/pos-bitcoin-risk'

  let {
    open,
    onAcknowledge,
    onBack,
  }: {
    open: boolean
    onAcknowledge: () => void
    onBack: () => void
  } = $props()

  let backButton = $state<HTMLButtonElement>()
  let acknowledgeButton = $state<HTMLButtonElement>()

  $effect(() => {
    if (!open || typeof document === 'undefined') return

    const priorFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null
    const priorOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    void tick().then(() => backButton?.focus())

    return () => {
      document.body.style.overflow = priorOverflow
      priorFocus?.focus()
    }
  })

  function handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      event.preventDefault()
      onBack()
      return
    }
    if (event.key !== 'Tab') return

    const controls = [backButton, acknowledgeButton].filter(
      (element): element is HTMLButtonElement => !!element && !element.disabled,
    )
    if (controls.length === 0) return
    const current = controls.indexOf(document.activeElement as HTMLButtonElement)
    const next = nextDialogFocusIndex(current, controls.length, event.shiftKey)
    event.preventDefault()
    controls[next]?.focus()
  }
</script>

{#if open}
  <div
    class="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4"
    role="presentation"
    onclick={(event) => {
      if (event.target === event.currentTarget) onBack()
    }}
  >
    <div
      class="w-full max-w-md rounded-xl border border-[#d7c8b4] bg-[#fffaf0] p-6 shadow-2xl dark:border-[#3a342a] dark:bg-[#211f1a]"
      role="dialog"
      aria-modal="true"
      aria-labelledby="pos-bitcoin-risk-title"
      aria-describedby="pos-bitcoin-risk-description"
      tabindex="-1"
      onkeydown={handleKeydown}
    >
      <h2 id="pos-bitcoin-risk-title" class="font-display text-2xl text-[#211f1a] dark:text-[#fff6e8]">
        Before showing Bitcoin
      </h2>
      <p id="pos-bitcoin-risk-description" class="mt-3 text-sm leading-6 text-[#5f5547] dark:text-[#c9bca7]">
        {POS_BITCOIN_RISK_COPY}
      </p>
      <div class="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
        <button
          bind:this={backButton}
          type="button"
          class="inline-flex min-h-12 items-center justify-center rounded-md bg-[#eadfce] px-5 py-3 font-display text-lg uppercase tracking-[0.06em] text-[#2d2418] transition hover:bg-[#dfd1bc] active:translate-y-px dark:bg-[#2c2922] dark:text-[#fbf0df]"
          onclick={onBack}
        >
          Back
        </button>
        <button
          bind:this={acknowledgeButton}
          type="button"
          class="inline-flex min-h-12 items-center justify-center rounded-md bg-[#B7000B] px-5 py-3 font-display text-lg uppercase tracking-[0.06em] text-[#fffaf0] shadow-sm transition hover:bg-[#8f0009] active:translate-y-px"
          onclick={onAcknowledge}
        >
          {POS_BITCOIN_ACKNOWLEDGEMENT}
        </button>
      </div>
    </div>
  </div>
{/if}

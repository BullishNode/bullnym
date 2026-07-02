<script lang="ts">
  // Reskinned to nostr-pos's Keypad.svelte layout
  // (~/apps/nostr-pos/apps/pos-pwa/src/routes/Keypad.svelte): header with
  // merchant name + History/Settings icon buttons, big AmountDisplay,
  // Keypad, note field, bottom-pinned Charge button behind a gradient
  // fade. Upstream's terminal-activation/tab-lock/booting flow is
  // Nostr-specific infra that doesn't exist in our simpler server model —
  // dropped entirely, not ported. Amount entry now uses the ported
  // applyAmountInput decimal-string model instead of our old
  // whole/frac minor-unit accumulator.
  import { History, Settings } from 'lucide-svelte'
  import { config } from '$lib/config'
  import { createInvoice, getSupportedCurrencies, type CurrencyView, ApiError } from '$lib/api/client'
  import { rate } from '$lib/stores/rate.svelte'
  import { settings } from '$lib/stores/settings.svelte'
  import { router } from '$lib/router.svelte'
  import { cacheInvoice } from '$lib/stores/posInvoice'
  import { applyAmountInput } from '$lib/amount-input'
  import Keypad from '$lib/components/Keypad.svelte'
  import AmountDisplay from '$lib/components/AmountDisplay.svelte'
  import RateBar from '$lib/components/RateBar.svelte'
  import BullFooter from '$lib/components/BullFooter.svelte'
  import Button from '$lib/components/Button.svelte'

  let currencies = $state<CurrencyView[]>([{ code: settings.currency, precision: 2 }])
  let amount = $state('')
  let note = $state('')
  let creating = $state(false)
  let errorMsg = $state<string | null>(null)

  getSupportedCurrencies()
    .then((res) => {
      if (res.currencies.length > 0) currencies = res.currencies
    })
    .catch(() => {
      /* keep fallback single-currency list */
    })

  // Display currency can change out-of-band via /#/settings (this screen
  // fully remounts on navigation back, so no need to clamp in-progress
  // entry — it's simply gone). Keep the rate store in sync too.
  const precision = $derived(currencies.find((c) => c.code === settings.currency)?.precision ?? 2)

  $effect(() => {
    if (rate.currency !== settings.currency) rate.currency = settings.currency
  })

  const minor = $derived(Math.round(Number(amount || '0') * 10 ** precision))
  const canCharge = $derived(minor > 0 && rate.available && !creating)

  function applyInput(value: string) {
    amount = applyAmountInput(amount, value)
  }

  async function charge() {
    if (!canCharge) return
    creating = true
    errorMsg = null
    try {
      const res = await createInvoice(config.nym, {
        fiat_amount_minor: minor,
        fiat_currency: settings.currency,
      })
      cacheInvoice({
        invoice: res,
        note,
        precision,
        fiatAmountMinor: minor,
        currency: settings.currency,
      })
      amount = ''
      note = ''
      router.go(`/pay/${res.invoice_id}`)
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.isRateLimited) errorMsg = 'Too many requests, wait a moment'
        else if (e.status === 0) errorMsg = 'Server unreachable'
        else errorMsg = e.message || 'Something went wrong'
      } else {
        errorMsg = 'Something went wrong'
      }
    } finally {
      creating = false
    }
  }

  const displayAmount = $derived(amount || '0')
</script>

<main class="h-[100dvh] overflow-hidden bg-[#f5f0e8] text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
  <div class="mx-auto flex h-[100dvh] max-w-4xl flex-col overflow-hidden">
    <section class="flex min-h-0 flex-1 flex-col overflow-hidden px-5 py-3 sm:px-8 sm:py-5">
      <header class="mb-3 flex shrink-0 items-center justify-between gap-4 sm:mb-5">
        <div>
          <h1 class="font-display text-3xl uppercase tracking-display leading-none">{config.header || config.nym}</h1>
          {#if config.description}
            <p class="mt-0.5 text-xs font-medium uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">
              {config.description}
            </p>
          {/if}
        </div>
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

      <!-- my-auto inside overflow-y-auto: centers when the stack fits the
           viewport, scrolls (instead of clipping both ends, which
           justify-center + overflow-hidden does) when it doesn't. -->
      <div class="mx-auto flex min-h-0 w-full max-w-xl flex-1 flex-col overflow-y-auto">
        <div class="my-auto flex w-full flex-col gap-3 sm:gap-5">
        <AmountDisplay amount={displayAmount} currency={settings.currency} {precision} />
        <Keypad {precision} onInput={applyInput} />
        <textarea
          class="min-h-12 shrink-0 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] px-4 py-3 text-base outline-none focus:ring-2 focus:ring-[#B7000B] dark:border-[#3a342a] dark:bg-[#211f1a]"
          bind:value={note}
          placeholder="Add note"
          rows="1"
        ></textarea>
        <RateBar {precision} />
        {#if errorMsg}
          <p class="rounded-md bg-[#ffe0d9] px-4 py-3 text-sm font-semibold text-[#8c2d28]">{errorMsg}</p>
        {/if}
        <BullFooter />
        </div>
      </div>

      <div
        class="mx-auto mt-2 flex w-full max-w-xl shrink-0 flex-col bg-gradient-to-t from-[#f5f0e8] from-60% to-transparent pb-[max(0.25rem,env(safe-area-inset-bottom))] pt-2 dark:from-[#161512]"
      >
        <Button disabled={!canCharge || creating} onclick={charge}>
          {creating ? 'Preparing' : 'Charge'}
        </Button>
      </div>
    </section>
  </div>
</main>

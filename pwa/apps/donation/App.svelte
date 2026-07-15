<script lang="ts">
  // Reskinned to nostr-pos's design system/components — there's no
  // donation-mode screen upstream to port, so this arranges the same kit
  // (AmountDisplay, Keypad, Button, PayFlow, BullFooter) for the
  // payer-initiated single-screen flow, matching the visual language
  // exactly.
  //
  // The entry screen structurally mirrors apps/pos/screens/KeypadScreen.svelte
  // exactly (per design review): same h-[100dvh] overflow-hidden shell,
  // same max-w-4xl outer / max-w-xl inner column widths, same
  // gradient-pinned primary action at the bottom.
  //
  // review item 3 + Lee's ask: this now adopts the hash router (mirroring
  // apps/pos/App.svelte) instead of a local `screen` state machine, so a
  // donation invoice is reloadable/shareable at '#/pay/:id' — previously a
  // reload lost the invoice entirely (no cache, no reconstruction path).
  // The payment/success screens are now PayFlow.svelte (shared with POS)
  // instead of this file's own hand-rolled payment/success branches.
  //
  // review item 7: sat/BTC entry (templates/store_amount.html:134-146,
  // :210-215) — a pricer outage must not block donations, so sat/BTC never
  // touch the rate store and are always payable regardless of rate.available.
  import { Globe, Instagram, X } from 'lucide-svelte'
  import { config } from '$lib/config'
  import { createInvoice, getSupportedCurrencies, ApiError, type CurrencyView } from '$lib/api/client'
  import { rate } from '$lib/stores/rate.svelte'
  import { cryptoAmountSat } from '$lib/money'
  import { applyAmountInput } from '$lib/amount-input'
  import { cacheInvoice } from '$lib/stores/invoiceCache'
  import { router } from '$lib/router.svelte'
  import Keypad from '$lib/components/Keypad.svelte'
  import AmountDisplay from '$lib/components/AmountDisplay.svelte'
  import RateBar from '$lib/components/RateBar.svelte'
  import Button from '$lib/components/Button.svelte'
  import BullFooter from '$lib/components/BullFooter.svelte'
  import PayFlow from '$lib/components/PayFlow.svelte'

  let currencies = $state<CurrencyView[]>([{ code: config.currency, precision: 2 }])
  /** Either a real fiat ISO code, or the synthetic 'sat'/'btc' units (never sent to the rate store — see onCurrencyChange). */
  let currency = $state(config.currency)
  let amount = $state('')
  let message = $state('')
  let errorMsg = $state<string | null>(null)
  let creating = $state(false)

  const unit = $derived<'fiat' | 'sat' | 'btc'>(currency === 'sat' ? 'sat' : currency === 'btc' ? 'btc' : 'fiat')
  const precision = $derived(unit === 'sat' ? 0 : unit === 'btc' ? 8 : (currencies.find((c) => c.code === currency)?.precision ?? 2))
  const numericAmount = $derived(Number(amount || '0'))
  const fiatMinor = $derived(unit === 'fiat' ? Math.round(numericAmount * 10 ** precision) : 0)
  const cryptoSat = $derived(unit === 'fiat' ? 0 : cryptoAmountSat(numericAmount, unit))
  // Sat/BTC are always payable — that's the whole point of offering them:
  // a rate-source outage must not block a Bitcoiner from donating. Only a
  // fiat-denominated amount needs a live rate (the server locks its own
  // rate at invoice-creation time; rate.available just gates the entry UI).
  const canPay = $derived(unit === 'fiat' ? fiatMinor > 0 && rate.available && !creating : cryptoSat > 0 && !creating)

  getSupportedCurrencies()
    .then((res) => {
      if (res.currencies.length === 0) return
      currencies = res.currencies
      // The fetched list may not include the currently selected currency
      // (e.g. server-default fallback list vs. the real supported set).
      // Keep the current selection if it's still valid; otherwise fall
      // back to the first listed currency and keep the rate store in sync.
      if (unit === 'fiat' && !currencies.some((c) => c.code === currency)) {
        currency = currencies[0]!.code
        rate.currency = currency
      }
    })
    .catch(() => {
      /* keep fallback single-currency list */
    })

  function onCurrencyChange(code: string) {
    currency = code
    // NEVER feed sat/btc into the rate store — it isn't an ISO currency
    // code, and doing so would fire GET /api/v1/rate?currency=sat for no
    // reason. Leave rate.currency on the merchant's display fiat currency
    // so RateBar keeps showing a meaningful reference rate underneath.
    if (code !== 'sat' && code !== 'btc') {
      rate.currency = code
    }
    // Switching to a zero-decimal unit mid-entry (fiat CRC, or 'sat')
    // strands a '.' that the Keypad's '00' key can't clear (its handler
    // no-ops when a '.' is already present).
    const nextPrecision = code === 'sat' ? 0 : code === 'btc' ? 8 : (currencies.find((c) => c.code === code)?.precision ?? 2)
    if (nextPrecision === 0 && amount.includes('.')) {
      amount = amount.split('.')[0] ?? ''
    }
  }

  function applyInput(value: string) {
    // BTC needs up to 8 decimal places (1 sat = 0.00000001 BTC); fiat/sat
    // keep the default 2-digit cap (sat never reaches the decimal branch —
    // its Keypad shows '00', not '.').
    amount = applyAmountInput(amount, value, unit === 'btc' ? 8 : 2)
  }

  function backToEntry() {
    amount = ''
    errorMsg = null
    router.go('/')
  }

  async function pay() {
    if (!canPay) return
    creating = true
    errorMsg = null
    try {
      const trimmedMessage = message.trim()
      const res = await createInvoice(config.invoice_base, {
        ...(unit === 'fiat' ? { fiat_amount_minor: fiatMinor, fiat_currency: currency } : { amount_sat: cryptoSat }),
        note: trimmedMessage || undefined,
      })
      cacheInvoice({
        invoice: res,
        note: trimmedMessage,
        precision,
        unit,
        ...(unit === 'fiat' ? { fiatAmountMinor: fiatMinor, currency } : { amountSat: cryptoSat }),
      })
      amount = ''
      message = ''
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
  // RateBar always shows the merchant's fiat reference rate (rate.currency),
  // never the entry unit — so it needs that fiat currency's own precision,
  // not the entry precision (which is 8 for BTC / 0 for sat and would
  // mis-format the reference rate).
  const ratePrecision = $derived(currencies.find((c) => c.code === rate.currency)?.precision ?? 2)
  const hasSocialLinks = $derived(Boolean(config.website || config.twitter || config.instagram))
  const payId = $derived(router.match('/pay/:id')?.id)
</script>

{#snippet payHeader(canCancel: boolean)}
  <div class="mb-6 flex w-full justify-start">
    <button
      type="button"
      class="inline-flex min-h-12 items-center gap-2 rounded-md px-2 text-sm font-semibold"
      onclick={backToEntry}
      disabled={!canCancel}
      aria-label={canCancel ? 'Back' : 'Back unavailable after payment evidence'}
    >
      ← Back
    </button>
  </div>
{/snippet}

{#if payId}
  {#key payId}
    <PayFlow id={payId} header={payHeader} successActionLabel="Send another" onSuccessAction={backToEntry} onExit={backToEntry} />
  {/key}
{:else}
  <main class="h-[100dvh] overflow-hidden bg-[#f5f0e8] text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
    <div class="mx-auto flex h-[100dvh] max-w-4xl flex-col overflow-hidden">
      <section class="flex min-h-0 flex-1 flex-col overflow-hidden px-5 py-3 sm:px-8 sm:py-5">
        <header class="mb-3 flex shrink-0 flex-col items-center gap-2 text-center sm:mb-5">
          <div>
            <h1 class="font-display text-3xl uppercase tracking-display leading-none">
              {config.header || config.page_key}
            </h1>
            {#if config.description}
              <p class="mt-0.5 text-xs font-medium uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">
                {config.description}
              </p>
            {/if}
          </div>
        </header>

        <!-- overflow-y-auto + my-auto (NOT justify-center + overflow-hidden):
             when the stack is taller than the viewport, justify-center clips
             it at BOTH ends — the amount display was getting cropped off the
             top. my-auto centers when content fits and degrades to a normal
             scroll when it doesn't. -->
        <div class="mx-auto flex min-h-0 w-full max-w-xl flex-1 flex-col overflow-y-auto scrollbar-none">
          <div class="my-auto flex w-full flex-col gap-3 sm:gap-5">
            <AmountDisplay amount={displayAmount} {currency} {precision} />

            <Keypad {precision} onInput={applyInput} />

            <select
              class="min-h-12 shrink-0 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] px-4 font-bold outline-none focus:ring-2 focus:ring-[#B7000B] dark:border-[#3a342a] dark:bg-[#211f1a]"
              value={currency}
              onchange={(e) => onCurrencyChange(e.currentTarget.value)}
            >
              <option value="sat">sat</option>
              <option value="btc">BTC</option>
              {#each currencies as c (c.code)}
                <option value={c.code}>{c.code}</option>
              {/each}
            </select>

            <RateBar precision={ratePrecision} />
            {#if !rate.available && !rate.loading}
              <p class="text-center text-xs text-[#776b5a] dark:text-[#b9aa91]">
                Rate unavailable — you can still pay in sat or BTC
              </p>
            {/if}

            <label class="flex shrink-0 flex-col gap-1.5">
              <span class="text-xs font-medium uppercase tracking-[0.12em] text-[#776b5a] dark:text-[#b9aa91]">Leave a message</span>
              <textarea
                class="min-h-12 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] px-4 py-3 text-base outline-none focus:ring-2 focus:ring-[#B7000B] dark:border-[#3a342a] dark:bg-[#211f1a]"
                bind:value={message}
                placeholder="Add a message for the recipient (optional)"
                maxlength="280"
                rows="1"
              ></textarea>
            </label>

            {#if errorMsg}
              <p class="rounded-md bg-[#ffe0d9] px-4 py-3 text-sm font-semibold text-[#8c2d28]">{errorMsg}</p>
            {/if}

            {#if hasSocialLinks}
              <div class="flex shrink-0 justify-center gap-2">
                {#if config.website}
                  <a
                    href={config.website}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="Website"
                    class="grid min-h-12 min-w-12 place-items-center rounded-md bg-[#eadfce] text-[#211f1a] dark:bg-[#2c2922] dark:text-[#fff6e8]"
                  >
                    <Globe size={20} />
                  </a>
                {/if}
                {#if config.twitter}
                  <a
                    href={`https://twitter.com/${config.twitter}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="X (Twitter)"
                    class="grid min-h-12 min-w-12 place-items-center rounded-md bg-[#eadfce] text-[#211f1a] dark:bg-[#2c2922] dark:text-[#fff6e8]"
                  >
                    <X size={20} />
                  </a>
                {/if}
                {#if config.instagram}
                  <a
                    href={`https://instagram.com/${config.instagram}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="Instagram"
                    class="grid min-h-12 min-w-12 place-items-center rounded-md bg-[#eadfce] text-[#211f1a] dark:bg-[#2c2922] dark:text-[#fff6e8]"
                  >
                    <Instagram size={20} />
                  </a>
                {/if}
              </div>
            {/if}

            <BullFooter />
          </div>
        </div>

        <div
          class="mx-auto mt-2 flex w-full max-w-xl shrink-0 flex-col bg-gradient-to-t from-[#f5f0e8] from-60% to-transparent pb-[max(0.25rem,env(safe-area-inset-bottom))] pt-2 dark:from-[#161512]"
        >
          <Button disabled={!canPay || creating} onclick={pay}>
            {creating ? 'Preparing' : 'Pay'}
          </Button>
        </div>
      </section>
    </div>
  </main>
{/if}

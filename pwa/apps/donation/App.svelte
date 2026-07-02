<script lang="ts">
  // Reskinned to nostr-pos's design system/components — there's no
  // donation-mode screen upstream to port, so this arranges the same kit
  // (AmountDisplay, Keypad, Button, PaymentScreen, SuccessScreen,
  // BullFooter) for the payer-initiated single-screen flow, matching the
  // visual language exactly.
  //
  // The entry screen structurally mirrors apps/pos/screens/KeypadScreen.svelte
  // exactly (per design review): same h-[100dvh] overflow-hidden shell,
  // same max-w-4xl outer / max-w-xl inner column widths (the narrower
  // max-w-md this screen used before was why the Keypad rendered smaller
  // than POS's — same component, narrower container), same gradient-pinned
  // primary action at the bottom. Payment/success sub-screens instead
  // mirror apps/pos/screens/PayScreen.svelte's plain scrollable
  // min-h-screen shell, since POS keeps those as separate non-fixed-height
  // views too (only the keypad itself is the fixed single-viewport shell).
  import { Globe, Instagram, X } from 'lucide-svelte'
  import { config } from '$lib/config'
  import {
    createInvoice,
    getSupportedCurrencies,
    ApiError,
    type CreateInvoiceResponse,
    type InvoiceStatus,
    type CurrencyView,
  } from '$lib/api/client'
  import { rate } from '$lib/stores/rate.svelte'
  import { formatFiat } from '$lib/money'
  import { applyAmountInput } from '$lib/amount-input'
  import Keypad from '$lib/components/Keypad.svelte'
  import AmountDisplay from '$lib/components/AmountDisplay.svelte'
  import RateBar from '$lib/components/RateBar.svelte'
  import Button from '$lib/components/Button.svelte'
  import BullFooter from '$lib/components/BullFooter.svelte'
  import PaymentScreen from '$lib/components/PaymentScreen.svelte'
  import SuccessScreen from '$lib/components/SuccessScreen.svelte'

  type Screen = 'entry' | 'payment' | 'success'

  let screen = $state<Screen>('entry')
  let currencies = $state<CurrencyView[]>([{ code: config.currency, precision: 2 }])
  let currency = $state(config.currency)
  let amount = $state('')
  let errorMsg = $state<string | null>(null)
  let creating = $state(false)
  let invoice = $state<CreateInvoiceResponse | null>(null)
  let paidStatus = $state<InvoiceStatus | null>(null)

  const precision = $derived(currencies.find((c) => c.code === currency)?.precision ?? 2)
  const minor = $derived(Math.round(Number(amount || '0') * 10 ** precision))
  const canPay = $derived(minor > 0 && rate.available && !creating)

  getSupportedCurrencies()
    .then((res) => {
      if (res.currencies.length === 0) return
      currencies = res.currencies
      // The fetched list may not include the currently selected currency
      // (e.g. server-default fallback list vs. the real supported set).
      // Keep the current selection if it's still valid; otherwise fall
      // back to the first listed currency and keep the rate store in sync.
      if (!currencies.some((c) => c.code === currency)) {
        currency = currencies[0]!.code
        rate.currency = currency
      }
    })
    .catch(() => {
      /* keep fallback single-currency list */
    })

  function onCurrencyChange(code: string) {
    currency = code
    rate.currency = code
    // Switching to a zero-decimal currency mid-entry (e.g. typed "12." in
    // USD, then switched to CRC) would otherwise strand a '.' that the
    // Keypad's '00' key can't clear (its handler no-ops when a '.' is
    // already present) — same class of bug as the CRC decimal-key fix.
    if (precision === 0 && amount.includes('.')) {
      amount = amount.split('.')[0] ?? ''
    }
  }

  function applyInput(value: string) {
    amount = applyAmountInput(amount, value)
  }

  function resetEntry() {
    amount = ''
    errorMsg = null
    invoice = null
    paidStatus = null
  }

  async function pay() {
    if (!canPay) return
    creating = true
    errorMsg = null
    try {
      const res = await createInvoice(config.nym, {
        fiat_amount_minor: minor,
        fiat_currency: currency,
      })
      invoice = res
      screen = 'payment'
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

  function onPaid(status: InvoiceStatus) {
    paidStatus = status
    screen = 'success'
  }

  function onExpired() {
    errorMsg = 'Invoice expired'
    screen = 'entry'
  }

  function onCancel() {
    screen = 'entry'
  }

  function onDismissSuccess() {
    resetEntry()
    screen = 'entry'
  }

  const displayAmount = $derived(amount || '0')
  const amountLabel = $derived(formatFiat(minor, currency, precision))
  const paidLabel = $derived(
    paidStatus
      ? formatFiat(paidStatus.fiat_amount_minor ?? minor, paidStatus.fiat_currency ?? currency, precision)
      : amountLabel,
  )
  const hasSocialLinks = $derived(Boolean(config.website || config.twitter || config.instagram))
</script>

{#if screen === 'entry'}
  <main class="h-[100dvh] overflow-hidden bg-[#f5f0e8] text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
    <div class="mx-auto flex h-[100dvh] max-w-4xl flex-col overflow-hidden">
      <section class="flex min-h-0 flex-1 flex-col overflow-hidden px-5 py-3 sm:px-8 sm:py-5">
        <header class="mb-3 flex shrink-0 flex-col items-center gap-2 text-center sm:mb-5">
          {#if config.avatar_url}
            <img src={config.avatar_url} alt="" class="h-14 w-14 rounded-full object-cover" />
          {/if}
          <div>
            <h1 class="font-display text-3xl uppercase tracking-display leading-none">
              {config.header || config.nym}
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
        <div class="mx-auto flex min-h-0 w-full max-w-xl flex-1 flex-col overflow-y-auto">
          <div class="my-auto flex w-full flex-col gap-3 sm:gap-5">
          <AmountDisplay amount={displayAmount} {currency} {precision} />

          <Keypad {precision} onInput={applyInput} />

          <select
            class="min-h-12 shrink-0 rounded-lg border border-[#d7c8b4] bg-[#fffaf0] px-4 font-bold outline-none focus:ring-2 focus:ring-[#B7000B] dark:border-[#3a342a] dark:bg-[#211f1a]"
            value={currency}
            onchange={(e) => onCurrencyChange(e.currentTarget.value)}
          >
            {#each currencies as c (c.code)}
              <option value={c.code}>{c.code}</option>
            {/each}
          </select>

          <RateBar {precision} />

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
{:else if screen === 'payment' && invoice}
  <main class="min-h-screen bg-[#f5f0e8] text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
    <div class="mx-auto grid min-h-screen max-w-4xl grid-rows-1">
      <section class="px-5 py-5 sm:px-8">
        <!-- PaymentScreen no longer renders its own back/cancel row (that
             was causing a duplicated "Cancel sale" header on the POS pay
             screen, which wraps its own header too) — each caller owns
             exactly one header row now, matching nostr-pos's Pos.svelte. -->
        <div class="mb-6 flex w-full justify-start">
          <button
            type="button"
            class="inline-flex min-h-12 items-center gap-2 rounded-md px-2 text-sm font-semibold"
            onclick={onCancel}
          >
            ← Back
          </button>
        </div>
        <PaymentScreen {invoice} nym={config.nym} {amountLabel} {onPaid} {onExpired} />
      </section>
    </div>
  </main>
{:else if screen === 'success'}
  <main class="min-h-screen bg-[#f5f0e8] text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
    <div class="mx-auto grid min-h-screen max-w-4xl grid-rows-1">
      <section class="px-5 py-5 sm:px-8">
        <SuccessScreen
          amountLabel={paidLabel}
          rail={paidStatus?.paid_via ?? null}
          actionLabel="Send another"
          onaction={onDismissSuccess}
        />
      </section>
    </div>
  </main>
{/if}

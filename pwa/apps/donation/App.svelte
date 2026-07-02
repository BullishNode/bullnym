<script lang="ts">
  // Reskinned to nostr-pos's design system/components — there's no
  // donation-mode screen upstream to port, so this arranges the same kit
  // (AmountDisplay, Keypad, Button, PaymentScreen, SuccessScreen,
  // BullFooter) for the payer-initiated single-screen flow, matching the
  // visual language exactly.
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
</script>

<main class="mx-auto flex min-h-[100dvh] max-w-md flex-col bg-[#f5f0e8] px-5 py-8 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
  {#if screen === 'entry'}
    <div class="flex flex-1 flex-col items-center gap-5">
      <div class="flex flex-col items-center gap-2 text-center">
        {#if config.avatar_url}
          <img src={config.avatar_url} alt="" class="h-16 w-16 rounded-full object-cover" />
        {/if}
        <h1 class="font-display text-3xl uppercase tracking-display leading-none">{config.header || config.nym}</h1>
        {#if config.description}
          <p class="text-sm text-[#776b5a] dark:text-[#b9aa91]">{config.description}</p>
        {/if}
      </div>

      <AmountDisplay amount={displayAmount} {currency} {precision} />

      <Keypad {precision} onInput={applyInput} />

      <select
        class="min-h-12 rounded-md border border-[#d7c8b4] bg-[#fffaf0] px-3 font-bold dark:border-[#3a342a] dark:bg-[#211f1a]"
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

      <Button disabled={!canPay || creating} onclick={pay}>
        {creating ? 'Preparing' : 'Pay'}
      </Button>

      {#if config.website || config.twitter || config.instagram}
        <div class="mt-auto flex gap-5 text-xl">
          {#if config.website}
            <a href={config.website} target="_blank" rel="noopener noreferrer">🌐</a>
          {/if}
          {#if config.twitter}
            <a href={`https://twitter.com/${config.twitter}`} target="_blank" rel="noopener noreferrer">𝕏</a>
          {/if}
          {#if config.instagram}
            <a href={`https://instagram.com/${config.instagram}`} target="_blank" rel="noopener noreferrer">📷</a>
          {/if}
        </div>
      {/if}

      <BullFooter />
    </div>
  {:else if screen === 'payment' && invoice}
    <!-- PaymentScreen no longer renders its own back/cancel row (that was
         causing a duplicated "Cancel sale" header on the POS pay screen,
         which wraps its own header too) — each caller owns exactly one
         header row now, matching nostr-pos's Pos.svelte. -->
    <div class="flex w-full justify-start">
      <button
        type="button"
        class="inline-flex min-h-12 items-center gap-2 rounded-md px-2 text-sm font-semibold"
        onclick={onCancel}
      >
        ← Back
      </button>
    </div>
    <PaymentScreen {invoice} nym={config.nym} {amountLabel} {onPaid} {onExpired} />
  {:else if screen === 'success'}
    <SuccessScreen
      amountLabel={paidLabel}
      rail={paidStatus?.paid_via ?? null}
      actionLabel="Send another"
      onaction={onDismissSuccess}
    />
  {/if}
</main>

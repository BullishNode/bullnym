<script lang="ts">
  // Ported from nostr-pos
  // (~/apps/nostr-pos/apps/pos-pwa/src/lib/ui/AmountDisplay.svelte). Prop
  // contract changed from our old {minor, precision} to upstream's
  // {amount: decimal string, currency} — paired with the ported Keypad +
  // applyAmountInput at call sites. Re-added a `precision` prop (upstream
  // doesn't have one — see lib/money.ts's formatFiatAmount) so a
  // precision-0 currency never displays cents even if a '.' somehow ended
  // up in `amount`.
  //
  // review item 7 (donation sat/BTC entry): `currency` can now be the
  // synthetic units 'sat'/'btc', which aren't ISO codes —
  // Intl.NumberFormat({style:'currency', currency}) throws on those, so
  // formatFiatAmount can never be used for them. Branch to the dedicated
  // crypto formatter (lib/money.ts's formatCryptoAmount) instead of forcing
  // them through the currency formatter.
  import { formatFiatAmount, formatCryptoAmount } from '$lib/money'

  let { amount, currency, precision = 2 }: { amount: string; currency: string; precision?: number } = $props()
  const isCrypto = $derived(currency === 'sat' || currency === 'btc')
  const showCents = $derived(amount.includes('.'))
  const display = $derived(
    isCrypto ? formatCryptoAmount(amount, currency as 'sat' | 'btc') : formatFiatAmount(amount, currency, precision, showCents),
  )
</script>

<div class="text-right">
  <div class="font-display text-xs uppercase tracking-[0.18em] text-[#776b5a] dark:text-[#b9aa91]">Total</div>
  <div
    class="mt-1 whitespace-nowrap font-display tabular-nums tracking-display text-[clamp(2.5rem,10vw,7.5rem)] leading-[0.95] text-[#211f1a] dark:text-[#fff6e8]"
  >
    {display}
  </div>
</div>

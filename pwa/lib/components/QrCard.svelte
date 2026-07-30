<script lang="ts">
  // Ported verbatim from nostr-pos
  // (~/apps/nostr-pos/apps/pos-pwa/src/lib/ui/QrCard.svelte). Replaces our
  // old QrCode.svelte + inline copy button; same qrcode-to-data-URL
  // approach, same card chrome.
  import QRCode from 'qrcode'
  import { onDestroy } from 'svelte'
  import { Copy, CreditCard } from 'lucide-svelte'
  import Button from './Button.svelte'

  let {
    value,
    label = 'Payment code',
    showBoltCard = false,
    onBoltCard,
  }: {
    value: string
    label?: string
    showBoltCard?: boolean
    onBoltCard?: () => void
  } = $props()
  let dataUrl = $state('')
  let copied = $state(false)
  let copyReset: ReturnType<typeof setTimeout> | undefined

  async function copyPayment() {
    await navigator.clipboard.writeText(value)
    copied = true
    if (copyReset) clearTimeout(copyReset)
    copyReset = setTimeout(() => (copied = false), 1_500)
  }

  onDestroy(() => {
    if (copyReset) clearTimeout(copyReset)
  })

  $effect(() => {
    const exactValue = value
    let current = true
    dataUrl = ''
    QRCode.toDataURL(exactValue, {
      margin: 4,
      width: 300,
      color: { dark: '#000000', light: '#ffffff' },
    }).then((next) => {
      if (current) dataUrl = next
    })
    return () => {
      current = false
    }
  })
</script>

<div
  class="mx-auto w-full max-w-sm rounded-lg border border-[#d7c8b4] bg-[#fffaf0] p-4 text-center shadow-sm dark:border-[#3a342a] dark:bg-[#211f1a]"
>
  {#if dataUrl}
    <img class="mx-auto aspect-square w-full max-w-[300px]" src={dataUrl} alt={label} />
  {/if}
  <div class="mt-3 flex flex-wrap items-center justify-center gap-2">
    <Button variant="secondary" onclick={copyPayment}>
      <Copy size={18} />
      {copied ? 'Copied' : 'Copy'}
    </Button>
    {#if showBoltCard}
      <Button variant="secondary" onclick={onBoltCard}>
        <CreditCard size={18} />
        Bolt Card
      </Button>
    {/if}
  </div>
</div>

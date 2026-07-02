<script lang="ts">
  // Ported from nostr-pos
  // (~/apps/nostr-pos/apps/pos-pwa/src/lib/ui/StatusPill.svelte). Same
  // markup/classes; `status` is a plain string from our InvoiceStatus
  // vocabulary (pending/partially_paid/paid/overpaid/expired/cancelled)
  // rather than upstream's much larger Nostr/Boltz SaleStatus enum — see
  // lib/status.ts for the label/tone mapping adaptation.
  import { statusLabel, statusPillTone } from '$lib/status'

  let { status }: { status: string } = $props()
  const tone = $derived(statusPillTone(status))
</script>

<span class={`inline-flex min-h-8 items-center rounded-full px-3 text-xs font-bold ${tone}`}>
  {statusLabel(status)}
</span>

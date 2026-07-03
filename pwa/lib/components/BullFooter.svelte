<script lang="ts">
  // Ported verbatim from nostr-pos
  // (~/apps/nostr-pos/apps/pos-pwa/src/lib/ui/BullFooter.svelte), except
  // asset URLs are resolved against import.meta.env.BASE_URL rather than
  // hardcoded root-absolute paths — the server only serves dist/ under
  // /pwa-assets/, nothing at site root except /sw.js, so a root-absolute
  // /bb-logo-*.png would silently 404 in production.
  let { width = 140 }: { width?: number } = $props()

  const lightLogo = `${import.meta.env.BASE_URL}bb-logo-light.png`
  const darkLogo = `${import.meta.env.BASE_URL}bb-logo-dark.png`
</script>

<div class="flex justify-center py-4">
  <a
    href="https://bullbitcoin.com"
    target="_blank"
    rel="noopener noreferrer"
    aria-label="Bull Bitcoin"
    class="inline-block transition hover:opacity-80"
  >
    <img src={lightLogo} alt="Bull Bitcoin" class="bb-banner block dark:hidden" {width} />
    <img src={darkLogo} alt="Bull Bitcoin" class="bb-banner hidden dark:block" {width} />
  </a>
</div>

<style>
  .bb-banner {
    height: auto;
  }
</style>

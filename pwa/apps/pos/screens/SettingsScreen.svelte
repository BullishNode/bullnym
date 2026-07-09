<script lang="ts">
  // Reskinned to nostr-pos's Settings.svelte
  // (~/apps/nostr-pos/apps/pos-pwa/src/routes/Settings.svelte) look (dl
  // card, Button component) while keeping our full functionality: PIN
  // gate, currency override, paper size, Bolt Card toggle, clear
  // history/reset terminal — none of which exist upstream (no PIN concept,
  // no multi-currency, no Bolt Card toggle, no paper size).
  import { config } from '$lib/config'
  import { getSupportedCurrencies, type CurrencyView } from '$lib/api/client'
  import { rate } from '$lib/stores/rate.svelte'
  import { settings, type PaperSize } from '$lib/stores/settings.svelte'
  import { history } from '$lib/stores/history.svelte'
  import { router } from '$lib/router.svelte'
  import { hasPin, setPin, verifyPin, lockoutRemainingMs, recordFailedAttempt, clearAttempts } from '$lib/pin'
  import Keypad from '$lib/components/Keypad.svelte'
  import Button from '$lib/components/Button.svelte'

  type GateState = 'checking' | 'challenge' | 'locked' | 'set-prompt' | 'unlocked'

  let gate = $state<GateState>('checking')
  let pinInput = $state('')
  let pinError = $state<string | null>(null)
  let lockoutMs = $state(0)
  let lockoutTimer: ReturnType<typeof setInterval> | undefined

  // New-PIN setup fields (used both from the "Set a PIN?" prompt and the
  // in-settings "Set/change PIN" action).
  let newPin = $state('')
  let newPinConfirm = $state('')
  let settingPin = $state(false)
  let pinSetupError = $state<string | null>(null)

  function checkGate() {
    const remaining = lockoutRemainingMs(config.page_key)
    if (remaining > 0) {
      lockoutMs = remaining
      gate = 'locked'
      startLockoutTimer()
      return
    }
    if (!hasPin(config.page_key)) {
      gate = 'set-prompt'
      return
    }
    gate = 'challenge'
  }

  function startLockoutTimer() {
    if (lockoutTimer) clearInterval(lockoutTimer)
    lockoutTimer = setInterval(() => {
      lockoutMs = lockoutRemainingMs(config.page_key)
      if (lockoutMs <= 0) {
        clearInterval(lockoutTimer)
        gate = hasPin(config.page_key) ? 'challenge' : 'set-prompt'
      }
    }, 1000)
  }

  checkGate()

  $effect(() => {
    return () => {
      if (lockoutTimer) clearInterval(lockoutTimer)
    }
  })

  async function onPinInput(d: string) {
    if (d === 'back') {
      pinInput = pinInput.slice(0, -1)
      return
    }
    if (d === '.' || pinInput.length >= 4) return
    pinInput += d
    if (pinInput.length === 4) {
      const ok = await verifyPin(config.page_key, pinInput)
      if (ok) {
        clearAttempts(config.page_key)
        gate = 'unlocked'
      } else {
        recordFailedAttempt(config.page_key)
        pinError = 'Incorrect PIN'
        pinInput = ''
        const remaining = lockoutRemainingMs(config.page_key)
        if (remaining > 0) {
          lockoutMs = remaining
          gate = 'locked'
          startLockoutTimer()
        }
      }
    }
  }

  function skipPinSetup() {
    gate = 'unlocked'
  }

  function beginPinSetup() {
    newPin = ''
    newPinConfirm = ''
    pinSetupError = null
    settingPin = true
  }

  async function onNewPinInput(d: string) {
    if (d === 'back') {
      if (newPinConfirm.length > 0) newPinConfirm = newPinConfirm.slice(0, -1)
      else newPin = newPin.slice(0, -1)
      return
    }
    if (d === '.') return
    if (newPin.length < 4) {
      newPin += d
    } else if (newPinConfirm.length < 4) {
      newPinConfirm += d
      if (newPinConfirm.length === 4) {
        if (newPin === newPinConfirm) {
          await setPin(config.page_key, newPin)
          settingPin = false
          gate = 'unlocked'
        } else {
          pinSetupError = 'PINs did not match — try again'
          newPin = ''
          newPinConfirm = ''
        }
      }
    }
  }

  function cancelPinSetup() {
    settingPin = false
    pinSetupError = null
  }

  // --- Settings content (only reachable once gate === 'unlocked') ---

  let currencies = $state<CurrencyView[]>([{ code: settings.currency, precision: 2 }])

  getSupportedCurrencies()
    .then((res) => {
      if (res.currencies.length > 0) currencies = res.currencies
    })
    .catch(() => {
      /* keep fallback single-currency list */
    })

  function onCurrencyChange(code: string) {
    settings.currency = code
    rate.currency = code
  }

  function onPaperSizeChange(size: PaperSize) {
    settings.paperSize = size
  }

  let clearHistoryConfirm = $state(false)
  function onClearHistory() {
    if (!clearHistoryConfirm) {
      clearHistoryConfirm = true
      return
    }
    history.clear()
    clearHistoryConfirm = false
  }

  let resetConfirm = $state(false)
  function onResetTerminal() {
    if (!resetConfirm) {
      resetConfirm = true
      return
    }
    try {
      const keys: string[] = []
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i)
        if (k?.startsWith('bullnym:')) keys.push(k)
      }
      for (const k of keys) localStorage.removeItem(k)
    } catch {
      /* localStorage unavailable */
    }
    location.reload()
  }
</script>

<main class="min-h-screen bg-[#f5f0e8] px-5 py-5 text-[#211f1a] dark:bg-[#161512] dark:text-[#fff6e8]">
  <div class="mx-auto max-w-2xl">
    <a class="inline-flex min-h-12 items-center gap-2 rounded-md font-bold" href="#/">← Back</a>

    {#snippet pinDots(filled: number)}
      <div class="flex items-center justify-center gap-3" role="img" aria-label={`${filled} of 4 digits entered`}>
        {#each { length: 4 }, i (i)}
          <span
            class={`h-4 w-4 rounded-full border border-[#d7c8b4] dark:border-[#3a342a] ${
              i < filled ? 'bg-[#211f1a] dark:bg-[#fff6e8]' : 'bg-transparent'
            }`}
          ></span>
        {/each}
      </div>
    {/snippet}

    {#if settingPin}
      <div class="flex flex-col items-center justify-center gap-5 py-10">
        <p class="font-display text-3xl uppercase tracking-display leading-none">
          {newPin.length < 4 ? 'Set a PIN' : 'Confirm PIN'}
        </p>
        {@render pinDots(newPin.length < 4 ? newPin.length : newPinConfirm.length)}
        {#if pinSetupError}
          <p class="rounded-md bg-[#ffe0d9] px-4 py-3 text-sm font-semibold text-[#8c2d28]">{pinSetupError}</p>
        {/if}
        <Keypad precision={null} onInput={onNewPinInput} />
        <button type="button" class="text-sm text-[#776b5a] dark:text-[#b9aa91]" onclick={cancelPinSetup}>
          Cancel
        </button>
      </div>
    {:else if gate === 'checking'}
      <!-- synchronous check, effectively instant -->
    {:else if gate === 'locked'}
      <div class="flex flex-col items-center justify-center gap-3 py-16">
        <p class="font-display text-3xl uppercase tracking-display leading-none text-[#8c2d28]">Too many attempts</p>
        <p class="text-sm text-[#776b5a] dark:text-[#b9aa91]">Try again in {Math.ceil(lockoutMs / 1000)}s</p>
      </div>
    {:else if gate === 'set-prompt'}
      <div class="flex flex-col items-center justify-center gap-4 py-10">
        <p class="text-center">Set a PIN to protect settings?</p>
        <Button onclick={beginPinSetup}>Set a PIN</Button>
        <button type="button" class="text-sm text-[#776b5a] dark:text-[#b9aa91]" onclick={skipPinSetup}>
          Skip for now
        </button>
      </div>
    {:else if gate === 'challenge'}
      <div class="flex flex-col items-center justify-center gap-5 py-10">
        <p class="font-display text-3xl uppercase tracking-display leading-none">Enter PIN</p>
        {@render pinDots(pinInput.length)}
        {#if pinError}
          <p class="rounded-md bg-[#ffe0d9] px-4 py-3 text-sm font-semibold text-[#8c2d28]">{pinError}</p>
        {/if}
        <Keypad precision={null} onInput={onPinInput} />
      </div>
    {:else if gate === 'unlocked'}
      <h1 class="mt-8 text-3xl font-black">Settings</h1>

      <div class="mt-5 rounded-md border border-[#d7c8b4] bg-[#fffaf0] p-5 dark:border-[#3a342a] dark:bg-[#211f1a]">
        <dl class="space-y-3">
          <div class="flex items-center justify-between gap-5">
            <dt class="text-[#776b5a] dark:text-[#b9aa91]">Display currency</dt>
            <dd>
              <select
                class="rounded-md border border-[#d7c8b4] bg-[#fffaf0] px-3 py-2 font-bold dark:border-[#3a342a] dark:bg-[#211f1a]"
                value={settings.currency}
                onchange={(e) => onCurrencyChange(e.currentTarget.value)}
              >
                {#each currencies as c (c.code)}
                  <option value={c.code}>{c.code}</option>
                {/each}
              </select>
            </dd>
          </div>
          <div class="flex items-center justify-between gap-5">
            <dt class="text-[#776b5a] dark:text-[#b9aa91]">Nym</dt>
            <dd class="font-bold">{config.page_key}</dd>
          </div>
          <div class="flex items-center justify-between gap-5">
            <dt class="text-[#776b5a] dark:text-[#b9aa91]">Domain</dt>
            <dd class="font-bold">{config.domain}</dd>
          </div>
          <div class="flex items-center justify-between gap-5">
            <dt class="text-[#776b5a] dark:text-[#b9aa91]">Mode</dt>
            <dd class="font-bold">{config.mode}</dd>
          </div>
          <div class="flex items-center justify-between gap-5">
            <dt class="text-[#776b5a] dark:text-[#b9aa91]">App version</dt>
            <dd class="font-bold">{__APP_VERSION__}</dd>
          </div>
        </dl>
      </div>

      <div class="mt-5 rounded-md border border-[#d7c8b4] bg-[#fffaf0] p-5 dark:border-[#3a342a] dark:bg-[#211f1a]">
        <p class="mb-3 font-semibold text-[#776b5a] dark:text-[#b9aa91]">Receipt paper size</p>
        <div class="flex gap-2">
          {#each [['58mm', '58mm'], ['80mm', '80mm'], ['a4', 'A4']] as [value, label] (value)}
            <button
              type="button"
              class={`min-h-12 flex-1 rounded-md border font-semibold transition ${
                settings.paperSize === value
                  ? 'border-[#B7000B] bg-[#B7000B] text-[#fffaf0]'
                  : 'border-[#d7c8b4] bg-[#fffaf0] text-[#2d2418] dark:border-[#3a342a] dark:bg-[#211f1a] dark:text-[#fbf0df]'
              }`}
              onclick={() => onPaperSizeChange(value as PaperSize)}
            >
              {label}
            </button>
          {/each}
        </div>
      </div>

      <div class="mt-5 flex items-center justify-between rounded-md border border-[#d7c8b4] bg-[#fffaf0] p-5 dark:border-[#3a342a] dark:bg-[#211f1a]">
        <p class="font-semibold text-[#776b5a] dark:text-[#b9aa91]">Bolt Card (Tap to Pay)</p>
        <button
          type="button"
          class={`min-h-10 min-w-20 rounded-md font-bold transition ${
            settings.boltCardEnabled ? 'bg-[#1f513a] text-[#fffaf0]' : 'bg-[#eadfce] text-[#2d2418] dark:bg-[#2c2922] dark:text-[#fbf0df]'
          }`}
          onclick={() => (settings.boltCardEnabled = !settings.boltCardEnabled)}
          aria-pressed={settings.boltCardEnabled}
        >
          {settings.boltCardEnabled ? 'On' : 'Off'}
        </button>
      </div>

      <div class="mt-5">
        {#if hasPin(config.page_key)}
          <Button variant="secondary" onclick={beginPinSetup}>Change PIN</Button>
        {:else}
          <Button variant="secondary" onclick={beginPinSetup}>Set a PIN</Button>
        {/if}
      </div>

      <div class="mt-5">
        <Button variant="danger" onclick={onClearHistory}>
          {clearHistoryConfirm ? 'Tap again to confirm' : 'Clear history'}
        </Button>
      </div>

      <div class="mt-5">
        <Button variant="danger" onclick={onResetTerminal}>
          {resetConfirm ? 'Tap again to confirm — this clears everything' : 'Reset terminal'}
        </Button>
      </div>
    {/if}
  </div>
</main>

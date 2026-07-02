// PIN gate for /#/settings. Local-only UX check, not server auth — SHA-256
// via Web Crypto (no new deps), stored as hex in localStorage per nym.

const MAX_ATTEMPTS = 5
const LOCKOUT_MS = 30_000

function pinKey(nym: string): string {
  return `bullnym:pin:${nym}`
}
function attemptsKey(nym: string): string {
  return `bullnym:pin-attempts:${nym}`
}
function lockoutKey(nym: string): string {
  return `bullnym:pin-lockout:${nym}`
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export function hasPin(nym: string): boolean {
  try {
    return localStorage.getItem(pinKey(nym)) !== null
  } catch {
    return false
  }
}

export async function setPin(nym: string, pin: string): Promise<void> {
  const hash = await sha256Hex(pin)
  try {
    localStorage.setItem(pinKey(nym), hash)
  } catch {
    /* quota exceeded / private mode: PIN just won't persist */
  }
}

export function clearPin(nym: string): void {
  try {
    localStorage.removeItem(pinKey(nym))
    localStorage.removeItem(attemptsKey(nym))
    localStorage.removeItem(lockoutKey(nym))
  } catch {
    /* localStorage unavailable */
  }
}

/** Returns true if the PIN matches, or if no PIN is set (nothing to verify). */
export async function verifyPin(nym: string, pin: string): Promise<boolean> {
  const stored = localStorage.getItem(pinKey(nym))
  if (stored === null) return true
  const hash = await sha256Hex(pin)
  return hash === stored
}

/** Milliseconds remaining in a lockout, or 0 if not locked out. */
export function lockoutRemainingMs(nym: string): number {
  try {
    const until = Number(localStorage.getItem(lockoutKey(nym)) ?? 0)
    return Math.max(0, until - Date.now())
  } catch {
    return 0
  }
}

/** Call after a failed PIN attempt. Triggers a lockout after MAX_ATTEMPTS. */
export function recordFailedAttempt(nym: string): void {
  try {
    const attempts = Number(localStorage.getItem(attemptsKey(nym)) ?? 0) + 1
    if (attempts >= MAX_ATTEMPTS) {
      localStorage.setItem(lockoutKey(nym), String(Date.now() + LOCKOUT_MS))
      localStorage.setItem(attemptsKey(nym), '0')
    } else {
      localStorage.setItem(attemptsKey(nym), String(attempts))
    }
  } catch {
    /* localStorage unavailable */
  }
}

export function clearAttempts(nym: string): void {
  try {
    localStorage.removeItem(attemptsKey(nym))
    localStorage.removeItem(lockoutKey(nym))
  } catch {
    /* localStorage unavailable */
  }
}

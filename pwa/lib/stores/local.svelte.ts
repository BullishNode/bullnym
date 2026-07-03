// localStorage-backed reactive store. Plain JSON, no crypto — nothing
// stored here is secret except the PIN hash, which is local-only UX
// gating, not server auth.

export function localStore<T>(key: string, initial: T) {
  let value = initial
  try {
    const raw = localStorage.getItem(key)
    if (raw !== null) value = JSON.parse(raw) as T
  } catch {
    /* corrupt entry: fall back to initial */
  }

  const state = $state({ value })

  return {
    get value(): T {
      return state.value
    },
    set value(v: T) {
      state.value = v
      try {
        localStorage.setItem(key, JSON.stringify(v))
      } catch {
        /* quota exceeded / private mode: keep in-memory value */
      }
    },
    /** Convenience for immutable updates. */
    update(fn: (v: T) => T): void {
      this.value = fn(state.value)
    },
  }
}

/**
 * Injected time source. Expiry (and, in later phases, revocation-adjacent
 * timing) must never read `Date.now()` directly (§2.10) — deterministic
 * testing requires the caller be able to fix "now".
 */
export interface Clock {
  now(): Date;
}

export function systemClock(): Clock {
  return { now: () => new Date() };
}

import { sha256Base64Url } from "../crypto/hash.js";
import type { AuditEvent } from "./types.js";

/**
 * Content hash of one audit event, including its own `prevEventHash` (so
 * the chain covers full history, not just the immediately-preceding link —
 * standard hash-chain construction). Relies on `AuditEvent` objects always
 * being built by `emitter.ts` with a fixed key order (`JSON.stringify` is
 * deterministic for a given insertion order) — not a general-purpose
 * canonicalizer for arbitrary externally-constructed objects.
 */
export function hashAuditEvent(event: AuditEvent): string {
  return sha256Base64Url(JSON.stringify(event));
}

export interface HashChainVerificationResult {
  readonly valid: boolean;
  /** Index of the first event whose `prevEventHash` doesn't match, if any. */
  readonly brokenAtIndex?: number;
}

/**
 * Re-verifies a sequence of hash-chained events (§12/T12): recomputes each
 * event's hash and checks the *next* event's `prevEventHash` against it.
 * A gap, reorder, or edit anywhere in the sequence breaks the chain from
 * that point forward.
 */
export function verifyHashChain(events: readonly AuditEvent[]): HashChainVerificationResult {
  for (let i = 1; i < events.length; i++) {
    const prevHash = hashAuditEvent(events[i - 1]!);
    if (events[i]!.prevEventHash !== prevHash) {
      return { valid: false, brokenAtIndex: i };
    }
  }
  return { valid: true };
}

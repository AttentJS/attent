import type { ExceedsDetail } from "./types.js";

function formatDetails(details: readonly ExceedsDetail[]): string {
  return details.map((d) => `${d.field}: ${d.reason}`).join("; ");
}

/**
 * Thrown by `delegate()` when the requested grant is not fully covered by
 * the parent's effective authority (reject-not-clip rule).
 * Carries structured `details` (not just a message) for good DX (a caller
 * can programmatically inspect exactly which clause exceeded).
 */
export class ExceedsAvailableAuthorityError extends Error {
  readonly details: readonly ExceedsDetail[];
  constructor(details: readonly ExceedsDetail[]) {
    super(`Requested grant exceeds available authority: ${formatDetails(details)}`);
    this.name = "ExceedsAvailableAuthorityError";
    this.details = details;
  }
}

/** Thrown by `delegate()` when issuing one more hop would exceed `maxDelegationDepth`. */
export class MaxDelegationDepthExceededError extends Error {
  constructor(maxDepth: number) {
    super(`Delegating would exceed max delegation depth (${maxDepth})`);
    this.name = "MaxDelegationDepthExceededError";
  }
}

/** Thrown by chain verification when a presented chain exceeds `maxDelegationDepth`. */
export class ChainTooDeepError extends Error {
  constructor(maxDepth: number, actual: number) {
    super(`Chain length (${actual}) exceeds max delegation depth (${maxDepth})`);
    this.name = "ChainTooDeepError";
  }
}

/** Thrown when a chain is empty, or hop n+1's `iss` doesn't equal hop n's `sub`. */
export class ChainContinuityError extends Error {
  constructor(reason: string) {
    super(`Chain continuity violation: ${reason}`);
    this.name = "ChainContinuityError";
  }
}

/**
 * Thrown when a hop's `parentHopHash` doesn't match the hash of the hop
 * immediately preceding it in the presented chain — the defense against
 * splicing a validly-signed hop onto a different, more-privileged parent.
 */
export class ChainHashMismatchError extends Error {
  constructor() {
    super("Hop's parentHopHash does not match its preceding hop in the chain (possible chain-splice attempt)");
    this.name = "ChainHashMismatchError";
  }
}

/**
 * Thrown when re-derived narrowing (capabilities, `aud`, or `exp`) between
 * two adjacent hops fails at verify-time — the belt-and-suspenders check
 * that catches a violation even if issuance-time enforcement had a bug.
 */
export class ChainNarrowingViolationError extends Error {
  readonly details: readonly ExceedsDetail[];
  constructor(details: readonly ExceedsDetail[]) {
    super(`Chain narrowing violation: ${formatDetails(details)}`);
    this.name = "ChainNarrowingViolationError";
    this.details = details;
  }
}

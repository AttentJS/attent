import type { Credential } from "../credentials/types.js";

/** Default `maxDelegationDepth` (§7) — overridable per call. */
export const DEFAULT_MAX_DELEGATION_DEPTH = 5;

/**
 * The full, ordered, root-to-leaf array of independently-signed hops a
 * Principal presents when calling `authorize()` (§7/§9). Each element is a
 * single-hop `Credential` (the same shape `issueCredential`/`verifyCredential`
 * from `credentials/` already produce) — a `CredentialChain` of length 1 is
 * exactly what a non-delegating root grant looks like.
 */
export interface CredentialChain {
  readonly hops: readonly Credential[];
}

export interface ExceedsDetail {
  readonly field: string;
  readonly reason: string;
}

/** Wraps a single root (non-delegated) hop, e.g. `issueCredential`'s output, as a length-1 `CredentialChain`. */
export function rootChain(credential: Credential): CredentialChain {
  return { hops: [credential] };
}

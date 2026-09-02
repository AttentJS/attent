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

declare const verifiedBrand: unique symbol;

/**
 * A `CredentialChain` known to have passed `verifyChain` (signature, chain
 * continuity, narrowing, splice, and depth checks). This is a compile-time-
 * only brand — no runtime property actually exists at `[verifiedBrand]` —
 * so the only way to obtain one through normal typed code is to call
 * `verifyChain()` (or the explicitly-named `unsafeAssumeVerified` escape
 * hatch). Consumers like `@attent/mcp`'s `ResolveCredential` require this
 * type specifically so an integrator cannot accidentally hand `authorize()`
 * an unverified, caller-controlled object shaped like a `CredentialChain`.
 */
export type VerifiedCredentialChain = CredentialChain & { readonly [verifiedBrand]: true };

/**
 * Escape hatch for the rare case where a chain was already verified through
 * some other trusted path (e.g. read back from a store that only ever
 * persists post-verification results) and re-running `verifyChain` would be
 * redundant. Named `unsafe` deliberately — it performs zero verification;
 * callers are asserting a fact, not establishing one. Prefer `verifyChain`.
 */
export function unsafeAssumeVerified(chain: CredentialChain): VerifiedCredentialChain {
  return chain as unknown as VerifiedCredentialChain;
}

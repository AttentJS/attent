import type { CapabilityGrant } from "../credentials/types.js";
import type { CredentialChain } from "../delegation/types.js";

/**
 * Deny reasons are a fixed, enumerable contract, not free-form
 * strings, so consuming applications can branch on `reason` reliably.
 * `signature_invalid` / `chain_tampered` / `chain_too_deep` remain reserved
 * but permanently unreachable through `authorize()`: chain/signature
 * integrity is always `verifyChain`'s job (a throw, not a `Decision` —
 * "throwing is reserved for programmer errors... and unrecoverable
 * failures"). `authorize()` only ever receives an already-verified
 * `CredentialChain` and decides allow/deny over it; it never re-runs
 * cryptographic/structural verification itself. A tampered/forged chain is
 * an adversarial input Attent rejects by never producing a `Decision` for
 * it at all, not by producing a `deny` decision.
 */
export type DenyReason =
  | "no_matching_capability"
  | "credential_expired"
  | "credential_revoked"
  | "audience_mismatch"
  | `policy_rejected:${string}`;

export interface AllowDecision {
  readonly outcome: "allow";
  readonly matchedCapability: CapabilityGrant;
}

export interface DenyDecision {
  readonly outcome: "deny";
  readonly reason: DenyReason;
}

/** The output of `authorize()` — always one or the other, never `undefined`. */
export type Decision = AllowDecision | DenyDecision;

export interface AuthorizeInput {
  /** An already-verified (`verifyChain`) or freshly-issued/delegated full root-to-leaf chain. */
  readonly credential: CredentialChain;
  readonly action: string;
  readonly resource: string;
  readonly context?: Readonly<Record<string, unknown>>;
}

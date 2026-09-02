import { sha256Base64Url } from "../crypto/hash.js";
import type { KeyProvider } from "../crypto/types.js";
import type { Identity } from "../identity/types.js";
import { MAX_TTL_SECONDS } from "../credentials/types.js";
import type { CapabilityGrant, Credential, HopClaims } from "../credentials/types.js";
import type { Clock } from "../credentials/clock.js";
import { systemClock } from "../credentials/clock.js";
import { InvalidCredentialInputError, TtlTooLongError } from "../credentials/errors.js";
import { intersectAudience, intersectCapabilities } from "./narrow.js";
import { ExceedsAvailableAuthorityError, MaxDelegationDepthExceededError } from "./errors.js";
import type { CredentialChain, ExceedsDetail } from "./types.js";
import { DEFAULT_MAX_DELEGATION_DEPTH } from "./types.js";

export interface DelegateInput {
  /** The delegator's own, already-held chain (its `iss`/signing identity is that chain's leaf `sub`). */
  readonly from: CredentialChain;
  readonly to: Identity;
  /** Signing key for the delegator (leaf `sub` of `from`) — never inspected beyond `.sign()`. */
  readonly keyProvider: KeyProvider;
  readonly grant: readonly CapabilityGrant[];
  /** Requested resource-namespace(s) for the new hop; defaults to the parent leaf's `aud` if omitted. */
  readonly aud?: string | readonly string[];
  /** Time-to-live in seconds; must be a positive integer, and cannot outlive the parent leaf. */
  readonly ttlSeconds: number;
  readonly clock?: Clock;
  readonly maxDelegationDepth?: number;
}

/**
 * Delegates a narrowed subset of `from`'s effective authority to `to`,
 * appending one new signed hop to the chain (§7). `intersectCapabilities`/
 * `intersectAudience` (the same functions chain verification re-derives,
 * `narrow.ts`) decide whether `grant`/`aud` are fully covered by the
 * parent leaf's effective capabilities/`aud`; if not, this **throws**
 * `ExceedsAvailableAuthorityError` rather than silently issuing a narrower
 * credential than requested (§7's corrected reject-not-clip rule) — the
 * same rule is applied to `exp` here for consistency (a `ttlSeconds` that
 * would outlive the parent is also a reject, not a silent clamp, since
 * silently truncating a requested TTL is exactly the kind of "wider grant
 * than what was actually issued" surprise the reject-not-clip rule exists
 * to prevent).
 */
export async function delegate(input: DelegateInput): Promise<CredentialChain> {
  const { from, to, keyProvider, grant, ttlSeconds } = input;
  const clock = input.clock ?? systemClock();
  const maxDepth = input.maxDelegationDepth ?? DEFAULT_MAX_DELEGATION_DEPTH;

  if (from.hops.length === 0) {
    throw new InvalidCredentialInputError("cannot delegate from an empty chain");
  }
  if (from.hops.length >= maxDepth) {
    throw new MaxDelegationDepthExceededError(maxDepth);
  }
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new InvalidCredentialInputError("ttlSeconds must be a positive integer");
  }
  if (ttlSeconds > MAX_TTL_SECONDS) {
    throw new TtlTooLongError(ttlSeconds, MAX_TTL_SECONDS);
  }
  if (!Array.isArray(grant) || grant.length === 0) {
    throw new InvalidCredentialInputError("grant must be a non-empty array of capabilities");
  }

  const parentLeaf = from.hops[from.hops.length - 1]!;
  const requestedAud = input.aud ?? parentLeaf.claims.aud;

  const exceeded: ExceedsDetail[] = [];

  const capResult = intersectCapabilities(parentLeaf.claims.capabilities, grant);
  exceeded.push(...capResult.exceeded);

  const audResult = intersectAudience(parentLeaf.claims.aud, requestedAud);
  exceeded.push(...audResult.exceeded);

  const iat = Math.floor(clock.now().getTime() / 1000);
  const exp = iat + ttlSeconds;
  if (exp > parentLeaf.claims.exp) {
    exceeded.push({
      field: "exp",
      reason: `requested expiry (${exp}) is later than parent's expiry (${parentLeaf.claims.exp})`,
    });
  }

  if (exceeded.length > 0) {
    throw new ExceedsAvailableAuthorityError(exceeded);
  }

  const claims: HopClaims = {
    iss: parentLeaf.claims.sub,
    sub: to.id,
    aud: audResult.aud,
    capabilities: capResult.capabilities,
    jti: crypto.randomUUID(),
    iat,
    exp,
    parentHopHash: sha256Base64Url(parentLeaf.jws),
  };

  const jws = await keyProvider.sign(claims as unknown as Record<string, unknown>);
  const hop: Credential = { jws, claims };

  return { hops: [...from.hops, hop] };
}

import { sha256Base64Url } from "../crypto/hash.js";
import type { TrustedKeyStore } from "../crypto/types.js";
import type { Credential } from "../credentials/types.js";
import type { Clock } from "../credentials/clock.js";
import { systemClock } from "../credentials/clock.js";
import { verifyCredential } from "../credentials/credentials.js";
import { intersectAudience, intersectCapabilities } from "./narrow.js";
import { ChainContinuityError, ChainHashMismatchError, ChainNarrowingViolationError, ChainTooDeepError } from "./errors.js";
import type { ExceedsDetail, VerifiedCredentialChain } from "./types.js";
import { DEFAULT_MAX_DELEGATION_DEPTH } from "./types.js";

export interface VerifyChainInput {
  /** Compact JWS strings, root hop first, leaf hop last. */
  readonly hops: readonly string[];
  readonly trustedKeys: TrustedKeyStore;
  readonly clock?: Clock;
  readonly maxDelegationDepth?: number;
}

/**
 * Walks a full delegation chain root-to-leaf (§7's "Chain verification"),
 * mandatory and non-partial: (a) every hop's signature verified against its
 * claimed issuer's trusted key + algorithm allowlist + expiry (delegates to
 * `verifyCredential` per hop, so a bad signature/alg/expiry throws from
 * there); (b) `sub` of hop *n* must equal `iss` of hop *n+1*; (c)
 * `capabilities`/`aud` of hop *n+1* re-derived as a structural subset of
 * hop *n*'s via the same `intersectCapabilities`/`intersectAudience` used
 * at issuance — belt-and-suspenders (§22/§23), catches a violation even if
 * `delegate()` had a bug; (d) `parentHopHash` of hop *n+1* matches the hash
 * of hop *n*'s `jws` (chain-splice defense, T8); (e) `exp` of hop *n+1* is
 * never later than hop *n*'s; (f) total depth ≤ `maxDelegationDepth`.
 * Revocation is deliberately NOT checked here (§13) — that's `authorize()`'s
 * mandatory, `RevocationStore`-backed job (T9); this function has no
 * storage dependency by design, matching Phase 1-3's existing
 * `verifyCredential` (crypto/structural verification only).
 */
export async function verifyChain(input: VerifyChainInput): Promise<VerifiedCredentialChain> {
  const { hops, trustedKeys } = input;
  const clock = input.clock ?? systemClock();
  const maxDepth = input.maxDelegationDepth ?? DEFAULT_MAX_DELEGATION_DEPTH;

  if (hops.length === 0) {
    throw new ChainContinuityError("chain must contain at least one hop");
  }
  if (hops.length > maxDepth) {
    throw new ChainTooDeepError(maxDepth, hops.length);
  }

  const verified: Credential[] = [];
  for (const jws of hops) {
    // Each hop's signature/alg/expiry is independently verified here —
    // propagates as a throw (MalformedCredentialError/CredentialVerificationError/
    // CredentialExpiredError) exactly as Phase 2 already documented.
    verified.push(await verifyCredential({ jws, trustedKeys, clock }));
  }

  const root = verified[0]!;
  if (root.claims.parentHopHash !== undefined) {
    throw new ChainContinuityError("root hop must not declare a parentHopHash");
  }

  for (let i = 1; i < verified.length; i++) {
    const parent = verified[i - 1]!;
    const child = verified[i]!;

    if (parent.claims.sub !== child.claims.iss) {
      throw new ChainContinuityError(
        `hop ${i} issuer ("${child.claims.iss}") does not match hop ${i - 1} subject ("${parent.claims.sub}")`
      );
    }

    if (child.claims.parentHopHash !== sha256Base64Url(parent.jws)) {
      throw new ChainHashMismatchError();
    }

    const exceeded: ExceedsDetail[] = [];

    const capResult = intersectCapabilities(parent.claims.capabilities, child.claims.capabilities);
    exceeded.push(...capResult.exceeded);

    const audResult = intersectAudience(parent.claims.aud, child.claims.aud);
    exceeded.push(...audResult.exceeded);

    if (child.claims.exp > parent.claims.exp) {
      exceeded.push({
        field: "exp",
        reason: `hop ${i} expiry (${child.claims.exp}) is later than hop ${i - 1} expiry (${parent.claims.exp})`,
      });
    }

    if (exceeded.length > 0) {
      throw new ChainNarrowingViolationError(exceeded);
    }
  }

  return { hops: verified } as unknown as VerifiedCredentialChain;
}

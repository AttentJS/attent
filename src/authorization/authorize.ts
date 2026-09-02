import type { Clock } from "../credentials/clock.js";
import { systemClock } from "../credentials/clock.js";
import type { RevocationStore } from "../revocation/types.js";
import type { PolicyEvaluator } from "../policy/types.js";
import { defaultPolicyEvaluator } from "../policy/default.js";
import { assertConcrete, matchAnyPattern, matchPattern } from "./grammar.js";
import type { AuthorizeInput, Decision } from "./types.js";

export interface AuthorizeOptions {
  readonly revocationStore: RevocationStore;
  readonly policyEvaluator?: PolicyEvaluator;
  readonly clock?: Clock;
}

/**
 * `authorize()` (§6/§26) — evaluated against an already-verified
 * `credential` chain (signature/structural-narrowing/chain integrity is
 * `verifyChain`'s job, a throw not a `Decision` — Phase 4). Evaluation
 * order mirrors §6: revocation (T9, every hop) -> expiry (leaf) -> audience
 * (leaf) -> capability match (leaf's effective set) -> policy predicate ->
 * return. Every branch defaults to deny; malformed `action`/`resource`
 * input throws (§26), it is never silently coerced into a deny.
 *
 * Only the leaf hop's `capabilities`/`aud`/`exp` are consulted for matching
 * — by the narrowing invariant (§7/§23), every ancestor hop's effective set
 * is already a superset of the leaf's, so the leaf alone *is* the chain's
 * effective capability/audience/expiry set. Revocation is the one check
 * that must walk every hop (not just the leaf): revoking hop *n* must deny
 * every chain built on hop *n* or later (§13 cascade), and any such chain
 * necessarily contains hop *n* somewhere in its own `hops` array.
 */
export async function authorize(input: AuthorizeInput, options: AuthorizeOptions): Promise<Decision> {
  const context = input.context ?? {};
  const clock = options.clock ?? systemClock();
  const policyEvaluator = options.policyEvaluator ?? defaultPolicyEvaluator();

  const actionSegments = assertConcrete(input.action, "action");
  const resourceSegments = assertConcrete(input.resource, "resource");

  const { hops } = input.credential;
  const leaf = hops[hops.length - 1]!;
  const { claims } = leaf;

  for (const hop of hops) {
    let revoked: boolean;
    try {
      revoked = await options.revocationStore.isRevoked(hop.claims.jti);
    } catch {
      // Fail-closed (T9): a store that can't answer is never treated as "not revoked".
      revoked = true;
    }
    if (revoked) {
      return { outcome: "deny", reason: "credential_revoked" };
    }
  }

  const nowSeconds = Math.floor(clock.now().getTime() / 1000);
  if (nowSeconds >= claims.exp) {
    return { outcome: "deny", reason: "credential_expired" };
  }

  const audList = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!matchAnyPattern(audList, resourceSegments)) {
    return { outcome: "deny", reason: "audience_mismatch" };
  }

  const structuralMatches = claims.capabilities.filter(
    (cap) => matchPattern(cap.action, actionSegments) && matchPattern(cap.resource, resourceSegments)
  );

  if (structuralMatches.length === 0) {
    return { outcome: "deny", reason: "no_matching_capability" };
  }

  for (const capability of structuralMatches) {
    const passes = policyEvaluator.evaluate({ capability, action: input.action, resource: input.resource, context });
    if (passes) {
      return { outcome: "allow", matchedCapability: capability };
    }
  }

  return { outcome: "deny", reason: `policy_rejected:${policyEvaluator.name}` };
}

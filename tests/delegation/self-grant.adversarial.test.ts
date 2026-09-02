import { describe, it, expect } from "vitest";
import { makeActor, scenario, issueRoot } from "../fixtures/chain.js";
import { delegate } from "../../src/delegation/delegate.js";
import { verifyChain } from "../../src/delegation/chain.js";
import { ExceedsAvailableAuthorityError, ChainNarrowingViolationError } from "../../src/delegation/errors.js";
import { sha256Base64Url } from "../../src/crypto/hash.js";
import type { HopClaims } from "../../src/credentials/types.js";

/**
 * No public API path lets a Principal mint a
 * hop naming itself `issuer` for capabilities it didn't already hold as
 * `subject` of a prior hop. Two angles: (1) going through `delegate()`
 * with `to === self`, and (2) hand-crafting a self-issued hop directly,
 * bypassing `delegate()` entirely — both must fail identically to
 * delegating/granting to anyone else, since no code path special-cases
 * "self".
 */
describe("agent-cannot-self-issue-broader-hop", () => {
  it("delegate() to oneself applies the identical narrowing check as delegating to anyone else", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const agentChain = await issueRoot(root, agent, [
      { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } },
    ]);

    await expect(
      delegate({
        from: agentChain,
        to: agent.identity,
        keyProvider: agent.keys,
        grant: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 999 } }],
        ttlSeconds: 60,
      })
    ).rejects.toThrow(ExceedsAvailableAuthorityError);
  });

  it("a hand-crafted self-issued hop with inflated capabilities fails chain verification (belt-and-suspenders)", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });

    const rootChainForAgent = await issueRoot(root, agent, [
      { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } },
    ]);
    const parentHop = rootChainForAgent.hops[0]!;

    // Agent mints a hop naming itself as both issuer and subject, claiming
    // authority beyond what it actually holds — bypassing delegate()'s
    // reject entirely (as if delegate() didn't exist or had a bug).
    const selfClaims: HopClaims = {
      iss: agent.identity.id,
      sub: agent.identity.id,
      aud: parentHop.claims.aud,
      capabilities: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 999999 } }],
      jti: crypto.randomUUID(),
      iat: parentHop.claims.iat,
      exp: parentHop.claims.exp,
      parentHopHash: sha256Base64Url(parentHop.jws),
    };
    const selfJws = await agent.keys.sign(selfClaims as unknown as Record<string, unknown>);

    await expect(
      verifyChain({ hops: [parentHop.jws, selfJws], trustedKeys })
    ).rejects.toThrow(ChainNarrowingViolationError);
  });
});

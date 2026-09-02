import { describe, it, expect } from "vitest";
import { makeActor, scenario, issueRoot, fixedClock } from "../fixtures/chain.js";
import { delegate } from "../../src/delegation/delegate.js";
import { ExceedsAvailableAuthorityError } from "../../src/delegation/errors.js";

describe("delegation expiry — child-cannot-outlive-parent", () => {
  it("accepts a child ttl that keeps it within the parent's expiry", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const tool = await makeActor(trustedKeys, { kind: "agent", name: "tool", createdBy: agent.identity.id });
    const issuedAt = new Date("2026-01-01T00:00:00Z");
    const clock = fixedClock(issuedAt);

    const parentChain = await issueRoot(root, agent, [{ action: "orders:read", resource: "order:*" }], {
      ttlSeconds: 900,
      clock,
    });

    const child = await delegate({
      from: parentChain,
      to: tool.identity,
      keyProvider: agent.keys,
      grant: [{ action: "orders:read", resource: "order:*" }],
      ttlSeconds: 300,
      clock,
    });
    expect(child.hops[1]!.claims.exp).toBeLessThanOrEqual(parentChain.hops[0]!.claims.exp);
  });

  it("throws (does not silently clamp) when the requested ttl would outlive the parent", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const tool = await makeActor(trustedKeys, { kind: "agent", name: "tool", createdBy: agent.identity.id });
    const clock = fixedClock(new Date("2026-01-01T00:00:00Z"));

    const parentChain = await issueRoot(root, agent, [{ action: "orders:read", resource: "order:*" }], {
      ttlSeconds: 60,
      clock,
    });

    await expect(
      delegate({
        from: parentChain,
        to: tool.identity,
        keyProvider: agent.keys,
        grant: [{ action: "orders:read", resource: "order:*" }],
        ttlSeconds: 3600,
        clock,
      })
    ).rejects.toThrow(ExceedsAvailableAuthorityError);
  });
});

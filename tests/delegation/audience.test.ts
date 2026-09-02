import { describe, it, expect } from "vitest";
import { makeActor, scenario, issueRoot } from "../fixtures/chain.js";
import { delegate } from "../../src/delegation/delegate.js";
import { ExceedsAvailableAuthorityError } from "../../src/delegation/errors.js";

describe("delegate() — rejects-over-broad-audience", () => {
  it("throws when the requested aud is broader than the parent's aud", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const tool = await makeActor(trustedKeys, { kind: "agent", name: "tool", createdBy: agent.identity.id });

    const parentChain = await issueRoot(root, agent, [{ action: "orders:read", resource: "order:*" }], {
      aud: "order:18472",
    });

    await expect(
      delegate({
        from: parentChain,
        to: tool.identity,
        keyProvider: agent.keys,
        grant: [{ action: "orders:read", resource: "order:18472" }],
        aud: "order:*",
        ttlSeconds: 60,
      })
    ).rejects.toThrow(ExceedsAvailableAuthorityError);
  });

  it("accepts a requested aud that narrows the parent's aud", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const tool = await makeActor(trustedKeys, { kind: "agent", name: "tool", createdBy: agent.identity.id });

    const parentChain = await issueRoot(root, agent, [{ action: "orders:read", resource: "order:*" }], {
      aud: "order:*",
    });

    const child = await delegate({
      from: parentChain,
      to: tool.identity,
      keyProvider: agent.keys,
      grant: [{ action: "orders:read", resource: "order:18472" }],
      aud: "order:18472",
      ttlSeconds: 60,
    });
    expect(child.hops[1]!.claims.aud).toBe("order:18472");
  });
});

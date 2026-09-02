import { describe, it, expect } from "vitest";
import { makeActor, scenario, issueRoot } from "../fixtures/chain.js";
import { delegate } from "../../src/delegation/delegate.js";
import { ExceedsAvailableAuthorityError } from "../../src/delegation/errors.js";
import { verifyChain } from "../../src/delegation/chain.js";

describe("delegate() — valid narrowing", () => {
  it("issues a 2-hop chain narrower than the parent, verifiable end-to-end", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "support-agent", createdBy: root.identity.id });
    const tool = await makeActor(trustedKeys, { kind: "agent", name: "refund-tool", createdBy: agent.identity.id });

    const agentChain = await issueRoot(
      root,
      agent,
      [
        { action: "orders:read", resource: "order:*" },
        { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } },
      ],
      { ttlSeconds: 900 }
    );

    const toolChain = await delegate({
      from: agentChain,
      to: tool.identity,
      keyProvider: agent.keys,
      grant: [{ action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } }],
      ttlSeconds: 120,
    });

    expect(toolChain.hops).toHaveLength(2);
    expect(toolChain.hops[1]!.claims.iss).toBe(agent.identity.id);
    expect(toolChain.hops[1]!.claims.sub).toBe(tool.identity.id);

    const verified = await verifyChain({ hops: toolChain.hops.map((h) => h.jws), trustedKeys });
    expect(verified.hops).toHaveLength(2);
  });

  it("defaults the child's aud to the parent's aud when not specified", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const tool = await makeActor(trustedKeys, { kind: "agent", name: "tool", createdBy: agent.identity.id });
    const chain = await issueRoot(root, agent, [{ action: "orders:read", resource: "order:*" }], {
      aud: "order:*",
    });
    const child = await delegate({
      from: chain,
      to: tool.identity,
      keyProvider: agent.keys,
      grant: [{ action: "orders:read", resource: "order:*" }],
      ttlSeconds: 60,
    });
    expect(child.hops[1]!.claims.aud).toBe("order:*");
  });
});

describe("delegate() — rejects-over-broad-request (naive-union attack)", () => {
  it("throws ExceedsAvailableAuthorityError with structured detail when the requested grant exceeds the parent's", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const tool = await makeActor(trustedKeys, { kind: "agent", name: "tool", createdBy: agent.identity.id });

    const agentChain = await issueRoot(root, agent, [
      { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } },
    ]);

    await expect(
      delegate({
        from: agentChain,
        to: tool.identity,
        keyProvider: agent.keys,
        grant: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 500 } }],
        ttlSeconds: 60,
      })
    ).rejects.toThrow(ExceedsAvailableAuthorityError);

    try {
      await delegate({
        from: agentChain,
        to: tool.identity,
        keyProvider: agent.keys,
        grant: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 500 } }],
        ttlSeconds: 60,
      });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(ExceedsAvailableAuthorityError);
      const e = err as ExceedsAvailableAuthorityError;
      expect(e.details.length).toBeGreaterThan(0);
      expect(e.details[0]!.field).toBe("capabilities[0]");
    }
  });

  it("throws for a wildcard-widening resource request even when the action pattern matches", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const tool = await makeActor(trustedKeys, { kind: "agent", name: "tool", createdBy: agent.identity.id });
    const agentChain = await issueRoot(root, agent, [{ action: "orders:read", resource: "order:18472" }]);

    await expect(
      delegate({
        from: agentChain,
        to: tool.identity,
        keyProvider: agent.keys,
        grant: [{ action: "orders:read", resource: "order:*" }],
        ttlSeconds: 60,
      })
    ).rejects.toThrow(ExceedsAvailableAuthorityError);
  });
});

describe("delegate() — malformed input", () => {
  it("throws for a non-positive ttlSeconds", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const chain = await issueRoot(root, agent, [{ action: "orders:read", resource: "order:*" }]);
    await expect(
      delegate({ from: chain, to: agent.identity, keyProvider: root.keys, grant: [{ action: "orders:read", resource: "order:*" }], ttlSeconds: 0 })
    ).rejects.toThrow();
  });

  it("throws for an empty grant array", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const chain = await issueRoot(root, agent, [{ action: "orders:read", resource: "order:*" }]);
    await expect(
      delegate({ from: chain, to: agent.identity, keyProvider: root.keys, grant: [], ttlSeconds: 60 })
    ).rejects.toThrow();
  });
});

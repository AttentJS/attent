import { describe, it, expect } from "vitest";
import { makeActor, scenario, issueRoot } from "../fixtures/chain.js";
import { delegate } from "../../src/delegation/delegate.js";
import { verifyChain } from "../../src/delegation/chain.js";
import { MaxDelegationDepthExceededError, ChainTooDeepError } from "../../src/delegation/errors.js";

const CAP = [{ action: "orders:read", resource: "order:*" }] as const;

describe("delegation depth — issuance-rejects-over-depth", () => {
  it("delegate() throws once the chain would exceed maxDelegationDepth", async () => {
    const { trustedKeys, root } = await scenario();
    const maxDepth = 3;

    const hop1 = await makeActor(trustedKeys, { kind: "agent", name: "hop-1", createdBy: root.identity.id });
    let chain = await issueRoot(root, hop1, [...CAP]);
    let signer = hop1.keys;

    // hop 0 (root->hop1) already issued. Delegating up to hops.length === maxDepth must still
    // succeed (maxDepth - 1 more delegations); one delegation beyond that must throw.
    for (let i = 0; i < maxDepth - 1; i++) {
      const next = await makeActor(trustedKeys, { kind: "agent", name: `hop-${i + 2}`, createdBy: root.identity.id });
      chain = await delegate({ from: chain, to: next.identity, keyProvider: signer, grant: [...CAP], ttlSeconds: 900, maxDelegationDepth: maxDepth });
      signer = next.keys;
    }
    expect(chain.hops).toHaveLength(maxDepth);

    const oneMore = await makeActor(trustedKeys, { kind: "agent", name: "too-deep", createdBy: root.identity.id });
    await expect(
      delegate({ from: chain, to: oneMore.identity, keyProvider: signer, grant: [...CAP], ttlSeconds: 900, maxDelegationDepth: maxDepth })
    ).rejects.toThrow(MaxDelegationDepthExceededError);
  });
});

describe("delegation depth — verify-rejects-over-depth", () => {
  it("verifyChain() rejects a chain longer than maxDelegationDepth even if issuance somehow produced it", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const tool = await makeActor(trustedKeys, { kind: "agent", name: "tool", createdBy: agent.identity.id });

    let chain = await issueRoot(root, agent, [...CAP]);
    chain = await delegate({ from: chain, to: tool.identity, keyProvider: agent.keys, grant: [...CAP], ttlSeconds: 900 });

    expect(chain.hops).toHaveLength(2);

    await expect(
      verifyChain({ hops: chain.hops.map((h) => h.jws), trustedKeys, maxDelegationDepth: 1 })
    ).rejects.toThrow(ChainTooDeepError);
  });
});

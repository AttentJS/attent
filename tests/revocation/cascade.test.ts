import { describe, it, expect } from "vitest";
import { makeActor, scenario, issueRoot } from "../fixtures/chain.js";
import { delegate } from "../../src/delegation/delegate.js";
import { authorize } from "../../src/authorization/authorize.js";
import { memoryRevocationStore, revoke } from "../../src/revocation/index.js";

const CAP = { action: "orders:read", resource: "order:*" } as const;

describe("revocation cascade — revoke-mid-chain-kills-descendants-only (§13)", () => {
  it("revoking a mid-chain hop denies every chain built on it or later, but not ancestors or unrelated siblings", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const toolA = await makeActor(trustedKeys, { kind: "agent", name: "tool-a", createdBy: agent.identity.id });
    const toolB = await makeActor(trustedKeys, { kind: "agent", name: "tool-b", createdBy: agent.identity.id });
    const subTool = await makeActor(trustedKeys, { kind: "agent", name: "sub-tool", createdBy: toolA.identity.id });

    const hop1Chain = await issueRoot(root, agent, [CAP]); // hop 1: root -> agent
    const hop2aChain = await delegate({ from: hop1Chain, to: toolA.identity, keyProvider: agent.keys, grant: [CAP], ttlSeconds: 900 }); // hop 2a: agent -> toolA
    const hop2bChain = await delegate({ from: hop1Chain, to: toolB.identity, keyProvider: agent.keys, grant: [CAP], ttlSeconds: 900 }); // hop 2b (sibling): agent -> toolB
    const hop3Chain = await delegate({ from: hop2aChain, to: subTool.identity, keyProvider: toolA.keys, grant: [CAP], ttlSeconds: 900 }); // hop 3: toolA -> subTool

    const store = memoryRevocationStore();

    // Everything allowed before revocation.
    for (const chain of [hop1Chain, hop2aChain, hop2bChain, hop3Chain]) {
      const decision = await authorize({ credential: chain, action: "orders:read", resource: "order:1" }, { revocationStore: store });
      expect(decision.outcome).toBe("allow");
    }

    // Revoke hop 2a specifically (agent -> toolA), not the whole toolA chain object — pass the
    // chain truncated to that hop.
    await revoke({ credential: hop2aChain, store });

    const hop1Decision = await authorize({ credential: hop1Chain, action: "orders:read", resource: "order:1" }, { revocationStore: store });
    expect(hop1Decision.outcome).toBe("allow"); // ancestor unaffected

    const hop2bDecision = await authorize({ credential: hop2bChain, action: "orders:read", resource: "order:1" }, { revocationStore: store });
    expect(hop2bDecision.outcome).toBe("allow"); // unrelated sibling unaffected

    const hop2aDecision = await authorize({ credential: hop2aChain, action: "orders:read", resource: "order:1" }, { revocationStore: store });
    expect(hop2aDecision).toEqual({ outcome: "deny", reason: "credential_revoked" }); // revoked hop itself

    const hop3Decision = await authorize({ credential: hop3Chain, action: "orders:read", resource: "order:1" }, { revocationStore: store });
    expect(hop3Decision).toEqual({ outcome: "deny", reason: "credential_revoked" }); // descendant of revoked hop
  });
});

import { describe, expect, it, vi } from "vitest";
import { delegate, memoryRevocationStore, verifyChain } from "attent";
import type { CallToolRequest, CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { resolveVerifiedCredential, withAttent } from "../src/index.js";
import { issueRoot, makeActor, scenario } from "./fixtures.js";

function callToolRequest(attentCredential: unknown): CallToolRequest {
  return {
    method: "tools/call",
    params: {
      name: "create",
      arguments: { orderId: "18472", amount: 15 },
      _meta: attentCredential === undefined ? undefined : { attentCredential },
    },
  };
}

function wiredHandler(trustedKeys: Parameters<typeof resolveVerifiedCredential>[0]["trustedKeys"]): {
  handler: ReturnType<typeof vi.fn<() => CallToolResult>>;
  wrapped: ReturnType<typeof withAttent>;
} {
  const handler = vi.fn((): CallToolResult => ({ content: [{ type: "text", text: "refunded" }] }));
  const wrapped = withAttent(
    {
      resolveCredential: resolveVerifiedCredential({ trustedKeys }),
      actionForTool: (tool) => `refunds:${tool}`,
      resourceForArgs: (_tool, args) => `order:${String(args.orderId)}`,
      contextForArgs: (_tool, args) => ({ amount: args.amount }),
      revocationStore: memoryRevocationStore(),
    },
    handler
  );
  return { handler, wrapped };
}

describe("withAttent + resolveVerifiedCredential — adversarial MCP inputs", () => {
  it("denies and never invokes the handler when _meta is entirely absent", async () => {
    const { trustedKeys } = await scenario();
    const { handler, wrapped } = wiredHandler(trustedKeys);

    const result = await wrapped(callToolRequest(undefined), undefined);

    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain("attent:no_credential");
  });

  it("denies when attentCredential is an empty array", async () => {
    const { trustedKeys } = await scenario();
    const { handler, wrapped } = wiredHandler(trustedKeys);

    const result = await wrapped(callToolRequest([]), undefined);

    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
  });

  it("denies when attentCredential is not an array of strings (garbage shape)", async () => {
    const { trustedKeys } = await scenario();
    const { handler, wrapped } = wiredHandler(trustedKeys);

    const result = await wrapped(callToolRequest({ nested: "garbage" }), undefined);

    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
  });

  it("denies a tampered JWS (bit-flipped signature) without invoking the handler", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "refund-tool", createdBy: root.identity.id });
    const credential = await issueRoot(trustedKeys, root, agent, [
      { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } },
    ]);
    const { handler, wrapped } = wiredHandler(trustedKeys);

    const jws = credential.hops[0]!.jws;
    const tampered = jws.slice(0, -4) + (jws.slice(-4) === "AAAA" ? "BBBB" : "AAAA");

    const result = await wrapped(callToolRequest([tampered]), undefined);

    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain("attent:no_credential");
  });

  it("denies a chain-spliced hop (valid signature, wrong parentHopHash) without invoking the handler", async () => {
    const { trustedKeys, root } = await scenario();
    const legitAgent = await makeActor(trustedKeys, { kind: "agent", name: "legit-agent", createdBy: root.identity.id });
    const attackerAgent = await makeActor(trustedKeys, {
      kind: "agent",
      name: "attacker-agent",
      createdBy: root.identity.id,
    });

    const narrowChain = await issueRoot(trustedKeys, root, legitAgent, [
      { action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } },
    ]);
    const broadChain = await issueRoot(trustedKeys, root, attackerAgent, [
      { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 10_000 } },
    ]);

    // Attacker delegates from their own broad grant, producing a hop whose
    // parentHopHash legitimately binds to `broadChain`'s leaf — then splices
    // that hop onto `narrowChain` instead, hoping verifyChain only checks
    // continuity (sub == iss) and not the hash binding (T8).
    const splicedGrant = await delegate({
      from: broadChain,
      to: legitAgent.identity,
      keyProvider: attackerAgent.keys,
      grant: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 10_000 } }],
      ttlSeconds: 900,
    });

    const splicedJws = [narrowChain.hops[0]!.jws, splicedGrant.hops[1]!.jws];
    const { handler, wrapped } = wiredHandler(trustedKeys);

    const result = await wrapped(callToolRequest(splicedJws), undefined);

    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
  });

  it("denies (but does not error out) a verified credential presented for a different caller's resource — audience mismatch, not no_credential", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "refund-tool", createdBy: root.identity.id });
    // Valid, verifiable chain — but scoped to a different order than the one requested.
    const credential = await issueRoot(trustedKeys, root, agent, [{ action: "refunds:create", resource: "order:99999" }], {
      aud: "order:99999",
    });
    const verified = await verifyChain({ hops: credential.hops.map((h) => h.jws), trustedKeys });
    expect(verified).toBeDefined();

    const { handler, wrapped } = wiredHandler(trustedKeys);
    const result = await wrapped(callToolRequest(credential.hops.map((h) => h.jws)), undefined);

    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain("audience_mismatch");
  });

  it("rejects an oversized attentCredential array without crashing the handler wiring", async () => {
    const { trustedKeys } = await scenario();
    const { handler, wrapped } = wiredHandler(trustedKeys);

    const oversized = Array.from({ length: 10_000 }, () => "not-a-jwt");
    const result = await wrapped(callToolRequest(oversized), undefined);

    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
  });
});

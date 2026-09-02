import { describe, expect, it, vi } from "vitest";
import { createAuditEmitter, memoryRevocationStore, type AuditEvent } from "attent";
import type { CallToolRequest, CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { withAttent } from "../src/index.js";
import { issueRoot, makeActor, scenario } from "./fixtures.js";

function callToolRequest(name: string, args: Record<string, unknown> = {}): CallToolRequest {
  return { method: "tools/call", params: { name, arguments: args } };
}

describe("withAttent", () => {
  it("allow path invokes the wrapped handler and returns its result", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "refund-tool", createdBy: root.identity.id });
    const credential = await issueRoot(trustedKeys, root, agent, [
      { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } },
    ]);

    const handler = vi.fn(
      (): CallToolResult => ({ content: [{ type: "text", text: "refunded" }] })
    );

    const wrapped = withAttent(
      {
        resolveCredential: () => credential,
        actionForTool: (tool) => `refunds:${tool}`,
        resourceForArgs: (_tool, args) => `order:${String(args.orderId)}`,
        contextForArgs: (_tool, args) => ({ amount: args.amount }),
        revocationStore: memoryRevocationStore(),
      },
      handler
    );

    const result = await wrapped(callToolRequest("create", { orderId: "18472", amount: 15 }), undefined);

    expect(handler).toHaveBeenCalledOnce();
    expect(result).toEqual({ content: [{ type: "text", text: "refunded" }] });
  });

  it("deny path returns an MCP tool error and never invokes the wrapped handler", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "refund-tool", createdBy: root.identity.id });
    const credential = await issueRoot(trustedKeys, root, agent, [
      { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 20 } },
    ]);

    const handler = vi.fn((): CallToolResult => ({ content: [{ type: "text", text: "refunded" }] }));

    const wrapped = withAttent(
      {
        resolveCredential: () => credential,
        actionForTool: (tool) => `refunds:${tool}`,
        resourceForArgs: (_tool, args) => `order:${String(args.orderId)}`,
        contextForArgs: (_tool, args) => ({ amount: args.amount }),
        revocationStore: memoryRevocationStore(),
      },
      handler
    );

    // Exceeds the delegated $20 ceiling -> policy_rejected.
    const result = await wrapped(callToolRequest("create", { orderId: "18472", amount: 30 }), undefined);

    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain("denied");
  });

  it("missing credential denies without invoking the handler", async () => {
    const handler = vi.fn((): CallToolResult => ({ content: [] }));

    const wrapped = withAttent(
      {
        resolveCredential: () => undefined,
        actionForTool: (tool) => `refunds:${tool}`,
        resourceForArgs: (_tool, args) => `order:${String(args.orderId)}`,
        revocationStore: memoryRevocationStore(),
      },
      handler
    );

    const result = await wrapped(callToolRequest("create", { orderId: "1" }), undefined);

    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain("attent:no_credential");
  });

  it("emits an authorization audit event on both allow and deny", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "refund-tool", createdBy: root.identity.id });
    const credential = await issueRoot(trustedKeys, root, agent, [
      { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 20 } },
    ]);

    const events: AuditEvent[] = [];
    const emitter = createAuditEmitter();
    emitter.onAuditEvent((event) => events.push(event));

    const wrapped = withAttent(
      {
        resolveCredential: () => credential,
        actionForTool: (tool) => `refunds:${tool}`,
        resourceForArgs: (_tool, args) => `order:${String(args.orderId)}`,
        contextForArgs: (_tool, args) => ({ amount: args.amount }),
        revocationStore: memoryRevocationStore(),
        emitter,
      },
      (): CallToolResult => ({ content: [] })
    );

    await wrapped(callToolRequest("create", { orderId: "1", amount: 15 }), undefined);
    await wrapped(callToolRequest("create", { orderId: "1", amount: 30 }), undefined);

    expect(events).toHaveLength(2);
    expect(events[0]?.decision?.outcome).toBe("allow");
    expect(events[1]?.decision?.outcome).toBe("deny");
    expect(events.every((event) => event.type === "authorization")).toBe(true);
  });
});

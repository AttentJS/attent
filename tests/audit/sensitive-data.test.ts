import { describe, it, expect } from "vitest";
import { makeActor, scenario } from "../fixtures/chain.js";
import { createAuditEmitter } from "../../src/audit/emitter.js";
import { auditedAuthorize, auditedIssueCredential } from "../../src/audit/observe.js";
import { memoryRevocationStore } from "../../src/revocation/index.js";
import type { AuditEvent } from "../../src/audit/types.js";

describe("audit — sensitive-data exclusion", () => {
  it("context is absent by default even when authorize() was called with one", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const events: AuditEvent[] = [];
    const emitter = createAuditEmitter();
    emitter.onAuditEvent((e) => events.push(e));

    const credential = await auditedIssueCredential(
      {
        issuer: root.identity,
        subject: agent.identity,
        keyProvider: root.keys,
        capabilities: [{ action: "refunds:create", resource: "order:*" }],
        aud: "order:*",
        ttlSeconds: 900,
      },
      { emitter }
    );

    await auditedAuthorize(
      {
        credential: { hops: [credential] },
        action: "refunds:create",
        resource: "order:1",
        context: { amount: 15, customerEmail: "user@example.com" },
      },
      { revocationStore: memoryRevocationStore(), emitter }
    );

    const authEvent = events.find((e) => e.type === "authorization")!;
    expect(authEvent.context).toBeUndefined();
    expect(JSON.stringify(authEvent)).not.toContain("user@example.com");
  });

  it("context is included, redacted, only when includeContext + redactContext are opted in", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const events: AuditEvent[] = [];
    const emitter = createAuditEmitter();
    emitter.onAuditEvent((e) => events.push(e));

    const credential = await auditedIssueCredential(
      {
        issuer: root.identity,
        subject: agent.identity,
        keyProvider: root.keys,
        capabilities: [{ action: "refunds:create", resource: "order:*" }],
        aud: "order:*",
        ttlSeconds: 900,
      },
      { emitter }
    );

    await auditedAuthorize(
      {
        credential: { hops: [credential] },
        action: "refunds:create",
        resource: "order:1",
        context: { amount: 15, customerEmail: "user@example.com" },
      },
      {
        revocationStore: memoryRevocationStore(),
        emitter,
        includeContext: true,
        redactContext: (ctx) => ({ amount: ctx.amount }),
      }
    );

    const authEvent = events.find((e) => e.type === "authorization")!;
    expect(authEvent.context).toEqual({ amount: 15 });
  });

  it("Identity names are absent from credential_issued events unless includeNames is opted in", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "very-secret-agent-name", createdBy: root.identity.id });
    const events: AuditEvent[] = [];
    const emitter = createAuditEmitter();
    emitter.onAuditEvent((e) => events.push(e));

    await auditedIssueCredential(
      {
        issuer: root.identity,
        subject: agent.identity,
        keyProvider: root.keys,
        capabilities: [{ action: "refunds:create", resource: "order:*" }],
        aud: "order:*",
        ttlSeconds: 900,
      },
      { emitter }
    );

    expect(JSON.stringify(events[0])).not.toContain("very-secret-agent-name");
  });

  it("never records raw JWS strings or key material — only hop ids ever appear in delegationChain", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
    const events: AuditEvent[] = [];
    const emitter = createAuditEmitter();
    emitter.onAuditEvent((e) => events.push(e));

    const credential = await auditedIssueCredential(
      {
        issuer: root.identity,
        subject: agent.identity,
        keyProvider: root.keys,
        capabilities: [{ action: "refunds:create", resource: "order:*" }],
        aud: "order:*",
        ttlSeconds: 900,
      },
      { emitter }
    );

    // A compact JWS always contains two dots; assert the serialized event never embeds it.
    expect(JSON.stringify(events[0])).not.toContain(credential.jws);
  });
});

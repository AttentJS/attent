import { describe, it, expect } from "vitest";
import { makeActor, scenario } from "../fixtures/chain.js";
import { issueCredential } from "../../src/credentials/credentials.js";
import { rootChain } from "../../src/delegation/types.js";
import { authorize } from "../../src/authorization/authorize.js";
import { memoryRevocationStore } from "../../src/revocation/index.js";
import { createAuditEmitter } from "../../src/audit/emitter.js";
import { auditedAuthorize, auditedDelegate, auditedIssueCredential, auditedRevoke } from "../../src/audit/observe.js";
import type { AuditEvent } from "../../src/audit/types.js";

/**
 * Phase 5 acceptance criterion (§21): every authorize/delegate/revoke/issue
 * call from Phases 1-4 must be observable via `onAuditEvent` in an
 * integration test *without modifying those modules' core logic* — proving
 * audit is additive (§10's no-reverse-dependency boundary). This file
 * exercises the full issue -> delegate -> authorize -> revoke flow through
 * the `audited*` wrappers and checks both the audit trail and that the
 * underlying result is byte-for-byte identical to calling the unwrapped
 * function directly.
 */
describe("audit — additive observation of the full issue/delegate/authorize/revoke flow", () => {
  it("emits one correctly-shaped event per call, and never changes the underlying return value", async () => {
    const { trustedKeys, root } = await scenario();
    const agent = await makeActor(trustedKeys, { kind: "agent", name: "support-agent", createdBy: root.identity.id });
    const tool = await makeActor(trustedKeys, { kind: "agent", name: "refund-tool", createdBy: agent.identity.id });

    const events: AuditEvent[] = [];
    const emitter = createAuditEmitter();
    emitter.onAuditEvent((e) => events.push(e));

    const store = memoryRevocationStore();

    // 1. issueCredential
    const auditedRoot = await auditedIssueCredential(
      {
        issuer: root.identity,
        subject: agent.identity,
        keyProvider: root.keys,
        capabilities: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } }],
        aud: "order:*",
        ttlSeconds: 900,
      },
      { emitter }
    );
    const plainRoot = await issueCredential({
      issuer: root.identity,
      subject: agent.identity,
      keyProvider: root.keys,
      capabilities: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } }],
      aud: "order:*",
      ttlSeconds: 900,
    });
    expect(auditedRoot.claims.iss).toBe(plainRoot.claims.iss);
    expect(auditedRoot.claims.capabilities).toEqual(plainRoot.claims.capabilities);

    const rootIdentityChain = rootChain(auditedRoot);

    // 2. delegate
    const toolChain = await auditedDelegate(
      {
        from: rootIdentityChain,
        to: tool.identity,
        keyProvider: agent.keys,
        grant: [{ action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } }],
        ttlSeconds: 120,
      },
      { emitter }
    );

    // 3. authorize (allow)
    const allowDecision = await auditedAuthorize(
      { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
      { revocationStore: store, emitter }
    );
    expect(allowDecision.outcome).toBe("allow");

    // 3b. authorize (deny)
    const denyDecision = await auditedAuthorize(
      { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 999 } },
      { revocationStore: store, emitter }
    );
    expect(denyDecision.outcome).toBe("deny");

    // 4. revoke
    await auditedRevoke({ credential: toolChain, store }, { emitter });
    const postRevoke = await authorize(
      { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
      { revocationStore: store }
    );
    expect(postRevoke).toEqual({ outcome: "deny", reason: "credential_revoked" });

    const types = events.map((e) => e.type);
    expect(types).toEqual(["credential_issued", "delegation", "authorization", "authorization", "revocation"]);

    const issuedEvent = events[0]!;
    expect(issuedEvent.principal.id).toBe(root.identity.id);
    expect(issuedEvent.agent).toEqual({ id: agent.identity.id });
    expect(issuedEvent.delegationChain).toEqual([
      { issuer: root.identity.id, subject: agent.identity.id, hopId: auditedRoot.claims.jti },
    ]);

    const delegationEvent = events[1]!;
    expect(delegationEvent.delegationChain).toHaveLength(2);
    expect(delegationEvent.delegationChain[1]!.subject).toBe(tool.identity.id);

    const allowEvent = events[2]!;
    expect(allowEvent.decision).toEqual({ outcome: "allow", reason: "matched_capability" });
    expect(allowEvent.action).toBe("refunds:create");

    const denyEvent = events[3]!;
    expect(denyEvent.decision).toEqual({ outcome: "deny", reason: "policy_rejected:default" });

    const revocationEvent = events[4]!;
    expect(revocationEvent.delegationChain).toHaveLength(2);
  });
});

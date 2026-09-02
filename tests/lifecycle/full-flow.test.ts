import { describe, it, expect } from "vitest";
import { generateKeyProvider, memoryTrustedKeyStore } from "../../src/crypto/keys.js";
import { createIdentity } from "../../src/identity/identity.js";
import { rootChain } from "../../src/delegation/types.js";
import { verifyChain } from "../../src/delegation/chain.js";
import { memoryRevocationStore } from "../../src/revocation/memory.js";
import { createAuditEmitter } from "../../src/audit/emitter.js";
import { memoryAuditSink } from "../../src/audit/sink.js";
import { auditedAuthorize, auditedDelegate, auditedIssueCredential, auditedRevoke } from "../../src/audit/observe.js";
import type { AuditEvent } from "../../src/audit/types.js";
import type { Clock } from "../../src/credentials/clock.js";

function farFutureClock(): Clock {
  return { now: () => new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) };
}

/**
 * A single continuous chain: issue -> delegate -> authorize (allow) ->
 * authorize (deny, narrowing) -> revoke -> authorize (deny, revoked) ->
 * expire -> authorize (deny, expired), with real assertions at every step
 * and a full audit trail verified at the end — converts
 * examples/e2e-support-agent/index.ts's narrative demo into an automated
 * test.
 */
describe("full credential lifecycle", () => {
  it("issuance -> delegation -> authorize -> revocation -> expiry, with a complete audit trail", async () => {
    const trustedKeys = memoryTrustedKeyStore();
    const revocationStore = memoryRevocationStore();
    const sink = memoryAuditSink();
    const emitter = createAuditEmitter({ sink });

    const humanKeys = await generateKeyProvider();
    const human = createIdentity({ kind: "human", name: "acme-human", publicJWK: await humanKeys.getPublicJWK() });
    await trustedKeys.addKey(human.id, humanKeys.kid, await humanKeys.getPublicJWK());

    const agentKeys = await generateKeyProvider();
    const supportAgent = createIdentity({
      kind: "agent",
      name: "support-agent",
      createdBy: human.id,
      publicJWK: await agentKeys.getPublicJWK(),
    });
    await trustedKeys.addKey(supportAgent.id, agentKeys.kid, await agentKeys.getPublicJWK());

    const toolKeys = await generateKeyProvider();
    const refundTool = createIdentity({
      kind: "agent",
      name: "refund-tool",
      createdBy: supportAgent.id,
      publicJWK: await toolKeys.getPublicJWK(),
    });
    await trustedKeys.addKey(refundTool.id, toolKeys.kid, await toolKeys.getPublicJWK());

    // 1. Issuance.
    const agentCredential = await auditedIssueCredential(
      {
        issuer: human,
        subject: supportAgent,
        keyProvider: humanKeys,
        capabilities: [
          { action: "orders:read", resource: "order:*" },
          { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } },
        ],
        aud: "order:*",
        ttlSeconds: 900,
      },
      { emitter, requestId: "scenario-1" }
    );
    expect(agentCredential.claims.iss).toBe(human.id);
    const agentChain = rootChain(agentCredential);

    // 2. Delegation, narrowed.
    const toolChain = await auditedDelegate(
      {
        from: agentChain,
        to: refundTool,
        keyProvider: agentKeys,
        grant: [{ action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } }],
        ttlSeconds: 120,
      },
      { emitter, requestId: "scenario-2" }
    );
    expect(toolChain.hops).toHaveLength(2);

    // Chain verifies end-to-end before it's relied on.
    const verified = await verifyChain({ hops: toolChain.hops.map((hop) => hop.jws), trustedKeys });
    expect(verified.hops).toHaveLength(2);

    // 3. Authorize within the narrowed ceiling -> allow.
    const allowDecision = await auditedAuthorize(
      { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
      { revocationStore, emitter, requestId: "scenario-3" }
    );
    expect(allowDecision.outcome).toBe("allow");

    // 4. Authorize beyond the delegated (narrower) ceiling, even though the
    //    agent's own ceiling would have covered it -> deny (narrowing, T4).
    const denyOverToolCeiling = await auditedAuthorize(
      { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 30 } },
      { revocationStore, emitter, requestId: "scenario-4" }
    );
    expect(denyOverToolCeiling.outcome).toBe("deny");

    // 5. Revoke the ancestor (Support Agent) hop -> cascade denies the tool's chain.
    await auditedRevoke({ credential: agentChain, store: revocationStore }, { emitter, requestId: "scenario-5" });
    const denyAfterRevoke = await auditedAuthorize(
      { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
      { revocationStore, emitter, requestId: "scenario-5" }
    );
    expect(denyAfterRevoke.outcome).toBe("deny");
    if (denyAfterRevoke.outcome === "deny") {
      expect(denyAfterRevoke.reason).toBe("credential_revoked");
    }

    // 6. Independently of revocation, an expired credential is also denied.
    const denyExpired = await auditedAuthorize(
      { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
      { revocationStore: memoryRevocationStore(), clock: farFutureClock(), emitter, requestId: "scenario-6" }
    );
    expect(denyExpired.outcome).toBe("deny");
    if (denyExpired.outcome === "deny") {
      expect(denyExpired.reason).toBe("credential_expired");
    }

    // 7. Full audit trail is durable, queryable, and covers every step above.
    const trail: readonly AuditEvent[] = await sink.query();
    expect(trail.map((e) => e.type)).toEqual([
      "credential_issued",
      "delegation",
      "authorization",
      "authorization",
      "revocation",
      "authorization",
      "authorization",
    ]);
    const requestIds = trail.map((e) => e.requestId);
    expect(requestIds).toEqual([
      "scenario-1",
      "scenario-2",
      "scenario-3",
      "scenario-4",
      "scenario-5",
      "scenario-5",
      "scenario-6",
    ]);
  });
});

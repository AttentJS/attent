/**
 * End-to-end demo: Human (root) -> Support Agent -> Refund Tool -> Order.
 * Exercises issuance, delegation, narrowed authorization, revocation
 * cascade, expiry, and the audit trail together, not as isolated unit
 * tests. Run:
 *
 *   npm run example:e2e-support-agent
 */
import {
  generateKeyProvider,
  memoryTrustedKeyStore,
  createIdentity,
  rootChain,
  verifyChain,
  memoryRevocationStore,
  createAuditEmitter,
  auditedIssueCredential,
  auditedDelegate,
  auditedAuthorize,
  auditedRevoke,
} from "../../src/index.js";

async function main(): Promise<void> {
  const trustedKeys = memoryTrustedKeyStore();
  const revocationStore = memoryRevocationStore();
  const emitter = createAuditEmitter();
  emitter.onAuditEvent((event) => console.log(`[audit] ${event.type}`, event));

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

  // 1. Human issues Support Agent a capability: orders:read, refunds:create <= $50.
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
  const agentChain = rootChain(agentCredential);
  console.log("1. Support Agent credential issued.");

  // 2. Support Agent delegates a narrower capability to Refund Tool (<= $20, single order).
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
  console.log("2. Refund Tool delegated a narrower capability.");

  // Prove the presented chain verifies end-to-end before relying on it below.
  await verifyChain({ hops: toolChain.hops.map((hop) => hop.jws), trustedKeys });

  // 3. Refund Tool calls authorize() for a $15 refund on that order -> allow.
  const allowDecision = await auditedAuthorize(
    { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
    { revocationStore, emitter, requestId: "scenario-3" }
  );
  console.log("3. $15 refund:", allowDecision);

  // 4. Refund Tool attempts a $30 refund (exceeds its own $20 ceiling, even though
  //    Support Agent's own ceiling was $50) -> deny, demonstrating narrowing (T4).
  const denyOverToolCeiling = await auditedAuthorize(
    { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 30 } },
    { revocationStore, emitter, requestId: "scenario-4" }
  );
  console.log("4. $30 refund (exceeds tool's delegated $20 ceiling, not agent's $50):", denyOverToolCeiling);

  // 5. Human revokes the Support Agent -> Refund Tool's already-issued credential
  //    is now denied on next authorize() call (cascade).
  await auditedRevoke({ credential: agentChain, store: revocationStore }, { emitter, requestId: "scenario-5" });
  const denyAfterRevoke = await auditedAuthorize(
    { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
    { revocationStore, emitter, requestId: "scenario-5" }
  );
  console.log("5. Same $15 refund after revoking Support Agent (cascade, denied):", denyAfterRevoke);

  // 6. Attempt authorize() with a manually expired credential -> deny, "credential_expired".
  const farFuture = { now: (): Date => new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) };
  const denyExpired = await auditedAuthorize(
    { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
    { revocationStore: memoryRevocationStore(), clock: farFuture, emitter, requestId: "scenario-6" }
  );
  console.log("6. Same request against a manually-expired clock:", denyExpired);

  // 7. All of the above were emitted as audit events above (printed as they occurred);
  //    pull-based confirmation that the trail is complete and inspectable.
  console.log("7. Audit trail is the printed [audit] lines above (push-based `onAuditEvent`).");
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});

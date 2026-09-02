/**
 * Delegation example: a 2-hop delegation chain, showing structural
 * narrowing in action — the tool ends up strictly less capable than the
 * agent that delegated to it, and an over-broad delegation attempt is
 * rejected outright. Run:
 *
 *   npm run example:delegation
 */
import {
  generateKeyProvider,
  memoryTrustedKeyStore,
  createIdentity,
  issueCredential,
  rootChain,
  delegate,
  verifyChain,
  ExceedsAvailableAuthorityError,
} from "../../src/index.js";

async function main(): Promise<void> {
  const trustedKeys = memoryTrustedKeyStore();

  const rootKeys = await generateKeyProvider();
  const root = createIdentity({ kind: "application", name: "acme-app", publicJWK: await rootKeys.getPublicJWK() });
  await trustedKeys.addKey(root.id, rootKeys.kid, await rootKeys.getPublicJWK());

  const agentKeys = await generateKeyProvider();
  const agent = createIdentity({
    kind: "agent",
    name: "support-agent",
    createdBy: root.id,
    publicJWK: await agentKeys.getPublicJWK(),
  });
  await trustedKeys.addKey(agent.id, agentKeys.kid, await agentKeys.getPublicJWK());

  const toolKeys = await generateKeyProvider();
  const tool = createIdentity({
    kind: "agent",
    name: "refund-tool",
    createdBy: agent.id,
    publicJWK: await toolKeys.getPublicJWK(),
  });
  await trustedKeys.addKey(tool.id, toolKeys.kid, await toolKeys.getPublicJWK());

  // Hop 1: root -> support-agent, up to $50 refunds.
  const agentCredential = await issueCredential({
    issuer: root,
    subject: agent,
    keyProvider: rootKeys,
    capabilities: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } }],
    aud: "order:*",
    ttlSeconds: 900,
  });
  const agentChain = rootChain(agentCredential);

  // Hop 2: support-agent -> refund-tool, narrowed to $20 on one order.
  const toolChain = await delegate({
    from: agentChain,
    to: tool,
    keyProvider: agentKeys,
    grant: [{ action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } }],
    ttlSeconds: 120,
  });

  const verified = await verifyChain({ hops: toolChain.hops.map((h) => h.jws), trustedKeys });
  console.log(
    "verified 2-hop chain, effective capability:",
    verified.hops[verified.hops.length - 1]!.claims.capabilities
  );

  // Attempting to delegate a wider grant than the agent itself holds is rejected, not silently clipped.
  try {
    await delegate({
      from: agentChain,
      to: tool,
      keyProvider: agentKeys,
      grant: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 500 } }],
      ttlSeconds: 120,
    });
  } catch (err) {
    if (err instanceof ExceedsAvailableAuthorityError) {
      console.log("over-broad delegation correctly rejected:", err.details);
    } else {
      throw err;
    }
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});

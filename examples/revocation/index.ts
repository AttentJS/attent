/**
 * Revocation example: issue a credential, use it, revoke it, show
 * reuse is denied, then show revocation cascades to a hop delegated from the
 * revoked one. Run:
 *
 *   npm run example:revocation
 */
import {
  generateKeyProvider,
  createIdentity,
  issueCredential,
  rootChain,
  delegate,
  authorize,
  revoke,
  memoryRevocationStore,
} from "../../src/index.js";

async function main(): Promise<void> {
  const store = memoryRevocationStore();

  const rootKeys = await generateKeyProvider();
  const root = createIdentity({ kind: "application", name: "acme-app", publicJWK: await rootKeys.getPublicJWK() });

  const agentKeys = await generateKeyProvider();
  const agent = createIdentity({
    kind: "agent",
    name: "support-agent",
    createdBy: root.id,
    publicJWK: await agentKeys.getPublicJWK(),
  });

  const credential = await issueCredential({
    issuer: root,
    subject: agent,
    keyProvider: rootKeys,
    capabilities: [{ action: "orders:read", resource: "order:*" }],
    aud: "order:*",
    ttlSeconds: 900,
  });
  const chain = rootChain(credential);

  console.log(
    "before revoke:",
    await authorize({ credential: chain, action: "orders:read", resource: "order:1" }, { revocationStore: store })
  );

  await revoke({ credential: chain, store });

  console.log(
    "reuse after revoke (denied):",
    await authorize({ credential: chain, action: "orders:read", resource: "order:1" }, { revocationStore: store })
  );

  // Cascade demo: revoking an ancestor hop denies every chain delegated from it too.
  const toolKeys = await generateKeyProvider();
  const tool = createIdentity({
    kind: "agent",
    name: "refund-tool",
    createdBy: agent.id,
    publicJWK: await toolKeys.getPublicJWK(),
  });

  const agent2Keys = await generateKeyProvider();
  const agent2 = createIdentity({
    kind: "agent",
    name: "support-agent-2",
    createdBy: root.id,
    publicJWK: await agent2Keys.getPublicJWK(),
  });

  const agent2Credential = await issueCredential({
    issuer: root,
    subject: agent2,
    keyProvider: rootKeys,
    capabilities: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } }],
    aud: "order:*",
    ttlSeconds: 900,
  });
  const agent2Chain = rootChain(agent2Credential);

  const toolChain = await delegate({
    from: agent2Chain,
    to: tool,
    keyProvider: agent2Keys,
    grant: [{ action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } }],
    ttlSeconds: 120,
  });

  console.log(
    "tool chain before ancestor revoke:",
    await authorize(
      { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
      { revocationStore: store }
    )
  );

  await revoke({ credential: agent2Chain, store }); // revoke the ancestor (support-agent-2), not the tool directly

  console.log(
    "tool chain after ancestor revoke (cascade, denied):",
    await authorize(
      { credential: toolChain, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
      { revocationStore: store }
    )
  );
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});

/**
 * Basic example (§16): one root Principal, one Agent, one non-delegated
 * credential, one allow and one deny `authorize()` call. Run:
 *
 *   npm run example:basic
 */
import {
  generateKeyProvider,
  createIdentity,
  issueCredential,
  rootChain,
  authorize,
  memoryRevocationStore,
} from "../../src/index.js";

async function main(): Promise<void> {
  // 1. Root Principal (e.g. your application) and one Agent it creates.
  const rootKeys = await generateKeyProvider();
  const root = createIdentity({ kind: "application", name: "acme-app", publicJWK: await rootKeys.getPublicJWK() });

  const agentKeys = await generateKeyProvider();
  const agent = createIdentity({
    kind: "agent",
    name: "reporting-agent",
    createdBy: root.id,
    publicJWK: await agentKeys.getPublicJWK(),
  });

  // 2. Root issues the agent a scoped, time-boxed credential.
  const credential = await issueCredential({
    issuer: root,
    subject: agent,
    keyProvider: rootKeys,
    capabilities: [{ action: "reports:read", resource: "report:*" }],
    aud: "report:*",
    ttlSeconds: 300,
  });

  const store = memoryRevocationStore();

  // 3. Allow path — the credential's capability covers this request.
  const allowed = await authorize(
    { credential: rootChain(credential), action: "reports:read", resource: "report:q3" },
    { revocationStore: store }
  );
  console.log("allow path:", allowed);

  // 4. Deny path — no capability covers "reports:delete".
  const denied = await authorize(
    { credential: rootChain(credential), action: "reports:delete", resource: "report:q3" },
    { revocationStore: store }
  );
  console.log("deny path:", denied);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});

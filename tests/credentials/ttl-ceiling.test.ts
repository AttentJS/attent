import { describe, it, expect } from "vitest";
import { generateKeyProvider, memoryTrustedKeyStore } from "../../src/crypto/keys.js";
import { createIdentity } from "../../src/identity/identity.js";
import { issueCredential } from "../../src/credentials/credentials.js";
import { MAX_TTL_SECONDS } from "../../src/credentials/types.js";
import { TtlTooLongError } from "../../src/credentials/errors.js";
import { delegate } from "../../src/delegation/delegate.js";
import { rootChain } from "../../src/delegation/types.js";

async function setup(): Promise<{
  issuerKeys: Awaited<ReturnType<typeof generateKeyProvider>>;
  issuer: ReturnType<typeof createIdentity>;
  subject: ReturnType<typeof createIdentity>;
  agent2: ReturnType<typeof createIdentity>;
}> {
  const issuerKeys = await generateKeyProvider();
  const issuer = createIdentity({ kind: "application", name: "acme-app", publicJWK: await issuerKeys.getPublicJWK() });
  const subject = createIdentity({
    kind: "agent",
    name: "support-agent",
    createdBy: issuer.id,
    publicJWK: await (await generateKeyProvider()).getPublicJWK(),
  });
  const agent2 = createIdentity({
    kind: "agent",
    name: "sub-agent",
    createdBy: issuer.id,
    publicJWK: await (await generateKeyProvider()).getPublicJWK(),
  });
  return { issuerKeys, issuer, subject, agent2 };
}

describe("MAX_TTL_SECONDS ceiling", () => {
  it("issueCredential rejects a ttlSeconds beyond MAX_TTL_SECONDS", async () => {
    const { issuerKeys, issuer, subject } = await setup();
    await expect(
      issueCredential({
        issuer,
        subject,
        keyProvider: issuerKeys,
        capabilities: [{ action: "orders:read", resource: "order:*" }],
        aud: "order:*",
        ttlSeconds: MAX_TTL_SECONDS + 1,
      })
    ).rejects.toThrow(TtlTooLongError);
  });

  it("issueCredential accepts a ttlSeconds exactly at MAX_TTL_SECONDS", async () => {
    const { issuerKeys, issuer, subject } = await setup();
    await expect(
      issueCredential({
        issuer,
        subject,
        keyProvider: issuerKeys,
        capabilities: [{ action: "orders:read", resource: "order:*" }],
        aud: "order:*",
        ttlSeconds: MAX_TTL_SECONDS,
      })
    ).resolves.toBeDefined();
  });

  it("delegate rejects a ttlSeconds beyond MAX_TTL_SECONDS even when the parent could technically cover it", async () => {
    const { issuerKeys, issuer, subject, agent2 } = await setup();
    const subjectKeys = await generateKeyProvider();
    const trustedKeys = memoryTrustedKeyStore();
    await trustedKeys.addKey(subject.id, subjectKeys.kid, await subjectKeys.getPublicJWK());

    const rootCredential = await issueCredential({
      issuer,
      subject,
      keyProvider: issuerKeys,
      capabilities: [{ action: "orders:read", resource: "order:*" }],
      aud: "order:*",
      ttlSeconds: MAX_TTL_SECONDS,
    });

    await expect(
      delegate({
        from: rootChain(rootCredential),
        to: agent2,
        keyProvider: subjectKeys,
        grant: [{ action: "orders:read", resource: "order:*" }],
        ttlSeconds: MAX_TTL_SECONDS + 1,
      })
    ).rejects.toThrow(TtlTooLongError);
  });
});

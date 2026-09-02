import { describe, it, expect } from "vitest";
import { generateKeyProvider, memoryTrustedKeyStore } from "../../src/crypto/keys.js";
import { createIdentity } from "../../src/identity/identity.js";
import { issueCredential, verifyCredential } from "../../src/credentials/credentials.js";
import type { Clock } from "../../src/credentials/clock.js";
import {
  CredentialExpiredError,
  CredentialVerificationError,
  InvalidCredentialInputError,
  MalformedCredentialError,
} from "../../src/credentials/errors.js";

function fixedClock(date: Date): Clock {
  return { now: () => date };
}

async function setup(): Promise<{
  issuerKeys: Awaited<ReturnType<typeof generateKeyProvider>>;
  issuer: ReturnType<typeof createIdentity>;
  subjectKeys: Awaited<ReturnType<typeof generateKeyProvider>>;
  subject: ReturnType<typeof createIdentity>;
  trustedKeys: ReturnType<typeof memoryTrustedKeyStore>;
}> {
  const issuerKeys = await generateKeyProvider();
  const issuer = createIdentity({ kind: "application", name: "acme-app", publicJWK: await issuerKeys.getPublicJWK() });
  const subjectKeys = await generateKeyProvider();
  const subject = createIdentity({
    kind: "agent",
    name: "support-agent",
    createdBy: issuer.id,
    publicJWK: await subjectKeys.getPublicJWK(),
  });
  const trustedKeys = memoryTrustedKeyStore();
  await trustedKeys.addKey(issuer.id, issuerKeys.kid, await issuerKeys.getPublicJWK());
  return { issuerKeys, issuer, subjectKeys, subject, trustedKeys };
}

describe("issueCredential / verifyCredential round trip", () => {
  it("issues and verifies a valid single-hop credential", async () => {
    const { issuerKeys, issuer, subject, trustedKeys } = await setup();
    const credential = await issueCredential({
      issuer,
      subject,
      keyProvider: issuerKeys,
      capabilities: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } }],
      aud: "order:*",
      ttlSeconds: 900,
    });

    const verified = await verifyCredential({ jws: credential.jws, trustedKeys });
    expect(verified.claims.iss).toBe(issuer.id);
    expect(verified.claims.sub).toBe(subject.id);
    expect(verified.claims.capabilities).toHaveLength(1);
    expect(verified.claims.capabilities[0]!.action).toBe("refunds:create");
  });

  it("rejects a non-positive or non-integer ttlSeconds", async () => {
    const { issuerKeys, issuer, subject } = await setup();
    await expect(
      issueCredential({ issuer, subject, keyProvider: issuerKeys, capabilities: [], aud: "order:*", ttlSeconds: 0 })
    ).rejects.toThrow(InvalidCredentialInputError);
    await expect(
      issueCredential({ issuer, subject, keyProvider: issuerKeys, capabilities: [], aud: "order:*", ttlSeconds: 1.5 })
    ).rejects.toThrow(InvalidCredentialInputError);
  });

  it("rejects a capability with an empty action/resource", async () => {
    const { issuerKeys, issuer, subject } = await setup();
    await expect(
      issueCredential({
        issuer,
        subject,
        keyProvider: issuerKeys,
        capabilities: [{ action: "", resource: "order:*" }],
        aud: "order:*",
        ttlSeconds: 60,
      })
    ).rejects.toThrow(InvalidCredentialInputError);
  });

  it("rejects prototype-pollution-shaped constraint keys at issuance", async () => {
    const { issuerKeys, issuer, subject } = await setup();
    const parsed = JSON.parse('{"__proto__": {"polluted": true}}') as Record<string, unknown>;
    await expect(
      issueCredential({
        issuer,
        subject,
        keyProvider: issuerKeys,
        capabilities: [{ action: "orders:read", resource: "order:*", constraints: parsed }],
        aud: "order:*",
        ttlSeconds: 60,
      })
    ).rejects.toThrow(MalformedCredentialError);
  });
});

describe("verifyCredential expiry", () => {
  it("accepts a credential before expiry and rejects the same credential after expiry", async () => {
    const { issuerKeys, issuer, subject, trustedKeys } = await setup();
    const issuedAt = new Date("2026-01-01T00:00:00Z");
    const credential = await issueCredential({
      issuer,
      subject,
      keyProvider: issuerKeys,
      capabilities: [{ action: "orders:read", resource: "order:*" }],
      aud: "order:*",
      ttlSeconds: 60,
      clock: fixedClock(issuedAt),
    });

    await expect(
      verifyCredential({ jws: credential.jws, trustedKeys, clock: fixedClock(new Date("2026-01-01T00:00:30Z")) })
    ).resolves.toBeDefined();

    await expect(
      verifyCredential({ jws: credential.jws, trustedKeys, clock: fixedClock(new Date("2026-01-01T00:01:01Z")) })
    ).rejects.toThrow(CredentialExpiredError);
  });
});

describe("verifyCredential adversarial cases", () => {
  it("rejects a malformed/forged token", async () => {
    const { trustedKeys } = await setup();
    await expect(verifyCredential({ jws: "not-a-jwt", trustedKeys })).rejects.toThrow(MalformedCredentialError);
  });

  it("rejects a credential signed by a key not in the trusted store", async () => {
    const { issuer, subject, trustedKeys } = await setup();
    const strangerKeys = await generateKeyProvider();
    const forged = await issueCredential({
      issuer,
      subject,
      keyProvider: strangerKeys,
      capabilities: [{ action: "orders:read", resource: "order:*" }],
      aud: "order:*",
      ttlSeconds: 60,
    });
    await expect(verifyCredential({ jws: forged.jws, trustedKeys })).rejects.toThrow(CredentialVerificationError);
  });

  it("rejects a tampered payload (signature mismatch)", async () => {
    const { issuerKeys, issuer, subject, trustedKeys } = await setup();
    const credential = await issueCredential({
      issuer,
      subject,
      keyProvider: issuerKeys,
      capabilities: [{ action: "orders:read", resource: "order:*" }],
      aud: "order:*",
      ttlSeconds: 60,
    });
    const [header, , signature] = credential.jws.split(".");
    const tamperedPayload = Buffer.from(
      JSON.stringify({ iss: issuer.id, sub: subject.id, aud: "order:*", capabilities: [], iat: 0, exp: 9999999999 })
    ).toString("base64url");
    const tampered = `${header}.${tamperedPayload}.${signature}`;
    await expect(verifyCredential({ jws: tampered, trustedKeys })).rejects.toThrow(CredentialVerificationError);
  });

  it("rejects a token using a disallowed algorithm even if otherwise well-formed", async () => {
    const { issuer, subject, trustedKeys } = await setup();
    const { SignJWT, generateSecret } = await import("jose");
    const secret = await generateSecret("HS256");
    const foreignJws = await new SignJWT({
      iss: issuer.id,
      sub: subject.id,
      aud: "order:*",
      capabilities: [],
      iat: 0,
      exp: 9999999999,
    })
      .setProtectedHeader({ alg: "HS256", kid: "whatever" })
      .sign(secret);
    await expect(verifyCredential({ jws: foreignJws, trustedKeys })).rejects.toThrow(CredentialVerificationError);
  });

  it("rejects a well-formed-but-unknown kid for a known issuer", async () => {
    const { issuerKeys, issuer, subject, trustedKeys } = await setup();
    const otherKeys = await generateKeyProvider();
    // Sign with a key whose kid was never registered in trustedKeys for this issuer.
    const credential = await issueCredential({
      issuer,
      subject,
      keyProvider: otherKeys,
      capabilities: [{ action: "orders:read", resource: "order:*" }],
      aud: "order:*",
      ttlSeconds: 60,
    });
    expect(otherKeys.kid).not.toBe(issuerKeys.kid);
    await expect(verifyCredential({ jws: credential.jws, trustedKeys })).rejects.toThrow(CredentialVerificationError);
  });
});

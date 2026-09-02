import { describe, it, expect } from "vitest";
import { generateKeyProvider } from "../../src/crypto/keys.js";
import { createIdentity } from "../../src/identity/identity.js";
import { issueCredential } from "../../src/credentials/credentials.js";
import type { Clock } from "../../src/credentials/clock.js";
import type { CredentialChain } from "../../src/delegation/types.js";
import { rootChain } from "../../src/delegation/types.js";
import { authorize } from "../../src/authorization/authorize.js";
import { InvalidActionError, InvalidResourceError } from "../../src/authorization/errors.js";
import { memoryRevocationStore, revoke } from "../../src/revocation/index.js";
import type { RevocationStore } from "../../src/revocation/types.js";

function fixedClock(date: Date): Clock {
  return { now: () => date };
}

async function issueSupportAgentCredential(overrides?: {
  clock?: Clock;
  ttlSeconds?: number;
}): Promise<CredentialChain> {
  const issuerKeys = await generateKeyProvider();
  const issuer = createIdentity({ kind: "application", name: "acme-app", publicJWK: await issuerKeys.getPublicJWK() });
  const subjectKeys = await generateKeyProvider();
  const subject = createIdentity({
    kind: "agent",
    name: "support-agent",
    createdBy: issuer.id,
    publicJWK: await subjectKeys.getPublicJWK(),
  });
  const credential = await issueCredential({
    issuer,
    subject,
    keyProvider: issuerKeys,
    capabilities: [
      { action: "orders:read", resource: "order:*" },
      { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } },
    ],
    aud: "order:*",
    ttlSeconds: overrides?.ttlSeconds ?? 900,
    clock: overrides?.clock,
  });
  return rootChain(credential);
}

describe("authorize() — allow/deny core paths", () => {
  it("allows a request matching action, resource, aud, and constraints", async () => {
    const credential = await issueSupportAgentCredential();
    const decision = await authorize(
      { credential, action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
      { revocationStore: memoryRevocationStore() }
    );
    expect(decision.outcome).toBe("allow");
    if (decision.outcome === "allow") {
      expect(decision.matchedCapability.action).toBe("refunds:create");
    }
  });

  it("denies with no_matching_capability when no capability's action/resource pattern matches", async () => {
    const credential = await issueSupportAgentCredential();
    const decision = await authorize(
      { credential, action: "refunds:delete", resource: "order:18472" },
      { revocationStore: memoryRevocationStore() }
    );
    expect(decision).toEqual({ outcome: "deny", reason: "no_matching_capability" });
  });

  it("denies with policy_rejected:<name> when the pattern matches but the constraint fails", async () => {
    const credential = await issueSupportAgentCredential();
    const decision = await authorize(
      { credential, action: "refunds:create", resource: "order:18472", context: { amount: 999 } },
      { revocationStore: memoryRevocationStore() }
    );
    expect(decision).toEqual({ outcome: "deny", reason: "policy_rejected:default" });
  });

  it("denies with audience_mismatch when resource falls outside the credential's aud", async () => {
    const issuerKeys = await generateKeyProvider();
    const issuer = createIdentity({ kind: "application", name: "acme-app", publicJWK: await issuerKeys.getPublicJWK() });
    const subjectKeys = await generateKeyProvider();
    const subject = createIdentity({
      kind: "agent",
      createdBy: issuer.id,
      publicJWK: await subjectKeys.getPublicJWK(),
    });
    const credential = rootChain(
      await issueCredential({
        issuer,
        subject,
        keyProvider: issuerKeys,
        capabilities: [{ action: "refunds:create", resource: "order:*" }],
        aud: "billing:*",
        ttlSeconds: 60,
      })
    );
    const decision = await authorize(
      { credential, action: "refunds:create", resource: "order:18472" },
      { revocationStore: memoryRevocationStore() }
    );
    expect(decision).toEqual({ outcome: "deny", reason: "audience_mismatch" });
  });
});

describe("authorize() — expiry", () => {
  it("denies with credential_expired once past exp", async () => {
    const issuedAt = new Date("2026-01-01T00:00:00Z");
    const credential = await issueSupportAgentCredential({ clock: fixedClock(issuedAt), ttlSeconds: 60 });

    const stillValid = await authorize(
      { credential, action: "orders:read", resource: "order:1" },
      { revocationStore: memoryRevocationStore(), clock: fixedClock(new Date("2026-01-01T00:00:30Z")) }
    );
    expect(stillValid.outcome).toBe("allow");

    const expired = await authorize(
      { credential, action: "orders:read", resource: "order:1" },
      { revocationStore: memoryRevocationStore(), clock: fixedClock(new Date("2026-01-01T00:01:01Z")) }
    );
    expect(expired).toEqual({ outcome: "deny", reason: "credential_expired" });
  });
});

describe("authorize() — revocation", () => {
  it("allows before revoke, denies immediately after (same-process, synchronous)", async () => {
    const credential = await issueSupportAgentCredential();
    const store = memoryRevocationStore();

    const before = await authorize({ credential, action: "orders:read", resource: "order:1" }, { revocationStore: store });
    expect(before.outcome).toBe("allow");

    await revoke({ credential, store });

    const after = await authorize({ credential, action: "orders:read", resource: "order:1" }, { revocationStore: store });
    expect(after).toEqual({ outcome: "deny", reason: "credential_revoked" });
  });

  it("fails closed (denies) when the revocation store is unreachable", async () => {
    const credential = await issueSupportAgentCredential();
    const brokenStore: RevocationStore = {
      revoke: () => Promise.reject(new Error("store unreachable")),
      isRevoked: () => Promise.reject(new Error("store unreachable")),
    };
    const decision = await authorize(
      { credential, action: "orders:read", resource: "order:1" },
      { revocationStore: brokenStore }
    );
    expect(decision).toEqual({ outcome: "deny", reason: "credential_revoked" });
  });
});

describe("authorize() — malformed request input throws, never a silent deny", () => {
  it("throws InvalidResourceError for a wildcard/glob literal in the request resource", async () => {
    const credential = await issueSupportAgentCredential();
    await expect(
      authorize({ credential, action: "orders:read", resource: "order:*" }, { revocationStore: memoryRevocationStore() })
    ).rejects.toThrow(InvalidResourceError);
  });

  it("throws InvalidActionError for an empty action", async () => {
    const credential = await issueSupportAgentCredential();
    await expect(
      authorize({ credential, action: "", resource: "order:1" }, { revocationStore: memoryRevocationStore() })
    ).rejects.toThrow(InvalidActionError);
  });
});

describe("authorize() — determinism", () => {
  it("identical inputs always yield an identical outcome", async () => {
    const credential = await issueSupportAgentCredential();
    const store = memoryRevocationStore();
    const input = { credential, action: "refunds:create", resource: "order:1", context: { amount: 20 } } as const;
    const options = { revocationStore: store };
    const first = await authorize(input, options);
    const second = await authorize(input, options);
    expect(first).toEqual(second);
  });
});

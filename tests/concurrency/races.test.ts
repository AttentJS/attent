import { describe, it, expect } from "vitest";
import { generateKeyProvider } from "../../src/crypto/keys.js";
import { createIdentity } from "../../src/identity/identity.js";
import { issueCredential } from "../../src/credentials/credentials.js";
import { rootChain } from "../../src/delegation/types.js";
import { authorize } from "../../src/authorization/authorize.js";
import { memoryRevocationStore } from "../../src/revocation/memory.js";
import { revoke } from "../../src/revocation/revoke.js";
import { memoryAuditSink } from "../../src/audit/sink.js";
import { memoryIdentityStore } from "../../src/identity/store.js";
import { DuplicateIdentityError } from "../../src/identity/errors.js";
import type { AuditEvent } from "../../src/audit/types.js";

async function setup(): Promise<{
  issuerKeys: Awaited<ReturnType<typeof generateKeyProvider>>;
  issuer: ReturnType<typeof createIdentity>;
  subject: ReturnType<typeof createIdentity>;
}> {
  const issuerKeys = await generateKeyProvider();
  const issuer = createIdentity({ kind: "application", name: "acme-app", publicJWK: await issuerKeys.getPublicJWK() });
  const subject = createIdentity({
    kind: "agent",
    name: "support-agent",
    createdBy: issuer.id,
    publicJWK: await (await generateKeyProvider()).getPublicJWK(),
  });
  return { issuerKeys, issuer, subject };
}

describe("concurrency", () => {
  it("a concurrent revoke() racing with authorize() never lets an in-flight call observe a torn/half-revoked state", async () => {
    const { issuerKeys, issuer, subject } = await setup();
    const credential = await issueCredential({
      issuer,
      subject,
      keyProvider: issuerKeys,
      capabilities: [{ action: "orders:read", resource: "order:*" }],
      aud: "order:*",
      ttlSeconds: 900,
    });
    const chain = rootChain(credential);
    const revocationStore = memoryRevocationStore();

    // Fire 50 concurrent authorize() calls interleaved with one revoke() —
    // every settled Promise must resolve to a well-formed Decision (allow
    // or deny), never throw, never hang, and once revoke() has settled every
    // subsequent authorize() must observe the revocation.
    const authorizeCalls = Array.from({ length: 50 }, (_, i) =>
      i === 25
        ? revoke({ credential: chain, store: revocationStore }).then(() => undefined)
        : authorize(
            { credential: chain, action: "orders:read", resource: "order:18472" },
            { revocationStore }
          )
    );

    const results = await Promise.all(authorizeCalls);
    for (const result of results) {
      if (result !== undefined) {
        expect(["allow", "deny"]).toContain(result.outcome);
      }
    }

    const after = await authorize(
      { credential: chain, action: "orders:read", resource: "order:18472" },
      { revocationStore }
    );
    expect(after.outcome).toBe("deny");
    if (after.outcome === "deny") {
      expect(after.reason).toBe("credential_revoked");
    }
  });

  it("concurrent issueCredential calls for the same issuer/subject never produce colliding jti values", async () => {
    const { issuerKeys, issuer, subject } = await setup();
    const results = await Promise.all(
      Array.from({ length: 100 }, () =>
        issueCredential({
          issuer,
          subject,
          keyProvider: issuerKeys,
          capabilities: [{ action: "orders:read", resource: "order:*" }],
          aud: "order:*",
          ttlSeconds: 900,
        })
      )
    );
    const jtis = new Set(results.map((c) => c.claims.jti));
    expect(jtis.size).toBe(results.length);
  });

  it("concurrent appends to an in-memory AuditSink never lose an event", async () => {
    const sink = memoryAuditSink();
    function event(i: number): AuditEvent {
      return {
        id: `evt-${i}`,
        timestamp: new Date(0).toISOString(),
        type: "authorization",
        principal: { id: "p1" },
        delegationChain: [],
      };
    }
    await Promise.all(Array.from({ length: 200 }, (_, i) => sink.append(event(i))));
    const all = await sink.query();
    expect(all).toHaveLength(200);
  });

  it("concurrent put() calls for the same identity id: exactly one succeeds, the rest reject with DuplicateIdentityError", async () => {
    const store = memoryIdentityStore();
    const issuerKeys = await generateKeyProvider();
    const identity = createIdentity({ kind: "application", name: "acme-app", publicJWK: await issuerKeys.getPublicJWK() });

    const results = await Promise.allSettled(Array.from({ length: 20 }, () => store.put(identity)));
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r): r is PromiseRejectedResult => r.status === "rejected");

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(19);
    for (const r of rejected) {
      expect(r.reason).toBeInstanceOf(DuplicateIdentityError);
    }
  });
});

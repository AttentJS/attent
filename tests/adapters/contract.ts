import { describe, it, expect } from "vitest";
import type { IdentityStore } from "../../src/identity/store.js";
import type { Identity } from "../../src/identity/types.js";
import type { RevocationStore } from "../../src/revocation/types.js";
import type { AuditSink } from "../../src/audit/sink.js";
import type { AuditEvent } from "../../src/audit/types.js";

/**
 * Shared adapter-conformance suites (§21 Phase 6, §11's "adapter contract
 * test suite requires two 'tenants' worth of fixture data and asserts zero
 * cross-read", T10). Written once, callable against any implementation —
 * today only the in-memory stores exist, but a future
 * `@attent/storage-sqlite`/`-postgres` adapter runs the exact same suite
 * (§11: "right fit... contract suite is written now so it's ready the
 * moment the real adapter exists").
 */

function fixtureIdentity(id: string, tenantId?: string): Identity {
  return {
    id,
    tenantId,
    kind: "application",
    publicJWK: { kty: "OKP", crv: "Ed25519", x: "fixture-x-value" },
    createdAt: new Date(0).toISOString(),
  };
}

export function describeIdentityStoreContract(name: string, makeStore: () => IdentityStore): void {
  describe(`IdentityStore contract — ${name}`, () => {
    it("put then get round-trips the identity", async () => {
      const store = makeStore();
      const identity = fixtureIdentity("user-1");
      await store.put(identity);
      expect(await store.get("user-1")).toEqual(identity);
    });

    it("get returns null for an unknown id", async () => {
      const store = makeStore();
      expect(await store.get("nope")).toBeNull();
    });

    it("put rejects a duplicate id rather than silently overwriting", async () => {
      const store = makeStore();
      const identity = fixtureIdentity("dup-1");
      await store.put(identity);
      // Matched by name/message, not `instanceof` — this suite runs against
      // adapters built and imported from an entirely different package
      // (e.g. `@attent/storage-sqlite`, which imports its own `attent`
      // module instance), so a shared class identity can't be assumed.
      await expect(store.put(identity)).rejects.toMatchObject({ name: "DuplicateIdentityError" });
    });

    it("tenant isolation (T10): identities carrying different tenantId values round-trip independently and never cross-read", async () => {
      const store = makeStore();
      const a = fixtureIdentity("user-1", "tenant-a");
      const b = fixtureIdentity("user-2", "tenant-b");
      await store.put(a);
      await store.put(b);
      expect(await store.get("user-1")).toEqual(a);
      expect(await store.get("user-2")).toEqual(b);
      expect((await store.get("user-1"))?.tenantId).toBe("tenant-a");
      expect((await store.get("user-2"))?.tenantId).toBe("tenant-b");
    });
  });
}

export function describeRevocationStoreContract(name: string, makeStore: () => RevocationStore): void {
  describe(`RevocationStore contract — ${name}`, () => {
    it("isRevoked is false for an unknown hop id", async () => {
      const store = makeStore();
      expect(await store.isRevoked("nope")).toBe(false);
    });

    it("revoke then isRevoked reflects the revocation", async () => {
      const store = makeStore();
      await store.revoke("hop-1");
      expect(await store.isRevoked("hop-1")).toBe(true);
    });

    it("revoking one hop id never marks a different hop id revoked", async () => {
      const store = makeStore();
      await store.revoke("hop-1");
      expect(await store.isRevoked("hop-2")).toBe(false);
    });

    it("tenant isolation (T10): hop ids are globally unique (jti), so revocations recorded with different tenantId bookkeeping never cross-revoke each other's hops", async () => {
      const store = makeStore();
      await store.revoke("hop-a", { tenantId: "tenant-a" });
      expect(await store.isRevoked("hop-a")).toBe(true);
      expect(await store.isRevoked("hop-b")).toBe(false);
    });
  });
}

export function describeAuditSinkContract(name: string, makeSink: () => AuditSink): void {
  function event(overrides: Partial<AuditEvent> = {}): AuditEvent {
    return {
      id: crypto.randomUUID(),
      timestamp: new Date(0).toISOString(),
      type: "authorization",
      principal: { id: "p1" },
      delegationChain: [],
      ...overrides,
    };
  }

  describe(`AuditSink contract — ${name}`, () => {
    it("append then query with no filter returns everything appended", async () => {
      const sink = makeSink();
      await sink.append(event());
      await sink.append(event());
      expect(await sink.query()).toHaveLength(2);
    });

    it("query filters by type", async () => {
      const sink = makeSink();
      await sink.append(event({ type: "authorization" }));
      await sink.append(event({ type: "revocation" }));
      const result = await sink.query({ type: "revocation" });
      expect(result).toHaveLength(1);
      expect(result[0]!.type).toBe("revocation");
    });

    it("tenant isolation (T10): querying by principalId never returns another principal's events", async () => {
      const sink = makeSink();
      await sink.append(event({ principal: { id: "tenant-a:user-1" } }));
      await sink.append(event({ principal: { id: "tenant-b:user-1" } }));
      const result = await sink.query({ principalId: "tenant-a:user-1" });
      expect(result).toHaveLength(1);
      expect(result[0]!.principal.id).toBe("tenant-a:user-1");
    });

    it("tenant isolation (T10): querying by the first-class tenantId field never returns another tenant's events", async () => {
      const sink = makeSink();
      await sink.append(event({ tenantId: "tenant-a", principal: { id: "user-1" } }));
      await sink.append(event({ tenantId: "tenant-b", principal: { id: "user-1" } }));
      const result = await sink.query({ tenantId: "tenant-a" });
      expect(result).toHaveLength(1);
      expect(result[0]!.tenantId).toBe("tenant-a");
    });
  });
}

import { describe, it, expect } from "vitest";
import type { IdentityStore } from "../../src/identity/store.js";
import { DuplicateIdentityError } from "../../src/identity/errors.js";
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

function fixtureIdentity(id: string): Identity {
  return {
    id,
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
      await expect(store.put(identity)).rejects.toThrow(DuplicateIdentityError);
    });

    it("tenant isolation (T10): namespaced ids from two 'tenants' never cross-read", async () => {
      const store = makeStore();
      const a = fixtureIdentity("tenant-a:user-1");
      const b = fixtureIdentity("tenant-b:user-1");
      await store.put(a);
      await store.put(b);
      expect(await store.get("tenant-a:user-1")).toEqual(a);
      expect(await store.get("tenant-b:user-1")).toEqual(b);
      expect(await store.get("tenant-a:user-1")).not.toEqual(b);
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

    it("tenant isolation (T10): namespaced hop ids from two 'tenants' never cross-revoke", async () => {
      const store = makeStore();
      await store.revoke("tenant-a:hop-1");
      expect(await store.isRevoked("tenant-a:hop-1")).toBe(true);
      expect(await store.isRevoked("tenant-b:hop-1")).toBe(false);
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
  });
}

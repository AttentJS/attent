import { describe, expect, it } from "vitest";
import { openAttentDatabase, sqliteAuditSink, sqliteIdentityStore, sqliteRevocationStore } from "../src/index.js";
import type { AuditEvent } from "attent";

describe("SQLite adapters — concurrency", () => {
  it("concurrent appends to a SqliteAuditSink never lose an event", async () => {
    const sink = sqliteAuditSink(openAttentDatabase(":memory:"));
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

  it("concurrent put() calls for the same identity id: exactly one succeeds", async () => {
    const store = sqliteIdentityStore(openAttentDatabase(":memory:"));
    const identity = {
      id: "user-1",
      kind: "application" as const,
      publicJWK: { kty: "OKP", crv: "Ed25519", x: "fixture-x-value" },
      createdAt: new Date(0).toISOString(),
    };

    const results = await Promise.allSettled(Array.from({ length: 20 }, () => store.put(identity)));
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    expect(fulfilled).toHaveLength(1);
  });

  it("concurrent revoke() calls for the same hop id settle without error and isRevoked reflects it", async () => {
    const store = sqliteRevocationStore(openAttentDatabase(":memory:"));
    await Promise.all(Array.from({ length: 20 }, () => store.revoke("hop-1")));
    expect(await store.isRevoked("hop-1")).toBe(true);
  });
});

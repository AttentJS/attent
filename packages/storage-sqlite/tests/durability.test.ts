import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  openAttentDatabase,
  sqliteAuditSink,
  sqliteIdentityStore,
  sqliteRevocationStore,
} from "../src/index.js";
import type { Identity } from "attent";

/**
 * Proves the SQLite adapters actually persist to disk across a process
 * boundary (closing and reopening the database file), not just within one
 * open `Database` handle — the property the in-memory stores structurally
 * cannot have.
 */
describe("SQLite adapters — durability across restart", () => {
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "attent-sqlite-"));
    dbPath = join(dir, "attent.db");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("an identity written before close is readable after reopening the same file", async () => {
    const identity: Identity = {
      id: "durable-user-1",
      kind: "application",
      publicJWK: { kty: "OKP", crv: "Ed25519", x: "fixture-x-value" },
      createdAt: new Date(0).toISOString(),
    };

    const db1 = openAttentDatabase(dbPath);
    await sqliteIdentityStore(db1).put(identity);
    db1.close();

    const db2 = openAttentDatabase(dbPath);
    const reopened = await sqliteIdentityStore(db2).get("durable-user-1");
    db2.close();

    expect(reopened).toEqual(identity);
  });

  it("a revocation recorded before close is still honored after reopening the same file", async () => {
    const db1 = openAttentDatabase(dbPath);
    await sqliteRevocationStore(db1).revoke("durable-hop-1");
    db1.close();

    const db2 = openAttentDatabase(dbPath);
    const revoked = await sqliteRevocationStore(db2).isRevoked("durable-hop-1");
    db2.close();

    expect(revoked).toBe(true);
  });

  it("an audit event appended before close is queryable after reopening the same file", async () => {
    const db1 = openAttentDatabase(dbPath);
    await sqliteAuditSink(db1).append({
      id: "evt-1",
      timestamp: new Date(0).toISOString(),
      type: "authorization",
      principal: { id: "user-1" },
      delegationChain: [],
    });
    db1.close();

    const db2 = openAttentDatabase(dbPath);
    const events = await sqliteAuditSink(db2).query();
    db2.close();

    expect(events).toHaveLength(1);
    expect(events[0]?.id).toBe("evt-1");
  });
});

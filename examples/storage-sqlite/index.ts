/**
 * Durable storage demo — the same `IdentityStore`/`RevocationStore`/
 * `AuditSink` interfaces the in-memory adapters satisfy, backed by SQLite
 * instead: an identity, a revocation, and an audit event all survive
 * closing and reopening the database file, which the in-memory adapters
 * structurally cannot do.
 *
 * Run:
 *
 *   npm run example:storage-sqlite
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openAttentDatabase, sqliteAuditSink, sqliteIdentityStore, sqliteRevocationStore } from "@attent/storage-sqlite";
import { createIdentity, generateKeyProvider } from "attent";

async function main(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "attent-storage-sqlite-demo-"));
  const dbPath = join(dir, "attent.db");

  try {
    const keys = await generateKeyProvider();
    const identity = createIdentity({
      kind: "application",
      name: "acme-app",
      tenantId: "tenant-acme",
      publicJWK: await keys.getPublicJWK(),
    });

    // --- Process "1": writes, then shuts down. ---
    const db1 = openAttentDatabase(dbPath);
    await sqliteIdentityStore(db1).put(identity);
    await sqliteRevocationStore(db1).revoke("hop-1");
    await sqliteAuditSink(db1).append({
      id: "evt-1",
      timestamp: new Date().toISOString(),
      tenantId: "tenant-acme",
      type: "credential_issued",
      principal: { id: identity.id },
      delegationChain: [],
    });
    db1.close();
    console.log("Process 1 wrote identity, revocation, and audit event, then closed the database.");

    // --- Process "2": reopens the same file, sees everything. ---
    const db2 = openAttentDatabase(dbPath);
    const reopenedIdentity = await sqliteIdentityStore(db2).get(identity.id);
    const stillRevoked = await sqliteRevocationStore(db2).isRevoked("hop-1");
    const events = await sqliteAuditSink(db2).query({ tenantId: "tenant-acme" });
    db2.close();

    console.log("Process 2 reopened the database file:");
    console.log("  identity survived restart:", reopenedIdentity?.id === identity.id);
    console.log("  revocation survived restart:", stillRevoked);
    console.log("  audit events for tenant-acme survived restart:", events.length);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});

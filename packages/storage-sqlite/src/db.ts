import Database from "better-sqlite3";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS identities (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  kind TEXT NOT NULL,
  name TEXT,
  public_jwk TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT,
  metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_identities_tenant ON identities (tenant_id);

CREATE TABLE IF NOT EXISTS revocations (
  hop_id TEXT PRIMARY KEY,
  tenant_id TEXT,
  cascade INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revocations_tenant ON revocations (tenant_id);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  timestamp TEXT NOT NULL,
  type TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  request_id TEXT,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events (type);
CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_events (principal_id);
CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_events (request_id);
`;

/**
 * Opens (creating if necessary) a SQLite database file for Attent's durable
 * stores, applies the schema, and enables WAL mode for crash-safe durability
 * under concurrent readers/writers (skipped for `:memory:`, which has no
 * file to WAL-journal and is used only by tests). One database is shared by
 * all three store adapters (`sqliteIdentityStore`/`sqliteRevocationStore`/
 * `sqliteAuditSink`) — pass the same instance to each so they see a
 * consistent view and a single file to back up/restore.
 */
export function openAttentDatabase(filename: string): Database.Database {
  const db = new Database(filename);
  if (filename !== ":memory:") {
    db.pragma("journal_mode = WAL");
  }
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA);
  return db;
}

export type AttentDatabase = Database.Database;

import type { RevocationStore, RevokeOptions } from "attent";
import type { AttentDatabase } from "./db.js";

/**
 * Durable `RevocationStore` backed by SQLite (§11/§13). Revocation is
 * consulted on every `authorize()` call, so this must answer `isRevoked`
 * correctly even across process restarts — the in-memory `Set` cannot.
 */
export class SqliteRevocationStore implements RevocationStore {
  readonly #db: AttentDatabase;

  constructor(db: AttentDatabase) {
    this.#db = db;
  }

  revoke(hopId: string, opts?: RevokeOptions): Promise<void> {
    this.#db
      .prepare(
        `INSERT INTO revocations (hop_id, tenant_id, cascade, revoked_at)
         VALUES (@hopId, @tenantId, @cascade, @revokedAt)
         ON CONFLICT(hop_id) DO NOTHING`
      )
      .run({
        hopId,
        tenantId: opts?.tenantId ?? null,
        cascade: opts?.cascade ? 1 : 0,
        revokedAt: new Date().toISOString(),
      });
    return Promise.resolve();
  }

  isRevoked(hopId: string): Promise<boolean> {
    const row = this.#db.prepare("SELECT 1 FROM revocations WHERE hop_id = ?").get(hopId);
    return Promise.resolve(row !== undefined);
  }
}

export function sqliteRevocationStore(db: AttentDatabase): RevocationStore {
  return new SqliteRevocationStore(db);
}

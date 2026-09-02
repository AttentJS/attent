import { DuplicateIdentityError, type Identity, type IdentityStore, type PrincipalKind } from "attent";
import type { AttentDatabase } from "./db.js";

interface IdentityRow {
  readonly id: string;
  readonly tenant_id: string | null;
  readonly kind: string;
  readonly name: string | null;
  readonly public_jwk: string;
  readonly created_at: string;
  readonly created_by: string | null;
  readonly metadata: string | null;
}

function toIdentity(row: IdentityRow): Identity {
  return {
    id: row.id,
    tenantId: row.tenant_id ?? undefined,
    kind: row.kind as PrincipalKind,
    name: row.name ?? undefined,
    publicJWK: JSON.parse(row.public_jwk) as Identity["publicJWK"],
    createdAt: row.created_at,
    createdBy: row.created_by ?? undefined,
    metadata: row.metadata ? (JSON.parse(row.metadata) as Identity["metadata"]) : undefined,
  };
}

/**
 * Durable `IdentityStore` backed by SQLite (§11). Satisfies the same
 * `IdentityStore` interface as `memoryIdentityStore` — verified against the
 * shared `describeIdentityStoreContract` suite — so it's a drop-in
 * replacement, the only difference being that data survives a process
 * restart.
 */
export class SqliteIdentityStore implements IdentityStore {
  readonly #db: AttentDatabase;

  constructor(db: AttentDatabase) {
    this.#db = db;
  }

  put(identity: Identity): Promise<void> {
    const existing = this.#db.prepare("SELECT 1 FROM identities WHERE id = ?").get(identity.id);
    if (existing) {
      return Promise.reject(new DuplicateIdentityError(identity.id));
    }
    this.#db
      .prepare(
        `INSERT INTO identities (id, tenant_id, kind, name, public_jwk, created_at, created_by, metadata)
         VALUES (@id, @tenantId, @kind, @name, @publicJWK, @createdAt, @createdBy, @metadata)`
      )
      .run({
        id: identity.id,
        tenantId: identity.tenantId ?? null,
        kind: identity.kind,
        name: identity.name ?? null,
        publicJWK: JSON.stringify(identity.publicJWK),
        createdAt: identity.createdAt,
        createdBy: identity.createdBy ?? null,
        metadata: identity.metadata ? JSON.stringify(identity.metadata) : null,
      });
    return Promise.resolve();
  }

  get(id: string): Promise<Identity | null> {
    const row = this.#db.prepare("SELECT * FROM identities WHERE id = ?").get(id) as IdentityRow | undefined;
    return Promise.resolve(row ? toIdentity(row) : null);
  }
}

export function sqliteIdentityStore(db: AttentDatabase): IdentityStore {
  return new SqliteIdentityStore(db);
}

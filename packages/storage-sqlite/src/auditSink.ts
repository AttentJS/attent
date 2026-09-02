import type { AuditEvent, AuditEventFilter, AuditSink } from "attent";
import type { AttentDatabase } from "./db.js";

interface AuditRow {
  readonly payload: string;
}

/**
 * Durable `AuditSink` backed by SQLite. The full event is stored
 * as a JSON payload column (audit events are read-heavy/append-only and
 * cheap to reconstruct — no need to normalize every field into its own
 * column beyond what's needed to filter); `type`/`principal_id`/
 * `request_id`/`tenant_id` are also promoted to indexed columns so `query()`
 * can filter without deserializing every row.
 */
export class SqliteAuditSink implements AuditSink {
  readonly #db: AttentDatabase;

  constructor(db: AttentDatabase) {
    this.#db = db;
  }

  append(event: AuditEvent): Promise<void> {
    this.#db
      .prepare(
        `INSERT INTO audit_events (id, tenant_id, timestamp, type, principal_id, request_id, payload)
         VALUES (@id, @tenantId, @timestamp, @type, @principalId, @requestId, @payload)`
      )
      .run({
        id: event.id,
        tenantId: event.tenantId ?? null,
        timestamp: event.timestamp,
        type: event.type,
        principalId: event.principal.id,
        requestId: event.requestId ?? null,
        payload: JSON.stringify(event),
      });
    return Promise.resolve();
  }

  query(filter?: AuditEventFilter): Promise<readonly AuditEvent[]> {
    const clauses: string[] = [];
    const params: Record<string, string> = {};

    if (filter?.type !== undefined) {
      clauses.push("type = @type");
      params.type = filter.type;
    }
    if (filter?.principalId !== undefined) {
      clauses.push("principal_id = @principalId");
      params.principalId = filter.principalId;
    }
    if (filter?.requestId !== undefined) {
      clauses.push("request_id = @requestId");
      params.requestId = filter.requestId;
    }
    if (filter?.tenantId !== undefined) {
      clauses.push("tenant_id = @tenantId");
      params.tenantId = filter.tenantId;
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
    const rows = this.#db
      .prepare(`SELECT payload FROM audit_events ${where} ORDER BY timestamp ASC`)
      .all(params) as AuditRow[];

    return Promise.resolve(rows.map((row) => JSON.parse(row.payload) as AuditEvent));
  }
}

export function sqliteAuditSink(db: AttentDatabase): AuditSink {
  return new SqliteAuditSink(db);
}

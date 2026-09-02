import type { AuditEvent, AuditEventFilter } from "./types.js";

/**
 * Optional pull-based storage for audit events. Apps that only want
 * push-based delivery (`onAuditEvent`) never need to configure one —
 * `getAuditEvents` simply isn't available without a sink.
 */
export interface AuditSink {
  append(event: AuditEvent): Promise<void>;
  query(filter?: AuditEventFilter): Promise<readonly AuditEvent[]>;
}

function matches(event: AuditEvent, filter?: AuditEventFilter): boolean {
  if (!filter) {
    return true;
  }
  if (filter.type !== undefined && event.type !== filter.type) {
    return false;
  }
  if (filter.principalId !== undefined && event.principal.id !== filter.principalId) {
    return false;
  }
  if (filter.requestId !== undefined && event.requestId !== filter.requestId) {
    return false;
  }
  if (filter.tenantId !== undefined && event.tenantId !== filter.tenantId) {
    return false;
  }
  return true;
}

class InMemoryAuditSink implements AuditSink {
  readonly #events: AuditEvent[] = [];

  append(event: AuditEvent): Promise<void> {
    this.#events.push(event);
    return Promise.resolve();
  }

  query(filter?: AuditEventFilter): Promise<readonly AuditEvent[]> {
    return Promise.resolve(this.#events.filter((e) => matches(e, filter)));
  }
}

export function memoryAuditSink(): AuditSink {
  return new InMemoryAuditSink();
}

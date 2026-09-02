import type { Clock } from "../credentials/clock.js";
import { systemClock } from "../credentials/clock.js";
import { hashAuditEvent } from "./hashchain.js";
import type { AuditSink } from "./sink.js";
import type { AuditEvent, AuditEventFilter } from "./types.js";

export type AuditEventListener = (event: AuditEvent) => void;

/** The fields the audit-producing call sites (`audit/observe.ts`) supply; the rest `emit()` fills in. */
export type AuditEventInput = Omit<AuditEvent, "id" | "timestamp" | "prevEventHash">;

export interface AuditEmitter {
  /** Push-based subscription. Returns an unsubscribe function. */
  onAuditEvent(listener: AuditEventListener): () => void;
  /** Pull-based read, only available when a `sink` was configured. */
  getAuditEvents(filter?: AuditEventFilter): Promise<readonly AuditEvent[]>;
  /** Internal: called by `audit/observe.ts`'s wrapper functions, not typically by app code directly. */
  emit(input: AuditEventInput): Promise<AuditEvent>;
}

export interface CreateAuditEmitterOptions {
  readonly sink?: AuditSink;
  readonly clock?: Clock;
  /** Off by default: perf cost of hashing every event isn't universally needed. */
  readonly hashChain?: boolean;
  /**
   * Called when `sink.append()` throws/rejects. Defaults to logging via
   * `console.error`. Audit is fail-open-for-the-decision, fail-visible-for-
   * audit: a failing durable-audit write must never cause the caller of
   * `audited*` (`observe.ts`) to lose the `Decision`/chain/etc. it already
   * computed — the opposite of revocation's fail-closed policy, because
   * losing one audit record is recoverable (retry, alert, backfill) while
   * silently discarding an already-correct authorization result is not.
   */
  readonly onSinkError?: (error: unknown, event: AuditEvent) => void;
}

class AuditEmitterImpl implements AuditEmitter {
  readonly #sink: AuditSink | undefined;
  readonly #clock: Clock;
  readonly #hashChain: boolean;
  readonly #listeners = new Set<AuditEventListener>();
  readonly #onSinkError: (error: unknown, event: AuditEvent) => void;
  #lastHash: string | undefined;

  constructor(options: CreateAuditEmitterOptions) {
    this.#sink = options.sink;
    this.#clock = options.clock ?? systemClock();
    this.#hashChain = options.hashChain ?? false;
    this.#onSinkError =
      options.onSinkError ??
      ((error: unknown, event: AuditEvent): void => {
        console.error(`attent: audit sink append failed for event ${event.id} (${event.type})`, error);
      });
  }

  onAuditEvent(listener: AuditEventListener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  async getAuditEvents(filter?: AuditEventFilter): Promise<readonly AuditEvent[]> {
    if (!this.#sink) {
      throw new Error("getAuditEvents() requires a configured AuditSink (pull-based reads are opt-in)");
    }
    return this.#sink.query(filter);
  }

  async emit(input: AuditEventInput): Promise<AuditEvent> {
    const event: AuditEvent = {
      ...input,
      id: crypto.randomUUID(),
      timestamp: this.#clock.now().toISOString(),
      ...(this.#hashChain && this.#lastHash !== undefined ? { prevEventHash: this.#lastHash } : {}),
    };

    if (this.#hashChain) {
      this.#lastHash = hashAuditEvent(event);
    }

    for (const listener of this.#listeners) {
      listener(event);
    }
    if (this.#sink) {
      try {
        await this.#sink.append(event);
      } catch (error) {
        this.#onSinkError(error, event);
      }
    }
    return event;
  }
}

export function createAuditEmitter(options: CreateAuditEmitterOptions = {}): AuditEmitter {
  return new AuditEmitterImpl(options);
}

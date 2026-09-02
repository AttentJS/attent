import type { Clock } from "../credentials/clock.js";
import { systemClock } from "../credentials/clock.js";
import { hashAuditEvent } from "./hashchain.js";
import type { AuditSink } from "./sink.js";
import type { AuditEvent, AuditEventFilter } from "./types.js";

export type AuditEventListener = (event: AuditEvent) => void;

/** The fields the audit-producing call sites (`audit/observe.ts`) supply; the rest `emit()` fills in. */
export type AuditEventInput = Omit<AuditEvent, "id" | "timestamp" | "prevEventHash">;

export interface AuditEmitter {
  /** Push-based subscription (§12). Returns an unsubscribe function. */
  onAuditEvent(listener: AuditEventListener): () => void;
  /** Pull-based read, only available when a `sink` was configured (§12). */
  getAuditEvents(filter?: AuditEventFilter): Promise<readonly AuditEvent[]>;
  /** Internal: called by `audit/observe.ts`'s wrapper functions, not typically by app code directly. */
  emit(input: AuditEventInput): Promise<AuditEvent>;
}

export interface CreateAuditEmitterOptions {
  readonly sink?: AuditSink;
  readonly clock?: Clock;
  /** Off by default (§12: perf cost of hashing every event isn't universally needed). */
  readonly hashChain?: boolean;
}

class AuditEmitterImpl implements AuditEmitter {
  readonly #sink: AuditSink | undefined;
  readonly #clock: Clock;
  readonly #hashChain: boolean;
  readonly #listeners = new Set<AuditEventListener>();
  #lastHash: string | undefined;

  constructor(options: CreateAuditEmitterOptions) {
    this.#sink = options.sink;
    this.#clock = options.clock ?? systemClock();
    this.#hashChain = options.hashChain ?? false;
  }

  onAuditEvent(listener: AuditEventListener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  async getAuditEvents(filter?: AuditEventFilter): Promise<readonly AuditEvent[]> {
    if (!this.#sink) {
      throw new Error("getAuditEvents() requires a configured AuditSink (pull-based reads are opt-in, §12)");
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
      await this.#sink.append(event);
    }
    return event;
  }
}

export function createAuditEmitter(options: CreateAuditEmitterOptions = {}): AuditEmitter {
  return new AuditEmitterImpl(options);
}

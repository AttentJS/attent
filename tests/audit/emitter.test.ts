import { describe, it, expect } from "vitest";
import { createAuditEmitter } from "../../src/audit/emitter.js";
import { memoryAuditSink } from "../../src/audit/sink.js";
import type { AuditEvent } from "../../src/audit/types.js";

function baseInput(): Omit<AuditEvent, "id" | "timestamp" | "prevEventHash"> {
  return { type: "authorization", principal: { id: "p1" }, delegationChain: [] };
}

describe("createAuditEmitter — push", () => {
  it("notifies subscribed listeners synchronously on emit", async () => {
    const emitter = createAuditEmitter();
    const received: AuditEvent[] = [];
    emitter.onAuditEvent((e) => received.push(e));
    await emitter.emit(baseInput());
    expect(received).toHaveLength(1);
    expect(received[0]!.type).toBe("authorization");
  });

  it("unsubscribe stops further notifications", async () => {
    const emitter = createAuditEmitter();
    const received: AuditEvent[] = [];
    const unsubscribe = emitter.onAuditEvent((e) => received.push(e));
    await emitter.emit(baseInput());
    unsubscribe();
    await emitter.emit(baseInput());
    expect(received).toHaveLength(1);
  });

  it("supports multiple independent listeners", async () => {
    const emitter = createAuditEmitter();
    let a = 0;
    let b = 0;
    emitter.onAuditEvent(() => (a += 1));
    emitter.onAuditEvent(() => (b += 1));
    await emitter.emit(baseInput());
    expect(a).toBe(1);
    expect(b).toBe(1);
  });
});

describe("createAuditEmitter — pull", () => {
  it("getAuditEvents() rejects when no sink is configured", async () => {
    const emitter = createAuditEmitter();
    await expect(emitter.getAuditEvents()).rejects.toThrow();
  });

  it("getAuditEvents() returns appended events when a sink is configured, filterable by type", async () => {
    const sink = memoryAuditSink();
    const emitter = createAuditEmitter({ sink });
    await emitter.emit(baseInput());
    await emitter.emit({ ...baseInput(), type: "revocation" });

    const all = await emitter.getAuditEvents();
    expect(all).toHaveLength(2);

    const onlyRevocations = await emitter.getAuditEvents({ type: "revocation" });
    expect(onlyRevocations).toHaveLength(1);
    expect(onlyRevocations[0]!.type).toBe("revocation");
  });
});

describe("createAuditEmitter — assigns id and timestamp", () => {
  it("each event gets a unique id and an ISO timestamp from the injected clock", async () => {
    const fixed = new Date("2026-01-01T00:00:00Z");
    const emitter = createAuditEmitter({ clock: { now: () => fixed } });
    const e1 = await emitter.emit(baseInput());
    const e2 = await emitter.emit(baseInput());
    expect(e1.id).not.toBe(e2.id);
    expect(e1.timestamp).toBe(fixed.toISOString());
    expect(e2.timestamp).toBe(fixed.toISOString());
  });
});

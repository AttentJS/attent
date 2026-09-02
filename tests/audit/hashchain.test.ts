import { describe, it, expect } from "vitest";
import { createAuditEmitter } from "../../src/audit/emitter.js";
import { verifyHashChain } from "../../src/audit/hashchain.js";
import type { AuditEvent } from "../../src/audit/types.js";

function baseInput(n: number): Omit<AuditEvent, "id" | "timestamp" | "prevEventHash"> {
  return { type: "authorization", principal: { id: `p${n}` }, delegationChain: [] };
}

describe("hash-chained audit events", () => {
  it("is off by default — emitted events carry no prevEventHash", async () => {
    const emitter = createAuditEmitter();
    const e1 = await emitter.emit(baseInput(1));
    const e2 = await emitter.emit(baseInput(2));
    expect(e1.prevEventHash).toBeUndefined();
    expect(e2.prevEventHash).toBeUndefined();
  });

  it("when enabled, an untampered sequence verifies as a valid chain", async () => {
    const emitter = createAuditEmitter({ hashChain: true });
    const events = [await emitter.emit(baseInput(1)), await emitter.emit(baseInput(2)), await emitter.emit(baseInput(3))];
    expect(events[0]!.prevEventHash).toBeUndefined(); // first event has nothing to chain to
    expect(events[1]!.prevEventHash).toBeDefined();
    expect(events[2]!.prevEventHash).toBeDefined();
    expect(verifyHashChain(events)).toEqual({ valid: true });
  });

  it("mutating one event in the sequence is detected by verifyHashChain (T12)", async () => {
    const emitter = createAuditEmitter({ hashChain: true });
    const events = [await emitter.emit(baseInput(1)), await emitter.emit(baseInput(2)), await emitter.emit(baseInput(3))];

    const tampered: AuditEvent[] = [...events];
    tampered[1] = { ...tampered[1]!, principal: { id: "attacker-substituted" } };

    const result = verifyHashChain(tampered);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(2); // hop 2's prevEventHash no longer matches the (now different) hop 1
  });

  it("deleting an event from the middle of the sequence is detected", async () => {
    const emitter = createAuditEmitter({ hashChain: true });
    const events = [await emitter.emit(baseInput(1)), await emitter.emit(baseInput(2)), await emitter.emit(baseInput(3))];
    const withGap = [events[0]!, events[2]!];
    expect(verifyHashChain(withGap).valid).toBe(false);
  });
});

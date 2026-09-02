import { describe, it, expect } from "vitest";
import { createAuditEmitter } from "../../src/audit/emitter.js";
import type { AuditEvent } from "../../src/audit/types.js";

describe("audit event determinism: fixed Clock + fixed inputs -> deterministic content minus id", () => {
  it("two events built from identical input differ only by id", async () => {
    const clock = { now: (): Date => new Date("2026-01-01T00:00:00Z") };
    const emitter = createAuditEmitter({ clock });
    const input: Omit<AuditEvent, "id" | "timestamp" | "prevEventHash"> = {
      type: "authorization",
      principal: { id: "root-1" },
      delegationChain: [{ issuer: "root-1", subject: "agent-1", hopId: "hop-1" }],
      action: "refunds:create",
      resource: "order:1",
      decision: { outcome: "allow", reason: "matched_capability" },
    };

    const e1 = await emitter.emit(input);
    const e2 = await emitter.emit(input);

    expect(e1.id).not.toBe(e2.id);
    expect({ ...e1, id: "" }).toEqual({ ...e2, id: "" });
    expect(e1.timestamp).toBe("2026-01-01T00:00:00.000Z");
  });
});

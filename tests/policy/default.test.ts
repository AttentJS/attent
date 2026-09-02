import { describe, it, expect } from "vitest";
import { defaultPolicyEvaluator } from "../../src/policy/default.js";
import type { CapabilityGrant } from "../../src/credentials/types.js";

function evalWith(capability: CapabilityGrant, context: Record<string, unknown>): boolean {
  return defaultPolicyEvaluator().evaluate({ capability, action: "refunds:create", resource: "order:1", context });
}

describe("defaultPolicyEvaluator", () => {
  it("allows when there are no constraints", () => {
    expect(evalWith({ action: "refunds:create", resource: "order:*" }, {})).toBe(true);
  });

  it("enforces maxAmount", () => {
    const cap: CapabilityGrant = { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } };
    expect(evalWith(cap, { amount: 15 })).toBe(true);
    expect(evalWith(cap, { amount: 50 })).toBe(true);
    expect(evalWith(cap, { amount: 51 })).toBe(false);
  });

  it("enforces minAmount", () => {
    const cap: CapabilityGrant = { action: "refunds:create", resource: "order:*", constraints: { minAmount: 10 } };
    expect(evalWith(cap, { amount: 10 })).toBe(true);
    expect(evalWith(cap, { amount: 9 })).toBe(false);
  });

  it("enforces arbitrary equality constraints", () => {
    const cap: CapabilityGrant = { action: "refunds:create", resource: "order:*", constraints: { region: "us" } };
    expect(evalWith(cap, { region: "us" })).toBe(true);
    expect(evalWith(cap, { region: "eu" })).toBe(false);
  });

  it("never throws on missing/wrong-typed/NaN context values — degrades to deny", () => {
    const cap: CapabilityGrant = { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } };
    expect(evalWith(cap, {})).toBe(false);
    expect(evalWith(cap, { amount: "not-a-number" })).toBe(false);
    expect(evalWith(cap, { amount: Number.NaN })).toBe(false);
    expect(evalWith(cap, { amount: -5 })).toBe(true);
  });
});

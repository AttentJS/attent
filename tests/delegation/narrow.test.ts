import { describe, it, expect } from "vitest";
import { intersectAudience, intersectCapabilities } from "../../src/delegation/narrow.js";

describe("intersectCapabilities", () => {
  it("accepts a request that is a structural subset of a parent capability", () => {
    const result = intersectCapabilities(
      [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } }],
      [{ action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } }]
    );
    expect(result.ok).toBe(true);
    expect(result.exceeded).toEqual([]);
    expect(result.capabilities).toEqual([
      { action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } },
    ]);
  });

  it("rejects the naive-union attack: requested ceiling above parent's ceiling (§23 example 1)", () => {
    const result = intersectCapabilities(
      [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } }],
      [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 500 } }]
    );
    expect(result.ok).toBe(false);
    expect(result.exceeded).toHaveLength(1);
    expect(result.exceeded[0]!.field).toBe("capabilities[0]");
  });

  it("rejects the wildcard-widening attack: requesting a wildcard where parent only holds a concrete resource (§23 example 2)", () => {
    const result = intersectCapabilities(
      [{ action: "orders:read", resource: "order:18472" }],
      [{ action: "orders:read", resource: "order:*" }]
    );
    expect(result.ok).toBe(false);
  });

  it("rejects dropping a parent constraint entirely (would be broader, not narrower)", () => {
    const result = intersectCapabilities(
      [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } }],
      [{ action: "refunds:create", resource: "order:*" }]
    );
    expect(result.ok).toBe(false);
    expect(result.exceeded[0]!.reason).toContain("maxAmount");
  });

  it("accepts adding a new, stricter constraint beyond what the parent required", () => {
    const result = intersectCapabilities(
      [{ action: "refunds:create", resource: "order:*" }],
      [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 20 } }]
    );
    expect(result.ok).toBe(true);
  });

  it("enforces minAmount as a floor (requested minimum must be >= parent's)", () => {
    const covered = intersectCapabilities(
      [{ action: "refunds:create", resource: "order:*", constraints: { minAmount: 10 } }],
      [{ action: "refunds:create", resource: "order:*", constraints: { minAmount: 15 } }]
    );
    expect(covered.ok).toBe(true);

    const violates = intersectCapabilities(
      [{ action: "refunds:create", resource: "order:*", constraints: { minAmount: 10 } }],
      [{ action: "refunds:create", resource: "order:*", constraints: { minAmount: 5 } }]
    );
    expect(violates.ok).toBe(false);
  });

  it("requires exact equality for non-amount constraint keys — cannot widen an equality constraint", () => {
    const covered = intersectCapabilities(
      [{ action: "refunds:create", resource: "order:*", constraints: { region: "us" } }],
      [{ action: "refunds:create", resource: "order:*", constraints: { region: "us" } }]
    );
    expect(covered.ok).toBe(true);

    const violates = intersectCapabilities(
      [{ action: "refunds:create", resource: "order:*", constraints: { region: "us" } }],
      [{ action: "refunds:create", resource: "order:*", constraints: { region: "eu" } }]
    );
    expect(violates.ok).toBe(false);
  });

  it("rejects when no parent capability matches the requested action/resource at all", () => {
    const result = intersectCapabilities(
      [{ action: "orders:read", resource: "order:*" }],
      [{ action: "refunds:create", resource: "order:*" }]
    );
    expect(result.ok).toBe(false);
  });
});

describe("intersectAudience — rejects-over-broad-audience", () => {
  it("accepts a requested aud that is a subset of the parent's aud", () => {
    const result = intersectAudience("order:*", "order:18472");
    expect(result.ok).toBe(true);
  });

  it("rejects a requested aud broader than the parent's aud", () => {
    const result = intersectAudience("order:18472", "order:*");
    expect(result.ok).toBe(false);
    expect(result.exceeded).toHaveLength(1);
  });

  it("rejects a requested aud in an entirely unrelated namespace", () => {
    const result = intersectAudience("order:*", "billing:*");
    expect(result.ok).toBe(false);
  });

  it("supports array-valued aud on both sides", () => {
    const result = intersectAudience(["order:*", "billing:*"], ["order:18472"]);
    expect(result.ok).toBe(true);
  });
});

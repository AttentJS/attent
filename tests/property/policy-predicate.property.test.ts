import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { defaultPolicyEvaluator } from "../../src/policy/default.js";
import type { CapabilityGrant } from "../../src/credentials/types.js";
import { fcParams } from "./fc.config.js";

/**
 * §17 "Policy predicate evaluation" property target: random constraint/
 * context pairs, assert the default evaluator never throws on well-typed-
 * but-unexpected values (negative amounts, NaN, missing keys, wrong types,
 * `__proto__`-shaped keys) — it must degrade to an explicit `false`, never
 * crash `authorize()`.
 */

// Values likely to trip up naive numeric/equality comparisons.
const trickyValueArb = fc.oneof(
  fc.integer(),
  fc.float(),
  fc.double({ noNaN: false }),
  fc.constant(Number.NaN),
  fc.constant(Infinity),
  fc.constant(-Infinity),
  fc.string(),
  fc.boolean(),
  fc.constant(null),
  fc.constant(undefined),
  fc.array(fc.integer(), { maxLength: 3 }),
  fc.object({ maxDepth: 1 })
);

const constraintKeyArb = fc.oneof(
  fc.constantFrom("maxAmount", "minAmount", "tenant", "__proto__", "constructor", "region"),
  fc.string({ minLength: 1, maxLength: 10 })
);

const constraintsArb = fc.dictionary(constraintKeyArb, trickyValueArb, { maxKeys: 5 });
const contextArb = fc.dictionary(constraintKeyArb, trickyValueArb, { maxKeys: 5 });

describe("defaultPolicyEvaluator — never throws on arbitrary constraint/context pairs (property)", () => {
  it("always returns a boolean, never throws, for any constraints/context combination", () => {
    fc.assert(
      fc.property(constraintsArb, contextArb, (constraints, context) => {
        const evaluator = defaultPolicyEvaluator();
        const capability: CapabilityGrant = {
          action: "refunds:create",
          resource: "order:*",
          constraints,
        };
        let result: boolean | undefined;
        expect(() => {
          result = evaluator.evaluate({ capability, action: "refunds:create", resource: "order:18472", context });
        }).not.toThrow();
        expect(typeof result).toBe("boolean");
      }),
      fcParams(200)
    );
  });

  it("no constraints always allows, regardless of context", () => {
    fc.assert(
      fc.property(contextArb, (context) => {
        const evaluator = defaultPolicyEvaluator();
        const capability: CapabilityGrant = { action: "refunds:create", resource: "order:*" };
        expect(evaluator.evaluate({ capability, action: "refunds:create", resource: "order:18472", context })).toBe(true);
      }),
      fcParams(100)
    );
  });

  it("NaN/Infinity/negative amounts against maxAmount/minAmount never throw and never spuriously allow", () => {
    fc.assert(
      fc.property(trickyValueArb, fc.integer({ min: -1000, max: 1000 }), (amount, ceiling) => {
        const evaluator = defaultPolicyEvaluator();
        const capability: CapabilityGrant = {
          action: "refunds:create",
          resource: "order:*",
          constraints: { maxAmount: ceiling },
        };
        let result: boolean | undefined;
        expect(() => {
          result = evaluator.evaluate({
            capability,
            action: "refunds:create",
            resource: "order:18472",
            context: { amount },
          });
        }).not.toThrow();
        if (typeof amount !== "number" || !Number.isFinite(amount) || amount > ceiling) {
          expect(result).toBe(false);
        } else {
          expect(result).toBe(true);
        }
      }),
      fcParams(100)
    );
  });
});

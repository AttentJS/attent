import type { PolicyEvaluator, PolicyEvaluatorInput } from "./types.js";

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/**
 * Built-in predicate evaluator. Understands two numeric-ceiling
 * constraint keys against `context.amount` (`maxAmount`/`minAmount`, e.g.
 * a refund ceiling) and falls back to strict equality
 * (`context[key] === constraints[key]`) for any other constraint key.
 * Context restricts, never grants: a missing/wrong-typed
 * context value always evaluates to `false`, never `true`, and never throws
 * — must degrade to a clean deny on well-typed-but-unexpected input.
 */
export function defaultPolicyEvaluator(): PolicyEvaluator {
  return {
    name: "default",
    evaluate(input: PolicyEvaluatorInput): boolean {
      const constraints = input.capability.constraints;
      if (!constraints) {
        return true;
      }
      for (const [key, expected] of Object.entries(constraints)) {
        if (key === "maxAmount") {
          const amount = input.context.amount;
          if (!isFiniteNumber(amount) || !isFiniteNumber(expected) || amount > expected) {
            return false;
          }
          continue;
        }
        if (key === "minAmount") {
          const amount = input.context.amount;
          if (!isFiniteNumber(amount) || !isFiniteNumber(expected) || amount < expected) {
            return false;
          }
          continue;
        }
        if (input.context[key] !== expected) {
          return false;
        }
      }
      return true;
    },
  };
}

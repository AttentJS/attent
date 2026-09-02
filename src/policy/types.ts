import type { CapabilityGrant } from "../credentials/types.js";

export interface PolicyEvaluatorInput {
  readonly capability: CapabilityGrant;
  readonly action: string;
  readonly resource: string;
  readonly context: Readonly<Record<string, unknown>>;
}

/**
 * @experimental Only one implementation exists so far (the built-in
 * predicate evaluator) — an extension-point interface stays
 * experimental until a second real implementation (e.g. a Cedar
 * adapter) validates its shape.
 *
 * Evaluated once per structurally-matching capability: given
 * a capability whose `action`/`resource` pattern already matched the
 * request, decide whether that capability's constraints are satisfied by
 * `context`. Must never throw — an evaluator that can't make sense of
 * `context` should return `false` (deny), not crash `authorize()`.
 */
export interface PolicyEvaluator {
  readonly name: string;
  evaluate(input: PolicyEvaluatorInput): boolean;
}

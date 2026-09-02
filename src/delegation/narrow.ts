import { patternIsSubsetOf } from "../authorization/grammar.js";
import type { CapabilityGrant } from "../credentials/types.js";
import type { ExceedsDetail } from "./types.js";

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/**
 * Returns `null` if `parent` constraints structurally cover `requested`
 * (every key parent restricts, requested restates at least as strictly);
 * otherwise a human-readable reason. `maxAmount`/`minAmount` are numeric
 * ceiling/floor comparisons (mirrors `policy/default.ts`'s constraint
 * semantics so the two layers agree on what "narrower" means); every other
 * key must match exactly — an equality constraint can only be preserved,
 * never loosened. A key present on the parent but absent from `requested`
 * is a widening (requested would be unconstrained on that dimension) and is
 * rejected, never silently inherited (§7's reject-not-clip rule).
 */
function constraintsCoverRequest(
  parent: Readonly<Record<string, unknown>> | undefined,
  requested: Readonly<Record<string, unknown>> | undefined
): string | null {
  if (!parent) {
    return null;
  }
  const req = requested ?? {};
  for (const [key, parentValue] of Object.entries(parent)) {
    if (!(key in req)) {
      return `missing constraint "${key}" (present on parent, would otherwise widen)`;
    }
    const requestedValue = req[key];
    if (key === "maxAmount") {
      if (!isFiniteNumber(requestedValue) || !isFiniteNumber(parentValue) || requestedValue > parentValue) {
        return `constraint "maxAmount" (${String(requestedValue)}) exceeds parent ceiling (${String(parentValue)})`;
      }
      continue;
    }
    if (key === "minAmount") {
      if (!isFiniteNumber(requestedValue) || !isFiniteNumber(parentValue) || requestedValue < parentValue) {
        return `constraint "minAmount" (${String(requestedValue)}) is below parent floor (${String(parentValue)})`;
      }
      continue;
    }
    if (requestedValue !== parentValue) {
      return `constraint "${key}" (${String(requestedValue)}) does not match parent's fixed value (${String(parentValue)})`;
    }
  }
  return null;
}

function capabilityCoversRequest(parent: CapabilityGrant, requested: CapabilityGrant): string | null {
  if (!patternIsSubsetOf(requested.action, parent.action)) {
    return `action "${requested.action}" is not covered by parent action pattern "${parent.action}"`;
  }
  if (!patternIsSubsetOf(requested.resource, parent.resource)) {
    return `resource "${requested.resource}" is not covered by parent resource pattern "${parent.resource}"`;
  }
  return constraintsCoverRequest(parent.constraints, requested.constraints);
}

export interface CapabilityNarrowResult {
  readonly ok: boolean;
  readonly capabilities: readonly CapabilityGrant[];
  readonly exceeded: readonly ExceedsDetail[];
}

/**
 * The single most security-critical function in the codebase (§7, §17,
 * §23) — the structural narrowing check every delegation issuance and every
 * chain verification re-derives. For each requested capability, at least
 * one parent capability must structurally cover it (pattern subset +
 * at-least-as-strict constraints). Never widens: on success the returned
 * `capabilities` is exactly `requestedGrant`, unchanged — narrowing is a
 * pass/fail gate on the request, not a transformation of it (§7's
 * corrected reject-not-clip rule). `exceeded` is empty iff `ok`.
 */
export function intersectCapabilities(
  parentCapabilities: readonly CapabilityGrant[],
  requestedGrant: readonly CapabilityGrant[]
): CapabilityNarrowResult {
  const exceeded: ExceedsDetail[] = [];
  requestedGrant.forEach((requested, index) => {
    const reasons = parentCapabilities.map((parent) => capabilityCoversRequest(parent, requested));
    const covered = reasons.some((reason) => reason === null);
    if (!covered) {
      const detail = reasons.filter((r): r is string => r !== null);
      exceeded.push({
        field: `capabilities[${index}]`,
        reason:
          detail.length > 0
            ? detail.join("; ")
            : "no capability granted to the parent (parent holds no capabilities at all)",
      });
    }
  });
  return { ok: exceeded.length === 0, capabilities: requestedGrant, exceeded };
}

export interface AudienceNarrowResult {
  readonly ok: boolean;
  readonly aud: string | readonly string[];
  readonly exceeded: readonly ExceedsDetail[];
}

/**
 * Same reject-not-clip narrowing rule as capabilities, applied to `aud`
 * (§8/§24/§28 — "same reject-on-exceed rule as capabilities"). Every
 * requested `aud` pattern must be a subset of at least one parent `aud`
 * pattern.
 */
function asList(value: string | readonly string[]): readonly string[] {
  return typeof value === "string" ? [value] : value;
}

export function intersectAudience(
  parentAud: string | readonly string[],
  requestedAud: string | readonly string[]
): AudienceNarrowResult {
  const parentList = asList(parentAud);
  const requestedList = asList(requestedAud);
  const exceeded: ExceedsDetail[] = [];
  requestedList.forEach((requested, index) => {
    const covered = parentList.some((parent) => patternIsSubsetOf(requested, parent));
    if (!covered) {
      exceeded.push({
        field: `aud[${index}]`,
        reason: `"${requested}" is not covered by any parent aud pattern (${parentList.join(", ")})`,
      });
    }
  });
  return { ok: exceeded.length === 0, aud: requestedAud, exceeded };
}

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { intersectCapabilities, intersectAudience } from "../../src/delegation/narrow.js";
import type { CapabilityGrant } from "../../src/credentials/types.js";
import { fcParams } from "../property/fc.config.js";

const SEGMENT_ALPHABET = ["alpha", "beta", "gamma"] as const;

/** A pattern segment: either a concrete value from the alphabet, or the wildcard. */
const segmentArb = fc.oneof(fc.constantFrom(...SEGMENT_ALPHABET), fc.constant("*" as const));

/** A 1-3 segment colon-joined pattern, e.g. "alpha:*:gamma". */
const patternArb = fc.array(segmentArb, { minLength: 1, maxLength: 3 }).map((segs) => segs.join(":"));

/**
 * Derives a strictly-narrower-or-equal pattern from `parent` by replacing
 * every wildcard segment with a concrete alphabet value (concrete segments
 * are left untouched) — narrower or equal to `parent` by construction,
 * regardless of what `intersectCapabilities`/`patternIsSubsetOf` does.
 */
function narrowerPattern(parent: string, fill: readonly string[]): string {
  const segs = parent.split(":");
  let fillIndex = 0;
  return segs.map((s) => (s === "*" ? (fill[fillIndex++ % fill.length] ?? "alpha") : s)).join(":");
}

describe("intersectCapabilities — intersection-never-widens (property)", () => {
  it("a capability constructed to be a structural narrowing of the parent is always accepted", () => {
    fc.assert(
      fc.property(patternArb, patternArb, fc.array(fc.constantFrom(...SEGMENT_ALPHABET), { minLength: 3, maxLength: 3 }), (actionPattern, resourcePattern, fill) => {
        const parent: CapabilityGrant = { action: actionPattern, resource: resourcePattern };
        const requested: CapabilityGrant = {
          action: narrowerPattern(actionPattern, fill),
          resource: narrowerPattern(resourcePattern, fill),
        };
        const result = intersectCapabilities([parent], [requested]);
        expect(result.ok).toBe(true);
        expect(result.capabilities).toEqual([requested]);
      }),
      fcParams(100)
    );
  });

  it("a capability constructed to replace a concrete parent segment with a wildcard is always rejected", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...SEGMENT_ALPHABET),
        fc.constantFrom(...SEGMENT_ALPHABET),
        (action, resource) => {
          // parent action is concrete ("alpha"); requested widens it to "*".
          const parent: CapabilityGrant = { action, resource };
          const requested: CapabilityGrant = { action: "*", resource };
          const result = intersectCapabilities([parent], [requested]);
          expect(result.ok).toBe(false);
        }
      ),
      fcParams(100)
    );
  });

  it("numeric maxAmount constraint: requested <= parent is always accepted, requested > parent is always rejected", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 100000 }), fc.integer({ min: 0, max: 100000 }), (parentMax, delta) => {
        const parent: CapabilityGrant = { action: "refunds:create", resource: "order:*", constraints: { maxAmount: parentMax } };

        const narrower: CapabilityGrant = {
          action: "refunds:create",
          resource: "order:*",
          constraints: { maxAmount: Math.max(0, parentMax - delta) },
        };
        expect(intersectCapabilities([parent], [narrower]).ok).toBe(true);

        const wider: CapabilityGrant = {
          action: "refunds:create",
          resource: "order:*",
          constraints: { maxAmount: parentMax + delta + 1 },
        };
        expect(intersectCapabilities([parent], [wider]).ok).toBe(false);
      }),
      fcParams(100)
    );
  });
});

describe("intersectAudience — intersection-never-widens (property)", () => {
  it("a narrower aud (wildcard filled in) is always accepted; a widened aud (concrete -> wildcard) is always rejected", () => {
    fc.assert(
      fc.property(patternArb, fc.array(fc.constantFrom(...SEGMENT_ALPHABET), { minLength: 3, maxLength: 3 }), (parentAud, fill) => {
        const narrower = narrowerPattern(parentAud, fill);
        expect(intersectAudience(parentAud, narrower).ok).toBe(true);
      }),
      fcParams(100)
    );

    fc.assert(
      fc.property(fc.constantFrom(...SEGMENT_ALPHABET), (segment) => {
        const parent = segment;
        const wider = "*";
        expect(intersectAudience(parent, wider).ok).toBe(false);
      }),
      fcParams(100)
    );
  });
});

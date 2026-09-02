import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { assertConcrete, matchPattern, parsePatternSegments, patternIsSubsetOf } from "../../src/authorization/grammar.js";
import { InvalidActionError, InvalidResourceError } from "../../src/authorization/errors.js";
import { fcParams } from "./fc.config.js";

/**
 * §17 "Resource/action grammar parsing" property target: fuzz raw strings
 * against the T11 grammar. Two invariants matter here — (1) no parser crash
 * ever escapes as an unhandled/unexpected error (request-side must always
 * resolve to a clean `InvalidActionError`/`InvalidResourceError` deny, and
 * pattern-side functions must never throw at all, degrading to a fail-closed
 * `false`/`null`), and (2) a literal `*` is never accepted as *request*
 * input (no wildcard-injection false-positive-match).
 */

// Arbitrary raw strings, including glob/wildcard/prototype-pollution-ish and
// non-printable characters — anything a hostile caller might pass as a
// resource/action string.
const rawStringArb = fc.string({ minLength: 0, maxLength: 40 });

describe("assertConcrete — never crashes with anything but a typed grammar error (property)", () => {
  it("either returns a segment array of only valid concrete segments, or throws Invalid(Action|Resource)Error", () => {
    fc.assert(
      fc.property(rawStringArb, fc.constantFrom<"action" | "resource">("action", "resource"), (raw, kind) => {
        let result: string[] | undefined;
        try {
          result = assertConcrete(raw, kind);
        } catch (err) {
          expect(err instanceof InvalidActionError || err instanceof InvalidResourceError).toBe(true);
          return;
        }
        // No literal wildcard ever survives as accepted request input.
        expect(result.every((seg) => seg !== "*" && /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(seg))).toBe(true);
      }),
      fcParams(100)
    );
  });

  it("a string containing a literal '*' segment is always rejected, never glob-matched", () => {
    fc.assert(
      fc.property(
        fc.array(fc.constantFrom("alpha", "beta", "*"), { minLength: 1, maxLength: 4 }).filter((segs) => segs.includes("*")),
        (segs) => {
          expect(() => assertConcrete(segs.join(":"), "resource")).toThrow(InvalidResourceError);
        }
      ),
      fcParams(100)
    );
  });
});

describe("parsePatternSegments / matchPattern / patternIsSubsetOf — never throw (property)", () => {
  it("parsePatternSegments never throws on arbitrary input", () => {
    fc.assert(
      fc.property(rawStringArb, (raw) => {
        expect(() => parsePatternSegments(raw)).not.toThrow();
      }),
      fcParams(100)
    );
  });

  it("matchPattern never throws and only matches equal-length, non-wildcard-injected segments", () => {
    fc.assert(
      fc.property(rawStringArb, fc.array(rawStringArb, { minLength: 0, maxLength: 4 }), (pattern, concrete) => {
        let matched = false;
        expect(() => {
          matched = matchPattern(pattern, concrete);
        }).not.toThrow();
        if (matched) {
          // A match implies the pattern parsed and had the same segment count.
          const segs = parsePatternSegments(pattern);
          expect(segs).not.toBeNull();
          expect(segs!.length).toBe(concrete.length);
        }
      }),
      fcParams(100)
    );
  });

  it("patternIsSubsetOf never throws on arbitrary pattern pairs", () => {
    fc.assert(
      fc.property(rawStringArb, rawStringArb, (child, parent) => {
        expect(() => patternIsSubsetOf(child, parent)).not.toThrow();
      }),
      fcParams(100)
    );
  });

  it("__proto__/constructor-shaped segments are treated as ordinary (rejected-as-wildcard-request or non-matching) strings, never special-cased", () => {
    fc.assert(
      fc.property(fc.constantFrom("__proto__", "constructor", "prototype"), (dangerous) => {
        // Not a valid concrete segment charset-wise (underscores are fine,
        // but this exercises the exact string end-to-end) — either accepted
        // as an ordinary identifier segment or rejected, never crashes and
        // never returns something with a polluted-looking prototype.
        let result: string[] | undefined;
        try {
          result = assertConcrete(dangerous, "resource");
        } catch (err) {
          expect(err instanceof InvalidResourceError).toBe(true);
          return;
        }
        expect(Object.getPrototypeOf({})).toBe(Object.prototype);
        expect(result).toEqual([dangerous]);
      }),
      fcParams(100)
    );
  });
});

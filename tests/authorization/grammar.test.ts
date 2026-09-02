import { describe, it, expect } from "vitest";
import { assertConcrete, matchPattern, matchAnyPattern } from "../../src/authorization/grammar.js";
import { InvalidActionError, InvalidResourceError } from "../../src/authorization/errors.js";

describe("assertConcrete (T11 grammar)", () => {
  it("accepts well-formed namespaced identifiers", () => {
    expect(assertConcrete("orders:read", "action")).toEqual(["orders", "read"]);
    expect(assertConcrete("order:18472", "resource")).toEqual(["order", "18472"]);
  });

  it("rejects a literal wildcard in request input rather than glob-matching it", () => {
    expect(() => assertConcrete("order:*", "resource")).toThrow(InvalidResourceError);
    expect(() => assertConcrete("*", "resource")).toThrow(InvalidResourceError);
  });

  it("rejects empty strings, empty segments, and non-string input", () => {
    expect(() => assertConcrete("", "resource")).toThrow(InvalidResourceError);
    expect(() => assertConcrete("order:", "resource")).toThrow(InvalidResourceError);
    expect(() => assertConcrete(":18472", "resource")).toThrow(InvalidResourceError);
    expect(() => assertConcrete(123 as unknown as string, "action")).toThrow(InvalidActionError);
  });

  it("rejects other glob metacharacters", () => {
    expect(() => assertConcrete("order:18?72", "resource")).toThrow(InvalidResourceError);
    expect(() => assertConcrete("order:187/2", "resource")).toThrow(InvalidResourceError);
  });
});

describe("matchPattern", () => {
  it("matches an exact identifier", () => {
    expect(matchPattern("refunds:create", ["refunds", "create"])).toBe(true);
    expect(matchPattern("refunds:create", ["refunds", "read"])).toBe(false);
  });

  it("matches a wildcard segment against exactly one concrete segment", () => {
    expect(matchPattern("order:*", ["order", "18472"])).toBe(true);
    expect(matchPattern("order:*", ["order", "18472", "line"])).toBe(false);
  });

  it("never throws on a malformed pattern — fails closed instead", () => {
    expect(matchPattern("", ["order", "1"])).toBe(false);
    expect(matchPattern("order:1?2", ["order", "1?2"])).toBe(false);
  });

  it("matchAnyPattern matches if any pattern in the list matches", () => {
    expect(matchAnyPattern(["billing:*", "order:*"], ["order", "18472"])).toBe(true);
    expect(matchAnyPattern(["billing:*"], ["order", "18472"])).toBe(false);
  });
});

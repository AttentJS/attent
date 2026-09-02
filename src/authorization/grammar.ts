import { InvalidActionError, InvalidResourceError } from "./errors.js";

/**
 * T11 grammar: namespaced colon-separated identifiers. A concrete (request)
 * segment is plain alphanumerics/`_`/`-`; a pattern (capability/aud) segment
 * may additionally be the literal wildcard `*`, matching exactly one
 * concrete segment at that position. The wildcard is never valid in request
 * input — only in policy-authored patterns — so a request resource/action
 * containing `*` is rejected outright, not glob-matched (defense against
 * wildcard-injection).
 */
const CONCRETE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;

function splitSegments(value: string): string[] {
  return value.split(":");
}

function isConcreteSegment(segment: string): boolean {
  return CONCRETE_SEGMENT.test(segment);
}

function isPatternSegment(segment: string): boolean {
  return segment === "*" || CONCRETE_SEGMENT.test(segment);
}

/**
 * Validates and splits a request-side action/resource string. Throws
 * (never returns an ambiguous result) on any grammar violation — per §26,
 * malformed input is a reject, not a deny.
 */
export function assertConcrete(value: string, kind: "action" | "resource"): string[] {
  if (typeof value !== "string" || value.length === 0) {
    return throwGrammarError(kind, "must be a non-empty string");
  }
  const segments = splitSegments(value);
  for (const segment of segments) {
    if (segment.length === 0) {
      return throwGrammarError(kind, `"${value}" contains an empty segment`);
    }
    if (!isConcreteSegment(segment)) {
      return throwGrammarError(
        kind,
        `"${value}" is not a valid concrete identifier (segment "${segment}" is invalid or a wildcard)`
      );
    }
  }
  return segments;
}

function throwGrammarError(kind: "action" | "resource", reason: string): never {
  if (kind === "action") {
    throw new InvalidActionError(reason);
  }
  throw new InvalidResourceError(reason);
}

/**
 * Parses a policy-authored pattern (capability action/resource, `aud`).
 * Returns `null` instead of throwing on a malformed pattern — a malformed
 * pattern living inside an already-signed, trusted credential must never
 * crash `authorize()`; it simply can never match anything (fail closed).
 */
export function parsePatternSegments(value: string): string[] | null {
  if (typeof value !== "string" || value.length === 0) {
    return null;
  }
  const segments = splitSegments(value);
  for (const segment of segments) {
    if (!isPatternSegment(segment)) {
      return null;
    }
  }
  return segments;
}

export function matchPattern(pattern: string, concreteSegments: readonly string[]): boolean {
  const patternSegments = parsePatternSegments(pattern);
  if (!patternSegments) {
    return false;
  }
  if (patternSegments.length !== concreteSegments.length) {
    return false;
  }
  return patternSegments.every((segment, i) => segment === "*" || segment === concreteSegments[i]);
}

export function matchAnyPattern(patterns: readonly string[], concreteSegments: readonly string[]): boolean {
  return patterns.some((pattern) => matchPattern(pattern, concreteSegments));
}

/**
 * True iff every string `childPattern` could match, `parentPattern` could
 * also match — i.e. `childPattern` is at least as narrow as `parentPattern`.
 * Used by delegation narrowing (§7/§23), not request-time matching: a
 * concrete parent segment only matches an identical child segment; a
 * wildcard parent segment matches anything at that position, including a
 * wildcard child segment. A wildcard child segment against a concrete
 * parent segment is never a subset (the canonical "wildcard-widening"
 * rejection, §23 example 2). Malformed patterns are never a subset of
 * anything (fail closed, mirrors `parsePatternSegments`).
 */
export function patternIsSubsetOf(childPattern: string, parentPattern: string): boolean {
  const child = parsePatternSegments(childPattern);
  const parent = parsePatternSegments(parentPattern);
  if (!child || !parent) {
    return false;
  }
  if (child.length !== parent.length) {
    return false;
  }
  return child.every((segment, i) => parent[i] === "*" || segment === parent[i]);
}

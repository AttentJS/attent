import {
  decodeProtectedHeader,
  decodeJwt,
  importJWK,
  jwtVerify,
  errors as joseErrors,
  type JWK,
} from "jose";
import { ALLOWED_ALGORITHMS, type Algorithm, type KeyProvider, type TrustedKeyStore } from "../crypto/types.js";
import type { Identity } from "../identity/types.js";
import type { CapabilityGrant, Credential, HopClaims } from "./types.js";
import type { Clock } from "./clock.js";
import { systemClock } from "./clock.js";
import {
  CredentialExpiredError,
  CredentialVerificationError,
  InvalidCredentialInputError,
  MalformedCredentialError,
} from "./errors.js";

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function assertSafeObject(obj: Readonly<Record<string, unknown>>, what: string): void {
  for (const key of Object.keys(obj)) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new MalformedCredentialError(`${what} contains forbidden key "${key}"`);
    }
  }
}

function assertValidCapabilities(capabilities: readonly CapabilityGrant[]): void {
  for (const cap of capabilities) {
    if (typeof cap.action !== "string" || cap.action.trim().length === 0) {
      throw new InvalidCredentialInputError("capability action must be a non-empty string");
    }
    if (typeof cap.resource !== "string" || cap.resource.trim().length === 0) {
      throw new InvalidCredentialInputError("capability resource must be a non-empty string");
    }
    if (cap.constraints) {
      assertSafeObject(cap.constraints, "capability constraints");
    }
  }
}

export interface IssueCredentialInput {
  readonly issuer: Identity;
  readonly subject: Identity;
  /** Signing key for `issuer` — never inspected beyond calling `.sign()`. */
  readonly keyProvider: KeyProvider;
  readonly capabilities: readonly CapabilityGrant[];
  readonly aud: string | readonly string[];
  /** Time-to-live in seconds; must be a positive integer. */
  readonly ttlSeconds: number;
  readonly clock?: Clock;
}

/**
 * Issues a single signed hop (§8). No delegation/chain support yet (Phase 4)
 * — this always produces a root, one-hop credential from `issuer` to
 * `subject`.
 */
export async function issueCredential(input: IssueCredentialInput): Promise<Credential> {
  const { issuer, subject, keyProvider, capabilities, aud, ttlSeconds } = input;
  const clock = input.clock ?? systemClock();

  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new InvalidCredentialInputError("ttlSeconds must be a positive integer");
  }
  if (!Array.isArray(capabilities)) {
    throw new InvalidCredentialInputError("capabilities must be an array");
  }
  assertValidCapabilities(capabilities);

  const audList = Array.isArray(aud) ? aud : [aud];
  if (audList.length === 0 || audList.some((a) => typeof a !== "string" || a.trim().length === 0)) {
    throw new InvalidCredentialInputError("aud must be a non-empty string or non-empty array of non-empty strings");
  }

  const iat = Math.floor(clock.now().getTime() / 1000);
  const exp = iat + ttlSeconds;

  const claims: HopClaims = {
    iss: issuer.id,
    sub: subject.id,
    aud,
    capabilities,
    jti: crypto.randomUUID(),
    iat,
    exp,
  };

  const jws = await keyProvider.sign(claims as unknown as Record<string, unknown>);
  return { jws, claims };
}

function assertShapeOfHopClaims(claims: Record<string, unknown>): asserts claims is HopClaims & Record<string, unknown> {
  assertSafeObject(claims, "credential claims");

  if (typeof claims.iss !== "string" || claims.iss.length === 0) {
    throw new MalformedCredentialError("missing or invalid iss claim");
  }
  if (typeof claims.sub !== "string" || claims.sub.length === 0) {
    throw new MalformedCredentialError("missing or invalid sub claim");
  }
  const aud = claims.aud;
  const audValid =
    (typeof aud === "string" && aud.length > 0) ||
    (Array.isArray(aud) && aud.length > 0 && aud.every((a) => typeof a === "string" && a.length > 0));
  if (!audValid) {
    throw new MalformedCredentialError("missing or invalid aud claim");
  }
  if (!Array.isArray(claims.capabilities)) {
    throw new MalformedCredentialError("missing or invalid capabilities claim");
  }
  for (const cap of claims.capabilities as unknown[]) {
    if (typeof cap !== "object" || cap === null) {
      throw new MalformedCredentialError("capability entry must be an object");
    }
    const c = cap as Record<string, unknown>;
    assertSafeObject(c, "capability entry");
    if (typeof c.action !== "string" || c.action.length === 0) {
      throw new MalformedCredentialError("capability entry missing valid action");
    }
    if (typeof c.resource !== "string" || c.resource.length === 0) {
      throw new MalformedCredentialError("capability entry missing valid resource");
    }
    if (c.constraints !== undefined) {
      if (typeof c.constraints !== "object" || c.constraints === null) {
        throw new MalformedCredentialError("capability constraints must be an object");
      }
      assertSafeObject(c.constraints as Record<string, unknown>, "capability constraints");
    }
  }
  if (typeof claims.jti !== "string" || claims.jti.length === 0) {
    throw new MalformedCredentialError("missing or invalid jti claim");
  }
  if (typeof claims.iat !== "number" || typeof claims.exp !== "number") {
    throw new MalformedCredentialError("missing or invalid iat/exp claim");
  }
  if (claims.parentHopHash !== undefined && (typeof claims.parentHopHash !== "string" || claims.parentHopHash.length === 0)) {
    throw new MalformedCredentialError("invalid parentHopHash claim");
  }
}

export interface VerifyCredentialInput {
  readonly jws: string;
  readonly trustedKeys: TrustedKeyStore;
  readonly clock?: Clock;
}

/**
 * Verifies a single-hop credential (§8/§9 step 7). Always mandatory-checks:
 * algorithm allowlist, `kid` known to `trustedKeys` for the claimed issuer,
 * signature, expiry (via injected `Clock`) — no partial-verification mode.
 */
export async function verifyCredential(input: VerifyCredentialInput): Promise<Credential> {
  const { jws, trustedKeys } = input;
  const clock = input.clock ?? systemClock();

  let header;
  try {
    header = decodeProtectedHeader(jws);
  } catch (err) {
    throw new MalformedCredentialError(`unparsable header: ${err instanceof Error ? err.message : String(err)}`);
  }

  const alg = header.alg;
  if (!alg || !(ALLOWED_ALGORITHMS as readonly string[]).includes(alg)) {
    throw new CredentialVerificationError(`disallowed algorithm: ${String(alg)}`);
  }
  const kid = header.kid;
  if (!kid) {
    throw new MalformedCredentialError("missing kid header");
  }

  // Unsafe/unverified peek — used only to look up which issuer+key signed
  // this token. Nothing derived from this is trusted for the decision; the
  // authoritative payload is the one returned by jwtVerify below.
  let unverifiedClaims: Record<string, unknown>;
  try {
    unverifiedClaims = decodeJwt(jws);
  } catch (err) {
    throw new MalformedCredentialError(`unparsable payload: ${err instanceof Error ? err.message : String(err)}`);
  }
  const iss = unverifiedClaims.iss;
  if (typeof iss !== "string" || iss.length === 0) {
    throw new MalformedCredentialError("missing or invalid iss claim");
  }

  const jwk: JWK | null = await trustedKeys.getKey(iss, kid);
  if (!jwk) {
    throw new CredentialVerificationError(`no trusted key for issuer "${iss}" kid "${kid}"`);
  }
  if (jwk.alg && jwk.alg !== alg) {
    throw new CredentialVerificationError("token alg does not match trusted key's alg");
  }

  const key = await importJWK(jwk, alg);

  let payload: Record<string, unknown>;
  try {
    const result = await jwtVerify(jws, key, {
      algorithms: [alg as Algorithm],
      currentDate: clock.now(),
    });
    payload = result.payload;
  } catch (err) {
    if (err instanceof joseErrors.JWTExpired) {
      throw new CredentialExpiredError();
    }
    throw new CredentialVerificationError(err instanceof Error ? err.message : String(err));
  }

  assertShapeOfHopClaims(payload);

  return { jws, claims: payload };
}

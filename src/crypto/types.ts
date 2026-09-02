import type { JWK } from "jose";

/**
 * Signing algorithms Attent supports. This is an explicit allowlist —
 * `verify()` must never trust an `alg` header from untrusted input alone (T-key-confusion).
 */
export type Algorithm = "EdDSA" | "ES256";

export const ALLOWED_ALGORITHMS: readonly Algorithm[] = ["EdDSA", "ES256"];

/**
 * Claims a caller wants signed. Plain JSON-serializable object; the crypto
 * layer does not interpret claim semantics (that's credentials/delegation's job).
 */
export type Claims = Record<string, unknown>;

/**
 * Wraps a signing keypair for a single Principal. The private key never
 * leaves an implementation of this interface (T14) — callers only ever see
 * signed strings, verified payloads, or the public JWK.
 */
export interface KeyProvider {
  readonly kid: string;
  readonly alg: Algorithm;
  sign(claims: Claims): Promise<string>;
  verify(jws: string): Promise<Claims>;
  getPublicJWK(): Promise<JWK>;
}

/**
 * Maps issuerId -> public JWK(s), keyed by `kid`, consulted at credential
 * verification time. Supports multiple concurrently-valid keys per issuer
 * so key rotation has an overlap window instead of a hard cutover.
 */
export interface TrustedKeyStore {
  addKey(issuerId: string, kid: string, jwk: JWK): Promise<void>;
  getKey(issuerId: string, kid: string): Promise<JWK | null>;
  removeKey(issuerId: string, kid: string): Promise<void>;
}

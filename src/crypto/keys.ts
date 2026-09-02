import {
  SignJWT,
  jwtVerify,
  exportJWK,
  generateKeyPair,
  calculateJwkThumbprint,
  type JWK,
  type KeyLike,
} from "jose";
import { ALLOWED_ALGORITHMS, type Algorithm, type Claims, type KeyProvider, type TrustedKeyStore } from "./types.js";
import { UnsupportedAlgorithmError, SignatureVerificationError } from "./errors.js";

function assertAllowedAlgorithm(alg: string): asserts alg is Algorithm {
  if (!(ALLOWED_ALGORITHMS as readonly string[]).includes(alg)) {
    throw new UnsupportedAlgorithmError(alg);
  }
}

class JoseKeyProvider implements KeyProvider {
  readonly kid: string;
  readonly alg: Algorithm;
  readonly #privateKey: KeyLike;
  readonly #publicKey: KeyLike;

  constructor(alg: Algorithm, kid: string, privateKey: KeyLike, publicKey: KeyLike) {
    this.alg = alg;
    this.kid = kid;
    this.#privateKey = privateKey;
    this.#publicKey = publicKey;
  }

  async sign(claims: Claims): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: this.alg, kid: this.kid })
      .sign(this.#privateKey);
  }

  async verify(jws: string): Promise<Claims> {
    try {
      const { payload } = await jwtVerify(jws, this.#publicKey, {
        algorithms: [this.alg],
      });
      return payload;
    } catch (err) {
      throw new SignatureVerificationError(err instanceof Error ? err.message : String(err));
    }
  }

  async getPublicJWK(): Promise<JWK> {
    const jwk = await exportJWK(this.#publicKey);
    return { ...jwk, kid: this.kid, alg: this.alg, use: "sig" };
  }
}

/**
 * Generates a fresh Ed25519 (default) or P-256 keypair and wraps it in a
 * `KeyProvider`. The private key is captured in a closure and never exposed
 * through the public interface (T14).
 */
export async function generateKeyProvider(alg: Algorithm = "EdDSA"): Promise<KeyProvider> {
  assertAllowedAlgorithm(alg);
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  return new JoseKeyProvider(alg, kid, privateKey, publicKey);
}

class InMemoryTrustedKeyStore implements TrustedKeyStore {
  readonly #keys = new Map<string, Map<string, JWK>>();

  addKey(issuerId: string, kid: string, jwk: JWK): Promise<void> {
    let forIssuer = this.#keys.get(issuerId);
    if (!forIssuer) {
      forIssuer = new Map();
      this.#keys.set(issuerId, forIssuer);
    }
    forIssuer.set(kid, jwk);
    return Promise.resolve();
  }

  getKey(issuerId: string, kid: string): Promise<JWK | null> {
    return Promise.resolve(this.#keys.get(issuerId)?.get(kid) ?? null);
  }

  removeKey(issuerId: string, kid: string): Promise<void> {
    this.#keys.get(issuerId)?.delete(kid);
    return Promise.resolve();
  }
}

export function memoryTrustedKeyStore(): TrustedKeyStore {
  return new InMemoryTrustedKeyStore();
}

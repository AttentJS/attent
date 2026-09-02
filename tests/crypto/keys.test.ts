import { describe, it, expect } from "vitest";
import { SignJWT, generateSecret } from "jose";
import { generateKeyProvider, memoryTrustedKeyStore } from "../../src/crypto/keys.js";
import { UnsupportedAlgorithmError, SignatureVerificationError } from "../../src/crypto/errors.js";
import type { Algorithm } from "../../src/crypto/types.js";

describe("generateKeyProvider", () => {
  it("defaults to EdDSA and produces a public JWK with matching kid", async () => {
    const provider = await generateKeyProvider();
    expect(provider.alg).toBe("EdDSA");
    const jwk = await provider.getPublicJWK();
    expect(jwk.kid).toBe(provider.kid);
    expect(jwk.kty).toBe("OKP");
  });

  it("supports ES256", async () => {
    const provider = await generateKeyProvider("ES256");
    expect(provider.alg).toBe("ES256");
    const jwk = await provider.getPublicJWK();
    expect(jwk.kty).toBe("EC");
  });

  it("rejects a disallowed algorithm", async () => {
    await expect(generateKeyProvider("HS256" as Algorithm)).rejects.toThrow(UnsupportedAlgorithmError);
  });

  it("never exposes private key material on the public interface", async () => {
    const provider = await generateKeyProvider();
    expect(Object.keys(provider)).not.toContain("privateKey");
    expect(JSON.stringify(provider)).not.toMatch(/priv/i);
  });
});

describe("sign / verify round trip", () => {
  it("signs a payload and verifies it back to the same claims", async () => {
    const provider = await generateKeyProvider();
    const jws = await provider.sign({ hello: "world", n: 42 });
    const claims = await provider.verify(jws);
    expect(claims.hello).toBe("world");
    expect(claims.n).toBe(42);
  });

  it("rejects a token signed by a different keypair", async () => {
    const a = await generateKeyProvider();
    const b = await generateKeyProvider();
    const jws = await a.sign({ x: 1 });
    await expect(b.verify(jws)).rejects.toThrow(SignatureVerificationError);
  });

  it("rejects a tampered payload (signature mismatch)", async () => {
    const provider = await generateKeyProvider();
    const jws = await provider.sign({ amount: 10 });
    const [header, , signature] = jws.split(".");
    const tamperedPayload = Buffer.from(JSON.stringify({ amount: 10000 })).toString("base64url");
    const tampered = `${header}.${tamperedPayload}.${signature}`;
    await expect(provider.verify(tampered)).rejects.toThrow(SignatureVerificationError);
  });

  it("rejects a token using a disallowed/unexpected algorithm even if otherwise well-formed", async () => {
    const provider = await generateKeyProvider();
    const secret = await generateSecret("HS256");
    const foreignJws = await new SignJWT({ x: 1 })
      .setProtectedHeader({ alg: "HS256" })
      .sign(secret);
    await expect(provider.verify(foreignJws)).rejects.toThrow(SignatureVerificationError);
  });
});

describe("memoryTrustedKeyStore", () => {
  it("stores and retrieves keys by issuerId + kid", async () => {
    const store = memoryTrustedKeyStore();
    const provider = await generateKeyProvider();
    const jwk = await provider.getPublicJWK();
    await store.addKey("issuer-1", provider.kid, jwk);
    expect(await store.getKey("issuer-1", provider.kid)).toEqual(jwk);
    expect(await store.getKey("issuer-1", "unknown-kid")).toBeNull();
    expect(await store.getKey("unknown-issuer", provider.kid)).toBeNull();
  });

  it("supports rotation: multiple concurrently-valid keys per issuer, and removal", async () => {
    const store = memoryTrustedKeyStore();
    const oldKey = await generateKeyProvider();
    const newKey = await generateKeyProvider();
    await store.addKey("issuer-1", oldKey.kid, await oldKey.getPublicJWK());
    await store.addKey("issuer-1", newKey.kid, await newKey.getPublicJWK());

    expect(await store.getKey("issuer-1", oldKey.kid)).not.toBeNull();
    expect(await store.getKey("issuer-1", newKey.kid)).not.toBeNull();

    await store.removeKey("issuer-1", oldKey.kid);
    expect(await store.getKey("issuer-1", oldKey.kid)).toBeNull();
    expect(await store.getKey("issuer-1", newKey.kid)).not.toBeNull();
  });
});

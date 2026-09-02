import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { verifyCredential, issueCredential } from "../../src/credentials/credentials.js";
import { makeActor, scenario, fixedClock } from "../fixtures/chain.js";
import {
  CredentialExpiredError,
  CredentialVerificationError,
  InvalidCredentialInputError,
  MalformedCredentialError,
} from "../../src/credentials/errors.js";
import { fcParams } from "./fc.config.js";

/**
 * Credential (de)serialization property target: (a) a legitimately
 * issued credential round-trips through verify stably, and (b) arbitrary
 * malformed/truncated/non-JWS input is always rejected with a graceful,
 * typed error — never a crash, and never a partially-parsed trusted-looking
 * `Credential` object.
 */

const KNOWN_ERRORS = [CredentialExpiredError, CredentialVerificationError, MalformedCredentialError, InvalidCredentialInputError];

function isKnownError(err: unknown): boolean {
  return KNOWN_ERRORS.some((Ctor) => err instanceof Ctor);
}

describe("verifyCredential — round-trip stability (property)", () => {
  it("a freshly issued credential verifies to structurally identical claims, repeatedly", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 20 }).filter((s) => /^[A-Za-z0-9_-]+$/.test(s)),
        fc.integer({ min: 1, max: 100000 }),
        async (actionSuffix, ttlSeconds) => {
          const { trustedKeys, root } = await scenario();
          const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
          const clock = fixedClock(new Date("2026-01-01T00:00:00.000Z"));

          const credential = await issueCredential({
            issuer: root.identity,
            subject: agent.identity,
            keyProvider: root.keys,
            capabilities: [{ action: `orders:${actionSuffix}`, resource: "order:*" }],
            aud: "order:*",
            ttlSeconds,
            clock,
          });

          const first = await verifyCredential({ jws: credential.jws, trustedKeys, clock });
          const second = await verifyCredential({ jws: credential.jws, trustedKeys, clock });
          expect(first.claims).toEqual(second.claims);
          expect(first.claims).toEqual(credential.claims);
        }
      ),
      fcParams(30)
    );
  });
});

describe("verifyCredential — malformed input never crashes, only ever rejects cleanly (property)", () => {
  it("arbitrary garbage strings are always rejected with a known error type", async () => {
    await fc.assert(
      fc.asyncProperty(fc.string({ minLength: 0, maxLength: 200 }), async (garbage) => {
        const { trustedKeys } = await scenario();
        try {
          await verifyCredential({ jws: garbage, trustedKeys });
          // If it didn't throw, that's a false-accept of unsigned garbage — fail loudly.
          expect.fail(`verifyCredential accepted garbage input: ${JSON.stringify(garbage)}`);
        } catch (err) {
          expect(isKnownError(err)).toBe(true);
        }
      }),
      fcParams(100)
    );
  });

  it("a syntactically JWS-shaped but garbage-payload token is always rejected with a known error type", async () => {
    const b64 = (obj: unknown): string => Buffer.from(JSON.stringify(obj)).toString("base64url");
    await fc.assert(
      fc.asyncProperty(
        fc.dictionary(fc.string({ minLength: 1, maxLength: 10 }), fc.jsonValue(), { maxKeys: 10 }),
        async (payload) => {
          const { trustedKeys } = await scenario();
          const header = b64({ alg: "EdDSA", kid: "nonexistent-kid" });
          const body = b64(payload);
          const fakeJws = `${header}.${body}.fake-signature`;
          try {
            await verifyCredential({ jws: fakeJws, trustedKeys });
            expect.fail("verifyCredential accepted a forged/unsigned JWS-shaped token");
          } catch (err) {
            expect(isKnownError(err)).toBe(true);
          }
        }
      ),
      fcParams(50)
    );
  });

  it("prototype-pollution-shaped payload keys are rejected as malformed, never applied to Object.prototype", async () => {
    const { trustedKeys } = await scenario();
    const b64 = (obj: unknown): string => Buffer.from(JSON.stringify(obj)).toString("base64url");
    const header = b64({ alg: "EdDSA", kid: "nonexistent-kid" });
    // JSON.parse on a literal "__proto__" key does NOT pollute Object.prototype
    // (it becomes an own enumerable property) — this asserts our own parsing
    // layer doesn't do anything unsafe (e.g. Object.assign) that would.
    const body = b64({ __proto__: { polluted: true }, iss: "x" });
    const fakeJws = `${header}.${body}.fake-signature`;

    await expect(verifyCredential({ jws: fakeJws, trustedKeys })).rejects.toThrow();
    expect((Object.prototype as Record<string, unknown>).polluted).toBeUndefined();
  });
});

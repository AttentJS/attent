import { describe, it, expect } from "vitest";
import { generateKeyProvider } from "../../src/crypto/keys.js";
import { createIdentity } from "../../src/identity/identity.js";
import { InvalidIdentityError } from "../../src/identity/errors.js";
import { isAgent } from "../../src/identity/types.js";
import type { PrincipalKind } from "../../src/identity/types.js";

describe("createIdentity", () => {
  it("creates a human/application identity with a generated id and timestamp", async () => {
    const provider = await generateKeyProvider();
    const identity = createIdentity({
      kind: "application",
      name: "acme-app",
      publicJWK: await provider.getPublicJWK(),
    });

    expect(identity.id).toBeTruthy();
    expect(identity.kind).toBe("application");
    expect(identity.name).toBe("acme-app");
    expect(new Date(identity.createdAt).toString()).not.toBe("Invalid Date");
    expect(isAgent(identity)).toBe(false);
  });

  it("defaults kind to agent and requires createdBy", async () => {
    const provider = await generateKeyProvider();
    const publicJWK = await provider.getPublicJWK();

    expect(() => createIdentity({ publicJWK })).toThrow(InvalidIdentityError);

    const agent = createIdentity({ publicJWK, createdBy: "root-id", name: "support-agent" });
    expect(agent.kind).toBe("agent");
    expect(agent.createdBy).toBe("root-id");
    expect(isAgent(agent)).toBe(true);
  });

  it("generates distinct ids for successive identities", async () => {
    const provider = await generateKeyProvider();
    const publicJWK = await provider.getPublicJWK();
    const a = createIdentity({ kind: "human", publicJWK });
    const b = createIdentity({ kind: "human", publicJWK });
    expect(a.id).not.toBe(b.id);
  });

  it("rejects an unknown kind", async () => {
    const provider = await generateKeyProvider();
    const publicJWK = await provider.getPublicJWK();
    expect(() =>
      createIdentity({ kind: "root" as PrincipalKind, publicJWK })
    ).toThrow(InvalidIdentityError);
  });

  it("rejects an empty name", async () => {
    const provider = await generateKeyProvider();
    const publicJWK = await provider.getPublicJWK();
    expect(() => createIdentity({ kind: "human", name: "   ", publicJWK })).toThrow(
      InvalidIdentityError
    );
  });

  it("rejects a missing/malformed publicJWK", () => {
    expect(() =>
      createIdentity({ kind: "human", publicJWK: {} })
    ).toThrow(InvalidIdentityError);
  });

  it("rejects prototype-pollution-shaped metadata keys", async () => {
    const provider = await generateKeyProvider();
    const publicJWK = await provider.getPublicJWK();
    expect(() =>
      createIdentity({
        kind: "human",
        publicJWK,
        metadata: { __proto__: { polluted: true } },
      })
    ).not.toThrow();
    // __proto__ as an object literal key does not become an own enumerable
    // key (it sets the prototype), so guard against the JSON.parse case too.
    const parsed = JSON.parse('{"__proto__": {"polluted": true}}') as Record<string, unknown>;
    expect(() => createIdentity({ kind: "human", publicJWK, metadata: parsed })).toThrow(
      InvalidIdentityError
    );
  });
});

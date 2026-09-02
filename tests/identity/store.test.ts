import { describe, it, expect } from "vitest";
import { generateKeyProvider } from "../../src/crypto/keys.js";
import { createIdentity } from "../../src/identity/identity.js";
import { memoryIdentityStore } from "../../src/identity/store.js";
import { DuplicateIdentityError } from "../../src/identity/errors.js";

describe("memoryIdentityStore", () => {
  it("stores and retrieves an identity by id", async () => {
    const provider = await generateKeyProvider();
    const store = memoryIdentityStore();
    const identity = createIdentity({ kind: "human", publicJWK: await provider.getPublicJWK() });

    await store.put(identity);
    expect(await store.get(identity.id)).toEqual(identity);
  });

  it("returns null for an unknown id", async () => {
    const store = memoryIdentityStore();
    expect(await store.get("does-not-exist")).toBeNull();
  });

  it("rejects putting a duplicate id", async () => {
    const provider = await generateKeyProvider();
    const store = memoryIdentityStore();
    const identity = createIdentity({ kind: "human", publicJWK: await provider.getPublicJWK() });

    await store.put(identity);
    await expect(store.put(identity)).rejects.toThrow(DuplicateIdentityError);
  });
});

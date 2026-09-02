import { describe, it, expect } from "vitest";
import { memoryRevocationStore } from "../../src/revocation/memory.js";

describe("memoryRevocationStore", () => {
  it("isRevoked is false for an unknown hop id", async () => {
    const store = memoryRevocationStore();
    expect(await store.isRevoked("nope")).toBe(false);
  });

  it("revoke marks exactly that hop id as revoked", async () => {
    const store = memoryRevocationStore();
    await store.revoke("hop-1");
    expect(await store.isRevoked("hop-1")).toBe(true);
    expect(await store.isRevoked("hop-2")).toBe(false);
  });

  it("two independent in-memory stores never share revocation state (documented limitation)", async () => {
    const a = memoryRevocationStore();
    const b = memoryRevocationStore();
    await a.revoke("hop-1");
    expect(await a.isRevoked("hop-1")).toBe(true);
    expect(await b.isRevoked("hop-1")).toBe(false);
  });
});

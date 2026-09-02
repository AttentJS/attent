import type { RevocationStore, RevokeOptions } from "./types.js";

class InMemoryRevocationStore implements RevocationStore {
  readonly #revoked = new Set<string>();

  revoke(hopId: string, _opts?: RevokeOptions): Promise<void> {
    this.#revoked.add(hopId);
    return Promise.resolve();
  }

  isRevoked(hopId: string): Promise<boolean> {
    return Promise.resolve(this.#revoked.has(hopId));
  }
}

/** Instant, local, synchronous-in-effect (§25) — the default store. */
export function memoryRevocationStore(): RevocationStore {
  return new InMemoryRevocationStore();
}

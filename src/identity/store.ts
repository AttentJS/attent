import type { Identity } from "./types.js";
import { DuplicateIdentityError } from "./errors.js";

export interface IdentityStore {
  put(identity: Identity): Promise<void>;
  get(id: string): Promise<Identity | null>;
}

class InMemoryIdentityStore implements IdentityStore {
  readonly #identities = new Map<string, Identity>();

  put(identity: Identity): Promise<void> {
    if (this.#identities.has(identity.id)) {
      return Promise.reject(new DuplicateIdentityError(identity.id));
    }
    this.#identities.set(identity.id, identity);
    return Promise.resolve();
  }

  get(id: string): Promise<Identity | null> {
    return Promise.resolve(this.#identities.get(id) ?? null);
  }
}

export function memoryIdentityStore(): IdentityStore {
  return new InMemoryIdentityStore();
}

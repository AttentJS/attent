import type { JWK } from "jose";
import { MAX_METADATA_KEYS } from "./types.js";
import type { Identity, PrincipalKind } from "./types.js";
import { InvalidIdentityError } from "./errors.js";

const VALID_KINDS: readonly PrincipalKind[] = ["human", "application", "agent"];
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export interface CreateIdentityInput {
  readonly kind?: PrincipalKind;
  readonly tenantId?: string;
  readonly name?: string;
  readonly publicJWK: JWK;
  /** Required when `kind` is "agent" — every Agent must be traceable. */
  readonly createdBy?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

function assertSafeMetadata(metadata: Readonly<Record<string, unknown>>): void {
  const keys = Object.keys(metadata);
  if (keys.length > MAX_METADATA_KEYS) {
    throw new InvalidIdentityError(`metadata exceeds maximum of ${MAX_METADATA_KEYS} keys`);
  }
  for (const key of keys) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new InvalidIdentityError(`metadata key "${key}" is not allowed`);
    }
  }
}

/**
 * Constructs a new Identity. Pure/local — does not persist it (callers pass
 * the result to an `IdentityStore`). Validates shape only; it cannot verify
 * that the caller actually holds the private key matching `publicJWK` —
 * that's established later, at credential-verification time.
 */
export function createIdentity(input: CreateIdentityInput): Identity {
  const kind = input.kind ?? "agent";
  if (!VALID_KINDS.includes(kind)) {
    throw new InvalidIdentityError(`unknown kind "${kind}"`);
  }

  if (input.name !== undefined && input.name.trim().length === 0) {
    throw new InvalidIdentityError("name, if provided, must be a non-empty string");
  }

  if (!input.publicJWK || typeof input.publicJWK !== "object" || !input.publicJWK.kty) {
    throw new InvalidIdentityError("publicJWK must be a valid JWK with a kty");
  }

  if (kind === "agent" && !input.createdBy) {
    throw new InvalidIdentityError('createdBy is required when kind is "agent"');
  }

  if (input.metadata) {
    assertSafeMetadata(input.metadata);
  }

  return {
    id: crypto.randomUUID(),
    kind,
    tenantId: input.tenantId,
    name: input.name,
    publicJWK: input.publicJWK,
    createdAt: new Date().toISOString(),
    createdBy: input.createdBy,
    metadata: input.metadata,
  };
}

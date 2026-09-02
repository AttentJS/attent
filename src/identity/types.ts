import type { JWK } from "jose";

/**
 * A Principal is any entity that can hold authority and be identified: a
 * human, an application, or an agent. `Identity` is the durable record of
 * one — an ID + public key + metadata. It is NOT proof of authority; only a
 * verified `Credential` is — nothing in this module issues authority.
 */
export type PrincipalKind = "human" | "application" | "agent";

/** Resource limit — bounds unbounded-metadata abuse at identity-creation time. */
export const MAX_METADATA_KEYS = 64;

export interface Identity {
  readonly id: string;
  readonly kind: PrincipalKind;
  /**
   * Optional tenant/organization namespace. Not consulted by `authorize()`
   * or any core decision (multi-tenancy is a storage-layer concern) —
   * `IdentityStore`/`RevocationStore`/`AuditSink` implementations use it to
   * scope reads/writes so one tenant's data is never visible to another.
   * Store adapters MUST treat `tenantId` as part of the lookup key, not as
   * an afterthought filter applied post-query.
   */
  readonly tenantId?: string;
  readonly name?: string;
  /** Public JWK corresponding to this Principal's signing key. */
  readonly publicJWK: JWK;
  readonly createdAt: string;
  /**
   * Set only for non-human Principals: the id of the Principal that created
   * this Agent. Every Agent is traceable to a root or delegating Principal.
   */
  readonly createdBy?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/** An Identity known to be non-human, always traceable via `createdBy`. */
export interface Agent extends Identity {
  readonly kind: "agent";
  readonly createdBy: string;
}

export function isAgent(identity: Identity): identity is Agent {
  return identity.kind === "agent" && typeof identity.createdBy === "string";
}

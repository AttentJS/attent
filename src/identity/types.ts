import type { JWK } from "jose";

/**
 * A Principal is any entity that can hold authority and be identified: a
 * human, an application, or an agent. `Identity` is the durable record of
 * one — an ID + public key + metadata. It is NOT proof of authority; only a
 * verified `Credential` is (T7) — nothing in this module issues authority.
 */
export type PrincipalKind = "human" | "application" | "agent";

export interface Identity {
  readonly id: string;
  readonly kind: PrincipalKind;
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

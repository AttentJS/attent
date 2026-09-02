/**
 * A single granted permission, optionally further constrained. Full
 * capability-matching/policy semantics (§6) land in Phase 3 — here it's just
 * the wire shape carried inside a signed hop.
 */
export interface CapabilityGrant {
  readonly action: string;
  readonly resource: string;
  readonly constraints?: Readonly<Record<string, unknown>>;
}

/**
 * Claims carried by one signed hop (§8). Phase 2 only ever issues/verifies a
 * single hop (no `parentHopHash`/chain yet — that's Phase 4) but the field
 * shape is the one the full multi-hop `Credential` will reuse per hop.
 */
export interface HopClaims {
  /** Issuer's Identity id. */
  readonly iss: string;
  /** Subject (holder) Identity id. */
  readonly sub: string;
  /** Resource-namespace pattern(s) this hop may be presented against. */
  readonly aud: string | readonly string[];
  readonly capabilities: readonly CapabilityGrant[];
  /**
   * Unique hop identifier (JWT `jti`). Doubles as the revocation key
   * (`RevocationStore` is keyed by hop id, §13) — added ahead of the plan's
   * "optional jti for replay protection" (§8) because revocation needs a
   * stable per-hop identifier regardless of whether replay protection is
   * enabled; every hop gets one, always.
   */
  readonly jti: string;
  /** Seconds since epoch. */
  readonly iat: number;
  /** Seconds since epoch. */
  readonly exp: number;
  /**
   * Hash (`sha256Base64Url`) of the parent hop's `jws` this hop was
   * delegated from (§7). Absent on a root hop (one issued directly via
   * `issueCredential`, not `delegate`). Binds a hop to the *specific* parent
   * it was issued from, preventing a valid hop from being spliced onto a
   * different, more-privileged parent (T8 chain-splice defense, §23 example 3).
   */
  readonly parentHopHash?: string;
}

/** A verified (or just-issued) single-hop credential. */
export interface Credential {
  /** Compact JWS — the actual bearer token, transportable as-is. */
  readonly jws: string;
  readonly claims: HopClaims;
}

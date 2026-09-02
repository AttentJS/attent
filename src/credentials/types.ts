/**
 * Bearer tokens are valid for reuse (not single-use) for their entire `exp`
 * window — Attent deliberately does not track "already presented" state
 * (that would require a durable, globally-consistent replay cache on every
 * verification path, including offline/air-gapped verifiers). Compromise is
 * mitigated by revocation (`RevocationStore`, keyed by `jti`), not by replay
 * detection. `MAX_TTL_SECONDS` bounds how long any single hop can remain a
 * live bearer token regardless of the caller-requested `ttlSeconds`, so the
 * bearer-replay window has a hard ceiling even if revocation is never
 * exercised. 30 days is a default upper bound, not a recommendation — most
 * deployments should issue much shorter-lived hops.
 */
export const MAX_TTL_SECONDS = 30 * 24 * 60 * 60;

/** Resource limits (defense against unbounded-payload abuse, not business rules). */
export const MAX_CAPABILITIES_PER_HOP = 100;
export const MAX_AUD_ENTRIES = 50;

/**
 * A single granted permission, optionally further constrained. This is
 * just the wire shape carried inside a signed hop — capability-matching/
 * policy semantics live elsewhere.
 */
export interface CapabilityGrant {
  readonly action: string;
  readonly resource: string;
  readonly constraints?: Readonly<Record<string, unknown>>;
}

/**
 * Claims carried by one signed hop. The field shape is the one the full
 * multi-hop `Credential` reuses per hop (`parentHopHash` is unset for a
 * single, non-delegated hop).
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
   * (`RevocationStore` is keyed by hop id) — every hop gets one, always,
   * since revocation needs a stable per-hop identifier regardless of
   * whether replay protection is otherwise in use.
   */
  readonly jti: string;
  /** Seconds since epoch. */
  readonly iat: number;
  /** Seconds since epoch. */
  readonly exp: number;
  /**
   * Hash (`sha256Base64Url`) of the parent hop's `jws` this hop was
   * delegated from. Absent on a root hop (one issued directly via
   * `issueCredential`, not `delegate`). Binds a hop to the *specific* parent
   * it was issued from, preventing a valid hop from being spliced onto a
   * different, more-privileged parent (chain-splice defense).
   */
  readonly parentHopHash?: string;
}

/** A verified (or just-issued) single-hop credential. */
export interface Credential {
  /** Compact JWS — the actual bearer token, transportable as-is. */
  readonly jws: string;
  readonly claims: HopClaims;
}

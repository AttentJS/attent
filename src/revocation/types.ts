export interface RevokeOptions {
  /**
   * Historically "cascade to descendant hops." As of Phase 4, cascade is
   * structural and unconditional for the in-memory model: `authorize()`
   * checks every hop in a presented chain, so revoking one hop already
   * denies every chain built on it or later, regardless of this flag (see
   * `revocation/revoke.ts`). Kept for interface stability and for a future
   * `credentialMeta`-aware store (§11/§13) that might want to proactively
   * mark not-yet-presented descendant hop ids revoked too.
   */
  readonly cascade?: boolean;
}

/**
 * Revocable unit is a hop id (§13) — capabilities within an otherwise-valid
 * hop are not independently revocable. Consulted as a mandatory step of
 * every `authorize()` call (T9); an unreachable/erroring store must be
 * treated as fail-closed by the caller (`authorize()` does this, not this
 * interface — a bare adapter only needs to answer `isRevoked` honestly).
 */
export interface RevocationStore {
  revoke(hopId: string, opts?: RevokeOptions): Promise<void>;
  isRevoked(hopId: string): Promise<boolean>;
}

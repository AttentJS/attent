export interface RevokeOptions {
  /**
   * Historically "cascade to descendant hops." Cascade is now structural
   * and unconditional for the in-memory model: `authorize()`
   * checks every hop in a presented chain, so revoking one hop already
   * denies every chain built on it or later, regardless of this flag (see
   * `revocation/revoke.ts`). Kept for interface stability and for a future
   * `credentialMeta`-aware store that might want to proactively
   * mark not-yet-presented descendant hop ids revoked too.
   */
  readonly cascade?: boolean;
  /** Optional tenant/organization namespace, recorded for adapters that partition storage by tenant. Hop ids (`jti`) are already globally unique, so this is bookkeeping, not an isolation requirement. */
  readonly tenantId?: string;
}

/**
 * Revocable unit is a hop id — capabilities within an otherwise-valid
 * hop are not independently revocable. Consulted as a mandatory step of
 * every `authorize()` call; an unreachable/erroring store must be
 * treated as fail-closed by the caller (`authorize()` does this, not this
 * interface — a bare adapter only needs to answer `isRevoked` honestly).
 */
export interface RevocationStore {
  revoke(hopId: string, opts?: RevokeOptions): Promise<void>;
  isRevoked(hopId: string): Promise<boolean>;
}

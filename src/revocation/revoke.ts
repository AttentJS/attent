import type { CredentialChain } from "../delegation/types.js";
import type { RevocationStore, RevokeOptions } from "./types.js";

export interface RevokeInput {
  readonly credential: CredentialChain;
  readonly store: RevocationStore;
  readonly opts?: RevokeOptions;
}

/**
 * Revokes `credential`'s leaf hop (§13). Cascade to everything delegated
 * from that hop needs no separate bookkeeping in the in-memory model: every
 * descendant chain necessarily contains this hop somewhere in its own
 * `hops` array (a chain is the full root-to-leaf lineage, §7), and
 * `authorize()` checks revocation of every hop in a presented chain — so
 * revoking hop *n* here transparently denies every chain built on it or
 * later the moment it's presented, without this function needing to
 * enumerate descendants itself. To revoke a specific ancestor hop (not the
 * leaf), pass a `CredentialChain` truncated to that hop.
 */
export async function revoke(input: RevokeInput): Promise<void> {
  const leaf = input.credential.hops[input.credential.hops.length - 1]!;
  await input.store.revoke(leaf.claims.jti, input.opts);
}

import type { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import { verifyChain, type Clock, type TrustedKeyStore, type VerifiedCredentialChain } from "attent";
import type { ResolveCredential, ResolveCredentialContext } from "./types.js";

/**
 * The documented (but not MCP-standard — the protocol has no built-in
 * credential-carrying field) convention this package's examples and
 * `attentCredentialMeta` use: a `tools/call` request's `_meta.attentCredential`
 * carries the presented chain as an ordered array of compact JWS strings,
 * root hop first.
 */
export interface AttentCredentialMeta {
  readonly attentCredential?: readonly string[];
}

/** Reads the `_meta.attentCredential` convention off a `tools/call` request, if present. */
export function attentCredentialFromMeta(request: CallToolRequest): readonly string[] | undefined {
  const meta = request.params._meta as AttentCredentialMeta | undefined;
  const hops = meta?.attentCredential;
  return hops && hops.length > 0 ? hops : undefined;
}

export interface ResolveVerifiedCredentialOptions<Extra> {
  readonly trustedKeys: TrustedKeyStore;
  readonly clock?: Clock;
  readonly maxDelegationDepth?: number;
  /**
   * Extracts the raw, unverified JWS hop strings from the request/extra —
   * defaults to `attentCredentialFromMeta` (the `_meta.attentCredential`
   * convention). Override for a custom transport-level credential channel.
   */
  readonly extractHops?: (ctx: ResolveCredentialContext<Extra>) => readonly string[] | undefined;
}

/**
 * The recommended way to implement `WithAttentOptions.resolveCredential`:
 * extracts raw JWS hop strings from the request and runs them through
 * `verifyChain` before ever returning them to `withAttent`. Any verification
 * failure (malformed, forged, expired, over-depth, narrowing-violated,
 * chain-spliced) is treated identically to "no credential presented" —
 * `withAttent` denies without distinguishing "absent" from "invalid," so a
 * forged credential gets no more information than a missing one.
 */
export function resolveVerifiedCredential<Extra>(
  options: ResolveVerifiedCredentialOptions<Extra>
): ResolveCredential<Extra> {
  const extractHops =
    options.extractHops ??
    ((ctx: ResolveCredentialContext<Extra>): readonly string[] | undefined => attentCredentialFromMeta(ctx.request));

  return async (ctx: ResolveCredentialContext<Extra>): Promise<VerifiedCredentialChain | undefined> => {
    const hops = extractHops(ctx);
    if (!hops || hops.length === 0) {
      return undefined;
    }
    try {
      return await verifyChain({
        hops,
        trustedKeys: options.trustedKeys,
        clock: options.clock,
        maxDelegationDepth: options.maxDelegationDepth,
      });
    } catch {
      return undefined;
    }
  };
}

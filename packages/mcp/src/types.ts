import type { CallToolRequest, CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { AuditEmitter, Clock, CredentialChain, PolicyEvaluator, RevocationStore } from "attent";

/**
 * Everything `resolveCredential` needs to pull an Attent credential out of a
 * single `tools/call` request — deliberately not prescriptive about *where*
 * the credential travels (MCP itself doesn't standardize a convention, §14),
 * so the app decides: `_meta` field, a custom header threaded through
 * `extra`, a side channel keyed by session id, etc.
 */
export interface ResolveCredentialContext<Extra> {
  readonly request: CallToolRequest;
  readonly extra: Extra;
}

export type ResolveCredential<Extra> = (
  ctx: ResolveCredentialContext<Extra>
) => CredentialChain | undefined | Promise<CredentialChain | undefined>;

/** The already-wrapped tool handler `withAttent` produces, matching the SDK's `setRequestHandler` callback shape. */
export type CallToolHandler<Extra> = (request: CallToolRequest, extra: Extra) => CallToolResult | Promise<CallToolResult>;

export interface WithAttentOptions<Extra = unknown> {
  /** Locates (and, if not already verified, resolves) the caller's credential chain for this request. */
  readonly resolveCredential: ResolveCredential<Extra>;
  /** Maps an MCP tool name to an Attent action string, e.g. `"refunds:create"` (§26 grammar). */
  readonly actionForTool: (toolName: string) => string;
  /** Maps a tool call's arguments to the Attent resource string the action targets. */
  readonly resourceForArgs: (toolName: string, args: Readonly<Record<string, unknown>>) => string;
  /** Optional — feeds `authorize()`'s `context` for policy predicates (e.g. amount ceilings). */
  readonly contextForArgs?: (toolName: string, args: Readonly<Record<string, unknown>>) => Readonly<Record<string, unknown>>;
  readonly revocationStore: RevocationStore;
  readonly policyEvaluator?: PolicyEvaluator;
  readonly clock?: Clock;
  /** Optional — every allow/deny is emitted as an `authorization` audit event when set (T5/T6 evidence trail). */
  readonly emitter?: AuditEmitter;
  readonly requestId?: (request: CallToolRequest) => string | undefined;
}

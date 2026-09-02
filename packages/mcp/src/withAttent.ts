import type { CallToolRequest, CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { auditedAuthorize } from "attent";
import type { CallToolHandler, WithAttentOptions } from "./types.js";

/**
 * `attent:no_credential` is `@attent/mcp`'s own deny reason, layered on top
 * of core's fixed `DenyReason` enum (§26) — core never sees "there was no
 * credential at all," only ever a resolved `CredentialChain` or nothing;
 * distinguishing "missing" from a core-produced deny keeps the mapping
 * honest instead of inventing a fake capability/audience/expiry failure.
 */
const NO_CREDENTIAL_REASON = "attent:no_credential";

function toolErrorResult(reason: string): CallToolResult {
  return {
    isError: true,
    content: [{ type: "text", text: `attent: denied (${reason})` }],
  };
}

/**
 * MCP middleware (§14) — wraps a `tools/call` handler so it only runs after
 * an Attent `authorize()` decision allows it (T5: confused-deputy defense —
 * the wrapped handler must never be reachable on a `deny`, and must never
 * run *before* the decision is known). On deny (including "no credential
 * resolved") this returns an MCP tool error result rather than throwing, so
 * a misbehaving/unauthorized call can't crash the server (§14) — and, if an
 * `emitter` is configured, the audit event is recorded regardless of
 * outcome, so a compliance/debugging consumer sees every attempt, not just
 * the allowed ones (T6).
 */
export function withAttent<Extra = unknown>(
  options: WithAttentOptions<Extra>,
  handler: CallToolHandler<Extra>
): CallToolHandler<Extra> {
  return async (request: CallToolRequest, extra: Extra): Promise<CallToolResult> => {
    const toolName = request.params.name;
    const args = request.params.arguments ?? {};

    const credential = await options.resolveCredential({ request, extra });
    if (!credential) {
      return toolErrorResult(NO_CREDENTIAL_REASON);
    }

    const action = options.actionForTool(toolName);
    const resource = options.resourceForArgs(toolName, args);
    const context = options.contextForArgs?.(toolName, args);

    const decision = await auditedAuthorize(
      { credential, action, resource, context },
      {
        revocationStore: options.revocationStore,
        policyEvaluator: options.policyEvaluator,
        clock: options.clock,
        emitter: options.emitter,
        requestId: options.requestId?.(request),
      }
    );

    if (decision.outcome === "deny") {
      return toolErrorResult(decision.reason);
    }

    return handler(request, extra);
  };
}

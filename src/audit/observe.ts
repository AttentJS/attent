import { authorize } from "../authorization/authorize.js";
import type { AuthorizeOptions } from "../authorization/authorize.js";
import type { AuthorizeInput, Decision } from "../authorization/types.js";
import { delegate } from "../delegation/delegate.js";
import type { DelegateInput } from "../delegation/delegate.js";
import type { CredentialChain } from "../delegation/types.js";
import { revoke } from "../revocation/revoke.js";
import type { RevokeInput } from "../revocation/revoke.js";
import { issueCredential } from "../credentials/credentials.js";
import type { IssueCredentialInput } from "../credentials/credentials.js";
import type { Credential } from "../credentials/types.js";
import type { AuditEmitter } from "./emitter.js";
import type { AuditDelegationHop, AuditPrincipalRef } from "./types.js";

/**
 * Shared audit-observation options, layered on top of each underlying
 * call's own options — this is the whole point of Phase 5's acceptance
 * criterion (§21): every one of `authorize`/`delegate`/`revoke`/
 * `issueCredential` is called completely unmodified here, wrapped from the
 * outside. If `emitter` is omitted, these functions behave identically to
 * calling the underlying function directly (audit is opt-in, additive,
 * never load-bearing for the security decision itself).
 */
export interface AuditOptions {
  readonly emitter?: AuditEmitter;
  readonly requestId?: string;
  /** Optional tenant/organization namespace stamped onto the emitted event, for a durable multi-tenant `AuditSink` to scope by (§11). */
  readonly tenantId?: string;
  /** Off by default (§12) — `context` often carries request-specific business data. */
  readonly includeContext?: boolean;
  /** Applied to `context` before recording, only when `includeContext` is set. */
  readonly redactContext?: (context: Readonly<Record<string, unknown>>) => Readonly<Record<string, unknown>>;
  /** Off by default (§12) — Identity names may be PII. */
  readonly includeNames?: boolean;
}

function toHops(chain: CredentialChain): readonly AuditDelegationHop[] {
  return chain.hops.map((hop) => ({ issuer: hop.claims.iss, subject: hop.claims.sub, hopId: hop.claims.jti }));
}

function ref(id: string, name: string | undefined, includeNames: boolean | undefined): AuditPrincipalRef {
  return includeNames && name !== undefined ? { id, name } : { id };
}

export async function auditedAuthorize(
  input: AuthorizeInput,
  options: AuthorizeOptions & AuditOptions
): Promise<Decision> {
  const decision = await authorize(input, options);

  if (options.emitter) {
    const hops = toHops(input.credential);
    const root = hops[0];
    const leaf = hops[hops.length - 1];
    const rawContext = input.context;
    await options.emitter.emit({
      tenantId: options.tenantId,
      type: "authorization",
      principal: root ? { id: root.issuer } : { id: leaf?.subject ?? "unknown" },
      agent: leaf && root && leaf.subject !== root.issuer ? { id: leaf.subject } : undefined,
      delegationChain: hops,
      action: input.action,
      resource: input.resource,
      decision:
        decision.outcome === "allow"
          ? { outcome: "allow", reason: "matched_capability" }
          : { outcome: "deny", reason: decision.reason },
      policy: options.policyEvaluator ? { evaluatorName: options.policyEvaluator.name } : undefined,
      requestId: options.requestId,
      ...(options.includeContext && rawContext
        ? { context: options.redactContext ? options.redactContext(rawContext) : rawContext }
        : {}),
    });
  }

  return decision;
}

export async function auditedDelegate(input: DelegateInput, options: AuditOptions = {}): Promise<CredentialChain> {
  const chain = await delegate(input);

  if (options.emitter) {
    const hops = toHops(chain);
    const root = hops[0]!;
    const leaf = hops[hops.length - 1]!;
    await options.emitter.emit({
      tenantId: options.tenantId,
      type: "delegation",
      principal: ref(root.issuer, undefined, options.includeNames),
      agent:
        leaf.subject !== root.issuer
          ? ref(leaf.subject, options.includeNames ? input.to.name : undefined, options.includeNames)
          : undefined,
      delegationChain: hops,
      requestId: options.requestId,
    });
  }

  return chain;
}

export async function auditedRevoke(input: RevokeInput, options: AuditOptions = {}): Promise<void> {
  await revoke(input);

  if (options.emitter) {
    const hops = toHops(input.credential);
    const root = hops[0];
    const leaf = hops[hops.length - 1];
    await options.emitter.emit({
      tenantId: options.tenantId,
      type: "revocation",
      principal: root ? { id: root.issuer } : { id: leaf?.subject ?? "unknown" },
      agent: leaf && root && leaf.subject !== root.issuer ? { id: leaf.subject } : undefined,
      delegationChain: hops,
      requestId: options.requestId,
    });
  }
}

export async function auditedIssueCredential(
  input: IssueCredentialInput,
  options: AuditOptions = {}
): Promise<Credential> {
  const credential = await issueCredential(input);

  if (options.emitter) {
    await options.emitter.emit({
      tenantId: options.tenantId,
      type: "credential_issued",
      principal: ref(input.issuer.id, options.includeNames ? input.issuer.name : undefined, options.includeNames),
      agent:
        input.subject.id !== input.issuer.id
          ? ref(input.subject.id, options.includeNames ? input.subject.name : undefined, options.includeNames)
          : undefined,
      delegationChain: [{ issuer: input.issuer.id, subject: input.subject.id, hopId: credential.claims.jti }],
      requestId: options.requestId,
    });
  }

  return credential;
}

/**
 * Structured, replayable record of a Decision/Delegation/Revocation/Issuance.
 * Deliberately excludes anything secret or reconstructable-as-a-live-
 * capability by default: no private key material (audit never touches
 * `crypto/` internals), no raw credential JWS strings (only hop ids —
 * `jti`), no `context` unless explicitly opted in, no Identity `name`s
 * unless explicitly opted in (names may be PII).
 */
export type AuditEventType = "authorization" | "delegation" | "revocation" | "credential_issued";

export interface AuditDelegationHop {
  readonly issuer: string;
  readonly subject: string;
  readonly hopId: string;
}

export interface AuditPrincipalRef {
  readonly id: string;
  readonly name?: string;
}

export interface AuditDecision {
  readonly outcome: "allow" | "deny";
  readonly reason: string;
}

export interface AuditPolicyRef {
  readonly evaluatorName: string;
  readonly matchedRuleId?: string;
}

export interface AuditEvent {
  readonly id: string;
  /** ISO 8601, from the injected `Clock` — never raw `Date.now()` (determinism). */
  readonly timestamp: string;
  /** Optional tenant/organization namespace (mirrors `Identity.tenantId`) — a durable `AuditSink` MUST scope storage/queries by this, not just filter post-query. */
  readonly tenantId?: string;
  readonly type: AuditEventType;
  readonly principal: AuditPrincipalRef;
  /** The acting agent, if different from `principal`. */
  readonly agent?: AuditPrincipalRef;
  readonly delegationChain: readonly AuditDelegationHop[];
  readonly action?: string;
  readonly resource?: string;
  readonly decision?: AuditDecision;
  readonly policy?: AuditPolicyRef;
  readonly requestId?: string;
  /** Present only when the caller opts in via `includeContext`. */
  readonly context?: Readonly<Record<string, unknown>>;
  /** Present only when hash-chaining is enabled. */
  readonly prevEventHash?: string;
}

export interface AuditEventFilter {
  readonly type?: AuditEventType;
  readonly principalId?: string;
  readonly requestId?: string;
  readonly tenantId?: string;
}

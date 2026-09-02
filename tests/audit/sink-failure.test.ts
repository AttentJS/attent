import { describe, it, expect, vi } from "vitest";
import { createAuditEmitter } from "../../src/audit/emitter.js";
import type { AuditSink } from "../../src/audit/sink.js";
import type { AuditEvent } from "../../src/audit/types.js";
import { auditedAuthorize } from "../../src/audit/observe.js";
import { memoryRevocationStore } from "../../src/revocation/memory.js";
import { generateKeyProvider, memoryTrustedKeyStore } from "../../src/crypto/keys.js";
import { createIdentity } from "../../src/identity/identity.js";
import { issueCredential } from "../../src/credentials/credentials.js";
import { rootChain } from "../../src/delegation/types.js";

function baseInput(): Omit<AuditEvent, "id" | "timestamp" | "prevEventHash"> {
  return { type: "authorization", principal: { id: "p1" }, delegationChain: [] };
}

function throwingSink(): AuditSink {
  return {
    append: () => Promise.reject(new Error("disk full")),
    query: () => Promise.resolve([]),
  };
}

describe("audit sink failure semantics", () => {
  it("emit() does not reject when the sink's append() throws — fail-visible, not fail-loud", async () => {
    const emitter = createAuditEmitter({ sink: throwingSink(), onSinkError: () => {} });
    await expect(emitter.emit(baseInput())).resolves.toMatchObject({ type: "authorization" });
  });

  it("a failing sink invokes onSinkError with the error and the event", async () => {
    const onSinkError = vi.fn<(error: unknown, event: AuditEvent) => void>();
    const emitter = createAuditEmitter({ sink: throwingSink(), onSinkError });
    const event = await emitter.emit(baseInput());
    expect(onSinkError).toHaveBeenCalledOnce();
    const [error, erroredEvent] = onSinkError.mock.calls[0]!;
    expect((error as Error).message).toBe("disk full");
    expect(erroredEvent.id).toBe(event.id);
  });

  it("defaults to logging via console.error when onSinkError is not provided", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const emitter = createAuditEmitter({ sink: throwingSink() });
    await emitter.emit(baseInput());
    expect(spy).toHaveBeenCalledOnce();
    spy.mockRestore();
  });

  it("auditedAuthorize still returns the real Decision when the configured sink's append() fails", async () => {
    const issuerKeys = await generateKeyProvider();
    const issuer = createIdentity({ kind: "application", name: "acme-app", publicJWK: await issuerKeys.getPublicJWK() });
    const subjectKeys = await generateKeyProvider();
    const subject = createIdentity({
      kind: "agent",
      name: "support-agent",
      createdBy: issuer.id,
      publicJWK: await subjectKeys.getPublicJWK(),
    });
    const trustedKeys = memoryTrustedKeyStore();
    await trustedKeys.addKey(issuer.id, issuerKeys.kid, await issuerKeys.getPublicJWK());
    void trustedKeys;

    const credential = await issueCredential({
      issuer,
      subject,
      keyProvider: issuerKeys,
      capabilities: [{ action: "orders:read", resource: "order:*" }],
      aud: "order:*",
      ttlSeconds: 900,
    });

    const emitter = createAuditEmitter({ sink: throwingSink(), onSinkError: () => {} });

    const decision = await auditedAuthorize(
      { credential: rootChain(credential), action: "orders:read", resource: "order:18472" },
      { revocationStore: memoryRevocationStore(), emitter }
    );

    expect(decision.outcome).toBe("allow");
  });
});

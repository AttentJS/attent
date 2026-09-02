# attent

Authorization infrastructure for autonomous software — identity, delegation, and authorization for AI agents and the tools they call, built around a credential model that verifies before it trusts.

## Install

```
npm install attent
```

For MCP (Model Context Protocol) tool servers:

```
npm install @attent/mcp
```

For durable, restart-surviving storage:

```
npm install @attent/storage-sqlite
```

Node ESM and CommonJS are both supported (`import`/`require`).

## Core concepts

- **Identity** — a durable record (id, public key, kind: human/application/agent) for anything that can hold authority. `Identity` is *not* proof of authority; only a verified credential is. `createIdentity()` / `IdentityStore`.
- **Credential** — a signed, single-hop grant (`issueCredential`): who issued it, who holds it, what capabilities, over what resource audience, for how long. The `jws` string is the bearer token; `verifyCredential`/`verifyChain` are how you check it's real.
- **Delegation** — `delegate()` appends a new, narrower hop to an existing chain. A delegated hop can never grant more than its parent held (reject, not silently clip) — the chain narrows monotonically from root to leaf.
- **Authorization** — `authorize()` evaluates an *already-verified* chain against a requested action/resource/context: revocation (every hop), expiry, audience, capability match, then policy. It never re-runs cryptographic verification itself — that's `verifyChain`'s job, always.
- **Revocation** — `revoke()` marks a hop's `jti` revoked. Because every descendant chain necessarily contains that hop, revoking one hop transparently denies every chain built on it or later, the next time it's presented.
- **Audit** — `auditedIssueCredential`/`auditedDelegate`/`auditedAuthorize`/`auditedRevoke` wrap the corresponding function unmodified and additionally emit a structured, redaction-aware event through an `AuditEmitter`. Audit is opt-in and never load-bearing for the underlying decision.

## Quickstart

```ts
import {
  createIdentity,
  generateKeyProvider,
  memoryTrustedKeyStore,
  memoryRevocationStore,
  issueCredential,
  rootChain,
  authorize,
} from "attent";

const trustedKeys = memoryTrustedKeyStore();
const revocationStore = memoryRevocationStore();

const rootKeys = await generateKeyProvider();
const root = createIdentity({ kind: "application", name: "acme-app", publicJWK: await rootKeys.getPublicJWK() });
await trustedKeys.addKey(root.id, rootKeys.kid, await rootKeys.getPublicJWK());

const agentKeys = await generateKeyProvider();
const agent = createIdentity({ kind: "agent", name: "refund-agent", createdBy: root.id, publicJWK: await agentKeys.getPublicJWK() });

const credential = await issueCredential({
  issuer: root,
  subject: agent,
  keyProvider: rootKeys,
  capabilities: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } }],
  aud: "order:*",
  ttlSeconds: 900,
});

const decision = await authorize(
  { credential: rootChain(credential), action: "refunds:create", resource: "order:18472", context: { amount: 15 } },
  { revocationStore }
);
// decision.outcome === "allow"
```

See `examples/` for runnable end-to-end scripts: `basic`, `delegation`, `authorization` (custom `PolicyEvaluator`), `revocation` (including cascade), `e2e-support-agent` (the full lifecycle narrative), `mcp` (in-process confused-deputy demo), `mcp-stdio` (a real two-process MCP stdio server), and `storage-sqlite` (durability across a process restart). Run any of them with `npm run example:<name>`.

## Security model

- **Verification and authorization are separate, and both are mandatory.** `authorize()` only ever evaluates an already-`verifyChain`-verified `CredentialChain` — it never re-checks signatures itself. `@attent/mcp`'s `withAttent` enforces this at the type level: `resolveCredential` must return a `VerifiedCredentialChain`, a type only `verifyChain()` can produce, so an MCP integration cannot accidentally authorize an unverified, caller-controlled object. See `packages/mcp/README.md`.
- **Bearer semantics, not replay prevention.** A credential's `jws` is a bearer token, valid for reuse for its entire `exp` window — Attent does not track "already presented" state. Compromise is mitigated by revoking the hop's `jti` (`RevocationStore`), not by single-use replay detection. `MAX_TTL_SECONDS` (30 days by default) puts a hard ceiling on how long any hop can remain a live bearer token regardless of the requested `ttlSeconds`, so the exposure window has a bound even if revocation is never exercised. Issue short-lived credentials for anything sensitive.
- **Fail-closed revocation, fail-visible audit.** If a `RevocationStore` errors mid-check, `authorize()` treats that hop as revoked (never fails open). If an `AuditSink` fails to persist an event, the underlying decision the caller already computed is still returned — audit failures are reported via `onSinkError` (default: `console.error`), not silently swallowed and not allowed to discard an already-correct authorization result.
- **Reject, not clip.** `delegate()` throws `ExceedsAvailableAuthorityError` if the requested grant isn't fully covered by the parent's effective authority — it never silently narrows a request to "whatever was actually available."
- **Resource limits.** Capability/audience list lengths, action/resource grammar segment counts and lengths, and identity metadata key counts are all bounded (see `src/credentials/types.ts`, `src/authorization/grammar.ts`, `src/identity/types.ts`) — defense against unbounded-payload abuse, not business rules.
- **Multi-tenancy is a storage-layer concern.** `Identity.tenantId` and `AuditEvent.tenantId`/`AuditEventFilter.tenantId` let a durable store adapter scope reads/writes per tenant; `authorize()` itself never consults tenant identity.

## Durable storage

The in-memory `IdentityStore`/`RevocationStore`/`AuditSink` (`memoryIdentityStore`, `memoryRevocationStore`, `memoryAuditSink`) are the defaults and lose all state on process restart. `@attent/storage-sqlite` provides drop-in SQLite-backed replacements satisfying the exact same interfaces, verified against the same shared adapter-conformance suite the in-memory stores run:

```ts
import { openAttentDatabase, sqliteIdentityStore, sqliteRevocationStore, sqliteAuditSink } from "@attent/storage-sqlite";

const db = openAttentDatabase("./attent.db"); // WAL mode, schema applied automatically
const identityStore = sqliteIdentityStore(db);
const revocationStore = sqliteRevocationStore(db);
const auditSink = sqliteAuditSink(db);
```

See `examples/storage-sqlite/index.ts`.

## MCP integration

See `packages/mcp/README.md` for the full guide: mandatory-verification wiring via `resolveVerifiedCredential`, the `_meta.attentCredential` transport convention, and a complete real-stdio-server example (`examples/mcp-stdio/`).

## Operational notes

- **CI** builds and typechecks both the root package and every `packages/*` workspace, runs the full test suite, and runs `npm audit --audit-level=high` as a blocking gate (`.github/workflows/ci.yml`) — a high/critical vulnerability fails the build, it isn't merely reported. `npm outdated` also runs, informationally, so staleness stays visible without blocking.
- **Dual ESM/CJS.** Both `attent` and `@attent/mcp`/`@attent/storage-sqlite` ship `dist/index.js` (ESM) and `dist/index.cjs` (CJS) with matching `.d.ts`/`.d.cts`, and `package.json#exports` declares both `import` and `require` conditions — `require("attent")` works, not just `import`.
- **Workspaces.** `packages/mcp` and `packages/storage-sqlite` are npm workspaces; `npm run build:all`/`npm run typecheck`/`npm run lint` all cover the root package and every workspace.

## Status

Early stage. The API surface is still settling; expect breaking changes before 1.0.

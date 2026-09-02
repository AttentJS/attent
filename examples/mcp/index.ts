/**
 * MCP example (§16/§21 Phase 8) — a `refund` tool exposed over two MCP
 * servers, wired to real MCP `Server`/`Client` pairs via `InMemoryTransport`
 * (no stdio process needed for a runnable demo, per §16's "plain Node
 * script" style). Both servers share the same underlying refund logic; the
 * only difference is *whose* credential authorizes the call, which is
 * exactly the confused-deputy gap from §4 T5:
 *
 *  - `vulnerable` handler uses the *tool's own* ambient service credential
 *    to authorize itself, ignoring whatever the caller presented — a rogue
 *    caller with no credential at all still gets the refund executed.
 *  - `fixed` handler is wrapped with `withAttent`, which resolves and
 *    authorizes the *caller's* credential before the handler ever runs — a
 *    rogue caller is denied, and the handler is provably never invoked.
 *
 * Run:
 *
 *   npm run example:mcp
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { CallToolRequest, CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { withAttent } from "@attent/mcp";
import {
  authorize,
  createAuditEmitter,
  createIdentity,
  generateKeyProvider,
  issueCredential,
  memoryRevocationStore,
  memoryTrustedKeyStore,
  rootChain,
  verifyChain,
  type AuditEvent,
  type CredentialChain,
  type Identity,
  type KeyProvider,
  type TrustedKeyStore,
} from "attent";

interface Actor {
  readonly identity: Identity;
  readonly keys: KeyProvider;
}

async function makeActor(
  trustedKeys: TrustedKeyStore,
  input: { kind: "human" | "application" | "agent"; name: string; createdBy?: string }
): Promise<Actor> {
  const keys = await generateKeyProvider();
  const publicJWK = await keys.getPublicJWK();
  const identity = createIdentity({ kind: input.kind, name: input.name, createdBy: input.createdBy, publicJWK });
  await trustedKeys.addKey(identity.id, keys.kid, publicJWK);
  return { identity, keys };
}

async function main(): Promise<void> {
  const trustedKeys = memoryTrustedKeyStore();
  const revocationStore = memoryRevocationStore();

  const root = await makeActor(trustedKeys, { kind: "application", name: "acme-app" });
  const refundService = await makeActor(trustedKeys, {
    kind: "agent",
    name: "refund-service",
    createdBy: root.identity.id,
  });
  const trustedAgent = await makeActor(trustedKeys, {
    kind: "agent",
    name: "trusted-support-agent",
    createdBy: root.identity.id,
  });

  // The tool's own ambient authority — broad, because it's the service
  // itself, not a per-caller grant. This is exactly the credential a
  // confused-deputy bug reaches for instead of checking the caller (T5).
  const serviceCredential = rootChain(
    await issueCredential({
      issuer: root.identity,
      subject: refundService.identity,
      keyProvider: root.keys,
      capabilities: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 10_000 } }],
      aud: "order:*",
      ttlSeconds: 3600,
    })
  );

  // A narrow, caller-specific credential legitimately delegated to one agent
  // for one order — what the *caller* actually holds.
  const trustedCredential = rootChain(
    await issueCredential({
      issuer: root.identity,
      subject: trustedAgent.identity,
      keyProvider: root.keys,
      capabilities: [{ action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } }],
      aud: "order:18472",
      ttlSeconds: 900,
    })
  );

  const emitter = createAuditEmitter();
  const auditLog: AuditEvent[] = [];
  emitter.onAuditEvent((event) => auditLog.push(event));

  function serializeChain(chain: CredentialChain): readonly string[] {
    return chain.hops.map((hop) => hop.jws);
  }

  function performRefund(orderId: string, amount: number): CallToolResult {
    return { content: [{ type: "text", text: `refunded $${amount} on ${orderId}` }] };
  }

  // --- Vulnerable server: authorizes using its OWN ambient credential, ---
  // --- never the caller's. Confused-deputy pattern (T5).               ---
  const vulnerableServer = new Server({ name: "refund-tool-vulnerable", version: "0.0.1" }, { capabilities: { tools: {} } });
  vulnerableServer.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [{ name: "refund", inputSchema: { type: "object", properties: {} } }],
  }));
  vulnerableServer.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
    const args = request.params.arguments ?? {};
    const orderId = String(args.orderId);
    const amount = Number(args.amount);
    // BUG: ignores whatever credential the caller presented in `_meta` and
    // authorizes using the tool's own ambient service credential instead.
    const decision = await authorize(
      { credential: serviceCredential, action: "refunds:create", resource: `order:${orderId}`, context: { amount } },
      { revocationStore }
    );
    if (decision.outcome === "deny") {
      return { isError: true, content: [{ type: "text", text: `denied (${decision.reason})` }] };
    }
    return performRefund(orderId, amount);
  });

  // --- Fixed server: withAttent resolves + authorizes the CALLER's own ---
  // --- credential before the handler is ever reachable.                 ---
  const fixedServer = new Server({ name: "refund-tool-fixed", version: "0.0.1" }, { capabilities: { tools: {} } });
  fixedServer.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [{ name: "refund", inputSchema: { type: "object", properties: {} } }],
  }));
  fixedServer.setRequestHandler(
    CallToolRequestSchema,
    withAttent(
      {
        resolveCredential: async ({ request }) => {
          const meta = request.params._meta as { attentCredential?: readonly string[] } | undefined;
          const hops = meta?.attentCredential;
          if (!hops || hops.length === 0) return undefined;
          try {
            return await verifyChain({ hops, trustedKeys });
          } catch {
            return undefined; // malformed/forged/expired -> treated as no credential, never trusted (T7/T8).
          }
        },
        actionForTool: () => "refunds:create",
        resourceForArgs: (_tool, args) => `order:${String(args.orderId)}`,
        contextForArgs: (_tool, args) => ({ amount: Number(args.amount) }),
        revocationStore,
        emitter,
      },
      (request: CallToolRequest) => {
        const args = request.params.arguments ?? {};
        return performRefund(String(args.orderId), Number(args.amount));
      }
    )
  );

  async function connectedClient(server: Server): Promise<Client> {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "demo-client", version: "0.0.1" });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    return client;
  }

  async function callRefund(client: Client, credential?: CredentialChain, amount = 15): Promise<CallToolResult> {
    return client.callTool({
      name: "refund",
      arguments: { orderId: "18472", amount },
      _meta: credential ? { attentCredential: serializeChain(credential) } : undefined,
    }) as Promise<CallToolResult>;
  }

  const vulnerableClient = await connectedClient(vulnerableServer);
  const fixedClient = await connectedClient(fixedServer);

  console.log("--- vulnerable server (checks its own ambient credential, not the caller's) ---");
  console.log("rogue caller, NO credential presented:", await callRefund(vulnerableClient));
  console.log("trusted caller, valid credential presented:", await callRefund(vulnerableClient, trustedCredential));

  console.log("\n--- fixed server (withAttent authorizes the caller's own credential) ---");
  console.log("rogue caller, NO credential presented:", await callRefund(fixedClient));
  console.log("trusted caller, valid credential presented:", await callRefund(fixedClient, trustedCredential));
  console.log(
    "trusted caller, amount exceeds delegated $20 ceiling:",
    await callRefund(fixedClient, trustedCredential, 50)
  );

  console.log("\n--- audit trail from the fixed server (both attempts recorded, T6) ---");
  for (const event of auditLog) {
    console.log(event.type, event.decision);
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});

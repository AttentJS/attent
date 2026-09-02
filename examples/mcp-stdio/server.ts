/**
 * Real MCP stdio server (§14 secure reference adapter) — unlike
 * examples/mcp/index.ts's `InMemoryTransport` demo, this process actually
 * speaks the MCP stdio protocol over its own stdin/stdout, the way a real
 * MCP server ships. Spawned as a child process by examples/mcp-stdio/index.ts
 * via `StdioClientTransport`.
 *
 * Trusted issuer key material is read from the file path in
 * `ATTENT_TRUSTED_KEYS_FILE` (written by the client before spawning) — this
 * process never sees any private key, only the public JWKs it needs to
 * verify presented credentials.
 */
import { readFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { CallToolRequest, CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { resolveVerifiedCredential, withAttent } from "@attent/mcp";
import { memoryRevocationStore, memoryTrustedKeyStore, type TrustedKeyStore } from "attent";
import type { JWK } from "jose";

interface TrustedKeyFileEntry {
  readonly issuerId: string;
  readonly kid: string;
  readonly jwk: JWK;
}

async function loadTrustedKeys(path: string): Promise<TrustedKeyStore> {
  const entries = JSON.parse(readFileSync(path, "utf8")) as readonly TrustedKeyFileEntry[];
  const store = memoryTrustedKeyStore();
  for (const entry of entries) {
    await store.addKey(entry.issuerId, entry.kid, entry.jwk);
  }
  return store;
}

async function main(): Promise<void> {
  const keysFile = process.env.ATTENT_TRUSTED_KEYS_FILE;
  if (!keysFile) {
    throw new Error("ATTENT_TRUSTED_KEYS_FILE env var is required");
  }
  const trustedKeys = await loadTrustedKeys(keysFile);
  const revocationStore = memoryRevocationStore();

  const server = new Server({ name: "refund-tool-stdio", version: "0.0.1" }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [{ name: "refund", inputSchema: { type: "object", properties: {} } }],
  }));

  server.setRequestHandler(
    CallToolRequestSchema,
    withAttent(
      {
        // The recommended, mandatory-verification pattern (§14): hops are
        // extracted from `_meta.attentCredential` and run through
        // `verifyChain` before `withAttent` ever sees them.
        resolveCredential: resolveVerifiedCredential({ trustedKeys }),
        actionForTool: () => "refunds:create",
        resourceForArgs: (_tool, args) => `order:${String(args.orderId)}`,
        contextForArgs: (_tool, args) => ({ amount: Number(args.amount) }),
        revocationStore,
      },
      (request: CallToolRequest): CallToolResult => {
        const args = request.params.arguments ?? {};
        return { content: [{ type: "text", text: `refunded $${String(args.amount)} on ${String(args.orderId)}` }] };
      }
    )
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});

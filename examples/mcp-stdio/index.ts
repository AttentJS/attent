/**
 * Real MCP stdio client/server demo (§14) — spawns examples/mcp-stdio/server.ts
 * as an actual child process and talks to it over real stdin/stdout via
 * `StdioClientTransport`, unlike examples/mcp/index.ts's in-process
 * `InMemoryTransport` demo. This is the pattern to copy for a production
 * MCP server: `withAttent` + `resolveVerifiedCredential` wired to a real
 * `StdioServerTransport`.
 *
 * Run:
 *
 *   npm run example:mcp-stdio
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  createIdentity,
  generateKeyProvider,
  issueCredential,
  rootChain,
  type CredentialChain,
  type Identity,
  type KeyProvider,
} from "attent";

interface Actor {
  readonly identity: Identity;
  readonly keys: KeyProvider;
}

async function makeActor(input: {
  kind: "human" | "application" | "agent";
  name: string;
  createdBy?: string;
}): Promise<Actor> {
  const keys = await generateKeyProvider();
  const publicJWK = await keys.getPublicJWK();
  const identity = createIdentity({ kind: input.kind, name: input.name, createdBy: input.createdBy, publicJWK });
  return { identity, keys };
}

function serializeChain(chain: CredentialChain): readonly string[] {
  return chain.hops.map((hop) => hop.jws);
}

async function main(): Promise<void> {
  const root = await makeActor({ kind: "application", name: "acme-app" });
  const trustedAgent = await makeActor({ kind: "agent", name: "trusted-support-agent", createdBy: root.identity.id });

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

  // Only the ISSUER'S PUBLIC JWK crosses the process boundary — the server
  // never sees any private key material (T14).
  const rootPublicJWK = await root.keys.getPublicJWK();
  const dir = mkdtempSync(join(tmpdir(), "attent-mcp-stdio-"));
  const keysFile = join(dir, "trusted-keys.json");
  writeFileSync(
    keysFile,
    JSON.stringify([{ issuerId: root.identity.id, kid: root.keys.kid, jwk: rootPublicJWK }])
  );

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["--import", "tsx", join(import.meta.dirname, "server.ts")],
    env: { ...process.env, ATTENT_TRUSTED_KEYS_FILE: keysFile },
  });
  const client = new Client({ name: "demo-client", version: "0.0.1" });
  await client.connect(transport);

  async function callRefund(credential?: CredentialChain, amount = 15): Promise<CallToolResult> {
    return client.callTool({
      name: "refund",
      arguments: { orderId: "18472", amount },
      _meta: credential ? { attentCredential: serializeChain(credential) } : undefined,
    }) as Promise<CallToolResult>;
  }

  try {
    console.log("rogue caller, NO credential presented:", await callRefund());
    console.log("trusted caller, valid credential presented:", await callRefund(trustedCredential));
    console.log(
      "trusted caller, amount exceeds delegated $20 ceiling:",
      await callRefund(trustedCredential, 50)
    );
  } finally {
    await client.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});

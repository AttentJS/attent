# @attent/mcp

Attent authorization middleware for [Model Context Protocol](https://modelcontextprotocol.io) servers. Wraps a `tools/call` handler so it only runs after an Attent `authorize()` decision allows it — the caller's own credential is checked, not the tool's own ambient service credential (the confused-deputy bug MCP tool servers are especially prone to).

## Install

```
npm install @attent/mcp attent @modelcontextprotocol/sdk
```

## Mandatory credential verification

`resolveCredential` must resolve to a `VerifiedCredentialChain` — a type that only `verifyChain()` (or the explicitly-named `unsafeAssumeVerified` escape hatch) can produce. This is enforced at the type level: you cannot hand `withAttent` an object shaped like a `CredentialChain` that hasn't actually passed signature/chain verification.

Use `resolveVerifiedCredential` — the recommended, correct-by-construction implementation:

```ts
import { withAttent, resolveVerifiedCredential } from "@attent/mcp";
import { memoryTrustedKeyStore, memoryRevocationStore } from "attent";

const trustedKeys = memoryTrustedKeyStore();
// ... register issuer public keys via trustedKeys.addKey(issuerId, kid, jwk) ...

server.setRequestHandler(
  CallToolRequestSchema,
  withAttent(
    {
      resolveCredential: resolveVerifiedCredential({ trustedKeys }),
      actionForTool: (tool) => `refunds:${tool}`,
      resourceForArgs: (_tool, args) => `order:${args.orderId}`,
      revocationStore: memoryRevocationStore(),
    },
    async (request, extra) => {
      // Only reachable once the caller's own credential has been verified AND authorized.
      return { content: [{ type: "text", text: "refunded" }] };
    }
  )
);
```

`resolveVerifiedCredential` extracts JWS hop strings from the request, verifies them (signature, `kid`/algorithm allowlist, expiry, chain continuity, narrowing, chain-splice binding, depth), and treats any verification failure — malformed, forged, expired, over-depth, narrowing-violated, spliced — identically to "no credential presented." A forged credential gives an attacker no more information than a missing one.

## The `_meta.attentCredential` transport convention

MCP does not standardize a credential-carrying field. `resolveVerifiedCredential`'s default `extractHops` reads `request.params._meta.attentCredential` — an ordered array of compact JWS strings, root hop first:

```ts
client.callTool({
  name: "refund",
  arguments: { orderId: "18472", amount: 15 },
  _meta: { attentCredential: chain.hops.map((hop) => hop.jws) },
});
```

Override `extractHops` if your transport carries the credential elsewhere (a custom header threaded through `extra`, a session-keyed side channel, etc.) — `withAttent` and `resolveVerifiedCredential` don't care where the raw hops come from, only that they get verified before use.

## Wiring into a real server (stdio)

See `examples/mcp-stdio/` in the root repo for a complete, runnable two-process demo: `server.ts` runs a real `@modelcontextprotocol/sdk` `Server` over `StdioServerTransport` with `withAttent` wired in exactly as above; `index.ts` spawns it as a child process via `StdioClientTransport` and calls the tool with a rogue (no-credential), a valid, and an over-limit credential. Run it with:

```
npm run example:mcp-stdio
```

The same pattern applies to SSE/streamable-HTTP transports — only the `Server`/transport construction changes, not the `withAttent` wiring.

## Security notes

- **Verification is mandatory, not a convention you have to remember** — see above.
- **Revocation, not replay prevention.** Attent credentials are bearer tokens, valid for reuse within their `exp` window. Compromise is mitigated by revoking the hop's `jti` via `RevocationStore`, not by single-use replay tracking. See the root README's security section.
- **Deny reasons never distinguish "missing" from "invalid."** Both `resolveVerifiedCredential` (verification failure) and `withAttent` (absent credential) collapse to the same `attent:no_credential` outcome, so a forged/tampered credential doesn't leak more information to an attacker than an absent one.
- **The wrapped handler is only ever reachable after an `allow` decision.** On `deny` (including "no credential"), `withAttent` returns an MCP tool error result — it never throws and never calls the handler — so a misbehaving or unauthorized call can't crash the server or execute side effects.

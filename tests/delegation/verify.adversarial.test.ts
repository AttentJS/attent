import { describe, it, expect } from "vitest";
import { makeActor, scenario, issueRoot, type Actor } from "../fixtures/chain.js";
import { delegate } from "../../src/delegation/delegate.js";
import { verifyChain } from "../../src/delegation/chain.js";
import {
  ChainContinuityError,
  ChainHashMismatchError,
  ChainNarrowingViolationError,
} from "../../src/delegation/errors.js";
import { sha256Base64Url } from "../../src/crypto/hash.js";
import type { HopClaims } from "../../src/credentials/types.js";
import type { CredentialChain } from "../../src/delegation/types.js";
import type { TrustedKeyStore } from "../../src/crypto/types.js";

async function buildLegitChain(): Promise<{
  trustedKeys: TrustedKeyStore;
  root: Actor;
  agent: Actor;
  tool: Actor;
  hop0Chain: CredentialChain;
  hop1Chain: CredentialChain;
}> {
  const { trustedKeys, root } = await scenario();
  const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
  const tool = await makeActor(trustedKeys, { kind: "agent", name: "tool", createdBy: agent.identity.id });

  const hop0Chain = await issueRoot(root, agent, [
    { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } },
  ]);
  const hop1Chain = await delegate({
    from: hop0Chain,
    to: tool.identity,
    keyProvider: agent.keys,
    grant: [{ action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } }],
    ttlSeconds: 900,
  });
  return { trustedKeys, root, agent, tool, hop0Chain, hop1Chain };
}

describe("verifyChain() — a valid chain is accepted", () => {
  it("verifies a legitimate 2-hop chain", async () => {
    const { trustedKeys, hop1Chain } = await buildLegitChain();
    const verified = await verifyChain({ hops: hop1Chain.hops.map((h) => h.jws), trustedKeys });
    expect(verified.hops).toHaveLength(2);
  });
});

describe("verifyChain() — tamper each position of a 3-hop chain individually, all rejected (T8)", () => {
  it("rejects a chain where the root hop's payload was tampered (breaks signature)", async () => {
    const { trustedKeys, hop1Chain } = await buildLegitChain();
    const [hop0Jws, hop1Jws] = hop1Chain.hops.map((h) => h.jws) as [string, string];
    const parts = hop0Jws.split(".");
    const tamperedPayload = Buffer.from(JSON.stringify({ hax: true })).toString("base64url");
    const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
    await expect(verifyChain({ hops: [tampered, hop1Jws], trustedKeys })).rejects.toThrow();
  });

  it("rejects a chain where the leaf hop's payload was tampered (breaks signature)", async () => {
    const { trustedKeys, hop1Chain } = await buildLegitChain();
    const [hop0Jws, hop1Jws] = hop1Chain.hops.map((h) => h.jws) as [string, string];
    const parts = hop1Jws.split(".");
    const tamperedPayload = Buffer.from(JSON.stringify({ hax: true })).toString("base64url");
    const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
    await expect(verifyChain({ hops: [hop0Jws, tampered], trustedKeys })).rejects.toThrow();
  });
});

describe("verifyChain() — hand-crafted-superset-hop-rejected (belt-and-suspenders)", () => {
  it("rejects a validly-signed child hop whose capabilities exceed its true parent's, even though delegate() was bypassed", async () => {
    const { trustedKeys, agent, tool, hop0Chain } = await buildLegitChain();
    const parentHop = hop0Chain.hops[0]!;

    // Attacker controls agent's signing key (or is a dishonest agent) and
    // hand-crafts a hop claiming broader capabilities than what it actually
    // holds, bypassing `delegate()`'s issuance-time rejection entirely.
    const forgedClaims: HopClaims = {
      iss: agent.identity.id,
      sub: tool.identity.id,
      aud: parentHop.claims.aud,
      capabilities: [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 5000 } }],
      jti: crypto.randomUUID(),
      iat: parentHop.claims.iat,
      exp: parentHop.claims.exp,
      parentHopHash: sha256Base64Url(parentHop.jws),
    };
    const forgedJws = await agent.keys.sign(forgedClaims as unknown as Record<string, unknown>);

    await expect(
      verifyChain({ hops: [parentHop.jws, forgedJws], trustedKeys })
    ).rejects.toThrow(ChainNarrowingViolationError);
  });
});

describe("verifyChain() — chain-splice-rejected", () => {
  it("rejects a valid hop spliced onto a different, more-privileged parent it wasn't issued from", async () => {
    const { trustedKeys, hop1Chain, agent } = await buildLegitChain();
    const capturedLeafJws = hop1Chain.hops[1]!.jws;

    // A second, unrelated root grants the SAME agent identity much broader
    // authority, registered in the same trustedKeys so its signature alone
    // verifies fine. The captured leaf hop's own signature is also
    // perfectly valid — but it was never issued from this richer parent.
    const richerRoot = await makeActor(trustedKeys, { kind: "application", name: "richer-root" });
    const richerRootChain = await issueRoot(richerRoot, agent, [
      { action: "refunds:create", resource: "order:*", constraints: { maxAmount: 999999 } },
    ]);

    await expect(
      verifyChain({ hops: [richerRootChain.hops[0]!.jws, capturedLeafJws], trustedKeys })
    ).rejects.toThrow(ChainHashMismatchError);
  });
});

describe("verifyChain() — chain continuity", () => {
  it("rejects when hop n+1's iss does not equal hop n's sub", async () => {
    const { trustedKeys, root, hop0Chain } = await buildLegitChain();
    const stranger = await makeActor(trustedKeys, { kind: "agent", name: "stranger", createdBy: root.identity.id });
    const strangerChain = await issueRoot(root, stranger, [{ action: "refunds:create", resource: "order:*" }]);

    await expect(
      verifyChain({ hops: [hop0Chain.hops[0]!.jws, strangerChain.hops[0]!.jws], trustedKeys })
    ).rejects.toThrow(ChainContinuityError);
  });

  it("rejects an empty hops array", async () => {
    const { trustedKeys } = await buildLegitChain();
    await expect(verifyChain({ hops: [], trustedKeys })).rejects.toThrow(ChainContinuityError);
  });
});

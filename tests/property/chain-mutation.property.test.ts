import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { makeActor, scenario, issueRoot, fixedClock, type Actor } from "../fixtures/chain.js";
import { delegate } from "../../src/delegation/delegate.js";
import { verifyChain } from "../../src/delegation/chain.js";
import type { HopClaims } from "../../src/credentials/types.js";
import type { TrustedKeyStore } from "../../src/crypto/types.js";
import { fcParams } from "./fc.config.js";

/**
 * Chain verification property target: generate random valid chains,
 * randomly mutate one field in one hop, assert verification always rejects
 * the mutated chain (never a false-accept). Mutations are re-signed with the
 * *legitimate* issuer's own key (mirroring the "attacker controls agent's
 * signing key" scenario already covered ad-hoc in verify.adversarial.test.ts)
 * so this exercises the structural re-derivation checks (T8), not just JWS
 * signature verification.
 */

interface Built {
  trustedKeys: TrustedKeyStore;
  agent: Actor;
  tool: Actor;
  hop0Jws: string;
  hop0Exp: number;
  hop1Claims: HopClaims;
}

const CLOCK = fixedClock(new Date("2026-01-01T00:00:00.000Z"));

async function buildLegitChain(): Promise<Built> {
  const { trustedKeys, root } = await scenario();
  const agent = await makeActor(trustedKeys, { kind: "agent", name: "agent", createdBy: root.identity.id });
  const tool = await makeActor(trustedKeys, { kind: "agent", name: "tool", createdBy: agent.identity.id });

  const hop0Chain = await issueRoot(
    root,
    agent,
    [{ action: "refunds:create", resource: "order:*", constraints: { maxAmount: 50 } }],
    { clock: CLOCK }
  );
  const hop1Chain = await delegate({
    from: hop0Chain,
    to: tool.identity,
    keyProvider: agent.keys,
    grant: [{ action: "refunds:create", resource: "order:18472", constraints: { maxAmount: 20 } }],
    ttlSeconds: 400,
    clock: CLOCK,
  });
  return {
    trustedKeys,
    agent,
    tool,
    hop0Jws: hop0Chain.hops[0]!.jws,
    hop0Exp: hop0Chain.hops[0]!.claims.exp,
    hop1Claims: hop1Chain.hops[1]!.claims,
  };
}

type Mutation =
  | { kind: "widen-action" }
  | { kind: "widen-resource" }
  | { kind: "widen-max-amount"; delta: number }
  | { kind: "widen-aud" }
  | { kind: "extend-exp"; delta: number }
  | { kind: "drop-parent-hash" };

// Parent (hop0) grants maxAmount: 50 — any mutated value strictly above that
// is a widening the chain must reject, regardless of the leaf's own (already
// narrower) value at issuance.
const PARENT_MAX_AMOUNT = 50;

const mutationArb: fc.Arbitrary<Mutation> = fc.oneof(
  fc.constant<Mutation>({ kind: "widen-action" }),
  fc.constant<Mutation>({ kind: "widen-resource" }),
  fc.integer({ min: 1, max: 100000 }).map((delta) => ({ kind: "widen-max-amount" as const, delta })),
  fc.constant<Mutation>({ kind: "widen-aud" }),
  fc.integer({ min: 1, max: 100000 }).map((delta) => ({ kind: "extend-exp" as const, delta })),
  fc.constant<Mutation>({ kind: "drop-parent-hash" })
);

function applyMutation(claims: HopClaims, mutation: Mutation, hop0Exp: number): HopClaims {
  switch (mutation.kind) {
    case "widen-action":
      return { ...claims, capabilities: [{ ...claims.capabilities[0]!, action: "*" }] };
    case "widen-resource":
      return { ...claims, capabilities: [{ ...claims.capabilities[0]!, resource: "*" }] };
    case "widen-max-amount": {
      const cap = claims.capabilities[0]!;
      return {
        ...claims,
        capabilities: [
          { ...cap, constraints: { ...cap.constraints, maxAmount: PARENT_MAX_AMOUNT + mutation.delta } },
        ],
      };
    }
    case "widen-aud":
      return { ...claims, aud: "*" };
    case "extend-exp":
      // Set strictly beyond the parent's own (known, fixed-clock) expiry —
      // relative-delta-off-leaf-exp would be flaky since the legitimate
      // leaf's exp is already some unspecified amount below the parent's.
      return { ...claims, exp: hop0Exp + mutation.delta };
    case "drop-parent-hash":
      return { ...claims, parentHopHash: undefined };
  }
}

describe("verifyChain() — random single-field hop mutation is always rejected (property)", () => {
  it("never false-accepts a legitimately-re-signed but structurally-mutated leaf hop", async () => {
    await fc.assert(
      fc.asyncProperty(mutationArb, async (mutation) => {
        const { trustedKeys, agent, hop0Jws, hop0Exp, hop1Claims } = await buildLegitChain();
        const mutatedClaims = applyMutation(hop1Claims, mutation, hop0Exp);
        const mutatedJws = await agent.keys.sign(mutatedClaims as unknown as Record<string, unknown>);

        await expect(verifyChain({ hops: [hop0Jws, mutatedJws], trustedKeys })).rejects.toThrow();
      }),
      fcParams(50)
    );
  });
});

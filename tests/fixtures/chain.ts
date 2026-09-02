import { generateKeyProvider, memoryTrustedKeyStore } from "../../src/crypto/keys.js";
import type { KeyProvider, TrustedKeyStore } from "../../src/crypto/types.js";
import { createIdentity } from "../../src/identity/identity.js";
import type { Identity } from "../../src/identity/types.js";
import { issueCredential } from "../../src/credentials/credentials.js";
import type { CapabilityGrant } from "../../src/credentials/types.js";
import type { Clock } from "../../src/credentials/clock.js";
import { rootChain } from "../../src/delegation/types.js";
import type { CredentialChain } from "../../src/delegation/types.js";

export function fixedClock(date: Date): Clock {
  return { now: () => date };
}

export interface Actor {
  readonly identity: Identity;
  readonly keys: KeyProvider;
}

/**
 * Creates an Identity + keypair and registers the public key in `trustedKeys`
 * under that identity's id — the setup every chain-verification test needs
 * (a hop signed by an issuer whose key was never registered is, correctly,
 * unverifiable, so tests must opt in to trust explicitly, mirroring what a
 * real app's bootstrapping does).
 */
export async function makeActor(
  trustedKeys: TrustedKeyStore,
  input: { kind: "human" | "application" | "agent"; name: string; createdBy?: string }
): Promise<Actor> {
  const keys = await generateKeyProvider();
  const publicJWK = await keys.getPublicJWK();
  const identity = createIdentity({ kind: input.kind, name: input.name, createdBy: input.createdBy, publicJWK });
  await trustedKeys.addKey(identity.id, keys.kid, publicJWK);
  return { identity, keys };
}

/** A root Principal + registered `TrustedKeyStore`, ready to issue/delegate/verify chains. */
export async function scenario(): Promise<{ trustedKeys: TrustedKeyStore; root: Actor }> {
  const trustedKeys = memoryTrustedKeyStore();
  const root = await makeActor(trustedKeys, { kind: "application", name: "acme-app" });
  return { trustedKeys, root };
}

export async function issueRoot(
  root: Actor,
  subject: Actor,
  capabilities: readonly CapabilityGrant[],
  opts: { aud?: string | readonly string[]; ttlSeconds?: number; clock?: Clock } = {}
): Promise<CredentialChain> {
  const credential = await issueCredential({
    issuer: root.identity,
    subject: subject.identity,
    keyProvider: root.keys,
    capabilities,
    aud: opts.aud ?? "order:*",
    ttlSeconds: opts.ttlSeconds ?? 900,
    clock: opts.clock,
  });
  return rootChain(credential);
}

import {
  createIdentity,
  generateKeyProvider,
  issueCredential,
  memoryTrustedKeyStore,
  rootChain,
  type CapabilityGrant,
  type CredentialChain,
  type Identity,
  type KeyProvider,
  type TrustedKeyStore,
} from "attent";

export interface Actor {
  readonly identity: Identity;
  readonly keys: KeyProvider;
}

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

export async function scenario(): Promise<{ trustedKeys: TrustedKeyStore; root: Actor }> {
  const trustedKeys = memoryTrustedKeyStore();
  const root = await makeActor(trustedKeys, { kind: "application", name: "acme-app" });
  return { trustedKeys, root };
}

export async function issueRoot(
  root: Actor,
  subject: Actor,
  capabilities: readonly CapabilityGrant[],
  opts: { aud?: string | readonly string[]; ttlSeconds?: number } = {}
): Promise<CredentialChain> {
  const credential = await issueCredential({
    issuer: root.identity,
    subject: subject.identity,
    keyProvider: root.keys,
    capabilities,
    aud: opts.aud ?? "order:*",
    ttlSeconds: opts.ttlSeconds ?? 900,
  });
  return rootChain(credential);
}

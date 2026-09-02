// @attent/mcp: Attent authorization middleware for Model Context Protocol servers

export { withAttent } from "./withAttent.js";
export type {
  CallToolHandler,
  ResolveCredential,
  ResolveCredentialContext,
  WithAttentOptions,
} from "./types.js";
export {
  attentCredentialFromMeta,
  resolveVerifiedCredential,
  type AttentCredentialMeta,
  type ResolveVerifiedCredentialOptions,
} from "./resolveVerifiedCredential.js";

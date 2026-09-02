export type { Clock } from "./clock.js";
export { systemClock } from "./clock.js";
export type { CapabilityGrant, HopClaims, Credential } from "./types.js";
export {
  issueCredential,
  verifyCredential,
  type IssueCredentialInput,
  type VerifyCredentialInput,
} from "./credentials.js";
export {
  InvalidCredentialInputError,
  MalformedCredentialError,
  CredentialExpiredError,
  CredentialVerificationError,
} from "./errors.js";

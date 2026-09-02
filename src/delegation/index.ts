export type { CredentialChain, ExceedsDetail, VerifiedCredentialChain } from "./types.js";
export { DEFAULT_MAX_DELEGATION_DEPTH, rootChain, unsafeAssumeVerified } from "./types.js";
export {
  intersectCapabilities,
  intersectAudience,
  type CapabilityNarrowResult,
  type AudienceNarrowResult,
} from "./narrow.js";
export { delegate, type DelegateInput } from "./delegate.js";
export { verifyChain, type VerifyChainInput } from "./chain.js";
export {
  ExceedsAvailableAuthorityError,
  MaxDelegationDepthExceededError,
  ChainTooDeepError,
  ChainContinuityError,
  ChainHashMismatchError,
  ChainNarrowingViolationError,
} from "./errors.js";

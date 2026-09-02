export type { Decision, AllowDecision, DenyDecision, DenyReason, AuthorizeInput } from "./types.js";
export { authorize, type AuthorizeOptions } from "./authorize.js";
export { InvalidActionError, InvalidResourceError } from "./errors.js";
export { matchPattern, matchAnyPattern } from "./grammar.js";

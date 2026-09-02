import { createHash } from "node:crypto";

/**
 * Structural (non-secret) content hash used to bind a delegated hop to the
 * exact parent hop it was issued from (`parentHopHash`, §7). This is not a
 * signature — it doesn't prove authenticity by itself, only that a claimed
 * parent string matches; authenticity comes from the parent hop's own JWS
 * signature, checked separately during chain verification.
 */
export function sha256Base64Url(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("base64url");
}

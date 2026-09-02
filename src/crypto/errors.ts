export class UnsupportedAlgorithmError extends Error {
  constructor(alg: string) {
    super(`Unsupported or disallowed signing algorithm: ${alg}`);
    this.name = "UnsupportedAlgorithmError";
  }
}

export class SignatureVerificationError extends Error {
  constructor(reason: string) {
    super(`Signature verification failed: ${reason}`);
    this.name = "SignatureVerificationError";
  }
}

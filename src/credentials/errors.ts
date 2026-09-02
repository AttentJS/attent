export class InvalidCredentialInputError extends Error {
  constructor(reason: string) {
    super(`Invalid credential input: ${reason}`);
    this.name = "InvalidCredentialInputError";
  }
}

export class MalformedCredentialError extends Error {
  constructor(reason: string) {
    super(`Malformed credential: ${reason}`);
    this.name = "MalformedCredentialError";
  }
}

export class CredentialExpiredError extends Error {
  constructor() {
    super("Credential has expired");
    this.name = "CredentialExpiredError";
  }
}

export class CredentialVerificationError extends Error {
  constructor(reason: string) {
    super(`Credential verification failed: ${reason}`);
    this.name = "CredentialVerificationError";
  }
}

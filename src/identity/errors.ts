export class InvalidIdentityError extends Error {
  constructor(reason: string) {
    super(`Invalid identity: ${reason}`);
    this.name = "InvalidIdentityError";
  }
}

export class DuplicateIdentityError extends Error {
  constructor(id: string) {
    super(`Identity already exists: ${id}`);
    this.name = "DuplicateIdentityError";
  }
}

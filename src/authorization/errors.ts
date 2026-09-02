export class InvalidActionError extends Error {
  constructor(reason: string) {
    super(`Invalid action: ${reason}`);
    this.name = "InvalidActionError";
  }
}

export class InvalidResourceError extends Error {
  constructor(reason: string) {
    super(`Invalid resource: ${reason}`);
    this.name = "InvalidResourceError";
  }
}

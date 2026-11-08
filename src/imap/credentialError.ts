/** A stored mailbox secret could not be decrypted (wrong/rotated master key or damaged data). Carries no detail on purpose. */
export class CredentialDecryptError extends Error {
  constructor() { super("Stored mailbox credentials cannot be decrypted"); this.name = "CredentialDecryptError"; }
}

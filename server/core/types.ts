export type Capability = "read" | "draft" | "organize";

/** Derived per request by bearerAuth from the live, validated access token. */
export interface TokenContext {
  tokenId: string;
  clientId: string;
  scopes: Capability[]; // derived from mail:* scopes; ceiling only
}

export class PolicyError extends Error {
  readonly code = "FORBIDDEN" as const;
  constructor(message = "Access denied") {
    super(message);
    this.name = "PolicyError";
  }
}

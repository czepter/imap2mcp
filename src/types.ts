import "express-session";

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

declare module "express-session" {
  interface SessionData {
    userId?: string;
    returnTo?: string;
  }
}

declare module "express-serve-static-core" {
  interface Request {
    tokenContext?: TokenContext;
  }
}

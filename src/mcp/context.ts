import type { TokenContext } from "../types.js";

// Maps MCP session ID to token context
const sessionContexts = new Map<string, TokenContext>();

export function setSessionContext(sessionId: string, ctx: TokenContext): void {
  sessionContexts.set(sessionId, ctx);
}

export function getSessionContext(sessionId: string): TokenContext | undefined {
  return sessionContexts.get(sessionId);
}

export function deleteSessionContext(sessionId: string): void {
  sessionContexts.delete(sessionId);
}

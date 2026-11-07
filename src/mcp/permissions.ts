import type { Scope } from "../types.js";

export function checkPermission(scopes: string[], required: Scope): void {
  if (!scopes.includes(required)) {
    throw new Error(`Permission denied: scope '${required}' not granted`);
  }
}

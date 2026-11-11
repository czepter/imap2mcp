import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Per-tool-call time budget (docs/DESIGN_V2.md "Timeouts"): every upstream tool operation, including retries
 * and reconciliation, must finish within 30 s in total. The budget lives in AsyncLocalStorage so nested helpers
 * (backends, the IMAP pool) share one deadline without threading a parameter everywhere.
 */
export const TOOL_BUDGET_MS = 30_000;

interface Budget { deadline: number }
const als = new AsyncLocalStorage<Budget>();

export function budgetMs(): number {
  const n = Number(process.env.TOOL_BUDGET_MS);
  return Number.isFinite(n) && n > 0 ? n : TOOL_BUDGET_MS;
}

/** Run `fn` inside a budget. Re-entrant: an outer budget wins (nested calls never extend the deadline). */
export function withBudget<T>(fn: () => Promise<T>, ms = budgetMs()): Promise<T> {
  if (als.getStore()) return fn();
  return als.run({ deadline: Date.now() + ms }, fn);
}

/** Milliseconds left in the current budget, or undefined outside one. May be <= 0. */
export function remainingMs(): number | undefined {
  const b = als.getStore();
  return b ? b.deadline - Date.now() : undefined;
}

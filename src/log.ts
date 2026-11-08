import { readFileSync } from "node:fs";

/**
 * Structured JSON logging (docs/DESIGN_V2.md "Logging"). One JSON object per line on stdout.
 * Everything is redacted centrally: secret-looking keys, bearer tokens, `key=value` credentials and any
 * occurrence of the master key / SESSION_SECRET values (read lazily from the environment).
 * All code logs through this module; `console.*` is not used elsewhere in src/.
 */

export type Level = "debug" | "info" | "warn" | "error";
const RANK: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

const REDACTED = "[REDACTED]";
const SECRET_KEY = /(pass(word|wd)?|secret|token|authorization|auth|cookie|api[-_]?key|private[-_]?key|code[-_]?verifier|credential|encryption[-_]?key|session[-_]?secret|^code$|^pass$|^pw$)/i;
// Keys that look secret but are safe metadata.
const SAFE_KEY = /^(tokenId|token_id|clientId|requestId|authMethod|auth_method|errorCode|error_code|tokenType|token_type|tokens|tokenCount)$/;

let extraSecrets: string[] = [];
let envCache: { sig: string; values: string[] } | null = null;

/** Register a runtime secret value that must never appear in logs. Values shorter than 6 chars are ignored. */
export function registerSecret(v: string | undefined | null): void {
  if (v && v.length >= 6 && !extraSecrets.includes(v)) extraSecrets.push(v);
}

/** Test hook. */
export function resetLogSecrets(): void { extraSecrets = []; envCache = null; }

function envSecrets(): string[] {
  const e = process.env;
  const sig = `${e.ENCRYPTION_KEY ?? ""}|${e.ENCRYPTION_KEY_FILE ?? ""}|${e.SESSION_SECRET ?? ""}|${e.ADMIN_BOOTSTRAP_TOKEN ?? ""}`;
  if (envCache && envCache.sig === sig) return envCache.values;
  const vals: string[] = [];
  const add = (v: string | undefined) => { const t = v?.trim(); if (t && t.length >= 6) vals.push(t); };
  add(e.ENCRYPTION_KEY);
  add(e.SESSION_SECRET);
  add(e.ADMIN_BOOTSTRAP_TOKEN);
  if (e.ENCRYPTION_KEY_FILE?.trim()) {
    try { add(readFileSync(e.ENCRYPTION_KEY_FILE.trim(), "utf8")); } catch { /* unreadable: nothing to redact */ }
  }
  // Longest first so a secret containing another is replaced whole.
  vals.sort((a, b) => b.length - a.length);
  envCache = { sig, values: vals };
  return vals;
}

function allSecrets(): string[] {
  return [...envSecrets(), ...extraSecrets].sort((a, b) => b.length - a.length);
}

const PATTERNS: [RegExp, string][] = [
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}/gi, `$1 ${REDACTED}`],
  [/(["']?(?:authorization|password|passwd|pass|secret|token|access_token|refresh_token|client_secret|authorization_code|code_verifier|api[_-]?key|session[_-]?secret|encryption[_-]?key)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;&"'}\]]+)/gi, `$1${REDACTED}`],
  [/\b(?:a|b|ey)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, REDACTED], // JWT-like
  [/\bv1:[0-9a-f]{8}:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+/g, REDACTED], // stored ciphertext blobs
];

/** Redact secrets inside a string. */
export function redactString(s: string): string {
  let out = s;
  for (const secret of allSecrets()) if (out.includes(secret)) out = out.split(secret).join(REDACTED);
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep);
  return out;
}

/** Deep-redact any value (objects, arrays, errors). Cycle-safe, depth-limited. */
export function redact(v: unknown, key = "", depth = 0, seen = new WeakSet<object>()): unknown {
  if (key && SECRET_KEY.test(key) && !SAFE_KEY.test(key)) {
    return v === undefined || v === null ? v : REDACTED;
  }
  if (typeof v === "string") return redactString(v);
  if (typeof v === "bigint") return v.toString();
  if (v === null || typeof v !== "object") return v;
  if (depth > 6) return "[Truncated]";
  if (seen.has(v as object)) return "[Circular]";
  seen.add(v as object);
  if (v instanceof Error) return serializeError(v, depth, seen);
  if (Buffer.isBuffer(v)) return `[Buffer ${v.length}]`;
  if (Array.isArray(v)) return v.map((x) => redact(x, "", depth + 1, seen));
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = redact(val, k, depth + 1, seen);
  return out;
}

function serializeError(e: Error, depth: number, seen: WeakSet<object>): Record<string, unknown> {
  const x = e as Error & { code?: unknown; serverResponseCode?: unknown; cause?: unknown };
  const out: Record<string, unknown> = { name: e.name, message: redactString(e.message) };
  if (typeof x.code === "string" || typeof x.code === "number") out.code = x.code;
  if (typeof x.serverResponseCode === "string") out.serverResponseCode = x.serverResponseCode;
  if (e.stack) out.stack = redactString(e.stack);
  if (x.cause && depth < 3) out.cause = redact(x.cause, "", depth + 1, seen);
  return out;
}

type Sink = (line: string) => void;
let sink: Sink = (line) => { process.stdout.write(line + "\n"); };
/** Test hook: capture output. Pass null to restore stdout. */
export function setLogSink(s: Sink | null): void {
  sink = s ?? ((line) => { process.stdout.write(line + "\n"); });
}

function threshold(): number {
  const l = (process.env.LOG_LEVEL || "info").toLowerCase() as Level;
  return RANK[l] ?? RANK.info;
}

export interface Logger {
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
  child(base: Record<string, unknown>): Logger;
}

function emit(level: Level, base: Record<string, unknown>, msg: string, fields?: Record<string, unknown>): void {
  if (RANK[level] < threshold()) return;
  let line: string;
  try {
    // Reserved keys (ts/level/msg) come last so callers cannot spoof them.
    const rec = { ...(redact({ ...base, ...(fields ?? {}) }) as Record<string, unknown>), ts: new Date().toISOString(), level, msg: redactString(String(msg)) };
    line = JSON.stringify(rec);
  } catch {
    line = JSON.stringify({ ts: new Date().toISOString(), level, msg: "log serialization failed" });
  }
  try { sink(redactString(line)); } catch { /* logging must never throw */ }
}

function make(base: Record<string, unknown>): Logger {
  return {
    debug: (m, f) => emit("debug", base, m, f),
    info: (m, f) => emit("info", base, m, f),
    warn: (m, f) => emit("warn", base, m, f),
    error: (m, f) => emit("error", base, m, f),
    child: (b) => make({ ...base, ...b }),
  };
}

export const log: Logger = make({});

/**
 * One-time operator banner (first-run admin setup code). Plain text on stdout on purpose: the operator must be
 * able to read and copy it, and it is NOT redacted. Only the setup flow may use this; it never carries a long-lived secret.
 */
export function banner(lines: string[]): void {
  process.stdout.write(lines.join("\n") + "\n");
}

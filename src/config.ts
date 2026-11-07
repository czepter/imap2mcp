import { join, resolve } from "path";
import { initCrypto } from "./imap/crypto.js";

export interface Config {
  baseUrl: string;
  isHttps: boolean;
  port: number;
  dataDir: string;
  dbPath: string;
  sessionSecret: string;
  corsOrigin: string | undefined;
  registrationMode: "dynamic" | "admin";
  allowPrivateHosts: string[];
  adminBootstrapToken: string | undefined;
  /** Path of the sidecar binary (SIDECAR_BIN). */
  sidecarBin: string;
  /** SIDECAR_DISABLED=1: use the v0 direct IMAP read path (debugging only; off by default). */
  sidecarDisabled: boolean;
}

export class ConfigError extends Error {}

/** Pure parse/validate of env. Throws ConfigError with a clear message. No defaults for secrets. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const problems: string[] = [];

  const baseUrl = (env.BASE_URL || "http://localhost:3000").replace(/\/+$/, "");
  let isHttps = false;
  try {
    const u = new URL(baseUrl);
    isHttps = u.protocol === "https:";
    if (!isHttps && u.protocol !== "http:") problems.push("BASE_URL must be http(s)");
  } catch {
    problems.push("BASE_URL is not a valid URL");
  }

  const port = parseInt(env.PORT || "3000", 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) problems.push("PORT is invalid");

  const sessionSecret = env.SESSION_SECRET?.trim() || "";
  if (!sessionSecret) problems.push("SESSION_SECRET is required (no default). Generate: openssl rand -hex 32");
  else if (sessionSecret.length < 32) problems.push("SESSION_SECRET must be at least 32 characters");

  const mode = (env.REGISTRATION_MODE || "dynamic").trim();
  if (mode !== "dynamic" && mode !== "admin") problems.push("REGISTRATION_MODE must be 'dynamic' or 'admin'");

  if (problems.length) throw new ConfigError("Invalid configuration:\n  - " + problems.join("\n  - "));

  const dataDir = resolve(env.DATA_DIR || "./data");
  return {
    baseUrl,
    isHttps,
    port,
    dataDir,
    dbPath: join(dataDir, "bridge.db"),
    sessionSecret,
    corsOrigin: env.CORS_ORIGIN || undefined,
    registrationMode: mode as "dynamic" | "admin",
    allowPrivateHosts: (env.ALLOW_PRIVATE_HOSTS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean),
    adminBootstrapToken: env.ADMIN_BOOTSTRAP_TOKEN?.trim() || undefined,
    sidecarBin: resolve(env.SIDECAR_BIN?.trim() || "sidecar/bin/sidecar"),
    sidecarDisabled: ["1", "true", "yes"].includes((env.SIDECAR_DISABLED || "").trim().toLowerCase()),
  };
}

let current: Config | null = null;

/** Validate everything (config + encryption key). Call first thing at startup; throws on any problem. */
export function validateStartup(env: NodeJS.ProcessEnv = process.env): Config {
  current = loadConfig(env);
  initCrypto(env);
  return current;
}

/** Lazy, validated config: first property access loads env (throws if invalid). */
export const config: Config = new Proxy({} as Config, {
  get(_t, prop) {
    if (!current) current = loadConfig();
    return (current as any)[prop];
  },
  has(_t, prop) {
    if (!current) current = loadConfig();
    return prop in current;
  },
  ownKeys() {
    if (!current) current = loadConfig();
    return Reflect.ownKeys(current);
  },
  getOwnPropertyDescriptor(_t, prop) {
    if (!current) current = loadConfig();
    return Object.getOwnPropertyDescriptor(current, prop);
  },
});

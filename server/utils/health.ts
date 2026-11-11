import { getDb, migrationStatus } from "~~/server/core/db/database";
import { config } from "~~/server/core/config";
import { decrypt, encrypt } from "~~/server/core/imap/crypto";
import { getSidecar } from "~~/server/core/sidecar/index";

/**
 * Liveness and readiness (DESIGN_V2 "Health endpoints"). Unauthenticated, rate limited, never cached.
 * Responses carry only fixed check names and ok/fail states: no hostnames, ids, paths, versions or error text.
 */
export type CheckState = "ok" | "fail" | "disabled";
export interface Readiness {
  status: "ok" | "fail";
  checks: { db: CheckState; key: CheckState; sidecar: CheckState; migrations: CheckState };
}

const SIDECAR_PING_MS = 2_000;

function checkDb(): CheckState {
  try {
    getDb().prepare("SELECT COUNT(*) AS n FROM sqlite_master").get();
    return "ok";
  } catch {
    return "fail";
  }
}

/**
 * The master key must load and round-trip a test vector. If the database already holds a mailbox secret,
 * one is also decrypted: this is what detects a syntactically valid but WRONG key (different keyId / failed GCM tag).
 */
function checkKey(): CheckState {
  try {
    const probe = "health-vector-" + Date.now();
    if (decrypt(encrypt(probe, "health:probe"), "health:probe") !== probe) return "fail";
    const row = getDb().prepare("SELECT id, imap_password_enc AS enc FROM mailboxes ORDER BY created_at LIMIT 1").get() as
      | { id: string; enc: string }
      | undefined;
    if (row) decrypt(row.enc, `mailboxes:${row.id}:imap_password_enc`);
    return "ok";
  } catch {
    return "fail";
  }
}

async function checkSidecar(): Promise<CheckState> {
  if (config.sidecarDisabled) return "disabled";
  try {
    await Promise.race([
      getSidecar().call("ping"),
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), SIDECAR_PING_MS).unref()),
    ]);
    return "ok";
  } catch {
    return "fail";
  }
}

function checkMigrations(): CheckState {
  try {
    return migrationStatus(getDb()).pending === 0 ? "ok" : "fail";
  } catch {
    return "fail";
  }
}

export async function readiness(): Promise<Readiness> {
  const checks = { db: checkDb(), key: checkKey(), sidecar: await checkSidecar(), migrations: checkMigrations() };
  const ok = Object.values(checks).every((v) => v === "ok" || v === "disabled");
  return { status: ok ? "ok" : "fail", checks };
}

import { randomBytes, scryptSync, timingSafeEqual, createHash } from "crypto";
import { v4 as uuid } from "uuid";
import { getDb } from "../db/database.js";
import type { User } from "../types.js";

function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password: string, storedHash: string): boolean {
  // Support legacy SHA256 hashes (no colon) for migration
  if (!storedHash.includes(":")) {
    const supplied = createHash("sha256").update(password).digest("hex");
    const a = Buffer.from(supplied, "hex");
    const b = Buffer.from(storedHash, "hex");
    return a.length === b.length && timingSafeEqual(a, b);
  }
  const [salt, hash] = storedHash.split(":");
  const hashBuffer = Buffer.from(hash, "hex");
  const supplied = scryptSync(password, salt, 64);
  return timingSafeEqual(hashBuffer, supplied);
}

export function createUser(username: string, password: string): User {
  const db = getDb();
  const id = uuid();
  const password_hash = hashPassword(password);
  db.prepare(
    "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)"
  ).run(id, username, password_hash);
  return { id, username, password_hash, created_at: new Date().toISOString() };
}

export function verifyUser(username: string, password: string): User | null {
  const db = getDb();
  const user = db
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(username) as User | undefined;
  if (!user) return null;
  if (!verifyPassword(password, user.password_hash)) return null;
  return user;
}

export function getUserById(id: string): User | null {
  const db = getDb();
  return (db.prepare("SELECT * FROM users WHERE id = ?").get(id) as User) || null;
}

export function changePassword(userId: string, newPassword: string): void {
  const db = getDb();
  const password_hash = hashPassword(newPassword);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(password_hash, userId);
}

export function ensureDefaultUser(): void {
  const db = getDb();
  const count = db.prepare("SELECT COUNT(*) as c FROM users").get() as { c: number };
  if (count.c === 0) {
    const password = randomBytes(16).toString("base64url");
    createUser("admin", password);
    console.log("========================================");
    console.log("  Default user created:");
    console.log(`  Username: admin`);
    console.log(`  Password: ${password}`);
    console.log("  CHANGE THIS PASSWORD IMMEDIATELY!");
    console.log("========================================");
  }
}

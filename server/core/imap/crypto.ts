import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";
import { readFileSync } from "fs";

/**
 * Column encryption (AES-256-GCM). Stored format:
 *   v1:<keyId>:<b64 iv>:<b64 ct>:<b64 tag>
 * AAD binds the ciphertext to its location, e.g. "mailboxes:<id>:imap_password_enc".
 * There is no default key: missing/malformed key => throws (fail closed).
 */

export class CryptoConfigError extends Error {}

export interface MasterKey {
  key: Buffer;
  keyId: string;
}

function decodeKey(raw: string, source: string): Buffer {
  const s = raw.trim();
  let key: Buffer | null = null;
  if (/^[0-9a-fA-F]{64}$/.test(s)) key = Buffer.from(s, "hex");
  else if (/^[A-Za-z0-9+/_-]{43}={0,1}$/.test(s)) {
    const b = Buffer.from(s, "base64");
    if (b.length === 32) key = b;
  }
  if (!key || key.length !== 32) {
    throw new CryptoConfigError(`${source} must contain a 32-byte key encoded as 64 hex chars or base64`);
  }
  if (key.every((b) => b === 0)) {
    throw new CryptoConfigError(`${source} is an all-zero key; generate one with: openssl rand -hex 32`);
  }
  return key;
}

/** Resolve the master key from env (ENCRYPTION_KEY_FILE preferred, then ENCRYPTION_KEY). Throws on any problem. */
export function loadMasterKey(env: NodeJS.ProcessEnv = process.env): MasterKey {
  let key: Buffer;
  const file = env.ENCRYPTION_KEY_FILE?.trim();
  if (file) {
    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch (e) {
      throw new CryptoConfigError(`Cannot read ENCRYPTION_KEY_FILE (${file}): ${(e as Error).message}`);
    }
    key = decodeKey(content, "ENCRYPTION_KEY_FILE contents");
  } else if (env.ENCRYPTION_KEY?.trim()) {
    key = decodeKey(env.ENCRYPTION_KEY, "ENCRYPTION_KEY");
  } else {
    throw new CryptoConfigError(
      "No encryption key configured. Set ENCRYPTION_KEY_FILE (path to a file with a 32-byte hex/base64 key) or ENCRYPTION_KEY (64 hex chars). Generate: openssl rand -hex 32"
    );
  }
  return { key, keyId: createHash("sha256").update(key).digest("hex").slice(0, 8) };
}

let cached: MasterKey | null = null;

/** Load and cache the key; call at startup so a bad key stops the process. */
export function initCrypto(env: NodeJS.ProcessEnv = process.env): MasterKey {
  cached = loadMasterKey(env);
  return cached;
}

/** Test helper. */
export function resetCrypto(): void {
  cached = null;
}

function master(): MasterKey {
  if (!cached) cached = loadMasterKey();
  return cached;
}

export function currentKeyId(): string {
  return master().keyId;
}

export function encrypt(plaintext: string, aad: string): string {
  const { key, keyId } = master();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ["v1", keyId, iv.toString("base64"), ct.toString("base64"), tag.toString("base64")].join(":");
}

export function decrypt(blob: string, aad: string): string {
  const { key, keyId } = master();
  const parts = blob.split(":");
  if (parts.length !== 5 || parts[0] !== "v1") throw new Error("Invalid ciphertext format");
  const [, blobKeyId, ivB64, ctB64, tagB64] = parts;
  if (blobKeyId !== keyId) throw new Error(`Ciphertext was encrypted with key ${blobKeyId}, configured key is ${keyId}`);
  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  if (iv.length !== 12 || tag.length !== 16) throw new Error("Invalid ciphertext format");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(Buffer.from(ctB64, "base64")), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("Decryption failed (wrong key, wrong AAD, or tampered data)");
  }
}

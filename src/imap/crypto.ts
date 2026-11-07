import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { config } from "../config.js";

const ALGORITHM = "aes-256-gcm";

function getKey(): Buffer {
  return Buffer.from(config.encryptionKey, "hex");
}

export function encrypt(plaintext: string): { ciphertext: string; iv: string } {
  const iv = randomBytes(16);
  const cipher = createCipheriv(ALGORITHM, getKey(), iv);
  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  return {
    ciphertext: encrypted + ":" + authTag,
    iv: iv.toString("hex"),
  };
}

export function decrypt(ciphertext: string, iv: string): string {
  const [encrypted, authTag] = ciphertext.split(":");
  const decipher = createDecipheriv(ALGORITHM, getKey(), Buffer.from(iv, "hex"));
  decipher.setAuthTag(Buffer.from(authTag, "hex"));
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

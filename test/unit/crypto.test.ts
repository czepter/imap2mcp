import { describe, it, expect, beforeEach } from "vitest";
import { writeFileSync, mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { randomBytes } from "crypto";
import { loadMasterKey, initCrypto, resetCrypto, encrypt, decrypt } from "../../server/core/imap/crypto.js";
import { loadConfig } from "../../server/core/config.js";

const HEX = "ab".repeat(32);
const OTHER = "cd".repeat(32);

describe("master key (fail closed)", () => {
  it("throws when no key configured", () => {
    expect(() => loadMasterKey({})).toThrow(/No encryption key/);
  });
  it("rejects malformed, short and all-zero keys", () => {
    expect(() => loadMasterKey({ ENCRYPTION_KEY: "abc" })).toThrow();
    expect(() => loadMasterKey({ ENCRYPTION_KEY: "zz".repeat(32) })).toThrow();
    expect(() => loadMasterKey({ ENCRYPTION_KEY: "0".repeat(64) })).toThrow(/all-zero/);
  });
  it("rejects missing key file", () => {
    expect(() => loadMasterKey({ ENCRYPTION_KEY_FILE: "/nonexistent/key" })).toThrow(/Cannot read/);
  });
  it("loads hex and base64 key files, file takes precedence", () => {
    const dir = mkdtempSync(join(tmpdir(), "key-"));
    const raw = randomBytes(32);
    const f = join(dir, "k");
    writeFileSync(f, raw.toString("base64") + "\n");
    const k = loadMasterKey({ ENCRYPTION_KEY_FILE: f, ENCRYPTION_KEY: HEX });
    expect(k.key.equals(raw)).toBe(true);
    expect(k.keyId).toMatch(/^[0-9a-f]{8}$/);
    writeFileSync(f, raw.toString("hex"));
    expect(loadMasterKey({ ENCRYPTION_KEY_FILE: f }).key.equals(raw)).toBe(true);
  });
  it("config requires SESSION_SECRET", () => {
    expect(() => loadConfig({})).toThrow(/SESSION_SECRET/);
    expect(() => loadConfig({ SESSION_SECRET: "short" })).toThrow(/32/);
    expect(loadConfig({ SESSION_SECRET: "x".repeat(32) }).registrationMode).toBe("dynamic");
  });
});

describe("encrypt/decrypt", () => {
  beforeEach(() => {
    resetCrypto();
    initCrypto({ ENCRYPTION_KEY: HEX });
  });
  it("round-trips with v1:keyId:iv:ct:tag format", () => {
    const blob = encrypt("s3cret", "mailboxes:1:imap_password_enc");
    const p = blob.split(":");
    expect(p).toHaveLength(5);
    expect(p[0]).toBe("v1");
    expect(Buffer.from(p[2], "base64")).toHaveLength(12);
    expect(blob).not.toContain("s3cret");
    expect(decrypt(blob, "mailboxes:1:imap_password_enc")).toBe("s3cret");
  });
  it("uses a fresh IV each time", () => {
    expect(encrypt("a", "x")).not.toBe(encrypt("a", "x"));
  });
  it("fails on wrong AAD, tampering, wrong key, bad format", () => {
    const blob = encrypt("s3cret", "t:1:c");
    expect(() => decrypt(blob, "t:2:c")).toThrow();
    const p = blob.split(":");
    p[3] = Buffer.from("tampered!!").toString("base64");
    expect(() => decrypt(p.join(":"), "t:1:c")).toThrow();
    expect(() => decrypt("garbage", "t:1:c")).toThrow(/format/);
    resetCrypto();
    initCrypto({ ENCRYPTION_KEY: OTHER });
    expect(() => decrypt(blob, "t:1:c")).toThrow();
  });
});

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { verifyPKCE } from "../../src/oauth/pkce.js";
import { validRedirectUri, scopesToCaps, capsToScopes } from "../../src/oauth/common.js";
import { isPrivateAddress } from "../../src/imap/ssrf.js";
import { loadConfig, ConfigError } from "../../src/config.js";
import { validateFlags } from "../../src/mcp/tools.js";

describe("PKCE", () => {
  const v = "a".repeat(43);
  const c = createHash("sha256").update(v).digest("base64url");
  it("accepts the matching S256 verifier", () => expect(verifyPKCE(v, c)).toBe(true));
  it("rejects wrong, short and plain verifiers", () => {
    expect(verifyPKCE("b".repeat(43), c)).toBe(false);
    expect(verifyPKCE("short", c)).toBe(false);
    expect(verifyPKCE(v, v)).toBe(false); // plain method
  });
});

describe("redirect URI validation", () => {
  it.each(["https://app.example/cb", "http://localhost:3000/cb", "http://127.0.0.1:9/cb"])("accepts %s", (u) => expect(validRedirectUri(u)).toBe(true));
  it.each(["http://app.example/cb", "ftp://x/y", "javascript:alert(1)", "https://x/y#f", "", "//x/y", "app://cb"])("rejects %s", (u) => expect(validRedirectUri(u)).toBe(false));
});

describe("scopes", () => {
  it("maps mail:* scopes to capabilities and back, ignoring unknown scopes", () => {
    expect(scopesToCaps("mail:read mail:organize openid mail:send mail:read")).toEqual(["read", "organize"]);
    expect(capsToScopes(["draft"])).toBe("mail:draft");
  });
});

describe("SSRF address classification", () => {
  it.each(["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::7f00:1"])("%s is private", (ip) => expect(isPrivateAddress(ip)).toBe(true));
  it.each(["8.8.8.8", "93.184.216.34", "172.32.0.1", "2606:4700:4700::1111"])("%s is public", (ip) => expect(isPrivateAddress(ip)).toBe(false));
  it("treats non-IP strings as private (fail closed)", () => expect(isPrivateAddress("not-an-ip")).toBe(true));
});

describe("config", () => {
  const ok = { SESSION_SECRET: "s".repeat(32) };
  it("requires SESSION_SECRET and rejects short ones", () => {
    expect(() => loadConfig({})).toThrow(ConfigError);
    expect(() => loadConfig({ SESSION_SECRET: "short" })).toThrow(ConfigError);
  });
  it("defaults to dynamic registration and parses ALLOW_PRIVATE_HOSTS", () => {
    const c = loadConfig({ ...ok, ALLOW_PRIVATE_HOSTS: " Mail.Lan , 10.0.0.5 ,," });
    expect(c.registrationMode).toBe("dynamic");
    expect(c.allowPrivateHosts).toEqual(["mail.lan", "10.0.0.5"]);
  });
  it("rejects unknown registration modes and bad BASE_URL", () => {
    expect(() => loadConfig({ ...ok, REGISTRATION_MODE: "open" })).toThrow(ConfigError);
    expect(() => loadConfig({ ...ok, BASE_URL: "ftp://x" })).toThrow(ConfigError);
  });
});

describe("flag validation", () => {
  it("allows system flags and keywords", () => expect(validateFlags(["\\Seen", "\\Flagged", "Todo_1"])).toEqual(["\\Seen", "\\Flagged", "Todo_1"]));
  it.each(["\\Deleted", "\\RECENT", "\\Nope", "has space", "a(b", ""])("rejects %j", (f) => expect(() => validateFlags([f])).toThrow());
});

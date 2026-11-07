import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface TestCert {
  dir: string;
  certPath: string;
  keyPath: string;
  cert: string;
  key: string;
}

/** Self-signed cert for localhost/127.0.0.1. Returns null when openssl is unavailable (callers must SKIP, not pass). */
export function makeSelfSignedCert(): TestCert | null {
  try {
    const dir = mkdtempSync(join(tmpdir(), "imap2mcp-cert-"));
    const keyPath = join(dir, "key.pem");
    const certPath = join(dir, "cert.pem");
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath, "-out", certPath, "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
      { stdio: "ignore" },
    );
    return { dir, certPath, keyPath, cert: readFileSync(certPath, "utf8"), key: readFileSync(keyPath, "utf8") };
  } catch {
    return null;
  }
}

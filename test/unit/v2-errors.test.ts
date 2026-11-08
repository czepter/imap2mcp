import { afterEach, describe, expect, it } from "vitest";
import { ImapAuthError, ImapConnectError, ImapTimeoutError } from "../../src/imap/client.js";
import { ToolError, errorPayload, errorResult, normalizeError } from "../../src/mcp/errors.js";
import { runWithAudit } from "../../src/audit/context.js";
import { PolicyError } from "../../src/types.js";
import {
  RPC_AUTH, RPC_STALE_REFERENCE, RPC_TIMEOUT, RPC_UPSTREAM, SidecarRpcError, SidecarTimeoutError, SidecarUnavailableError,
} from "../../src/sidecar/errors.js";
import { log, redact, redactString, registerSecret, resetLogSecrets, setLogSink } from "../../src/log.js";

const imapErr = (o: Record<string, unknown>) => Object.assign(new Error("Command failed"), o);

describe("error taxonomy (docs/ERRORS.md)", () => {
  it("auth failures => AUTH_FAILED with operatorAction, not retryable", () => {
    for (const e of [
      new ImapAuthError(), new ImapAuthError("x", true),
      imapErr({ authenticationFailed: true, serverResponseCode: "AUTHENTICATIONFAILED" }),
      new SidecarRpcError(RPC_UPSTREAM, "upstream authentication failed"),
    ]) {
      const t = normalizeError(e);
      expect(t.code).toBe("AUTH_FAILED");
      expect(t.retryable).toBe(false);
      expect(t.operatorAction).toMatch(/password|Retry/);
    }
  });

  it("NO [OVERQUOTA] / [LIMIT] => QUOTA_EXCEEDED, also for writes (definite rejection, not UNKNOWN_OUTCOME)", () => {
    for (const mutating of [false, true]) {
      expect(normalizeError(imapErr({ serverResponseCode: "OVERQUOTA", responseStatus: "NO" }), mutating).code).toBe("QUOTA_EXCEEDED");
      expect(normalizeError(imapErr({ responseText: "[LIMIT] too many" , responseStatus: "NO" }), mutating).code).toBe("QUOTA_EXCEEDED");
    }
    expect(normalizeError(new SidecarRpcError(RPC_UPSTREAM, "upstream error: NO [OVERQUOTA] mailbox full")).code).toBe("QUOTA_EXCEEDED");
  });

  it("[UNAVAILABLE] on select => FOLDER_UNAVAILABLE, nonexistent => NOT_FOUND", () => {
    expect(normalizeError(imapErr({ serverResponseCode: "UNAVAILABLE", responseStatus: "NO", command: "SELECT" })).code).toBe("FOLDER_UNAVAILABLE");
    expect(normalizeError(new SidecarRpcError(RPC_UPSTREAM, "upstream error: NO [UNAVAILABLE] try later")).code).toBe("FOLDER_UNAVAILABLE");
    expect(normalizeError(imapErr({ mailboxMissing: true })).code).toBe("NOT_FOUND");
    expect(normalizeError(imapErr({ serverResponseCode: "NONEXISTENT" })).code).toBe("NOT_FOUND");
    expect(normalizeError(new SidecarRpcError(RPC_UPSTREAM, "upstream error: no such mailbox")).code).toBe("NOT_FOUND");
  });

  it("malformed replies => PROTOCOL_ERROR for reads, UNKNOWN_OUTCOME for writes", () => {
    const e = Object.assign(new SyntaxError("Unexpected token in server response"), {});
    expect(normalizeError(e).code).toBe("PROTOCOL_ERROR");
    expect(normalizeError(e).retryable).toBe(false);
    expect(normalizeError(new SidecarRpcError(RPC_UPSTREAM, "upstream error: malformed response")).code).toBe("PROTOCOL_ERROR");
    expect(normalizeError(e, true).code).toBe("UNKNOWN_OUTCOME");
  });

  it("timeouts: TIMEOUT retryable on reads; UNKNOWN_OUTCOME and never retryable on writes", () => {
    for (const e of [new ImapTimeoutError(), new SidecarTimeoutError("search"), new SidecarRpcError(RPC_TIMEOUT, "request timed out")]) {
      const r = normalizeError(e);
      expect(r.code).toBe("TIMEOUT");
      expect(r.retryable).toBe(true);
    }
    const w = normalizeError(new ImapTimeoutError(), true);
    expect(w.code).toBe("UNKNOWN_OUTCOME");
    expect(w.retryable).toBe(false);
  });

  it("our own subsystem down => UNAVAILABLE; unreachable mailbox => UPSTREAM_ERROR (retryable on reads)", () => {
    expect(normalizeError(new SidecarUnavailableError()).code).toBe("UNAVAILABLE");
    expect(normalizeError(new SidecarRpcError(RPC_AUTH, "unauthorized")).code).toBe("UNAVAILABLE");
    const u = normalizeError(new ImapConnectError("x", new Error("ECONNREFUSED")));
    expect(u.code).toBe("UPSTREAM_ERROR");
    expect(u.retryable).toBe(true);
    expect(normalizeError(new ImapConnectError("x"), true).retryable).toBe(false);
    expect(normalizeError(new Error("???")).code).toBe("UPSTREAM_ERROR");
  });

  it("existing mappings are unchanged", () => {
    expect(normalizeError(new PolicyError()).code).toBe("FORBIDDEN");
    expect(normalizeError(new SidecarRpcError(RPC_STALE_REFERENCE, "stale")).code).toBe("STALE_REFERENCE");
    expect(normalizeError(new Error("boom"), true).code).toBe("UNKNOWN_OUTCOME");
  });

  it("payload shape: {code,message,requestId,retryable,operatorAction?}; no hosts or server text leak", () => {
    const t = normalizeError(new SidecarRpcError(RPC_UPSTREAM, "upstream error: imap.secret-host.example said NO [OVERQUOTA] for bob"));
    const p = errorPayload(t, "req-12345678");
    expect(Object.keys(p).sort()).toEqual(["code", "message", "operatorAction", "requestId", "retryable"]);
    expect(JSON.stringify(p)).not.toMatch(/secret-host|bob/);
    const r = errorResult(new ToolError("NOT_FOUND", "Folder not found"), "req-12345678");
    expect(JSON.parse(r.content[0].text)).toEqual({ code: "NOT_FOUND", message: "Folder not found", requestId: "req-12345678", retryable: false });
  });

  it("requestId defaults to the audit scope's request id", async () => {
    const out = await runWithAudit({ requestId: "abcd-1234-req", note: {} }, async () => errorResult(new ToolError("INVALID_INPUT", "bad")));
    expect(JSON.parse(out.content[0].text).requestId).toBe("abcd-1234-req");
  });

  it("only TIMEOUT/UPSTREAM_ERROR/UNAVAILABLE can be retryable", () => {
    for (const c of ["FORBIDDEN", "NOT_FOUND", "STALE_REFERENCE", "INVALID_INPUT", "UNSUPPORTED", "UNKNOWN_OUTCOME", "AUTH_FAILED", "QUOTA_EXCEEDED", "FOLDER_UNAVAILABLE", "PROTOCOL_ERROR"] as const) {
      expect(new ToolError(c, "x").retryable).toBe(false);
    }
    for (const c of ["TIMEOUT", "UPSTREAM_ERROR", "UNAVAILABLE"] as const) expect(new ToolError(c, "x").retryable).toBe(true);
  });
});

describe("log redaction", () => {
  const lines: string[] = [];
  const saved = { ...process.env };
  afterEach(() => { setLogSink(null); resetLogSecrets(); process.env = { ...saved }; lines.length = 0; });

  it("emits one JSON object per line with ts/level/msg", () => {
    setLogSink((l) => lines.push(l));
    log.info("hello", { mailboxId: "m1" });
    const o = JSON.parse(lines[0]);
    expect(o).toMatchObject({ level: "info", msg: "hello", mailboxId: "m1" });
    expect(new Date(o.ts).toISOString()).toBe(o.ts);
  });

  it("redacts secret keys, bearer tokens, key=value credentials and the configured master key / SESSION_SECRET", () => {
    const key = "a".repeat(10) + "0123456789abcdef".repeat(3) + "ff";
    process.env.ENCRYPTION_KEY = key;
    process.env.SESSION_SECRET = "session-secret-value-1234567890abcdef";
    setLogSink((l) => lines.push(l));
    log.error("failed with Authorization: Bearer abc.def-ghijkl and password=hunter2hunter2", {
      password: "p4ss", accessToken: "tok123456", nested: { client_secret: "cs" }, note: `contains ${key} and ${process.env.SESSION_SECRET}`,
      err: new Error(`boom ${key}`), tokenId: "keep-me",
    });
    const out = lines.join("\n");
    for (const s of ["hunter2", "p4ss", "tok123456", "abc.def-ghijkl", key, "session-secret-value", '"cs"']) expect(out).not.toContain(s);
    expect(out).toContain("[REDACTED]");
    expect(out).toContain("keep-me");
  });

  it("respects LOG_LEVEL and registerSecret; redact() handles cycles", () => {
    process.env.LOG_LEVEL = "warn";
    setLogSink((l) => lines.push(l));
    log.info("dropped");
    expect(lines).toHaveLength(0);
    registerSecret("runtime-secret-xyz");
    expect(redactString("x runtime-secret-xyz y")).toBe("x [REDACTED] y");
    const a: Record<string, unknown> = { n: 1 }; a.self = a;
    expect(() => redact(a)).not.toThrow();
  });
});

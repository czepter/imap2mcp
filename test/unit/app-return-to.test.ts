import { describe, it, expect } from "vitest";
import { safeReturnTo } from "../../app/composables/returnTo";

/** The same-site check behind "after sign-in go to returnTo" (an open-redirect defence). */
describe("safeReturnTo", () => {
  it.each(["/dashboard", "/mailboxes/abc-123", "/clients/00000000-0000-4000-8000-000000000000", "/audit?outcome=denied&page=2", "/oauth/authorize?client_id=x&redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcb", "/dashboard#tokens", "/"])(
    "accepts the same-site path %s",
    (v) => expect(safeReturnTo(v)).toBe(v),
  );

  it.each([
    ["scheme-relative URL", "//evil.example/steal"],
    ["absolute https URL", "https://evil.example/"],
    ["absolute http URL", "http://evil.example/"],
    ["javascript: URL", "javascript:alert(1)"],
    ["data: URL", "data:text/html,<script>alert(1)</script>"],
    ["backslash trick", "/\\evil.example"],
    ["backslash inside", "/ok\\..\\evil"],
    ["triple slash", "///evil.example"],
    ["relative path", "dashboard"],
    ["empty", ""],
    ["whitespace first", " /dashboard"],
    ["tab", "/da\tshboard"],
    ["newline (header injection)", "/dashboard\r\nSet-Cookie: x=1"],
    ["NUL", "/dash\u0000board"],
    ["DEL", "/dash\u007fboard"],
    ["login (would loop)", "/login"],
    ["login with query (would loop)", "/login?returnTo=%2Fdashboard"],
    ["setup (would loop)", "/setup"],
    ["login fragment", "/login#x"],
    ["absurdly long", "/" + "a".repeat(2000)],
  ])("rejects %s", (_n, v) => expect(safeReturnTo(v)).toBeNull());

  it("rejects non-strings and takes the first of repeated query values", () => {
    for (const v of [undefined, null, 5, {}, true, [], [""], [undefined]]) expect(safeReturnTo(v as unknown)).toBeNull();
    expect(safeReturnTo(["/audit", "/evil"])).toBe("/audit");
    expect(safeReturnTo(["//evil.example", "/audit"])).toBeNull();
  });

  it("does not reject paths merely containing 'login' elsewhere", () => {
    expect(safeReturnTo("/clients/login-bot")).toBe("/clients/login-bot");
    expect(safeReturnTo("/audit?next=/login")).toBe("/audit?next=/login");
  });
});

/**
 * [slow] Version 2 acceptance criterion 2 with REAL default timers (1 s initial backoff, 60 s cap, no scaled knobs):
 * after connectivity returns, the mailbox resumes and reconciles missed changes within 90 s.
 *
 *   run only this:      npx vitest run test/integration/v2-slow.test.ts      (or -t "[slow]")
 *   skip it explicitly: V2_SKIP_SLOW=1 npm test                              (reason is printed)
 * It takes about 2-3 minutes; the 90 s budget is measured from the moment the fake server accepts connections again.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { msg, sleep, type Stack } from "../helpers/stack.js";
import { allowAll, newClient, type Client } from "../helpers/v1.js";
import { ALICE, canRunV2, createV2Stack, mailboxStatus } from "../helpers/v2.js";

vi.setConfig({ testTimeout: 400_000, hookTimeout: 120_000 });

const skipSlow = process.env.V2_SKIP_SLOW === "1";
if (skipSlow) console.warn("SKIPPED [slow] v2 resume-within-90s test: V2_SKIP_SLOW=1 (real-timer test, ~2-3 min)");

describe.skipIf(!canRunV2 || skipSlow)("[slow] v2 resume within 90 s with default timers", () => {
  let s: Stack;
  let box: string;
  let c: Client;

  beforeAll(async () => {
    // no RECONNECT_* knobs: production defaults. Reconcile timer is parked so only the reconnect path can find the changes.
    s = await createV2Stack({ fast: false, env: { RECONNECT_INITIAL_MS: undefined, RECONNECT_MAX_MS: undefined, IDLE_RENEW_SECS: undefined, SYNC_RECONCILE_SECS: "3600" }, fake: (f) => { f.idleCap = true; } });
    box = s.mailbox[ALICE];
    for (let i = 0; i < 3; i++) s.fake.addMessage(ALICE, "INBOX", msg(`slow-base-${i}`));
    c = await newClient(s, box, allowAll(), "v2-slow");
    expect((await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX" })).isError).toBe(false);
  });
  afterAll(async () => {
    await c?.mcp.close();
    await s?.teardown();
  });

  it("[slow] outage of ~75 s (backoff reaches its 32-60 s steps), then resumes and reconciles within 90 s of connectivity returning", async () => {
    const t0 = Date.now();
    s.fake.refuseConnections = true;
    s.fake.dropConnections();
    s.fake.externalDeliver(ALICE, "INBOX", 2, (i) => `slow-arrival-${i}`);
    s.fake.externalExpunge(ALICE, "INBOX", [1]);
    await sleep(75_000);

    const attempts = s.fake.connectLog.filter((x) => x.ts >= t0 && x.refused).map((x) => x.ts);
    const gaps = attempts.slice(1).map((t, i) => t - attempts[i]);
    console.info(`[slow] ${attempts.length} refused attempts during the outage; gaps ms: ${gaps.join(",")}`);
    expect(attempts.length).toBeGreaterThanOrEqual(4);
    expect(attempts.length).toBeLessThanOrEqual(60);
    for (const g of gaps) expect(g, `gaps ${gaps.join(",")}`).toBeLessThanOrEqual(60_000 + 3_000); // 60 s cap + connect time
    expect(Math.max(...gaps), "backoff actually grew").toBeGreaterThan(4_000);
    expect(mailboxStatus(s, box).status).not.toBe("auth_failed");

    s.fake.resetFetchStats();
    const back = Date.now();
    s.fake.refuseConnections = false;
    let reconnectAt = 0;
    let reconciledAt = 0;
    while (Date.now() - back < 100_000) {
      if (!reconnectAt && s.fake.connectLog.some((x) => x.ts >= back && !x.refused)) reconnectAt = Date.now();
      if (!reconciledAt && s.fake.fetchTotal(ALICE, "INBOX", "envelope") >= 2) reconciledAt = Date.now();
      if (reconnectAt && reconciledAt) break;
      await sleep(250);
    }
    console.info(`[slow] reconnected ${reconnectAt ? reconnectAt - back : "never"} ms, reconciled ${reconciledAt ? reconciledAt - back : "never"} ms after connectivity returned`);
    expect(reconnectAt, "sidecar reconnected").toBeGreaterThan(0);
    expect(reconnectAt - back, "reconnect within 90 s").toBeLessThanOrEqual(90_000);
    expect(reconciledAt, "reconcile ran without any tool call").toBeGreaterThan(0);
    expect(reconciledAt - back, "reconciled within 90 s").toBeLessThanOrEqual(90_000);

    const r = await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX", limit: 50 });
    const subj = (r.data.messages as any[]).map((m) => m.subject);
    expect(subj.filter((x) => x.startsWith("slow-arrival-"))).toHaveLength(2);
    expect(subj).not.toContain("slow-base-0");
    expect(Date.now() - back, "first correct answer within 90 s").toBeLessThanOrEqual(90_000);
  });
});

import { Router } from "express";
import type { Request, Response } from "express";
import { requireAdmin, csrfProtection } from "../web/deps.js";
import { layout, card } from "../web/views/layout.js";
import { escapeHtml as esc } from "../web/views/escapeHtml.js";
import { countAudit, distinctValues, queryAudit, type AuditFilter, type AuditOutcome } from "./store.js";
import { exportLines, parseTime } from "./export.js";

export const auditRouter = Router();

// Admin-only. All routes are GET (read-only), so CSRF only matters if one is ever added.
auditRouter.use("/audit", requireAdmin, csrfProtection);

const PAGE_SIZE = 50;
const OUTCOMES: AuditOutcome[] = ["ok", "denied", "failed", "unknown_outcome"];
const q = (v: unknown, max = 128): string => (typeof v === "string" ? v.trim().slice(0, max) : "");

function filterFrom(req: Request): { f: AuditFilter; raw: Record<string, string> } {
  const raw = {
    client: q(req.query.client), mailbox: q(req.query.mailbox), tool: q(req.query.tool), outcome: q(req.query.outcome, 32),
    from: q(req.query.from, 40), to: q(req.query.to, 40),
  };
  const f: AuditFilter = {};
  if (raw.client) f.clientId = raw.client;
  if (raw.mailbox) f.mailboxId = raw.mailbox;
  if (raw.tool) f.tool = raw.tool;
  if ((OUTCOMES as string[]).includes(raw.outcome)) f.outcome = raw.outcome as AuditOutcome;
  const from = parseTime(raw.from);
  if (from) f.from = from;
  const to = parseTime(raw.to);
  // a bare date in "to" means "through the end of that day"
  if (to) f.to = /^\d{4}-\d{2}-\d{2}$/.test(raw.to) ? new Date(Date.parse(to) + 86_400_000).toISOString() : to;
  return { f, raw };
}

const qs = (raw: Record<string, string>, extra: Record<string, string> = {}): string => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries({ ...raw, ...extra })) if (v) p.set(k, v);
  const s = p.toString();
  return s ? "?" + s : "";
};

const opt = (vals: string[], cur: string, any: string) =>
  `<option value="">${esc(any)}</option>` + vals.map((v) => `<option value="${esc(v)}"${v === cur ? " selected" : ""}>${esc(v)}</option>`).join("");

const pillFor = (o: string) => `<span class="pill ${o === "ok" ? "ok" : o === "denied" ? "warn" : "off"}">${esc(o.replace("_", " "))}</span>`;

auditRouter.get("/audit", (req: Request, res: Response) => {
  const { f, raw } = filterFrom(req);
  const total = countAudit(f);
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.min(Math.max(parseInt(q(req.query.page, 8), 10) || 1, 1), pages);
  const rows = queryAudit(f, { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE });

  const filters = `<form method="GET" action="/audit" class="pad"><div class="filters">
    <div><label for="fc">Client</label><select id="fc" name="client">${opt(distinctValues("client_id"), raw.client, "All clients")}</select></div>
    <div><label for="fm">Mailbox</label><select id="fm" name="mailbox">${opt(distinctValues("mailbox_id"), raw.mailbox, "All mailboxes")}</select></div>
    <div><label for="ft">Tool</label><select id="ft" name="tool">${opt(distinctValues("tool"), raw.tool, "All tools")}</select></div>
    <div><label for="fo">Outcome</label><select id="fo" name="outcome">${opt(OUTCOMES, raw.outcome, "All outcomes")}</select></div>
    <div><label for="ff">From (UTC)</label><input id="ff" type="date" name="from" value="${esc(/^\d{4}-\d{2}-\d{2}$/.test(raw.from) ? raw.from : "")}"></div>
    <div><label for="fe">To (UTC, inclusive)</label><input id="fe" type="date" name="to" value="${esc(/^\d{4}-\d{2}-\d{2}$/.test(raw.to) ? raw.to : "")}"></div>
  </div><div class="row" style="margin-top:14px"><button type="submit" class="p">Filter</button><a class="btn" href="/audit">Reset</a>
    <span class="grow"></span>
    <a class="btn" href="/audit/export.jsonl${esc(qs(raw))}" download>Download JSONL</a>
    <a class="btn" href="/audit/export.csv${esc(qs(raw))}" download>Download CSV</a></div></form>`;

  const uidCell = (e: (typeof rows)[number]) =>
    e.uid !== null ? String(e.uid)
      : e.uids ? `${e.uids.length} UIDs${e.uidsTruncated ? " (truncated)" : ""}`
      : `<span class="none">—</span>`;
  const body = rows.length
    ? `<div class="scroll"><table><thead><tr><th scope="col">Time (UTC)</th><th scope="col">Client</th><th scope="col">Mailbox</th><th scope="col">Folder</th><th scope="col">UIDVALIDITY</th><th scope="col">UID(s)</th><th scope="col">Tool</th><th scope="col">Outcome</th><th scope="col">Flags</th><th scope="col">ms</th><th scope="col">Request</th></tr></thead><tbody>${rows.map((e) => `<tr>
      <td class="mono"><time datetime="${esc(e.ts)}">${esc(e.ts.replace("T", " ").replace("Z", ""))}</time></td>
      <td class="mono">${e.clientId ? esc(e.clientId) : '<span class="none">—</span>'}</td>
      <td class="mono">${e.mailboxId ? esc(e.mailboxId) : '<span class="none">—</span>'}</td>
      <td>${e.folder ? esc(e.folder) : '<span class="none">—</span>'}</td>
      <td>${e.uidValidity ?? '<span class="none">—</span>'}</td>
      <td>${uidCell(e)}</td>
      <td>${esc(e.tool)}</td>
      <td>${pillFor(e.outcome)}${e.errorCode ? ` <span class="small">${esc(e.errorCode)}</span>` : ""}</td>
      <td>${e.cached ? '<span class="pill read">cached</span> ' : ""}${e.reconciled ? '<span class="pill read">reconciled</span>' : ""}</td>
      <td class="r">${e.durationMs ?? ""}</td>
      <td class="mono">${esc(e.requestId)}</td></tr>`).join("")}</tbody></table></div>
      <div class="pager"><span class="sub">${total} event${total === 1 ? "" : "s"} · page ${page} of ${pages}</span><span class="row">
        ${page > 1 ? `<a class="btn s" href="/audit${esc(qs(raw, { page: String(page - 1) }))}">Previous</a>` : ""}
        ${page < pages ? `<a class="btn s" href="/audit${esc(qs(raw, { page: String(page + 1) }))}">Next</a>` : ""}</span></div>`
    : `<p class="pad sub">No audit events match.</p>`;

  res.send(layout("Audit log", `<div class="head"><div><h1>Audit log</h1>
    <p>Every tool attempt: who, which mailbox and message references, outcome. Never message content, headers or credentials.</p></div></div>
    ${card("filter", "Filter", filters)}${card("events", "Events", body)}`, "admin", "audit"));
});

function download(format: "jsonl" | "csv") {
  return (req: Request, res: Response) => {
    const { f } = filterFrom(req);
    res.setHeader("Content-Type", format === "csv" ? "text/csv; charset=utf-8" : "application/x-ndjson; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="audit.${format}"`);
    res.setHeader("Cache-Control", "no-store");
    for (const line of exportLines(format, f)) res.write(line + "\n");
    res.end();
  };
}
auditRouter.get("/audit/export.jsonl", download("jsonl"));
auditRouter.get("/audit/export.csv", download("csv"));

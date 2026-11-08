import { Router } from "express";
import type { Request, Response } from "express";
import { randomUUID } from "crypto";
import { getDb } from "../db/database.js";
import { config } from "../config.js";
import { requireAdmin, csrfProtection, csrfToken, CSRF_FIELD } from "./deps.js";
import {
  listMailboxes, getMailbox, createMailbox, updateMailbox, deleteMailbox, setDraftsFolder, testMailbox, validateMailboxInput,
} from "../imap/mailboxes.js";
import { layout, card, type NavKey } from "./views/layout.js";
import { escapeHtml as esc } from "./views/escapeHtml.js";
import { CAPABILITIES, validRedirectUri, scopesToCaps } from "../oauth/common.js";
import type { Capability } from "../types.js";
import { clearMailboxAuthFailure } from "../imap/client.js";
import { retryMailbox } from "../sidecar/index.js";
import { capabilityRows, OPERATIONS, OP_CAPABILITY, PRESET_OPS, grantPreset, isOperation, isValidSelector, listRules, presetActive, revokePreset, setRule } from "../policy/rules.js";

const router = Router();

// Everything below is admin-only and CSRF-protected on state changes. Path-scoped so
// /mcp, /oauth/*, /login, /setup are untouched.
const PREFIXES = ["/dashboard", "/mailboxes", "/clients", "/tokens"];
router.use(PREFIXES, requireAdmin, csrfProtection);

const csrf = (req: Request) => `<input type="hidden" name="${CSRF_FIELD}" value="${esc(csrfToken(req))}">`;
const post = (req: Request, action: string, label: string, cls = "") =>
  `<form method="POST" action="${esc(action)}" class="inline">${csrf(req)}<button type="submit" class="${cls}">${esc(label)}</button></form>`;
const flash = (req: Request) => {
  const m = typeof req.query.msg === "string" ? req.query.msg : "";
  const e = typeof req.query.err === "string" ? req.query.err : "";
  return (e ? `<div class="error">${esc(e)}</div>` : "") + (m ? `<div class="success">${esc(m)}</div>` : "");
};
const back = (res: Response, path: string, kind: "msg" | "err", text: string) =>
  res.redirect(`${path}${path.includes("?") ? "&" : "?"}${kind}=${encodeURIComponent(text)}`);
const str = (v: unknown, max = 500) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const send = (res: Response, title: string, body: string, active?: NavKey) => res.send(layout(title, body, "admin", active));
const pill = (cap: string) => `<span class="pill ${esc(cap)}">${esc(cap)}</span>`;
const when = (iso: string) => esc(iso.replace("T", " ").slice(0, 16)) + " UTC";

// ---- mailbox connection status (v2) ----
interface MbStatus { status: string; last_error_code: string | null; last_ok_at: string | null; next_retry_at: string | null }
function mailboxStatus(id: string): MbStatus {
  try {
    return (getDb().prepare("SELECT status, last_error_code, last_ok_at, next_retry_at FROM mailboxes WHERE id = ?").get(id) as MbStatus | undefined)
      ?? { status: "unknown", last_error_code: null, last_ok_at: null, next_retry_at: null };
  } catch { return { status: "unknown", last_error_code: null, last_ok_at: null, next_retry_at: null }; }
}
const statusBadge = (st: string) => {
  const cls = st === "ok" ? "ok" : st === "auth_failed" ? "off" : st === "degraded" ? "warn" : "read";
  const text = st === "auth_failed" ? "auth failed" : st;
  return `<span class="pill ${cls}">${esc(text)}</span>`;
};
/** Resets status to 'unknown' and clears the in-process auth-failure latch (sidecar retry is handled by workstream K's poller). */
async function resetMailboxStatus(id: string): Promise<void> {
  getDb().prepare("UPDATE mailboxes SET status = 'unknown', last_error_code = NULL, next_retry_at = NULL WHERE id = ?").run(id);
  clearMailboxAuthFailure(id); // Node pool latch
  await retryMailbox(id); // sidecar latch (never throws)
}
const reRaw = (v: string) => v.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");

// ---------------- Dashboard ----------------
router.get("/dashboard", (req, res) => {
  const db = getDb();
  const mailboxes = listMailboxes();
  const clients = db.prepare("SELECT client_id, client_name, created_at, disabled FROM oauth_clients ORDER BY created_at DESC").all() as any[];
  const grantRows = capabilityRows(db);
  const granted = new Map<string, Set<string>>(); // `${client}:${mailbox}` -> caps
  for (const g of grantRows) {
    const k = `${g.client_id}:${g.mailbox_id}`;
    if (!granted.has(k)) granted.set(k, new Set());
    granted.get(k)!.add(g.capability);
  }
  const tokens = db.prepare(
    `SELECT t.id, t.client_id, t.scopes, t.expires_at, t.created_at, c.client_name
       FROM oauth_tokens t JOIN oauth_clients c ON c.client_id = t.client_id
      WHERE t.revoked = 0 AND (t.expires_at > ? OR (t.refresh_expires_at IS NOT NULL AND t.refresh_expires_at > ?))
      ORDER BY t.created_at DESC`
  ).all(new Date().toISOString(), new Date().toISOString()) as any[];

  const capPills = (set?: Set<string>) => (set && set.size ? CAPABILITIES.filter((c) => set.has(c)).map(pill).join(" ") : `<span class="none">\u2014</span>`);
  const noDrafts = mailboxes.filter((m) => !m.drafts_folder);
  const warn = noDrafts.length
    ? `<div class="alert warn" role="status"><span>${noDrafts.map((m) => `<b>${esc(m.label)}</b>`).join(", ")} ${noDrafts.length === 1 ? "has" : "have"} no Drafts folder. <b>draft</b> grants there do not work until you pick one.</span><a href="/mailboxes/${esc(noDrafts[0].id)}">Fix it</a></div>`
    : "";

  const mapRows = clients.map((c) => `<tr><th scope="row">${esc(c.client_name || "(unnamed)")}${c.disabled ? ` <span class="pill off">disabled</span>` : ""}<div class="sub mono" style="font-weight:400">${esc(c.client_id)}</div></th>
    ${mailboxes.map((m) => `<td>${capPills(granted.get(`${c.client_id}:${m.id}`))}</td>`).join("")}
    <td class="r">${c.disabled ? post(req, `/clients/${encodeURIComponent(c.client_id)}/enable`, "Enable", "s") : `<a class="btn s" href="/clients/${esc(c.client_id)}">Edit grants</a>`}</td></tr>`).join("");
  const map = mailboxes.length && clients.length
    ? `<div class="scroll"><table><thead><tr><th scope="col">Client</th>${mailboxes.map((m) => `<th scope="col">${esc(m.label)}</th>`).join("")}<th></th></tr></thead><tbody>${mapRows}</tbody></table></div>`
    : `<p class="pad sub">${mailboxes.length ? "No clients registered yet." : "Add a mailbox first, then connect a client."}</p>`;

  const clientCount = (mid: string) => new Set(grantRows.filter((g) => g.mailbox_id === mid).map((g) => g.client_id)).size;
  const mbRows = mailboxes.map((m) => `<tr><td><b>${esc(m.label)}</b></td><td class="mono">${esc(m.imap_host)}:${m.imap_port}</td><td>${esc(m.imap_username)}</td><td>${statusBadge(mailboxStatus(m.id).status)}</td>
    <td>${m.drafts_folder ? esc(m.drafts_folder) : '<span class="pill warn">not set</span>'}</td><td>${clientCount(m.id) || '<span class="none">0</span>'}</td><td class="r"><a class="btn s" href="/mailboxes/${esc(m.id)}">Manage</a></td></tr>`).join("");

  const mbLabel = new Map(mailboxes.map((m) => [m.id, m.label]));
  const reach = (t: any) => {
    const ceiling = new Set<string>(scopesToCaps(t.scopes));
    const lines = mailboxes.map((m) => {
      const live = CAPABILITIES.filter((c) => ceiling.has(c) && granted.get(`${t.client_id}:${m.id}`)?.has(c));
      return live.length ? `<div>${esc(mbLabel.get(m.id) ?? m.id)} ${live.map(pill).join(" ")}</div>` : "";
    }).join("");
    return lines || `<span class="none">nothing (all grants removed)</span>`;
  };
  const tkRows = tokens.map((t) => `<tr><td><b>${esc(t.client_name || t.client_id)}</b></td><td>${reach(t)}</td><td class="sub">${when(t.created_at)}</td>
    <td class="sub">${when(t.expires_at)}</td><td class="r"><a class="btn s d" href="/tokens/${encodeURIComponent(t.id)}/revoke">Revoke</a></td></tr>`).join("");

  const addClient = config.registrationMode === "admin"
    ? `<form method="POST" action="/clients" class="pad" style="border-top:1px solid var(--line)">${csrf(req)}<h3 style="font-size:14px">Add client</h3>
      <label for="cn">Name</label><input id="cn" type="text" name="client_name" maxlength="100" required>
      <label for="ru">Redirect URIs (one per line; https or http://localhost)</label><textarea id="ru" name="redirect_uris" rows="3" style="width:100%;border:1px solid var(--line-strong);border-radius:8px;padding:8px 12px;font:inherit;background:var(--surface);color:var(--ink)" required></textarea>
      <button type="submit" class="p" style="margin-top:14px">Create client</button></form>`
    : "";

  send(res, "Overview", `<div class="head"><div><h1>Overview</h1><p>Who can reach which mailbox, and how.</p></div></div>
  ${flash(req)}${warn}
  ${card("clients", "Access map", map + addClient, { aside: `<span class="sub">Blank means no access. ${pill("draft")} ${pill("organize")} change things.${config.registrationMode === "admin" ? "" : " Clients register themselves; registration grants nothing."}</span>` })}
  ${card("mailboxes", "Mailboxes", mailboxes.length
    ? `<div class="scroll"><table><thead><tr><th scope="col">Label</th><th scope="col">Server</th><th scope="col">User</th><th scope="col">Status</th><th scope="col">Drafts folder</th><th scope="col">Clients</th><th></th></tr></thead><tbody>${mbRows}</tbody></table></div>`
    : `<p class="pad sub">No mailboxes yet.</p>`, { aside: `<a class="btn p s" href="/mailboxes/new">Add mailbox</a>` })}
  ${card("tokens", "Active tokens", tokens.length
    ? `<div class="scroll"><table><thead><tr><th scope="col">Client</th><th scope="col">Can reach</th><th scope="col">Issued</th><th scope="col">Access token expires</th><th></th></tr></thead><tbody>${tkRows}</tbody></table></div>`
    : `<p class="pad sub">No active tokens.</p>`, { aside: `<span class="sub">Revoking cuts access at the next call.</span>` })}`, "overview");
});

// ---------------- Mailboxes ----------------
function mailboxForm(req: Request, opts: { action: string; m?: { label: string; imap_host: string; imap_port: number; imap_username: string }; edit: boolean }) {
  const m = opts.m;
  return `<form method="POST" action="${esc(opts.action)}" autocomplete="off" class="pad">${csrf(req)}
    <label for="mb-label" style="margin-top:0">Label</label><input id="mb-label" type="text" name="label" maxlength="100" required value="${esc(m?.label ?? "")}" style="max-width:340px">
    <div class="grid2"><div><label for="mb-host">IMAP host</label><input id="mb-host" type="text" name="host" maxlength="253" required value="${esc(m?.imap_host ?? "")}"></div>
    <div><label for="mb-port">Port (TLS)</label><input id="mb-port" type="number" name="port" min="1" max="65535" required value="${m?.imap_port ?? 993}"></div></div>
    <label for="mb-user">Username</label><input id="mb-user" type="text" name="username" maxlength="320" required value="${esc(m?.imap_username ?? "")}">
    <label for="mb-pass">Password</label>
    <input id="mb-pass" type="password" name="password" autocomplete="new-password" ${opts.edit ? 'placeholder="Leave empty to keep the saved password"' : "required"}>
    <div class="hint">Stored encrypted. TLS with certificate validation is always on.</div>
    <button type="submit" class="p" style="margin-top:18px">${opts.edit ? "Save connection" : "Add mailbox"}</button></form>`;
}

router.get("/mailboxes/new", (req, res) => {
  send(res, "Add mailbox", `<div class="crumb"><a href="/dashboard#mailboxes">Mailboxes</a> / New</div><div class="head"><h1>Add mailbox</h1></div>${flash(req)}
    ${card("add", "Connection", mailboxForm(req, { action: "/mailboxes", edit: false }))}
    <p class="small">Test the connection after saving, then choose the Drafts folder.</p>`, "mailboxes");
});

router.post("/mailboxes", (req, res) => {
  const i = { label: str(req.body.label, 100), host: str(req.body.host, 253), port: parseInt(str(req.body.port, 6), 10), username: str(req.body.username, 320), password: typeof req.body.password === "string" ? req.body.password : "" };
  const bad = validateMailboxInput(i, true);
  if (bad) return back(res, "/mailboxes/new", "err", bad);
  const m = createMailbox(i);
  back(res, `/mailboxes/${m.id}`, "msg", "Mailbox saved. Run the connection test, then choose the Drafts folder.");
});

function statusBanner(req: Request, id: string): string {
  const st = mailboxStatus(id);
  const retry = post(req, `/mailboxes/${id}/retry`, "Retry", "s");
  if (st.status === "auth_failed") {
    return `<div class="error" role="alert"><span><b>Authentication failed.</b> The mail server rejected this mailbox's credentials, so the bridge stopped trying. Update the password below, or press Retry once it is fixed at the provider.${st.last_error_code ? ` <span class="mono">${esc(st.last_error_code)}</span>` : ""}</span>${retry}</div>`;
  }
  if (st.status === "degraded") {
    return `<div class="alert warn" role="status"><span><b>Degraded.</b> The connection is unstable${st.last_error_code ? ` (<span class="mono">${esc(st.last_error_code)}</span>)` : ""}${st.next_retry_at ? `; next attempt ${when(st.next_retry_at)}` : ""}.</span>${retry}</div>`;
  }
  return `<p class="small" style="margin-bottom:14px">Connection status: ${statusBadge(st.status)}${st.last_ok_at ? ` \u00b7 last OK ${when(st.last_ok_at)}` : ""}</p>`;
}

function renderMailbox(req: Request, res: Response, id: string, test?: { ok: boolean; message: string; folders: string[] }) {
  const m = getMailbox(id);
  if (!m) return res.status(404).send(layout("Not found", `<div class="card"><div class="pad"><h2>Mailbox not found</h2><a href="/dashboard">Back</a></div></div>`, "admin", "mailboxes"));
  const rows = capabilityRows(getDb(), { mailboxId: m.id });
  const byClient = new Map<string, Set<string>>();
  for (const r of rows) (byClient.get(r.client_id) ?? byClient.set(r.client_id, new Set()).get(r.client_id)!).add(r.capability);
  const names = new Map((getDb().prepare("SELECT client_id, client_name FROM oauth_clients").all() as any[]).map((c) => [c.client_id, c.client_name || "(unnamed)"]));
  const reach = byClient.size
    ? `<table><tbody>${[...byClient].map(([cid, caps]) => `<tr><th scope="row">${esc(names.get(cid) ?? cid)}</th><td>${CAPABILITIES.filter((c) => caps.has(c)).map(pill).join(" ")}</td><td class="r"><a class="btn s" href="/clients/${esc(cid)}">Edit grants</a></td></tr>`).join("")}</tbody></table>`
    : `<p class="pad sub">No client has access to ${esc(m.label)} yet. Grant it from a client's page.</p>`;
  const folderForm = `<form method="POST" action="/mailboxes/${esc(m.id)}/drafts" class="pad">${csrf(req)}
    <p class="sub">Clients with <b>draft</b> write only here. They cannot read, move or send.</p>
    ${test?.ok
      ? `<label for="df">Folder on server</label>
        <select id="df" name="drafts_folder" style="max-width:340px">${m.drafts_folder ? "" : `<option value="">Choose a folder\u2026</option>`}${test.folders.map((f) => `<option value="${esc(f)}"${f === m.drafts_folder ? " selected" : ""}>${esc(f)}</option>`).join("")}</select>
        <button type="submit" class="p" style="margin-top:14px">Save Drafts folder</button>`
      : `<p class="hint">Run the connection test to choose the Drafts folder from the server's folder list.</p>`}</form>`;
  send(res, m.label, `<div class="crumb"><a href="/dashboard#mailboxes">Mailboxes</a> / ${esc(m.label)}</div>
  <div class="head"><div><h1>${esc(m.label)}</h1><p class="mono">${esc(m.imap_username)} \u00b7 ${esc(m.imap_host)}:${m.imap_port}</p></div>${post(req, `/mailboxes/${m.id}/test`, "Test connection")}</div>
  ${flash(req)}${statusBanner(req, m.id)}${test ? `<div class="${test.ok ? "success" : "error"}" role="status"><span>${esc(test.message)}</span></div>` : ""}
  ${card("conn", "Connection", mailboxForm(req, { action: `/mailboxes/${m.id}`, m, edit: true }))}
  ${card("drafts", "Drafts folder", folderForm, { aside: m.drafts_folder ? `<span class="sub">Current: <b>${esc(m.drafts_folder)}</b></span>` : `<span class="pill warn">not set</span>` })}
  ${card("reach", "Who can reach this mailbox", reach)}
  ${card("delete", "Delete mailbox", `<form method="POST" action="/mailboxes/${esc(m.id)}/delete">${csrf(req)}
    <p>This removes the connection and ${byClient.size ? `the grants of <b>${byClient.size}</b> client${byClient.size === 1 ? "" : "s"}` : "all grants"} for <b>${esc(m.label)}</b>. Mail on the server is not touched.</p>
    <label for="cf">Type <b>${esc(m.label)}</b> to confirm</label>
    <input id="cf" type="text" required autocomplete="off" pattern="${esc(reRaw(m.label))}" title="Type the mailbox label exactly: ${esc(m.label)}" style="max-width:340px">
    <button type="submit" class="dfill" style="margin-top:14px">Delete mailbox</button></form>`, { cls: "danger-zone", padded: true })}`, "mailboxes");
}

router.get("/mailboxes/:id", (req, res) => renderMailbox(req, res, req.params.id));

router.post("/mailboxes/:id", async (req, res) => {
  const id = req.params.id;
  const i = { label: str(req.body.label, 100), host: str(req.body.host, 253), port: parseInt(str(req.body.port, 6), 10), username: str(req.body.username, 320), password: typeof req.body.password === "string" ? req.body.password : "" };
  const bad = validateMailboxInput(i, false);
  if (bad) return back(res, `/mailboxes/${id}`, "err", bad);
  if (!updateMailbox(id, i)) return res.status(404).send("Not found");
  if (i.password) await resetMailboxStatus(id); // new credentials: resume automatic attempts (both latches)
  back(res, `/mailboxes/${id}`, "msg", "Saved. If host, port or username changed, re-test and re-select the Drafts folder.");
});

router.post("/mailboxes/:id/retry", async (req, res) => {
  if (!getMailbox(req.params.id)) return res.status(404).send("Not found");
  await resetMailboxStatus(req.params.id);
  back(res, `/mailboxes/${req.params.id}`, "msg", "Status reset. The bridge will try to connect again on the next request.");
});

router.post("/mailboxes/:id/test", async (req, res) => {
  if (!getMailbox(req.params.id)) return res.status(404).send("Not found");
  renderMailbox(req, res, req.params.id, await testMailbox(req.params.id));
});

router.post("/mailboxes/:id/drafts", async (req, res) => {
  const id = req.params.id;
  const folder = str(req.body.drafts_folder, 255);
  if (!getMailbox(id)) return res.status(404).send("Not found");
  if (!folder || /[\x00-\x1f]/.test(folder)) return back(res, `/mailboxes/${id}`, "err", "Choose a folder");
  // must be a folder that really exists on the server
  const t = await testMailbox(id);
  if (!t.ok) return renderMailbox(req, res, id, t);
  if (!t.folders.includes(folder)) return back(res, `/mailboxes/${id}`, "err", "That folder does not exist on the server");
  setDraftsFolder(id, folder);
  back(res, `/mailboxes/${id}`, "msg", "Drafts folder saved.");
});

router.post("/mailboxes/:id/delete", (req, res) => {
  deleteMailbox(req.params.id);
  back(res, "/dashboard", "msg", "Mailbox configuration removed.");
});

// ---------------- Clients & grants ----------------
router.post("/clients", (req, res) => {
  if (config.registrationMode !== "admin") return res.status(403).send("Clients are registered dynamically");
  const name = str(req.body.client_name, 100);
  const uris = str(req.body.redirect_uris, 4000).split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  if (!name || uris.length === 0 || uris.length > 10 || !uris.every(validRedirectUri)) {
    return back(res, "/dashboard", "err", "Name and 1-10 valid redirect URIs required (https, or http on localhost)");
  }
  const id = randomUUID();
  getDb().prepare("INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?, ?, ?)").run(id, name, JSON.stringify(uris));
  back(res, `/clients/${id}`, "msg", `Client created. client_id: ${id}`);
});

router.get("/clients/:id", (req, res) => {
  const db = getDb();
  const c = db.prepare("SELECT client_id, client_name, redirect_uris, disabled, created_at FROM oauth_clients WHERE client_id = ?").get(req.params.id) as any;
  if (!c) return res.status(404).send(layout("Not found", `<div class="card"><div class="pad"><h2>Client not found</h2><a href="/dashboard">Back</a></div></div>`, "admin", "clients"));
  const mailboxes = listMailboxes();
  const labels = new Map(mailboxes.map((m) => [m.id, m.label]));
  let uris: string[] = [];
  try { uris = JSON.parse(c.redirect_uris); } catch { /* ignore */ }
  const name = c.client_name || "(unnamed)";
  const rules = listRules(db, c.client_id);
  const ruleRows = rules.map((r) => `<tr><td>${esc(labels.get(r.mailbox_id) ?? r.mailbox_id)}</td><td class="mono">${esc(r.folder)}${isValidSelector(r.folder) ? "" : " <span class=\"pill warn\">invalid, never matches</span>"}</td><td>${esc(r.operation)}</td><td><b>${esc(r.effect)}</b></td><td class="r">${post(req, `/clients/${encodeURIComponent(c.client_id)}/rules/${encodeURIComponent(r.id)}/delete`, "Remove", "s")}</td></tr>`).join("");
  const rows = mailboxes.map((m) => `<tr><th scope="row">${esc(m.label)}${m.drafts_folder ? "" : `<div class="sub" style="font-weight:400">No Drafts folder yet</div>`}</th>${CAPABILITIES.map((cap) => {
    const on = presetActive(db, c.client_id, m.id, cap);
    const off = cap === "draft" && !m.drafts_folder && !on;
    return `<td class="c"><input type="checkbox" name="g_${esc(m.id)}_${cap}" value="1"${on ? " checked" : ""}${off ? " disabled" : ""} aria-label="${esc(name)}: ${cap} on ${esc(m.label)}${off ? " (unavailable: no Drafts folder)" : ""}"></td>`;
  }).join("")}</tr>`).join("");
  send(res, name, `<div class="crumb"><a href="/dashboard#clients">Clients</a> / ${esc(name)}</div>
  <div class="head"><div><h1>${esc(name)}</h1><p class="mono">${esc(c.client_id)} \u00b7 registered ${when(c.created_at)} \u00b7 <span class="pill ${c.disabled ? "off" : "ok"}" style="font-family:system-ui">${c.disabled ? "disabled" : "active"}</span></p></div>
    ${c.disabled ? post(req, `/clients/${encodeURIComponent(c.client_id)}/enable`, "Enable client") : `<a class="btn d" href="/clients/${esc(c.client_id)}/disable">Disable client</a>`}</div>
  ${flash(req)}
  ${mailboxes.length ? `<form method="POST" action="/clients/${esc(c.client_id)}/grants">${csrf(req)}${card("grants", "Grants",
    `<p class="pad sub" style="padding-bottom:0">Removing a grant applies on the next call, even for tokens already issued. Adding a capability the token was not authorized for needs a new authorization.</p>
    <div class="scroll" style="margin-top:12px"><table><thead><tr><th scope="col">Mailbox</th>${CAPABILITIES.map((x) => `<th scope="col" class="c">${x}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table></div>
    <div class="confirm"><span class="sub">Nothing ticked means no access.</span><button type="submit" class="p s">Save grants</button></div>`)}</form>` : card("grants", "Grants", `<p class="pad sub">No mailboxes configured.</p>`)}
  ${card("rules", "Advanced rules", `<p class="pad sub" style="padding-bottom:0">Presets above expand to allow rules on all folders (<code>*</code>): read = ${PRESET_OPS.read.join(", ")}; draft = ${PRESET_OPS.draft.join(", ")}; organize = ${PRESET_OPS.organize.join(", ")}. A matching <b>deny</b> always wins; no matching allow means denied. Folder: exact IMAP path (case-sensitive), <code>*</code>, or <code>Prefix/*</code> for sub-folders. Renaming a folder on the server makes an exact rule stop matching (fails closed).</p>
    ${rules.length ? `<div class="scroll" style="margin-top:12px"><table><thead><tr><th scope="col">Mailbox</th><th scope="col">Folder</th><th scope="col">Operation</th><th scope="col">Effect</th><th></th></tr></thead><tbody>${ruleRows}</tbody></table></div>` : `<p class="pad sub">No rules.</p>`}
    ${mailboxes.length ? `<form method="POST" action="/clients/${esc(c.client_id)}/rules" class="pad" style="border-top:1px solid var(--line)">${csrf(req)}<h3 style="font-size:14px">Add rule</h3>
      <label for="rm">Mailbox</label><select id="rm" name="mailbox_id">${mailboxes.map((m) => `<option value="${esc(m.id)}">${esc(m.label)}</option>`).join("")}</select>
      <label for="rf">Folder (exact path, <code>*</code>, or <code>Prefix/*</code>)</label><input id="rf" type="text" name="folder" maxlength="255" required>
      <label for="ro">Operation</label><select id="ro" name="operation">${OPERATIONS.map((o) => `<option value="${o}">${o} (needs ${OP_CAPABILITY[o]})</option>`).join("")}</select>
      <label for="re">Effect</label><select id="re" name="effect"><option value="allow">allow</option><option value="deny">deny</option></select>
      <button type="submit" class="p s">Add rule</button></form>` : ""}`)}
  ${card("revoke", "Revoke client", `<p>Removes every rule and revokes all tokens. IMAP credentials are not changed.</p>${post(req, `/clients/${encodeURIComponent(c.client_id)}/revoke`, "Revoke client", "dfill")}`, { cls: "danger-zone", padded: true })}
  ${card("caps", "What each capability allows", `<table><tbody>
    <tr><td>${pill("read")}</td><td>List folders, search, read messages</td></tr>
    <tr><td>${pill("draft")}</td><td>Create drafts in the mailbox's Drafts folder only</td></tr>
    <tr><td>${pill("organize")}</td><td>Move messages and set flags within one mailbox</td></tr></tbody></table>`)}
  ${card("uris", "Redirect URIs", `<p class="mono">${uris.map(esc).join("<br>")}</p>`, { padded: true })}`, "clients");
});

// Confirmation pages (no JS available under the CSP): state the impact, then POST to the real endpoint.
router.get("/clients/:id/disable", (req, res) => {
  const c = getDb().prepare("SELECT client_id, client_name FROM oauth_clients WHERE client_id = ?").get(req.params.id) as any;
  if (!c) return res.status(404).send("Not found");
  const n = (getDb().prepare("SELECT COUNT(*) AS n FROM oauth_tokens WHERE client_id = ? AND revoked = 0").get(c.client_id) as any).n as number;
  send(res, "Disable client", `<div class="crumb"><a href="/clients/${esc(c.client_id)}">${esc(c.client_name || "(unnamed)")}</a> / Disable</div><div class="head"><h1>Disable ${esc(c.client_name || "(unnamed)")}?</h1></div>
  ${card("confirm", "This takes effect immediately", `<p>${n} active token${n === 1 ? "" : "s"} will be revoked and the client cannot authorize again until you enable it. Grants are kept.</p>
    <div class="row" style="margin-top:16px"><form method="POST" action="/clients/${esc(c.client_id)}/disable">${csrf(req)}<button type="submit" class="dfill">Disable client</button></form><a class="btn" href="/clients/${esc(c.client_id)}">Cancel</a></div>`, { cls: "danger-zone", padded: true })}`, "clients");
});

router.get("/tokens/:id/revoke", (req, res) => {
  const t = getDb().prepare("SELECT t.id, t.client_id, t.scopes, c.client_name FROM oauth_tokens t JOIN oauth_clients c ON c.client_id = t.client_id WHERE t.id = ?").get(req.params.id) as any;
  if (!t) return res.status(404).send("Not found");
  send(res, "Revoke token", `<div class="crumb"><a href="/dashboard#tokens">Tokens</a> / Revoke</div><div class="head"><h1>Revoke ${esc(t.client_name || t.client_id)}'s token?</h1></div>
  ${card("confirm", "This takes effect immediately", `<p>The client loses access with this token (${scopesToCaps(t.scopes).map(pill).join(" ")}) on its next call. It can ask you to authorize again.</p>
    <div class="row" style="margin-top:16px"><form method="POST" action="/tokens/${encodeURIComponent(t.id)}/revoke">${csrf(req)}<button type="submit" class="dfill">Revoke token</button></form><a class="btn" href="/dashboard#tokens">Cancel</a></div>`, { cls: "danger-zone", padded: true })}`, "tokens");
});

router.post("/clients/:id/grants", (req, res) => {
  const db = getDb();
  const c = db.prepare("SELECT client_id FROM oauth_clients WHERE client_id = ?").get(req.params.id);
  if (!c) return res.status(404).send("Not found");
  const mailboxes = listMailboxes();
  db.transaction(() => {
    for (const m of mailboxes) for (const cap of CAPABILITIES as Capability[]) {
      const want = !!req.body[`g_${m.id}_${cap}`];
      const have = presetActive(db, req.params.id, m.id, cap);
      if (want && !have) grantPreset(db, req.params.id, m.id, cap);
      else if (!want && have) revokePreset(db, req.params.id, m.id, cap);
    }
  })();
  back(res, `/clients/${encodeURIComponent(req.params.id)}`, "msg", "Presets saved.");
});

router.post("/clients/:id/rules", (req, res) => {
  const db = getDb();
  const id = req.params.id;
  const path = `/clients/${encodeURIComponent(id)}`;
  if (!db.prepare("SELECT 1 FROM oauth_clients WHERE client_id = ?").get(id)) return res.status(404).send("Not found");
  const mailboxId = str(req.body.mailbox_id, 100);
  const folder = typeof req.body.folder === "string" ? req.body.folder.trim() : "";
  const op = req.body.operation;
  const effect = req.body.effect;
  if (!getMailbox(mailboxId)) return back(res, path, "err", "Unknown mailbox");
  if (!isValidSelector(folder)) return back(res, path, "err", "Invalid folder selector: use an exact path, *, or Prefix/* (no other wildcards)");
  if (!isOperation(op)) return back(res, path, "err", "Unknown operation");
  if (effect !== "allow" && effect !== "deny") return back(res, path, "err", "Effect must be allow or deny");
  setRule(db, id, mailboxId, folder, op, effect);
  back(res, path, "msg", "Rule saved.");
});

router.post("/clients/:id/rules/:ruleId/delete", (req, res) => {
  getDb().prepare("DELETE FROM policy_rules WHERE id = ? AND client_id = ?").run(req.params.ruleId, req.params.id);
  back(res, `/clients/${encodeURIComponent(req.params.id)}`, "msg", "Rule removed.");
});

router.post("/clients/:id/revoke", (req, res) => {
  const db = getDb();
  if (!db.prepare("SELECT 1 FROM oauth_clients WHERE client_id = ?").get(req.params.id)) return res.status(404).send("Not found");
  db.transaction(() => {
    db.prepare("DELETE FROM policy_rules WHERE client_id = ?").run(req.params.id);
    db.prepare("UPDATE oauth_tokens SET revoked = 1 WHERE client_id = ?").run(req.params.id);
  })();
  back(res, `/clients/${encodeURIComponent(req.params.id)}`, "msg", "All rules removed and tokens revoked. IMAP credentials are unchanged.");
});

for (const [action, val] of [["disable", 1], ["enable", 0]] as const) {
  router.post(`/clients/:id/${action}`, (req, res) => {
    const db = getDb();
    db.prepare("UPDATE oauth_clients SET disabled = ? WHERE client_id = ?").run(val, req.params.id);
    if (val) db.prepare("UPDATE oauth_tokens SET revoked = 1 WHERE client_id = ?").run(req.params.id);
    back(res, "/dashboard", "msg", val ? "Client disabled and its tokens revoked." : "Client enabled.");
  });
}

// ---------------- Tokens ----------------
router.post("/tokens/:id/revoke", (req, res) => {
  getDb().prepare("UPDATE oauth_tokens SET revoked = 1 WHERE id = ?").run(req.params.id);
  back(res, "/dashboard", "msg", "Token revoked.");
});

export default router;
